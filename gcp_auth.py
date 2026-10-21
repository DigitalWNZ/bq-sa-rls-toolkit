"""公共认证工具：支持 ADC 或指定 gcloud 账号（token 到期自动刷新）。"""

import datetime
import subprocess
import threading

from collections import namedtuple

import google.auth
import google.auth.exceptions
from google.auth import credentials as ga_credentials

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_GCLOUD_TOKEN_TTL = datetime.timedelta(minutes=50)   # gcloud token 约 1 小时，提前刷新


class GcloudCredentials(ga_credentials.CredentialsWithQuotaProject):
    """
    用 gcloud 已登录账号的 token 作为凭证，到期自动刷新。
    通过 `gcloud config config-helper --account=<账号>` 同时取得 token 和它的**真实**到期时间
    （gcloud 会返回缓存的 token，剩余寿命可能远少于 1 小时；按真实到期时间，google-auth 会在到期前约 4 分钟主动刷新）。
    """

    def __init__(self, account, quota_project_id=None):
        super().__init__()
        self._account = account
        self._quota_project_id = quota_project_id
        self._lock = threading.Lock()
        self._last_refresh = None

    def _fetch(self):
        try:
            out = subprocess.check_output(
                ["gcloud", "config", "config-helper", f"--account={self._account}",
                 "--format=value(credential.access_token,credential.token_expiry)"],
                text=True, stderr=subprocess.PIPE).strip()
            token, _, expiry = out.partition("\t")
            if token and expiry:
                exp = datetime.datetime.strptime(expiry.strip(), "%Y-%m-%dT%H:%M:%SZ")
                return token.strip(), exp
        except (subprocess.CalledProcessError, ValueError):
            pass
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token", f"--account={self._account}"], text=True).strip()
        return token, datetime.datetime.utcnow() + _GCLOUD_TOKEN_TTL

    def refresh(self, request):  # noqa: ARG002  (google-auth 接口)
        with self._lock:
            now = datetime.datetime.utcnow()
            # 并发线程几乎同时发现过期时只调用一次 gcloud；但 401 触发的强制刷新（距上次 > 5 秒）必须真正执行
            if self._last_refresh and (now - self._last_refresh).total_seconds() < 5 and self.valid:
                return
            self.token, self.expiry = self._fetch()
            self._last_refresh = now

    def with_quota_project(self, quota_project_id):
        return GcloudCredentials(self._account, quota_project_id)


def _gcloud_config_value(name, account=None):
    cmd = ["gcloud", "config", "get-value", name] + ([f"--account={account}"] if account else [])
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        return out if out and out != "(unset)" else None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _gcloud_default_project(account=None):
    return _gcloud_config_value("project", account)


def _gcloud_active_account():
    return _gcloud_config_value("account")


def _adc():
    """application-default 凭证（没有时返回 None）。"""
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        return creds
    except google.auth.exceptions.DefaultCredentialsError:
        return None


class AuthConfigError(Exception):
    """找不到可用的登录凭证或 quota 项目（运行环境配置问题，脚本以退出码 2 结束）。"""


LOGIN_HINT = "请先执行 gcloud auth login <账号> 登录一次（或用 --gcloud-account 指定已登录的账号）"
PROJECT_HINT = "请执行 gcloud config set project <项目ID> 设置一次默认项目（或用 --quota-project 指定）"

Auth = namedtuple("Auth", "creds account account_source project project_source impersonated", defaults=(None,))


def _gcloud_impersonated_sa(account=None):
    """
    gcloud 的扮演设置（gcloud config set auth/impersonate_service_account，或环境变量
    CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT）。有委托链 "a,b,c" 时实际身份是最后一个。没有设置时返回 None。
    """
    v = _gcloud_config_value("auth/impersonate_service_account", account)
    return v.split(",")[-1].strip() if v else None


def resolve_auth(gcloud_account=None, quota_project=None):
    """
    确定执行账号与 quota 项目，返回 Auth(creds, account, account_source, project, project_source)。
      账号：--gcloud-account → gcloud 当前活动账号（gcloud auth login 后的那个）→ application-default 凭证 → 报错
      quota 项目：--quota-project → gcloud 默认项目（gcloud config set project）→ application-default 凭证的 quota 项目 → 报错
    """
    account, account_source, adc = gcloud_account, "--gcloud-account", None
    if not account:
        account, account_source = _gcloud_active_account(), "gcloud 当前活动账号"
    if not account:
        adc = _adc()
        if adc is None:
            raise AuthConfigError(f"找不到可用的登录凭证（gcloud 没有活动账号，也没有 application-default 凭证）。{LOGIN_HINT}")
        account, account_source = None, "application-default 凭证"

    project, project_source = quota_project, "--quota-project"
    if not project:
        project, project_source = _gcloud_default_project(account), "gcloud 默认项目"
    if not project:
        cand = adc if adc is not None else _adc()
        project = getattr(cand, "quota_project_id", None) if cand is not None else None
        project_source = "application-default 凭证的 quota 项目"
    if not project:
        raise AuthConfigError(f"无法确定 quota 项目（未指定 --quota-project，gcloud 也没有默认项目）。{PROJECT_HINT}")

    impersonated = None
    if account:
        impersonated = _gcloud_impersonated_sa(account)    # 通过 gcloud 扮演 SA 时，所有调用实际以该 SA 身份执行
        creds = GcloudCredentials(account, quota_project_id=project)
        try:
            creds.refresh(None)                  # 立即取一次 token，尽早暴露登录问题
        except Exception as e:  # noqa: BLE001
            if impersonated:
                raise AuthConfigError(
                    f"登录账号 {account} 无法扮演 {impersonated}（{str(e)[:200]}）：登录账号需要对该 SA 有 "
                    f"Service Account Token Creator 权限，并确认该 SA 存在") from e
            raise AuthConfigError(f"无法获取账号 {account} 的访问令牌（{str(e)[:200]}）。{LOGIN_HINT}") from e
    else:
        creds = adc.with_quota_project(project) if hasattr(adc, "with_quota_project") else adc
    return Auth(creds, account or "（application-default 凭证的账号）", account_source, project, project_source,
                impersonated)


def describe_auth(auth):
    if auth.impersonated:
        return (f"[AUTH] 执行账号: {auth.impersonated}（gcloud 扮演；登录账号 {auth.account}）；"
                f"quota 项目: {auth.project}（{auth.project_source}）")
    return f"[AUTH] 执行账号: {auth.account}（{auth.account_source}）；quota 项目: {auth.project}（{auth.project_source}）"


def get_credentials(gcloud_account=None, quota_project=None):
    """
    gcloud_account 为空时使用 Application Default Credentials；
    否则返回 GcloudCredentials（按需调用 gcloud 获取 token，并在到期前自动刷新）。
    quota_project 为空且使用 gcloud 账号时，回退到 gcloud 配置的默认项目
    （Cloud Identity 等 API 对用户凭证要求 quota project）。
    """
    if gcloud_account:
        quota_project = quota_project or _gcloud_default_project(gcloud_account)
        creds = GcloudCredentials(gcloud_account, quota_project_id=quota_project)
        creds.refresh(None)   # 立即获取一次，便于尽早暴露登录问题
        return creds
    creds, _ = google.auth.default(scopes=SCOPES)
    if quota_project and hasattr(creds, "with_quota_project"):
        creds = creds.with_quota_project(quota_project)
    return creds
