"""公共认证工具：支持 ADC 或指定 gcloud 账号（token 到期自动刷新）。"""

import datetime
import subprocess

import google.auth
from google.auth import credentials as ga_credentials

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_GCLOUD_TOKEN_TTL = datetime.timedelta(minutes=50)   # gcloud token 约 1 小时，提前刷新


class GcloudCredentials(ga_credentials.CredentialsWithQuotaProject):
    """
    用 `gcloud auth print-access-token --account=<账号>` 获取 token 的凭证。
    google-auth 发现 token 过期时会调用 refresh() 重新获取，长时间任务不会因 1 小时到期而中断。
    """

    def __init__(self, account, quota_project_id=None):
        super().__init__()
        self._account = account
        self._quota_project_id = quota_project_id

    def refresh(self, request):  # noqa: ARG002  (google-auth 接口)
        self.token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token", f"--account={self._account}"],
            text=True,
        ).strip()
        self.expiry = datetime.datetime.utcnow() + _GCLOUD_TOKEN_TTL

    def with_quota_project(self, quota_project_id):
        return GcloudCredentials(self._account, quota_project_id)


def _gcloud_default_project(account):
    try:
        out = subprocess.check_output(
            ["gcloud", "config", "get-value", "project", f"--account={account}"],
            text=True, stderr=subprocess.DEVNULL).strip()
        return out or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


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
