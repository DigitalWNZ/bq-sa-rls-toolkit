"""gcp_auth 的单元测试：gcloud 账号凭证按真实到期时间自动刷新，多线程只调用一次 gcloud，401 强制刷新有效。"""

import datetime
import subprocess
import threading

import gcp_auth


class _Req:  # google.auth 的 refresh(request) 不会用到
    pass


def _fake_helper(monkeypatch, expiries, tokens=None, fail_helper=False):
    """模拟 gcloud：config-helper 返回 (token \\t expiry)；fail_helper 时退回 print-access-token。"""
    calls = []
    toks = list(tokens or [f"tok-{i}" for i in range(len(expiries))])

    def fake_check_output(cmd, text=True, **kw):
        calls.append(cmd)
        if cmd[1:3] == ["config", "config-helper"]:
            if fail_helper:
                raise subprocess.CalledProcessError(1, cmd)
            i = sum(1 for c in calls if c[1:3] == ["config", "config-helper"]) - 1
            return f"{toks[i]}\t{expiries[i]}\n"
        return "tok-fallback\n"
    monkeypatch.setattr(gcp_auth.subprocess, "check_output", fake_check_output)
    return calls


def _in(minutes):
    return (datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_refresh_uses_real_expiry_from_gcloud(monkeypatch):
    calls = _fake_helper(monkeypatch, [_in(7)])
    creds = gcp_auth.GcloudCredentials("ops@x.com", quota_project_id="p")
    assert creds.token is None and not creds.valid
    creds.refresh(_Req())
    assert creds.token == "tok-0" and creds.quota_project_id == "p"
    remaining = (creds.expiry - datetime.datetime.utcnow()).total_seconds()
    assert 6 * 60 < remaining <= 7 * 60                       # 用的是 gcloud 报告的到期时间，不是固定 50 分钟
    assert "--account=ops@x.com" in calls[0]


def test_short_lived_cached_token_counts_as_expired_for_google_auth(monkeypatch):
    # google-auth 在到期前 3 分 45 秒就视为过期并主动刷新；gcloud 缓存的 token 只剩 2 分钟时必须被视为无效
    _fake_helper(monkeypatch, [_in(2), _in(60)])
    creds = gcp_auth.GcloudCredentials("ops@x.com")
    creds.refresh(_Req())
    assert creds.expired and not creds.valid
    creds._last_refresh = None
    creds.refresh(_Req())
    assert creds.token == "tok-1" and creds.valid


def test_forced_refresh_after_401_really_refreshes(monkeypatch):
    # 服务端返回 401 时 google-auth 会调用 refresh()：即使本地认为还没过期，也必须重新取 token
    calls = _fake_helper(monkeypatch, [_in(50), _in(55)])
    creds = gcp_auth.GcloudCredentials("ops@x.com")
    creds.refresh(_Req())
    creds._last_refresh -= datetime.timedelta(seconds=10)
    creds.refresh(_Req())
    assert creds.token == "tok-1" and len(calls) == 2


def test_concurrent_refresh_calls_gcloud_once(monkeypatch):
    calls = _fake_helper(monkeypatch, [_in(50)] * 20)
    creds = gcp_auth.GcloudCredentials("ops@x.com")
    threads = [threading.Thread(target=creds.refresh, args=(_Req(),)) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1 and creds.token == "tok-0"


def test_falls_back_to_print_access_token(monkeypatch):
    _fake_helper(monkeypatch, [], fail_helper=True)
    creds = gcp_auth.GcloudCredentials("ops@x.com")
    creds.refresh(_Req())
    assert creds.token == "tok-fallback"
    assert 45 * 60 < (creds.expiry - datetime.datetime.utcnow()).total_seconds() <= 50 * 60


def test_get_credentials_returns_refreshable_for_gcloud_account(monkeypatch):
    _fake_helper(monkeypatch, [_in(50)])
    creds = gcp_auth.get_credentials("ops@x.com", "p")
    assert isinstance(creds, gcp_auth.GcloudCredentials) and creds.quota_project_id == "p" and creds.valid


def test_with_quota_project_keeps_account(monkeypatch):
    _fake_helper(monkeypatch, [_in(50)])
    c2 = gcp_auth.GcloudCredentials("ops@x.com").with_quota_project("q")
    assert c2.quota_project_id == "q" and c2._account == "ops@x.com"


# --------------------------------------------------------------------------- #
# resolve_auth：执行账号与 quota 项目的自动确定（2026-10-18）
#   账号：--gcloud-account → gcloud 当前活动账号 → application-default 凭证 → 报错（提示 gcloud auth login）
#   quota：--quota-project → gcloud 默认项目 → application-default 凭证的 quota 项目 → 报错（提示 gcloud config set project）
# --------------------------------------------------------------------------- #
import pytest  # noqa: E402


class _FakeAdc:
    def __init__(self, quota=None):
        self.quota_project_id = quota
        self.with_quota = None

    def with_quota_project(self, q):
        c = _FakeAdc(q)
        c.with_quota = q
        return c


def _env(monkeypatch, active_account=None, default_project=None, adc=None, token_ok=True):
    """模拟 gcloud config get-value account/project、config-helper（取 token）与 google.auth.default。"""
    calls = []

    def fake_check_output(cmd, text=True, **kw):
        calls.append(cmd)
        if cmd[1:4] == ["config", "get-value", "account"]:
            return (active_account or "") + "\n"
        if cmd[1:4] == ["config", "get-value", "project"]:
            return (default_project or "") + "\n"
        if cmd[1:3] == ["config", "config-helper"]:
            if not token_ok:
                raise subprocess.CalledProcessError(1, cmd)
            return f"tok\t{_in(60)}\n"
        if cmd[1:3] == ["auth", "print-access-token"]:
            if not token_ok:
                raise subprocess.CalledProcessError(1, cmd, output="ERROR: Reauthentication required")
            return "tok\n"
        raise AssertionError(cmd)

    def fake_default(scopes=None):
        if adc is None:
            raise gcp_auth.google.auth.exceptions.DefaultCredentialsError("Could not automatically determine credentials")
        return adc, None
    monkeypatch.setattr(gcp_auth.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(gcp_auth.google.auth, "default", fake_default)
    return calls


def test_resolve_explicit_account_and_project(monkeypatch):
    _env(monkeypatch, active_account="other@x.com", default_project="dflt")
    a = gcp_auth.resolve_auth("ops@x.com", "qp")
    assert isinstance(a.creds, gcp_auth.GcloudCredentials) and a.creds.quota_project_id == "qp"
    assert (a.account, a.account_source, a.project, a.project_source) == ("ops@x.com", "--gcloud-account", "qp", "--quota-project")


def test_resolve_defaults_to_active_gcloud_account_and_default_project(monkeypatch):
    _env(monkeypatch, active_account="ops@x.com", default_project="dflt")
    a = gcp_auth.resolve_auth(None, None)
    assert a.account == "ops@x.com" and a.account_source == "gcloud 当前活动账号"
    assert a.project == "dflt" and a.project_source == "gcloud 默认项目"
    assert a.creds.quota_project_id == "dflt"


def test_resolve_falls_back_to_adc_when_no_active_account(monkeypatch):
    _env(monkeypatch, active_account=None, default_project="dflt", adc=_FakeAdc("adcq"))
    a = gcp_auth.resolve_auth(None, None)
    assert a.account_source == "application-default 凭证" and a.project == "dflt"   # gcloud 默认项目优先
    assert a.creds.with_quota == "dflt"


def test_resolve_project_falls_back_to_adc_quota_project(monkeypatch):
    _env(monkeypatch, active_account="ops@x.com", default_project=None, adc=_FakeAdc("adcq"))
    a = gcp_auth.resolve_auth(None, None)
    assert a.account == "ops@x.com" and a.project == "adcq"
    assert a.project_source == "application-default 凭证的 quota 项目"


def test_resolve_no_login_anywhere_is_clear_error(monkeypatch):
    _env(monkeypatch, active_account=None, default_project="dflt", adc=None)
    with pytest.raises(gcp_auth.AuthConfigError) as e:
        gcp_auth.resolve_auth(None, None)
    assert "gcloud auth login" in str(e.value)


def test_resolve_no_project_anywhere_is_clear_error(monkeypatch):
    _env(monkeypatch, active_account="ops@x.com", default_project=None, adc=None)
    with pytest.raises(gcp_auth.AuthConfigError) as e:
        gcp_auth.resolve_auth(None, None)
    assert "gcloud config set project" in str(e.value)


def test_resolve_account_token_failure_is_clear_error(monkeypatch):
    _env(monkeypatch, active_account="ops@x.com", default_project="dflt", token_ok=False)
    with pytest.raises(gcp_auth.AuthConfigError) as e:
        gcp_auth.resolve_auth(None, None)
    assert "ops@x.com" in str(e.value) and "gcloud auth login" in str(e.value)


def test_resolve_explicit_project_wins_over_everything(monkeypatch):
    _env(monkeypatch, active_account=None, default_project="dflt", adc=_FakeAdc("adcq"))
    a = gcp_auth.resolve_auth(None, "qp")
    assert a.project == "qp" and a.creds.with_quota == "qp"
