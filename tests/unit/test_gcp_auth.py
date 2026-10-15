"""gcp_auth 的单元测试：gcloud 账号凭证可自动刷新（E6）。"""

import datetime

import gcp_auth


class _Req:  # google.auth 的 refresh(request) 不会用到
    pass


def test_gcloud_credentials_refresh_calls_gcloud_and_sets_expiry(monkeypatch):
    calls = []

    def fake_check_output(cmd, text=True, **kw):
        calls.append(cmd)
        return f"tok-{len(calls)}\n"
    monkeypatch.setattr(gcp_auth.subprocess, "check_output", fake_check_output)

    creds = gcp_auth.GcloudCredentials("ops@x.com", quota_project_id="p")
    assert creds.token is None and not creds.valid
    creds.refresh(_Req())
    assert creds.token == "tok-1" and creds.valid
    assert calls[0][:3] == ["gcloud", "auth", "print-access-token"] and "--account=ops@x.com" in calls[0]
    assert creds.quota_project_id == "p"
    # 到期后 valid 为 False，再次 refresh 会重新调用 gcloud 拿新 token
    creds.expiry = datetime.datetime.utcnow() - datetime.timedelta(seconds=1)
    assert not creds.valid
    creds.refresh(_Req())
    assert creds.token == "tok-2" and len(calls) == 2


def test_get_credentials_returns_refreshable_for_gcloud_account(monkeypatch):
    monkeypatch.setattr(gcp_auth.subprocess, "check_output", lambda *a, **k: "tok\n")
    creds = gcp_auth.get_credentials("ops@x.com", "p")
    assert isinstance(creds, gcp_auth.GcloudCredentials)
    assert creds.quota_project_id == "p"


def test_with_quota_project_keeps_account(monkeypatch):
    monkeypatch.setattr(gcp_auth.subprocess, "check_output", lambda *a, **k: "tok\n")
    c2 = gcp_auth.GcloudCredentials("ops@x.com").with_quota_project("q")
    assert c2.quota_project_id == "q" and c2._account == "ops@x.com"
