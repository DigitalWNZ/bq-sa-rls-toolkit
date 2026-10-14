"""公共认证工具：支持 ADC 或指定 gcloud 账号。"""

import subprocess

import google.auth
from google.oauth2.credentials import Credentials

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_credentials(gcloud_account=None, quota_project=None):
    """
    gcloud_account 为空时使用 Application Default Credentials；
    否则使用 `gcloud auth print-access-token --account=<账号>` 获取的 token（约 1 小时有效）。
    """
    if gcloud_account:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token", f"--account={gcloud_account}"],
            text=True,
        ).strip()
        creds = Credentials(token=token, quota_project_id=quota_project)
    else:
        creds, _ = google.auth.default(scopes=SCOPES)
        if quota_project and hasattr(creds, "with_quota_project"):
            creds = creds.with_quota_project(quota_project)
    return creds
