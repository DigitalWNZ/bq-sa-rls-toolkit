"""
集成测试公共工具（独立于被测代码，直接使用 GCP 客户端库验证结果）。

需要环境变量:
  RLS_IT=1                 启用集成测试
  RLS_IT_PROJECT           测试项目
  RLS_IT_ACCOUNT           已 gcloud auth login 的执行账号（需 Owner + Cloud Identity Groups Admin）
  RLS_IT_DOMAIN            Cloud Identity 域名（group 邮箱后缀）
  RLS_IT_DATASET           可选，默认 rls_it（US）
  RLS_IT_ORG               可选，组织 ID；设置后运行组织级 SA 盘点用例（需 cloudasset API 与组织级查看权限）
"""

import os
import subprocess
import sys
import time

from google.api_core import exceptions as gexc
from google.auth import impersonated_credentials
from google.cloud import bigquery
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from googleapiclient.errors import HttpError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

ENABLED = os.environ.get("RLS_IT") == "1"
PROJECT = os.environ.get("RLS_IT_PROJECT", "")
ACCOUNT = os.environ.get("RLS_IT_ACCOUNT", "")
DOMAIN = os.environ.get("RLS_IT_DOMAIN", "")
DATASET = os.environ.get("RLS_IT_DATASET", "rls_it")
ORG = os.environ.get("RLS_IT_ORG", "")            # 可选：组织 ID，用于 Cloud Asset Inventory 的组织级用例
LOCATION = "US"

PREFIX = "rlsit"


def sa(account_id):
    return f"{account_id}@{PROJECT}.iam.gserviceaccount.com"


def grp(name):
    return f"{PREFIX}-{name}@{DOMAIN}"


def tbl(name):
    return f"{PROJECT}.{DATASET}.{name}"


# 测试身份
SA_API = sa(f"{PREFIX}-api")            # Copilot 后端 API SA
SA_ETL = sa(f"{PREFIX}-etl")            # 存量写入账号（数据集 WRITER）
SA_READER = sa(f"{PREFIX}-reader")      # 存量读取账号（表级 dataViewer）
SA_PROBE = sa(f"{PREFIX}-probe")        # Group 生效探针账号
SA_LATE = sa(f"{PREFIX}-late")          # 用于热修补白名单测试
SA_COP_HI = sa(f"{PREFIX}-cop-hi")      # Copilot 高权限 SA
SA_COP_LO = sa(f"{PREFIX}-cop-lo")      # Copilot 低权限 SA
SA_COP_NONE = sa(f"{PREFIX}-cop-none")  # Copilot SA，无行条件
FIXTURE_SAS = [SA_API, SA_ETL, SA_READER, SA_PROBE, SA_LATE]
COPILOT_PATTERN = f"{PREFIX}-cop-*@*"

G_WRITE = grp("full-write")
G_READ = grp("full-read")
G_HIGH = grp("copilot-high")
G_LOW = grp("copilot-low")
G_ALL = grp("copilot-all")

T_ORDERS = tbl("orders")
T_SENSITIVE = tbl("sensitive")
T_ALT = tbl("orders_alt")          # 列名/层级不同：area, ptype, meta.ref
T_PART = tbl("orders_part")        # 按 dt 分区且 require_partition_filter=TRUE（C1）
T_BADMAP = tbl("bad_mapping_t")    # 映射到不存在的列
T_CONFLICT = tbl("conflict_t")
T_NOBYPASS = tbl("no_bypass_t")
T_COND = tbl("adm_user_mem_copilot_condition")
T_MAPPING = tbl("adm_user_mem_copilot_tb_col_mapping")
T_GROUP = tbl("adm_user_mem_copilot_group")          # 表级权限组字典：id, group
T_GRANT = tbl("adm_user_mem_copilot_grant_tb")       # Group -> 表范围：group_id, table_name
T_BIND = tbl("adm_user_mem_copilot_user_bind")       # 用户绑定：id, role_id, condition_id, group_id
T_ACL = tbl("adm_user_mem_copilot_acl_group_sa")     # 全量白名单名册：sa, acl_group

# region, prd_type, refername, amount
ROWS = [("HK", "P1", "REF_A", 1), ("HK", "P2", "REF_B", 2), ("SG", "P2", "REF_A", 3),
        ("US", "P1", "REF_A", 4), ("US", "P3", "REF_C", 5), ("SG", "P1", "REF_C", 6)]
ALL_AMOUNTS = sorted(r[3] for r in ROWS)


# --------------------------------------------------------------------------- #
# 认证
# --------------------------------------------------------------------------- #
_admin = {}


def admin_creds():
    tok = _admin.get("tok")
    if not tok or time.time() - _admin["t"] > 1800:
        tok = subprocess.check_output(
            ["gcloud", "auth", "print-access-token", f"--account={ACCOUNT}"], text=True).strip()
        _admin.update(tok=tok, t=time.time())
    return Credentials(token=tok, quota_project_id=PROJECT)


def impersonate(target, delegates=()):
    return impersonated_credentials.Credentials(
        source_credentials=admin_creds(), target_principal=target,
        delegates=list(delegates), target_scopes=SCOPES, lifetime=3600)


def bq(creds=None):
    return bigquery.Client(project=PROJECT, credentials=creds or admin_creds())


def api(name, version):
    return discovery.build(name, version, credentials=admin_creds(), cache_discovery=False)


def query(creds, sql):
    client = bq(creds)
    job = client.query(sql, location=LOCATION)
    return job, list(job.result())


def amounts(creds, table):
    job, rows = query(creds, f"SELECT amount FROM `{table}` ORDER BY amount")
    return job, [r.amount for r in rows]


# --------------------------------------------------------------------------- #
# 等待 / 重试
# --------------------------------------------------------------------------- #
def eventually(fn, timeout=600, interval=15, desc=""):
    """反复调用 fn 直到不抛异常（AssertionError 或 API 错误），超时则抛出最后一次异常。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last = e
            print(f"  [eventually:{desc}] {type(e).__name__}: {str(e)[:160]}", file=sys.stderr)
            time.sleep(interval)
    raise last


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def run_cli(script, *args, timeout=1500):
    cmd = [sys.executable, os.path.join(ROOT, script), "--gcloud-account", ACCOUNT, *args]
    print("\n$ " + " ".join(cmd), file=sys.stderr)
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=timeout)
    out = p.stdout + p.stderr
    print(out, file=sys.stderr)
    return p.returncode, out


# --------------------------------------------------------------------------- #
# 独立的验证工具
# --------------------------------------------------------------------------- #
def policies(table):
    """{policy_id: {"filter":..., "grantees": set()}}"""
    p, d, t = table.split(".")
    bqapi = api("bigquery", "v2")
    resp = bqapi.rowAccessPolicies().list(projectId=p, datasetId=d, tableId=t).execute()
    out = {}
    for item in resp.get("rowAccessPolicies", []):
        pid = item["rowAccessPolicyReference"]["policyId"]
        res = f"projects/{p}/datasets/{d}/tables/{t}/rowAccessPolicies/{pid}"
        iam = bqapi.rowAccessPolicies().getIamPolicy(resource=res, body={}).execute()
        grantees = {m.lower() for b in iam.get("bindings", []) for m in b.get("members", [])
                    if b.get("role") == "roles/bigquery.filteredDataViewer"}
        out[pid] = {"filter": item.get("filterPredicate"), "grantees": grantees}
    return out


def table_role_members(table, role="roles/bigquery.dataViewer"):
    pol = bq().get_iam_policy(table)
    return {m.lower() for b in pol.bindings if b["role"] == role for m in b["members"]}


def project_role_members(role):
    pol = api("cloudresourcemanager", "v1").projects().getIamPolicy(
        resource=PROJECT, body={}).execute()
    return {m.lower() for b in pol.get("bindings", []) if b["role"] == role
            for m in b.get("members", [])}


def sa_role_members(sa_email, role):
    pol = api("iam", "v1").projects().serviceAccounts().getIamPolicy(
        resource=f"projects/{PROJECT}/serviceAccounts/{sa_email}").execute()
    return {m.lower() for b in pol.get("bindings", []) if b["role"] == role
            for m in b.get("members", [])}


def sa_exists(sa_email):
    try:
        api("iam", "v1").projects().serviceAccounts().get(
            name=f"projects/{PROJECT}/serviceAccounts/{sa_email}").execute()
        return True
    except HttpError as e:
        if e.resp.status == 404:
            return False
        raise


def group_members(group_email):
    ci = api("cloudidentity", "v1")
    try:
        name = ci.groups().lookup(groupKey_id=group_email).execute()["name"]
    except HttpError as e:
        if e.resp.status in (403, 404):
            return None
        raise
    resp = ci.groups().memberships().list(parent=name, pageSize=200).execute()
    return {m["preferredMemberKey"]["id"].lower() for m in resp.get("memberships", [])}


def set_group_member(group_email, member_email, present):
    """加入 / 移除 group 成员（独立于被测代码）。"""
    ci = api("cloudidentity", "v1")
    name = ci.groups().lookup(groupKey_id=group_email).execute()["name"]
    if present:
        try:
            ci.groups().memberships().create(
                parent=name, body={"preferredMemberKey": {"id": member_email},
                                   "roles": [{"name": "MEMBER"}]}).execute()
        except HttpError as e:
            if e.resp.status != 409:
                raise
    else:
        try:
            resp = ci.groups().memberships().lookup(parent=name, memberKey_id=member_email).execute()
            ci.groups().memberships().delete(name=resp["name"]).execute()
        except HttpError as e:
            if e.resp.status != 404:      # 本来就不在组里
                raise


def is_forbidden(e):
    return isinstance(e, (gexc.Forbidden, gexc.NotFound)) or "Access Denied" in str(e)
