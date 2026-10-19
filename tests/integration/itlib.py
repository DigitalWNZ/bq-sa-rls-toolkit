"""
集成测试公共工具（独立于被测代码，直接使用 GCP 客户端库准备环境和验证结果）。

需要环境变量:
  RLS_IT=1                 启用集成测试
  RLS_IT_PROJECT           测试项目（如 rls-testing-harrishe）
  RLS_IT_ACCOUNT           已 gcloud auth login 的执行账号（需项目 Owner + Cloud Identity Groups 管理员）
  RLS_IT_DOMAIN            Cloud Identity 域名（Group 邮箱后缀）
  RLS_IT_ORG               可选，组织 ID；设置后运行组织范围的 list_principals 用例（需组织级 roles/browser、roles/iam.securityReviewer、roles/bigquery.metadataViewer，及 Workspace 读用户权限）
  RLS_IT_CLEANUP           可选，=1 时测试结束删除测试数据集（默认保留；SA 与 Group 始终保留）
"""

import os
import subprocess
import sys
import threading
import time

from google.auth import impersonated_credentials
from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from gcp_auth import GcloudCredentials

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

ENABLED = os.environ.get("RLS_IT") == "1"
PROJECT = os.environ.get("RLS_IT_PROJECT", "")
ACCOUNT = os.environ.get("RLS_IT_ACCOUNT", "").lower()
DOMAIN = os.environ.get("RLS_IT_DOMAIN", "")
ORG = os.environ.get("RLS_IT_ORG", "")
LOCATION = "US"
PREFIX = "rlsit"

DATASET = "rls_it"                  # 业务表
AUTH_DATASET = "rls_it_auth"        # 条件表 / 映射表 / 登记表（不能挂 RLS，否则 Copilot 子查询读不到）
NB_DATASET = "rls_it_nobypass"      # 没有 bypass 规则的表（验证 copilot 不再要求 bypass）


def sa(account_id):
    return f"{account_id}@{PROJECT}.iam.gserviceaccount.com"


def grp(name):
    return f"{PREFIX}-{name}@{DOMAIN}"


def tbl(name, dataset=DATASET):
    return f"{PROJECT}.{dataset}.{name}"


# 测试身份
SA_ETL = sa(f"{PREFIX}-etl")            # 存量写账号（Writable Group 成员）
SA_READER = sa(f"{PREFIX}-reader")      # 存量读账号（ReadOnly Group 成员）
SA_ACL = sa(f"{PREFIX}-acl")            # 只通过数据集 ACL 里的 Group 获得权限
SA_COP_A = sa(f"{PREFIX}-cop-a")        # Copilot：region = ['HK']
SA_COP_B = sa(f"{PREFIX}-cop-b")        # Copilot：全部维度为空（全部可见）
SA_COP_N = sa(f"{PREFIX}-cop-n")        # Copilot：一开始不在条件表中
ALL_SAS = [SA_ETL, SA_READER, SA_ACL, SA_COP_A, SA_COP_B, SA_COP_N]

G_READ = grp("existingsa-read")
G_WRITE = grp("existingsa-write")
G_ACL = grp("acl")                      # 数据集 ACL 里授权的 Group，成员 SA_ACL
G_COPILOT = grp("copilot")              # Copilot Group：SA_COP_A / B / N 与执行账号；每张表一条规则授权给它

T_ORDERS = tbl("orders")                # region, prd_type, refername, amount
T_ALT = tbl("orders_alt")               # 列名不同：market, ptype, meta.ref
T_PART = tbl("orders_part")             # 按 dt 分区且必须带分区过滤
T_BADMAP = tbl("bad_mapping_t")         # 映射到不存在的列
T_NOMAP = tbl("no_mapping_t")           # 映射表里没有（Copilot 不处理）
T_NOBYPASS = tbl("no_bypass_t", NB_DATASET)
TARGET_TABLES = [T_ORDERS, T_ALT, T_PART, T_BADMAP, T_NOMAP]
T_COND = tbl("adm_user_mem_copilot_condition", AUTH_DATASET)
T_MAPPING = tbl("adm_user_mem_copilot_tb_col_mapping", AUTH_DATASET)
T_MAPPING_NB = tbl("mapping_nobypass", AUTH_DATASET)
T_REGISTRY = tbl("adm_user_mem_copilot_tb", AUTH_DATASET)   # apply_bypass_rls.py 的登记表
T_DISABLED = tbl("rls_disabled_t")      # 登记表中 rls_enabled = 0：apply_bypass 必须跳过

# region, prd_type, refername, amount
ROWS = [("HK", "P1", "REF_A", 1), ("HK", "P2", "REF_B", 2), ("SG", "P2", "REF_A", 3),
        ("US", "P1", "REF_A", 4), ("US", "P3", "REF_C", 5), ("SG", "P1", "REF_C", 6)]
ALL_AMOUNTS = sorted(r[3] for r in ROWS)
HK, SG, US = [1, 2], [3, 6], [4, 5]


# --------------------------------------------------------------------------- #
# 认证 / 客户端
# --------------------------------------------------------------------------- #
_admin = {}
_tls = threading.local()


def admin_creds():
    """可自动刷新的 gcloud 账号凭证（与被测脚本同一套实现，线程安全）。"""
    if "creds" not in _admin:
        _admin["creds"] = GcloudCredentials(ACCOUNT, quota_project_id=PROJECT)
    return _admin["creds"]


def impersonate(target):
    return impersonated_credentials.Credentials(
        source_credentials=admin_creds(), target_principal=target, target_scopes=SCOPES, lifetime=3600)


def bq(creds=None):
    if creds is not None:
        return bigquery.Client(project=PROJECT, credentials=creds)
    if getattr(_tls, "bq", None) is None:                 # 每线程一个客户端
        _tls.bq = bigquery.Client(project=PROJECT, credentials=admin_creds())
    return _tls.bq


def api(name, version):
    """googleapiclient 不是线程安全的：每线程各建一份。"""
    cache = getattr(_tls, "api", None)
    if cache is None:
        cache = _tls.api = {}
    key = f"{name}/{version}"
    if key not in cache:
        import google_auth_httplib2
        import httplib2
        http = google_auth_httplib2.AuthorizedHttp(admin_creds(), http=httplib2.Http(timeout=120))
        cache[key] = discovery.build(name, version, http=http, cache_discovery=False)
    return cache[key]


def run_sql(sql, creds=None):
    return list(bq(creds).query(sql, location=LOCATION).result())


def amounts(who, table):
    """以 who（SA 邮箱，或 ACCOUNT 本人）身份查表，返回可见的 amount 列表。"""
    creds = admin_creds() if who == ACCOUNT else impersonate(who)
    where = " WHERE dt IS NOT NULL" if table == T_PART else ""
    return [r.amount for r in run_sql(f"SELECT amount FROM `{table}`{where} ORDER BY amount", creds)]


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
            print(f"  [eventually:{desc}] {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
            time.sleep(interval)
    raise last


def expect_amounts(who, table, expected, timeout=600):
    def check():
        got = amounts(who, table)
        assert got == expected, f"{who} @ {table}: 期望 {expected}，实际 {got}"
        return got
    return eventually(check, timeout=timeout, interval=15, desc=f"{who.split('@')[0]}@{table.split('.')[-1]}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def run_cli(script, *args, timeout=1800, env=None, auto_auth=False):
    """
    运行脚本。默认显式传入 --gcloud-account ACCOUNT 和 --quota-project PROJECT（与运行机器的 gcloud 配置无关）；
    auto_auth=True 时两者都不传，验证脚本按 gcloud 当前活动账号 / 默认项目自动确定。
    """
    extra = [] if auto_auth else ["--gcloud-account", ACCOUNT] + ([] if "--quota-project" in args else ["--quota-project", PROJECT])
    cmd = [sys.executable, os.path.join(ROOT, script), *extra, *args]
    print("\n$ " + " ".join(cmd), file=sys.stderr)
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=timeout,
                       env={**os.environ, **env} if env else None)
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


# --------------------------------------------------------------------------- #
# 环境准备（独立于被测代码）
# --------------------------------------------------------------------------- #
def ensure_group(group_email, customer):
    ci = api("cloudidentity", "v1")
    try:
        ci.groups().lookup(groupKey_id=group_email).execute()
        return
    except HttpError as e:
        if e.resp.status not in (403, 404):
            raise
    ci.groups().create(initialGroupConfig="EMPTY", body={
        "groupKey": {"id": group_email}, "parent": f"customers/{customer}",
        "labels": {"cloudidentity.googleapis.com/groups.discussion_forum": ""}}).execute()


def set_group_member(group_email, member_email):
    ci = api("cloudidentity", "v1")
    name = ci.groups().lookup(groupKey_id=group_email).execute()["name"]
    try:
        ci.groups().memberships().create(
            parent=name, body={"preferredMemberKey": {"id": member_email},
                               "roles": [{"name": "MEMBER"}]}).execute()
    except HttpError as e:
        if e.resp.status != 409:
            raise


def customer_id():
    crm = api("cloudresourcemanager", "v1")
    org = [a for a in crm.projects().getAncestry(projectId=PROJECT, body={}).execute()["ancestor"]
           if a["resourceId"]["type"] == "organization"][0]["resourceId"]["id"]
    return crm.organizations().get(name=f"organizations/{org}").execute()["owner"]["directoryCustomerId"]
