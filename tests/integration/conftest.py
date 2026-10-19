"""集成测试环境准备：数据集、业务表、条件表、映射表、测试 SA、Group 及其权限。"""

import os
import sys
import time

import pytest
from google.cloud import bigquery
from googleapiclient.errors import HttpError

from tests.integration import itlib as L

if not L.ENABLED:
    collect_ignore_glob = ["test_*.py"]


def _log(msg):
    print(f"[setup] {msg}", file=sys.stderr)


def _values_sql():
    return ", ".join(f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)"
                     for r, p, f, a in L.ROWS)


def _q(sql):
    L.bq().query(sql, location=L.LOCATION).result()


def _create_tables():
    client = L.bq()
    for ds_id in (L.DATASET, L.AUTH_DATASET, L.NB_DATASET):
        ds = bigquery.Dataset(f"{L.PROJECT}.{ds_id}")
        ds.location = L.LOCATION
        client.create_dataset(ds, exists_ok=True)
    # CREATE OR REPLACE 会同时清掉旧的 RLS，保证每次从干净状态开始
    for t in (L.T_ORDERS, L.T_BADMAP, L.T_NOMAP, L.T_NOBYPASS, L.T_DISABLED):
        _q(f"CREATE OR REPLACE TABLE `{t}` AS SELECT * FROM UNNEST([{_values_sql()}])")
    _q(f"""CREATE OR REPLACE TABLE `{L.T_ALT}` AS
           SELECT region AS market, prd_type AS ptype, STRUCT(refername AS ref) AS meta, amount
           FROM UNNEST([{_values_sql()}])""")
    _q(f"""CREATE OR REPLACE TABLE `{L.T_PART}` PARTITION BY dt OPTIONS (require_partition_filter = TRUE) AS
           SELECT DATE '2026-01-01' AS dt, * FROM UNNEST([{_values_sql()}])""")
    _q(f"""CREATE OR REPLACE TABLE `{L.T_COND}`
           (id STRING, sa STRING, region ARRAY<STRING>, prdtype ARRAY<STRING>, refername ARRAY<STRING>)
           CLUSTER BY sa""")
    _q(f"""INSERT INTO `{L.T_COND}` (id, sa, region, prdtype, refername) VALUES
           ('c1', '{L.SA_COP_A}', ['HK'], [], []),
           ('c2', '{L.SA_COP_B}', [], [], []),
           ('c3', '{L.ACCOUNT}', ['SG'], [], [])""")
    _q(f"""CREATE OR REPLACE TABLE `{L.T_MAPPING}` AS SELECT * FROM UNNEST([
           STRUCT('{L.T_ORDERS}' AS table_name, 'region' AS col_name, 'region' AS to_name),
           STRUCT('{L.T_ORDERS}', 'prd_type', 'prdtype'),
           STRUCT('{L.T_ORDERS}', 'refername', 'refername'),
           STRUCT('{L.T_ORDERS}', 'whatever', 'not_a_dimension'),
           STRUCT('{L.T_ALT}', 'market', 'region'),
           STRUCT('{L.T_ALT}', 'ptype', 'prdtype'),
           STRUCT('{L.T_ALT}', 'meta.ref', 'refername'),
           STRUCT('{L.T_PART}', 'region', 'region'),
           STRUCT('{L.T_BADMAP}', 'missing_col', 'region'),
           STRUCT('{L.T_COND}', 'sa', 'region')])""")         # 误配：条件表自身，应被排除
    _q(f"""CREATE OR REPLACE TABLE `{L.T_MAPPING_NB}` AS SELECT * FROM UNNEST([
           STRUCT('{L.T_NOBYPASS}' AS table_name, 'region' AS col_name, 'region' AS to_name)])""")
    # apply_bypass_rls.py 的登记表（与客户 trip-bq-admin.bq_auth.adm_user_mem_copilot_tb 同结构）
    _q(f"""CREATE OR REPLACE TABLE `{L.T_REGISTRY}` (
           id STRING NOT NULL, table_name STRING NOT NULL, rls_enabled INT64 NOT NULL, status INT64 NOT NULL,
           create_time TIMESTAMP NOT NULL, update_time TIMESTAMP NOT NULL)""")
    enabled = [L.T_ORDERS, L.T_ALT, L.T_PART, L.T_BADMAP, L.T_NOMAP, L.T_NOBYPASS]
    rows = [(t, 1, 1) for t in enabled] + [
        (L.T_NOMAP, 1, 0),                       # 软删除的重复行（rls_enabled 相同）：不看 status，仍为开启
        (L.T_DISABLED, 0, 1),                    # 未开启
        (L.T_COND, 0, 1), (L.T_MAPPING, 0, 1),   # 客户把条件表 / 映射表登记为未开启（T_MAPPING_NB、登记表自身未登记）
    ]
    values = ",\n".join(f"(GENERATE_UUID(), '{t}', {on}, {st}, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())"
                        for t, on, st in rows)
    _q(f"INSERT INTO `{L.T_REGISTRY}` (id, table_name, rls_enabled, status, create_time, update_time) VALUES\n{values}")


def _ensure_sa(email):
    iam = L.api("iam", "v1")
    try:
        iam.projects().serviceAccounts().get(name=f"projects/{L.PROJECT}/serviceAccounts/{email}").execute()
        return
    except HttpError as e:
        if e.resp.status != 404:
            raise
    for attempt in range(8):
        try:
            iam.projects().serviceAccounts().create(
                name=f"projects/{L.PROJECT}",
                body={"accountId": email.split("@")[0], "serviceAccount": {"displayName": email.split("@")[0]}}).execute()
            _log(f"创建 SA {email}")
            return
        except HttpError as e:
            if e.resp.status == 409:
                return
            if e.resp.status == 429 and attempt < 7:          # SA 创建每分钟配额（与其他测试并行时会碰到）
                time.sleep(30)
                continue
            raise


def _add_binding(get, set_, role, member):
    def op():
        pol = get()
        for b in pol.setdefault("bindings", []):
            if b["role"] == role:
                if member in b["members"]:
                    return
                b["members"].append(member)
                break
        else:
            pol["bindings"].append({"role": role, "members": [member]})
        set_(pol)
    L.eventually(op, timeout=300, interval=10, desc=f"bind {role} {member}")


def _sa_binding(sa_email, role, member):
    iam = L.api("iam", "v1").projects().serviceAccounts()
    res = f"projects/{L.PROJECT}/serviceAccounts/{sa_email}"
    _add_binding(lambda: iam.getIamPolicy(resource=res).execute(),
                 lambda pol: iam.setIamPolicy(resource=res, body={"policy": pol}).execute(), role, member)


def _project_binding(role, member):
    crm = L.api("cloudresourcemanager", "v1").projects()
    _add_binding(lambda: crm.getIamPolicy(resource=L.PROJECT, body={}).execute(),
                 lambda pol: crm.setIamPolicy(resource=L.PROJECT, body={"policy": pol}).execute(), role, member)


def _dataset_access(ds_id, entries):
    """entries: [(role, entity_type, entity_id)]，已存在的跳过。"""
    client = L.bq()

    def op():
        ds = client.get_dataset(f"{L.PROJECT}.{ds_id}")
        have = {(e.role, e.entity_type, e.entity_id) for e in ds.access_entries}
        add = [bigquery.AccessEntry(r, t, i) for r, t, i in entries if (r, t, i) not in have]
        if add:
            ds.access_entries = list(ds.access_entries) + add
            client.update_dataset(ds, ["access_entries"])
    L.eventually(op, timeout=300, interval=10, desc=f"dataset access {ds_id}")


@pytest.fixture(scope="session")
def world():
    _log("建表 ...")
    _create_tables()
    for email in L.ALL_SAS:
        _ensure_sa(email)
    admin = f"user:{L.ACCOUNT}"
    for email in L.ALL_SAS:
        _sa_binding(email, "roles/iam.serviceAccountTokenCreator", admin)    # 测试账号可扮演
        _project_binding("roles/bigquery.jobUser", f"serviceAccount:{email}")
    customer = L.customer_id()
    for g in (L.G_READ, L.G_WRITE, L.G_ACL, L.G_COPILOT):
        L.ensure_group(g, customer)
    members = [(L.G_READ, L.SA_READER), (L.G_WRITE, L.SA_ETL), (L.G_ACL, L.SA_ACL)]
    members += [(L.G_COPILOT, m) for m in (L.SA_COP_A, L.SA_COP_B, L.SA_COP_N, L.ACCOUNT)]
    for g, m in members:
        L.eventually(lambda g=g, m=m: L.set_group_member(g, m), timeout=300, interval=15, desc=f"member {m}")
    # 业务数据集：存量读 / 写账号、Copilot 账号的读权限；ACL 里授权一个 Group（list_principals 要展开它）
    readers = [L.SA_READER, L.SA_COP_A, L.SA_COP_B, L.SA_COP_N]
    _dataset_access(L.DATASET, [("READER", "userByEmail", e) for e in readers]
                    + [("WRITER", "userByEmail", L.SA_ETL), ("READER", "groupByEmail", L.G_ACL)])
    # 条件表所在数据集：Copilot Group 需要读条件表（RLS 子查询以查询者身份执行）
    _dataset_access(L.AUTH_DATASET, [("READER", "groupByEmail", L.G_COPILOT)])
    for who in (L.SA_READER, L.SA_ETL, L.SA_COP_A):
        L.eventually(lambda who=who: L.amounts(who, L.T_ORDERS), desc=f"{who} ready")
    _log("环境就绪")
    yield {}
    # 默认保留测试数据集、SA 与 Group，便于事后查看；下次运行会重建表、清掉旧规则。设置 RLS_IT_CLEANUP=1 才删除数据集
    if os.environ.get("RLS_IT_CLEANUP") == "1":
        _log("清理数据集（SA 与 Group 保留）")
        for ds_id in (L.DATASET, L.AUTH_DATASET, L.NB_DATASET):
            L.bq().delete_dataset(f"{L.PROJECT}.{ds_id}", delete_contents=True, not_found_ok=True)
