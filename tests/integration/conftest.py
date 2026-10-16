"""集成测试环境准备：数据集、表、权限表、映射表、存量账号（fixture SA）及其权限。"""

import sys

import pytest
from googleapiclient.errors import HttpError

from tests.integration import itlib as L

if not L.ENABLED:
    collect_ignore_glob = ["test_*.py"]


def _log(msg):
    print(f"[setup] {msg}", file=sys.stderr)


def _values_sql():
    return ", ".join(
        f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)"
        for r, p, f, a in L.ROWS)


def _create_tables():
    client = L.bq()
    from google.cloud import bigquery
    ds = bigquery.Dataset(f"{L.PROJECT}.{L.DATASET}")
    ds.location = L.LOCATION
    client.create_dataset(ds, exists_ok=True)
    for t in (L.T_ORDERS, L.T_SENSITIVE, L.T_CONFLICT, L.T_NOBYPASS, L.T_BADMAP):
        # CREATE OR REPLACE 会同时清掉旧的 RLS 和表级 IAM，保证每次测试从干净状态开始
        client.query(f"CREATE OR REPLACE TABLE `{t}` AS SELECT * FROM UNNEST([{_values_sql()}])",
                     location=L.LOCATION).result()
    # 分区表：按 dt 分区且必须带分区过滤（验证 C1 自动加分区条件）
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_PART}`
        PARTITION BY dt OPTIONS (require_partition_filter = TRUE) AS
        SELECT DATE '2026-01-01' AS dt, * FROM UNNEST([{_values_sql()}])""",
                 location=L.LOCATION).result()
    # 异构表：同样的数据，列名不同且 refername 在嵌套字段里
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_ALT}` AS
        SELECT region AS area, prd_type AS ptype,
               STRUCT(refername AS ref, amount * 10 AS code) AS meta, amount
        FROM UNNEST([{_values_sql()}])""", location=L.LOCATION).result()
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_COND}`
        (id STRING, sa STRING, region ARRAY<STRING>, prdtype ARRAY<STRING>, refername ARRAY<STRING>)
        CLUSTER BY sa""", location=L.LOCATION).result()
    client.query(f"""
        INSERT INTO `{L.T_COND}` (id, sa, region, prdtype, refername) VALUES
          ('c1', '{L.SA_COP_HI}', ['HK', 'SG'], [], ['REF_A']),
          ('c2', '{L.SA_COP_LO}', [], ['P1'], [])""", location=L.LOCATION).result()
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_MAPPING}` AS
        SELECT * FROM UNNEST([
          STRUCT('{L.T_ORDERS}' AS table_name, 'region' AS col_name, 'region' AS to_name),
          STRUCT('{L.T_ORDERS}', 'prd_type', 'prdtype'),
          STRUCT('{L.T_ORDERS}', 'refername', 'refername'),
          STRUCT('{L.T_SENSITIVE}', 'region', 'region'),
          STRUCT('{L.T_ALT}', 'area', 'region'),
          STRUCT('{L.T_ALT}', 'ptype', 'prdtype'),
          STRUCT('{L.T_ALT}', 'meta.ref', 'refername'),
          STRUCT('{L.T_BADMAP}', 'missing_col', 'region'),
          STRUCT('{L.T_NOBYPASS}', 'region', 'region')])""", location=L.LOCATION).result()
    # 其余权限表（文档 8 张表中脚本会用到的）：表级权限组字典、Group 授权范围、用户绑定、白名单名册
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_GROUP}` AS
        SELECT * FROM UNNEST([STRUCT('g1' AS id, '{L.G_HIGH}' AS `group`),
                              STRUCT('g2', '{L.G_LOW}')])""", location=L.LOCATION).result()
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_GRANT}` AS
        SELECT * FROM UNNEST([STRUCT('g1' AS group_id, '{L.T_ORDERS}' AS table_name),
                              STRUCT('g1', '{L.T_SENSITIVE}'), STRUCT('g1', '{L.T_ALT}'),
                              STRUCT('g2', '{L.T_ORDERS}'), STRUCT('g2', '{L.T_ALT}')])""",
                 location=L.LOCATION).result()
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_BIND}` AS
        SELECT * FROM UNNEST([STRUCT('b1' AS id, 'r1' AS role_id, 'c1' AS condition_id, 'g1' AS group_id),
                              STRUCT('b2', 'r1', 'c2', 'g2')])""", location=L.LOCATION).result()
    client.query(f"""
        CREATE OR REPLACE TABLE `{L.T_ACL}` AS
        SELECT * FROM UNNEST([STRUCT('{L.SA_ETL}' AS sa, '{L.G_WRITE}' AS acl_group),
                              STRUCT('{L.SA_READER}', 'full_read')])""", location=L.LOCATION).result()


def _create_authorized_view():
    from google.cloud import bigquery
    client = L.bq()
    ds = bigquery.Dataset(f"{L.PROJECT}.{L.VIEW_DATASET}")
    ds.location = L.LOCATION
    client.create_dataset(ds, exists_ok=True)
    client.query(f"CREATE OR REPLACE VIEW `{L.T_VIEW}` AS SELECT * FROM `{L.T_ORDERS}`",
                 location=L.LOCATION).result()
    src = client.get_dataset(f"{L.PROJECT}.{L.DATASET}")
    ref = {"projectId": L.PROJECT, "datasetId": L.VIEW_DATASET, "tableId": "v_orders"}
    if not any(e.entity_type == "view" and e.entity_id == ref for e in src.access_entries):
        src.access_entries = list(src.access_entries) + [bigquery.AccessEntry(None, "view", ref)]
        L.eventually(lambda: client.update_dataset(src, ["access_entries"]),
                     timeout=300, interval=10, desc="authorize view")


def _ensure_sa(email):
    iam = L.api("iam", "v1")
    account_id = email.split("@")[0]
    try:
        iam.projects().serviceAccounts().create(
            name=f"projects/{L.PROJECT}",
            body={"accountId": account_id, "serviceAccount": {"displayName": account_id}}).execute()
        _log(f"创建 SA {email}")
    except HttpError as e:
        if e.resp.status != 409:
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
                 lambda pol: iam.setIamPolicy(resource=res, body={"policy": pol}).execute(),
                 role, member)


def _project_binding(role, member):
    crm = L.api("cloudresourcemanager", "v1").projects()
    _add_binding(lambda: crm.getIamPolicy(resource=L.PROJECT, body={}).execute(),
                 lambda pol: crm.setIamPolicy(resource=L.PROJECT, body={"policy": pol}).execute(),
                 role, member)


def _table_viewer(table, member):
    client = L.bq()

    def op():
        pol = client.get_iam_policy(table)
        pol.bindings.append({"role": "roles/bigquery.dataViewer", "members": {member}})
        client.set_iam_policy(table, pol)
    L.eventually(op, timeout=300, interval=10, desc=f"table viewer {member}")


def _dataset_writer(email):
    from google.cloud import bigquery
    client = L.bq()
    ds = client.get_dataset(f"{L.PROJECT}.{L.DATASET}")
    if any(e.entity_id == email and e.role == "WRITER" for e in ds.access_entries):
        return
    ds.access_entries = list(ds.access_entries) + [
        bigquery.AccessEntry("WRITER", "userByEmail", email)]
    L.eventually(lambda: client.update_dataset(ds, ["access_entries"]),
                 timeout=300, interval=10, desc="dataset writer")


@pytest.fixture(scope="session")
def world():
    _log("建表 ...")
    _create_tables()
    for email in L.FIXTURE_SAS:
        _ensure_sa(email)
    admin = f"user:{L.ACCOUNT}"
    for email in L.FIXTURE_SAS:
        # 测试执行账号可直接扮演 fixture SA（存量账号 / API SA / 探针）
        _sa_binding(email, "roles/iam.serviceAccountTokenCreator", admin)
    for email in L.FIXTURE_SAS:
        _project_binding("roles/bigquery.jobUser", f"serviceAccount:{email}")
    _dataset_writer(L.SA_ETL)                              # 存量写：数据集级 WRITER
    for t in (L.T_ORDERS, L.T_SENSITIVE, L.T_PART):
        _table_viewer(t, f"serviceAccount:{L.SA_READER}")  # 存量读：表级 dataViewer
    # 等待扮演与权限生效
    L.eventually(lambda: L.query(L.impersonate(L.SA_ETL), f"SELECT 1 FROM `{L.T_ORDERS}` LIMIT 1"),
                 desc="etl ready")
    L.eventually(lambda: L.query(L.impersonate(L.SA_READER), f"SELECT 1 FROM `{L.T_ORDERS}` LIMIT 1"),
                 desc="reader ready")
    # 授权视图：另一个数据集里的视图读 orders，被 rls_it 授权；late 只有视图的读权限（R1）
    _create_authorized_view()
    _table_viewer(L.T_VIEW, f"serviceAccount:{L.SA_LATE}")
    # 嵌套组：业务组里有 Copilot SA，验证白名单的嵌套组防护（P0）
    L.ensure_group(L.G_NESTED)
    L.eventually(lambda: L.set_group_member(L.G_NESTED, L.SA_COP_HI, True), timeout=300, interval=15,
                 desc="nested group member")
    _log("环境就绪")
    return {}
