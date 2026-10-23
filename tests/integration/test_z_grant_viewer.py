"""
真实环境：grant_table_viewer.py（给 Group 统一授予表级 BigQuery Data Viewer）。
在 test_z_abnormal.py 之后运行；使用独立的表 rls_it_nobypass.viewer_t 与测试 Group rlsit-viewer（成员 SA_ETL，
它对 rls_it_nobypass 数据集本来没有读权限），用完撤销授权并删除表。
"""

import pytest
from google.api_core.exceptions import Forbidden

import rls_core as core
from tests.integration import itlib as L

pytestmark = pytest.mark.integration

T_VIEW = L.tbl("viewer_t", L.NB_DATASET)
G_VIEW = L.grp("viewer")
OTHER = ("roles/bigquery.metadataViewer", f"serviceAccount:{L.SA_ACL}")   # 表上原有的其它授权，必须保留


def table_policy(t):
    p, d, n = t.split(".")
    return L.api("bigquery", "v2").tables().getIamPolicy(
        resource=f"projects/{p}/datasets/{d}/tables/{n}", body={}).execute()


def set_policy(t, policy):
    p, d, n = t.split(".")
    L.api("bigquery", "v2").tables().setIamPolicy(
        resource=f"projects/{p}/datasets/{d}/tables/{n}", body={"policy": policy}).execute()


def members(t, role=core.VIEWER_ROLE):
    return {m.lower() for b in table_policy(t).get("bindings", []) if b["role"] == role and not b.get("condition")
            for m in b["members"]}


def strip_group(t):
    pol = table_policy(t)
    for b in pol.get("bindings", []):
        b["members"] = [m for m in b["members"] if m.lower() != f"group:{G_VIEW}"]
    pol["bindings"] = [b for b in pol.get("bindings", []) if b["members"]]
    set_policy(t, pol)


def grant(*args):
    return L.run_cli("grant_table_viewer.py", *args)


@pytest.fixture(scope="module")
def gv(world):
    values = ", ".join(f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)" for r, p, f, a in L.ROWS)
    L.run_sql(f"CREATE OR REPLACE TABLE `{T_VIEW}` AS SELECT * FROM UNNEST([{values}])")
    pol = table_policy(T_VIEW)
    pol.setdefault("bindings", []).append({"role": OTHER[0], "members": [OTHER[1]]})
    L.eventually(lambda: set_policy(T_VIEW, pol), timeout=300, interval=10, desc="other binding")
    L.ensure_group(G_VIEW, L.customer_id())
    L.eventually(lambda: L.set_group_member(G_VIEW, L.SA_ETL), timeout=300, interval=15, desc="viewer ⊃ etl")
    for t in (T_VIEW, L.T_NOBYPASS):                                        # 上次运行中断时可能残留
        strip_group(t)

    def group_known_to_bigquery():                                          # 新建的 Group 同步到 BigQuery 需要几分钟
        p = table_policy(T_VIEW)
        p["bindings"].append({"role": "roles/bigquery.metadataViewer", "members": [f"group:{G_VIEW}"]})
        set_policy(T_VIEW, p)
    L.eventually(group_known_to_bigquery, timeout=900, interval=30, desc="group known")
    strip_group(T_VIEW)
    yield
    for t in (T_VIEW, L.T_NOBYPASS):
        try:
            strip_group(t)
        except Exception as e:  # noqa: BLE001
            print(f"[cleanup] {t}: {e}")
    L.run_sql(f"DROP TABLE IF EXISTS `{T_VIEW}`")


def test_g01_grant_makes_group_member_able_to_read(gv):
    with pytest.raises(Forbidden):                                         # 授权前：读不到
        L.amounts(L.SA_ETL, T_VIEW)
    code, log = grant("--groups", G_VIEW, "--tables", T_VIEW)              # 演练
    assert code == 0 and f"[GRANT] {T_VIEW}: 新增 ['group:{G_VIEW}']" in log and G_VIEW not in str(members(T_VIEW)), log
    code, log = grant("--groups", G_VIEW, "--tables", T_VIEW, "--apply")
    assert code == 0 and "GRANT 1" in log and "Traceback" not in log, log
    assert f"group:{G_VIEW}" in members(T_VIEW)
    assert OTHER[1].lower() in members(T_VIEW, OTHER[0])                  # 原有的其它授权保留
    L.expect_amounts(L.SA_ETL, T_VIEW, L.ALL_AMOUNTS, timeout=900)       # 没有 RLS：Group 成员看到全部


def test_g02_rerun_noop_and_dataset_scope(gv, tmp_path):
    code, log = grant("--groups", G_VIEW, "--tables", T_VIEW, "--apply")
    assert code == 0 and f"[NOOP] {T_VIEW}" in log and "[GRANT]" not in log, log
    f = tmp_path / "groups.csv"
    f.write_text(f"{G_VIEW}\n", encoding="utf-8")
    code, log = grant("--groups", str(f), "--datasets", f"{L.PROJECT}.{L.NB_DATASET}", "--apply")
    assert code == 0, log
    assert f"[NOOP] {T_VIEW}" in log and f"[GRANT] {L.T_NOBYPASS}: 新增 ['group:{G_VIEW}']" in log
    assert f"group:{G_VIEW}" in members(L.T_NOBYPASS)


def test_g03_missing_group_stops_without_change(gv):
    nosuch = L.grp("nosuch-viewer")
    before = table_policy(T_VIEW).get("bindings")
    code, log = grant("--groups", nosuch, "--tables", T_VIEW, L.T_NOBYPASS, "--apply")
    assert code == 2, log
    assert "BigQuery 报 --groups 中有 Group 不存在（是哪个见上方 [ERROR]），已停止" in log, log
    assert "未做任何变更" in log and nosuch in log and "Traceback" not in log
    assert table_policy(T_VIEW).get("bindings") == before


def test_g04_missing_table_and_arg_errors(gv):
    code, log = grant("--groups", G_VIEW, "--tables", T_VIEW, f"{L.PROJECT}.{L.NB_DATASET}.no_such_t", "--apply")
    assert code == 1 and f"[SKIP] {L.PROJECT}.{L.NB_DATASET}.no_such_t: 表不存在" in log and f"[NOOP] {T_VIEW}" in log, log
    for bad in (f"group:{G_VIEW}", L.SA_ETL):
        code, log = grant("--groups", bad, "--tables", T_VIEW)
        assert code == 2 and "--groups" in log, log
    code, log = grant("--groups", G_VIEW)
    assert code == 2 and "--tables / --datasets / --projects" in log, log


def test_g05_existing_viewer_member_only_missing_added(gv):
    strip_group(L.T_NOBYPASS)
    code, log = grant("--groups", f"{G_VIEW},{L.G_ACL}", "--tables", T_VIEW, "--apply")
    assert code == 0 and f"[GRANT] {T_VIEW}: 新增 ['group:{L.G_ACL}']；已有 ['group:{G_VIEW}']" in log, log
    assert {f"group:{G_VIEW}", f"group:{L.G_ACL}"} <= members(T_VIEW)
    pol = table_policy(T_VIEW)                                              # 清理 G_ACL
    for b in pol["bindings"]:
        b["members"] = [m for m in b["members"] if m.lower() != f"group:{L.G_ACL}"]
    set_policy(T_VIEW, pol)
