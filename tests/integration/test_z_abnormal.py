"""
真实环境异常系测试：只有 BigQuery / IAM 本身才能回答的行为。依赖 test_e2e.py 的 world fixture，
在 e2e 之后运行（文件名排序），用完自行清理。
"""

import pytest

import rls_core as core
from tests.integration import itlib as L
from tests.integration.test_e2e import BYP_R, bypass, copilot, read_csv

pytestmark = pytest.mark.integration

T_X = L.tbl("abn_orders")
T_VIEW = L.tbl("abn_view")
COND2 = L.tbl("abn_condition", L.AUTH_DATASET)
MAP2 = L.tbl("abn_mapping", L.AUTH_DATASET)
COP_G = core.copilot_policy_name(L.G_COPILOT)          # Group 级别：每张表一条 Copilot 规则


def q(sql):
    return L.run_sql(sql)


@pytest.fixture(scope="module")
def abn(world):
    values = ", ".join(f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)" for r, p, f, a in L.ROWS)
    q(f"CREATE OR REPLACE TABLE `{T_X}` AS SELECT * FROM UNNEST([{values}])")
    q(f"CREATE OR REPLACE VIEW `{T_VIEW}` AS SELECT * FROM `{T_X}`")
    q(f"CREATE OR REPLACE TABLE `{COND2}` (id STRING, sa STRING, region ARRAY<STRING>, `odd col` ARRAY<STRING>, "
      f"note STRING, status INT64) CLUSTER BY sa")
    q(f"""INSERT INTO `{COND2}` (id, sa, region, `odd col`, note, status) VALUES
          ('u1', '{L.SA_COP_A.upper()}', ['HK'], [], 'mixed case', 1),
          ('u2', 'serviceAccount:{L.SA_COP_B}', ['SG'], [], 'prefixed', 1),
          ('u3', '{L.G_READ}', [], [], 'group email as sa', 1),
          ('u4', 'not an email', ['US'], [], 'garbage', 1),
          ('u5', '{L.ACCOUNT}', ['SG'], [], 'ok user', 1)""")
    q(f"""CREATE OR REPLACE TABLE `{MAP2}` AS SELECT * FROM UNNEST([
          STRUCT('{T_X}' AS table_name, 'region' AS col_name, 'region' AS to_name),
          STRUCT('{T_X}', 'region', 'odd col'),
          STRUCT('{T_VIEW}', 'region', 'region')])""")        # 视图被误配进映射表
    reg = ", ".join(f"(GENERATE_UUID(), '{t}', 1, 1, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())" for t in (T_X, T_VIEW))
    q(f"INSERT INTO `{L.T_REGISTRY}` (id, table_name, rls_enabled, status, create_time, update_time) VALUES {reg}")
    # bypass 只看登记表：T_X、T_VIEW 都登记为开启（同时处理登记表里其它开启的表）
    code, log = bypass("--group", L.G_READ, "--apply")
    yield {"bypass_code": code, "bypass_log": log}
    q(f"DELETE FROM `{L.T_REGISTRY}` WHERE table_name IN ('{T_X}', '{T_VIEW}')")
    for t in (T_X, T_VIEW):
        q(f"DROP TABLE IF EXISTS `{t}`") if t == T_X else q(f"DROP VIEW IF EXISTS `{t}`")
    for t in (COND2, MAP2):
        q(f"DROP TABLE IF EXISTS `{t}`")


def test_r01_rls_on_view_is_rejected_by_bigquery_and_isolated(abn):
    # 视图不支持 RLS：登记表里登记了视图 → 它在 DDL 阶段失败（[ERROR]，退出码 1），普通表照常成功
    assert abn["bypass_code"] == 1
    log = abn["bypass_log"]
    assert f"[CREATE] {T_VIEW}" in log and "[ERROR]" in log and "Traceback" not in log, log
    assert BYP_R in L.policies(T_X) and L.policies(T_VIEW) == {}


def test_r02a_view_in_mapping_table_fails_in_isolation(abn, tmp_path):
    # bypass 闸门已删除：误配进映射表的视图不再让整批中止；视图本身在 BigQuery 那一步失败（退出码 1），不影响其它表
    code, log = L.run_cli("apply_copilot_rls.py", "--condition-table", COND2, "--mapping-table", MAP2,
                          "--registry-table", L.T_REGISTRY, "--group", L.G_COPILOT, "--tables", T_VIEW,
                          "-o", str(tmp_path / "c.csv"), "--apply")
    assert code == 1 and "[ABORT]" not in log and T_VIEW in log and "Traceback" not in log, log
    assert L.policies(T_VIEW) == {}
    assert not any(p.startswith(core.COPILOT_PREFIX) for p in L.policies(T_X))
    q(f"DELETE FROM `{MAP2}` WHERE table_name = '{T_VIEW}'")


def test_r02_dirty_condition_values(abn, tmp_path):
    out = tmp_path / "c.csv"
    code, log = L.run_cli("apply_copilot_rls.py", "--condition-table", COND2, "--mapping-table", MAP2,
                          "--registry-table", L.T_REGISTRY, "--group", L.G_COPILOT, "-o", str(out), "--apply")
    assert code == 1, log                                               # 条件表数据有问题：只提醒，规则照建
    assert "含有特殊字符" in log and "odd col" in log                 # 灵活列名不作为维度
    assert "不是裸邮箱" in log and f"serviceAccount:{L.SA_COP_B}" in log and "not an email" in log   # 带前缀 / 垃圾值
    assert "非小写" in log and L.SA_COP_A.upper() in log                # 大小写问题被警告
    rows = read_csv(out)
    assert [r["table"] for r in rows] == [T_X] and rows[0]["result"] == "OK"   # 每张表一行
    pols = L.policies(T_X)
    assert pols[COP_G]["grantees"] == {f"group:{L.G_COPILOT}"} and "odd col" not in pols[COP_G]["filter"]
    assert not any(p.startswith(core.COPILOT_PREFIX) and p != COP_G for p in pols)


def test_r03_mixed_case_sa_sees_zero_rows_until_fixed(abn):
    # 条件表存的是大写邮箱，SESSION_USER() 是小写 → 子查询匹配不到 → 0 行（这正是 [WARN] 提醒的后果）
    L.expect_amounts(L.SA_COP_A, T_X, [], timeout=300)
    q(f"UPDATE `{COND2}` SET sa = LOWER(sa) WHERE id = 'u1'")
    L.expect_amounts(L.SA_COP_A, T_X, L.HK, timeout=300)             # 修正数据后无需重跑脚本


def test_r04_user_principal_runner_sees_only_own_rows(abn):
    L.expect_amounts(L.ACCOUNT, T_X, L.SG, timeout=300)


def test_r05_verify_sa_not_impersonable_fails_cleanly(abn):
    ghost = L.sa("rlsit-ghost")
    code, log = bypass("--group", L.G_WRITE, "--apply", "--verify-sa", ghost)
    assert code == 1 and "[VERIFY-FAIL]" in log and "Traceback" not in log


def test_r06_bad_gcloud_account_is_clean_error():
    code, out = L.run_cli("list_principals.py", "--projects", L.PROJECT, "-o", "/tmp/x.csv")
    assert code == 0
    import subprocess, sys, os
    p = subprocess.run([sys.executable, os.path.join(L.ROOT, "list_principals.py"), "--gcloud-account",
                        "nobody@example.invalid", "--projects", L.PROJECT, "-o", "/tmp/x.csv", "--log-dir", L.LOG_DIR],
                       capture_output=True, text=True, cwd=L.ROOT, timeout=120)
    assert p.returncode == 2 and "[ERROR]" in p.stderr and "nobody@example.invalid" in p.stderr, p.stderr
    assert "gcloud auth login" in p.stderr and "Traceback" not in p.stderr


def test_r07_nonexistent_dataset_and_project_scope(abn):
    # apply_bypass 已不接受范围参数；rollback 仍支持 --datasets：数据集不存在 → 展开失败，退出码 1
    code, log = L.run_cli("rollback_rls.py", "--datasets", f"{L.PROJECT}.no_such_dataset", "--principals", L.SA_COP_A,
                          "--apply")
    assert code == 1 and "展开目标表失败" in log and "Traceback" not in log, log
    code, log = L.run_cli("rollback_rls.py", "--tables", f"{L.PROJECT}.{L.DATASET}.no_such_table", "--principals", L.SA_COP_A, "--apply")
    assert code == 1 and "读取现有规则失败" in log and "Traceback" not in log


def test_r08_table_deleted_during_list_principals_is_note(world, tmp_path, capsys, monkeypatch):
    # 真实地「列出表之后、读取它的 IAM 之前把表删掉」：真实 BigQuery 返回 404 → [NOTE] 跳过，退出码 0、不中断、CSV 照常
    import gcp_ops
    import list_principals
    gone = L.tbl("lp_deleted_mid_scan")
    q(f"CREATE OR REPLACE TABLE `{gone}` AS SELECT 1 AS x")
    real = gcp_ops.dataset_tables

    def list_then_drop(ctx, ds):
        tables = real(ctx, ds)
        if gone in tables:
            q(f"DROP TABLE `{gone}`")                                  # 已列出，随后被删除
        return tables
    monkeypatch.setattr(gcp_ops, "dataset_tables", list_then_drop)
    out = tmp_path / "p.csv"
    try:
        code = list_principals.main(["--gcloud-account", L.ACCOUNT, "--quota-project", L.PROJECT,
                                     "--projects", L.PROJECT, "-o", str(out), "--log-dir", L.LOG_DIR])
    finally:
        q(f"DROP TABLE IF EXISTS `{gone}`")
    err = capsys.readouterr().err
    assert f"[NOTE] 表 {gone}: 表已不存在（扫描期间被删除），跳过" in err, err[-3000:]
    assert code == 0 and "[ERROR]" not in err and "Traceback" not in err, err[-3000:]
    assert "张扫描期间已被删除，跳过）" in err and "===== 完成" in err
    rows = {r["email"]: r for r in read_csv(out)}
    assert L.SA_ETL in rows and L.G_ACL in rows and L.SA_ACL in rows          # 其余主体照常写入 CSV
