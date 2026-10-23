"""
真实环境：apply_bypass_rls --principals / --policy-name（多个主体共用一条 FILTER TRUE 规则）与
rollback_rls --principals 只去掉指定主体（[REMOVE]）。在 test_z_abnormal.py 之后、test_zz_stability.py 之前运行。
"""

import re

import pytest

import rls_core as core
from tests.integration import itlib as L
from tests.integration.test_e2e import BYP_DISABLED, BYP_TABLES, bypass

pytestmark = pytest.mark.integration

SHARED = core.BYPASS_PREFIX + "it_shared"
MANY = core.BYPASS_PREFIX + "it_many"
TABLES_ARG = ",".join(BYP_TABLES)


def shared(*principals, name="it_shared", extra=()):
    return bypass("--policy-name", name, "--principals", *principals, *extra)


def grantees(table, name=SHARED):
    p = L.policies(table).get(name)
    return p and p["grantees"]


def low(*members):
    return {m.lower() for m in members}                     # L.policies 返回的授权对象一律小写


def assert_only_dropped_skipped(code, log):
    assert code == 1, log
    assert f"[SKIP] {L.T_DROPPED}: {core.TABLE_NOT_FOUND_MSG}" in log and "Traceback" not in log, log
    assert "[ERROR]" not in log, log


@pytest.fixture(scope="module")
def shr(world):
    yield
    L.run_cli("rollback_rls.py", "--tables", TABLES_ARG, "--policy-names", f"{SHARED},{MANY}", "--apply")


def test_s01_csv_principals_one_policy(shr, tmp_path):
    f = tmp_path / "principals.csv"
    f.write_text("\n".join([f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}", f"serviceAccount:{L.SA_COP_M}"]) + "\n",
                 encoding="utf-8")
    code, log = shared(str(f), extra=["--apply"])
    assert_only_dropped_skipped(code, log)
    assert f"[PRINCIPALS] 规则 {SHARED} 的授权对象共 3 个" in log
    want = low(f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}", f"serviceAccount:{L.SA_COP_M}")
    for t in BYP_TABLES:
        assert grantees(t) == want, t
        assert L.policies(t)[SHARED]["filter"].upper() == "TRUE"
    for t in BYP_DISABLED:
        assert SHARED not in L.policies(t)
    # cop-b / cop-m 本来不在任何 bypass Group 里：只靠这条共享规则就能看到全部
    L.expect_amounts(L.SA_COP_B, L.T_NOMAP, L.ALL_AMOUNTS)
    L.expect_amounts(L.SA_COP_M, L.T_NOMAP, L.ALL_AMOUNTS)


def test_s02_rerun_noop_then_full_list_replace(shr):
    code, log = shared(f"serviceAccount:{L.SA_COP_M}", f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}")
    assert_only_dropped_skipped(code, log)
    assert log.count("[NOOP]") == len(BYP_TABLES) and "[REPLACE]" not in log        # 顺序不同也 NOOP
    # 完整名单：去掉 cop-m → 每张表 REPLACE，日志列出将移除；cop-m 立刻失去全部可见
    code, log = shared(f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}", extra=["--apply"])
    assert_only_dropped_skipped(code, log)
    assert log.count("[REPLACE]") == len(BYP_TABLES)
    assert f"  将移除: ['serviceAccount:{L.SA_COP_M}']" in log and "  将新增: 无" in log
    assert grantees(L.T_NOMAP) == low(f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}")
    L.expect_amounts(L.SA_COP_M, L.T_NOMAP, [])
    L.expect_amounts(L.SA_COP_B, L.T_NOMAP, L.ALL_AMOUNTS)


@pytest.mark.parametrize("ghost", [f"user:rlsit-nobody-zz@{L.DOMAIN}",
                                   f"serviceAccount:rlsit-ghost-zz@{L.PROJECT}.iam.gserviceaccount.com"])
def test_s03_missing_principal_stops_without_change(shr, ghost):
    before = {t: L.policies(t) for t in BYP_TABLES}
    code, log = shared(f"group:{L.G_READ}", f"serviceAccount:{L.SA_COP_B}", ghost, extra=["--apply"])
    assert code == 2, log
    assert "BigQuery 报 --principals 中有授权对象不存在（是哪个见上方 [ERROR]），已停止" in log, log
    assert "未做任何变更" in log and "[retry]" not in log and "Traceback" not in log
    assert ghost.split(":", 1)[1] in log                                                # 上方 [ERROR] 里是 BigQuery 原文
    assert {t: L.policies(t) for t in BYP_TABLES} == before


def test_s04_argument_errors(shr):
    code, log = shared(f"group:{L.G_READ}", L.SA_COP_B)                                 # 有一个不带前缀
    assert code == 2 and "必须带前缀" in log and L.SA_COP_B in log, log
    code, log = bypass("--principals", f"group:{L.G_READ}")                             # 缺 --policy-name
    assert code == 2 and "必须同时给 --policy-name" in log, log
    code, log = bypass("--group", L.G_READ, "--principals", f"group:{L.G_WRITE}", "--policy-name", "x")
    assert code == 2 and "not allowed with argument" in log, log                        # 二者只能给一个
    code, log = shared("domain:" + L.DOMAIN)
    assert code == 2 and "必须带前缀" in log, log


def test_s05_fifty_principals_in_one_policy(shr):
    from tests.integration.test_e2e import _iam_project_sas
    sas = sorted(_iam_project_sas(L.PROJECT))[:49]
    assert len(sas) == 49
    principals = [f"group:{L.G_READ}"] + [f"serviceAccount:{e}" for e in sas]
    code, log = shared(",".join(principals), name="it_many", extra=["--apply"])
    assert_only_dropped_skipped(code, log)
    assert grantees(L.T_NOMAP, MANY) == low(*principals) and len(grantees(L.T_ORDERS, MANY)) == 50


def test_s06_rollback_removes_only_given_principal(shr):
    code, log = L.run_cli("rollback_rls.py", "--tables", TABLES_ARG, "--principals", L.SA_COP_B, "--apply")
    assert code == 0, log
    assert re.search(rf"\[REMOVE\] `{SHARED}` 去掉: \['serviceAccount:{re.escape(L.SA_COP_B)}'\]；保留: "
                     rf"\['group:{re.escape(L.G_READ)}'\]", log, re.I), log
    assert f"从 {2 * len(BYP_TABLES)} 条规则中去掉主体" in log                          # cop-b 也在 s05 的 50 人规则里
    for t in BYP_TABLES:
        assert grantees(t) == low(f"group:{L.G_READ}"), t                               # 共享规则保留，只去掉 cop-b
        assert len(grantees(t, MANY)) == 49 and f"serviceaccount:{L.SA_COP_B}" not in grantees(t, MANY)
        assert L.policies(t)[SHARED]["filter"].upper() == "TRUE"
    L.expect_amounts(L.SA_COP_B, L.T_NOMAP, [])
    L.expect_amounts(L.SA_READER, L.T_NOMAP, L.ALL_AMOUNTS)
    # 只给规则名：整条删除（清理）
    code, log = L.run_cli("rollback_rls.py", "--tables", TABLES_ARG, "--policy-names", f"{SHARED},{MANY}", "--apply")
    assert code == 0 and "[REMOVE]" not in log, log
    for t in BYP_TABLES:
        assert SHARED not in L.policies(t) and MANY not in L.policies(t)
