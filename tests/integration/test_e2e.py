"""
端到端集成测试：按文档 Step 2 → 3 → 4 → 6 → 7 → 巡检 → Gate 2 五项验收 → 回退 的顺序执行。
测试按定义顺序运行，后面的用例依赖前面用例创建的资源。
"""

import csv
import json
import os

import pytest
from google.auth.exceptions import RefreshError

from tests.integration import itlib as L

pytestmark = pytest.mark.integration
STATE = {}


def _csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return {r["principal"]: r for r in csv.DictReader(f)}


# =========================================================================== #
# T2  存量账号扫描（读/写分类 + 三层 IAM + 作业历史）
# =========================================================================== #
def test_t2_scan_classifies_read_write_and_jobs(world, tmp_path_factory):
    etl, reader = L.impersonate(L.SA_ETL), L.impersonate(L.SA_READER)
    L.query(etl, f"INSERT INTO `{L.T_ORDERS}` VALUES ('XX', 'PX', 'REF_X', 100)")
    L.query(etl, f"DELETE FROM `{L.T_ORDERS}` WHERE region = 'XX'")
    L.query(reader, f"SELECT COUNT(*) FROM `{L.T_ORDERS}`")
    # 通配符表查询（R5）需要数据集级权限：reader 只有表级 dataViewer 会 403，所以用 etl（数据集 WRITER）执行
    L.query(etl, f"SELECT COUNT(*) FROM `{L.PROJECT}.{L.DATASET}.sens*`")
    out = str(tmp_path_factory.mktemp("scan") / "scan.csv")
    projects_out = out.replace("scan.csv", "sa_projects.txt")
    STATE["scan_csv"] = out

    def scan_ok():
        code, log = L.run_cli("scan_bq_access.py", "--tables", f"{L.T_ORDERS},{L.T_SENSITIVE}",
                              "--jobs-days", "1", "--job-projects", L.PROJECT,   # C2：额外作业项目（与目标项目相同，验证去重）
                              "--copilot-patterns", L.COPILOT_PATTERN,
                              "--copilot-members", L.SA_API, "-o", out, "--sa-projects-out", projects_out)
        assert code == 0, log
        # 扫描到的 SA 所属项目：作为 list_project_sas.py 项目列表的数据来源
        assert "[PROJECTS] 涉及的 SA 所属项目" in log and L.PROJECT in log.split("[PROJECTS]")[1], log
        assert L.PROJECT in open(projects_out, encoding="utf-8").read().split()
        rows = _csv(out)
        e = rows[f"serviceAccount:{L.SA_ETL}"]
        r = rows[f"serviceAccount:{L.SA_READER}"]
        assert e["can_write"] == "True" and "dataset:" in e["sources"]
        assert e["suggested_group"] == "write"
        assert r["can_read"] == "True" and r["can_write"] == "False" and "table:" in r["sources"]
        assert r["suggested_group"] == "read"
        # 作业历史（INFORMATION_SCHEMA 有延迟，需要重试）
        assert int(e["jobs_write_count"]) >= 1, e
        assert int(r["jobs_read_count"]) >= 1, r
        assert int(e["wildcard_jobs"]) >= 1 and "通配符" in e["note"], e   # E3（失败的尝试也会计入作业历史）
        assert log.count("[JOBS] ") == 1                                  # 同一项目只扫一次
    L.eventually(scan_ok, timeout=600, interval=30, desc="scan")


def test_t2_scan_org_scope_and_dataset_range(world, tmp_path):
    """C2 组织级作业视图 + E4 按数据集范围展开。"""
    out = str(tmp_path / "scan_org.csv")
    code, log = L.run_cli("scan_bq_access.py", "--datasets", f"{L.PROJECT}.{L.DATASET}",
                          "--jobs-days", "1", "--jobs-scope", "organization",
                          "--copilot-patterns", L.COPILOT_PATTERN, "-o", out)
    assert code == 0, log
    assert "[SCOPE] 数据集" in log and "[JOBS] 组织 / region-us" in log
    assert "跳过通配符表查询检测" in log and "通配符查询检测失败" not in log   # 组织级视图没有 query 列
    rows = _csv(out)
    assert int(rows[f"serviceAccount:{L.SA_READER}"]["jobs_read_count"]) >= 1
    assert int(rows[f"serviceAccount:{L.SA_ETL}"]["jobs_write_count"]) >= 1


# =========================================================================== #
# T3  白名单 Group：防混入 / 从扫描结果生成 / 建组加成员 + 探针验证
# =========================================================================== #
def test_t3_whitelist_rejects_copilot_sa(world):
    before = L.group_members(L.G_READ)
    code, log = L.run_cli("whitelist_groups.py", "--write-group", L.G_WRITE, "--read-group", L.G_READ,
                          "--read-members", f"{L.SA_READER},{L.SA_API}",
                          "--copilot-members", L.SA_API, "--copilot-patterns", L.COPILOT_PATTERN,
                          "--apply")
    assert code == 2, log
    assert L.SA_API in log
    after = L.group_members(L.G_READ)
    assert after == before                       # 中止，未做任何变更
    assert after is None or L.SA_API not in after


def test_t3_whitelist_plan_from_scan_csv(world):
    code, log = L.run_cli("whitelist_groups.py", "--write-group", L.G_WRITE, "--read-group", L.G_READ,
                          "--scan-csv", STATE["scan_csv"], "--copilot-patterns", L.COPILOT_PATTERN)
    assert code == 0, log
    assert f"{L.G_WRITE} <- {L.SA_ETL}" in log
    assert f"{L.G_READ} <- {L.SA_READER}" in log


def test_t3_whitelist_apply_with_probe(world):
    code, log = L.run_cli("whitelist_groups.py", "--write-group", L.G_WRITE, "--read-group", L.G_READ,
                          "--write-members", L.SA_ETL, "--read-members", L.SA_READER,
                          "--copilot-patterns", L.COPILOT_PATTERN, "--initial-config", "EMPTY",
                          "--probe-sa", L.SA_PROBE, "--probe-dataset", f"{L.PROJECT}.{L.DATASET}",
                          "--project", L.PROJECT, "--apply")
    assert code == 0, log
    assert f"[PROBE] {L.G_WRITE} 已生效" in log
    assert f"[PROBE] {L.G_READ} 已生效" in log
    assert {L.SA_ETL, L.SA_PROBE} <= L.group_members(L.G_WRITE)
    assert {L.SA_READER, L.SA_PROBE} <= L.group_members(L.G_READ)


def test_t3_whitelist_from_acl_table_and_acl_out(world, tmp_path):
    """表 8（白名单名册）直接作为名单来源；--acl-out 导出可回填名册的 CSV；名册值非法时拒绝。"""
    out = str(tmp_path / "acl.csv")
    base = ["--write-group", L.G_WRITE, "--read-group", L.G_READ, "--acl-table", L.T_ACL,
            "--copilot-patterns", L.COPILOT_PATTERN, "--project", L.PROJECT]
    code, log = L.run_cli("whitelist_groups.py", *base, "--acl-out", out)
    assert code == 0, log
    assert f"[SOURCE] 白名单名册 {L.T_ACL}: 2 行" in log
    assert f"{L.G_WRITE} <- {L.SA_ETL}" in log and f"{L.G_READ} <- {L.SA_READER}" in log
    assert {(r["sa"], r["acl_group"]) for r in csv.DictReader(open(out, encoding="utf-8"))} == {
        (L.SA_ETL, L.G_WRITE), (L.SA_READER, L.G_READ)}
    code, log = L.run_cli("whitelist_groups.py", *base, "--apply")          # 已存在 -> 幂等
    assert code == 0 and "[MEMBER]" in log, log
    # 名册里出现无法识别的 acl_group -> 退出码 1，不做任何变更（成员关系与执行前完全一致）
    before = L.group_members(L.G_READ)
    L.query(L.admin_creds(), f"INSERT INTO `{L.T_ACL}` (sa, acl_group) VALUES ('{L.SA_LATE}', 'vip')")
    try:
        code, log = L.run_cli("whitelist_groups.py", *base, "--apply")
        assert code == 1 and "vip" in log, log
        assert L.group_members(L.G_READ) == before
    finally:
        L.query(L.admin_creds(), f"DELETE FROM `{L.T_ACL}` WHERE sa = '{L.SA_LATE}'")


# =========================================================================== #
# T4  FILTER TRUE 白名单策略
# =========================================================================== #
BYPASS = "rls_bypass_full_access"
TARGETS = [L.T_ORDERS, L.T_SENSITIVE, L.T_ALT, L.T_BADMAP, L.T_PART]


def test_t4_bypass_requires_force_on_first_policy(world):
    code, log = L.run_cli("apply_bypass_rls.py", "--tables", ",".join(TARGETS),
                          "--groups", f"{L.G_WRITE},{L.G_READ}", "--apply")
    assert code == 2, log
    for t in TARGETS:
        assert L.policies(t) == {}


def test_t4_bypass_create_batch_multi_group_and_idempotent(world):
    args = ["--tables", ",".join(TARGETS), "--groups", f"{L.G_WRITE},{L.G_READ}",
            "--force-first-policy", "--apply"]
    code, log = L.run_cli("apply_bypass_rls.py", *args)
    assert code == 0, log
    assert "[EDITION] " in log and "OK" in log          # C3：版本前置检查已执行（按需项目 -> OK）
    want = {f"group:{L.G_WRITE}", f"group:{L.G_READ}"}
    for t in TARGETS:
        p = L.policies(t)[BYPASS]
        assert p["grantees"] == want and p["filter"].strip().upper() == "TRUE"
    code, log = L.run_cli("apply_bypass_rls.py", *args)
    assert code == 0 and log.count("[NOOP]") == len(TARGETS), log


def test_t4_bypass_conflict_then_merge(world):
    admin = f"user:{L.ACCOUNT}"
    L.query(L.admin_creds(), f'CREATE OR REPLACE ROW ACCESS POLICY {BYPASS} ON `{L.T_CONFLICT}` '
                             f'GRANT TO ("{admin}") FILTER USING (TRUE)')
    base = ["--tables", L.T_CONFLICT, "--groups", f"{L.G_WRITE},{L.G_READ}", "--apply"]
    code, log = L.run_cli("apply_bypass_rls.py", *base)
    assert code == 1 and "[CONFLICT]" in log, log
    assert L.policies(L.T_CONFLICT)[BYPASS]["grantees"] == {admin.lower()}
    code, log = L.run_cli("apply_bypass_rls.py", *base, "--merge")
    assert code == 0, log
    assert L.policies(L.T_CONFLICT)[BYPASS]["grantees"] == {
        admin.lower(), f"group:{L.G_WRITE}", f"group:{L.G_READ}"}


def test_t4_whitelisted_accounts_unaffected(world):
    import time
    etl, reader = L.impersonate(L.SA_ETL), L.impersonate(L.SA_READER)
    t0 = time.time()

    def check():
        assert L.amounts(etl, L.T_ORDERS)[1] == L.ALL_AMOUNTS
        assert L.amounts(reader, L.T_ORDERS)[1] == L.ALL_AMOUNTS
        assert L.amounts(reader, L.T_SENSITIVE)[1] == L.ALL_AMOUNTS
        # DML 需要对整张表有完整访问权限（命中 FILTER TRUE）
        L.query(etl, f"INSERT INTO `{L.T_ORDERS}` VALUES ('XX', 'PX', 'REF_X', 100)")
        try:
            assert L.amounts(etl, L.T_ORDERS)[1] == L.ALL_AMOUNTS + [100]
        finally:
            L.query(etl, f"DELETE FROM `{L.T_ORDERS}` WHERE region = 'XX'")
        assert L.amounts(etl, L.T_ORDERS)[1] == L.ALL_AMOUNTS
    L.eventually(check, interval=10, desc="whitelist read/write")
    print(f"\n[METRIC] 白名单读写在测试开始后 {time.time() - t0:.0f}s 达到稳定", flush=True)


def test_t4_verify_with_whitelisted_account(world):
    """挂载后验证：以白名单账号身份探测，看到数据才算生效（含要求分区过滤的表）。"""
    code, log = L.run_cli("apply_bypass_rls.py", "--tables", f"{L.T_ORDERS},{L.T_SENSITIVE},{L.T_PART}",
                          "--groups", f"{L.G_WRITE},{L.G_READ}", "--verify-sa", L.SA_READER,
                          "--force-first-policy", "--apply")
    assert code == 0, log
    assert log.count("[VERIFY-OK]") == 3, log                   # C1：分区表自动加 dt IS NOT NULL
    # count 模式：与元数据行数比对
    code, log = L.run_cli("apply_bypass_rls.py", "--tables", L.T_ORDERS,
                          "--groups", f"{L.G_WRITE},{L.G_READ}", "--verify-sa", L.SA_READER,
                          "--verify-mode", "count", "--skip-edition-check", "--apply")
    assert code == 0 and "[VERIFY-OK]" in log and "6 行" in log, log
    # 非白名单账号（API SA，无表权限）验证会失败
    code, log = L.run_cli("apply_bypass_rls.py", "--tables", L.T_ORDERS,
                          "--groups", f"{L.G_WRITE},{L.G_READ}", "--verify-sa", L.SA_API,
                          "--verify-timeout", "30", "--apply")
    assert code == 1 and "[VERIFY-FAIL]" in log, log


# =========================================================================== #
# T7  批量建 Copilot SA + Impersonation + 表级 IAM + condition 表 + jobUser
# =========================================================================== #
def _sa_file(tmp_path, extra=()):
    path = tmp_path / "sas.csv"
    rows = [("rlsit-cop-hi", L.G_HIGH), ("rlsit-cop-lo", L.G_LOW), ("rlsit-cop-none", L.G_HIGH),
            *extra]
    path.write_text("account_id,group\n" + "".join(f"{a},{g}\n" for a, g in rows))
    return str(path)


def _grants_file(tmp_path):
    path = tmp_path / "grants.csv"
    path.write_text("group,resource\n"
                    f"{L.G_HIGH},{L.T_ORDERS}\n{L.G_HIGH},{L.T_SENSITIVE}\n{L.G_LOW},{L.T_ORDERS}\n"
                    f"{L.G_HIGH},{L.T_ALT}\n{L.G_LOW},{L.T_ALT}\n")
    return str(path)


def _copilot_args(tmp_path, **kw):
    return ["--project", L.PROJECT, "--api-sa", L.SA_API,
            "--sa-file", kw.get("sa_file") or _sa_file(tmp_path),
            "--grants-file", _grants_file(tmp_path), "--all-group", L.G_ALL,
            "--condition-table", L.T_COND, "--initial-config", "EMPTY"]


def test_t7_quota_guard(world, tmp_path):
    sa_file = _sa_file(tmp_path, extra=[("rlsit-cop-quota", L.G_LOW)])
    code, log = L.run_cli("setup_copilot_sas.py", *_copilot_args(tmp_path, sa_file=sa_file),
                          "--sa-limit", "5", "--apply")
    assert code == 2 and "上限" in log, log
    assert not L.sa_exists(L.sa("rlsit-cop-quota"))


def test_t7_setup_copilot_sas(world, tmp_path):
    code, log = L.run_cli("setup_copilot_sas.py", *_copilot_args(tmp_path), "--apply")
    assert code == 0, log
    assert "API SA 数据权限检查: OK" in log
    # 项目级可扮演任意 SA 的主体需要被报告出来
    for m in L.project_role_members("roles/iam.serviceAccountTokenCreator"):
        if not m.endswith(L.SA_API):
            assert f"[impersonation-risk] {m}" in log.lower(), m
    cops = [L.SA_COP_HI, L.SA_COP_LO, L.SA_COP_NONE]
    for s in cops:
        assert L.sa_exists(s)
        creators = L.sa_role_members(s, "roles/iam.serviceAccountTokenCreator")
        assert f"serviceaccount:{L.SA_API}" in creators
        assert f"user:{L.ACCOUNT}".lower() not in creators   # 只有 API SA 能扮演
    assert {L.SA_COP_HI, L.SA_COP_NONE} <= L.group_members(L.G_HIGH)
    assert L.SA_COP_LO in L.group_members(L.G_LOW)
    assert set(cops) <= L.group_members(L.G_ALL)
    assert {f"group:{L.G_HIGH}", f"group:{L.G_LOW}"} <= L.table_role_members(L.T_ORDERS)
    sens = L.table_role_members(L.T_SENSITIVE)
    assert f"group:{L.G_HIGH}" in sens and f"group:{L.G_LOW}" not in sens
    assert f"group:{L.G_ALL}" in L.table_role_members(L.T_COND)
    assert f"group:{L.G_ALL}" in L.project_role_members("roles/bigquery.jobUser")
    code, log = L.run_cli("setup_copilot_sas.py", *_copilot_args(tmp_path), "--apply")
    assert code == 0, log   # 幂等


def test_t7_setup_from_auth_tables(world):
    """直接读表 5 ⋈ 表 1 ⋈ 表 3（SA -> Group）和表 4 ⋈ 表 3（Group -> 表范围），不经过 CSV。"""
    base = ["--project", L.PROJECT, "--api-sa", L.SA_API, "--all-group", L.G_ALL,
            "--condition-table", L.T_COND, "--auth-dataset", f"{L.PROJECT}.{L.DATASET}",
            "--initial-config", "EMPTY"]
    code, log = L.run_cli("setup_copilot_sas.py", *base)                   # 演练
    assert code == 0, log
    assert f"[SOURCE] 权限 SA 清单: {L.T_BIND} ⋈ {L.T_COND} ⋈ {L.T_GROUP}（2 行）" in log
    assert f"[SOURCE] 表级授权范围: {L.T_GRANT} ⋈ {L.T_GROUP}（5 行）" in log
    assert "一 SA 一 Group: OK" in log
    assert f"[PLAN] SA {L.SA_COP_HI} -> {L.G_HIGH}, {L.G_ALL}" in log
    assert f"[PLAN] SA {L.SA_COP_LO} -> {L.G_LOW}, {L.G_ALL}" in log
    assert log.count("[PLAN] roles/bigquery.dataViewer on ") == 6          # 5 条授权 + 条件表
    assert f"roles/bigquery.dataViewer on {L.T_SENSITIVE} -> group:{L.G_LOW}" not in log
    code, log = L.run_cli("setup_copilot_sas.py", *base, "--apply")        # 与 CSV 方式结果一致 -> 全部已存在
    assert code == 0 and "[ERROR]" not in log and "[OK]" not in log, log


def test_t7_rejects_sa_in_two_groups(world, tmp_path):
    """一 SA 一 Group：同一个权限 SA 映射到两个 Group 时中止，不做任何变更。"""
    sa_file = _sa_file(tmp_path, extra=[("rlsit-cop-hi", L.G_LOW)])
    code, log = L.run_cli("setup_copilot_sas.py", *_copilot_args(tmp_path, sa_file=sa_file), "--apply")
    assert code == 1 and "一 SA 一 Group" in log and L.SA_COP_HI in log, log
    assert L.SA_COP_HI not in L.group_members(L.G_LOW)


# =========================================================================== #
# 白名单候选：项目列表下的全部 SA（比 T2 扫描更宽松）
# =========================================================================== #
def test_list_project_sas_from_project_list(world, tmp_path):
    pfile = tmp_path / "projects.txt"
    pfile.write_text(f"# 项目列表\n{L.PROJECT}\n")
    out = str(tmp_path / "all_sas.csv")
    # 项目既在 --projects 又在 --projects-file 中，验证列表合并与去重
    code, log = L.run_cli("list_project_sas.py", "--projects", L.PROJECT, "--projects-file", str(pfile),
                          "--group", "write", "--include-iam-bound",
                          "--copilot-patterns", L.COPILOT_PATTERN, "--copilot-members", L.SA_API,
                          "-o", out)
    assert code == 0, log
    rows = _csv(out)
    for s in (L.SA_ETL, L.SA_READER, L.SA_LATE):
        r = rows[f"serviceAccount:{s}"]
        assert r["suggested_group"] == "write", r
        assert r["sources"].count(f"{L.PROJECT}:project-sa") == 1   # 去重
    for s in (L.SA_COP_HI, L.SA_COP_LO, L.SA_COP_NONE, L.SA_API):
        r = rows[f"serviceAccount:{s}"]
        assert r["suggested_group"] == "" and r["copilot"] == "True", r
    # --include-iam-bound：项目 IAM 中出现的服务代理也被列出
    assert any("服务代理" in r["note"] for r in rows.values())
    # 输出可直接作为 whitelist_groups.py 的 --scan-csv
    code, log = L.run_cli("whitelist_groups.py", "--write-group", L.G_WRITE, "--scan-csv", out,
                          "--copilot-patterns", L.COPILOT_PATTERN, "--copilot-members", L.SA_API)
    assert code == 0, log
    assert f"{L.G_WRITE} <- {L.SA_ETL}" in log and L.SA_COP_HI not in log


@pytest.mark.skipif(not L.ORG, reason="需要 RLS_IT_ORG（组织 ID）")
def test_list_project_sas_org_scope(world, tmp_path):
    """组织级盘点（Cloud Asset Inventory）：不需要项目列表；能看到数据集 / 表级的授权。"""
    out = str(tmp_path / "org_sas.csv")
    code, log = L.run_cli("list_project_sas.py", "--organization", L.ORG, "--include-iam-bound",
                          "--quota-project", L.PROJECT, "--copilot-patterns", L.COPILOT_PATTERN,
                          "--copilot-members", L.SA_API, "-o", out)
    assert code == 0, log
    assert f"[ASSET] organizations/{L.ORG}: 范围内" in log and "[ASSET-IAM]" in log
    rows = _csv(out)
    etl, reader = rows[f"serviceAccount:{L.SA_ETL}"], rows[f"serviceAccount:{L.SA_READER}"]
    assert etl["suggested_group"] == "write" and f"{L.PROJECT}:asset-sa" in etl["sources"]
    assert f"datasets/{L.DATASET}:iam-binding:" in etl["sources"]                 # 数据集级 WRITER（ACL 映射为 IAM 角色）
    assert f"datasets/{L.DATASET}/tables/orders:iam-binding:roles/bigquery.dataViewer" in reader["sources"]   # 表级
    for s in (L.SA_COP_HI, L.SA_API):
        assert rows[f"serviceAccount:{s}"]["copilot"] == "True"


# =========================================================================== #
# T8  动态 RLS Subquery
# =========================================================================== #
COPILOT = "rls_copilot_subquery_policy"


def _copilot_rls(*tables, extra=()):
    return L.run_cli("apply_copilot_rls.py", "--mapping-table", L.T_MAPPING,
                     "--condition-table", L.T_COND, "--groups", f"{L.G_HIGH},{L.G_LOW}",
                     "--tables", ",".join(tables), *extra, "--apply")


def test_t8_requires_bypass_policy(world):
    code, log = _copilot_rls(L.T_NOBYPASS)
    assert code == 2, log
    assert L.policies(L.T_NOBYPASS) == {}


def test_t8_apply_from_mapping_and_idempotent(world):
    code, log = _copilot_rls(L.T_ORDERS, L.T_SENSITIVE)
    assert code == 0, log
    o = L.policies(L.T_ORDERS)
    assert set(o) == {BYPASS, COPILOT}
    assert o[COPILOT]["grantees"] == {f"group:{L.G_HIGH}", f"group:{L.G_LOW}"}
    for dim in ("region", "prdtype", "refername"):
        assert f"UNNEST(c.{dim})" in o[COPILOT]["filter"]
    s = L.policies(L.T_SENSITIVE)[COPILOT]["filter"]
    assert "UNNEST(c.region)" in s and "prdtype" not in s
    code, log = _copilot_rls(L.T_ORDERS, L.T_SENSITIVE)
    assert code == 0 and log.count("[NOOP]") == 2, log


def test_t8_heterogeneous_columns_per_table(world):
    """不同表的过滤字段列名、层级不同；映射错误的表被跳过，不影响其他表。"""
    code, log = _copilot_rls(L.T_ALT, L.T_BADMAP)
    assert code == 1, log
    assert "missing_col" in log and "bad_mapping_t" in log
    f = L.policies(L.T_ALT)[COPILOT]["filter"].replace("`", "")   # BigQuery 存储时会去掉反引号
    assert "(area IN" in f and "(ptype IN" in f and "(meta.ref IN" in f
    assert "(region IN" not in f
    assert set(L.policies(L.T_BADMAP)) == {BYPASS}


# =========================================================================== #
# 巡检 + T5 热修补白名单
# =========================================================================== #
def _inspect(*extra):
    return L.run_cli("inspect_rls.py", "--tables", f"{L.T_ORDERS},{L.T_SENSITIVE},{L.T_ALT}",
                     "--mapping-table", L.T_MAPPING, "--condition-table", L.T_COND,
                     "--bypass-groups", f"{L.G_WRITE},{L.G_READ}",
                     "--copilot-groups", f"{L.G_HIGH},{L.G_LOW}",
                     "--copilot-patterns", L.COPILOT_PATTERN, *extra)


def test_inspect_clean(world):
    code, log = _inspect("--copilot-members", L.SA_API)
    assert code == 0, log
    assert log.count("[OK]") == 3


def test_inspect_acl_roster_reconciliation(world):
    """表 8 名册 vs. 白名单 Group 实际成员：一致 -> 0 问题；名册多出 / 组里多出 都是问题；探针 SA 忽略。"""
    L.set_group_member(L.G_READ, L.SA_LATE, False)             # 上次运行的热修补测试可能把 late 留在组里
    acl = ["--acl-table", L.T_ACL, "--probe-sa", L.SA_PROBE]
    L.eventually(lambda: _assert_eq(_inspect(*acl)[0], 0), timeout=180, interval=15, desc="roster clean")
    assert f"[ACL] 名册 {L.T_ACL}: 2 行" in _inspect(*acl)[1]
    L.query(L.admin_creds(), f"INSERT INTO `{L.T_ACL}` (sa, acl_group) VALUES ('{L.SA_LATE}', 'full_read')")
    try:
        code, log = _inspect(*acl)                                  # 名册有、组里没有
        assert code == 1 and f"名册中的 {L.SA_LATE} 还没有加入 {L.G_READ}" in log, log
        L.query(L.admin_creds(), f"DELETE FROM `{L.T_ACL}` WHERE sa = '{L.SA_READER}'")
        code, log = _inspect(*acl)                                  # 组里有、名册没有
        assert code == 1 and f"{L.G_READ} 的成员 {L.SA_READER} 不在白名单名册中" in log, log
        assert L.SA_PROBE not in log                                # 探针 SA 不算
    finally:
        L.query(L.admin_creds(), f"DELETE FROM `{L.T_ACL}` WHERE sa IN ('{L.SA_LATE}', '{L.SA_READER}')")
        L.query(L.admin_creds(), f"INSERT INTO `{L.T_ACL}` (sa, acl_group) VALUES ('{L.SA_READER}', 'full_read')")
    assert _inspect(*acl)[0] == 0


def test_inspect_detects_filter_drift_and_fix(world):
    L.query(L.admin_creds(),
            f'CREATE OR REPLACE ROW ACCESS POLICY {COPILOT} ON `{L.T_SENSITIVE}` '
            f'GRANT TO ("group:{L.G_HIGH}", "group:{L.G_LOW}") FILTER USING (region = "HK")')
    code, log = _inspect()
    assert code == 1 and "sensitive" in log and "过滤条件" in log, log
    code, log = _copilot_rls(L.T_SENSITIVE)
    assert code == 0 and "[REPLACE]" in log, log
    assert _inspect()[0] == 0


def test_e1_case_insensitive_round_trip(world):
    """--case-insensitive 是全局开关：所有表统一用 UPPER() 条件、巡检带同样参数；数据过滤结果不变。"""
    ci_tables = (L.T_ORDERS, L.T_SENSITIVE, L.T_ALT)            # 与 _inspect 巡检的表一致
    code, log = _copilot_rls(*ci_tables, extra=["--case-insensitive"])
    assert code == 0 and log.count("[REPLACE]") == 3, log
    for t in ci_tables:
        assert "UPPER(" in L.policies(t)[COPILOT]["filter"]
    code, log = _inspect()                                      # 不带参数巡检 -> 三张表过滤条件都不一致
    assert code == 1 and log.count("过滤条件与映射表不一致") == 3, log
    code, log = _inspect("--case-insensitive")
    assert code == 0 and log.count("[OK]") == 3, log
    L.eventually(lambda: _assert_eq(L.amounts(_as_copilot(L.SA_COP_HI), L.T_SENSITIVE)[1], [1, 2, 3, 6]),
                 desc="ci rows sensitive")
    L.eventually(lambda: _assert_eq(L.amounts(_as_copilot(L.SA_COP_HI), L.T_ORDERS)[1], [1, 3]),
                 desc="ci rows orders")
    code, log = _copilot_rls(*ci_tables)                        # 恢复为大小写敏感
    assert code == 0 and log.count("[REPLACE]") == 3, log
    assert _inspect()[0] == 0


def test_e2_inspect_copilot_membership(world):
    """巡检：条件表聚簇、SA 归属、API SA、无条件行提醒。"""
    code, log = _inspect("--api-sa", L.SA_API)
    assert code == 0, log
    assert f"[WARN] {L.SA_COP_NONE} 在 Copilot 组中但条件表没有条件行" in log     # 提醒不影响退出码
    assert "未按 sa 聚簇" not in log
    L.set_group_member(L.G_LOW, L.SA_COP_HI, True)              # 制造"一 SA 两组"
    try:
        code, log = _inspect("--api-sa", L.SA_API)
        assert code == 1 and f"[ISSUE] {L.SA_COP_HI} 同时属于多个 Copilot 组" in log, log
    finally:
        L.set_group_member(L.G_LOW, L.SA_COP_HI, False)
    assert _inspect("--api-sa", L.SA_API)[0] == 0


def test_t5_hot_patch_whitelist_and_inspect_membership(world):
    # 热修补：只把遗漏账号加入白名单 Group，不碰 RLS
    code, log = L.run_cli("whitelist_groups.py", "--read-group", L.G_READ,
                          "--read-members", L.SA_LATE, "--copilot-patterns", L.COPILOT_PATTERN,
                          "--apply")
    assert code == 0, log
    assert L.SA_LATE in L.group_members(L.G_READ)
    # 巡检能发现白名单组混入 "Copilot SA"（此处把 late 视为 Copilot SA 验证检测逻辑）
    code, log = _inspect("--copilot-members", L.SA_LATE)
    assert code == 1 and L.SA_LATE in log, log


# =========================================================================== #
# Gate 2：端到端五项验收（admin -> API SA -> 权限 SA 链式扮演）
# =========================================================================== #
def _as_copilot(sa_email):
    return L.impersonate(sa_email, delegates=[L.SA_API])


def test_e2e_1_3_rows_filtered_and_job_identity_is_permission_sa(world):
    hi, lo = _as_copilot(L.SA_COP_HI), _as_copilot(L.SA_COP_LO)

    def check():
        job, got = L.amounts(hi, L.T_ORDERS)
        assert got == [1, 3]                                  # region∈{HK,SG} 且 refername=REF_A
        assert job.user_email.lower() == L.SA_COP_HI          # ③ Job 身份是权限 SA
        assert L.amounts(hi, L.T_SENSITIVE)[1] == [1, 2, 3, 6]  # 仅 region 过滤
        job, got = L.amounts(lo, L.T_ORDERS)
        assert got == [1, 4, 6]                               # prdtype=P1，其余维度通配
        assert job.user_email.lower() == L.SA_COP_LO
        # 异构表（area / ptype / meta.ref）过滤结果与 orders 一致
        assert L.amounts(hi, L.T_ALT)[1] == [1, 3]
        assert L.amounts(lo, L.T_ALT)[1] == [1, 4, 6]
    L.eventually(check, desc="copilot rows")


def test_e2e_1_low_group_cannot_read_high_table(world):
    with pytest.raises(Exception) as ei:
        L.amounts(_as_copilot(L.SA_COP_LO), L.T_SENSITIVE)
    assert L.is_forbidden(ei.value)


def test_e2e_2_no_condition_returns_nothing(world):
    none = _as_copilot(L.SA_COP_NONE)
    L.eventually(lambda: _assert_eq(L.amounts(none, L.T_ORDERS)[1], []), desc="no rows")


def _assert_eq(a, b):
    assert a == b, (a, b)


def test_e2e_4_etl_writes_unaffected(world):
    etl = L.impersonate(L.SA_ETL)
    L.query(etl, f"INSERT INTO `{L.T_ORDERS}` VALUES ('XX', 'PX', 'REF_X', 100)")
    L.query(etl, f"UPDATE `{L.T_ORDERS}` SET amount = 101 WHERE region = 'XX'")
    assert L.amounts(etl, L.T_ORDERS)[1] == L.ALL_AMOUNTS + [101]
    L.query(etl, f"DELETE FROM `{L.T_ORDERS}` WHERE region = 'XX'")
    assert L.amounts(etl, L.T_ORDERS)[1] == L.ALL_AMOUNTS


def test_e2e_5_whitelist_full_read(world):
    reader = L.impersonate(L.SA_READER)
    assert L.amounts(reader, L.T_ORDERS)[1] == L.ALL_AMOUNTS
    assert L.amounts(reader, L.T_SENSITIVE)[1] == L.ALL_AMOUNTS


def test_e2e_api_sa_has_no_data_access_and_only_api_sa_can_impersonate(world):
    with pytest.raises(Exception) as ei:
        L.amounts(L.impersonate(L.SA_API), L.T_ORDERS)
    assert L.is_forbidden(ei.value)
    # 权限 SA 只授权 API SA 扮演：经由其他 SA（ETL）的扮演链会被拒绝
    with pytest.raises(RefreshError):
        L.amounts(L.impersonate(L.SA_COP_HI, delegates=[L.SA_ETL]), L.T_ORDERS)


# =========================================================================== #
# T5  回退
# =========================================================================== #
def test_t5_rollback_by_policy_name_with_backup(world, tmp_path):
    code, log = L.run_cli("rollback_group_rls.py", "--tables", L.T_ORDERS,
                          "--policy-names", COPILOT, "--backup-dir", str(tmp_path), "--apply")
    assert code == 0, log
    assert set(L.policies(L.T_ORDERS)) == {BYPASS}
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    backup = json.loads(files[0].read_text())
    ids = {p["id"] for p in backup["policies"]}
    assert ids == {BYPASS, COPILOT}
    cop = next(p for p in backup["policies"] if p["id"] == COPILOT)
    assert cop["ddl"].startswith(f"CREATE OR REPLACE ROW ACCESS POLICY `{COPILOT}`")


def test_t5_rollback_all(world):
    tables = [L.T_ORDERS, L.T_SENSITIVE, L.T_CONFLICT, L.T_ALT, L.T_BADMAP, L.T_PART]
    code, log = L.run_cli("rollback_group_rls.py", "--tables", ",".join(tables), "--apply")
    assert code == 0, log
    for t in tables:
        assert L.policies(t) == {}
