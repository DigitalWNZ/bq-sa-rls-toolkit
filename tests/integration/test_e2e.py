"""
端到端集成测试：按 Doc 流程在真实 GCP 项目上依次运行 4 个脚本，并以各账号身份查表验证可见性。
  第 1 步 list_principals.py → 第 3 步 apply_bypass_rls.py → 第 7 步 apply_copilot_rls.py → 第 8 步 rollback_rls.py
用例之间有先后依赖（按文件顺序执行）。
"""

import csv
import os
import re

import pytest

import rls_core as core
from tests.integration import itlib as L

pytestmark = pytest.mark.integration

BYP_R = core.bypass_policy_name(L.G_READ)
BYP_W = core.bypass_policy_name(L.G_WRITE)
COP_G = core.copilot_policy_name(L.G_COPILOT)          # 每张表一条 Copilot 规则，授权给 Copilot Group
COPILOT_TABLES = [L.T_ORDERS, L.T_ALT, L.T_PART]


def bypass(*args):
    return L.run_cli("apply_bypass_rls.py", "--registry-table", L.T_REGISTRY, *args)


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_list(tmp_path, name, values):
    f = tmp_path / name
    f.write_text("\n".join(values) + "\n", encoding="utf-8")
    return str(f)


# =========================================================================== #
# 第 1 步：list_principals.py
# =========================================================================== #
EXPECTED_SAS = set(L.ALL_SAS)


def _iam_project_sas(project):
    """IAM API 直接列出的项目 SA（权威，用来核对 list_principals 不遗漏）。"""
    iam = L.api("iam", "v1")
    out, req = set(), iam.projects().serviceAccounts().list(name=f"projects/{project}", pageSize=100)
    while req is not None:
        r = req.execute()
        out |= {a["email"].lower() for a in r.get("accounts", [])}
        req = iam.projects().serviceAccounts().list_next(req, r)
    return out


def _list(tmp_path, *scope_args, env=None):
    out = tmp_path / "principals.csv"
    code, log = L.run_cli("list_principals.py", *scope_args, "-o", str(out), "--quota-project", L.PROJECT, env=env)
    return code, log, {r["email"]: r for r in read_csv(out)}


def test_01_list_principals_project_scope(world, tmp_path):
    code, log, rows = _list(tmp_path, "--projects", L.PROJECT)
    assert code == 0, log
    with open(tmp_path / "principals.csv", encoding="utf-8-sig") as f:
        assert next(csv.reader(f)) == core.PRINCIPAL_COLUMNS == ["email", "principal_type", "home_project"]
    # 不遗漏：项目里的全部 SA（含没有任何授权的）都在结果中，与 IAM API 完全一致
    project_sas = _iam_project_sas(L.PROJECT)
    assert len(project_sas) >= 100 and project_sas <= set(rows), sorted(project_sas - set(rows))[:10]
    assert EXPECTED_SAS <= set(rows)
    etl = rows[L.SA_ETL]
    assert etl == {"email": L.SA_ETL, "principal_type": "serviceAccount", "home_project": L.PROJECT}
    assert rows[L.ACCOUNT]["principal_type"] == "user"                # 项目 IAM 里能读表的 user（Owner）
    assert L.SA_ACL in rows                                            # 数据集 ACL 中 Group 的成员
    assert not any(e.startswith(f"{L.PREFIX}-") and e.endswith(L.DOMAIN) for e in rows)   # Group 本身不列出
    for tag in ("[SA] 项目", "[IAM]", "[ACL]", "[TABLE]", "[GROUP]"):
        assert tag in log, tag
    assert "[DIR]" not in log                                          # 只指定项目时不读账号目录


@pytest.mark.skipif(not L.ORG, reason="未设置 RLS_IT_ORG")
def test_02_list_principals_org_scope(world, tmp_path):
    # 执行账号（Argolis 的 admin@）是 Workspace 超级管理员：用它自己的 gcloud 凭证读账号目录
    code, log, rows = _list(tmp_path, "--organizations", L.ORG)
    assert code == 0 and "[ERROR]" not in log and "Traceback" not in log, log
    assert "[ORG] organizations/" in log and "[DIR] 账号目录" in log
    for prj in ("rls-sapool-harrishe-1", "rls-sapool-harrishe-5"):    # 组织下其它项目的 SA（没有任何授权）也列出
        assert _iam_project_sas(prj) <= set(rows), prj
    assert _iam_project_sas(L.PROJECT) <= set(rows)
    users = _directory_users_expected()                                # 账号目录里的全部 user（含没有任何授权的）
    assert users and users <= set(rows), sorted(users - set(rows))[:10]
    assert rows[L.ACCOUNT]["principal_type"] == "user" and L.SA_ACL in rows


def _directory_users_expected():
    """直接调用 Admin SDK（与脚本独立的 HTTP 请求）列出账号目录里的全部 user，作为核对基准。"""
    import requests
    token = L.admin_creds()
    token.refresh(None)
    crm = L.api("cloudresourcemanager", "v3")
    customer = crm.organizations().get(name=f"organizations/{L.ORG}").execute()["directoryCustomerId"]
    out, page = set(), None
    while True:
        params = {"customer": customer, "maxResults": 500, "projection": "basic"}
        if page:
            params["pageToken"] = page
        r = requests.get("https://admin.googleapis.com/admin/directory/v1/users", params=params, timeout=60,
                         headers={"Authorization": f"Bearer {token.token}", "x-goog-user-project": L.PROJECT})
        r.raise_for_status()
        d = r.json()
        out |= {u["primaryEmail"].lower() for u in d.get("users", [])}
        page = d.get("nextPageToken")
        if not page:
            return out


def test_04_auth_auto_resolved_without_account_and_quota_flags(world, tmp_path):
    # 不给 --gcloud-account / --quota-project：账号取 gcloud 当前活动账号，quota 项目取 gcloud 默认项目
    # （用 CLOUDSDK_CORE_ACCOUNT / CLOUDSDK_CORE_PROJECT 环境变量模拟客户的 gcloud config，不改动本机配置）
    env = {"CLOUDSDK_CORE_ACCOUNT": L.ACCOUNT, "CLOUDSDK_CORE_PROJECT": L.PROJECT}
    out = tmp_path / "p.csv"
    code, log = L.run_cli("list_principals.py", "--projects", L.PROJECT, "-o", str(out), env=env, auto_auth=True)
    assert code == 0, log
    assert f"[AUTH] 执行账号: {L.ACCOUNT}（gcloud 当前活动账号）；quota 项目: {L.PROJECT}（gcloud 默认项目）" in log
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_NOMAP, "--policy-names", "no_such_rule", env=env, auto_auth=True)
    assert code == 0 and "（gcloud 当前活动账号）" in log, log
    # gcloud 没有活动账号、也没有 application-default 凭证 → 退出码 2，提示 gcloud auth login
    bad = {"CLOUDSDK_CORE_ACCOUNT": "", "CLOUDSDK_CONFIG": str(tmp_path / "empty-gcloud"),
           "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "none.json")}
    code, log = L.run_cli("list_principals.py", "--projects", L.PROJECT, "-o", str(out), env=bad, auto_auth=True)
    assert code == 2 and "gcloud auth login" in log and "Traceback" not in log, log


def test_03_list_principals_files_and_exclusions(world, tmp_path):
    out = tmp_path / "p.csv"
    code, log = L.run_cli("list_principals.py", "--projects", write_list(tmp_path, "projects.csv", [L.PROJECT]),
                          "--exclude-patterns", f"{L.PREFIX}-cop-*@*", "--exclude-members", L.ACCOUNT,
                          "-o", str(out))
    emails = {r["email"] for r in read_csv(out)}
    assert code == 0, log
    assert L.SA_ETL in emails and L.SA_COP_A not in emails and L.ACCOUNT not in emails


# =========================================================================== #
# 第 3 步：apply_bypass_rls.py
# =========================================================================== #
def test_10_bypass_first_policy_listed_as_note_dry_run(world):
    # 首条策略保护已删除：只在日志中列出（演练，不做变更）
    code, log = bypass("--group", L.G_READ, "--tables", L.T_ORDERS, "--datasets", f"{L.PROJECT}.{L.DATASET}")
    assert code == 0, log
    assert "将为以下这些表首次设置RLS规则" in log and "--force-first-policy" not in log
    for t in L.TARGET_TABLES:
        assert f"  - {t}" in log
        assert L.policies(t) == {}
    assert f"[SKIP] {L.T_DISABLED}: 登记表中 rls_enabled ≠ 1，不授权" in log
    assert f"  - {L.T_DISABLED}" not in log                              # 跳过的表不进首条策略清单


def test_11_bypass_apply_read_and_write_groups(world, tmp_path):
    code, log = bypass("--group", L.G_READ, "--tables", L.T_ORDERS,
                          "--datasets", write_list(tmp_path, "ds.csv", [f"{L.PROJECT}.{L.DATASET}"]),
                          "--apply", "--verify-sa", L.SA_READER)
    assert code == 0, log
    assert log.count("[VERIFY-OK]") == len(L.TARGET_TABLES)
    assert L.policies(L.T_DISABLED) == {}
    # 第二个组：表上已有规则，不再是首条，无需 --force-first-policy
    code, log = bypass("--group", L.G_WRITE,
                          "--tables", write_list(tmp_path, "t.csv", L.TARGET_TABLES), "--apply")
    assert code == 0, log
    for t in L.TARGET_TABLES:
        pols = L.policies(t)
        assert pols[BYP_R]["filter"].upper() == "TRUE" and pols[BYP_R]["grantees"] == {f"group:{L.G_READ}"}
        assert pols[BYP_W]["grantees"] == {f"group:{L.G_WRITE}"}


def test_11b_bypass_projects_scope_union_then_registry_dry_run(world):
    # --tables 必填；--projects 追加项目内全部普通表，再与登记表 rls_enabled=1 取交集；只演练，不做变更
    code, log = bypass("--group", L.G_WRITE, "--tables", L.T_ORDERS, "--projects", L.PROJECT)
    assert code == 0, log
    for t in L.TARGET_TABLES + [L.T_NOBYPASS]:
        assert re.search(rf"\[(CREATE|NOOP)\] {re.escape(t)}\n", log), t
    for t in (L.T_DISABLED, L.T_COND, L.T_MAPPING, L.T_MAPPING_NB, L.T_REGISTRY):
        assert f"[SKIP] {t}" in log and f"[CREATE] {t}" not in log
    for t in (L.T_MAPPING_NB, L.T_REGISTRY):                                # 登记表自身 / 备用映射表都登记为未开启
        assert f"[SKIP] {t}: 登记表中 rls_enabled ≠ 1，不授权" in log
    assert L.T_DROPPED not in log                                          # 项目范围只展开实际存在的表
    assert L.policies(L.T_COND) == {} and L.policies(L.T_NOBYPASS) == {}


def test_11c_bypass_auth_tables_follow_registry(world):
    # 条件表 / 映射表保护已删除：它们与其它表一样只看登记表（这里全部登记为未开启 → 跳过）
    code, log = bypass("--group", L.G_READ, "--tables", f"{L.T_COND},{L.T_MAPPING},{L.T_ORDERS}",
                       "--datasets", f"{L.PROJECT}.{L.AUTH_DATASET}", "--apply")
    assert code == 0, log
    assert "[EXCLUDE]" not in log and f"[NOOP] {L.T_ORDERS}" in log
    for t in (L.T_COND, L.T_MAPPING, L.T_MAPPING_NB, L.T_REGISTRY):
        assert f"[SKIP] {t}: 登记表中 rls_enabled ≠ 1，不授权" in log and L.policies(t) == {}


def test_11d_bypass_registry_errors(world):
    code, log = bypass("--group", L.G_READ, "--apply")
    assert code == 2 and "--tables" in log and "--datasets" in log, log  # 三类范围都没给
    code, log = bypass("--group", L.G_READ, "--datasets", f"{L.PROJECT}.{L.DATASET}")
    assert code == 0 and f"[SKIP] {L.T_DISABLED}" in log, log            # 只给数据集即可（演练），登记表照样把关
    code, log = L.run_cli("apply_bypass_rls.py", "--registry-table", f"{L.PROJECT}.{L.AUTH_DATASET}.typo_reg",
                          "--group", L.G_READ, "--tables", L.T_ORDERS, "--apply")
    assert code == 2 and "typo_reg" in log, log                          # 登记表不存在
    code, log = L.run_cli("apply_bypass_rls.py", "--registry-table", L.T_COND,
                          "--group", L.G_READ, "--tables", L.T_ORDERS, "--apply")
    assert code == 2 and "table_name" in log, log                        # 不是登记表结构
    code, log = L.run_cli("apply_bypass_rls.py", "--condition-table", L.T_COND, "--registry-table", L.T_REGISTRY,
                          "--group", L.G_READ, "--tables", L.T_ORDERS)
    assert code == 2, log                                                # 旧参数不再接受


def test_11e_bypass_registry_conflict_warns_and_skips(world):
    # 同一 table_name 再插一行 rls_enabled=0 → 冲突：[WARN] + [SKIP]，退出码 1；其余表照常
    L.run_sql(f"INSERT INTO `{L.T_REGISTRY}` (id, table_name, rls_enabled, status, create_time, update_time) "
              f"VALUES (GENERATE_UUID(), '{L.T_DISABLED}', 1, 0, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())")
    try:
        code, log = bypass("--group", L.G_READ, "--tables", f"{L.T_DISABLED},{L.T_ORDERS}", "--apply")
        assert code == 1, log
        assert f"[WARN] {L.T_DISABLED}" in log and f"[SKIP] {L.T_DISABLED}" in log and f"[NOOP] {L.T_ORDERS}" in log
        assert L.policies(L.T_DISABLED) == {}
    finally:
        L.run_sql(f"DELETE FROM `{L.T_REGISTRY}` WHERE table_name = '{L.T_DISABLED}' AND rls_enabled = 1")


def test_12_bypass_rerun_is_noop(world):
    code, log = bypass("--group", L.G_READ, "--tables", ",".join(L.TARGET_TABLES))
    assert code == 0, log
    assert log.count("[NOOP]") == len(L.TARGET_TABLES) and "[CREATE]" not in log and "[REPLACE]" not in log


def test_13_bypass_effect(world):
    L.expect_amounts(L.SA_READER, L.T_ORDERS, L.ALL_AMOUNTS)
    L.expect_amounts(L.SA_ETL, L.T_ALT, L.ALL_AMOUNTS)
    L.expect_amounts(L.SA_COP_A, L.T_ORDERS, [])             # 未被任何规则授权：0 行


def test_14_bypass_replace_prints_old_content(world):
    # 手工把 T_NOMAP 上的 read 规则改坏，再运行脚本应 REPLACE 回 TRUE
    L.run_sql(f'CREATE OR REPLACE ROW ACCESS POLICY `{BYP_R}` ON `{L.T_NOMAP}` '
              f'GRANT TO ("group:{L.G_READ}") FILTER USING (region = "HK")')
    code, log = bypass("--group", L.G_READ, "--tables", L.T_NOMAP, "--apply")
    assert code == 0, log
    assert f"[REPLACE] {L.T_NOMAP}" in log and "HK" in log
    assert L.policies(L.T_NOMAP)[BYP_R]["filter"].upper() == "TRUE"


# =========================================================================== #
# 第 7 步：apply_copilot_rls.py
# =========================================================================== #
def copilot(*args):
    return L.run_cli("apply_copilot_rls.py", "--condition-table", L.T_COND, "--registry-table", L.T_REGISTRY,
                     "--group", L.G_COPILOT, *args)


def test_20_copilot_no_bypass_gate_dry_run(world, tmp_path):
    # bypass 闸门已删除：没有 bypass 规则的表照常计划建规则，首次设置 RLS 的表只作提示（演练，不做变更）
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING_NB, "-o", str(out))
    assert code == 0, log
    assert "[ABORT]" not in log and "将为以下这些表首次设置RLS规则" in log and f"  - {L.T_NOBYPASS}" in log
    assert {r["table"] for r in read_csv(out)} == {L.T_NOBYPASS} and L.policies(L.T_NOBYPASS) == {}
    code, log = L.run_cli("apply_copilot_rls.py", "--condition-table", L.T_COND, "--mapping-table", L.T_MAPPING,
                          "--group", L.G_COPILOT)
    assert code == 2, log                                                  # 缺少必填的 --registry-table
    code, log = L.run_cli("apply_copilot_rls.py", "--condition-table", L.T_COND, "--mapping-table", L.T_MAPPING,
                          "--registry-table", L.T_REGISTRY)
    assert code == 2, log                                                  # 缺少必填的 --group


def test_21_copilot_dry_run_all_tables(world, tmp_path):
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out))
    assert code == 1, log                                                  # bad_mapping_t 被跳过
    assert f"[SKIP] {L.T_BADMAP}" in log and "not_a_dimension" in log      # 无效 to_name 行被忽略
    assert f"[SKIP] {L.T_COND}: 登记表中 rls_enabled ≠ 1" in log and "[EXCLUDE]" not in log   # 误配的条件表由登记表挡住
    assert f"[SKIP] {L.T_NOMAP}: 映射表中没有该表的校验维度" in log         # 登记为开启但没有维度
    assert f"[SKIP] {L.T_DROPPED}: {core.TABLE_NOT_FOUND_MSG}" in log       # 映射表 / 登记表里有，但表已被 drop
    assert "Traceback" not in log
    rows = read_csv(out)
    assert sorted(r["table"] for r in rows) == sorted(COPILOT_TABLES)     # 每张表一行
    assert {r["action"] for r in rows} == {"CREATE"} and {r["policy_name"] for r in rows} == {COP_G}
    for t in COPILOT_TABLES:
        assert not any(p.startswith(core.COPILOT_PREFIX) for p in L.policies(t))


def test_22_copilot_apply(world, tmp_path):
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out), "--apply",
                        "--tables", write_list(tmp_path, "t.csv", COPILOT_TABLES))
    assert code == 0, log
    rows = read_csv(out)
    assert len(rows) == 3 and {r["result"] for r in rows} == {"OK"}
    for t in COPILOT_TABLES:
        cop = [p for p in L.policies(t) if p.startswith(core.COPILOT_PREFIX)]
        assert cop == [COP_G] and L.policies(t)[COP_G]["grantees"] == {f"group:{L.G_COPILOT}"}
    assert "market" in L.policies(L.T_ALT)[COP_G]["filter"]
    assert not any(p.startswith(core.COPILOT_PREFIX) for p in L.policies(L.T_NOMAP))
    assert L.policies(L.T_COND) == {} and L.policies(L.T_MAPPING) == {}
    # 运行日志：--log-dir 下生成 apply_copilot_rls_<时间戳>.log，内容与屏幕输出完全一致
    m = re.match(r"\[LOG\] 日志文件: (\S+)\n", log)
    assert m and os.path.basename(m[1]).startswith("apply_copilot_rls_"), log[:300]
    with open(m[1], encoding="utf-8") as f:
        assert f.read() == log


def test_22b_copilot_dropped_table_isolated_in_apply(world, tmp_path):
    # 执行模式下，已被 drop 的表只跳过它自己：其余表照常处理（这里 orders 已建好 → NOOP），退出码 1
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out), "--apply",
                        "--tables", f"{L.T_ORDERS},{L.T_DROPPED}")
    assert code == 1, log
    assert f"[SKIP] {L.T_DROPPED}: {core.TABLE_NOT_FOUND_MSG}" in log and f"[NOOP] {L.T_ORDERS}" in log
    assert "Traceback" not in log and read_csv(out) == []
    assert COP_G in L.policies(L.T_ORDERS)


def test_23_copilot_visibility(world):
    for t in COPILOT_TABLES:
        L.expect_amounts(L.SA_COP_A, t, L.HK)                  # region = ['HK']
        L.expect_amounts(L.SA_COP_B, t, L.ALL_AMOUNTS)         # 全部维度为空 = 全部可见
    L.expect_amounts(L.SA_COP_M, L.T_ORDERS, L.HK_MOBILE)      # region = ['HK'] 且 prdtype = ['mobile']：两个条件同时满足
    L.expect_amounts(L.SA_COP_M, L.T_ALT, L.HK_MOBILE)         # 列名不同（market / ptype）也一样
    L.expect_amounts(L.SA_COP_M, L.T_PART, L.HK)               # orders_part 只映射了 region：HK 全部
    L.expect_amounts(L.ACCOUNT, L.T_ORDERS, L.SG)              # user 主体：region = ['SG']
    L.expect_amounts(L.SA_READER, L.T_ORDERS, L.ALL_AMOUNTS)   # 白名单不受影响
    L.expect_amounts(L.SA_COP_N, L.T_ORDERS, [])               # 在 Group 里但不在条件表：0 行
    L.expect_amounts(L.SA_COP_B, L.T_NOMAP, [])                # 没有校验维度的表：只有 bypass 规则，Copilot 成员 0 行


def test_24_condition_change_takes_effect_without_rerun(world):
    L.run_sql(f"UPDATE `{L.T_COND}` SET region = ['SG', 'US'] WHERE sa = '{L.SA_COP_A}'")
    L.expect_amounts(L.SA_COP_A, L.T_ORDERS, sorted(L.SG + L.US))
    L.expect_amounts(L.SA_COP_A, L.T_ALT, sorted(L.SG + L.US))


def test_25_new_principal_takes_effect_without_rerun(world, tmp_path):
    # Group 级别：新增账号只要在 Group 里、条件表写一行，不跑脚本即可生效
    L.run_sql(f"INSERT INTO `{L.T_COND}` (id, sa, region, prdtype, refername) "
              f"VALUES ('c5', '{L.SA_COP_N}', [], ['P1'], [])")
    L.expect_amounts(L.SA_COP_N, L.T_ORDERS, [1, 4, 6])        # prdtype = ['P1']
    L.expect_amounts(L.SA_COP_N, L.T_PART, L.ALL_AMOUNTS)      # orders_part 只映射了 region：全部可见
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out), "--apply", "--tables", ",".join(COPILOT_TABLES))
    assert code == 0 and read_csv(out) == [] and "NOOP 3" in log, log   # 重跑也不会有任何变更


def test_26_copilot_rerun_noop_and_replace(world, tmp_path):
    out = tmp_path / "plan.csv"
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out), "--apply",
                        "--tables", ",".join(COPILOT_TABLES))
    assert code == 0, log
    assert read_csv(out) == [] and "NOOP 3" in log
    # 手工改坏 Group 规则 → REPLACE，note 里记录旧过滤条件
    L.run_sql(f'CREATE OR REPLACE ROW ACCESS POLICY `{COP_G}` ON `{L.T_ORDERS}` '
              f'GRANT TO ("group:{L.G_COPILOT}") FILTER USING (region = "XX")')
    code, log = copilot("--mapping-table", L.T_MAPPING, "-o", str(out), "--apply", "--tables", L.T_ORDERS)
    rows = read_csv(out)
    assert code == 0 and len(rows) == 1 and rows[0]["action"] == "REPLACE" and "XX" in rows[0]["note"], log
    L.expect_amounts(L.SA_COP_B, L.T_ORDERS, L.ALL_AMOUNTS)


# =========================================================================== #
# 第 8 步：rollback_rls.py
# =========================================================================== #
def test_30_rollback_no_filter_means_all_dry_run(world):
    # 删除全部保护已删除：不给 --principals / --policy-names = 删除全部规则（这里只演练，不做变更）
    before = L.policies(L.T_ORDERS)
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_ORDERS)
    assert code == 0, log
    assert f"DROP ALL ROW ACCESS POLICIES ON `{L.T_ORDERS}`" in log and f"  - {L.T_ORDERS}" in log
    assert L.policies(L.T_ORDERS) == before
    for flag in ("--all-policies", "--force-drop-all"):                    # 旧参数不再接受
        code, log = L.run_cli("rollback_rls.py", "--tables", L.T_ORDERS, flag)
        assert code == 2, log


def test_31_rollback_copilot_group(world):
    # 撤销 Copilot：按 Group 回退（删除各表上授权给 Copilot Group 的那一条规则），bypass 不受影响
    code, log = L.run_cli("rollback_rls.py", "--datasets", f"{L.PROJECT}.{L.DATASET}",
                          "--principals", L.G_COPILOT, "--apply", "--verify-sa", L.SA_COP_A)
    assert code == 0, log
    assert f"[DROP] `{COP_G}`" in log and f"group:{L.G_COPILOT}" in log
    assert f"可见 0 行 / 表共 {len(L.ROWS)} 行" in log
    for t in COPILOT_TABLES:
        pols = L.policies(t)
        assert COP_G not in pols and BYP_R in pols
    L.expect_amounts(L.SA_COP_A, L.T_ORDERS, [])
    L.expect_amounts(L.SA_COP_B, L.T_ORDERS, [])
    L.expect_amounts(L.SA_READER, L.T_ORDERS, L.ALL_AMOUNTS)


def test_32_rollback_user_principal_and_policy_name(world, tmp_path):
    # user 主体：用一条手工建的、只授权给执行账号的规则验证按 user 邮箱回退
    manual = "manual_user_rule"
    L.run_sql(f'CREATE OR REPLACE ROW ACCESS POLICY `{manual}` ON `{L.T_ORDERS}` '
              f'GRANT TO ("user:{L.ACCOUNT}") FILTER USING (TRUE)')
    code, log = L.run_cli("rollback_rls.py", "--tables", ",".join(COPILOT_TABLES),
                          "--principals", write_list(tmp_path, "p.csv", [L.ACCOUNT]), "--apply")
    assert code == 0 and manual not in L.policies(L.T_ORDERS) and BYP_R in L.policies(L.T_ORDERS), log
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_ALT,
                          "--policy-names", write_list(tmp_path, "n.csv", [BYP_W]), "--apply")
    assert code == 0 and BYP_W not in L.policies(L.T_ALT) and BYP_R in L.policies(L.T_ALT), log


def test_33_rollback_group_principal(world):
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_BADMAP, "--principals", L.G_WRITE, "--apply")
    assert code == 0, log
    assert set(L.policies(L.T_BADMAP)) == {BYP_R}


def test_34_drop_all_not_blocked(world):
    # 删光保护已删除：单个主体恰好删光（bad_mapping_t 只剩 read 规则）直接执行，清单只作提示
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_BADMAP, "--principals", L.G_READ, "--apply")
    assert code == 0 and L.policies(L.T_BADMAP) == {}, log
    assert "以下这些表的 RLS 规则将被全部删除（删除后所有有读表权限的账号都能看到全部数据）：" in log
    assert f"  - {L.T_BADMAP}" in log and "--force-drop-all" not in log
    # 不给筛选 = 删除全部
    code, log = L.run_cli("rollback_rls.py", "--tables", L.T_ORDERS, "--apply")
    assert code == 0 and f"DROP ALL ROW ACCESS POLICIES ON `{L.T_ORDERS}`" in log, log
    assert L.policies(L.T_ORDERS) == {}
    L.expect_amounts(L.SA_COP_A, L.T_ORDERS, L.ALL_AMOUNTS)   # 没有 RLS 后，有读权限的账号都能看到全部数据
