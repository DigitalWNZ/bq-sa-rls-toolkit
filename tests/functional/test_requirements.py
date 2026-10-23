"""
功能测试：逐条验证客户需求（F01–F20）是否 100% 满足。每个测试对应一条需求，在内存模拟的 GCP 上按客户的真实操作流程运行脚本。
真实环境中对应的系统测试见 tests/integration（映射见 REQUIREMENTS 的第三列）。

运行：.venv/bin/python -m pytest tests/functional -v
"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

# 需求编号 -> (需求描述, 真实环境系统测试)
REQUIREMENTS = {
    "F01": ("list_principals 项目范围：列出项目里全部 SA（含没有任何授权的、已禁用的）", "test_e2e::test_01"),
    "F02": ("list_principals 组织范围：递归所有文件夹下 ACTIVE 项目的全部 SA；待删除项目也尝试列出其中的 SA（失败只 [NOTE]）", "test_e2e::test_02"),
    "F03": ("list_principals 组织范围：账号目录全部 user（含没有任何授权的、暂停 / 归档、多域名）与全部 Group", "test_e2e::test_02"),
    "F04": ("list_principals：授权记录（组织 / 文件夹 / 项目 IAM、数据集 ACL、表 IAM）中的全部授权对象，不看角色"
            "（其它项目 SA、外部 user、服务代理、Group 及其直接成员）", "test_e2e::test_01/02"),
    "F05": ("list_principals：输出 3 列 email, principal_type, source（在哪里、以什么角色被找到）；不使用 Cloud Asset", "test_e2e::test_01"),
    "F06": ("apply_bypass：为一个白名单 Group 建 FILTER TRUE 规则（每 Group 一条，一次一个），ReadOnly / Writable 各一次", "test_e2e::test_11/12/13"),
    "F07": ("apply_bypass：目标表 = 登记表中 rls_enabled = 1 的全部表，不扫描项目 / 数据集；--tables / --datasets / --projects "
            "已删除（传入即参数错误）", "test_e2e::test_10/11/11d/11f"),
    "F08": ("apply_bypass：只有 rls_enabled = 1 的表授权；不看 status；表名格式不对 / 同名冲突 [WARN] + [SKIP]、表不存在 [SKIP]，"
            "退出码 1，其余表照常", "test_e2e::test_10/11e/z_abnormal::r01"),
    "F09": ("apply_copilot：每张表给 Copilot Group 建一条规则，过滤条件与客户 sample 一致；同组成员按条件表各看各的", "test_e2e::test_22/23"),
    "F10": ("apply_copilot：维度 = 条件表除 id、sa、status 外的 ARRAY<STRING> 列；表的维度 = 映射表 to_name；多维度 AND；"
            "只有 status = 1 的行生效（每个子查询都加 c.status = 1），条件表缺 status 列退出码 2", "test_e2e::test_21/22/23/25b/25c"),
    "F11": ("apply_copilot：只处理登记表 rls_enabled = 1 的表；没有校验维度的表 [SKIP]；表已不存在 [SKIP]、其余表照常",
            "test_e2e::test_21/22b"),
    "F12": ("新增 Copilot 账号：加入 Group + 条件表加一行即生效，无需重跑脚本", "test_e2e::test_25"),
    "F13": ("457 / 500 个账号也不超过每表 400 条规则上限（每表每 Group 一条）", "perf::run_perf"),
    "F14": ("条件表 / 映射表是否设置 RLS 只由登记表控制（不再有 [EXCLUDE] 保护）", "test_e2e::test_11/21"),
    "F15": ("不再有任何「闸门」：copilot 不要求 bypass；bypass 首条只提示；rollback 无删除全部 / 删光保护", "test_e2e::test_10/20/30/34"),
    "F16": ("rollback：按主体（Group / SA / user，含手工规则）、按规则名、或全部删除；两者取交集；删光只提示", "test_e2e::test_31–34"),
    "F17": ("三个 RLS 脚本默认只演练，--apply 才执行", "test_e2e::test_10/21/30"),
    "F18": ("参数精简：值或 .csv 文件、可重复累加；表名 project.dataset.table（反引号可选、不支持冒号）；旧参数被拒；--parallel 默认 16", "test_e2e::test_11d/32"),
    "F19": ("执行账号 / quota 项目自动确定（gcloud 活动账号 → ADC；gcloud 默认项目 → ADC quota）；确定不了退出码 2 + 提示", "test_e2e::test_04"),
    "F20": ("出错不输出 Python 堆栈；退出码 0 成功 / 1 部分失败或数据问题 / 2 参数或环境错误（未做任何变更）", "test_z_abnormal::r05/r06/r07"),
    "F21": ("每次运行自动保存日志文件：默认当前目录 logs/<脚本名>_<时间戳>.log、--log-dir 可改、内容与屏幕完全一致、"
            "建不了只 [WARN] 照常运行、不覆盖不清理", "test_e2e::test_22"),
    "F22": ("list_principals 项目范围：含从组织 / 文件夹继承的能读表数据的授权（读项目全部上级的策略）", "test_e2e::test_01c"),
    "F23": ("list_principals：展不开的 Group 作为 group 写入 CSV；外部域 [NOTE] 不影响退出码，本组织域名的 [ERROR] 退出码 1",
            "test_e2e::test_02"),
    "F24": ("list_principals：只有基本角色或读不到数据的角色（Job User、Browser 等）的 user / SA 也列出", "test_e2e::test_01d"),
    "F25": ("list_principals：授权视图 / 数据集 / 例程所在项目不在扫描范围时 [NOTE] 列出这些项目", "（本地）"),
    "F26": ("list_principals：授权记录中的 Group 只展开一层；嵌套组只列组名", "test_e2e::test_01e"),
    "F27": ("list_principals：非具体账号也写入 CSV（domain / public / federated / deleted）", "（本地）"),
}

P = "trip-prod"
T1, T2, T3, T4 = f"{P}.dw.orders", f"{P}.dw.booking", f"{P}.ods.events", f"{P}.dw.no_dim"
T_OFF = f"{P}.dw.disabled_t"
COND = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition"
MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G_R, G_W = "group_existingsa_read@trip.com", "group_existingsa_write@trip.com"
G_COP = "group_copilot@trip.com"
BYP_R, BYP_W, COP = core.bypass_policy_name(G_R), core.bypass_policy_name(G_W), core.copilot_policy_name(G_COP)
SA_A, SA_B, U_C = "copilot-a@trip-prod.iam.gserviceaccount.com", "copilot-b@trip-prod.iam.gserviceaccount.com", "carol@trip.com"


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    cols = {"region": ("STRING", "NULLABLE"), "prd_type": ("STRING", "NULLABLE"), "refername": ("STRING", "NULLABLE")}
    w.add_table(T1, schema=cols)
    w.add_table(T2, schema={"market": ("STRING", "NULLABLE")})
    w.add_table(T3, schema={"region": ("STRING", "NULLABLE"), "ptype": ("INT64", "NULLABLE")})
    w.add_table(T4, schema={"x": ("STRING", "NULLABLE")})
    w.add_table(T_OFF, schema={"region": ("STRING", "NULLABLE")}, rls_enabled=0)
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED"),
                                ("prdtype", "STRING", "REPEATED"), ("refername", "STRING", "REPEATED"),
                                ("status", "INTEGER", "NULLABLE")]
    w.condition_sas[COND] = [SA_A, SA_B, U_C]
    w.mapping_rows[MAP] = [
        {"table_name": T1, "col_name": "region", "to_name": "region"},
        {"table_name": T1, "col_name": "prd_type", "to_name": "prdtype"},
        {"table_name": T1, "col_name": "refername", "to_name": "refername"},
        {"table_name": T2, "col_name": "market", "to_name": "region"},
        {"table_name": T3, "col_name": "region", "to_name": "region"},
        {"table_name": T3, "col_name": "ptype", "to_name": "prdtype"},
        {"table_name": T_OFF, "col_name": "region", "to_name": "region"},
    ]
    # list_principals 数据
    w.crm_children["organizations/111"] = {"folders": ["folders/1"], "projects": [(P, "ACTIVE"), ("old", "DELETE_REQUESTED")]}
    w.crm_children["folders/1"] = {"folders": [], "projects": [("dev", "ACTIVE")]}
    w.org_customer["111"] = "C0trip"
    w.org_domain["111"] = "trip.com"
    w.directory_groups["C0trip"] = ["bi@trip.com", "idle-group@trip.com"]
    w.directory["C0trip"] = ["alice@trip.com", "idle-user@trip.com", "suspended@trip.com", "x@ctrip.com"]
    w.project_sas[P] = [SA_A, SA_B, "idle@trip-prod.iam.gserviceaccount.com", "disabled@trip-prod.iam.gserviceaccount.com"]
    w.project_sas["dev"] = ["dev-sa@dev.iam.gserviceaccount.com"]
    w.project_sas["old"] = ["ghost@old.iam.gserviceaccount.com"]
    w.iam_policies[f"projects/{P}"] = [
        {"role": "roles/bigquery.dataViewer", "members": ["serviceAccount:ext@partner.iam.gserviceaccount.com",
                                                         "group:bi@trip.com"]},
        {"role": "roles/bigquery.jobUser", "members": ["user:jobonly@vendor.com"]}]
    w.dataset_acl[f"{P}.dw"] = [("READER", "userByEmail", "vendor@partner.com")]
    w.table_iam[T1] = [{"role": "roles/bigquery.dataViewer",
                        "members": ["serviceAccount:service-1@gcp-sa-bigquery.iam.gserviceaccount.com"]}]
    w.groups["bi@trip.com"] = [("ana@trip.com", "USER"), ("nested@trip.com", "GROUP")]
    w.groups["nested@trip.com"] = [("deep@vendor.com", "USER")]
    install(monkeypatch, w)
    for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def lp(tmp_path, *args):
    out = tmp_path / "principals.csv"
    code = list_principals.main([*args, "-o", str(out)])
    return code, {r["email"]: r for r in read_csv(out)}, out


def bypass(group, *args):
    return apply_bypass_rls.main(["--group", group, "--registry-table", REG, *args])


def copilot(tmp_path, *args):
    out = tmp_path / "copilot.csv"
    code = apply_copilot_rls.main(["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP,
                                   "--registry-table", REG, "-o", str(out), *args])
    return code, (read_csv(out) if out.exists() else None)


def test_requirement_table_complete():
    assert sorted(REQUIREMENTS) == [f"F{i:02d}" for i in range(1, 28)]


# --------------------------------------------------------------------------- #
def test_F01_project_scope_lists_all_project_sas(world, tmp_path):
    code, rows, _ = lp(tmp_path, "--projects", P)
    assert code == 0 and set(world.project_sas[P]) <= set(rows)          # 含 idle（无授权）、disabled


def test_F02_org_scope_recursive_projects_active_only(world, tmp_path, capsys):
    code, rows, _ = lp(tmp_path, "--organizations", "111")
    assert code == 0 and "dev-sa@dev.iam.gserviceaccount.com" in rows
    assert rows["ghost@old.iam.gserviceaccount.com"]["source"] == "项目 SA: old（待删除项目）"


def test_F03_org_scope_lists_all_directory_users(world, tmp_path):
    _, rows, _ = lp(tmp_path, "--organizations", "111")
    assert set(world.directory["C0trip"]) <= set(rows)
    assert rows["idle-group@trip.com"] == {"email": "idle-group@trip.com", "principal_type": "group", "source": "账号目录 Group"}


def test_F04_bq_data_grantees_and_groups(world, tmp_path):
    _, rows, _ = lp(tmp_path, "--projects", P)
    for e in ("ext@partner.iam.gserviceaccount.com", "vendor@partner.com", "ana@trip.com", "bi@trip.com",
              "service-1@gcp-sa-bigquery.iam.gserviceaccount.com", "jobonly@vendor.com"):
        assert e in rows, e
    assert rows["jobonly@vendor.com"]["source"] == f"项目 IAM {P}: roles/bigquery.jobUser"   # 读不到数据也列出


def test_F05_three_columns_no_cloud_asset(world, tmp_path):
    import gcp_ops as ops
    _, rows, out = lp(tmp_path, "--projects", P)
    with open(out, encoding="utf-8-sig") as f:
        assert next(csv.reader(f)) == ["email", "principal_type", "source"]
    assert rows[SA_A] == {"email": SA_A, "principal_type": "serviceAccount", "source": f"项目 SA: {P}"}
    assert not any(n.startswith("asset_search") for n in dir(ops))


def test_F06_bypass_one_true_rule_per_group(world):
    assert bypass(G_R, "--apply") == 0
    assert bypass(G_W, "--apply") == 0
    for t in (T1, T2):
        assert world.policy(t, BYP_R) == {"id": BYP_R, "filter": "TRUE", "grantees": [f"group:{G_R}"]}
        assert world.policy(t, BYP_W)["grantees"] == [f"group:{G_W}"]
    assert bypass(f"{G_R},{G_W}", "--apply") == 2                       # 一次只能一个 Group


def test_F07_bypass_targets_are_registry_enabled_tables(world):
    assert bypass(G_R, "--apply") == 0
    assert all(world.policy(t, BYP_R) for t in (T1, T2, T3, T4)) and world.policies(T_OFF) == []
    assert world.calls["list_tables"] == 0                              # 不扫描项目 / 数据集
    for scope in (["--tables", T1], ["--datasets", f"{P}.ods"], ["--projects", P]):
        with pytest.raises(SystemExit) as e:
            bypass(G_R, *scope, "--apply")
        assert e.value.code == 2


def test_F08_bypass_registry_checks(world, capsys):
    world.register(T2, 0)                                                # T2 冲突（1 与 0）
    world.register("dw.bad_name", 1)                                     # 表名格式不对
    world.register(f"{P}.dw.dropped_t", 1)                               # 表已被 drop
    assert bypass(G_R, "--apply") == 1
    err = capsys.readouterr().err
    assert world.policy(T1, BYP_R) and world.policies(T2) == [] and world.policies(T_OFF) == []
    assert f"[WARN] {T2}" in err and "[SKIP] dw.bad_name" in err and f"[SKIP] {P}.dw.dropped_t" in err


def test_F09_copilot_one_group_rule_per_table(world, tmp_path):
    code, rows = copilot(tmp_path, "--apply")
    assert code == 0
    for t in (T1, T2, T3):
        cop = [p for p in world.policies(t) if p["id"].startswith(core.COPILOT_PREFIX)]
        assert len(cop) == 1 and cop[0]["grantees"] == [f"group:{G_COP}"]
        assert "WHERE c.status = 1 AND c.sa = SESSION_USER()" in cop[0]["filter"]   # 组内成员按自己的生效行过滤
    assert len(rows) == 3


def test_F10_dimensions_from_condition_and_mapping(world, tmp_path):
    copilot(tmp_path, "--apply")
    f1 = world.policy(T1, COP)["filter"]
    assert all(f"UNNEST(c.{d})" in f1 for d in ("region", "prdtype", "refername")) and f1.count(" AND (`") == 2   # 三个维度 AND 连接
    assert "UNNEST(c.region)" in world.policy(T2, COP)["filter"] and "`market`" in world.policy(T2, COP)["filter"]
    assert f1.count("c.status = 1 AND c.sa = SESSION_USER()") == 6       # 只有 status = 1 的行生效


def test_F11_only_registry_enabled_and_dimensioned_tables(world, tmp_path, capsys):
    gone = f"{P}.dw.dropped_t"                    # 映射表 / 登记表里有，但表已被 drop
    world.register(gone, 1)
    world.mapping_rows[MAP].append({"table_name": gone, "col_name": "region", "to_name": "region"})
    code, rows = copilot(tmp_path, "--apply")
    err = capsys.readouterr().err
    assert world.policies(T_OFF) == [] and world.policies(T4) == []
    assert f"[SKIP] {T_OFF}" in err and f"[SKIP] {T4}" in err
    assert code == 1 and f"[SKIP] {gone}: {core.TABLE_NOT_FOUND_MSG}" in err and "Traceback" not in err
    assert {r["table"] for r in rows} == {T1, T2, T3}                           # 其余表照常建规则


def test_F12_new_account_needs_no_rerun(world, tmp_path):
    copilot(tmp_path, "--apply")
    before = [dict(p) for p in world.policies(T1)]
    world.condition_sas[COND].append("new-sa@trip-prod.iam.gserviceaccount.com")
    code, rows = copilot(tmp_path, "--apply")
    assert code == 0 and rows == [] and world.policies(T1) == before


def test_F13_many_accounts_within_policy_limit(world, tmp_path):
    world.condition_sas[COND] = [f"u{i}@trip.com" for i in range(500)]
    bypass(G_R, "--apply")
    bypass(G_W, "--apply")
    code, _ = copilot(tmp_path, "--apply")
    assert code == 0 and len(world.policies(T1)) == 3 <= core.MAX_POLICIES_PER_TABLE


def test_F14_auth_tables_controlled_by_registry_only(world, tmp_path, capsys):
    world.mapping_rows[MAP].append({"table_name": COND, "col_name": "sa", "to_name": "region"})
    copilot(tmp_path, "--apply")
    err = capsys.readouterr().err
    assert world.policies(COND) == [] and "[EXCLUDE]" not in err and f"[SKIP] {COND}" in err


def test_F15_no_gates_anywhere(world, tmp_path, capsys):
    code, _ = copilot(tmp_path, "--apply")                               # 表上没有 bypass 也照建
    assert code == 0 and world.policy(T1, COP)
    world.add_table(f"{P}.dw.fresh", schema={"region": ("STRING", "NULLABLE")})   # 登记为开启、没有任何规则
    assert bypass(G_R, "--apply") == 0                                   # 首条策略：只提示、不拦截
    assert rollback_rls.main(["--tables", T3, "--apply"]) == 0 and world.policies(T3) == []   # 不给筛选 = 全删、不拦
    assert "将为以下这些表首次设置RLS规则" in capsys.readouterr().err


def test_F16_rollback_by_principal_name_or_all(world, tmp_path, capsys):
    bypass(G_R, "--apply")
    copilot(tmp_path, "--apply")
    world.policies(T1).append({"id": "manual_user", "filter": "TRUE", "grantees": [f"user:{U_C}"]})
    assert rollback_rls.main(["--tables", f"{T1},{T2}", "--principals", G_COP, "--apply"]) == 0
    assert world.policy(T1, COP) is None and world.policy(T1, BYP_R)
    assert rollback_rls.main(["--tables", T1, "--principals", U_C, "--apply"]) == 0 and world.policy(T1, "manual_user") is None
    assert rollback_rls.main(["--tables", T2, "--policy-names", BYP_R, "--apply"]) == 0
    assert world.policies(T2) == [] and "将被全部删除" in capsys.readouterr().err


def test_F17_dry_run_by_default(world, tmp_path):
    bypass(G_R)
    copilot(tmp_path)
    world.policies(T2).append({"id": "x", "filter": "TRUE", "grantees": ["user:x@trip.com"]})
    rollback_rls.main(["--tables", T2])
    assert world.ddl_log == [] and world.policies(T1) == [] and world.policy(T2, "x")


def test_F18_simplified_parameters(world, tmp_path, capsys):
    f = tmp_path / "t.csv"
    f.write_text(f"`{T2}`\n", encoding="utf-8")
    assert apply_bypass_rls.main(["--group", G_R, "--registry-table", f"`{REG}`", "--apply"]) == 0   # 反引号可选
    assert world.policy(T1, BYP_R) and world.policy(T2, BYP_R)
    assert rollback_rls.main(["--tables", f"`{T1}`", "--tables", str(f), "--policy-names", BYP_R, "--apply"]) == 0
    assert world.policy(T1, BYP_R) is None and world.policy(T2, BYP_R) is None               # 值与 .csv 可混用
    assert apply_bypass_rls.main(["--group", G_R, "--registry-table", REG.replace(".", ":", 1), "--apply"]) == 2
    with pytest.raises(SystemExit):
        bypass(G_R, "--tables-file", str(f))
    assert "并行: 16" in capsys.readouterr().err


def test_F19_auth_resolution_failure_exit_2(world, monkeypatch, capsys):
    import gcp_auth

    def boom(*a, **k):
        raise gcp_auth.AuthConfigError(f"找不到可用的登录凭证。{gcp_auth.LOGIN_HINT}")
    monkeypatch.setattr(apply_bypass_rls, "resolve_auth", boom)
    assert bypass(G_R, "--apply") == 2 and world.ddl_log == []
    assert "gcloud auth login" in capsys.readouterr().err


def test_F20_no_traceback_and_exit_codes(world, tmp_path, monkeypatch, capsys):
    world.fail_ddl_on.add(T1)
    assert bypass(G_R, "--apply") == 1                                  # 部分失败
    monkeypatch.setattr(apply_bypass_rls, "resolve_auth", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert bypass(G_R, "--apply") == 1                                  # 意外异常：[ERROR] 而非堆栈
    err = capsys.readouterr().err
    assert "Traceback" not in err and "[ERROR] RuntimeError: boom" in err


def test_F21_run_log_file_saved(world, tmp_path, capsys):
    import os

    import gcp_ops as ops
    # 默认：logs/<脚本名>_<时间戳>.log，内容与屏幕完全一致（含被跳过的表及原因）
    code, _ = copilot(tmp_path, "--apply")
    err = capsys.readouterr().err
    files = os.listdir(ops.DEFAULT_LOG_DIR)
    assert code == 0 and len(files) == 1 and files[0].startswith("apply_copilot_rls_") and files[0].endswith(".log")
    with open(os.path.join(ops.DEFAULT_LOG_DIR, files[0]), encoding="utf-8") as f:
        assert f.read() == err
    assert f"[SKIP] {T4}" in err and err.startswith("[LOG] 日志文件: ")
    # --log-dir 可改目录；再跑一次是新文件，旧文件不变
    d = tmp_path / "audit_logs"
    assert bypass(G_R, "--log-dir", str(d)) == 0
    assert len(os.listdir(d)) == 1 and len(os.listdir(ops.DEFAULT_LOG_DIR)) == 1
    capsys.readouterr()
    # 建不了：只 [WARN]，照常运行
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    assert rollback_rls.main(["--tables", T1, "--log-dir", str(blocker)]) == 0
    assert "[WARN] 无法创建日志文件" in capsys.readouterr().err


def test_F22_project_scope_includes_inherited_grants(world, tmp_path, capsys):
    world.iam_policies["organizations/111"] = [{"role": "roles/bigquery.dataViewer", "members": ["user:org-reader@partner.com"]}]
    world.iam_policies["folders/1"] = [{"role": "roles/viewer", "members": ["serviceAccount:f@x.iam.gserviceaccount.com"]}]
    code, rows, _ = lp(tmp_path, "--projects", "dev")                # dev 在 组织 111 → folders/1 下
    assert code == 0 and {"org-reader@partner.com", "f@x.iam.gserviceaccount.com"} <= set(rows)
    assert "[ANCESTOR]" in capsys.readouterr().err


def test_F23_unexpandable_groups_written_to_csv(world, tmp_path, capsys):
    world.iam_policies[f"projects/{P}"].append(
        {"role": "roles/bigquery.dataViewer", "members": ["group:partner-team@vendor.com"]})
    world.groups["partner-team@vendor.com"] = None                   # 外部域
    code, rows, _ = lp(tmp_path, "--projects", P)
    err = capsys.readouterr().err
    assert code == 0 and rows["partner-team@vendor.com"]["principal_type"] == "group" and "[NOTE]" in err
    world.groups["bi@trip.com"] = None                               # 本组织域名
    code, rows, _ = lp(tmp_path, "--projects", P)
    err = capsys.readouterr().err
    assert code == 1 and rows["bi@trip.com"]["source"].endswith("（未能展开）") and "群组 → 读取" in err


def test_F24_any_role_holders_listed(world, tmp_path):
    world.iam_policies[f"projects/{P}"].append({"role": "roles/browser", "members": ["user:browser@partner.com"]})
    world.iam_policies[f"projects/{P}"].append({"role": "roles/viewer", "members": ["user:viewer@partner.com"]})
    world.iam_policies["organizations/111"] = [{"role": "roles/editor", "members": ["user:carol2@trip.com"]}]
    world.iam_policies[f"projects/{P}"].append(
        {"role": "roles/owner", "members": ["serviceAccount:dev-sa@dev.iam.gserviceaccount.com"]})
    code, rows, _ = lp(tmp_path, "--projects", P)
    assert code == 0 and {"viewer@partner.com", "carol2@trip.com", "dev-sa@dev.iam.gserviceaccount.com",
                          "browser@partner.com"} <= set(rows)


def test_F25_authorized_view_outside_scope_noted(world, tmp_path, capsys):
    world.dataset_acl[f"{P}.dw"].append((None, "view", {"projectId": "rpt", "datasetId": "s", "tableId": "v"}))
    code, _, _ = lp(tmp_path, "--projects", P)
    assert code == 0 and "授权视图 rpt.s.v" in capsys.readouterr().err


def test_F26_groups_expanded_one_level(world, tmp_path):
    _, rows, _ = lp(tmp_path, "--projects", P)
    assert rows["nested@trip.com"]["source"] == "Group 成员: bi@trip.com（嵌套组，未展开）"
    assert "deep@vendor.com" not in rows                             # 嵌套组的成员不再展开


def test_F27_non_concrete_principals_written(world, tmp_path):
    world.iam_policies[f"projects/{P}"].append({"role": "roles/viewer", "members": [
        "domain:trip.com", "allAuthenticatedUsers", "principalSet://iam.googleapis.com/x", "deleted:user:a@trip.com?uid=9"]})
    _, rows, _ = lp(tmp_path, "--projects", P)
    assert [rows[k]["principal_type"] for k in ("trip.com", "allAuthenticatedUsers", "principalSet://iam.googleapis.com/x",
                                                 "deleted:user:a@trip.com?uid=9")] == ["domain", "public", "federated", "deleted"]
