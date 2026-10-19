"""
apply_bypass_rls.py 的双重保证（2026-10-18 需求变更）：
  1) 参数中必须给出目标范围：--tables、--datasets、--projects（值或 .csv）任给其一，不能都不给；
  2) 只有登记表 adm_user_mem_copilot_tb 中 rls_enabled = 1 的表才授权（不看 status）。
最终表 = (--tables ∪ --datasets 展开 ∪ --projects 展开) ∩ 登记表 rls_enabled=1。
登记表 table_name 按原始字符串精确比较；同名多行只要有一行 rls_enabled ≠ 1 即视为未开启，并 [WARN]、退出码 1。
未开启的表（不论显式列出还是展开出来）每张打印一行 [SKIP]，退出码 0。
条件表 / 映射表保护已删除（--condition-table / --mapping-table 不再接受）。
"""

import pytest

import apply_bypass_rls
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.fact_orders", f"{P}.dw.fact_booking", f"{P}.ods.raw_events"
T_OFF, T_NEW = f"{P}.dw.tmp_off", f"{P}.dw.not_registered"
COND, MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition", "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G = "group_existingsa_read@domain.com"
BYP = core.bypass_policy_name(G)
RG = ["--registry-table", REG]
READER_SA = "reader@trip-prod.iam.gserviceaccount.com"


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in (T1, T2, T3):
        w.add_table(t)                          # 登记为 rls_enabled=1
    w.add_table(T_OFF, rls_enabled=0)           # 登记但未开启
    w.add_table(T_NEW, rls_enabled=None)        # 未登记
    w.add_table(COND, rls_enabled=0)            # 客户把条件表 / 映射表登记为未开启
    w.add_table(MAP, rls_enabled=None)
    install(monkeypatch, w, apply_bypass_rls)
    return w


def run(*args):
    return apply_bypass_rls.main(["--group", G, *args, *RG])


def lines(err, tag):
    return [l for l in err.splitlines() if l.startswith(tag)]


# =========================================================================== #
# 正常系
# =========================================================================== #
class TestRegistryNormal:
    def test_r_n_01_only_enabled_listed_tables_get_rule(self, world, capsys):
        code = run("--tables", f"{T1},{T_OFF},{T_NEW}", "--apply")
        err = capsys.readouterr().err
        assert code == 0
        assert world.policy(T1, BYP) is not None
        assert world.policies(T_OFF) == [] and world.policies(T_NEW) == []
        assert len(world.ddl_log) == 1 and T1 in world.ddl_log[0]
        assert f"[SKIP] {T_OFF}: 登记表中 rls_enabled ≠ 1，不授权" in err
        assert f"[SKIP] {T_NEW}: 不在登记表 {REG} 中，不授权" in err

    def test_r_n_02_dry_run_same_decision_and_no_change(self, world, capsys):
        code = run("--tables", f"{T1},{T_OFF}")
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert f"[CREATE] {T1}" in err and f"[SKIP] {T_OFF}" in err

    def test_r_n_03_datasets_and_projects_union_then_intersect(self, world, capsys):
        code = run("--tables", T1, "--datasets", f"{P}.ods", "--projects", P, "--apply")
        err = capsys.readouterr().err
        assert code == 0
        assert all(world.policy(t, BYP) for t in (T1, T2, T3))            # T2 来自项目展开、T3 来自数据集
        assert world.policies(T_OFF) == [] and world.policies(T_NEW) == []
        skipped = {l.split(":")[0].split()[1] for l in lines(err, "[SKIP]")}
        assert skipped == {T_OFF, T_NEW}                                    # 展开出来的未开启表也逐行 [SKIP]

    def test_r_n_04_tables_file_satisfies_requirement(self, world, tmp_path):
        f = tmp_path / "t.csv"
        f.write_text(f"{T1}\n", encoding="utf-8")
        assert run("--tables", str(f), "--apply") == 0
        assert world.policy(T1, BYP) is not None

    def test_r_n_05_status_is_ignored(self, world):
        world.unregister(T1).register(T1, rls_enabled=1, status=0)        # 软删除但 rls_enabled=1 → 仍授权
        assert run("--tables", T1, "--apply") == 0
        assert world.policy(T1, BYP) is not None

    def test_r_n_06_duplicate_rows_all_enabled_is_fine(self, world, capsys):
        world.register(T1, 1).register(T1, 1, status=0)
        code = run("--tables", T1, "--apply")
        assert code == 0 and world.policy(T1, BYP) is not None and "[WARN]" not in capsys.readouterr().err

    def test_r_n_07_duplicate_rows_all_disabled_skip_without_warn(self, world, capsys):
        world.register(T_OFF, 0)
        code = run("--tables", T_OFF)
        err = capsys.readouterr().err
        assert code == 0 and "[WARN]" not in err and f"[SKIP] {T_OFF}" in err

    def test_r_n_08_nothing_to_authorize_exit_0(self, world, capsys):
        code = run("--tables", f"{T_OFF},{T_NEW}", "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert "SKIP 2" in err.splitlines()[-1]

    def test_r_n_09_summary_counts_skip(self, world, capsys):
        world.policies(T2).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]})
        code = run("--tables", f"{T1},{T2},{T_OFF}", "--apply")
        last = capsys.readouterr().err.splitlines()[-1]
        assert code == 0 and "CREATE 1" in last and "NOOP 1" in last and "SKIP 1" in last

    def test_r_n_10_registry_read_once_and_skipped_tables_not_read(self, world):
        run("--tables", f"{T1},{T_OFF},{T_NEW}", "--datasets", f"{P}.dw")
        assert world.calls["query"] == 1                                   # 登记表只读一次
        assert world.calls["list_policies"] == 2                           # 只读 T1、T2 的现有规则

    def test_r_n_11_first_policy_gate_ignores_skipped_tables(self, world, capsys):
        world.policies(T1).append({"id": "other", "filter": "TRUE", "grantees": ["group:x@domain.com"]})
        code = run("--tables", f"{T1},{T_OFF},{T_NEW}", "--apply")       # T_OFF / T_NEW 无 RLS 但被跳过
        err = capsys.readouterr().err
        assert code == 0 and "将为以下这些表首次设置RLS规则" not in err
        assert world.policy(T1, BYP) is not None

    def test_r_n_12_first_policy_note_lists_only_enabled_tables(self, world, capsys):
        code = run("--tables", f"{T1},{T_OFF}", "--apply")              # 首条策略只提示、不拦截
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T1, BYP) is not None
        assert f"  - {T1}" in err and f"  - {T_OFF}" not in err

    def test_r_n_13_condition_and_mapping_tables_follow_registry(self, world, capsys):
        """保护功能已删除：条件表 / 映射表与其它表一样只看登记表（这里登记为未开启 / 未登记 → 跳过）。"""
        code = run("--tables", f"{T1},{COND},{MAP}", "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policies(COND) == [] and world.policies(MAP) == []
        assert f"[SKIP] {COND}" in err and f"[SKIP] {MAP}" in err and "[EXCLUDE]" not in err

    def test_r_n_14_registered_condition_table_is_authorized_like_any_table(self, world):
        world.unregister(COND).register(COND, 1)
        assert run("--tables", COND, "--apply") == 0
        assert world.policy(COND, BYP) is not None

    def test_r_n_15_verify_only_enabled_tables(self, world, capsys):
        code = run("--tables", f"{T1},{T_OFF}", "--apply", "--verify-sa", READER_SA)
        err = capsys.readouterr().err
        assert code == 0 and f"[VERIFY-OK] {T1}" in err and T_OFF not in "".join(lines(err, "[VERIFY"))

    def test_r_n_16_registry_in_other_project_than_targets(self, world):
        assert REG.split(".")[0] != P
        assert run("--tables", T1, "--apply") == 0

    @pytest.mark.parametrize("parallel", ["1", "32"])
    def test_r_n_17_parallel_same_outcome(self, world, parallel):
        code = run("--tables", T1, "--projects", P, "--apply", "--parallel", parallel)
        assert code == 0 and sorted(world.ddl_log) == sorted(
            core.build_policy_ddl(t, BYP, [f"group:{G}"], "TRUE") for t in (T1, T2, T3))

    def test_r_n_18_rollback_unchanged_and_ignores_registry(self, world, monkeypatch):
        install(monkeypatch, world, rollback_rls)
        world.policies(T_OFF).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]})
        world.policies(T_OFF).append({"id": "keep", "filter": "TRUE", "grantees": ["group:k@domain.com"]})
        assert rollback_rls.main(["--tables", T_OFF, "--principals", G, "--apply"]) == 0   # 未开启的表也能回退
        assert world.policy(T_OFF, BYP) is None


# =========================================================================== #
# 异常系
# =========================================================================== #
class TestRegistryAbnormal:
    def test_r_a_01_no_scope_at_all_rejected(self, world, capsys):
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 2 and world.ddl_log == []
        assert "--tables" in err and "--datasets" in err and "--projects" in err

    def test_r_a_02_empty_files_count_as_missing(self, world, tmp_path):
        files = []
        for name in ("t.csv", "d.csv", "p.csv"):
            f = tmp_path / name
            f.write_text("\n", encoding="utf-8")
            files.append(str(f))
        assert run("--tables", files[0], "--datasets", files[1], "--projects", files[2], "--apply") == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("scope", [["--datasets", f"{P}.dw"], ["--projects", P], ["--tables", T1]])
    def test_r_a_03_any_single_scope_is_enough_and_registry_still_applies(self, world, capsys, scope):
        code = run(*scope, "--apply")
        assert code == 0 and world.policy(T1, BYP) is not None
        assert world.policies(T_OFF) == [] and world.policies(T_NEW) == []          # 登记表照样把关

    def test_r_a_03b_scope_files_alone_are_enough(self, world, tmp_path):
        d = tmp_path / "d.csv"
        d.write_text(f"{P}.ods\n", encoding="utf-8")
        p = tmp_path / "p.csv"
        p.write_text(f"{P}\n", encoding="utf-8")
        assert run("--datasets", str(d), "--apply") == 0
        assert world.policy(T3, BYP) is not None and world.policy(T1, BYP) is None
        assert run("--projects", str(p), "--apply") == 0
        assert world.policy(T1, BYP) is not None and world.policies(T_OFF) == []

    def test_r_a_04_registry_table_required(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(["--group", G, "--tables", T1])
        assert e.value.code == 2

    @pytest.mark.parametrize("flag", ["--condition-table", "--mapping-table"])
    def test_r_a_05_old_protection_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit) as e:
            run("--tables", T1, flag, COND)
        assert e.value.code == 2

    def test_r_a_06_registry_table_missing(self, world, capsys):
        code = apply_bypass_rls.main(["--group", G, "--tables", T1, "--registry-table", "trip-bq-admin.bq_auth.typo",
                                      "--apply"])
        assert code == 2 and world.ddl_log == [] and "trip-bq-admin.bq_auth.typo" in capsys.readouterr().err

    @pytest.mark.parametrize("bad", ["bad table!", "only.two", "a.b.c`; DROP TABLE x; --"])
    def test_r_a_07_registry_table_name_invalid(self, world, bad):
        assert apply_bypass_rls.main(["--group", G, "--tables", T1, "--registry-table", bad, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("fields", [
        [("id", "STRING", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],                     # 缺 table_name
        [("id", "STRING", "REQUIRED"), ("table_name", "STRING", "REQUIRED")],                      # 缺 rls_enabled
        [("table_name", "STRING", "REQUIRED"), ("rls_enabled", "STRING", "REQUIRED")],             # 类型不对
        [("table_name", "INTEGER", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],
        [("table_name", "STRING", "REPEATED"), ("rls_enabled", "INTEGER", "REQUIRED")],            # 数组
    ])
    def test_r_a_08_registry_schema_invalid(self, world, capsys, fields):
        world.registry_fields[REG] = fields
        code = run("--tables", T1, "--apply")
        assert code == 2 and world.ddl_log == [] and "[ERROR]" in capsys.readouterr().err

    def test_r_a_09_int64_type_name_accepted(self, world):
        world.registry_fields[REG] = [("table_name", "STRING", "NULLABLE"), ("rls_enabled", "INT64", "NULLABLE")]
        assert run("--tables", T1, "--apply") == 0

    def test_r_a_10_conflicting_rows_warn_skip_exit_1(self, world, capsys):
        world.register(T1, 0, status=0)                                     # 旧行 1、新行 0
        code = run("--tables", f"{T1},{T2}", "--apply")
        err = capsys.readouterr().err
        assert code == 1
        assert world.policies(T1) == [] and world.policy(T2, BYP) is not None   # 其余表照常
        assert any(l.startswith(f"[WARN] {T1}") for l in err.splitlines())
        assert f"[SKIP] {T1}" in err

    def test_r_a_11_conflict_outside_target_scope_not_reported(self, world, capsys):
        world.register(T3, 0)
        code = run("--tables", T1, "--apply")
        assert code == 0 and "[WARN]" not in capsys.readouterr().err

    def test_r_a_12_conflict_on_dataset_expanded_table(self, world, capsys):
        world.register(T2, 0)
        code = run("--tables", T1, "--datasets", f"{P}.dw", "--apply")
        assert code == 1 and world.policies(T2) == [] and f"[WARN] {T2}" in capsys.readouterr().err

    @pytest.mark.parametrize("raw", [f" {T1}", f"{T1} ", f"`{T1}`", T1.upper(), f"{P}:dw.fact_orders",
                                     "dw.fact_orders", f"{P}.DW.fact_orders"])
    def test_r_a_13_registry_name_exact_raw_match_only(self, world, capsys, raw):
        world.unregister(T1).register(raw, 1)
        code = run("--tables", T1, "--apply")
        assert code == 0 and world.policies(T1) == [] and f"[SKIP] {T1}: 不在登记表" in capsys.readouterr().err

    @pytest.mark.parametrize("value", [2, -1, None, 0])
    def test_r_a_14_non_one_rls_enabled_values_not_enabled(self, world, value):
        world.unregister(T1).register(T1, value)
        assert run("--tables", T1, "--apply") == 0
        assert world.policies(T1) == []

    def test_r_a_15_one_and_null_is_conflict(self, world, capsys):
        world.register(T1, None)
        assert run("--tables", T1, "--apply") == 1
        assert world.policies(T1) == [] and "[WARN]" in capsys.readouterr().err

    def test_r_a_16_registry_values_never_reach_sql(self, world):
        evil = f"{T1}`; DROP TABLE x; --"
        world.register(evil, 1)
        assert run("--tables", T1, "--apply") == 0
        assert all("DROP TABLE" not in d for d in world.ddl_log)

    def test_r_a_17_registry_only_entries_not_authorized(self, world):
        """登记表里 rls_enabled=1、但参数没给（也不在展开范围内）的表不授权（AND 关系）。"""
        world.add_table(f"{P}.mart.only_in_registry")
        assert run("--tables", T1, "--apply") == 0
        assert world.policies(f"{P}.mart.only_in_registry") == []

    def test_r_a_18_empty_registry_skips_everything(self, world, capsys):
        world.registry_rows[REG] = []
        code = run("--tables", f"{T1},{T2}", "--apply")
        assert code == 0 and world.ddl_log == [] and len(lines(capsys.readouterr().err, "[SKIP]")) == 2

    def test_r_a_19_registry_query_failure_is_error_without_ddl(self, world, monkeypatch, capsys):
        import gcp_ops as ops

        def boom(ctx, t):
            raise RuntimeError("Access Denied: Table trip-bq-admin:bq_auth.adm_user_mem_copilot_tb")
        monkeypatch.setattr(ops, "read_registry_rows", boom)
        code = run("--tables", T1, "--apply")
        assert code == 2 and world.ddl_log == [] and "Access Denied" in capsys.readouterr().err

    def test_r_a_20_rollback_rejects_registry_flag(self, world, monkeypatch):
        install(monkeypatch, world, rollback_rls)
        with pytest.raises(SystemExit):
            rollback_rls.main(["--tables", T1, "--principals", G, "--registry-table", REG])

    def test_r_a_21_skip_lines_one_per_table_sorted(self, world, capsys):
        run("--tables", f"{T_NEW},{T_OFF}", "--datasets", f"{P}.dw")
        skipped = [l.split(":")[0].split()[1] for l in lines(capsys.readouterr().err, "[SKIP]")]
        assert skipped == sorted(skipped) and len(skipped) == len(set(skipped)) == 2
