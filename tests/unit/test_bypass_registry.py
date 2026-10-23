"""
apply_bypass_rls.py 只看登记表（2026-10-22 需求变更）：
  目标表 = 登记表 adm_user_mem_copilot_tb 中 rls_enabled = 1 的全部表（不看 status）；不再扫描项目 / 数据集，
  --tables / --datasets / --projects 已删除（传入即参数错误）。
  table_name 须为 project.dataset.table（反引号、首尾空白可容忍），格式不对 -> [WARN] + [SKIP]、退出码 1；
  同名多行 rls_enabled 不一致 -> [WARN] + [SKIP]、退出码 1；rls_enabled ≠ 1 的表不处理，只在 [SCAN] 汇总数量；
  登记表里有、但表不存在 -> [SKIP] 表不存在、退出码 1，其余表照常。
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
ENABLED = (T1, T2, T3)


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


def ddl_for(*tables):
    return sorted(core.build_policy_ddl(t, BYP, [f"group:{G}"], "TRUE") for t in tables)


# =========================================================================== #
# 正常系
# =========================================================================== #
class TestRegistryNormal:
    def test_r_n_01_all_enabled_tables_get_rule_only(self, world, capsys):
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 0 and sorted(world.ddl_log) == ddl_for(*ENABLED)
        assert world.policies(T_OFF) == [] and world.policies(T_NEW) == [] and world.policies(COND) == []
        assert "[SCAN] 登记表中 rls_enabled = 1 的表 3 张；rls_enabled ≠ 1 的 2 张不处理" in err
        assert lines(err, "[SKIP]") == []                                  # 未开启的表不再逐张打印

    def test_r_n_02_dry_run_same_decision_and_no_change(self, world, capsys):
        code = run()
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert all(f"[CREATE] {t}" in err for t in ENABLED) and f"[CREATE] {T_OFF}" not in err

    def test_r_n_03_no_project_or_dataset_scan(self, world):
        run("--apply")
        assert world.calls["list_tables"] == 0                             # 不再列出项目 / 数据集里的表
        assert world.calls["list_policies"] == 3                           # 只读 3 张目标表的现有规则

    def test_r_n_04_status_is_ignored(self, world):
        world.unregister(T1).register(T1, rls_enabled=1, status=0)        # 软删除但 rls_enabled=1 → 仍授权
        assert run("--apply") == 0 and world.policy(T1, BYP) is not None

    def test_r_n_05_duplicate_rows_all_enabled_is_fine(self, world, capsys):
        world.register(T1, 1).register(T1, 1, status=0)
        code = run("--apply")
        assert code == 0 and world.policy(T1, BYP) is not None and "[WARN]" not in capsys.readouterr().err
        assert len(world.ddl_log) == 3

    def test_r_n_06_duplicate_rows_all_disabled_no_warn(self, world, capsys):
        world.register(T_OFF, 0)
        code = run()
        err = capsys.readouterr().err
        assert code == 0 and "[WARN]" not in err and f"[CREATE] {T_OFF}" not in err

    def test_r_n_07_nothing_enabled_exit_0(self, world, capsys):
        for t in ENABLED:
            world.unregister(t).register(t, 0)
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert "[SCAN] 登记表中 rls_enabled = 1 的表 0 张" in err

    def test_r_n_08_summary_counts(self, world, capsys):
        world.policies(T2).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]})
        code = run("--apply")
        last = capsys.readouterr().err.splitlines()[-1]
        assert code == 0 and "CREATE 2" in last and "NOOP 1" in last and "SKIP" not in last

    def test_r_n_09_registry_read_once(self, world):
        run()
        assert world.calls["query"] == 1

    def test_r_n_10_first_policy_note_lists_target_tables(self, world, capsys):
        world.policies(T1).append({"id": "other", "filter": "TRUE", "grantees": ["group:x@domain.com"]})
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 0 and f"  - {T2}" in err and f"  - {T3}" in err
        assert f"  - {T1}" not in err and f"  - {T_OFF}" not in err   # T1 已有规则；T_OFF 不处理

    def test_r_n_11_condition_table_follows_registry(self, world):
        assert run("--apply") == 0 and world.policies(COND) == []          # 登记为 0
        world.unregister(COND).register(COND, 1)
        assert run("--apply") == 0 and world.policy(COND, BYP) is not None   # 登记为 1 就和其它表一样

    def test_r_n_12_verify_only_target_tables(self, world, capsys):
        code = run("--apply", "--verify-sa", READER_SA)
        err = capsys.readouterr().err
        assert code == 0 and len(lines(err, "[VERIFY-OK]")) == 3 and T_OFF not in "".join(lines(err, "[VERIFY"))

    def test_r_n_13_registry_in_other_project_than_targets(self, world):
        assert REG.split(".")[0] != P
        assert run("--apply") == 0

    @pytest.mark.parametrize("parallel", ["1", "32"])
    def test_r_n_14_parallel_same_outcome(self, world, parallel):
        assert run("--apply", "--parallel", parallel) == 0
        assert sorted(world.ddl_log) == ddl_for(*ENABLED)

    @pytest.mark.parametrize("raw", [f" {T1}", f"{T1} ", f"`{T1}`"])
    def test_r_n_15_registry_name_backticks_and_spaces_normalized(self, world, raw):
        world.register(raw, 1)                                             # 与 T1 是同一张表：只建一次
        assert run("--apply") == 0 and sorted(world.ddl_log) == ddl_for(*ENABLED)

    def test_r_n_16_rollback_keeps_scope_args_and_ignores_registry(self, world, monkeypatch):
        install(monkeypatch, world, rollback_rls)
        world.policies(T_OFF).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]})
        world.policies(T_OFF).append({"id": "keep", "filter": "TRUE", "grantees": ["group:k@domain.com"]})
        assert rollback_rls.main(["--tables", T_OFF, "--principals", G, "--apply"]) == 0   # 未开启的表也能回退
        assert world.policy(T_OFF, BYP) is None
        world.policies(T2).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]})
        assert rollback_rls.main(["--datasets", f"{P}.dw", "--principals", G, "--apply"]) == 0
        assert world.policy(T2, BYP) is None


# =========================================================================== #
# 异常系
# =========================================================================== #
class TestRegistryAbnormal:
    @pytest.mark.parametrize("scope", [["--tables", T1], ["--datasets", f"{P}.dw"], ["--projects", P]])
    def test_r_a_01_removed_scope_args_rejected(self, world, scope):
        with pytest.raises(SystemExit) as e:
            run(*scope, "--apply")
        assert e.value.code == 2 and world.ddl_log == []

    def test_r_a_02_registry_table_required(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(["--group", G])
        assert e.value.code == 2

    @pytest.mark.parametrize("flag", ["--condition-table", "--mapping-table"])
    def test_r_a_03_old_protection_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit) as e:
            run(flag, COND)
        assert e.value.code == 2

    def test_r_a_04_registry_table_missing(self, world, capsys):
        code = apply_bypass_rls.main(["--group", G, "--registry-table", "trip-bq-admin.bq_auth.typo", "--apply"])
        assert code == 2 and world.ddl_log == [] and "trip-bq-admin.bq_auth.typo" in capsys.readouterr().err

    @pytest.mark.parametrize("bad", ["bad table!", "only.two", "a.b.c`; DROP TABLE x; --"])
    def test_r_a_05_registry_table_name_invalid(self, world, bad):
        assert apply_bypass_rls.main(["--group", G, "--registry-table", bad, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("fields", [
        [("id", "STRING", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],                     # 缺 table_name
        [("id", "STRING", "REQUIRED"), ("table_name", "STRING", "REQUIRED")],                      # 缺 rls_enabled
        [("table_name", "STRING", "REQUIRED"), ("rls_enabled", "STRING", "REQUIRED")],             # 类型不对
        [("table_name", "INTEGER", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],
        [("table_name", "STRING", "REPEATED"), ("rls_enabled", "INTEGER", "REQUIRED")],            # 数组
    ])
    def test_r_a_06_registry_schema_invalid(self, world, capsys, fields):
        world.registry_fields[REG] = fields
        code = run("--apply")
        assert code == 2 and world.ddl_log == [] and "[ERROR]" in capsys.readouterr().err

    def test_r_a_07_int64_type_name_accepted(self, world):
        world.registry_fields[REG] = [("table_name", "STRING", "NULLABLE"), ("rls_enabled", "INT64", "NULLABLE")]
        assert run("--apply") == 0

    def test_r_a_08_conflicting_rows_warn_skip_exit_1(self, world, capsys):
        world.register(T1, 0, status=0)                                     # 旧行 1、新行 0
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 1
        assert world.policies(T1) == [] and world.policy(T2, BYP) is not None   # 其余表照常
        assert any(l.startswith(f"[WARN] {T1}") for l in err.splitlines()) and f"[SKIP] {T1}: 登记表记录冲突" in err
        assert "SKIP 1" in err.splitlines()[-1]

    @pytest.mark.parametrize("raw", ["dw.fact_orders", f"{P}:dw.fact_orders", f"{P}.dw.x.y", "not a table"])
    def test_r_a_09_registry_name_bad_format_warn_skip_exit_1(self, world, capsys, raw):
        world.register(raw, 1)
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 1 and sorted(world.ddl_log) == ddl_for(*ENABLED)   # 其余表照常
        assert f"[WARN] 登记表 table_name {raw!r} 不是 project.dataset.table 格式" in err
        assert f"[SKIP] {raw}: 登记表表名格式不对" in err

    @pytest.mark.parametrize("value", [2, -1, None, 0])
    def test_r_a_10_non_one_rls_enabled_values_not_enabled(self, world, value):
        world.unregister(T1).register(T1, value)
        assert run("--apply") == 0
        assert world.policies(T1) == []

    def test_r_a_11_one_and_null_is_conflict(self, world, capsys):
        world.register(T1, None)
        assert run("--apply") == 1
        assert world.policies(T1) == [] and "[WARN]" in capsys.readouterr().err

    def test_r_a_12_registry_values_never_reach_sql(self, world):
        world.register(f"{T1}`; DROP TABLE x; --", 1)
        assert run("--apply") == 1                                          # 格式不对：[WARN] + [SKIP]
        assert all("DROP TABLE" not in d for d in world.ddl_log)

    def test_r_a_13_registered_but_table_missing_skip_exit_1(self, world, capsys):
        world.register(f"{P}.dw.dropped_t", 1)                              # 登记了，但表已被 drop
        code = run("--apply")
        err = capsys.readouterr().err
        assert code == 1 and sorted(world.ddl_log) == ddl_for(*ENABLED)
        assert f"[SKIP] {P}.dw.dropped_t: {core.TABLE_NOT_FOUND_MSG}" in err
        assert "SKIP 1" in err.splitlines()[-1]

    def test_r_a_14_empty_registry_does_nothing(self, world, capsys):
        world.registry_rows[REG] = []
        code = run("--apply")
        assert code == 0 and world.ddl_log == [] and "rls_enabled = 1 的表 0 张" in capsys.readouterr().err

    def test_r_a_15_registry_query_failure_is_error_without_ddl(self, world, monkeypatch, capsys):
        import gcp_ops as ops

        def boom(ctx, t):
            raise RuntimeError("Access Denied: Table trip-bq-admin:bq_auth.adm_user_mem_copilot_tb")
        monkeypatch.setattr(ops, "read_registry_rows", boom)
        code = run("--apply")
        assert code == 2 and world.ddl_log == [] and "Access Denied" in capsys.readouterr().err

    def test_r_a_16_rollback_rejects_registry_flag(self, world, monkeypatch):
        install(monkeypatch, world, rollback_rls)
        with pytest.raises(SystemExit):
            rollback_rls.main(["--tables", T1, "--principals", G, "--registry-table", REG])

    def test_r_a_17_warn_and_skip_lines_sorted(self, world, capsys):
        world.register("zz.bad", 1).register("aa.bad", 1)
        run()
        warns = [l for l in lines(capsys.readouterr().err, "[WARN] 登记表 table_name")]
        assert warns == sorted(warns) and len(warns) == 2
