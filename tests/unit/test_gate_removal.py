"""
需求变更②（2026-10-18）：去掉全部「闸门」，apply_copilot_rls.py 也参照登记表。
  - apply_copilot_rls.py：去掉 bypass 闸门（表上没有 bypass 规则也照建）；不加首条策略保护；
    新增必填 --registry-table：映射表 / --tables 里的表只有登记表 rls_enabled = 1 才建规则，其余逐张 [SKIP]
    （与 apply_bypass_rls.py 完全一致：原始字符串精确比较、不看 status、冲突 [WARN] + 退出码 1）；
    删除条件表 / 映射表保护（[EXCLUDE]），改由登记表 rls_enabled = 0 控制。
  - apply_bypass_rls.py：去掉首条策略保护，删除 --force-first-policy；「将为以下这些表首次设置RLS规则」清单只作提示。
  - rollback_rls.py：去掉删除全部保护与删光保护，删除 --all-policies、--force-drop-all；
    不给 --principals / --policy-names = 删除目标表上的全部规则；「将被全部删除」清单只作提示。
"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, install, fake_auth

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.fact_orders", f"{P}.dw.fact_booking", f"{P}.ods.raw_events"
T_OFF, T_NEW = f"{P}.dw.tmp_off", f"{P}.dw.not_registered"
COND = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition"
MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G = "group_existingsa_read@domain.com"
BYP = core.bypass_policy_name(G)
SA_A, U_B = "copilot-a@trip-prod.iam.gserviceaccount.com", "bob@domain.com"
G_COP = "group_copilot@domain.com"
COP_A = COP_B = core.copilot_policy_name(G_COP)          # Group 级别：每张表一条 Copilot 规则（2026-10-18）
FIRST_MSG = "将为以下这些表首次设置RLS规则"
DROP_ALL_MSG = "以下这些表的 RLS 规则将被全部删除"


def bypass_rule(group=G):
    return {"id": core.bypass_policy_name(group), "filter": "TRUE", "grantees": [f"group:{group}"]}


def other_rule(name="manual_rule"):
    return {"id": name, "filter": "region = 'HK'", "grantees": ["user:someone@domain.com"]}


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    region = {"region": ("STRING", "NULLABLE")}
    for t in (T1, T2, T3):
        w.add_table(t, schema=region)                      # 登记为 rls_enabled = 1
    w.add_table(T_OFF, schema=region, rls_enabled=0)       # 登记但未开启
    w.add_table(T_NEW, schema=region, rls_enabled=None)    # 未登记
    w.add_table(COND, schema={"sa": ("STRING", "NULLABLE")}, rls_enabled=0)
    w.add_table(MAP, schema={"col_name": ("STRING", "NULLABLE")}, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
    w.condition_sas[COND] = [SA_A, U_B]
    w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in (T1, T2, T3, T_OFF, T_NEW)]
    install(monkeypatch, w)
    for mod in (apply_bypass_rls, apply_copilot_rls, rollback_rls):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def copilot(tmp_path, *args):
    out = tmp_path / "plan.csv"
    code = apply_copilot_rls.main(["--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG,
                                   "--group", G_COP, "-o", str(out), *args])
    return code, (read_csv(out) if out.exists() else None)


def bypass(*args):
    return apply_bypass_rls.main(["--group", G, "--registry-table", REG, *args])


def tags(err, tag):
    return [l for l in err.splitlines() if l.startswith(tag)]


def listed_after(err, msg):
    """msg 那一行之后紧跟的「  - 表名」清单。"""
    lines = err.splitlines()
    i = next(k for k, l in enumerate(lines) if msg in l)
    out = []
    for l in lines[i + 1:]:
        if not l.startswith("  - "):
            break
        out.append(l[4:].strip())
    return out


# =========================================================================== #
# apply_copilot_rls.py：去掉 bypass 闸门
# =========================================================================== #
class TestCopilotNoBypassGate:
    def test_g_c_01_tables_without_any_rls_get_rules(self, world, tmp_path, capsys):
        code, rows = copilot(tmp_path, "--apply")                 # 表上一条 RLS 都没有
        err = capsys.readouterr().err
        assert code == 0 and "[ABORT]" not in err
        for t in (T1, T2, T3):
            assert world.policy(t, COP_A) is not None and world.policy(t, COP_B) is not None

    def test_g_c_02_first_policy_tables_listed_as_note_only(self, world, tmp_path, capsys):
        world.policies(T2).append(other_rule())
        code, _ = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0
        assert listed_after(err, FIRST_MSG) == sorted([T1, T3])
        assert "--force-first-policy" not in err

    def test_g_c_03_tables_with_non_bypass_rls_proceed(self, world, tmp_path):
        world.policies(T1).append(other_rule())
        code, _ = copilot(tmp_path, "--tables", T1, "--apply")
        assert code == 0 and world.policy(T1, COP_A) is not None and world.policy(T1, "manual_rule") is not None

    def test_g_c_04_mixed_bypass_and_no_bypass_all_created(self, world, tmp_path):
        world.policies(T1).append(bypass_rule())
        code, _ = copilot(tmp_path, "--apply")
        assert code == 0 and all(world.policy(t, COP_A) for t in (T1, T2, T3))
        assert world.policy(T1, BYP) is not None                  # bypass 规则不受影响

    def test_g_c_05_dry_run_no_change(self, world, tmp_path, capsys):
        code, rows = copilot(tmp_path)
        assert code == 0 and world.ddl_log == []
        assert {r["table"] for r in rows} == {T1, T2, T3}

    def test_g_c_06_bypass_added_later_restores_existing_accounts(self, world, tmp_path):
        """先建 Copilot 规则（现存账号查到 0 行），再用 apply_bypass_rls.py 补 bypass：无需首条策略确认。"""
        copilot(tmp_path, "--apply")
        assert bypass("--tables", T1, "--apply") == 0
        assert world.policy(T1, BYP) is not None and world.policy(T1, COP_A) is not None

    def test_g_c_07_exit_2_only_for_param_or_registry_errors(self, world, tmp_path):
        with pytest.raises(SystemExit) as e:
            apply_copilot_rls.main(["--condition-table", COND, "--mapping-table", MAP])     # 缺 --registry-table
        assert e.value.code == 2


# =========================================================================== #
# apply_copilot_rls.py：登记表
# =========================================================================== #
class TestCopilotRegistry:
    def test_g_r_01_only_enabled_mapping_tables(self, world, tmp_path, capsys):
        code, rows = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0
        assert world.policies(T_OFF) == [] and world.policies(T_NEW) == []
        assert f"[SKIP] {T_OFF}: 登记表中 rls_enabled ≠ 1，不授权" in err
        assert f"[SKIP] {T_NEW}: 不在登记表 {REG} 中，不授权" in err
        assert {r["table"] for r in rows} == {T1, T2, T3}

    def test_g_r_02_tables_arg_also_filtered(self, world, tmp_path, capsys):
        code, rows = copilot(tmp_path, "--tables", f"{T1},{T_OFF}", "--apply")
        err = capsys.readouterr().err
        assert code == 0 and {r["table"] for r in rows} == {T1} and f"[SKIP] {T_OFF}" in err

    def test_g_r_03_conflict_warn_skip_exit_1(self, world, tmp_path, capsys):
        world.register(T2, 0, status=0)
        code, rows = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.policies(T2) == [] and f"[WARN] {T2}" in err
        assert world.policy(T1, COP_A) is not None

    def test_g_r_04_raw_exact_match(self, world, tmp_path):
        world.unregister(T1).register(f" {T1}", 1)
        code, _ = copilot(tmp_path, "--apply")
        assert code == 0 and world.policies(T1) == []

    def test_g_r_05_status_ignored(self, world, tmp_path):
        world.unregister(T1).register(T1, 1, status=0)
        copilot(tmp_path, "--apply")
        assert world.policy(T1, COP_A) is not None

    def test_g_r_06_registry_missing_or_bad_schema_exit_2(self, world, tmp_path, capsys):
        out = str(tmp_path / "c.csv")
        code = apply_copilot_rls.main(["--condition-table", COND, "--mapping-table", MAP,
                                       "--registry-table", "trip-bq-admin.bq_auth.typo", "--group", G_COP, "-o", out, "--apply"])
        assert code == 2 and world.ddl_log == [] and "typo" in capsys.readouterr().err
        world.registry_fields[REG] = [("table_name", "STRING", "REQUIRED")]
        assert copilot(tmp_path, "--apply")[0] == 2 and world.ddl_log == []

    def test_g_r_07_registry_read_once(self, world, tmp_path):
        copilot(tmp_path)
        assert world.calls["query"] == 3          # 条件表 sa + 映射表 + 登记表各一次

    def test_g_r_08_skipped_tables_not_read(self, world, tmp_path):
        copilot(tmp_path)
        assert world.calls["list_policies"] == 3 and world.calls["get_table"] == 3     # 只处理 T1–T3

    def test_g_r_09_principals_flag_removed(self, world, tmp_path):
        with pytest.raises(SystemExit):
            copilot(tmp_path, "--principals", U_B, "--apply")

    def test_g_r_10_all_mapping_tables_disabled_exit_0(self, world, tmp_path, capsys):
        world.registry_rows[REG] = []
        code, rows = copilot(tmp_path, "--apply")
        assert code == 0 and world.ddl_log == [] and rows == [] and len(tags(capsys.readouterr().err, "[SKIP]")) == 5


# =========================================================================== #
# apply_copilot_rls.py：删除条件表 / 映射表保护
# =========================================================================== #
class TestCopilotNoAuthTableProtection:
    def test_g_p_01_auth_tables_disabled_in_registry_are_skipped(self, world, tmp_path, capsys):
        world.mapping_rows[MAP] += [{"table_name": COND, "col_name": "sa", "to_name": "region"},
                                    {"table_name": MAP, "col_name": "col_name", "to_name": "region"}]
        code, _ = copilot(tmp_path, "--tables", f"{T1},{COND},{MAP}", "--apply")
        err = capsys.readouterr().err
        assert code == 0 and "[EXCLUDE]" not in err
        assert f"[SKIP] {COND}" in err and f"[SKIP] {MAP}" in err
        assert world.policies(COND) == [] and world.policies(MAP) == []

    def test_g_p_02_auth_table_registered_enabled_gets_rule(self, world, tmp_path):
        """保护已删除：若登记表把条件表登记为开启，脚本照建（由客户用 rls_enabled = 0 控制）。"""
        world.unregister(COND).register(COND, 1)
        world.mapping_rows[MAP].append({"table_name": COND, "col_name": "sa", "to_name": "region"})
        code, _ = copilot(tmp_path, "--tables", COND, "--apply")
        assert code == 0 and world.policy(COND, COP_A) is not None


# =========================================================================== #
# apply_bypass_rls.py：去掉首条策略保护
# =========================================================================== #
class TestBypassNoFirstPolicyGate:
    def test_g_b_01_apply_creates_first_policy_without_flag(self, world, capsys):
        code = bypass("--tables", f"{T1},{T2}", "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T1, BYP) is not None and world.policy(T2, BYP) is not None
        assert FIRST_MSG in err and "如确认" not in err

    def test_g_b_02_force_first_policy_flag_removed(self, world):
        with pytest.raises(SystemExit) as e:
            bypass("--tables", T1, "--force-first-policy", "--apply")
        assert e.value.code == 2

    def test_g_b_03_first_policy_list_sorted_note_only(self, world, capsys):
        world.policies(T1).append(other_rule())
        code = bypass("--tables", f"{T3},{T2},{T1}")
        err = capsys.readouterr().err
        assert code == 0 and listed_after(err, FIRST_MSG) == [T2, T3]          # 按表名排序，已有 RLS 的 T1 不在内

    def test_g_b_04_no_list_when_all_tables_have_rls(self, world, capsys):
        world.policies(T1).append(other_rule())
        assert bypass("--tables", T1, "--apply") == 0
        assert FIRST_MSG not in capsys.readouterr().err


# =========================================================================== #
# rollback_rls.py：去掉删除全部保护 / 删光保护
# =========================================================================== #
class TestRollbackNoGates:
    def test_g_rb_01_no_filter_means_delete_all(self, world, capsys):
        world.policies(T1).extend([bypass_rule(), other_rule()])
        world.policies(T2).append(other_rule())
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T1) == [] and world.policies(T2) == []
        assert f"DROP ALL ROW ACCESS POLICIES ON `{T1}`" in err
        assert DROP_ALL_MSG in err and "如确认" not in err

    @pytest.mark.parametrize("flag", ["--all-policies", "--force-drop-all"])
    def test_g_rb_02_removed_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit) as e:
            rollback_rls.main(["--tables", T1, flag, "--apply"])
        assert e.value.code == 2

    def test_g_rb_03_principal_emptying_table_not_blocked(self, world, capsys):
        world.policies(T1).append(bypass_rule())
        code = rollback_rls.main(["--tables", T1, "--principals", G, "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T1) == [] and DROP_ALL_MSG in err

    def test_g_rb_04_partial_delete_no_drop_all_list(self, world, capsys):
        world.policies(T1).extend([bypass_rule(), other_rule()])
        code = rollback_rls.main(["--tables", T1, "--policy-names", "manual_rule", "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T1) == [bypass_rule()] and DROP_ALL_MSG not in err

    def test_g_rb_05_dry_run_delete_all_changes_nothing(self, world, capsys):
        world.policies(T1).append(other_rule())
        code = rollback_rls.main(["--tables", T1])
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == [] and world.policies(T1) == [other_rule()]
        assert "DRY-RUN" in err and DROP_ALL_MSG in err

    def test_g_rb_06_scope_still_required(self, world):
        assert rollback_rls.main(["--apply"]) == 2


    def test_g_rb_08_tables_without_rules_untouched(self, world):
        world.policies(T1).append(other_rule())
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--apply"])
        assert code == 0 and not any(T2 in d for d in world.ddl_log)
