"""
异常系（非通常操作）测试：注入、误用、脏数据、部分失败、并发一致性。
目标：任何异常输入都不能生成危险 DDL、不能越过安全闸门、不能以 Python 堆栈退出。
"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import FakeWorld, install, fake_auth
from tests.unit.test_normal_cases import (AUTH, BYP_ARGS, BYP_R, COP_G, G_COP, COND, G_R, G_W, MAP, P, SA_A, SA_B, T1, T2, T3, U_C,
                                          bypass_rule, cai_sa, cop_rule, read_csv, schema, write_list)

INJECTIONS = [
    'x"); DROP TABLE t; --', "x`; DROP", "x' OR 1=1", "a\nb", "a b", "a\\b", "x)) OR TRUE --",
]


def no_dangerous_ddl(world):
    for ddl in world.ddl_log:
        assert "DROP TABLE" not in ddl and "OR 1=1" not in ddl and "OR TRUE" not in ddl
        assert ddl.count("`") % 2 == 0 and ddl.count('"') % 2 == 0
        head = ddl.split("FILTER USING")[0]
        assert head.count("\n") == 3                                  # 固定格式：名字行 / ON 行 / GRANT 行 / FILTER 行
        assert all(line.startswith(("CREATE OR REPLACE ROW ACCESS POLICY `", "ON `", "GRANT TO (\"", "DROP "))
                   for line in head.strip().split("\n")), ddl


def exit_code(mod, args):
    """脚本既可能 return 2，也可能由 argparse 抛 SystemExit(2)；两者都算参数错误。"""
    try:
        return mod.main(args)
    except SystemExit as e:
        return e.code


# =========================================================================== #
# 参数 / 文件误用
# =========================================================================== #
class TestArgumentAbuse:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1, policies=[bypass_rule(G_R)], schema=schema(region="STRING"))
        w.add_table(COND)
        w.add_table(MAP)
        w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
        w.condition_sas[COND] = [SA_A]
        w.mapping_rows[MAP] = [{"table_name": T1, "col_name": "region", "to_name": "region"}]
        install(monkeypatch, w)
        for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
            monkeypatch.setattr(mod, "resolve_auth", fake_auth)
        return w

    @pytest.mark.parametrize("mod", [list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls])
    def test_a_arg_01_no_args_is_usage_error(self, world, mod):
        assert exit_code(mod, []) == 2

    @pytest.mark.parametrize("mod,args", [
        (list_principals, ["--proj", P]), (list_principals, ["--organization", "1"]),
        (apply_bypass_rls, ["--grou", G_R, "--tables", T1, *BYP_ARGS]),
        (apply_copilot_rls, ["--condition", COND, "--mapping-table", MAP]),
        (rollback_rls, ["--tab", T1, "--principals", SA_A]),
    ])
    def test_a_arg_02_abbreviated_or_unknown_flags_rejected(self, world, mod, args):
        with pytest.raises(SystemExit) as e:
            mod.main(args)
        assert e.value.code == 2 and world.ddl_log == []

    @pytest.mark.parametrize("mod,args", [
        (list_principals, ["--projects", "/nonexistent/p.csv"]),
        (list_principals, ["--organizations", "/nonexistent/o.csv"]),
        (apply_bypass_rls, ["--group", G_R, "--tables", "/nonexistent/t.csv", *BYP_ARGS]),
        (apply_bypass_rls, ["--group", G_R, "--datasets", "/nonexistent/d.csv", *BYP_ARGS]),
        (apply_bypass_rls, ["--group", G_R, "--projects", "/nonexistent/p.csv", *BYP_ARGS]),
        (apply_copilot_rls, [*AUTH, "--tables", "/nonexistent/t.csv"]),
        (rollback_rls, ["--tables", T1, "--principals", "/nonexistent/p.csv"]),
        (rollback_rls, ["--tables", T1, "--policy-names", "/nonexistent/n.csv"]),
    ])
    def test_a_arg_03_missing_file_is_clean_error(self, world, capsys, mod, args):
        code = exit_code(mod, args)
        err = capsys.readouterr().err
        assert code == 2 and "No such file" in err and "Traceback" not in err and world.ddl_log == []

    def test_a_arg_04_multi_column_csv_rejected(self, world, tmp_path, capsys):
        f = tmp_path / "t.csv"
        f.write_text(f"{T1},extra\n", encoding="utf-8")
        assert apply_bypass_rls.main(["--group", G_R, "--tables", str(f), *BYP_ARGS]) == 2
        assert "单列" in capsys.readouterr().err

    def test_a_arg_05_header_row_treated_as_value_and_rejected(self, world, tmp_path, capsys):
        f = tmp_path / "t.csv"
        f.write_text(f"table\n{T1}\n", encoding="utf-8")
        assert apply_bypass_rls.main(["--group", G_R, "--tables", str(f), *BYP_ARGS]) == 2
        assert "table" in capsys.readouterr().err and world.ddl_log == []

    def test_a_arg_06_empty_file_means_no_scope(self, world, tmp_path):
        f = write_list(tmp_path, "t.csv", [""])
        assert apply_bypass_rls.main(["--group", G_R, "--tables", f, *BYP_ARGS]) == 2
        assert rollback_rls.main(["--tables", f, "--principals", SA_A]) == 2

    @pytest.mark.parametrize("parallel", ["0", "-5"])
    def test_a_arg_07_nonpositive_parallel_degrades_to_serial(self, world, parallel):
        assert apply_bypass_rls.main(["--group", G_R, "--tables", T1, *BYP_ARGS, "--apply", "--parallel", parallel]) == 0

    def test_a_arg_08_bypass_two_groups_rejected(self, world, capsys):
        assert apply_bypass_rls.main(["--group", f"{G_R} {G_W}", "--tables", T1, *BYP_ARGS, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("flag", ["--all-policies", "--force-drop-all"])
    def test_a_arg_09_rollback_removed_gate_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit) as e:
            rollback_rls.main(["--tables", T1, flag, "--principals", SA_A, "--apply"])
        assert e.value.code == 2 and world.ddl_log == []

    def test_a_arg_09b_bypass_force_first_policy_rejected(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(["--group", G_R, "--tables", T1, *BYP_ARGS, "--force-first-policy", "--apply"])
        assert e.value.code == 2 and world.ddl_log == []

    @pytest.mark.parametrize("mod,flag", [
        (apply_bypass_rls, "--merge"), (apply_bypass_rls, "--groups"), (apply_bypass_rls, "--skip-edition-check"),
        (apply_copilot_rls, "--mapping-csv"), (apply_copilot_rls, "--groups"), (apply_copilot_rls, "--case-insensitive"),
        (rollback_rls, "--strip-only"), (rollback_rls, "--backup-dir"), (rollback_rls, "--delete-group"),
        (rollback_rls, "--groups"), (list_principals, "--folder"), (list_principals, "--include-iam-bound"),
    ])
    def test_a_arg_10_legacy_flags_rejected(self, world, mod, flag):
        base = {list_principals: ["--projects", P], apply_bypass_rls: ["--group", G_R, "--tables", T1, *BYP_ARGS],
                apply_copilot_rls: [*AUTH], rollback_rls: ["--tables", T1, "--principals", SA_A]}[mod]
        with pytest.raises(SystemExit):
            mod.main([*base, flag, "x"])


# =========================================================================== #
# 注入
# =========================================================================== #
class TestInjection:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1, policies=[bypass_rule(G_R)], schema=schema(region="STRING"))
        w.add_table(COND)
        w.add_table(MAP)
        w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
        w.condition_sas[COND] = [SA_A]
        w.mapping_rows[MAP] = [{"table_name": T1, "col_name": "region", "to_name": "region"}]
        install(monkeypatch, w)
        for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
            monkeypatch.setattr(mod, "resolve_auth", fake_auth)
        return w

    @pytest.mark.parametrize("bad", ["p.d.t`; DROP TABLE x; --", "p.d.t\nx", "p;d.t", "p.d.t) OR TRUE", "p.d", "p.d.t.u", "../etc"])
    def test_a_inj_01_table_names(self, world, bad):
        assert apply_bypass_rls.main(["--group", G_R, "--tables", bad, *BYP_ARGS, "--apply"]) == 2
        assert rollback_rls.main(["--tables", bad, "--principals", SA_A, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("bad", ["p.d`x", "p d", "p.d;", "p"])
    def test_a_inj_02_dataset_and_project_names(self, world, bad):
        assert apply_bypass_rls.main(["--group", G_R, "--datasets", bad, *BYP_ARGS, "--apply"]) == 2
        assert apply_bypass_rls.main(["--group", G_R, "--projects", "bad proj!", *BYP_ARGS, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("bad", ['g@x.com") FILTER USING (TRUE) --', "g@x.com`", "g@x.com\\", "g@x.com'", "g@x.com\u00a0x"])
    def test_a_inj_03_group_email(self, world, bad, capsys):
        code = apply_bypass_rls.main(["--group", bad, "--tables", T1, *BYP_ARGS, "--apply"])
        assert code == 2 and world.ddl_log == [] and "Traceback" not in capsys.readouterr().err

    @pytest.mark.parametrize("bad_col", INJECTIONS + ["region, amount", "`region`"])
    def test_a_inj_04_mapping_col_name(self, world, tmp_path, bad_col, capsys):
        world.mapping_rows[MAP] = [{"table_name": T1, "col_name": bad_col, "to_name": "region"}]
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and world.ddl_log == [] and "[IGNORE]" in err and "Traceback" not in err

    @pytest.mark.parametrize("bad_dim", INJECTIONS + ["region)", "sa"])
    def test_a_inj_05_mapping_to_name(self, world, tmp_path, bad_dim):
        world.mapping_rows[MAP] = [{"table_name": T1, "col_name": "region", "to_name": bad_dim}]
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        assert code == 1 and world.ddl_log == []

    def test_a_inj_06_mapping_table_name_injection(self, world, tmp_path):
        world.mapping_rows[MAP] = [{"table_name": "p.d.t`; DROP TABLE x; --", "col_name": "region", "to_name": "region"}]
        assert apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"]) == 1
        assert world.ddl_log == []

    @pytest.mark.parametrize("col", ["region x", "reg;drop", "reg)", "维度", "a-b", "x`y"])
    def test_a_inj_07_condition_table_flexible_column_names_not_used(self, world, tmp_path, col, capsys):
        # BigQuery 灵活列名可含空格 / 特殊字符；这类列不能进入 SQL
        world.condition_fields[COND].append((col, "STRING", "REPEATED"))
        world.mapping_rows[MAP].append({"table_name": T1, "col_name": "region", "to_name": col})
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and "含有特殊字符" in err and len(world.ddl_log) == 1
        assert col not in world.ddl_log[0] and "UNNEST(c.region)" in world.ddl_log[0]
        no_dangerous_ddl(world)

    @pytest.mark.parametrize("bad_sa", ['a"@x.com', "a`@x.com", "a@x.com\\", "a b@x.com", "a@x.com)", "not-an-email",
                                        "allUsers", "domain:x.com", "group:g@x.com", "a@x", "@x.com"])
    def test_a_inj_08_condition_sa_values(self, world, tmp_path, bad_sa, capsys):
        world.condition_sas[COND] = [bad_sa, SA_A]
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and "Traceback" not in err and "[WARN]" in err          # 只提醒；规则照建（与账号无关）
        assert len(world.ddl_log) == 1 and f'GRANT TO ("group:{G_COP}")' in world.ddl_log[0]
        assert bad_sa not in world.ddl_log[0]                                   # 条件表的值绝不进入 DDL
        no_dangerous_ddl(world)

    def test_a_inj_09_condition_sa_group_email_never_becomes_grantee(self, world, tmp_path):
        # 组邮箱被放进条件表 sa 列：它永远不会等于 SESSION_USER()（组不能查询），不会给整组放行；授权对象只来自 --group
        world.condition_sas[COND] = ["bi-team@domain.com"]
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        assert code == 0 and "bi-team@domain.com" not in world.ddl_log[0]
        assert f'GRANT TO ("group:{G_COP}")' in world.ddl_log[0]

    @pytest.mark.parametrize("prefixed", ["user:alice@domain.com", "serviceAccount:" + SA_A, "group:g@domain.com"])
    def test_a_inj_09b_prefixed_sa_values_rejected(self, world, tmp_path, capsys, prefixed):
        # 带前缀的值永远不等于 SESSION_USER()：[WARN] 提醒修正条件表，退出码 1；规则照建
        world.condition_sas[COND] = [prefixed, SA_A]
        code = apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and "不是裸邮箱" in err and prefixed in err and len(world.ddl_log) == 1

    @pytest.mark.parametrize("bad", INJECTIONS)
    def test_a_inj_10_rollback_policy_names_and_principals(self, world, bad):
        assert rollback_rls.main(["--tables", T1, "--policy-names", bad, "--apply"]) == 0
        assert rollback_rls.main(["--tables", T1, "--principals", bad, "--apply"]) == 0
        assert world.ddl_log == []                                              # 匹配不到任何现有规则

    def test_a_inj_11_drop_ddl_rejects_bad_name(self):
        with pytest.raises(ValueError):
            core.drop_policy_ddl(T1, "x`; DROP")
        with pytest.raises(ValueError):
            core.drop_policy_ddl(T1, "a" * 300)

    def test_a_inj_13_csv_formula_injection_in_copilot_note(self, world, tmp_path):
        world.policies(T1).append({"id": COP_G, "filter": "=cmd|' /C calc'!A0",
                                   "grantees": [f"group:{G_COP}"]})
        out = tmp_path / "c.csv"
        apply_copilot_rls.main([*AUTH, "-o", str(out), "--apply"])
        row = read_csv(out)[0]
        assert row["action"] == "REPLACE" and not row["note"].startswith("=") and "=cmd" in row["note"]

    def test_a_inj_15_policy_name_from_long_or_odd_email(self, world):
        for email in ["a" * 300 + "@x.com", "user+tag.name@sub.domain.com", "ÜNICODE@domain.com"]:
            name = core.copilot_policy_name(email)
            assert len(name) <= 256 and core._POLICY_RE.match(name), email
        assert core.copilot_policy_name("a.b@x.com") == core.copilot_policy_name("a_b@x.com")   # 撞名由 COLLISION 保护


# =========================================================================== #
# 安全闸门 / 脏数据 / 部分失败
# =========================================================================== #
class TestSafetyAndFailures:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1, policies=[bypass_rule(G_R)], schema=schema(region="STRING"))
        w.add_table(T2, policies=[bypass_rule(G_R)], schema=schema(region="STRING"))
        w.add_table(T3, schema=schema(region="STRING"))                                  # 无 bypass
        w.add_table(COND)
        w.add_table(MAP)
        w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
        w.condition_sas[COND] = [SA_A, U_C]
        w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in (T1, T2)]
        install(monkeypatch, w)
        for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
            monkeypatch.setattr(mod, "resolve_auth", fake_auth)
        return w

    def copilot(self, tmp_path, *args):
        out = tmp_path / "c.csv"
        return apply_copilot_rls.main([*AUTH, "-o", str(out), *args]), read_csv(out) if out.exists() else None

    def test_a_safe_01_no_bypass_gate_table_without_bypass_still_gets_rules(self, world, tmp_path):
        world.mapping_rows[MAP].append({"table_name": T3, "col_name": "region", "to_name": "region"})
        code, _ = self.copilot(tmp_path, "--apply")                             # T3 没有 bypass 规则
        assert code == 0 and world.policy(T3, COP_G) is not None
        assert world.policy(T1, COP_G) is not None

    def test_a_safe_02_bypass_first_policy_mixed_batch_not_blocked(self, world, capsys):
        code = apply_bypass_rls.main(["--group", G_W, "--tables", f"{T1},{T3}", *BYP_ARGS, "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T1, core.bypass_policy_name(G_W)) and world.policy(T3, core.bypass_policy_name(G_W))
        assert "将为以下这些表首次设置RLS规则" in err and f"  - {T3}" in err and f"  - {T1}" not in err

    def test_a_safe_03_rollback_drop_all_listed_but_not_blocked(self, world, capsys):
        world.policies(T3).append(cop_rule(SA_A))
        world.policies(T1).append(cop_rule(SA_A))
        code = rollback_rls.main(["--tables", f"{T1},{T3}", "--principals", SA_A, "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T3) == []                            # T3 被删空：只提示
        assert world.policy(T1, core.copilot_policy_name(SA_A)) is None and world.policies(T1)   # T1 部分删除
        assert f"  - {T3}" in err and f"  - {T1}" not in err

    def test_a_safe_04_registry_gate_duplicates_and_missing_registry(self, world, capsys):
        world.unregister(COND).register(COND, 0)
        code = apply_bypass_rls.main(["--group", G_W, "--tables", f"{T1},{T1},{COND}", *BYP_ARGS, "--apply"])
        assert code == 0 and world.policies(COND) == [] and world.policy(T1, core.bypass_policy_name(G_W))
        assert len(world.ddl_log) == 1                                          # 重复的表只执行一次
        code = apply_bypass_rls.main(["--group", G_W, "--tables", T1, "--registry-table", f"{P}.auth.missing",
                                      "--apply"])
        assert code == 2 and "missing" in capsys.readouterr().err

    def test_a_safe_05_copilot_auth_tables_controlled_by_registry(self, world, tmp_path, capsys):
        world.unregister(COND).register(COND, 0).unregister(MAP)            # 条件表登记为未开启、映射表未登记
        world.mapping_rows[MAP] += [{"table_name": COND, "col_name": "sa", "to_name": "region"},
                                    {"table_name": MAP, "col_name": "col_name", "to_name": "region"}]
        code, _ = self.copilot(tmp_path, "--apply", "--tables", f"{T1},{COND},{MAP}")
        err = capsys.readouterr().err
        assert code == 0 and "[EXCLUDE]" not in err and f"[SKIP] {COND}" in err and f"[SKIP] {MAP}" in err
        assert all(COND not in d.split("FILTER")[0] and MAP not in d.split("FILTER")[0] for d in world.ddl_log)

    def test_a_safe_06_policy_limit_never_exceeded(self, world, tmp_path):
        world.policies(T1).extend({"id": f"pad_{i}", "filter": "TRUE", "grantees": [f"user:u{i}@d.com"]} for i in range(400))
        code, rows = self.copilot(tmp_path, "--apply")
        assert code == 1 and len(world.policies(T1)) == 401                     # 1 条 bypass + 400 条 pad：不再新建
        assert sum(1 for r in rows if r["table"] == T1) == 0 and sum(1 for r in rows if r["table"] == T2) == 1

    def test_a_safe_07_same_name_other_grantee_is_replaced(self, world, tmp_path):
        # Group 级别：同名规则的授权对象被改动（例如改成某个账号）-> REPLACE 恢复为 group:，并在 CSV 记录旧内容
        world.policies(T1).append({"id": COP_G, "filter": "x", "grantees": ["serviceAccount:intruder@p.iam.gserviceaccount.com"]})
        code, rows = self.copilot(tmp_path, "--apply")
        assert code == 0 and world.policy(T1, COP_G)["grantees"] == [f"group:{G_COP}"]
        r = next(r for r in rows if r["table"] == T1)
        assert r["action"] == "REPLACE" and "intruder" in r["note"]

    def test_a_safe_08_principals_flag_removed(self, world, tmp_path):
        with pytest.raises(SystemExit):
            self.copilot(tmp_path, "--apply", "--principals", SA_A)

    def test_a_safe_09_condition_table_without_sa_column(self, world, tmp_path, capsys):
        world.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
        code, _ = self.copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.ddl_log == [] and "sa" in err and "Traceback" not in err

    def test_a_safe_10_condition_table_without_dimensions(self, world, tmp_path, capsys):
        world.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("note", "STRING", "NULLABLE")]
        code, _ = self.copilot(tmp_path, "--apply")
        assert code == 1 and world.ddl_log == [] and "没有可用作维度" in capsys.readouterr().err

    def test_a_safe_11_mapping_table_wrong_schema(self, world, tmp_path, capsys):
        world.mapping_rows[MAP] = [{"tbl": T1, "column": "region"}]                 # 列名不对
        code, _ = self.copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.ddl_log == [] and "全部无效" in err and "Traceback" not in err

    def test_a_safe_12_empty_mapping_table(self, world, tmp_path, capsys):
        world.mapping_rows[MAP] = []
        code, rows = self.copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == [] and rows == [] and "没有该表的校验维度" in err

    @pytest.mark.parametrize("raw", ["Copilot-SA-A@prod-proj.iam.gserviceaccount.com", f" {SA_A}", f"{SA_A}\t"])
    def test_a_safe_13_unnormalized_sa_values_warned(self, world, tmp_path, capsys, raw):
        world.condition_sas[COND] = [raw, U_C]
        code, rows = self.copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and "SESSION_USER()" in err and "0 行" in err
        assert world.policy(T1, COP_G)["grantees"] == [f"group:{G_COP}"]              # 规则照建

    def test_a_safe_14_duplicate_principals_by_case_collapse(self, world, tmp_path):
        world.condition_sas[COND] = [SA_A, SA_A.upper()]
        code, rows = self.copilot(tmp_path, "--apply")
        assert code == 1 and len([x for x in world.policies(T1) if x["id"].startswith(core.COPILOT_PREFIX)]) == 1

    def test_a_safe_15_table_missing_or_schema_error_isolated(self, world, tmp_path, capsys):
        del world.tables[T2]
        code, rows = self.copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and f"[SKIP] {T2}" in err and "Traceback" not in err
        assert {r["table"] for r in rows} == {T1}

    def test_a_safe_16_bypass_ddl_failure_isolated(self, world, capsys):
        world.fail_ddl_on.add(T1)
        code = apply_bypass_rls.main(["--group", G_W, "--tables", f"{T1},{T2}", *BYP_ARGS, "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and world.policy(T2, core.bypass_policy_name(G_W)) and "[ERROR]" in err and "Traceback" not in err

    def test_a_safe_17_copilot_ddl_failure_recorded_in_csv(self, world, tmp_path):
        world.fail_ddl_on.add(T1)
        code, rows = self.copilot(tmp_path, "--apply")
        assert code == 1
        assert {r["result"][:5] for r in rows if r["table"] == T1} == {"ERROR"}
        assert {r["result"] for r in rows if r["table"] == T2} == {"OK"}

    def test_a_safe_18_rollback_ddl_failure_isolated(self, world, capsys):
        world.policies(T1).append(cop_rule(SA_A))
        world.policies(T2).append(cop_rule(SA_A))
        world.fail_ddl_on.add(T1)
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--principals", SA_A, "--apply"])
        assert code == 1 and world.policy(T2, cop_rule(SA_A)["id"]) is None and world.policy(T1, cop_rule(SA_A)["id"])

    def test_a_safe_19_verify_failure_semantics(self, world, capsys):
        world.verify_result[(T1, SA_A)] = ("fail", "403 Access Denied")
        assert apply_bypass_rls.main(["--group", G_W, "--tables", T1, *BYP_ARGS, "--apply", "--verify-sa", SA_A]) == 1
        world.policies(T1).append(cop_rule(SA_A))
        # rollback 的验证只报告：查询失败也不改变退出码
        import gcp_ops as ops
        ops.count_visible = lambda ctx, t, sa: (_ for _ in ()).throw(RuntimeError("403"))
        assert rollback_rls.main(["--tables", T1, "--principals", SA_A, "--apply", "--verify-sa", SA_A]) == 0
        assert "查询失败" in capsys.readouterr().err

    def test_a_safe_20_unexpected_exception_is_clean_error(self, world, monkeypatch, capsys):
        monkeypatch.setattr(apply_bypass_rls, "resolve_auth", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("gcloud not logged in")))
        code = apply_bypass_rls.main(["--group", G_W, "--tables", T1, *BYP_ARGS, "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and "[ERROR] RuntimeError: gcloud not logged in" in err and "Traceback" not in err

    def test_a_safe_21_keyboard_interrupt(self, world, monkeypatch):
        monkeypatch.setattr(apply_copilot_rls, "resolve_auth", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
        assert apply_copilot_rls.main([*AUTH]) == 130

    def test_a_safe_24_rollback_nonexistent_names_and_table_without_rules(self, world, capsys):
        del world.tables[T3]
        world.add_table(T3)
        code = rollback_rls.main(["--tables", f"{T1},{T3}", "--policy-names", "nope", "--apply"])
        assert code == 0 and world.ddl_log == [] and "0 张表" in capsys.readouterr().err

    def test_a_safe_25_parallel_consistency_many_tables(self, world, tmp_path):
        for i in range(60):
            world.add_table(f"{P}.bulk.t{i:03d}", policies=[bypass_rule(G_R)], schema=schema(region="STRING"))
            world.mapping_rows[MAP].append({"table_name": f"{P}.bulk.t{i:03d}", "col_name": "region", "to_name": "region"})
        code, rows = self.copilot(tmp_path, "--apply", "--parallel", "16")
        assert code == 0 and len(rows) == 62 and len(set(world.ddl_log)) == len(world.ddl_log) == 62
        assert all(len([x for x in world.policies(f"{P}.bulk.t{i:03d}") if x["id"].startswith(core.COPILOT_PREFIX)]) == 1
                   for i in range(60))
        code = rollback_rls.main(["--datasets", f"{P}.bulk", "--principals", G_COP, "--apply", "--parallel", "16"])
        assert code == 0 and all(world.policy(f"{P}.bulk.t{i:03d}", COP_G) is None for i in range(60))
