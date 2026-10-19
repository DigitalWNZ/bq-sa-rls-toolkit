"""
参数精简（2026-10-19，实施计划 param_simplification_plan_v1.0，已批准）：
  - 合并 X / X-file：--tables / --datasets / --projects / --principals / --policy-names / --organizations 的值可直接写
    （逗号 / 空格分隔），也可写 .csv 文件（以 .csv 结尾且不在反引号内即读文件），可混用；文件不存在 -> 退出码 2
  - 表名参数统一 project.dataset.table（必须三段），反引号可选；不接受 project:dataset.table；--datasets 同理
  - 删除：全部 -file 参数、rollback 的 --match-names-only / --skip-grantee-log、bypass 的 --verify-timeout / --verify-mode
  - --parallel 默认 16
"""

import pytest

import apply_bypass_rls
import apply_copilot_rls
import gcp_ops as ops
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.orders", f"{P}.dw.booking", f"{P}.ods.events"
COND = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition"
MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G = "group_existingsa_read@trip.com"
G_COP = "group_copilot@trip.com"
BYP = core.bypass_policy_name(G)
COP = core.copilot_policy_name(G_COP)
SA_A = "copilot-a@trip-prod.iam.gserviceaccount.com"
READER = "reader@trip-prod.iam.gserviceaccount.com"


def bq(name):
    return f"`{name}`"


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in (T1, T2, T3):
        w.add_table(t, schema={"region": ("STRING", "NULLABLE")})
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
    w.condition_sas[COND] = [SA_A]
    w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in (T1, T2, T3)]
    w.project_sas[P] = [SA_A]
    install(monkeypatch, w)
    for mod in (apply_bypass_rls, apply_copilot_rls, rollback_rls, list_principals):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def write(tmp_path, name, lines, raw=None):
    f = tmp_path / name
    if raw is not None:
        f.write_bytes(raw)
    else:
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(f)


def bypass(*args):
    return apply_bypass_rls.main(["--group", G, "--registry-table", REG, *args])


def copilot(tmp_path, *args, cond=COND, mapping=MAP, reg=REG):
    return apply_copilot_rls.main(["--group", G_COP, "--condition-table", cond, "--mapping-table", mapping,
                                   "--registry-table", reg, "-o", str(tmp_path / "c.csv"), *args])


# =========================================================================== #
# 公共解析函数（单体测试）
# =========================================================================== #
class TestParseFunctions:
    @pytest.mark.parametrize("v", ["p.d.t", "`p.d.t`", "  `trip-bq-admin.bq_auth.adm_user_mem_copilot_tb`  ",
                                   "trip-prod.dw.orders", "123456.d_1.t-2"])
    def test_table_arg_ok(self, v):
        assert core.parse_table_arg(v) == v.strip().strip("`")

    @pytest.mark.parametrize("v", ["p:d.t", "`p:d.t`", "d.t", "p.d.t.u", "`p.d.t", "p.d.t`", "``p.d.t``",
                                   "`p`.`d`.`t`", "p.d.t`; DROP", "", "`", "p..t", "p.d.t\nx", "p.d.t)"])
    def test_table_arg_rejected(self, v):
        with pytest.raises(ValueError):
            core.parse_table_arg(v)

    @pytest.mark.parametrize("v", ["p.d", "`p.d`", "trip-prod.dw"])
    def test_dataset_arg_ok(self, v):
        assert core.parse_dataset_arg(v) == v.strip("`")

    @pytest.mark.parametrize("v", ["p:d", "`p:d`", "p", "p.d.t", "`p.d", "p d"])
    def test_dataset_arg_rejected(self, v):
        with pytest.raises(ValueError):
            core.parse_dataset_arg(v)

    def test_collect_values_mixed_and_dedup(self, tmp_path):
        f = write(tmp_path, "t.csv", ["p.d.b", "p.d.a", ""])
        assert core.collect_values(["p.d.a,p.d.c", f, "p.d.b p.d.d"]) == ["p.d.a", "p.d.c", "p.d.b", "p.d.d"]

    def test_collect_values_bom_crlf_blank_lines(self, tmp_path):
        f = write(tmp_path, "x.CSV", None, raw="\ufeffp.d.a\r\n\r\n  p.d.b  \r\n".encode("utf-8"))
        assert core.collect_values([f]) == ["p.d.a", "p.d.b"]

    def test_collect_values_missing_csv_is_error(self, tmp_path):
        with pytest.raises(OSError):
            core.collect_values([str(tmp_path / "nope.csv")])

    def test_collect_values_backticked_csv_is_a_name(self):
        assert core.collect_values(["`p.csv`"]) == ["`p.csv`"]

    def test_collect_values_multi_column_file_rejected(self, tmp_path):
        f = write(tmp_path, "m.csv", ["p.d.a,p.d.b"])
        with pytest.raises(ValueError):
            core.collect_values([f])

    def test_collect_values_empty(self):
        assert core.collect_values([]) == [] and core.collect_values(None) == []

    def test_old_collect_removed(self):
        assert not hasattr(core, "collect")


# =========================================================================== #
# 合并后的列表参数（各脚本）
# =========================================================================== #
class TestMergedListParams:
    def test_bypass_tables_values_file_mixed(self, world, tmp_path):
        f = write(tmp_path, "t.csv", [T2, bq(T3)])
        assert bypass("--tables", T1, f, "--apply") == 0
        assert all(world.policy(t, BYP) for t in (T1, T2, T3))

    def test_bypass_datasets_and_projects_files(self, world, tmp_path):
        d = write(tmp_path, "d.csv", [bq(f"{P}.ods")])
        p = write(tmp_path, "p.csv", [P])
        assert bypass("--datasets", d, "--apply") == 0 and world.policy(T3, BYP) and world.policy(T1, BYP) is None
        assert bypass("--projects", p, "--apply") == 0 and world.policy(T1, BYP)

    def test_copilot_tables_file(self, world, tmp_path):
        f = write(tmp_path, "t.csv", [T1])
        assert copilot(tmp_path, "--tables", f, "--apply") == 0
        assert world.policy(T1, COP) and world.policy(T2, COP) is None

    def test_rollback_principals_and_policy_names_files(self, world, tmp_path):
        for t in (T1, T2):
            world.policies(t).extend([{"id": BYP, "filter": "TRUE", "grantees": [f"group:{G}"]},
                                      {"id": "keep", "filter": "TRUE", "grantees": ["user:k@trip.com"]}])
        pf = write(tmp_path, "p.csv", [G])
        assert rollback_rls.main(["--tables", T1, "--principals", pf, "--apply"]) == 0
        assert world.policy(T1, BYP) is None and world.policy(T1, "keep")
        nf = write(tmp_path, "n.csv", ["keep"])
        assert rollback_rls.main(["--tables", bq(T2), "--policy-names", nf, "--apply"]) == 0
        assert world.policy(T2, "keep") is None and world.policy(T2, BYP)

    def test_list_principals_organizations_and_projects_files(self, world, tmp_path):
        world.crm_children["organizations/111"] = {"folders": [], "projects": [(P, "ACTIVE")]}
        world.org_customer["111"] = "C0"
        o = write(tmp_path, "o.csv", ["111"])
        p = write(tmp_path, "p.csv", [P])
        assert list_principals.main(["--organizations", o, "--projects", p, "-o", str(tmp_path / "x.csv")]) == 0

    def test_repeated_flags_accumulate(self, world, tmp_path):
        """同一个列表参数写多次（例如值一次、文件一次）全部生效，而不是只保留最后一次。"""
        f = write(tmp_path, "t.csv", [T3])
        assert bypass("--tables", T1, "--tables", f, "--tables", bq(T2), "--apply") == 0
        assert all(world.policy(t, BYP) for t in (T1, T2, T3))
        for t in (T1, T2):
            world.policies(t).append({"id": "k", "filter": "TRUE", "grantees": ["user:k@trip.com"]})
        nf = write(tmp_path, "n.csv", ["k"])
        assert rollback_rls.main(["--tables", T1, "--tables", T2, "--policy-names", BYP, "--policy-names", nf, "--apply"]) == 0
        assert world.policies(T1) == [] and world.policies(T2) == []

    @pytest.mark.parametrize("mod,args", [
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", "/nonexistent/t.csv"]),
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--datasets", "/nonexistent/d.csv"]),
        (apply_copilot_rls, ["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP,
                             "--registry-table", REG, "--tables", "/nonexistent/t.csv"]),
        (rollback_rls, ["--tables", T1, "--principals", "/nonexistent/p.csv"]),
        (rollback_rls, ["--tables", T1, "--policy-names", "missing.csv"]),
        (list_principals, ["--projects", "/nonexistent/p.csv"]),
    ])
    def test_missing_csv_is_exit_2(self, world, capsys, mod, args):
        try:
            code = mod.main(args)
        except SystemExit as e:
            code = e.code
        err = capsys.readouterr().err
        assert code == 2 and "Traceback" not in err and world.ddl_log == []


# =========================================================================== #
# 表名参数格式
# =========================================================================== #
class TestTableNameFormat:
    def test_backticked_names_everywhere(self, world, tmp_path):
        assert apply_bypass_rls.main(["--group", G, "--registry-table", bq(REG), "--tables", bq(T1), "--apply"]) == 0
        assert copilot(tmp_path, "--tables", bq(T1), "--apply", cond=bq(COND), mapping=bq(MAP), reg=bq(REG)) == 0
        assert world.policy(T1, BYP) and world.policy(T1, COP)
        assert rollback_rls.main(["--tables", bq(T1), "--principals", G_COP, "--apply"]) == 0
        assert world.policy(T1, COP) is None

    @pytest.mark.parametrize("bad", [f"{P}:dw.orders", "dw.orders", f"`{P}.dw.orders", f"{P}.dw.orders.x",
                                     f"`{P}`.`dw`.`orders`"])
    def test_bad_table_names_rejected_in_every_script(self, world, tmp_path, bad):
        assert bypass("--tables", bad, "--apply") == 2
        assert copilot(tmp_path, "--tables", bad, "--apply") == 2
        assert rollback_rls.main(["--tables", bad, "--principals", G, "--apply"]) == 2
        assert world.ddl_log == []

    @pytest.mark.parametrize("which", ["cond", "mapping", "reg"])
    def test_colon_form_rejected_for_copilot_auth_tables(self, world, tmp_path, which):
        kw = {"cond": COND, "mapping": MAP, "reg": REG}
        kw[which] = kw[which].replace(".", ":", 1)
        assert copilot(tmp_path, "--apply", **kw) == 2 and world.ddl_log == []

    def test_colon_form_rejected_for_bypass_registry(self, world):
        assert apply_bypass_rls.main(["--group", G, "--registry-table", REG.replace(".", ":", 1),
                                      "--tables", T1, "--apply"]) == 2

    @pytest.mark.parametrize("bad", [f"{P}:dw", "dw", f"`{P}.dw"])
    def test_bad_dataset_names_rejected(self, world, bad):
        assert bypass("--datasets", bad, "--apply") == 2
        assert rollback_rls.main(["--datasets", bad, "--principals", G, "--apply"]) == 2

    def test_bad_name_inside_file_rejected(self, world, tmp_path):
        f = write(tmp_path, "t.csv", [T1, f"{P}:dw.booking"])
        assert bypass("--tables", f, "--apply") == 2 and world.ddl_log == []

    def test_mapping_table_contents_rules_unchanged(self, world, tmp_path):
        """只改参数解析：映射表里仍允许 dataset.table（默认映射表所在项目）。"""
        world.add_table("trip-bq-admin.dw2.t9", schema={"region": ("STRING", "NULLABLE")})
        world.mapping_rows[MAP].append({"table_name": "dw2.t9", "col_name": "region", "to_name": "region"})
        assert copilot(tmp_path, "--apply") == 0 and world.policy("trip-bq-admin.dw2.t9", COP)


# =========================================================================== #
# 删除的参数 / 默认值
# =========================================================================== #
class TestRemovedFlagsAndDefaults:
    @pytest.mark.parametrize("mod,base,flag", [
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", T1], "--tables-file"),
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", T1], "--datasets-file"),
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", T1], "--projects-file"),
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", T1], "--verify-timeout"),
        (apply_bypass_rls, ["--group", G, "--registry-table", REG, "--tables", T1], "--verify-mode"),
        (apply_copilot_rls, ["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG],
         "--tables-file"),
        (rollback_rls, ["--tables", T1, "--principals", G], "--tables-file"),
        (rollback_rls, ["--tables", T1, "--principals", G], "--datasets-file"),
        (rollback_rls, ["--tables", T1, "--principals", G], "--projects-file"),
        (rollback_rls, ["--tables", T1, "--principals", G], "--principals-file"),
        (rollback_rls, ["--tables", T1, "--principals", G], "--policy-names-file"),
        (list_principals, ["--projects", P], "--organizations-file"),
        (list_principals, ["--projects", P], "--projects-file"),
    ])
    def test_removed_value_flags(self, world, mod, base, flag):
        with pytest.raises(SystemExit) as e:
            mod.main([*base, flag, "x"])
        assert e.value.code == 2

    @pytest.mark.parametrize("flag", ["--match-names-only", "--skip-grantee-log"])
    def test_removed_rollback_switches(self, world, flag):
        with pytest.raises(SystemExit) as e:
            rollback_rls.main(["--tables", T1, "--principals", G, flag])
        assert e.value.code == 2

    def test_parallel_default_16(self, world, tmp_path, capsys):
        bypass("--tables", T1)
        copilot(tmp_path)
        rollback_rls.main(["--tables", T1, "--principals", G])
        err = capsys.readouterr().err
        assert err.count("并行: 16") == 3

    def test_list_principals_parallel_default_16(self, world, tmp_path, monkeypatch):
        seen = []
        orig = ops.parallel_map

        def spy(fn, items, workers=8, desc=""):
            seen.append(workers)
            return orig(fn, items, workers=workers, desc=desc)
        monkeypatch.setattr(ops, "parallel_map", spy)
        list_principals.main(["--projects", P, "-o", str(tmp_path / "x.csv")])
        assert seen and set(seen) == {16}

    def test_bypass_verify_uses_fixed_timeout_and_sample(self, world, monkeypatch):
        calls = []
        monkeypatch.setattr(ops, "verify_full_access",
                            lambda ctx, t, sa, timeout=300, mode="sample": calls.append((t, sa, timeout, mode)) or ("ok", "1 行"))
        assert bypass("--tables", T1, "--apply", "--verify-sa", READER) == 0
        assert calls == [(T1, READER, 300, "sample")]

    def test_rollback_by_principal_always_reads_grantees(self, world):
        world.policies(T1).extend([{"id": "manual_x", "filter": "TRUE", "grantees": [f"group:{G}"]},
                                   {"id": "other", "filter": "TRUE", "grantees": ["user:o@trip.com"]}])
        assert rollback_rls.main(["--tables", T1, "--principals", G, "--apply"]) == 0
        assert world.calls["policy_iam"] == 2                              # 每条规则都读授权对象
        assert world.policy(T1, "manual_x") is None and world.policy(T1, "other")   # 手工规则名也能按主体删除

    def test_rollback_log_always_has_grantees(self, world, capsys):
        world.policies(T1).append({"id": "only", "filter": "TRUE", "grantees": ["user:o@trip.com"]})
        rollback_rls.main(["--tables", T1, "--apply"])
        assert "grantees=['user:o@trip.com']" in capsys.readouterr().err
