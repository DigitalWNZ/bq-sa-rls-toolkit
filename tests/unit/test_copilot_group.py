"""
apply_copilot_rls.py 改为 Group 级别（2026-10-18，实施计划 copilot_group_rls_plan_v1.0）：
  - 每张表给 --group 建一条规则 rls_copilot_<group>，GRANT TO ("group:<group>")；过滤条件仍按 SESSION_USER() 实时查条件表
  - 只处理登记表 rls_enabled = 1 的表；登记为开启但没有校验维度的表 [SKIP]
  - 条件表 sa 值不规范 / 非法 / 重复 → [WARN]、退出码 1（不影响建规则）；条件表为空 → [NOTE]、照建
  - 删除 --principals / --principals-file；审核 CSV 每张表一行
"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import rls_core as core
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.orders", f"{P}.dw.booking", f"{P}.ods.events"
T_OFF, T_NODIM, T_NOMAP = f"{P}.dw.tmp_off", f"{P}.dw.nodim", f"{P}.dw.not_in_mapping"
COND = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition"
MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G = "group_copilot@trip.com"
G2 = "group_copilot_vendor@trip.com"
POL, POL2 = core.copilot_policy_name(G), core.copilot_policy_name(G2)
GRANTEE = f"group:{G}"
SA_A, U_B = "copilot-a@trip-prod.iam.gserviceaccount.com", "bob@trip.com"
BYP = core.bypass_policy_name("group_existingsa_read@trip.com")
DIM3 = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED"),
        ("prdtype", "STRING", "REPEATED"), ("refername", "STRING", "REPEATED"), ("status", "INTEGER", "NULLABLE")]


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    cols3 = {"region": ("STRING", "NULLABLE"), "prd_type": ("STRING", "NULLABLE"), "refername": ("STRING", "NULLABLE")}
    w.add_table(T1, schema=cols3)                                       # 三个维度
    w.add_table(T2, schema={"market": ("STRING", "NULLABLE")})          # 一个维度、列名不同
    w.add_table(T3, schema={"region": ("STRING", "NULLABLE"), "ptype": ("INT64", "NULLABLE")})   # 两个维度、非 STRING 列
    w.add_table(T_OFF, schema={"region": ("STRING", "NULLABLE")}, rls_enabled=0)
    w.add_table(T_NODIM, schema={"x": ("STRING", "NULLABLE")})          # 映射表里只有无效维度
    w.add_table(T_NOMAP, schema={"x": ("STRING", "NULLABLE")})          # 映射表里没有
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = list(DIM3)
    w.condition_sas[COND] = [SA_A, U_B]
    w.mapping_rows[MAP] = [
        {"table_name": T1, "col_name": "region", "to_name": "region"},
        {"table_name": T1, "col_name": "prd_type", "to_name": "prdtype"},
        {"table_name": T1, "col_name": "refername", "to_name": "refername"},
        {"table_name": T2, "col_name": "market", "to_name": "region"},
        {"table_name": T3, "col_name": "region", "to_name": "region"},
        {"table_name": T3, "col_name": "ptype", "to_name": "prdtype"},
        {"table_name": T_OFF, "col_name": "region", "to_name": "region"},
        {"table_name": T_NODIM, "col_name": "x", "to_name": "not_a_dimension"},
    ]
    install(monkeypatch, w)
    for mod in (apply_copilot_rls, apply_bypass_rls):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def run(tmp_path, *args, group=G, name="plan.csv"):
    out = tmp_path / name
    g = ["--group", group] if group else []
    code = apply_copilot_rls.main(["--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG,
                                   *g, "-o", str(out), *args])
    return code, (read_csv(out) if out.exists() else None)


def expected_filter(table, world):
    cols = {T1: [("region", "region"), ("prd_type", "prdtype"), ("refername", "refername")],
            T2: [("market", "region")], T3: [("region", "region"), ("ptype", "prdtype")]}[table]
    types = {c: world.tables[table]["schema"][c][0] for c, _ in cols}
    return core.build_copilot_filter(cols, COND, column_types=types)


# =========================================================================== #
# 正常系
# =========================================================================== #
class TestNormal:
    def test_c_n_01_one_group_rule_per_table(self, world, tmp_path):
        code, rows = run(tmp_path, "--apply")
        assert code == 0
        for t in (T1, T2, T3):
            pols = world.policies(t)
            assert len(pols) == 1
            assert pols[0] == {"id": POL, "filter": expected_filter(t, world), "grantees": [GRANTEE]}
        assert len(world.ddl_log) == 3                              # 每张表一条 DDL，与账号数无关

    def test_c_n_02_exact_ddl_matches_sample_structure(self, world, tmp_path):
        run(tmp_path, "--tables", T2, "--apply")
        cond = COND
        assert world.ddl_log == [
            f"CREATE OR REPLACE ROW ACCESS POLICY `{POL}`\nON `{T2}`\nGRANT TO (\"{GRANTEE}\")\nFILTER USING ("
            f"(`market` IN (SELECT v FROM `{cond}` AS c, UNNEST(c.region) AS v WHERE c.sa = SESSION_USER()) "
            f"OR EXISTS (SELECT 1 FROM `{cond}` AS c WHERE c.sa = SESSION_USER() "
            f"AND (c.region IS NULL OR ARRAY_LENGTH(c.region) = 0))))"]

    def test_c_n_03_multi_dimension_and_and_no_status(self, world, tmp_path):
        run(tmp_path, "--tables", T1, "--apply")
        flt = world.policy(T1, POL)["filter"]
        assert flt.count(" AND (") >= 2 and "UNNEST(c.region)" in flt and "UNNEST(c.prdtype)" in flt
        assert "UNNEST(c.refername)" in flt and "status" not in flt          # Q3：status 不生效

    def test_c_n_04_non_string_column_cast(self, world, tmp_path):
        run(tmp_path, "--tables", T3, "--apply")
        assert "CAST(`ptype` AS STRING)" in world.policy(T3, POL)["filter"]

    def test_c_n_05_only_registry_enabled_tables(self, world, tmp_path, capsys):
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T_OFF) == []
        assert f"[SKIP] {T_OFF}: 登记表中 rls_enabled ≠ 1，不授权" in err

    def test_c_n_06_enabled_tables_without_dimension_skipped(self, world, tmp_path, capsys):
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T_NODIM) == [] and world.policies(T_NOMAP) == []
        assert f"[SKIP] {T_NODIM}" in err and f"[SKIP] {T_NOMAP}" in err and "没有该表的校验维度" in err

    def test_c_n_07_rerun_is_noop(self, world, tmp_path, capsys):
        run(tmp_path, "--apply")
        n = len(world.ddl_log)
        code, rows = run(tmp_path, "--apply")
        assert code == 0 and len(world.ddl_log) == n and rows == []
        assert "NOOP 3" in capsys.readouterr().err

    def test_c_n_08_new_account_needs_no_rerun_changes(self, world, tmp_path):
        run(tmp_path, "--apply")
        n = len(world.ddl_log)
        world.condition_sas[COND].append("new-sa@trip-prod.iam.gserviceaccount.com")
        code, rows = run(tmp_path, "--apply")
        assert code == 0 and len(world.ddl_log) == n and rows == []       # 新增账号：规则不变

    def test_c_n_09_mapping_change_replaces_and_records_old(self, world, tmp_path):
        run(tmp_path, "--apply")
        old = world.policy(T2, POL)["filter"]
        world.mapping_rows[MAP].append({"table_name": T2, "col_name": "market", "to_name": "refername"})
        code, rows = run(tmp_path, "--apply")
        assert code == 0 and world.policy(T2, POL)["filter"] != old and "UNNEST(c.refername)" in world.policy(T2, POL)["filter"]
        r = next(r for r in rows if r["table"] == T2)
        assert r["action"] == "REPLACE" and old in r["note"]

    def test_c_n_10_manual_tamper_replaced(self, world, tmp_path):
        run(tmp_path, "--apply")
        world.policy(T1, POL)["grantees"] = ["user:intruder@x.com"]
        code, rows = run(tmp_path, "--apply")
        assert code == 0 and world.policy(T1, POL)["grantees"] == [GRANTEE]
        assert [r["action"] for r in rows if r["table"] == T1] == ["REPLACE"]

    def test_c_n_11_tables_filter(self, world, tmp_path):
        code, rows = run(tmp_path, "--tables", f"{T1},{T3}", "--apply")
        assert code == 0 and {r["table"] for r in rows} == {T1, T3} and world.policies(T2) == []

    def test_c_n_12_csv_one_row_per_table(self, world, tmp_path):
        code, rows = run(tmp_path)                                         # 演练
        assert code == 0 and world.ddl_log == []
        assert list(rows[0]) == ["table", "policy_name", "action", "dimensions", "filter", "note"]
        r1 = next(r for r in rows if r["table"] == T1)
        assert r1["policy_name"] == POL and r1["action"] == "CREATE" and r1["dimensions"] == "region, prdtype, refername"
        code, rows = run(tmp_path, "--apply", name="apply.csv")
        assert list(rows[0])[-1] == "result" and {r["result"] for r in rows} == {"OK"}

    def test_c_n_13_first_policy_note(self, world, tmp_path, capsys):
        world.policies(T1).append({"id": BYP, "filter": "TRUE", "grantees": ["group:group_existingsa_read@trip.com"]})
        run(tmp_path, "--apply")
        err = capsys.readouterr().err
        block = err[err.index("将为以下这些表首次设置RLS规则"):].splitlines()
        listed = [l[4:] for l in block[1:] if l.startswith("  - ")]
        assert T1 not in listed and T2 in listed

    def test_c_n_14_bypass_rules_untouched(self, world, tmp_path):
        byp = {"id": BYP, "filter": "TRUE", "grantees": ["group:group_existingsa_read@trip.com"]}
        world.policies(T1).append(dict(byp))
        run(tmp_path, "--apply")
        assert world.policy(T1, BYP) == byp and world.policy(T1, POL) is not None

    def test_c_n_15_second_group_gets_its_own_rule(self, world, tmp_path):
        run(tmp_path, "--apply")
        code, _ = run(tmp_path, "--apply", group=G2)
        assert code == 0 and {p["id"] for p in world.policies(T1)} == {POL, POL2}
        assert world.policy(T1, POL2)["grantees"] == [f"group:{G2}"]

    def test_c_n_16_new_dimension_column_picked_up(self, world, tmp_path):
        world.condition_fields[COND].append(("channel", "STRING", "REPEATED"))
        world.tables[T2]["schema"]["ch"] = ("STRING", "NULLABLE")
        world.mapping_rows[MAP].append({"table_name": T2, "col_name": "ch", "to_name": "channel"})
        run(tmp_path, "--tables", T2, "--apply")
        assert "UNNEST(c.channel)" in world.policy(T2, POL)["filter"]

    def test_c_n_17_empty_condition_table_still_creates(self, world, tmp_path, capsys):
        world.condition_sas[COND] = []
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T1, POL) is not None and "[NOTE]" in err and "条件表" in err

    @pytest.mark.parametrize("parallel", ["1", "32"])
    def test_c_n_18_parallel_same_outcome(self, world, tmp_path, parallel):
        run(tmp_path, "--apply", "--parallel", parallel)
        assert sorted(d.split("\n")[1] for d in world.ddl_log) == sorted(f"ON `{t}`" for t in (T1, T2, T3))

    def test_c_n_19_group_email_normalized(self, world, tmp_path):
        run(tmp_path, "--tables", T2, "--apply", group="Group_Copilot@Trip.COM")
        assert world.policy(T2, POL)["grantees"] == [GRANTEE]

    def test_c_n_20_api_calls_independent_of_account_count(self, world, tmp_path):
        world.condition_sas[COND] = [f"u{i}@trip.com" for i in range(457)]
        run(tmp_path, "--apply")
        assert world.calls["ddl"] == 3 and world.calls["policy_iam"] == 0     # 首次：不读授权对象


# =========================================================================== #
# 异常系
# =========================================================================== #
class TestAbnormal:
    def test_c_a_01_group_required(self, world, tmp_path):
        with pytest.raises(SystemExit) as e:
            run(tmp_path, group=None)
        assert e.value.code == 2

    @pytest.mark.parametrize("bad", [f"{G},{G2}", f"{G} {G2}"])
    def test_c_a_02_only_one_group(self, world, tmp_path, bad, capsys):
        code, _ = run(tmp_path, group=bad)
        assert code == 2 and world.ddl_log == [] and "只能指定一个" in capsys.readouterr().err

    def test_c_a_03_service_account_is_not_a_group(self, world, tmp_path):
        code, _ = run(tmp_path, "--apply", group=SA_A)
        assert code == 2 and world.ddl_log == []

    @pytest.mark.parametrize("bad", ['g@x.com") OR TRUE --', "g@x.com`", "noatsign", "g@x.com\\", "g@x.com'", "user:g@x.com"])
    def test_c_a_04_bad_group_values_rejected(self, world, tmp_path, bad):
        code, _ = run(tmp_path, "--apply", group=bad)
        assert code == 2 and world.ddl_log == []

    @pytest.mark.parametrize("flag", ["--principals", "--principals-file", "--tables-file", "--project"])
    def test_c_a_05_removed_flags(self, world, tmp_path, flag):
        with pytest.raises(SystemExit) as e:
            run(tmp_path, flag, "x")
        assert e.value.code == 2

    def test_c_a_06_policy_limit(self, world, tmp_path, capsys):
        world.policies(T1).extend({"id": f"pad_{i}", "filter": "TRUE", "grantees": [f"user:u{i}@d.com"]} for i in range(400))
        world.policies(T2).extend({"id": f"pad_{i}", "filter": "TRUE", "grantees": [f"user:u{i}@d.com"]} for i in range(399))
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.policy(T1, POL) is None and f"[SKIP] {T1}" in err and "400" in err
        assert world.policy(T2, POL) is not None and len(world.policies(T2)) == 400

    def test_c_a_07_policy_limit_replace_still_allowed(self, world, tmp_path):
        world.policies(T1).extend({"id": f"pad_{i}", "filter": "TRUE", "grantees": [f"user:u{i}@d.com"]} for i in range(399))
        world.policies(T1).append({"id": POL, "filter": "FALSE", "grantees": [GRANTEE]})
        code, _ = run(tmp_path, "--tables", T1, "--apply")
        assert code == 0 and world.policy(T1, POL)["filter"] == expected_filter(T1, world)

    def test_c_a_08_duplicate_sa_rows_warned(self, world, tmp_path, capsys):
        world.condition_sas[COND] = [SA_A, SA_A, U_B]
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and "[WARN]" in err and SA_A in err and "多行" in err
        assert world.policy(T1, POL) is not None                           # 不影响建规则

    @pytest.mark.parametrize("raw", [SA_A.upper(), f" {U_B}", f"{U_B} "])
    def test_c_a_09_unnormalized_sa_warned(self, world, tmp_path, capsys, raw):
        world.condition_sas[COND] = [raw, U_B.replace("bob", "carol")]
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and "[WARN]" in err and "非小写" in err and world.policy(T1, POL) is not None

    @pytest.mark.parametrize("raw", [f"serviceAccount:{SA_A}", f"user:{U_B}", "group:g@trip.com", "allUsers",
                                     "not an email", "domain:trip.com"])
    def test_c_a_10_invalid_sa_values_warned(self, world, tmp_path, capsys, raw):
        world.condition_sas[COND] = [raw, U_B]
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and "[WARN]" in err and raw.strip() in err and world.policy(T1, POL) is not None

    def test_c_a_11_ddl_failure_isolated_and_recorded(self, world, tmp_path):
        world.fail_ddl_on.add(T1)
        code, rows = run(tmp_path, "--apply")
        assert code == 1 and world.policy(T2, POL) is not None
        r = next(r for r in rows if r["table"] == T1)
        assert r["result"].startswith("ERROR")

    def test_c_a_12_condition_table_without_sa_column(self, world, tmp_path):
        world.condition_fields[COND] = [f for f in DIM3 if f[0] != "sa"]
        code, _ = run(tmp_path, "--apply")
        assert code == 1 and world.ddl_log == []

    def test_c_a_13_condition_table_without_dimensions(self, world, tmp_path):
        world.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("status", "INTEGER", "NULLABLE")]
        code, _ = run(tmp_path, "--apply")
        assert code == 1 and world.ddl_log == []

    def test_c_a_14_schema_mismatch_skips_table(self, world, tmp_path, capsys):
        del world.tables[T2]["schema"]["market"]
        code, _ = run(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.policies(T2) == [] and f"[SKIP] {T2}" in err and world.policy(T1, POL) is not None

    def test_c_a_15_mapping_injection_still_rejected(self, world, tmp_path):
        world.mapping_rows[MAP] = [{"table_name": T2, "col_name": "market) OR TRUE --", "to_name": "region"}]
        code, _ = run(tmp_path, "--apply")
        assert code == 1 and world.ddl_log == []

    def test_c_a_16_csv_formula_injection_in_note(self, world, tmp_path):
        world.policies(T1).append({"id": POL, "filter": "=cmd|' /C calc'!A0", "grantees": [GRANTEE]})
        code, rows = run(tmp_path, "--tables", T1, "--apply")
        r = rows[0]
        assert r["action"] == "REPLACE" and not r["note"].startswith("=") and "=cmd" in r["note"]

    def test_c_a_17_registry_conflict_warn(self, world, tmp_path, capsys):
        world.register(T2, 0)
        code, _ = run(tmp_path, "--apply")
        assert code == 1 and world.policies(T2) == [] and f"[WARN] {T2}" in capsys.readouterr().err
