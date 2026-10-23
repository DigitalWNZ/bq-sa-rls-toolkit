"""
正常系（通常操作）测试：按 Doc 流程覆盖 4 个脚本的常规用法，用 FakeWorld 模拟 GCP。
每个用例对应设计记录（script_redesign_decisions）里的一条决定。
"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, install, fake_auth

P = "prod-proj"
T1, T2, T3, T4 = f"{P}.dw.fact_orders", f"{P}.dw.fact_booking", f"{P}.ods.raw_events", f"{P}.dw.dim_user"
COND, MAP = f"{P}.auth.adm_user_mem_copilot_condition", f"{P}.auth.adm_user_mem_copilot_tb_col_mapping"
G_COP = "group_copilot@domain.com"
COP_G = core.copilot_policy_name(G_COP)
AUTH = ["--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG, "--group", G_COP]   # apply_copilot_rls.py
BYP_ARGS = ["--registry-table", REG]                                 # apply_bypass_rls.py
G_R, G_W = "group_existingsa_read@domain.com", "group_existingsa_write@domain.com"
BYP_R, BYP_W = core.bypass_policy_name(G_R), core.bypass_policy_name(G_W)
SA_A, SA_B = "copilot-sa-a@prod-proj.iam.gserviceaccount.com", "copilot-sa-b@prod-proj.iam.gserviceaccount.com"
U_C = "carol@domain.com"
READER_SA = "reader@prod-proj.iam.gserviceaccount.com"


def bypass_rule(group):
    return {"id": core.bypass_policy_name(group), "filter": "TRUE", "grantees": [f"group:{group}"]}


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_list(tmp_path, name, values, newline="\n"):
    f = tmp_path / name
    f.write_text(newline.join(values) + newline, encoding="utf-8")
    return str(f)


def schema(**cols):
    return {k: (v, "NULLABLE") for k, v in cols.items()}


# =========================================================================== #
# 第 1 步 list_principals.py
# =========================================================================== #
def cai_sa(email, disabled=False, name=""):
    return {"name": f"//iam.googleapis.com/projects/{P}/serviceAccounts/{email}", "displayName": name,
            "state": "DISABLED" if disabled else "ENABLED", "additionalAttributes": {"email": email}}


def cai_iam(resource, members, role="roles/viewer"):
    return {"resource": resource, "policy": {"bindings": [{"role": role, "members": members}]}}


# =========================================================================== #
# 第 3 步 apply_bypass_rls.py
# =========================================================================== #
class TestApplyBypassNormal:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        for t in (T1, T2, T3, T4):
            w.add_table(t)                                   # 登记表中 rls_enabled = 1
        w.add_table(COND, rls_enabled=0)
        w.add_table(MAP, rls_enabled=0)
        install(monkeypatch, w, apply_bypass_rls)
        return w

    @staticmethod
    def run(*args):
        return apply_bypass_rls.main([*args, *BYP_ARGS])

    def test_n_bp_01_dry_run_shows_plan_and_changes_nothing(self, world, capsys):
        world.policies(T2).append(bypass_rule(G_R))
        world.policies(T3).append({**bypass_rule(G_R), "filter": "region = 'HK'"})
        code = self.run("--group", G_R)
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert f"[CREATE] {T1}" in err and f"[NOOP] {T2}" in err and f"[REPLACE] {T3}" in err
        assert "DRY-RUN" in err and "CREATE 2，NOOP 1，REPLACE 1" in err        # T1、T4 新建

    def test_n_bp_02_apply_creates_exact_ddl(self, world):
        code = self.run("--group", G_R, "--apply")
        assert code == 0
        assert f"CREATE OR REPLACE ROW ACCESS POLICY `{BYP_R}`\nON `{T1}`\nGRANT TO (\"group:{G_R}\")\nFILTER USING (TRUE)" \
            in world.ddl_log
        assert len(world.ddl_log) == 4                                   # 登记表中开启的 4 张表各一次
        assert world.policy(T1, BYP_R) == {"id": BYP_R, "filter": "TRUE", "grantees": [f"group:{G_R}"]}

    def test_n_bp_03_rerun_is_noop(self, world, capsys):
        self.run("--group", G_R, "--apply")
        n = len(world.ddl_log)
        code = self.run("--group", G_R, "--apply")
        assert code == 0 and len(world.ddl_log) == n and "[NOOP]" in capsys.readouterr().err

    def test_n_bp_04_second_group_gets_own_rule(self, world):
        self.run("--group", G_R, "--apply")
        code = self.run("--group", G_W, "--apply")        # 已非首条，无需 force
        assert code == 0
        assert {p["id"] for p in world.policies(T1)} == {BYP_R, BYP_W}
        assert world.policy(T1, BYP_W)["grantees"] == [f"group:{G_W}"]

    @pytest.mark.parametrize("change", [{"filter": "region = 'HK'"}, {"grantees": ["group:other@domain.com"]},
                                        {"grantees": [f"group:{G_R}", "user:x@domain.com"]}])
    def test_n_bp_05_replace_restores_rule(self, world, capsys, change):
        world.policies(T1).append({**bypass_rule(G_R), **change})
        code = self.run("--group", G_R, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and f"[REPLACE] {T1}" in err and "被覆盖的旧内容" in err
        assert world.policy(T1, BYP_R) == bypass_rule(G_R)

    def test_n_bp_06_targets_come_from_registry_only(self, world):
        world.register(T1, 1)                                # 登记表里重复登记：只执行一次
        code = self.run("--group", G_R, "--apply")
        assert code == 0
        assert len(world.ddl_log) == 4                       # 4 张业务表各一次
        assert all(world.policy(t, BYP_R) for t in (T1, T2, T3, T4))
        assert world.policies(COND) == [] and world.policies(MAP) == []

    def test_n_bp_07_verify_outcomes(self, world, capsys):
        world.verify_result[(T1, READER_SA)] = ("ok", "可见数据（2s）")
        world.verify_result[(T2, READER_SA)] = ("skip", "表元数据行数为 0")
        code = self.run("--group", G_R, "--apply", "--verify-sa", READER_SA)
        err = capsys.readouterr().err
        assert code == 0 and f"[VERIFY-OK] {T1}" in err and f"[VERIFY-SKIP] {T2}" in err

    def test_n_bp_08_group_email_normalized(self, world):
        code = self.run("--group", "Group_ExistingSA_Read@Domain.COM", "--apply")
        assert code == 0 and world.policy(T1, BYP_R)["grantees"] == [f"group:{G_R}"]

    @pytest.mark.parametrize("parallel", ["1", "3", "32"])
    def test_n_bp_09_parallel_levels_same_outcome(self, world, parallel):
        code = self.run("--group", G_R, "--apply",
                        "--parallel", parallel)
        assert code == 0 and sorted(world.ddl_log) == sorted(
            core.build_policy_ddl(t, BYP_R, [f"group:{G_R}"], "TRUE") for t in (T1, T2, T3, T4))

    def test_n_bp_10_first_policy_list_sorted_and_only_fresh_tables(self, world, capsys):
        world.policies(T1).append(bypass_rule(G_W))
        code = self.run("--group", G_R)
        err = capsys.readouterr().err
        block = err[err.index("将为以下这些表首次设置RLS规则"):]
        block = block[:block.index("[CREATE]")]
        assert code == 0 and block.index(T4) < block.index(T2) and T1 not in block    # 按表名排序：dim_user < fact_booking
        assert "如确认" not in err                                                     # 只提示，不要求确认


# =========================================================================== #
# 第 7 步 apply_copilot_rls.py
# =========================================================================== #
# =========================================================================== #
# 第 8 步 rollback_rls.py
# =========================================================================== #
def cop_rule(email):
    """一条只授权给单个账号的规则（回退测试用；如手工建的规则或旧版按账号的 Copilot 规则）。"""
    member = f"serviceAccount:{email}" if email.endswith("gserviceaccount.com") else f"user:{email}"
    return {"id": core.copilot_policy_name(email), "filter": "f", "grantees": [member]}


class TestRollbackNormal:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1, policies=[bypass_rule(G_R), bypass_rule(G_W), cop_rule(SA_A), cop_rule(U_C)])
        w.add_table(T2, policies=[bypass_rule(G_R), cop_rule(SA_A)])
        w.add_table(T3, policies=[cop_rule(U_C)])
        w.add_table(T4)                                                       # 无规则
        install(monkeypatch, w, rollback_rls)
        return w

    @pytest.mark.parametrize("principal,removed", [(SA_A, {T1: 3, T2: 1}), (U_C, {T1: 3, T3: 0}), (G_W, {T1: 3})])
    def test_n_rb_01_each_principal_type_removes_only_own(self, world, principal, removed):
        code = rollback_rls.main(["--projects", P, "--principals", principal, "--apply"])   # 删空某表也不拦
        assert code == 0
        for t, n in removed.items():
            assert len(world.policies(t)) == n
            assert not any(core.member_email(g) == principal for x in world.policies(t) for g in x["grantees"])

    def test_n_rb_02_multiple_principals_and_file(self, world, tmp_path):
        pf = write_list(tmp_path, "p.csv", [SA_A])
        code = rollback_rls.main(["--tables", T1, "--principals", G_W, "--principals", pf, "--apply"])
        assert code == 0 and {x["id"] for x in world.policies(T1)} == {BYP_R, cop_rule(U_C)["id"]}

    def test_n_rb_03_policy_names(self, world, tmp_path):
        nf = write_list(tmp_path, "n.csv", [BYP_W])
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--policy-names", BYP_R, "--policy-names", nf, "--apply"])
        assert code == 0
        assert {x["id"] for x in world.policies(T1)} == {cop_rule(SA_A)["id"], cop_rule(U_C)["id"]}
        assert {x["id"] for x in world.policies(T2)} == {cop_rule(SA_A)["id"]}

    def test_n_rb_04_intersection(self, world):
        code = rollback_rls.main(["--tables", T1, "--principals", f"{G_R},{SA_A}", "--policy-names", BYP_R, "--apply"])
        assert code == 0 and {x["id"] for x in world.policies(T1)} == {BYP_W, cop_rule(SA_A)["id"], cop_rule(U_C)["id"]}

    def test_n_rb_05_no_filter_deletes_all(self, world, capsys):
        code = rollback_rls.main(["--datasets", f"{P}.dw", "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T1) == [] and world.policies(T2) == [] and world.policies(T4) == []
        assert err.count("DROP ALL ROW ACCESS POLICIES") == 2 and "2 张表，共 6 条规则" in err

    def test_n_rb_06_partial_uses_single_drops(self, world):
        code = rollback_rls.main(["--tables", T1, "--principals", SA_A, "--apply"])
        assert code == 0 and world.ddl_log == [f"DROP ROW ACCESS POLICY `{cop_rule(SA_A)['id']}` ON `{T1}`"]

    def test_n_rb_07_dry_run_prints_everything(self, world, capsys):
        code = rollback_rls.main(["--projects", P, "--principals", SA_A])
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert f"[TABLE] {T1}（共 4 条规则，删除 1 条）" in err and f"[TABLE] {T2}（共 2 条规则，删除 1 条）" in err
        assert f"[DROP] `{cop_rule(SA_A)['id']}` grantees=['serviceAccount:{SA_A}'] filter=f" in err
        assert "DRY-RUN" in err and T3 not in err and T4 not in err

    def test_n_rb_08_verify_sa_reports_only(self, world, capsys):
        world.visible[(T1, SA_A)] = (0, 10)
        world.visible[(T2, SA_A)] = (10, 10)
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--principals", SA_A, "--apply", "--verify-sa", SA_A])
        err = capsys.readouterr().err
        assert code == 0 and f"[VISIBLE] {T1}: {SA_A} 可见 0 行 / 表共 10 行" in err and "可见 10 行 / 表共 10 行" in err

    def test_n_rb_09_scope_files(self, world, tmp_path):
        tf = write_list(tmp_path, "t.csv", [T1])
        df = write_list(tmp_path, "d.csv", [f"{P}.ods"])
        code = rollback_rls.main(["--tables", tf, "--datasets", df, "--principals", U_C, "--apply"])
        assert code == 0 and world.policy(T1, cop_rule(U_C)["id"]) is None and world.policies(T3) == []



    @pytest.mark.parametrize("parallel", ["1", "16"])
    def test_n_rb_10_parallel_same_outcome(self, world, parallel):
        code = rollback_rls.main(["--projects", P, "--principals", SA_A, "--apply", "--parallel", parallel])
        assert code == 0 and sorted(world.ddl_log) == sorted(
            [f"DROP ROW ACCESS POLICY `{cop_rule(SA_A)['id']}` ON `{T1}`", f"DROP ROW ACCESS POLICY `{cop_rule(SA_A)['id']}` ON `{T2}`"])


# =========================================================================== #
# 端到端：按 Doc 顺序 1 → 3 → 7 → 8
# =========================================================================== #
class TestEndToEndFlow:
    def test_full_flow(self, monkeypatch, tmp_path):
        w = FakeWorld()
        for t in (T1, T2):
            w.add_table(t, schema=schema(region="STRING"))
        w.add_table(COND, rls_enabled=0)
        w.add_table(MAP, rls_enabled=0)
        w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
        w.condition_sas[COND] = [SA_A, U_C]
        w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in (T1, T2)]
        w.project_sas[P] = [READER_SA]
        install(monkeypatch, w)
        for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
            monkeypatch.setattr(mod, "resolve_auth", fake_auth)

        assert list_principals.main(["--projects", P, "-o", str(tmp_path / "p.csv")]) == 0            # 第 1 步
        assert apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"]) == 0          # 第 7 步先于第 3 步：不再拦截
        assert {x["id"] for x in w.policies(T1)} == {COP_G}                                         # 每表一条 Group 规则
        assert apply_bypass_rls.main(["--group", G_R, *BYP_ARGS, "--apply"]) == 0   # 第 3 步补 bypass
        assert apply_bypass_rls.main(["--group", G_W, *BYP_ARGS, "--apply"]) == 0
        assert apply_copilot_rls.main([*AUTH, "-o", str(tmp_path / "c.csv"), "--apply"]) == 0          # 重跑：NOOP
        assert {x["id"] for x in w.policies(T1)} == {BYP_R, BYP_W, COP_G}
        assert rollback_rls.main(["--datasets", f"{P}.dw", "--principals", G_COP, "--apply"]) == 0         # 第 8 步：撤 Copilot Group 规则
        assert COP_G not in {x["id"] for x in w.policies(T1)} and BYP_R in {x["id"] for x in w.policies(T1)}
        assert rollback_rls.main(["--datasets", f"{P}.dw", "--apply"]) == 0                               # 不给筛选 = 全部删除
        assert w.policies(T1) == [] and w.policies(T2) == [] and w.policies(COND) == []
