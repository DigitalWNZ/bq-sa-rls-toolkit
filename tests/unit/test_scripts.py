"""业务脚本的单元测试：用 fakes.FakeWorld 模拟 GCP，完整跑通参数解析 → 计划 → 执行 → 输出。"""

import csv

import pytest

import apply_bypass_rls
import apply_copilot_rls
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, install

T1, T2, T3 = "p.dw.t1", "p.dw.t2", "p.ods.t3"
G_R, G_W = "group_existingsa_read@x.com", "group_existingsa_write@x.com"
BYP_R = core.bypass_policy_name(G_R)
BYP_W = core.bypass_policy_name(G_W)
COND, MAP = "auth.ds.adm_user_mem_copilot_condition", "auth.ds.adm_user_mem_copilot_tb_col_mapping"
SA_A = "copilot-sa-a@p.iam.gserviceaccount.com"
U_B = "bob@x.com"


def bypass(group):
    return {"id": core.bypass_policy_name(group), "filter": "TRUE", "grantees": [f"group:{group}"]}


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


# =========================================================================== #
# apply_bypass_rls.py
# =========================================================================== #
AUTH_COND, AUTH_MAP = "p.dw.adm_user_mem_copilot_condition", "p.dw.adm_user_mem_copilot_tb_col_mapping"
AUTH = ["--registry-table", REG]


class TestApplyBypass:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1)                                    # 无 RLS
        w.add_table(T2, policies=[bypass(G_W)])            # 已有别的 bypass
        w.add_table(T3, policies=[bypass(G_R)])            # 已有相同规则
        w.add_table(AUTH_COND, rls_enabled=0)              # 条件表 / 映射表与业务表在同一数据集，登记为未开启
        w.add_table(AUTH_MAP, rls_enabled=None)            # 未登记
        install(monkeypatch, w, apply_bypass_rls)
        return w

    @staticmethod
    def run(*args):
        return apply_bypass_rls.main([*args, *AUTH])

    def test_registry_table_required_and_old_flags_rejected(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(["--group", G_R])
        assert e.value.code == 2
        for old in (["--condition-table", AUTH_COND], ["--mapping-table", AUTH_MAP], ["--tables", T1],
                    ["--datasets", "p.dw"], ["--projects", "p"]):
            with pytest.raises(SystemExit):
                self.run("--group", G_R, *old)

    def test_unregistered_or_disabled_tables_not_processed(self, world, capsys):
        code = self.run("--group", G_R, "--apply")
        err = capsys.readouterr().err
        assert code == 0
        assert world.policies(AUTH_COND) == [] and world.policies(AUTH_MAP) == []
        assert world.policy(T1, BYP_R) is not None
        assert not any(AUTH_COND in d or AUTH_MAP in d for d in world.ddl_log)
        first_block = err[err.index("将为以下这些表首次设置RLS规则"):].split("=====")[0]
        assert AUTH_COND not in first_block and AUTH_MAP not in first_block

    def test_nonexistent_registry_table_is_error(self, world, capsys):
        code = apply_bypass_rls.main(["--group", G_R, "--registry-table", "p.dw.typo"])
        assert code == 2 and world.ddl_log == [] and "p.dw.typo" in capsys.readouterr().err

    def test_dry_run_changes_nothing(self, world, capsys):
        code = self.run("--group", G_R)
        out = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert f"[CREATE] {T1}" in out and f"[NOOP] {T3}" in out
        assert "将为以下这些表首次设置RLS规则" in out and T1 in out

    def test_first_policy_listed_but_not_blocked(self, world, capsys):
        code = self.run("--group", G_R, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T1, BYP_R) and world.policy(T2, BYP_R)
        assert f"  - {T1}" in err and f"  - {T2}" not in err          # 只有原本无 RLS 的 T1 被列出
        assert "--force-first-policy" not in err

    def test_per_group_rule_on_every_registered_table(self, world):
        code = self.run("--group", G_R, "--apply")
        assert code == 0
        for t in (T1, T2, T3):
            p = world.policy(t, BYP_R)
            assert p["filter"] == "TRUE" and p["grantees"] == [f"group:{G_R}"]
        assert world.policy(T2, BYP_W) is not None        # 别的组的规则不受影响
        assert len(world.ddl_log) == 2                     # T3 为 NOOP

    def test_replace_when_content_differs_prints_old(self, world, monkeypatch, capsys):
        world.policies(T3)[0]["filter"] = "region = 'HK'"
        code = self.run("--group", G_R, "--apply")
        err = capsys.readouterr().err
        assert code == 0 and world.policy(T3, BYP_R)["filter"] == "TRUE"
        assert f"[REPLACE] {T3}" in err and "region = 'HK'" in err
        assert "CONFLICT" not in err

    def test_group_required(self, world):
        with pytest.raises(SystemExit) as e:
            self.run()
        assert e.value.code == 2

    def test_only_one_group(self, world, capsys):
        code = self.run("--group", f"{G_R},{G_W}")
        assert code == 2 and "只能指定一个" in capsys.readouterr().err

    @pytest.mark.parametrize("flag", ["--merge", "--groups", "--skip-edition-check", "--edition-days"])
    def test_removed_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit):
            self.run("--group", G_R, flag, "x")

    def test_only_registry_decides_targets(self, world):
        code = self.run("--group", G_W, "--apply")
        assert code == 0
        for t in (T1, T2, T3):
            assert world.policy(t, BYP_W) is not None
        assert world.policies(AUTH_COND) == [] and world.policies(AUTH_MAP) == []

    def test_verify_sa_failure_exit_1(self, world):
        sa = "reader@p.iam.gserviceaccount.com"
        world.verify_result[(T3, sa)] = ("fail", "300s 内未达到可见")
        code = self.run("--group", G_R, "--apply", "--verify-sa", sa)
        assert code == 1

    def test_verify_sa_ok(self, world, capsys):
        sa = "reader@p.iam.gserviceaccount.com"
        code = self.run("--group", G_R, "--apply", "--verify-sa", sa)
        assert code == 0 and "[VERIFY-OK]" in capsys.readouterr().err

    def test_ddl_failure_exit_1(self, world):
        world.fail_ddl_on.add(T1)
        code = self.run("--group", G_R, "--apply")
        assert code == 1 and world.policy(T2, BYP_R) is not None


# =========================================================================== #
# apply_copilot_rls.py
# =========================================================================== #
def _schema(**cols):
    return {k: (v, "NULLABLE") for k, v in cols.items()}


# =========================================================================== #
# rollback_rls.py
# =========================================================================== #
COP_A = {"id": core.copilot_policy_name(U_B), "filter": "f", "grantees": [f"user:{U_B}"]}
COP_S = {"id": core.copilot_policy_name(SA_A), "filter": "f", "grantees": [f"serviceAccount:{SA_A}"]}


class TestRollback:
    @pytest.fixture
    def world(self, monkeypatch):
        w = FakeWorld()
        w.add_table(T1, policies=[bypass(G_R), bypass(G_W), COP_A, COP_S])
        w.add_table(T2, policies=[COP_A])
        install(monkeypatch, w, rollback_rls)
        return w

    def test_no_filter_deletes_all_rules(self, world, capsys):
        code = rollback_rls.main(["--tables", T1, "--apply"])
        assert code == 0 and world.policies(T1) == []
        assert world.ddl_log == [f"DROP ALL ROW ACCESS POLICIES ON `{T1}`"]

    def test_principal_removes_only_own_rules(self, world):
        code = rollback_rls.main(["--tables", T1, "--principals", SA_A, "--apply"])
        assert code == 0
        assert [p["id"] for p in world.policies(T1)] == [BYP_R, BYP_W, COP_A["id"]]

    def test_group_principal(self, world):
        code = rollback_rls.main(["--tables", T1, "--principals", self._file(world, G_W), "--apply"])
        assert code == 0 and world.policy(T1, BYP_W) is None and world.policy(T1, BYP_R) is not None

    def _file(self, world, *values):
        import tempfile
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8")
        f.write("\n".join(values) + "\n")
        f.close()
        return f.name

    def test_policy_names_and_intersection(self, world):
        code = rollback_rls.main(["--tables", T1, "--principals", f"{U_B},{G_R}",
                                  "--policy-names", BYP_R, "--apply"])
        assert code == 0 and [p["id"] for p in world.policies(T1)] == [BYP_W, COP_A["id"], COP_S["id"]]

    def test_drop_all_listed_but_not_blocked(self, world, capsys):
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--principals", U_B, "--apply"])
        err = capsys.readouterr().err
        assert code == 0 and world.policies(T2) == []      # 不再整批拦截
        assert "以下这些表的 RLS 规则将被全部删除（删除后所有有读表权限的账号都能看到全部数据）：" in err
        assert f"  - {T2}" in err and f"  - {T1}" not in err
        assert "--force-drop-all" not in err

    def test_emptied_table_uses_drop_all(self, world):
        code = rollback_rls.main(["--tables", f"{T1},{T2}", "--principals", U_B, "--apply"])
        assert code == 0 and world.policies(T2) == []
        assert f"DROP ALL ROW ACCESS POLICIES ON `{T2}`" in world.ddl_log
        assert world.policy(T1, COP_A["id"]) is None and len(world.policies(T1)) == 3

    @pytest.mark.parametrize("flag", ["--all-policies", "--force-drop-all"])
    def test_removed_gate_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit):
            rollback_rls.main(["--tables", T1, flag, "--apply"])
        assert world.ddl_log == []

    def test_dry_run_prints_full_content(self, world, capsys):
        code = rollback_rls.main(["--tables", T1, "--principals", SA_A])
        err = capsys.readouterr().err
        assert code == 0 and world.ddl_log == []
        assert COP_S["id"] in err and f"serviceAccount:{SA_A}" in err and "filter=f" in err
        assert f"DROP ROW ACCESS POLICY `{COP_S['id']}` ON `{T1}`" in err

    def test_verify_sa_report_only(self, world, capsys):
        world.visible[(T1, SA_A)] = (0, 10)
        code = rollback_rls.main(["--tables", T1, "--principals", SA_A, "--apply", "--verify-sa", SA_A])
        err = capsys.readouterr().err
        assert code == 0 and "可见 0 行 / 表共 10 行" in err

    def test_scope_datasets(self, world):
        code = rollback_rls.main(["--datasets", "p.dw", "--principals", SA_A, "--apply"])
        assert code == 0 and world.policy(T1, COP_S["id"]) is None

    def test_failure_exit_1(self, world):
        world.fail_ddl_on.add(T1)
        assert rollback_rls.main(["--tables", T1, "--principals", SA_A, "--apply"]) == 1

    @pytest.mark.parametrize("flag", ["--groups", "--strip-only", "--revoke-table-viewer", "--delete-group",
                                      "--backup-dir", "--verify-principals"])
    def test_removed_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit):
            rollback_rls.main(["--tables", T1, "--principals", SA_A, flag, "x"])


# =========================================================================== #
# list_principals.py
# =========================================================================== #
ORG = "organizations/123"


def cai_sa(email, disabled=False, name=""):
    return {"name": f"//iam.googleapis.com/projects/p/serviceAccounts/{email}", "displayName": name,
            "state": "DISABLED" if disabled else "ACTIVE", "additionalAttributes": {"email": email}}


def cai_iam(resource, members, role="roles/viewer"):
    return {"resource": resource, "policy": {"bindings": [{"role": role, "members": members}]}}


