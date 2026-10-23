"""
apply_bypass_rls --principals / --policy-name（2026-10-23）：多个 user / group / SA 共用一条 FILTER TRUE 规则；
rollback_rls --principals 只从规则里去掉这些主体（去光了才删除整条）。
"""

import pytest

import apply_bypass_rls
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.fact_orders", f"{P}.dw.fact_booking", f"{P}.ods.raw_events"
G_R, G_W = "group_existingsa_read@domain.com", "group_existingsa_write@domain.com"
SA = "etl@trip-prod.iam.gserviceaccount.com"
U = "analyst@domain.com"
SHARED = core.BYPASS_PREFIX + "existing_all"
PRIN = [f"group:{G_R}", f"group:{G_W}", f"serviceAccount:{SA}", f"user:{U}"]
RG = ["--registry-table", REG]


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in (T1, T2, T3):
        w.add_table(t)
    install(monkeypatch, w, apply_bypass_rls)
    install(monkeypatch, w, rollback_rls)
    return w


def shared(*principals, name="existing_all", extra=()):
    return apply_bypass_rls.main(["--policy-name", name, "--principals", *principals, *RG, *extra])


def grantees(world, t, name=SHARED):
    p = world.policy(t, name)
    return sorted(p["grantees"]) if p else None


# =========================================================================== #
# rls_core：解析 / 命名 / 差异
# =========================================================================== #
class TestParsePrincipals:
    def test_three_prefixes_lowercased_order_kept(self):
        got = core.parse_bypass_principals(["group:G@Domain.com", "ServiceAccount:ETL@trip-prod.iam.gserviceaccount.com",
                                            "USER:Ana@domain.com"])
        assert got == ["group:g@domain.com", "serviceAccount:etl@trip-prod.iam.gserviceaccount.com", "user:ana@domain.com"]

    def test_dedup_case_insensitive(self):
        assert core.parse_bypass_principals([f"group:{G_R}", f"group:{G_R.upper()}"]) == [f"group:{G_R}"]

    @pytest.mark.parametrize("bad", [G_R, SA, "domain:domain.com", "allUsers", "allAuthenticatedUsers",
                                     "principalSet://x", "deleted:user:a@x.com", "group:", "group:not-an-email",
                                     'group:a"b@x.com', "group:a`b@x.com", "user:a\\b@x.com",
                                     f"serviceAccount:{U}", f"user:{SA}", f"group:{SA}"])
    def test_rejected_values(self, bad):
        with pytest.raises(ValueError) as e:
            core.parse_bypass_principals([f"group:{G_W}", bad])
        assert "--principals 中有不合格的值" in str(e.value)

    def test_all_problems_listed_at_once(self):
        with pytest.raises(ValueError) as e:
            core.parse_bypass_principals([G_R, SA, f"group:{G_W}"])
        assert G_R in str(e.value) and SA in str(e.value)

    def test_same_email_two_kinds_rejected(self):
        with pytest.raises(ValueError, match="两种类型"):
            core.parse_bypass_principals([f"user:{G_R}", f"group:{G_R}"])

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="至少需要一个"):
            core.parse_bypass_principals([])


class TestPolicyNameAndDiff:
    @pytest.mark.parametrize("ok", ["existing_all", "a", "ro_2026", "0abc"])
    def test_valid_suffix(self, ok):
        assert core.shared_bypass_policy_name(ok) == core.BYPASS_PREFIX + ok
        assert core.is_bypass_policy(core.shared_bypass_policy_name(ok))

    @pytest.mark.parametrize("bad", ["", "Existing", "a-b", "a.b", "a b", "rls`x", "中文"])
    def test_invalid_suffix(self, bad):
        with pytest.raises(ValueError, match="--policy-name"):
            core.shared_bypass_policy_name(bad)

    def test_too_long(self):
        with pytest.raises(ValueError, match="过长"):
            core.shared_bypass_policy_name("a" * (core.POLICY_NAME_MAX - len(core.BYPASS_PREFIX) + 1))
        core.shared_bypass_policy_name("a" * (core.POLICY_NAME_MAX - len(core.BYPASS_PREFIX)))

    def test_grantee_diff(self):
        added, removed = core.grantee_diff(["group:a@x.com", "user:b@x.com"], ["group:A@x.com", "user:c@x.com"])
        assert added == ["user:c@x.com"] and removed == ["user:b@x.com"]


# =========================================================================== #
# apply_bypass_rls --principals
# =========================================================================== #
class TestSharedBypassArgs:
    def test_group_and_principals_together_rejected(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(["--group", G_R, "--principals", f"group:{G_W}", "--policy-name", "x", *RG])
        assert e.value.code == 2 and world.ddl_log == [] and world.calls["list_policies"] == 0

    def test_neither_rejected(self, world):
        with pytest.raises(SystemExit) as e:
            apply_bypass_rls.main(RG)
        assert e.value.code == 2

    def test_principals_without_policy_name(self, world, capsys):
        assert apply_bypass_rls.main(["--principals", f"group:{G_R}", *RG]) == 2
        assert "必须同时给 --policy-name" in capsys.readouterr().err and world.calls["list_policies"] == 0

    def test_policy_name_with_group_rejected(self, world, capsys):
        assert apply_bypass_rls.main(["--group", G_R, "--policy-name", "x", *RG]) == 2
        assert "--policy-name 只能与 --principals 搭配" in capsys.readouterr().err

    @pytest.mark.parametrize("bad", [G_R, SA, "domain:domain.com", "allUsers"])
    def test_any_unprefixed_or_unsupported_rejects_whole_run(self, world, capsys, bad):
        assert shared(f"group:{G_W}", bad, extra=["--apply"]) == 2
        assert "不合格的值" in capsys.readouterr().err and world.ddl_log == [] and world.calls["list_policies"] == 0

    def test_empty_principals_rejected(self, world, capsys):
        assert apply_bypass_rls.main(["--policy-name", "x", "--principals", *RG]) == 2
        assert "至少需要一个主体" in capsys.readouterr().err

    def test_invalid_policy_name(self, world, capsys):
        assert shared(f"group:{G_R}", name="Bad-Name") == 2
        assert "只允许小写字母" in capsys.readouterr().err


class TestSharedBypassApply:
    def test_create_one_policy_with_all_grantees(self, world, capsys):
        code = shared(",".join(PRIN), extra=["--apply"])
        err = capsys.readouterr().err
        assert code == 0
        for t in (T1, T2, T3):
            assert grantees(world, t) == sorted(PRIN) and len(world.policies(t)) == 1
            assert world.policy(t, SHARED)["filter"].upper() == "TRUE"
        assert sorted(world.ddl_log) == sorted(core.build_policy_ddl(t, SHARED, PRIN, "TRUE") for t in (T1, T2, T3))
        assert f"[PRINCIPALS] 规则 {SHARED} 的授权对象共 4 个" in err and f"  - serviceAccount:{SA}" in err
        assert "授权对象: 4 个（共用一条规则）" in err
        assert "将为以下这些表首次设置RLS规则" in err

    def test_csv_input_and_mixed_values(self, world, tmp_path):
        f = tmp_path / "p.csv"
        f.write_text("\ufeff" + "\r\n".join(PRIN[:3]) + "\r\n\r\n", encoding="utf-8")
        assert shared(str(f), PRIN[3], extra=["--apply"]) == 0
        assert grantees(world, T1) == sorted(PRIN)

    def test_csv_with_unprefixed_line_rejected(self, world, tmp_path, capsys):
        f = tmp_path / "p.csv"
        f.write_text(f"group:{G_R}\n{U}\n", encoding="utf-8")
        assert shared(str(f), extra=["--apply"]) == 2 and world.ddl_log == []
        assert U in capsys.readouterr().err

    def test_rerun_noop_regardless_of_order(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        capsys.readouterr()
        world.ddl_log.clear()
        assert shared(*reversed(PRIN), extra=["--apply"]) == 0
        err = capsys.readouterr().err
        assert world.ddl_log == [] and err.count("[NOOP]") == 3 and "[REPLACE]" not in err

    def test_change_list_replaces_and_logs_diff(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        capsys.readouterr()
        new = [f"group:{G_R}", f"serviceAccount:{SA}", "user:new@domain.com"]
        assert shared(*new, extra=["--apply"]) == 0
        err = capsys.readouterr().err
        assert err.count("[REPLACE]") == 3
        assert "  将新增: ['user:new@domain.com']" in err
        assert f"  将移除: ['group:{G_W}', 'user:{U}']" in err
        assert grantees(world, T2) == sorted(new)

    def test_dry_run_shows_diff_without_change(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        capsys.readouterr()
        world.ddl_log.clear()
        assert shared(f"group:{G_R}") == 0
        err = capsys.readouterr().err
        assert world.ddl_log == [] and "将移除: [" in err and grantees(world, T1) == sorted(PRIN)

    def test_coexists_with_group_policy(self, world):
        assert apply_bypass_rls.main(["--group", G_R, "--apply", *RG]) == 0
        assert shared(*PRIN, extra=["--apply"]) == 0
        for t in (T1, T2, T3):
            assert {p["id"] for p in world.policies(t)} == {core.bypass_policy_name(G_R), SHARED}
        assert world.policy(T1, core.bypass_policy_name(G_R))["grantees"] == [f"group:{G_R}"]

    def test_name_collision_with_group_policy_is_replaced(self, world, capsys):
        # Q5：不检查撞名——同名就按完整名单 REPLACE
        apply_bypass_rls.main(["--group", G_R, "--apply", *RG])
        suffix = core.bypass_policy_name(G_R)[len(core.BYPASS_PREFIX):]
        capsys.readouterr()
        assert shared(f"group:{G_W}", name=suffix, extra=["--apply"]) == 0
        assert world.policy(T1, core.bypass_policy_name(G_R))["grantees"] == [f"group:{G_W}"]
        assert "[REPLACE]" in capsys.readouterr().err

    @pytest.mark.parametrize("missing", [f"user:{U}", f"serviceAccount:{SA}", f"group:{G_W}"])
    def test_missing_principal_stops_at_first_table(self, world, capsys, missing):
        if missing.startswith("group:"):
            world.missing_groups.add(G_W)
        else:
            world.missing_members.add(missing)
        code = shared(*PRIN, extra=["--apply"])
        err = capsys.readouterr().err
        assert code == 2 and "BigQuery 报 --principals 中有授权对象不存在（是哪个见上方 [ERROR]），已停止" in err
        assert "未做任何变更" in err and "检查 --principals 是否拼错" in err
        assert all(world.policies(t) == [] for t in (T1, T2, T3)) and len(world.ddl_log) == 1

    def test_verify_sa_works(self, world, capsys, monkeypatch):
        import gcp_ops as ops
        monkeypatch.setattr(ops, "verify_full_access", lambda *a, **k: ("ok", "可见数据（0s）"), raising=False)
        assert shared(*PRIN, extra=["--apply", "--verify-sa", SA]) == 0
        assert capsys.readouterr().err.count("[VERIFY-OK]") == 3

    def test_registry_rules_same_as_group(self, world, capsys):
        world.add_table(f"{P}.dw.off", rls_enabled=0)
        world.tables.pop(T3)                                             # 登记了但表不存在
        code = shared(*PRIN, extra=["--apply"])
        err = capsys.readouterr().err
        assert code == 1 and f"[SKIP] {T3}: {core.TABLE_NOT_FOUND_MSG}" in err
        assert world.policies(f"{P}.dw.off") == [] and grantees(world, T1) == sorted(PRIN)

    def test_group_mode_output_unchanged(self, world, capsys):
        assert apply_bypass_rls.main(["--group", G_R, *RG]) == 0
        err = capsys.readouterr().err
        assert f"授权对象: group:{G_R}  并行: 16" in err and "[PRINCIPALS]" not in err and "将新增" not in err


# =========================================================================== #
# rollback_rls --principals：只去掉主体
# =========================================================================== #
def rollback(*args):
    return rollback_rls.main(["--tables", ",".join((T1, T2, T3)), *args])


class TestRollbackRemove:
    def test_plan_core(self):
        pols = [{"id": "s", "filter": "TRUE", "grantees": ["group:a@x.com", "user:b@x.com"]},
                {"id": "g", "filter": "TRUE", "grantees": ["group:a@x.com"]},
                {"id": "o", "filter": "TRUE", "grantees": ["group:c@x.com"]}]
        pl = core.plan_rollback(pols, {"a@x.com"})
        assert [p["id"] for p in pl.to_drop] == ["g"]
        assert [(p["id"], rest, hit) for p, rest, hit in pl.to_remove] == [("s", ["user:b@x.com"], ["group:a@x.com"])]
        assert not pl.drop_all
        pl = core.plan_rollback(pols, {"a@x.com", "b@x.com", "c@x.com"})
        assert len(pl.to_drop) == 3 and pl.to_remove == [] and pl.drop_all
        pl = core.plan_rollback(pols, None, {"s"})                       # 只给规则名：整条删除
        assert [p["id"] for p in pl.to_drop] == ["s"] and pl.to_remove == []

    def test_remove_one_principal_keeps_others(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        capsys.readouterr()
        assert rollback("--principals", U, "--apply") == 0
        err = capsys.readouterr().err
        for t in (T1, T2, T3):
            assert grantees(world, t) == sorted(PRIN[:3])
        assert f"[REMOVE] `{SHARED}` 去掉: ['user:{U}']" in err and "保留: [" in err
        assert "从 3 条规则中去掉主体" in err and "将被全部删除" not in err
        assert "CREATE OR REPLACE ROW ACCESS POLICY" in err

    def test_remove_all_principals_drops_policy(self, world, capsys):
        shared(f"group:{G_R}", f"user:{U}", extra=["--apply"])
        apply_bypass_rls.main(["--group", G_W, "--apply", *RG])
        capsys.readouterr()
        assert rollback("--principals", f"{G_R},{U}", "--apply") == 0
        err = capsys.readouterr().err
        assert all(world.policy(t, SHARED) is None for t in (T1, T2, T3)) and "[DROP]" in err and "[REMOVE]" not in err
        assert all(world.policy(t, core.bypass_policy_name(G_W)) for t in (T1, T2, T3))

    def test_single_grantee_policy_still_dropped(self, world, capsys):
        apply_bypass_rls.main(["--group", G_R, "--apply", *RG])
        apply_bypass_rls.main(["--group", G_W, "--apply", *RG])
        assert rollback("--principals", G_R, "--apply") == 0
        assert all({p["id"] for p in world.policies(t)} == {core.bypass_policy_name(G_W)} for t in (T1, T2, T3))
        assert "[REMOVE]" not in capsys.readouterr().err

    def test_names_and_principals_intersection_removes_only(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        shared(*PRIN, name="other", extra=["--apply"])
        capsys.readouterr()
        assert rollback("--principals", SA, "--policy-names", SHARED, "--apply") == 0
        assert grantees(world, T1) == sorted(set(PRIN) - {f"serviceAccount:{SA}"})
        assert grantees(world, T1, core.BYPASS_PREFIX + "other") == sorted(PRIN)

    def test_names_only_drops_whole_shared_policy(self, world):
        shared(*PRIN, extra=["--apply"])
        apply_bypass_rls.main(["--group", G_W, "--apply", *RG])
        assert rollback("--policy-names", SHARED, "--apply") == 0
        assert all(world.policy(t, SHARED) is None for t in (T1, T2, T3))

    def test_dry_run_no_change(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        world.ddl_log.clear()
        assert rollback("--principals", U) == 0
        assert world.ddl_log == [] and grantees(world, T1) == sorted(PRIN)
        assert "[REMOVE]" in capsys.readouterr().err

    def test_remove_keeps_original_filter(self, world):
        f = "region = 'HK'"
        world.policies(T1).append({"id": "manual_multi", "filter": f, "grantees": [f"user:{U}", f"group:{G_R}"]})
        assert rollback_rls.main(["--tables", T1, "--principals", U, "--apply"]) == 0
        pol = world.policy(T1, "manual_multi")
        assert pol["grantees"] == [f"group:{G_R}"] and pol["filter"] == f

    def test_unrebuildable_remaining_grantee_is_error_and_untouched(self, world, capsys):
        world.policies(T1).append({"id": "fed", "filter": "TRUE",
                                   "grantees": [f"user:{U}", "principalSet://iam.googleapis.com/x"]})
        world.policies(T1).append({"id": "other", "filter": "TRUE", "grantees": [f"user:{U}"]})
        code = rollback_rls.main(["--tables", T1, "--principals", U, "--apply"])
        err = capsys.readouterr().err
        assert code == 1 and "无法写进 GRANT TO" in err and "principalSet://" in err
        assert world.policy(T1, "fed")["grantees"] == [f"user:{U}", "principalSet://iam.googleapis.com/x"]
        assert world.policy(T1, "other") is None                         # 同表其它规则照常处理

    def test_remove_ddl_failure_reported(self, world, capsys):
        shared(*PRIN, extra=["--apply"])
        world.fail_ddl_on.add(T2)
        code = rollback("--principals", U, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and f"[ERROR] {T2}: 第 1 / 1 条 DDL 执行失败" in err
        assert grantees(world, T1) == sorted(PRIN[:3]) and grantees(world, T2) == sorted(PRIN)
