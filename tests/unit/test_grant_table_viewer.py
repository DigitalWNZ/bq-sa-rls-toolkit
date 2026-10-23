"""grant_table_viewer.py（2026-10-23）：给多个 Group 统一授予多张表的表级 BigQuery Data Viewer。"""

import pytest

import gcp_ops as ops
import grant_table_viewer as gtv
import rls_core as core
from tests.unit.fakes import FakeWorld, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.orders", f"{P}.dw.booking", f"{P}.ods.events"
G1, G2 = "group_high@trip.com", "group_low@trip.com"
VIEWER = core.VIEWER_ROLE


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in (T1, T2, T3):
        w.add_table(t, rls_enabled=None)
    install(monkeypatch, w, gtv)
    monkeypatch.setattr(ops.time, "sleep", lambda s: None)
    return w


def run(*args):
    return gtv.main(list(args))


def members(world, t, role=VIEWER):
    return sorted(m for b in world.table_iam.get(t, []) if b["role"] == role and not b.get("condition")
                  for m in b["members"])


# =========================================================================== #
# rls_core
# =========================================================================== #
class TestCore:
    def test_parse_groups(self):
        assert core.parse_groups([f"{G1.upper()}", G2, G1]) == [G1, G2]

    @pytest.mark.parametrize("bad", [f"group:{G1}", "etl@p.iam.gserviceaccount.com", "not-an-email", 'a"b@x.com'])
    def test_parse_groups_rejects(self, bad):
        with pytest.raises(ValueError, match="--groups"):
            core.parse_groups([G1, bad])

    def test_parse_groups_empty(self):
        with pytest.raises(ValueError, match="至少需要一个"):
            core.parse_groups([])

    def test_plan_ignores_conditional_and_other_roles(self):
        pol = {"bindings": [{"role": VIEWER, "members": [f"group:{G1.upper()}"]},
                            {"role": VIEWER, "members": [f"group:{G2}"], "condition": {"expression": "x"}},
                            {"role": "roles/bigquery.dataEditor", "members": [f"group:{G2}"]}]}
        assert core.plan_table_viewer(pol, [G1, G2]) == ([G2], [G1])
        assert core.plan_table_viewer({}, [G1]) == ([G1], [])

    def test_add_members_keeps_everything_else(self):
        cond = {"role": VIEWER, "members": ["user:c@x.com"], "condition": {"expression": "x", "title": "t"}}
        pol = {"etag": "e1", "version": 1, "bindings": [cond, {"role": "roles/owner", "members": ["user:o@x.com"]}]}
        new = core.add_viewer_members(pol, [G1])
        assert new["etag"] == "e1" and new["version"] == 1                     # 表级 IAM 只支持 v1：不改 version
        assert cond in new["bindings"] and {"role": "roles/owner", "members": ["user:o@x.com"]} in new["bindings"]
        assert {"role": VIEWER, "members": [f"group:{G1}"]} in new["bindings"]
        assert pol["bindings"] == [cond, {"role": "roles/owner", "members": ["user:o@x.com"]}]   # 原对象不变

    def test_add_members_appends_to_existing_binding(self):
        pol = {"bindings": [{"role": VIEWER, "members": ["user:a@x.com"]}]}
        new = core.add_viewer_members(pol, [G1, G2])
        assert new["bindings"] == [{"role": VIEWER, "members": ["user:a@x.com", f"group:{G1}", f"group:{G2}"]}]


# =========================================================================== #
# 参数
# =========================================================================== #
class TestArgs:
    def test_groups_required(self, world):
        with pytest.raises(SystemExit) as e:
            run("--tables", T1)
        assert e.value.code == 2

    @pytest.mark.parametrize("bad", [f"group:{G1}", "etl@p.iam.gserviceaccount.com", "x"])
    def test_bad_group_exit_2_no_api(self, world, capsys, bad):
        assert run("--groups", G1, bad, "--tables", T1, "--apply") == 2
        assert "--groups" in capsys.readouterr().err and world.calls.get("table_iam", 0) == 0

    def test_empty_groups(self, world, capsys):
        assert run("--groups", "--tables", T1) == 2
        assert "至少需要一个 Group" in capsys.readouterr().err

    def test_scope_required(self, world, capsys):
        assert run("--groups", G1) == 2
        assert "--tables / --datasets / --projects" in capsys.readouterr().err

    def test_csv_and_dedupe(self, world, tmp_path):
        g = tmp_path / "groups.csv"
        g.write_text(f"\ufeff{G1}\r\n{G2}\r\n\r\n", encoding="utf-8")
        t = tmp_path / "tables.csv"
        t.write_text(f"{T1}\n`{T2}`\n", encoding="utf-8")
        assert run("--groups", str(g), G1.upper(), "--tables", str(t), "--apply") == 0
        assert members(world, T1) == members(world, T2) == sorted([f"group:{G1}", f"group:{G2}"])
        assert world.table_iam.get(T3) is None

    def test_missing_csv_file(self, world, capsys):
        assert run("--groups", "nope.csv", "--tables", T1) == 2

    def test_bad_table_name(self, world, capsys):
        assert run("--groups", G1, "--tables", "p:d.t") == 2


# =========================================================================== #
# 执行
# =========================================================================== #
class TestGrant:
    def test_dry_run_no_write(self, world, capsys):
        assert run("--groups", G1, G2, "--tables", T1, T2) == 0
        err = capsys.readouterr().err
        assert world.iam_set_log == [] and err.count("[GRANT]") == 2
        assert f"[GRANT] {T1}: 新增 ['group:{G1}', 'group:{G2}']" in err
        assert "[SCAN] 共 2 张表" in err and "===== 完成 (DRY-RUN)：GRANT 2 =====" in err

    def test_apply_then_rerun_noop(self, world, capsys):
        assert run("--groups", G1, G2, "--tables", T1, T2, T3, "--apply") == 0
        assert all(members(world, t) == [f"group:{G1}", f"group:{G2}"] for t in (T1, T2, T3))
        assert len(world.iam_set_log) == 3
        capsys.readouterr()
        assert run("--groups", G2, G1, "--tables", T1, T2, T3, "--apply") == 0
        err = capsys.readouterr().err
        assert len(world.iam_set_log) == 3 and err.count("[NOOP]") == 3 and "NOOP 3" in err

    def test_only_missing_groups_added_and_others_kept(self, world, capsys):
        cond = {"role": VIEWER, "members": [f"group:{G2}"], "condition": {"expression": "request.time < x", "title": "t"}}
        world.table_iam[T1] = [{"role": VIEWER, "members": [f"group:{G1}", "user:a@trip.com"]}, cond,
                               {"role": "roles/bigquery.dataEditor", "members": ["user:w@trip.com"]}]
        assert run("--groups", G1, G2, "--tables", T1, "--apply") == 0
        err = capsys.readouterr().err
        assert f"[GRANT] {T1}: 新增 ['group:{G2}']；已有 ['group:{G1}']" in err
        assert members(world, T1) == sorted([f"group:{G1}", f"group:{G2}", "user:a@trip.com"])
        assert cond in world.table_iam[T1]                                       # 带条件的授权保留
        assert members(world, T1, "roles/bigquery.dataEditor") == ["user:w@trip.com"]
        assert world.iam_set_log[-1][1].get("version", 1) == 1

    def test_datasets_and_projects_expand(self, world):
        assert run("--groups", G1, "--datasets", f"{P}.dw", "--apply") == 0
        assert members(world, T1) == members(world, T2) == [f"group:{G1}"] and world.table_iam.get(T3) is None
        assert run("--groups", G1, "--projects", P, "--apply") == 0
        assert members(world, T3) == [f"group:{G1}"]

    def test_missing_table_skipped(self, world, capsys):
        assert run("--groups", G1, "--tables", T1, f"{P}.dw.gone", "--apply") == 1
        err = capsys.readouterr().err
        assert f"[SKIP] {P}.dw.gone: 表不存在（可能已被删除）" in err and members(world, T1) == [f"group:{G1}"]
        assert "GRANT 1，SKIP 1" in err

    def test_read_failure_error_others_continue(self, world, capsys):
        world.fail_resources.add(f"table_iam:{T2}")
        assert run("--groups", G1, "--tables", T1, T2, T3, "--apply") == 1
        err = capsys.readouterr().err
        assert f"[ERROR] {T2}: 读取 IAM 策略失败" in err and members(world, T3) == [f"group:{G1}"]

    def test_write_failure_error_others_continue(self, world, capsys):
        world.fail_iam_set.add(T2)
        assert run("--groups", G1, "--tables", T1, T2, T3, "--apply") == 1
        err = capsys.readouterr().err
        assert "boom setIamPolicy" in err and members(world, T1) == members(world, T3) == [f"group:{G1}"]
        assert "ERROR 1" in err

    def test_concurrent_change_retried(self, world, capsys):
        world.iam_conflicts[T1] = 2
        assert run("--groups", G1, "--tables", T1, "--apply") == 0
        assert members(world, T1) == [f"group:{G1}"]
        assert capsys.readouterr().err.count("被并发修改，重新读取后重试") == 2

    def test_concurrent_change_gives_up(self, world, capsys):
        world.iam_conflicts[T1] = 10
        assert run("--groups", G1, "--tables", T1, "--apply") == 1
        assert "etag" in capsys.readouterr().err

    def test_missing_group_stops_at_first_table(self, world, capsys):
        world.missing_groups.add(G2)
        assert run("--groups", G1, G2, "--tables", T1, T2, T3, "--apply") == 2
        err = capsys.readouterr().err
        assert "BigQuery 报 --groups 中有 Group 不存在（是哪个见上方 [ERROR]），已停止" in err
        assert "未做任何变更" in err and "检查 --groups 是否拼错" in err
        assert world.iam_set_log == [] and all(world.table_iam.get(t) is None for t in (T1, T2, T3))

    def test_noop_tables_do_not_trigger_first_table_check(self, world, capsys):
        world.table_iam[T1] = [{"role": VIEWER, "members": [f"group:{G1}"]}]
        assert run("--groups", G1, "--tables", T1, T2, "--apply") == 0
        err = capsys.readouterr().err
        assert f"[NOOP] {T1}" in err and f"[GRANT] {T2}" in err

    def test_log_file_written(self, world, tmp_path, capsys):
        assert run("--groups", G1, "--tables", T1, "--log-dir", str(tmp_path)) == 0
        err = capsys.readouterr().err
        files = list(tmp_path.glob("grant_table_viewer_*.log"))
        assert len(files) == 1 and files[0].read_text(encoding="utf-8") == err


class TestConflictDetection:
    def test_only_409_or_concurrent_text(self):
        from tests.unit.fakes import http_error
        assert ops.is_policy_conflict_error(http_error(409, "x"))
        assert not ops.is_policy_conflict_error(http_error(400, "Unsupported policy version 3 ... etag ... concurrent"))
        assert ops.is_policy_conflict_error(RuntimeError("There were concurrent policy changes"))
        assert not ops.is_policy_conflict_error(RuntimeError("Group x does not exist"))


def test_brief_error_strips_http_details():
    from tests.unit.fakes import http_error
    e = http_error(400, "x")
    e.reason = "IAM setPolicy failed for Table p:d.t: Group g@x.com does not exist."
    assert ops.brief_error(e) == "HTTP 400: IAM setPolicy failed for Table p:d.t: Group g@x.com does not exist."
    assert ops.brief_error(RuntimeError("a" * 900)) == "a" * 500
