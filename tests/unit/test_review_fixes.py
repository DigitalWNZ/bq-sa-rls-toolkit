"""
独立审查报告（rls_review_report_v1.0）中已批准修改项的单元测试：
  F-03 list_principals 展开 Group 失败不再静默（gcp_ops 用 HttpMockSequence 模拟真实响应形状）
  F-06 BigQuery 报 Group 不存在：不重试、先单独执行第一张表、立即停止
  F-09 rollback 中途失败仍输出已删规则的完整内容
  F-10 apply_bypass 检查 --group 格式
  F-11 映射表列名不区分大小写
"""

import json

import pytest
from googleapiclient import discovery
from googleapiclient.http import HttpMockSequence

import apply_bypass_rls
import apply_copilot_rls
import gcp_ops as ops
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

P = "trip-prod"
T1, T2, T3 = f"{P}.dw.a_orders", f"{P}.dw.b_booking", f"{P}.dw.c_events"
COND = f"{P}.auth.adm_user_mem_copilot_condition"
MAP = f"{P}.auth.adm_user_mem_copilot_tb_col_mapping"
G_COP, G_R = "group_copilot@trip.com", "group_read@trip.com"
COP = core.copilot_policy_name(G_COP)
BYP = core.bypass_policy_name(G_R)
MISSING_MSG = ("400 Failed to create row access policy: IAM setPolicy failed for RowAccessPolicy x on table "
               "trip-prod:dw.a_orders: Group nosuch@trip.com does not exist.")


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in (T1, T2, T3):
        w.add_table(t, schema={"region": ("STRING", "NULLABLE"), "Prd_Type": ("STRING", "NULLABLE"),
                               "meta": ("RECORD", "NULLABLE"), "meta.Ref": ("STRING", "NULLABLE")})
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"),
                                ("region", "STRING", "REPEATED"), ("prdtype", "STRING", "REPEATED")]
    w.condition_sas[COND] = ["copilot-a@trip-prod.iam.gserviceaccount.com"]
    w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in (T1, T2, T3)]
    install(monkeypatch, w)
    for mod in (apply_bypass_rls, apply_copilot_rls, rollback_rls):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def copilot(tmp_path, *args, group=G_COP):
    return apply_copilot_rls.main(["--group", group, "--condition-table", COND, "--mapping-table", MAP,
                                   "--registry-table", REG, "-o", str(tmp_path / "c.csv"), *args])


def bypass(*args, group=G_R):
    return apply_bypass_rls.main(["--group", group, "--tables", f"{T1},{T2},{T3}", "--registry-table", REG, *args])


# =========================================================================== #
# F-06：Group 不存在 → 不重试，立即停止
# =========================================================================== #
class TestGroupMissing:
    def test_regex_matches_real_bigquery_message(self):
        assert ops.is_principal_missing_error(RuntimeError(MISSING_MSG))
        assert ops.is_principal_missing_error(RuntimeError("Group nosuch@\n trip.com does not exist."))   # 换行折断
        assert not ops.is_principal_missing_error(RuntimeError("Not found: Table trip-prod:dw.x was not found"))
        assert not ops.is_principal_missing_error(RuntimeError("Dataset trip-prod:dw does not exist"))

    @staticmethod
    def _ctx(errors, calls, sleeps, monkeypatch):
        monkeypatch.setattr(ops.time, "sleep", lambda s: sleeps.append(s))

        class _Job:
            def result(self):
                calls.append(1)
                if errors:
                    raise RuntimeError(errors.pop(0))
                return []

        class _BQ:
            def query(self, *a, **k):
                return _Job()

        class _Ctx:
            bq = _BQ()
        return _Ctx()

    def test_run_ddl_no_retry_when_disabled(self, monkeypatch):
        calls, sleeps = [], []
        ctx = self._ctx([MISSING_MSG] * 50, calls, sleeps, monkeypatch)
        with pytest.raises(RuntimeError, match="does not exist"):
            ops.run_ddl(ctx, "CREATE ...", "US", retry_missing_principal=False)
        assert calls == [1] and sleeps == []                              # 只执行一次，没有任何等待

    def test_run_ddl_still_retries_rate_limit_when_disabled(self, monkeypatch):
        calls, sleeps = [], []
        ctx = self._ctx(["403 Exceeded rate limits: too many table update operations"], calls, sleeps, monkeypatch)
        ops.run_ddl(ctx, "CREATE ...", "US", retry_missing_principal=False)
        assert len(calls) == 2 and sleeps == [2.0]

    def test_run_ddl_default_keeps_propagation_retry(self, monkeypatch):
        calls, sleeps = [], []
        ctx = self._ctx([MISSING_MSG, MISSING_MSG], calls, sleeps, monkeypatch)
        ops.run_ddl(ctx, "CREATE ...", "US")                             # 默认（rollback 等）行为不变
        assert len(calls) == 3 and sleeps == [10, 10]

    def test_bypass_first_table_missing_group_stops_everything(self, world, capsys):
        world.missing_groups.add(G_R)
        code = bypass("--apply")
        err = capsys.readouterr().err
        assert code == 2
        assert len(world.ddl_log) == 1 and all(world.policies(t) == [] for t in (T1, T2, T3))   # 只尝试了第一张
        assert f"[ERROR] BigQuery 报 Group {G_R} 不存在，已停止：其余 2 张需要变更的表未执行，未做任何变更" in err
        assert "===== 中止 (APPLY)：未做任何变更，2 张需要变更的表未执行 =====" in err and "CREATE 1" not in err
        assert "请稍后重跑" in err and "Traceback" not in err and "[retry]" not in err

    def test_copilot_first_table_missing_group_stops_everything(self, world, tmp_path, capsys):
        world.missing_groups.add(G_COP)
        code = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 2 and len(world.ddl_log) == 1
        assert f"[ERROR] BigQuery 报 Group {G_COP} 不存在，已停止：其余 2 张需要变更的表未执行" in err
        assert "===== 中止 (APPLY)：未做任何变更，2 张需要变更的表未执行 =====" in err
        rows = [r for r in (tmp_path / "c.csv").read_text(encoding="utf-8-sig").splitlines()[1:]]
        assert len(rows) == 3 and sum("NOT RUN" in r for r in rows) == 2      # 审核 CSV 标明未执行的表

    def test_first_table_is_first_change_not_first_noop(self, world, capsys):
        world.policies(T1).append({"id": BYP, "filter": "TRUE", "grantees": [f"group:{G_R}"]})   # T1 已正确 → NOOP
        world.missing_groups.add(G_R)
        code = bypass("--apply")
        err = capsys.readouterr().err
        assert code == 2 and len(world.ddl_log) == 1 and T2 in world.ddl_log[0]
        assert "其余 1 张需要变更的表未执行" in err                         # 已正确的 T1（NOOP）不计入

    def test_missing_group_mid_run_stops_remaining(self, world, capsys, monkeypatch):
        # 第一张成功，之后 Group 被删除：后续出现 Group 不存在 → 尚未开始的表不再执行，退出码 1
        state = {"n": 0}

        def hook(ddl):
            state["n"] += 1
            if state["n"] == 2:
                world.missing_groups.add(G_R)
        world.ddl_hook = hook
        code = bypass("--apply", "--parallel", "1")
        err = capsys.readouterr().err
        assert code == 1 and world.policies(T1) and not world.policies(T3)
        assert "执行中 BigQuery 报 Group" in err and "1 张需要变更的表未执行" in err
        assert "===== 中止 (APPLY)：CREATE 1，ERROR 1；1 张需要变更的表未执行 =====" in err   # 失败的表计入 ERROR

    def test_dry_run_unchanged(self, world, tmp_path, capsys):
        world.missing_groups.add(G_R)
        assert bypass() == 0 and world.ddl_log == []                       # 演练不执行 DDL，发现不了，也不受影响
        assert copilot(tmp_path, group=G_R) == 0

    def test_other_error_on_first_table_does_not_stop(self, world, capsys):
        world.fail_ddl_on.add(T1)                                          # 与 Group 无关的错误：其余表照常
        code = bypass("--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.policies(T2) and world.policies(T3)
        assert "===== 完成 (APPLY)：CREATE 2，ERROR 1 =====" in err          # 失败的表计入 ERROR，不计入 CREATE


# =========================================================================== #
# F-10：apply_bypass 检查 --group 格式
# =========================================================================== #
@pytest.mark.parametrize("bad", ["foo", "user:alice@trip.com", "group:g@trip.com",
                                 "etl@trip-prod.iam.gserviceaccount.com", 'g"x@trip.com', "a b@trip.com"])
def test_f10_bypass_rejects_bad_group(world, capsys, bad):
    assert bypass("--apply", group=bad) == 2
    assert world.ddl_log == [] and "--group" in capsys.readouterr().err


def test_f10_bypass_group_normalized_lowercase(world):
    assert bypass("--apply", group="Group_Read@Trip.com") == 0
    assert world.policy(T1, BYP)["grantees"] == [f"group:{G_R}"]


# =========================================================================== #
# F-11：映射表列名不区分大小写
# =========================================================================== #
def test_f11_resolve_column_case():
    schema = {"region": ("STRING", "NULLABLE"), "Prd_Type": ("STRING", "NULLABLE"), "meta.Ref": ("STRING", "NULLABLE")}
    got = core.resolve_column_case([("Region", "region"), ("prd_type", "prdtype"), ("META.ref", "x"), ("nope", "y")],
                                   schema)
    assert got == [("region", "region"), ("Prd_Type", "prdtype"), ("meta.Ref", "x"), ("nope", "y")]


def test_f11_copilot_mixed_case_mapping(world, tmp_path, capsys):
    world.mapping_rows[MAP] = [{"table_name": T1, "col_name": "REGION", "to_name": "region"},
                               {"table_name": T1, "col_name": "prd_type", "to_name": "prdtype"}]
    code = copilot(tmp_path, "--apply", "--tables", T1)
    flt = world.policy(T1, COP)["filter"]
    assert code == 0 and "`region` IN" in flt and "`Prd_Type` IN" in flt and "REGION" not in flt


# =========================================================================== #
# F-09：rollback 中途失败仍输出已删规则的完整内容
# =========================================================================== #
def test_f09_rollback_partial_failure_keeps_dropped_content(world, capsys):
    rules = [{"id": f"r{i}", "filter": f"region = 'R{i}'", "grantees": [f"group:g{i}@trip.com"]} for i in (1, 2, 3)]
    world.policies(T1).extend(rules + [{"id": "keep", "filter": "TRUE", "grantees": ["group:keep@trip.com"]}])
    world.fail_drop_policies.add("r2")
    code = rollback_rls.main(["--tables", T1, "--policy-names", "r1,r2,r3", "--apply"])
    err = capsys.readouterr().err
    assert code == 1
    assert "[DROP] `r1` grantees=['group:g1@trip.com'] filter=region = 'R1'" in err      # r1 已删除，内容仍可查
    assert "第 2 / 3 条 DDL 执行失败（此前 1 条已执行" in err
    assert [p["id"] for p in world.policies(T1)] == ["r2", "r3", "keep"]
    assert "共 1 条规则" in err                                                        # 汇总只计实际删除的


# =========================================================================== #
# F-03：gcp_ops 的 Cloud Identity 调用（真实响应形状）
# =========================================================================== #
def _ci(responses):
    """responses: [(status, body_dict)]；第一条是 discovery 文档。"""
    disc = discovery.build("cloudidentity", "v1", static_discovery=True, cache_discovery=False)._rootDesc
    seq = [({"status": "200"}, json.dumps(disc))] + [({"status": str(s)}, json.dumps(b)) for s, b in responses]
    return discovery.build("cloudidentity", "v1", http=HttpMockSequence(seq), static_discovery=False,
                           cache_discovery=False)


class _CICtx:
    def __init__(self, ci):
        self.ci = ci


def _err(status, message, reason="PERMISSION_DENIED"):
    return {"error": {"code": status, "message": message, "status": reason}}


LOOKUP_OK = (200, {"name": "groups/abc"})


class TestCloudIdentityShapes:
    def test_members_and_empty_group(self):
        ctx = _CICtx(_ci([LOOKUP_OK, (200, {"memberships": [
            {"preferredMemberKey": {"id": "ETL@p.iam.gserviceaccount.com"}, "type": "SERVICE_ACCOUNT"}]})]))
        assert ops.group_members_typed(ctx, "g@trip.com") == [("etl@p.iam.gserviceaccount.com", "SERVICE_ACCOUNT")]
        ctx = _CICtx(_ci([LOOKUP_OK, (200, {})]))
        assert ops.group_members_typed(ctx, "empty@trip.com") == []                 # 空组 ≠ 读不到

    def test_permission_denied_is_unreadable_with_reason(self):
        reasons = {}
        ctx = _CICtx(_ci([(403, _err(403, "Error(2028): Permission denied for resource g@x.com (or it may not exist)."))]))
        assert ops.group_members_typed(ctx, "g@x.com", reasons) is None
        assert reasons["g@x.com"].startswith("无权读取") and "HTTP 403" in reasons["g@x.com"]

    def test_api_disabled_raises(self):
        msg = "Cloud Identity API has not been used in project 123 before or it is disabled."
        ctx = _CICtx(_ci([(403, _err(403, msg, "PERMISSION_DENIED"))]))
        with pytest.raises(Exception, match="has not been used"):
            ops.group_members_typed(ctx, "g@trip.com")

    def test_rate_limit_retried_then_ok(self, monkeypatch):
        monkeypatch.setattr(ops.time, "sleep", lambda s: None)
        ctx = _CICtx(_ci([(429, _err(429, "Quota exceeded", "RESOURCE_EXHAUSTED")), LOOKUP_OK, (200, {})]))
        assert ops.group_members_typed(ctx, "g@trip.com") == []

    def test_server_error_exhausted_raises(self, monkeypatch):
        monkeypatch.setattr(ops.time, "sleep", lambda s: None)
        ctx = _CICtx(_ci([(503, _err(503, "Backend Error", "UNAVAILABLE"))] * 10))
        with pytest.raises(Exception):
            ops.group_members_typed(ctx, "g@trip.com")

    def test_expand_group_reports_unreadable_root_and_nested(self):
        ctx = _CICtx(_ci([
            LOOKUP_OK, (200, {"memberships": [{"preferredMemberKey": {"id": "ext@partner.com"}, "type": "GROUP"},
                                              {"preferredMemberKey": {"id": "a@trip.com"}, "type": "USER"}]}),
            (403, _err(403, "Permission denied for resource ext@partner.com (or it may not exist)."))]))
        members, unresolved, reasons = ops.expand_group(ctx, "root@trip.com")
        assert "a@trip.com" in members and unresolved == [("ext@partner.com", ["root@trip.com"])]
        assert reasons["ext@partner.com"].startswith("无权读取")
        ctx = _CICtx(_ci([(403, _err(403, "Permission denied for resource root@trip.com (or it may not exist)."))]))
        members, unresolved, reasons = ops.expand_group(ctx, "root@trip.com")
        assert members == {} and unresolved == [("root@trip.com", [])] and "root@trip.com" in reasons
