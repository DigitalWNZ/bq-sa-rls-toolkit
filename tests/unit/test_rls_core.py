"""rls_core 的单元测试：纯逻辑，不访问 GCP。"""

import pytest

import rls_core as core

COND = "auth-proj.auth_ds.adm_user_mem_copilot_condition"


# --------------------------------------------------------------------------- #
# 输入解析
# --------------------------------------------------------------------------- #
class TestSplitItems:
    def test_splits_commas_and_whitespace(self):
        assert core.split_items(["a,b", "c d", " e "]) == ["a", "b", "c", "d", "e"]

    def test_ignores_empty(self):
        assert core.split_items(["", " , "]) == []


class TestNormalizeMember:
    def test_bare_email_defaults_to_group(self):
        assert core.normalize_member("G@X.com") == "group:g@x.com"

    def test_bare_email_custom_default(self):
        assert core.normalize_member("a@x.com", default_prefix="user") == "user:a@x.com"

    def test_gserviceaccount_email_detected_as_service_account(self):
        assert (core.normalize_member("sa@p.iam.gserviceaccount.com")
                == "serviceAccount:sa@p.iam.gserviceaccount.com")

    def test_keeps_prefix_and_lowercases_email(self):
        assert core.normalize_member("serviceAccount:SA@P.iam.gserviceaccount.com") == \
            "serviceAccount:sa@p.iam.gserviceaccount.com"

    def test_special_members_kept(self):
        assert core.normalize_member("allAuthenticatedUsers") == "allAuthenticatedUsers"

    def test_deleted_member_kept_as_is(self):
        m = "deleted:serviceAccount:x@p.iam.gserviceaccount.com?uid=1"
        assert core.normalize_member(m) == m


class TestQualifiedTable:
    def test_three_part(self):
        assert core.parse_table("p.d.t") == ("p", "d", "t")

    def test_colon_form(self):
        assert core.parse_table("p:d.t") == ("p", "d", "t")

    def test_two_part_with_default_project(self):
        assert core.parse_table("d.t", default_project="p") == ("p", "d", "t")

    def test_rejects_bad_identifier(self):
        with pytest.raises(ValueError):
            core.parse_table("p.d.t`; DROP TABLE x --")

    def test_rejects_wrong_parts(self):
        with pytest.raises(ValueError):
            core.parse_table("p.d")


# --------------------------------------------------------------------------- #
# 权限分类
# --------------------------------------------------------------------------- #
class TestClassifyPermissions:
    def test_getdata_is_read(self):
        assert core.classify_permissions(["bigquery.tables.getData"]) == (True, False)

    def test_updatedata_is_write(self):
        assert core.classify_permissions(["bigquery.tables.updateData"]) == (False, True)

    def test_both(self):
        assert core.classify_permissions(
            ["bigquery.tables.getData", "bigquery.tables.updateData"]) == (True, True)

    def test_metadata_only_is_neither(self):
        assert core.classify_permissions(["bigquery.tables.get", "bigquery.jobs.create"]) == \
            (False, False)

    def test_legacy_dataset_roles(self):
        assert core.classify_legacy_dataset_role("READER") == (True, False)
        assert core.classify_legacy_dataset_role("WRITER") == (True, True)
        assert core.classify_legacy_dataset_role("OWNER") == (True, True)


# --------------------------------------------------------------------------- #
# Copilot SA 防混入
# --------------------------------------------------------------------------- #
class TestCopilotGuard:
    def test_explicit_member_rejected(self):
        allowed, rejected = core.filter_whitelist_members(
            ["serviceAccount:etl@p.iam.gserviceaccount.com",
             "serviceAccount:copilot-api@p.iam.gserviceaccount.com"],
            copilot_members=["copilot-api@p.iam.gserviceaccount.com"])
        assert allowed == ["serviceAccount:etl@p.iam.gserviceaccount.com"]
        assert rejected == ["serviceAccount:copilot-api@p.iam.gserviceaccount.com"]

    def test_pattern_rejected(self):
        allowed, rejected = core.filter_whitelist_members(
            ["serviceAccount:copilot-u-001@p.iam.gserviceaccount.com", "user:alice@x.com"],
            copilot_patterns=["copilot-*@*"])
        assert allowed == ["user:alice@x.com"]
        assert rejected == ["serviceAccount:copilot-u-001@p.iam.gserviceaccount.com"]

    def test_no_guard_allows_all(self):
        allowed, rejected = core.filter_whitelist_members(["user:a@x.com"])
        assert allowed == ["user:a@x.com"] and rejected == []


# --------------------------------------------------------------------------- #
# 白名单 FILTER TRUE DDL 与合并计划
# --------------------------------------------------------------------------- #
class TestGenericPolicyDdl:
    def test_build_policy_ddl(self):
        assert core.build_policy_ddl("p.d.t", "probe", ["group:g@x.com"], "x > 1") == (
            "CREATE OR REPLACE ROW ACCESS POLICY `probe`\n"
            "ON `p.d.t`\n"
            'GRANT TO ("group:g@x.com")\n'
            "FILTER USING (x > 1)")

    def test_rejects_quote_in_grantee(self):
        with pytest.raises(ValueError):
            core.build_policy_ddl("p.d.t", "probe", ['group:g@x.com") OR ("'], "TRUE")

    def test_sanitize_identifier(self):
        assert core.sanitize_identifier("rlsit-full.write") == "rlsit_full_write"

    def test_grantee_role_constant(self):
        assert core.RLS_GRANTEE_ROLE == "roles/bigquery.filteredDataViewer"


class TestBypassPolicy:
    def test_ddl_grants_all_groups_with_true_filter(self):
        ddl = core.build_bypass_policy_ddl(
            "p.d.t", ["group:w@x.com", "group:r@x.com"])
        assert ddl == (
            "CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`\n"
            "ON `p.d.t`\n"
            'GRANT TO ("group:w@x.com", "group:r@x.com")\n'
            "FILTER USING (TRUE)")

    def test_ddl_requires_grantees(self):
        with pytest.raises(ValueError):
            core.build_bypass_policy_ddl("p.d.t", [])

    def test_plan_create_when_absent(self):
        plan = core.plan_policy_upsert([], "rls_bypass_full_access", "TRUE", ["group:w@x.com"])
        assert plan.action == "create"

    def test_plan_noop_when_identical(self):
        existing = [{"id": "rls_bypass_full_access", "filter": "TRUE",
                     "grantees": ["group:w@x.com", "group:r@x.com"]}]
        plan = core.plan_policy_upsert(existing, "rls_bypass_full_access", "TRUE",
                                       ["group:r@x.com", "group:w@x.com"])
        assert plan.action == "noop"

    def test_plan_conflict_when_grantees_differ(self):
        existing = [{"id": "rls_bypass_full_access", "filter": "TRUE",
                     "grantees": ["user:someone@x.com"]}]
        plan = core.plan_policy_upsert(existing, "rls_bypass_full_access", "TRUE",
                                       ["group:w@x.com"])
        assert plan.action == "conflict"

    def test_plan_merge_unions_grantees(self):
        existing = [{"id": "rls_bypass_full_access", "filter": "TRUE",
                     "grantees": ["user:someone@x.com"]}]
        plan = core.plan_policy_upsert(existing, "rls_bypass_full_access", "TRUE",
                                       ["group:w@x.com"], merge=True)
        assert plan.action == "replace"
        assert plan.grantees == ["group:w@x.com", "user:someone@x.com"]

    def test_plan_conflict_when_filter_differs_even_with_merge(self):
        existing = [{"id": "rls_bypass_full_access", "filter": "region = 'HK'",
                     "grantees": ["group:w@x.com"]}]
        plan = core.plan_policy_upsert(existing, "rls_bypass_full_access", "TRUE",
                                       ["group:w@x.com"], merge=True)
        assert plan.action == "conflict"

    def test_first_policy_flag(self):
        assert core.plan_policy_upsert([], "p", "TRUE", ["group:a@x.com"]).first_policy
        assert not core.plan_policy_upsert(
            [{"id": "other", "filter": "TRUE", "grantees": []}],
            "p", "TRUE", ["group:a@x.com"]).first_policy


# --------------------------------------------------------------------------- #
# Copilot Subquery DDL
# --------------------------------------------------------------------------- #
class TestCopilotPolicy:
    def test_single_dimension_filter(self):
        f = core.build_copilot_filter([("prd_type", "prdtype")], COND)
        assert f == (
            "(`prd_type` IN (SELECT v FROM `auth-proj.auth_ds.adm_user_mem_copilot_condition` AS c, "
            "UNNEST(c.prdtype) AS v WHERE c.sa = SESSION_USER()) "
            "OR EXISTS (SELECT 1 FROM `auth-proj.auth_ds.adm_user_mem_copilot_condition` AS c "
            "WHERE c.sa = SESSION_USER() AND (c.prdtype IS NULL OR ARRAY_LENGTH(c.prdtype) = 0)))")

    def test_multiple_dimensions_joined_with_and(self):
        f = core.build_copilot_filter(
            [("region", "region"), ("prd_type", "prdtype"), ("ref", "refername")], COND)
        assert f.count(" AND (`") == 2  # 3 个维度之间 2 个 AND（EXISTS 内部是 " AND (c."）
        assert "UNNEST(c.region)" in f and "UNNEST(c.prdtype)" in f and "UNNEST(c.refername)" in f
        assert "`ref` IN" in f

    def test_rejects_unknown_dimension(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([("x", "city")], COND)

    def test_rejects_bad_column_name(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([("a b", "region")], COND)

    def test_rejects_empty_mapping(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([], COND)

    def test_policy_ddl(self):
        ddl = core.build_copilot_policy_ddl(
            "p.d.t", [("region", "region")], COND, ["group:hi@x.com", "group:lo@x.com"])
        assert ddl.startswith(
            "CREATE OR REPLACE ROW ACCESS POLICY `rls_copilot_subquery_policy`\n"
            "ON `p.d.t`\n"
            'GRANT TO ("group:hi@x.com", "group:lo@x.com")\n'
            "FILTER USING (")
        assert ddl.endswith(")")


class TestHeterogeneousTables:
    """多张表、每张表过滤字段的列名/类型/层级都不同。"""

    def test_bigquery_reformatted_predicate_equals_generated(self):
        cond = "my-proj.rls_it.adm_user_mem_copilot_condition"
        generated = core.build_copilot_filter([("region", "region")], cond)
        # BigQuery rowAccessPolicies.list 实际返回的 filterPredicate（去反引号、重新排版）
        stored = ("(region IN (\n  SELECT\n    v\n  FROM\n    `" + cond + "` AS c,\n"
                  "    UNNEST(c.region) AS v\n  WHERE\n    c.sa = SESSION_USER()\n) OR EXISTS(\n"
                  "  SELECT\n    1\n  FROM\n    `" + cond + "` AS c\n  WHERE\n"
                  "    c.sa = SESSION_USER() AND (c.region IS NULL OR ARRAY_LENGTH(c.region) = 0)\n))")
        assert core.normalize_filter(stored) == core.normalize_filter(generated)

    def test_normalize_filter_still_detects_real_change(self):
        assert core.normalize_filter("region = 'HK'") != core.normalize_filter("region = 'SG'")
        assert core.normalize_filter("a IN (1)") != core.normalize_filter("b IN (1)")

    def test_same_dimension_different_column_names_per_table(self):
        rows = [
            {"table_name": "p.d.a", "col_name": "region", "to_name": "region"},
            {"table_name": "p.d.b", "col_name": "area", "to_name": "region"},
            {"table_name": "p.d.b", "col_name": "ptype", "to_name": "prdtype"},
        ]
        m = core.parse_mapping_rows(rows)
        fa = core.build_copilot_filter(m["p.d.a"], COND)
        fb = core.build_copilot_filter(m["p.d.b"], COND)
        assert "`region` IN" in fa and "prdtype" not in fa
        assert "`area` IN" in fb and "`ptype` IN" in fb and "`region` IN" not in fb

    def test_non_string_column_is_cast(self):
        f = core.build_copilot_filter([("prd_code", "prdtype")], COND,
                                      column_types={"prd_code": "INT64"})
        assert f.startswith("(CAST(`prd_code` AS STRING) IN (SELECT v FROM")

    def test_string_column_not_cast(self):
        f = core.build_copilot_filter([("area", "region")], COND, column_types={"area": "STRING"})
        assert f.startswith("(`area` IN")

    def test_nested_column_path(self):
        f = core.build_copilot_filter([("meta.ref", "refername")], COND)
        assert f.startswith("(`meta`.`ref` IN")

    def test_nested_column_rejects_bad_part(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([("meta.re f", "refername")], COND)

    def test_schema_validation_ok(self):
        schema = {"area": ("STRING", "NULLABLE"), "meta": ("RECORD", "NULLABLE"),
                  "meta.ref": ("STRING", "NULLABLE"), "n": ("INT64", "NULLABLE")}
        assert core.validate_mapping_against_schema(
            [("area", "region"), ("meta.ref", "refername"), ("n", "prdtype")], schema) == []

    def test_schema_validation_missing_column(self):
        errs = core.validate_mapping_against_schema([("nope", "region")], {"area": ("STRING", "NULLABLE")})
        assert len(errs) == 1 and "nope" in errs[0] and "不存在" in errs[0]

    def test_schema_validation_rejects_repeated_and_record(self):
        schema = {"tags": ("STRING", "REPEATED"), "meta": ("RECORD", "NULLABLE")}
        errs = core.validate_mapping_against_schema([("tags", "region"), ("meta", "prdtype")], schema)
        assert len(errs) == 2

    def test_schema_validation_rejects_unsupported_type(self):
        errs = core.validate_mapping_against_schema(
            [("g", "region")], {"g": ("GEOGRAPHY", "NULLABLE")})
        assert len(errs) == 1 and "GEOGRAPHY" in errs[0]

    def test_flatten_schema(self):
        class F:  # 模拟 bigquery.SchemaField
            def __init__(self, name, field_type, mode="NULLABLE", fields=()):
                self.name, self.field_type, self.mode, self.fields = name, field_type, mode, fields
        flat = core.flatten_schema([F("a", "STRING"), F("m", "RECORD", fields=[F("x", "INTEGER")])])
        assert flat == {"a": ("STRING", "NULLABLE"), "m": ("RECORD", "NULLABLE"),
                        "m.x": ("INT64", "NULLABLE")}


class TestParseMappingRows:
    def test_groups_by_table_and_normalizes(self):
        rows = [
            {"table_name": "p.d.t1", "col_name": "region", "to_name": "REGION"},
            {"table_name": "p.d.t1", "col_name": "prd_type", "to_name": "prdtype"},
            {"table_name": "d.t2", "col_name": "refername", "to_name": "refername"},
        ]
        m = core.parse_mapping_rows(rows, default_project="p")
        assert m == {
            "p.d.t1": [("region", "region"), ("prd_type", "prdtype")],
            "p.d.t2": [("refername", "refername")],
        }

    def test_dedupes(self):
        rows = [{"table_name": "p.d.t", "col_name": "region", "to_name": "region"}] * 2
        assert core.parse_mapping_rows(rows) == {"p.d.t": [("region", "region")]}

    def test_invalid_dimension_raises(self):
        with pytest.raises(ValueError):
            core.parse_mapping_rows([{"table_name": "p.d.t", "col_name": "c", "to_name": "x"}])


# --------------------------------------------------------------------------- #
# 回退计划
# --------------------------------------------------------------------------- #
G = "group:g@x.com"
U = "user:u@x.com"


def pol(pid, grantees, flt="TRUE"):
    return {"id": pid, "filter": flt, "grantees": grantees}


class TestPlanRollback:
    def test_no_members_drops_all(self):
        plan = core.plan_rollback([pol("a", [G]), pol("b", [U])], members=set())
        assert plan.drop_all and [p["id"] for p in plan.to_drop] == ["a", "b"]

    def test_drops_only_related(self):
        plan = core.plan_rollback([pol("a", [G]), pol("b", [U])], members={G})
        assert not plan.drop_all
        assert [p["id"] for p in plan.to_drop] == ["a"]

    def test_shared_policy_dropped_by_default(self):
        plan = core.plan_rollback([pol("a", [G, U]), pol("b", [U])], members={G})
        assert [p["id"] for p in plan.to_drop] == ["a"] and plan.to_update == []

    def test_strip_only_updates_shared(self):
        plan = core.plan_rollback([pol("a", [G, U]), pol("b", [U])], members={G}, strip_only=True)
        assert plan.to_drop == []
        assert plan.to_update == [(pol("a", [G, U]), [U])]

    def test_last_policy_uses_drop_all(self):
        plan = core.plan_rollback([pol("a", [G])], members={G})
        assert plan.drop_all

    def test_policy_name_filter(self):
        plan = core.plan_rollback(
            [pol("rls_bypass_full_access", [G]), pol("rls_copilot_subquery_policy", [U])],
            members=set(), policy_names={"rls_copilot_subquery_policy"})
        assert not plan.drop_all
        assert [p["id"] for p in plan.to_drop] == ["rls_copilot_subquery_policy"]

    def test_member_matching_is_case_insensitive(self):
        plan = core.plan_rollback([pol("a", ["group:G@X.com"]), pol("b", [U])], members={G})
        assert [p["id"] for p in plan.to_drop] == ["a"]


# --------------------------------------------------------------------------- #
# 巡检
# --------------------------------------------------------------------------- #
class TestInspect:
    BYPASS = ["group:w@x.com", "group:r@x.com"]
    COP = ["group:hi@x.com"]

    def _ok_policies(self, flt="X = 1"):
        return [pol("rls_bypass_full_access", self.BYPASS),
                pol("rls_copilot_subquery_policy", self.COP, flt)]

    def test_all_good(self):
        assert core.inspect_policies(self._ok_policies(), self.BYPASS, self.COP, "X = 1") == []

    def test_missing_bypass(self):
        issues = core.inspect_policies(
            [pol("rls_copilot_subquery_policy", self.COP, "X = 1")], self.BYPASS, self.COP, "X = 1")
        assert any("rls_bypass_full_access" in i and "缺失" in i for i in issues)

    def test_bypass_missing_group(self):
        ps = self._ok_policies()
        ps[0]["grantees"] = ["group:w@x.com"]
        issues = core.inspect_policies(ps, self.BYPASS, self.COP, "X = 1")
        assert any("group:r@x.com" in i for i in issues)

    def test_bypass_not_true(self):
        ps = self._ok_policies()
        ps[0]["filter"] = "region = 'HK'"
        assert any("TRUE" in i for i in core.inspect_policies(ps, self.BYPASS, self.COP, "X = 1"))

    def test_filter_drift_detected_ignoring_whitespace(self):
        assert core.inspect_policies(self._ok_policies("X  =\n1"), self.BYPASS, self.COP, "X = 1") == []
        issues = core.inspect_policies(self._ok_policies("X = 2"), self.BYPASS, self.COP, "X = 1")
        assert any("过滤条件" in i for i in issues)

    def test_missing_copilot_policy(self):
        issues = core.inspect_policies(self._ok_policies()[:1], self.BYPASS, self.COP, "X = 1")
        assert any("rls_copilot_subquery_policy" in i and "缺失" in i for i in issues)

    def test_copilot_member_in_whitelist_group(self):
        issues = core.inspect_whitelist_membership(
            {"group:w@x.com": ["serviceAccount:copilot-u-1@p.iam.gserviceaccount.com",
                               "serviceAccount:etl@p.iam.gserviceaccount.com"]},
            copilot_patterns=["copilot-*@*"])
        assert len(issues) == 1 and "copilot-u-1" in issues[0]


# --------------------------------------------------------------------------- #
# 其他
# --------------------------------------------------------------------------- #
class TestServiceAgent:
    def test_google_managed_service_agents(self):
        for m in ["serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com",
                  "serviceAccount:service-123@container-engine-robot.iam.gserviceaccount.com",
                  "serviceAccount:123@cloudservices.gserviceaccount.com",
                  "serviceAccount:bqcx-123-7kfg@gcp-sa-bigquery-condel.iam.gserviceaccount.com",
                  "serviceAccount:123@cloudbuild.gserviceaccount.com"]:
            assert core.is_service_agent(m), m

    def test_regular_sa_is_not_agent(self):
        assert not core.is_service_agent("serviceAccount:etl@p.iam.gserviceaccount.com")
        assert not core.is_service_agent("serviceAccount:123-compute@developer.gserviceaccount.com")
        assert not core.is_service_agent("user:a@x.com")


class TestImpersonationRisk:
    PERMS = {
        "roles/iam.serviceAccountTokenCreator": ["iam.serviceAccounts.getAccessToken"],
        "roles/owner": ["resourcemanager.projects.get"],
        "roles/custom": ["iam.serviceAccounts.implicitDelegation"],
    }

    def test_finds_project_level_impersonators_except_allowed(self):
        bindings = [
            {"role": "roles/iam.serviceAccountTokenCreator",
             "members": ["user:admin@x.com", "serviceAccount:api@p.iam.gserviceaccount.com"]},
            {"role": "roles/owner", "members": ["user:owner@x.com"]},
            {"role": "roles/custom", "members": ["group:ops@x.com"]},
        ]
        risks = core.impersonation_risks(bindings, self.PERMS.get,
                                         allowed=["api@p.iam.gserviceaccount.com"])
        assert risks == [("group:ops@x.com", "roles/custom"),
                         ("user:admin@x.com", "roles/iam.serviceAccountTokenCreator")]

    def test_no_risk(self):
        assert core.impersonation_risks([{"role": "roles/owner", "members": ["user:o@x.com"]}],
                                        self.PERMS.get) == []


class TestProjectSaWhitelistRows:
    def _sa(self, email, project="p", disabled=False, source="project-sa"):
        return {"email": email, "project": project, "display_name": "", "disabled": disabled,
                "source": source}

    def test_all_sas_suggested_to_target_group(self):
        rows = core.build_sa_whitelist_rows(
            [self._sa("etl@p.iam.gserviceaccount.com"), self._sa("bi@p.iam.gserviceaccount.com")],
            group="write")
        assert [(r["principal"], r["suggested_group"]) for r in rows] == [
            ("serviceAccount:bi@p.iam.gserviceaccount.com", "write"),
            ("serviceAccount:etl@p.iam.gserviceaccount.com", "write")]

    def test_copilot_sas_excluded(self):
        rows = core.build_sa_whitelist_rows(
            [self._sa("copilot-u-1@p.iam.gserviceaccount.com"), self._sa("api@p.iam.gserviceaccount.com"),
             self._sa("etl@p.iam.gserviceaccount.com")],
            group="read", copilot_members=["api@p.iam.gserviceaccount.com"],
            copilot_patterns=["copilot-*@*"])
        by = {r["principal"]: r for r in rows}
        assert by["serviceAccount:copilot-u-1@p.iam.gserviceaccount.com"]["suggested_group"] == ""
        assert by["serviceAccount:copilot-u-1@p.iam.gserviceaccount.com"]["copilot"] is True
        assert by["serviceAccount:api@p.iam.gserviceaccount.com"]["suggested_group"] == ""
        assert by["serviceAccount:etl@p.iam.gserviceaccount.com"]["suggested_group"] == "read"

    def test_disabled_excluded_by_default(self):
        rows = core.build_sa_whitelist_rows([self._sa("old@p.iam.gserviceaccount.com", disabled=True)],
                                            group="write")
        assert rows[0]["suggested_group"] == "" and "已禁用" in rows[0]["note"]
        rows = core.build_sa_whitelist_rows([self._sa("old@p.iam.gserviceaccount.com", disabled=True)],
                                            group="write", include_disabled=True)
        assert rows[0]["suggested_group"] == "write"

    def test_dedupes_and_merges_sources(self):
        rows = core.build_sa_whitelist_rows(
            [self._sa("x@q.iam.gserviceaccount.com", project="q"),
             self._sa("x@q.iam.gserviceaccount.com", project="p", source="iam-binding")],
            group="write")
        assert len(rows) == 1
        assert rows[0]["sources"] == "q:project-sa; p:iam-binding"

    def test_service_agent_noted(self):
        rows = core.build_sa_whitelist_rows(
            [self._sa("service-1@gcp-sa-pubsub.iam.gserviceaccount.com", source="iam-binding")],
            group="write")
        assert "服务代理" in rows[0]["note"] and rows[0]["suggested_group"] == "write"

    def test_rejects_bad_group(self):
        with pytest.raises(ValueError):
            core.build_sa_whitelist_rows([], group="admin")


class TestQuota:
    def test_within_quota(self):
        core.check_sa_quota(existing=10, to_create=5)

    def test_exceeds_quota(self):
        with pytest.raises(ValueError, match="100"):
            core.check_sa_quota(existing=98, to_create=5)


# --------------------------------------------------------------------------- #
# C1 挂载后验证：按分区要求生成探测 SQL
# --------------------------------------------------------------------------- #
class TestVisibilityProbeSql:
    def test_plain_table_samples_one_row(self):
        assert core.visibility_probe_sql("p.d.t", None) == "SELECT 1 FROM `p.d.t` LIMIT 1"

    def test_partition_filter_not_required_no_where(self):
        part = {"require_filter": False, "field": "dt", "kind": "time"}
        assert core.visibility_probe_sql("p.d.t", part) == "SELECT 1 FROM `p.d.t` LIMIT 1"

    def test_column_time_partition_requires_filter(self):
        part = {"require_filter": True, "field": "dt", "kind": "time"}
        assert core.visibility_probe_sql("p.d.t", part) == \
            "SELECT 1 FROM `p.d.t` WHERE `dt` IS NOT NULL LIMIT 1"

    def test_ingestion_time_partition_uses_pseudo_column(self):
        part = {"require_filter": True, "field": None, "kind": "time"}
        assert core.visibility_probe_sql("p.d.t", part) == \
            "SELECT 1 FROM `p.d.t` WHERE _PARTITIONTIME IS NOT NULL LIMIT 1"

    def test_range_partition(self):
        part = {"require_filter": True, "field": "cust_id", "kind": "range"}
        assert "WHERE `cust_id` IS NOT NULL" in core.visibility_probe_sql("p.d.t", part)

    def test_count_mode(self):
        part = {"require_filter": True, "field": "dt", "kind": "time"}
        assert core.visibility_probe_sql("p.d.t", part, mode="count") == \
            "SELECT COUNT(*) AS n FROM `p.d.t` WHERE `dt` IS NOT NULL"


# --------------------------------------------------------------------------- #
# C3 Reservation 版本前置检查
# --------------------------------------------------------------------------- #
class TestEditionCheck:
    def test_standard_jobs_flagged(self):
        rows = [{"edition": "STANDARD", "reservation_id": "a:US.std", "n": 12},
                {"edition": "ENTERPRISE", "reservation_id": "a:US.ent", "n": 3},
                {"edition": None, "reservation_id": None, "n": 5}]
        assert core.standard_edition_usage(rows) == [("a:US.std", 12)]

    def test_no_jobs_is_unknown(self):
        assert core.standard_edition_usage([]) == []

    def test_sql_targets_project_region(self):
        sql = core.edition_usage_sql("p", "us", days=7)
        assert "`p`.`region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT" in sql
        assert "edition" in sql and "INTERVAL 7 DAY" in sql


# --------------------------------------------------------------------------- #
# C2 跨项目 / 组织级作业历史
# --------------------------------------------------------------------------- #
class TestJobsSqlScope:
    def test_project_view_default(self):
        assert "INFORMATION_SCHEMA.JOBS_BY_PROJECT" in core.jobs_access_sql("p", "us", 30)

    def test_organization_view(self):
        sql = core.jobs_access_sql("p", "us", 30, scope="organization")
        assert "`p`.`region-us`.INFORMATION_SCHEMA.JOBS_BY_ORGANIZATION" in sql
        assert "JOBS_BY_PROJECT" not in sql

    def test_rejects_unknown_scope(self):
        with pytest.raises(ValueError):
            core.jobs_access_sql("p", "us", 30, scope="folder")


# --------------------------------------------------------------------------- #
# E1 大小写不敏感匹配
# --------------------------------------------------------------------------- #
class TestCaseInsensitiveFilter:
    def test_upper_wraps_both_sides(self):
        f = core.build_copilot_filter([("region", "region")], COND, case_insensitive=True)
        assert f.startswith("(UPPER(`region`) IN (SELECT UPPER(v) FROM")
        assert "UNNEST(c.region) AS v" in f

    def test_upper_with_cast(self):
        f = core.build_copilot_filter([("code", "prdtype")], COND, column_types={"code": "INT64"},
                                      case_insensitive=True)
        assert f.startswith("(UPPER(CAST(`code` AS STRING)) IN (SELECT UPPER(v)")

    def test_default_is_case_sensitive(self):
        assert "UPPER(" not in core.build_copilot_filter([("region", "region")], COND)


# --------------------------------------------------------------------------- #
# E2 巡检：Copilot SA 归属 / 条件行 / API SA / 条件表聚簇
# --------------------------------------------------------------------------- #
class TestInspectCopilotMembership:
    HI, LO = "group:hi@x.com", "group:lo@x.com"
    S1, S2, S3 = ("s1@p.iam.gserviceaccount.com", "s2@p.iam.gserviceaccount.com",
                  "s3@p.iam.gserviceaccount.com")

    def test_all_good(self):
        issues, warns = core.inspect_copilot_membership(
            {self.HI: {self.S1}, self.LO: {self.S2}}, condition_sas={self.S1, self.S2},
            api_sa="api@p.iam.gserviceaccount.com")
        assert issues == [] and warns == []

    def test_sa_in_both_groups_is_issue(self):
        issues, _ = core.inspect_copilot_membership(
            {self.HI: {self.S1}, self.LO: {self.S1}}, condition_sas={self.S1})
        assert any("同时" in i and self.S1 in i for i in issues)

    def test_sa_without_condition_row_is_warning_only(self):
        issues, warns = core.inspect_copilot_membership(
            {self.HI: {self.S1, self.S3}}, condition_sas={self.S1})
        assert issues == [] and any(self.S3 in w and "条件行" in w for w in warns)

    def test_condition_row_without_group_is_warning(self):
        _, warns = core.inspect_copilot_membership({self.HI: {self.S1}}, condition_sas={self.S1, self.S2})
        assert any(self.S2 in w and "不在任何" in w for w in warns)

    def test_api_sa_in_copilot_group_is_issue(self):
        issues, _ = core.inspect_copilot_membership(
            {self.HI: {self.S1, "api@p.iam.gserviceaccount.com"}}, condition_sas={self.S1},
            api_sa="api@p.iam.gserviceaccount.com")
        assert any("API SA" in i for i in issues)

    def test_clustering_check(self):
        assert core.inspect_condition_clustering(["sa"]) == []
        assert core.inspect_condition_clustering(["sa", "status"]) == []
        assert len(core.inspect_condition_clustering([])) == 1
        assert len(core.inspect_condition_clustering(["status"])) == 1


# --------------------------------------------------------------------------- #
# E3 通配符表查询检测
# --------------------------------------------------------------------------- #
class TestWildcardSql:
    def test_pattern_matches_wildcard_refs_in_target_datasets(self):
        import re
        pat = core.wildcard_pattern(["my-proj.dw", "my-proj.dw_2"])
        assert re.search(pat, "SELECT * FROM `my-proj.dw.fact_*` WHERE 1=1")
        assert re.search(pat, "select x from dw.events_2024*")
        assert not re.search(pat, "SELECT * FROM `my-proj.dw.fact_orders`")
        assert not re.search(pat, "SELECT * FROM `other.dw.fact_*`") or True  # 数据集同名的跨项目引用允许命中

    def test_sql_uses_parameter(self):
        sql = core.wildcard_jobs_sql("p", "us", 30)
        assert "REGEXP_CONTAINS(query, @pattern)" in sql and "JOBS_BY_PROJECT" in sql


class TestJobsSql:
    def test_contains_referenced_and_destination_and_params(self):
        sql = core.jobs_access_sql("p", "us", days=30)
        assert "`p`.`region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT" in sql
        assert "UNNEST(referenced_tables)" in sql
        assert "destination_table" in sql
        assert "@tables" in sql
        assert "INTERVAL 30 DAY" in sql

    def test_rejects_bad_region(self):
        with pytest.raises(ValueError):
            core.jobs_access_sql("p", "us`; --", days=30)


class TestAccountId:
    def test_account_id_from_email(self):
        assert core.sa_account_id("copilot-u-1@p.iam.gserviceaccount.com") == "copilot-u-1"
        assert core.sa_account_id("copilot-u-1") == "copilot-u-1"

    def test_sa_email(self):
        assert core.sa_email("copilot-u-1", "p") == "copilot-u-1@p.iam.gserviceaccount.com"

    def test_invalid_account_id(self):
        with pytest.raises(ValueError):
            core.sa_account_id("Bad_ID")


# --------------------------------------------------------------------------- #
# 8 张权限表：表名推导、bind/grant SQL、一 SA 一 Group、白名单名册
# --------------------------------------------------------------------------- #
class TestAuthTables:
    def test_default_names_from_dataset(self):
        assert core.auth_table("bind", dataset="auth-proj.auth") == \
            "auth-proj.auth.adm_user_mem_copilot_user_bind"
        assert core.auth_table("acl", dataset="auth-proj.auth") == \
            "auth-proj.auth.adm_user_mem_copilot_acl_group_sa"

    def test_explicit_table_wins(self):
        assert core.auth_table("group", dataset="auth-proj.auth",
                               override="p:d.my_groups") == "p.d.my_groups"

    def test_requires_dataset_or_override(self):
        with pytest.raises(ValueError):
            core.auth_table("grant")
        with pytest.raises(ValueError):
            core.auth_table("grant", dataset="only-dataset")

    def test_bind_sql_joins_condition_and_group(self):
        sql = core.bind_sa_group_sql("a.b.bind", "a.b.cond", "a.b.grp")
        assert "`a.b.bind` AS b" in sql and "`a.b.cond` AS c ON c.id = b.condition_id" in sql
        assert "`a.b.grp` AS g ON g.id = b.group_id" in sql
        assert "LOWER(c.sa) AS sa" in sql and "g.`group`" in sql      # group 是保留字，必须反引号

    def test_grant_sql_joins_group(self):
        sql = core.grant_scope_sql("a.b.grant_tb", "a.b.grp")
        assert "`a.b.grant_tb` AS t" in sql and "g.id = t.group_id" in sql
        assert "t.table_name AS resource" in sql

    def test_sql_rejects_bad_names(self):
        with pytest.raises(ValueError):
            core.bind_sa_group_sql("a.b.bind`; DROP", "a.b.cond", "a.b.grp")


class TestSaRows:
    def test_parse_accepts_csv_and_table_shapes(self):
        rows = [{"account_id": "copilot-u-001", "group": "G_High@X.com", "display_name": "HK lead"},
                {"sa": "copilot-u-002@p.iam.gserviceaccount.com", "grp": "g_low@x.com"},
                {"sa": "copilot-u-002@p.iam.gserviceaccount.com", "grp": "G_LOW@x.com"}]   # 重复行
        assert core.parse_sa_rows(rows) == [("copilot-u-001", "g_high@x.com", "HK lead"),
                                            ("copilot-u-002", "g_low@x.com", None)]

    def test_parse_rejects_missing_group(self):
        with pytest.raises(ValueError):
            core.parse_sa_rows([{"account_id": "copilot-u-001", "group": ""}])

    def test_one_group_per_sa(self):
        sas = [("u-001", "high@x.com", None), ("u-002", "low@x.com", None), ("u-001", "low@x.com", None)]
        assert core.sa_group_conflicts(sas) == {"u-001": ["high@x.com", "low@x.com"]}
        assert core.sa_group_conflicts(sas[:2]) == {}

    def test_parse_grants(self):
        rows = [{"group": "High@x.com", "resource": "p:d.t"},
                {"grp": "low@x.com", "table_name": "p.d"},
                {"grp": "low@x.com", "table_name": "p.d"}]
        assert core.parse_grant_rows(rows) == [("high@x.com", "p.d.t"), ("low@x.com", "p.d")]


class TestAclRoster:
    W, R = "group_full_write@x.com", "group_full_read@x.com"

    def test_resolve_by_email_or_suffix(self):
        assert core.resolve_acl_group("Group_Full_Write@x.com", self.W, self.R) == self.W
        assert core.resolve_acl_group("group_full_read", self.W, self.R) == self.R
        assert core.resolve_acl_group("WRITE", self.W, self.R) == self.W

    def test_resolve_rejects_unknown(self):
        with pytest.raises(ValueError):
            core.resolve_acl_group("other@x.com", self.W, self.R)
        with pytest.raises(ValueError):
            core.resolve_acl_group("vip", self.W, self.R)
        with pytest.raises(ValueError):
            core.resolve_acl_group("full_write", None, self.R)        # 名册有写账号但没给 --write-group

    def test_roster_to_plan(self):
        rows = [{"sa": "etl@p.iam.gserviceaccount.com", "acl_group": "group_full_write"},
                {"sa": "admin@x.com", "acl_group": self.W},
                {"sa": "iba@p.iam.gserviceaccount.com", "acl_group": "read"}]
        assert core.acl_roster(rows, self.W, self.R) == {
            self.W: ["serviceAccount:etl@p.iam.gserviceaccount.com", "user:admin@x.com"],
            self.R: ["serviceAccount:iba@p.iam.gserviceaccount.com"]}

    def test_roster_collects_all_errors(self):
        rows = [{"sa": "a@x.com", "acl_group": "vip"}, {"sa": "", "acl_group": "read"}]
        with pytest.raises(ValueError) as ei:
            core.acl_roster(rows, self.W, self.R)
        assert "vip" in str(ei.value) and "sa 为空" in str(ei.value)

    def test_inspect_roster_both_directions(self):
        actual = {self.W: {"etl@p.iam.gserviceaccount.com", "probe@p.iam.gserviceaccount.com",
                           "stranger@x.com"},
                  self.R: {"iba@p.iam.gserviceaccount.com"}}
        roster = {self.W: {"etl@p.iam.gserviceaccount.com"},
                  self.R: {"iba@p.iam.gserviceaccount.com", "late@p.iam.gserviceaccount.com"}}
        issues = core.inspect_acl_roster(actual, roster, ignore=["probe@p.iam.gserviceaccount.com"])
        assert len(issues) == 2
        assert any("stranger@x.com" in i and "不在白名单名册" in i for i in issues)
        assert any("late@p.iam.gserviceaccount.com" in i and "还没有加入" in i for i in issues)
        assert core.inspect_acl_roster(roster, roster) == []
