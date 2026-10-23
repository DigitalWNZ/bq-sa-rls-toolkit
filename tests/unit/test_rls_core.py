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


class TestReadListFile:
    def test_single_column_no_header(self, tmp_path):
        f = tmp_path / "tables.csv"
        f.write_text("p.d.t1\np.d.t2\n", encoding="utf-8")
        assert core.read_list_file(str(f)) == ["p.d.t1", "p.d.t2"]

    def test_blank_lines_ignored_and_values_stripped(self, tmp_path):
        f = tmp_path / "x.csv"
        f.write_text("\n  a  \n\n b\n", encoding="utf-8")
        assert core.read_list_file(str(f)) == ["a", "b"]

    def test_utf8_bom_tolerated(self, tmp_path):
        f = tmp_path / "x.csv"
        f.write_bytes("\ufeffprod-proj\netl-proj\n".encode("utf-8"))
        assert core.read_list_file(str(f)) == ["prod-proj", "etl-proj"]

    def test_hash_is_not_a_comment(self, tmp_path):
        # CSV 不支持注释：以 # 开头的行按普通值读入（后续校验会报错）
        f = tmp_path / "x.csv"
        f.write_text("#abc\n", encoding="utf-8")
        assert core.read_list_file(str(f)) == ["#abc"]

    def test_multiple_columns_rejected(self, tmp_path):
        f = tmp_path / "x.csv"
        f.write_text("a,b\n", encoding="utf-8")
        with pytest.raises(ValueError, match="单列"):
            core.read_list_file(str(f))

    def test_quoted_value_with_trailing_empty_cell_ok(self, tmp_path):
        # Excel 另存为 CSV 时可能多出空列
        f = tmp_path / "x.csv"
        f.write_text("a,\n\"b\",\n", encoding="utf-8")
        assert core.read_list_file(str(f)) == ["a", "b"]


class TestNormalizeMember:
    def test_bare_email_defaults_to_group(self):
        assert core.normalize_member("G@X.com") == "group:g@x.com"

    def test_gserviceaccount_email_detected_as_service_account(self):
        assert (core.normalize_member("sa@p.iam.gserviceaccount.com")
                == "serviceAccount:sa@p.iam.gserviceaccount.com")

    def test_keeps_prefix_and_lowercases_email(self):
        assert core.normalize_member("user:Alice@X.com") == "user:alice@x.com"

    def test_deleted_member_kept_as_is(self):
        m = "deleted:serviceAccount:x@p.iam.gserviceaccount.com?uid=1"
        assert core.normalize_member(m) == m


class TestMemberEmail:
    def test_strips_prefix(self):
        assert core.member_email("serviceAccount:SA@p.iam.gserviceaccount.com") == \
            "sa@p.iam.gserviceaccount.com"

    def test_bare(self):
        assert core.member_email("A@x.com") == "a@x.com"


class TestTableAndDataset:
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

    def test_dataset(self):
        assert core.parse_dataset("p.d") == ("p", "d")
        assert core.parse_dataset("p:d") == ("p", "d")

    def test_dataset_rejects_table(self):
        with pytest.raises(ValueError):
            core.parse_dataset("p.d.t")


class TestScopeIds:
    def test_org_id_digits(self):
        assert core.org_scope("230135420009") == "organizations/230135420009"
        assert core.org_scope("organizations/230135420009") == "organizations/230135420009"

    def test_org_id_rejects_non_digits(self):
        with pytest.raises(ValueError):
            core.org_scope("harrishe.altostrat.com")

    def test_project_id(self):
        assert core.project_scope("prod-proj") == "projects/prod-proj"

    def test_project_number_tolerated(self):
        assert core.project_scope("123456789012") == "projects/123456789012"

    def test_project_rejects_bad(self):
        with pytest.raises(ValueError):
            core.project_scope("bad proj!")


# --------------------------------------------------------------------------- #
# 规则命名
# --------------------------------------------------------------------------- #
class TestPolicyNames:
    def test_bypass_name(self):
        assert (core.bypass_policy_name("group_existingSA_read@domain.com")
                == "rls_bypass_full_access_group_existingsa_read_domain_com")

    def test_copilot_name(self):
        assert core.copilot_policy_name("Alice.W@domain.com") == "rls_copilot_alice_w_domain_com"

    def test_copilot_name_for_sa(self):
        assert (core.copilot_policy_name("copilot-sa-a@p.iam.gserviceaccount.com")
                == "rls_copilot_copilot_sa_a_p_iam_gserviceaccount_com")

    def test_prefix_strips_group_prefix(self):
        assert core.bypass_policy_name("group:g@x.com") == "rls_bypass_full_access_g_x_com"

    def test_long_email_truncated_with_hash_and_stays_valid(self):
        long = ("a" * 240) + "@x.com"
        name = core.copilot_policy_name(long)
        assert len(name) <= 256 and name.startswith("rls_copilot_")
        assert core.copilot_policy_name(long) == name          # 稳定
        assert core.copilot_policy_name(("a" * 241) + "@x.com") != name

    def test_is_bypass_name(self):
        assert core.is_bypass_policy("rls_bypass_full_access_g_x_com")
        assert not core.is_bypass_policy("rls_bypass_full_access")
        assert not core.is_bypass_policy("rls_copilot_a_x_com")


# --------------------------------------------------------------------------- #
# list_principals：主体抽取
# --------------------------------------------------------------------------- #
class TestPrincipalType:
    def test_types(self):
        assert core.principal_type("alice@x.com") == "user"
        assert core.principal_type("etl@p.iam.gserviceaccount.com") == "serviceAccount"
        assert core.principal_type("123-compute@developer.gserviceaccount.com") == "serviceAccount"
        assert core.principal_type("service-123@gcp-sa-bigquerydatatransfer.iam.gserviceaccount.com") \
            == "serviceAgent"
        assert core.principal_type("123@cloudservices.gserviceaccount.com") == "serviceAgent"


class TestClassifyMember:
    @pytest.mark.parametrize("member, expected", [
        ("user:Alice@x.com", ("alice@x.com", "user")),
        ("user:etl@p.iam.gserviceaccount.com", ("etl@p.iam.gserviceaccount.com", "serviceAccount")),
        ("serviceAccount:etl@p.iam.gserviceaccount.com", ("etl@p.iam.gserviceaccount.com", "serviceAccount")),
        ("serviceAccount:service-1@gcp-sa-bigquery.iam.gserviceaccount.com",
         ("service-1@gcp-sa-bigquery.iam.gserviceaccount.com", "serviceAgent")),
        ("group:G@x.com", ("g@x.com", "group")),
        ("domain:Trip.com", ("trip.com", "domain")),
        ("allUsers", ("allUsers", "public")),
        ("allAuthenticatedUsers", ("allAuthenticatedUsers", "public")),
        ("principal://iam.googleapis.com/locations/global/workforcePools/p/subject/u",
         ("principal://iam.googleapis.com/locations/global/workforcePools/p/subject/u", "federated")),
        ("principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*",
         ("principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*", "federated")),
        ("deleted:user:old@x.com?uid=1", ("deleted:user:old@x.com?uid=1", "deleted")),
        ("deleted:serviceAccount:s@p.iam.gserviceaccount.com?uid=2",
         ("deleted:serviceAccount:s@p.iam.gserviceaccount.com?uid=2", "deleted")),
    ])
    def test_kinds(self, member, expected):
        assert core.classify_member(member) == expected

    @pytest.mark.parametrize("member", ["projectOwner:p", "projectEditor:p", "projectViewer:p", "", "  ",
                                        "user:", "weird", "unknownPrefix:x"])
    def test_skipped(self, member):
        assert core.classify_member(member) is None


class TestBindingMembers:
    """IAM 策略 bindings -> [(值, 类型, 来源)]；不看角色，全部纳入。"""

    def test_all_roles_and_member_types_with_source(self):
        bindings = [
            {"role": "roles/viewer", "members": ["user:A@x.com", "deleted:user:gone@x.com?uid=1", "domain:x.com"]},
            {"role": "roles/storage.admin", "members": ["user:gcs@x.com", "group:G@x.com", "allUsers"]},
            {"role": "roles/bigquery.dataViewer", "members": ["user:cond@x.com"],
             "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}},
            {"role": "roles/browser", "members": ["projectViewer:p", "principalSet://iam.googleapis.com/x"]},
        ]
        got = core.binding_members(bindings, "项目 IAM p")
        assert got == [
            ("a@x.com", "user", "项目 IAM p: roles/viewer"),
            ("deleted:user:gone@x.com?uid=1", "deleted", "项目 IAM p: roles/viewer"),
            ("x.com", "domain", "项目 IAM p: roles/viewer"),
            ("gcs@x.com", "user", "项目 IAM p: roles/storage.admin"),
            ("g@x.com", "group", "项目 IAM p: roles/storage.admin"),
            ("allUsers", "public", "项目 IAM p: roles/storage.admin"),
            ("cond@x.com", "user", "项目 IAM p: roles/bigquery.dataViewer（带条件）"),
            ("principalSet://iam.googleapis.com/x", "federated", "项目 IAM p: roles/browser")]

    def test_missing_role_still_listed(self):
        assert core.binding_members([{"members": ["user:a@x.com"]}], "组织 IAM") == [("a@x.com", "user", "组织 IAM: ?")]


class TestDatasetAcl:
    def test_all_entries_regardless_of_role(self):
        entries = [
            ("READER", "userByEmail", "Alice@x.com"),
            ("WRITER", "userByEmail", "etl@p.iam.gserviceaccount.com"),
            ("OWNER", "groupByEmail", "G@x.com"),
            ("roles/bigquery.dataViewer", "iamMember", "user:bob@x.com"),
            ("roles/bigquery.dataViewer", "iamMember", "principal://iam.googleapis.com/x"),
            ("roles/bigquery.metadataViewer", "userByEmail", "meta@x.com"),          # 读不到数据，也列出
            ("READER", "specialGroup", "projectReaders"),                            # 等同项目 Viewer，跳过
            ("READER", "specialGroup", "allAuthenticatedUsers"),
            ("READER", "domain", "X.com"),
            (None, "view", {"projectId": "p", "datasetId": "d", "tableId": "v"}),
            (None, "routine", {"projectId": "p", "datasetId": "d", "routineId": "r"}),
            (None, "dataset", {"dataset": {"projectId": "p", "datasetId": "d2"}}),
        ]
        got = core.acl_members(entries, "数据集 ACL p.d")
        assert got == [
            ("alice@x.com", "user", "数据集 ACL p.d: READER"),
            ("etl@p.iam.gserviceaccount.com", "serviceAccount", "数据集 ACL p.d: WRITER"),
            ("g@x.com", "group", "数据集 ACL p.d: OWNER"),
            ("bob@x.com", "user", "数据集 ACL p.d: roles/bigquery.dataViewer"),
            ("principal://iam.googleapis.com/x", "federated", "数据集 ACL p.d: roles/bigquery.dataViewer"),
            ("meta@x.com", "user", "数据集 ACL p.d: roles/bigquery.metadataViewer"),
            ("allAuthenticatedUsers", "public", "数据集 ACL p.d: READER"),
            ("x.com", "domain", "数据集 ACL p.d: READER")]


class TestFormatSources:
    def test_order_dedup_and_note(self):
        s = core.format_sources({"Group 成员: b@x.com", "项目 IAM p: roles/viewer", "账号目录", "组织 IAM: roles/browser",
                                 "数据集 ACL p.d: READER", "项目 IAM p: roles/viewer"})
        assert s == "账号目录；组织 IAM: roles/browser；项目 IAM p: roles/viewer；数据集 ACL p.d: READER；Group 成员: b@x.com"
        assert core.format_sources({"数据集 ACL p.d: READER"}, note="外部域，未展开") == "数据集 ACL p.d: READER（外部域，未展开）"

    def test_limit_five(self):
        srcs = {f"表 IAM p.d.t{i}: roles/bigquery.dataViewer" for i in range(8)} | {"项目 SA: p"}
        s = core.format_sources(srcs)
        assert s.startswith("项目 SA: p；表 IAM p.d.t0") and s.endswith("；…共 9 处") and s.count("；") == 5


class TestPrincipalRows:
    def book(self, *items):
        b = core.PrincipalBook()
        for it in items:
            b.add(*it)
        return b

    def test_columns_types_sources_and_sorting(self):
        b = self.book(("zed@x.com", "user", "账号目录"), ("etl@prod.iam.gserviceaccount.com", "serviceAccount", "项目 SA: prod"),
                      ("etl@prod.iam.gserviceaccount.com", "serviceAccount", "项目 IAM prod: roles/bigquery.dataEditor"),
                      ("trip.com", "domain", "表 IAM p.d.t: roles/bigquery.dataViewer"))
        rows = core.build_principal_rows(b)
        assert list(rows[0]) == core.PRINCIPAL_COLUMNS == ["email", "principal_type", "source"]
        assert rows == [
            {"email": "etl@prod.iam.gserviceaccount.com", "principal_type": "serviceAccount",
             "source": "项目 SA: prod；项目 IAM prod: roles/bigquery.dataEditor"},
            {"email": "trip.com", "principal_type": "domain", "source": "表 IAM p.d.t: roles/bigquery.dataViewer"},
            {"email": "zed@x.com", "principal_type": "user", "source": "账号目录"}]

    def test_group_type_wins_and_note(self):
        b = self.book(("g@x.com", "user", "数据集 ACL p.d: READER"), ("g@x.com", "group", "账号目录 Group"))
        b.add("g@x.com", "user", "Group 成员: h@x.com")
        b.note("g@x.com", "未能展开")
        assert core.build_principal_rows(b) == [{"email": "g@x.com", "principal_type": "group",
                                                 "source": "账号目录 Group；数据集 ACL p.d: READER；Group 成员: h@x.com（未能展开）"}]

    def test_exclude_members_and_patterns(self):
        b = self.book(("copilot-api@p.iam.gserviceaccount.com", "serviceAccount", "项目 SA: p"),
                      ("copilot-u1@p.iam.gserviceaccount.com", "serviceAccount", "项目 SA: p"),
                      ("keep@x.com", "user", "账号目录"), ("allUsers", "public", "组织 IAM: roles/viewer"))
        rows = core.build_principal_rows(b, exclude_members=["Copilot-API@p.iam.gserviceaccount.com", "ALLUSERS"],
                                         exclude_patterns=["copilot-u*@*"])
        assert [r["email"] for r in rows] == ["keep@x.com"]


class TestAuthorizedRefs:
    def test_view_routine_dataset_refs(self):
        entries = [("READER", "userByEmail", "a@x.com"),
                   ("READER", "specialGroup", "projectReaders"),
                   (None, "view", {"projectId": "p2", "datasetId": "d2", "tableId": "v"}),
                   (None, "routine", {"projectId": "p3", "datasetId": "d3", "routineId": "r"}),
                   (None, "dataset", {"dataset": {"projectId": "p4", "datasetId": "d4"}, "targetTypes": ["VIEWS"]}),
                   (None, "view", "not-a-dict"), (None, "view", {"datasetId": "x"})]
        assert core.authorized_refs(entries) == [("授权视图", "p2.d2.v", "p2"), ("授权例程", "p3.d3.r", "p3"),
                                                 ("授权数据集", "p4.d4", "p4")]


class TestOwnDomain:
    def test_email_domain(self):
        assert core.email_domain("User@Trip.COM") == "trip.com"
        assert core.email_domain("group:bi@ctrip.com") == "ctrip.com"
        assert core.email_domain("nodomain") == ""

    def test_is_own_domain_exact_match_only(self):
        own = {"trip.com", "ctrip.com"}
        assert core.is_own_domain("bi@TRIP.com", own) and core.is_own_domain("x@ctrip.com", own)
        assert not core.is_own_domain("x@sub.trip.com", own)          # 子域名不算
        assert not core.is_own_domain("x@nottrip.com", own)
        assert not core.is_own_domain("x@trip.com", set()) and not core.is_own_domain("", own)


class TestPrincipalColumns:
    def test_three_columns(self):
        assert core.PRINCIPAL_COLUMNS == ["email", "principal_type", "source"]   # source 取代 home_project


# --------------------------------------------------------------------------- #
# DDL 生成
# --------------------------------------------------------------------------- #
class TestPolicyDdl:
    def test_basic(self):
        ddl = core.build_policy_ddl("p.d.t", "pol", ["group:g@x.com"], "TRUE")
        assert ddl == ("CREATE OR REPLACE ROW ACCESS POLICY `pol`\nON `p.d.t`\n"
                       'GRANT TO ("group:g@x.com")\nFILTER USING (TRUE)')

    def test_rejects_bad_policy_name(self):
        with pytest.raises(ValueError):
            core.build_policy_ddl("p.d.t", "bad-name", ["group:g@x.com"], "TRUE")

    def test_rejects_name_starting_with_digit(self):
        with pytest.raises(ValueError):
            core.build_policy_ddl("p.d.t", "1abc", ["group:g@x.com"], "TRUE")

    def test_rejects_injected_grantee(self):
        with pytest.raises(ValueError):
            core.build_policy_ddl("p.d.t", "pol", ['group:g@x.com") FILTER USING (TRUE); --'], "TRUE")

    def test_rejects_empty_grantees(self):
        with pytest.raises(ValueError):
            core.build_policy_ddl("p.d.t", "pol", [], "TRUE")


class TestConditionDimensions:
    ST = ("status", "INT64", "NULLABLE")

    def test_dimensions_are_columns_except_id_sa_status(self):
        fields = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), self.ST,
                  ("region", "STRING", "REPEATED"), ("prdtype", "STRING", "REPEATED"),
                  ("refername", "STRING", "REPEATED")]
        dims, warns, notes = core.condition_dimensions(fields)
        assert dims == ["region", "prdtype", "refername"] and warns == [] and notes == []   # status 不再提示

    def test_new_dimension_picked_up_automatically(self):
        fields = [("id", "STRING", "NULLABLE"), ("SA", "STRING", "NULLABLE"), ("Status", "INTEGER", "NULLABLE"),
                  ("region", "STRING", "REPEATED"), ("channel", "STRING", "REPEATED")]
        dims, _, _ = core.condition_dimensions(fields)
        assert dims == ["region", "channel"]

    def test_non_array_column_excluded_with_note_not_warning(self):
        # 普通的非数组列（如 updated_at）是正常情况：提示（[NOTE]），不是警告；status 是固定列，不提示
        fields = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"),
                  ("region", "STRING", "REPEATED"), ("updated_at", "TIMESTAMP", "NULLABLE"), ("status", "INTEGER", "NULLABLE")]
        dims, warns, notes = core.condition_dimensions(fields)
        assert dims == ["region"] and warns == [] and len(notes) == 1 and "updated_at" in notes[0]

    def test_special_char_column_is_still_warning(self):
        fields = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), self.ST, ("odd col", "STRING", "REPEATED")]
        dims, warns, notes = core.condition_dimensions(fields)
        assert dims == [] and len(warns) == 1 and "含有特殊字符" in warns[0] and notes == []

    def test_requires_sa_column(self):
        with pytest.raises(core.ConditionSchemaError, match="sa"):
            core.condition_dimensions([("id", "STRING", "NULLABLE"), self.ST, ("region", "STRING", "REPEATED")])

    def test_requires_status_column(self):
        with pytest.raises(core.ConditionSchemaError, match="缺少 status 列"):
            core.condition_dimensions([("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"),
                                       ("region", "STRING", "REPEATED")])

    @pytest.mark.parametrize("ftype, mode", [("STRING", "NULLABLE"), ("BOOL", "NULLABLE"), ("FLOAT64", "NULLABLE"),
                                             ("INT64", "REPEATED")])
    def test_status_must_be_int64(self, ftype, mode):
        with pytest.raises(core.ConditionSchemaError, match="应为 INT64"):
            core.condition_dimensions([("sa", "STRING", "NULLABLE"), ("status", ftype, mode),
                                       ("region", "STRING", "REPEATED")])

    @pytest.mark.parametrize("ftype", ["INT64", "INTEGER"])
    def test_status_int64_aliases_accepted(self, ftype):
        dims, _, _ = core.condition_dimensions([("sa", "STRING", "REQUIRED"), ("status", ftype, "REQUIRED"),
                                                ("region", "STRING", "REPEATED")])
        assert dims == ["region"]


class TestSelectCopilotTables:
    DIMS = ["region", "prdtype", "refername"]

    def test_selects_by_to_name_only(self):
        rows = [{"table_name": "p.dw.t1", "col_name": "region", "to_name": "region"},
                {"table_name": "p.dw.t2", "col_name": "market", "to_name": "region"},
                {"table_name": "p.dw.t2", "col_name": "prd_type", "to_name": "PRDTYPE"}]
        mapping, ignored = core.select_copilot_tables(rows, self.DIMS)
        assert mapping == {"p.dw.t1": [("region", "region")],
                           "p.dw.t2": [("market", "region"), ("prd_type", "prdtype")]}
        assert ignored == []

    def test_invalid_to_name_row_ignored_but_table_kept(self):
        rows = [{"table_name": "p.dw.t1", "col_name": "region", "to_name": "region"},
                {"table_name": "p.dw.t1", "col_name": "x", "to_name": "regoin"}]
        mapping, ignored = core.select_copilot_tables(rows, self.DIMS)
        assert mapping == {"p.dw.t1": [("region", "region")]}
        assert len(ignored) == 1 and "regoin" in ignored[0]

    def test_table_with_only_invalid_rows_ignored(self):
        rows = [{"table_name": "p.dw.t3", "col_name": "x", "to_name": "foo"}]
        mapping, ignored = core.select_copilot_tables(rows, self.DIMS)
        assert mapping == {} and len(ignored) == 1

    def test_dataset_table_uses_default_project(self):
        rows = [{"table_name": "dw.t1", "col_name": "region", "to_name": "region"}]
        mapping, _ = core.select_copilot_tables(rows, self.DIMS, default_project="p")
        assert list(mapping) == ["p.dw.t1"]

    def test_duplicate_rows_deduplicated(self):
        rows = [{"table_name": "p.dw.t1", "col_name": "region", "to_name": "region"}] * 2
        mapping, _ = core.select_copilot_tables(rows, self.DIMS)
        assert mapping == {"p.dw.t1": [("region", "region")]}

    def test_bad_column_name_reported(self):
        rows = [{"table_name": "p.dw.t1", "col_name": "region; DROP", "to_name": "region"}]
        mapping, ignored = core.select_copilot_tables(rows, self.DIMS)
        assert mapping == {} and len(ignored) == 1


class TestCopilotFilter:
    def test_single_dimension_with_different_column_name(self):
        flt = core.build_copilot_filter([("market", "region")], COND)
        assert flt == (
            f"(`market` IN (SELECT v FROM `{COND}` AS c, UNNEST(c.region) AS v "
            f"WHERE c.status = 1 AND c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `{COND}` AS c "
            f"WHERE c.status = 1 AND c.sa = SESSION_USER() AND (c.region IS NULL OR ARRAY_LENGTH(c.region) = 0)))")

    def test_every_subquery_requires_status_1(self):
        flt = core.build_copilot_filter([("region", "region"), ("prd_type", "prdtype"), ("ref", "refername")], COND)
        assert flt.count("WHERE c.status = 1 AND c.sa = SESSION_USER()") == 6       # 3 个维度 × (IN + EXISTS)
        assert flt.count("c.sa = SESSION_USER()") == 6

    def test_multiple_dimensions_and(self):
        flt = core.build_copilot_filter([("region", "region"), ("prd_type", "prdtype")], COND)
        assert flt.count(")) AND (") == 1 and ")) AND (`prd_type` IN" in flt
        assert flt.startswith("(`region` IN") and "UNNEST(c.prdtype)" in flt

    def test_new_dimension_allowed(self):
        flt = core.build_copilot_filter([("ch", "channel")], COND)
        assert "UNNEST(c.channel)" in flt

    def test_non_string_column_cast(self):
        flt = core.build_copilot_filter([("region_id", "region")], COND, column_types={"region_id": "INT64"})
        assert "CAST(`region_id` AS STRING) IN" in flt

    def test_nested_column(self):
        flt = core.build_copilot_filter([("meta.ref", "refername")], COND)
        assert "`meta`.`ref` IN" in flt

    def test_rejects_bad_dimension_identifier(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([("region", "region) OR TRUE --")], COND)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            core.build_copilot_filter([], COND)


class TestSchemaValidation:
    class F:
        def __init__(self, name, field_type, mode="NULLABLE", fields=()):
            self.name, self.field_type, self.mode, self.fields = name, field_type, mode, list(fields)

    def schema(self):
        F = self.F
        return core.flatten_schema([
            F("region", "STRING"), F("region_id", "INTEGER"), F("tags", "STRING", "REPEATED"),
            F("meta", "RECORD", fields=[F("ref", "STRING")]), F("amount", "FLOAT")])

    def test_ok(self):
        assert core.validate_mapping_against_schema([("region", "region"), ("meta.ref", "refername"),
                                                     ("region_id", "region")], self.schema()) == []

    def test_errors(self):
        errs = core.validate_mapping_against_schema(
            [("nope", "region"), ("tags", "region"), ("meta", "region"), ("amount", "region")], self.schema())
        assert len(errs) == 4


class TestNormalizeFilter:
    def test_bigquery_reformatting_equal(self):
        a = core.build_copilot_filter([("region", "region")], COND)
        b = a.replace("`", "").replace("EXISTS (", "EXISTS(").replace(" AS c", "  AS  c\n")
        assert core.normalize_filter(a) == core.normalize_filter(b)

    def test_literals_case_sensitive(self):
        assert core.normalize_filter("x = 'HK'") != core.normalize_filter("x = 'hk'")

    def test_true(self):
        assert core.normalize_filter("true") == "TRUE"


# --------------------------------------------------------------------------- #
# 计划：CREATE / NOOP / REPLACE / COLLISION
# --------------------------------------------------------------------------- #
class TestPlanUpsert:
    G = "group:g@x.com"

    def test_create(self):
        pl = core.plan_upsert([], "pol", "TRUE", [self.G])
        assert pl.action == "create" and pl.first_policy

    def test_create_not_first_when_other_policies_exist(self):
        pl = core.plan_upsert([{"id": "other", "filter": "TRUE", "grantees": ["group:o@x.com"]}],
                              "pol", "TRUE", [self.G])
        assert pl.action == "create" and not pl.first_policy

    def test_noop_when_same(self):
        pl = core.plan_upsert([{"id": "pol", "filter": "true", "grantees": ["group:G@x.com"]}],
                              "pol", "TRUE", [self.G])
        assert pl.action == "noop"

    def test_replace_when_filter_differs_keeps_old(self):
        old = {"id": "pol", "filter": "region = 'HK'", "grantees": [self.G]}
        pl = core.plan_upsert([old], "pol", "TRUE", [self.G])
        assert pl.action == "replace" and pl.old == old

    def test_replace_when_grantees_differ(self):
        pl = core.plan_upsert([{"id": "pol", "filter": "TRUE", "grantees": [self.G, "user:x@x.com"]}],
                              "pol", "TRUE", [self.G])
        assert pl.action == "replace"

    def test_collision_when_same_name_belongs_to_other_principal(self):
        pl = core.plan_upsert([{"id": "pol", "filter": "TRUE", "grantees": ["user:a_b@x.com"]}],
                              "pol", "TRUE", ["user:a.b@x.com"], check_collision=True)
        assert pl.action == "collision" and "a_b@x.com" in pl.reason

    def test_no_collision_check_means_replace(self):
        pl = core.plan_upsert([{"id": "pol", "filter": "TRUE", "grantees": ["user:a_b@x.com"]}],
                              "pol", "TRUE", ["user:a.b@x.com"])
        assert pl.action == "replace"


class TestPolicyLimit:
    def test_remaining_slots(self):
        assert core.remaining_policy_slots(398) == 2
        assert core.remaining_policy_slots(400) == 0
        assert core.remaining_policy_slots(450) == 0


# --------------------------------------------------------------------------- #
# 回退计划
# --------------------------------------------------------------------------- #
P_BYP_R = {"id": "rls_bypass_full_access_r_x_com", "filter": "TRUE", "grantees": ["group:r@x.com"]}
P_BYP_W = {"id": "rls_bypass_full_access_w_x_com", "filter": "TRUE", "grantees": ["group:w@x.com"]}
P_COP_A = {"id": "rls_copilot_a_x_com", "filter": "f", "grantees": ["user:a@x.com"]}
P_COP_S = {"id": "rls_copilot_s_p_iam_gserviceaccount_com", "filter": "f",
           "grantees": ["serviceAccount:s@p.iam.gserviceaccount.com"]}
ALL = [P_BYP_R, P_BYP_W, P_COP_A, P_COP_S]


class TestPlanRollback:
    def test_by_principal_matches_any_type(self):
        plan = core.plan_rollback(ALL, principals={"R@x.com", "s@p.iam.gserviceaccount.com"})
        assert [p["id"] for p in plan.to_drop] == [P_BYP_R["id"], P_COP_S["id"]]
        assert not plan.drop_all

    def test_user_principal_only_removes_own_rule(self):
        plan = core.plan_rollback(ALL, principals={"a@x.com"})
        assert [p["id"] for p in plan.to_drop] == [P_COP_A["id"]]

    def test_by_policy_name(self):
        plan = core.plan_rollback(ALL, policy_names={P_COP_A["id"]})
        assert [p["id"] for p in plan.to_drop] == [P_COP_A["id"]]

    def test_intersection(self):
        plan = core.plan_rollback(ALL, principals={"a@x.com", "r@x.com"}, policy_names={P_BYP_R["id"]})
        assert [p["id"] for p in plan.to_drop] == [P_BYP_R["id"]]

    def test_all_policies(self):
        plan = core.plan_rollback(ALL)
        assert len(plan.to_drop) == 4 and plan.drop_all

    def test_drop_all_when_selection_covers_every_policy(self):
        plan = core.plan_rollback([P_COP_A], principals={"a@x.com"})
        assert plan.drop_all

    def test_no_match(self):
        plan = core.plan_rollback(ALL, principals={"nobody@x.com"})
        assert plan.to_drop == [] and not plan.drop_all


# --------------------------------------------------------------------------- #
# 挂载后验证 SQL
# --------------------------------------------------------------------------- #
class TestVisibilityProbeSql:
    def test_sample(self):
        assert core.visibility_probe_sql("p.d.t", None) == "SELECT 1 FROM `p.d.t` LIMIT 1"

    def test_count(self):
        assert core.visibility_probe_sql("p.d.t", None, mode="count") == "SELECT COUNT(*) AS n FROM `p.d.t`"

    def test_partition_filter(self):
        sql = core.visibility_probe_sql("p.d.t", {"require_filter": True, "field": "dt"})
        assert "WHERE `dt` IS NOT NULL" in sql

    def test_ingestion_time_partition(self):
        sql = core.visibility_probe_sql("p.d.t", {"require_filter": True, "field": None})
        assert "_PARTITIONTIME IS NOT NULL" in sql


# --------------------------------------------------------------------------- #
# Copilot 审核 CSV
# --------------------------------------------------------------------------- #
class TestCopilotPlanCsvRows:
    def test_columns(self):
        assert core.COPILOT_PLAN_COLUMNS == ["table", "policy_name", "action", "dimensions", "filter", "note"]
        assert core.COPILOT_PLAN_COLUMNS_APPLY == core.COPILOT_PLAN_COLUMNS + ["result"]


class TestRegistry:
    """apply_bypass_rls.py 的登记表（adm_user_mem_copilot_tb）判定。"""

    def test_status_enabled_disabled_conflict(self):
        rows = [{"table_name": "p.d.a", "rls_enabled": 1},
                {"table_name": "p.d.b", "rls_enabled": 0},
                {"table_name": "p.d.c", "rls_enabled": 1}, {"table_name": "p.d.c", "rls_enabled": 0},
                {"table_name": "p.d.d", "rls_enabled": 1}, {"table_name": "p.d.d", "rls_enabled": 1},
                {"table_name": "p.d.e", "rls_enabled": None}, {"table_name": "p.d.e", "rls_enabled": 2}]
        st = core.registry_status(rows)
        assert st == {"p.d.a": "enabled", "p.d.b": "disabled", "p.d.c": "conflict", "p.d.d": "enabled",
                      "p.d.e": "disabled"}

    def test_names_compared_raw(self):
        st = core.registry_status([{"table_name": " p.d.a", "rls_enabled": 1}, {"table_name": "P.d.a", "rls_enabled": 1}])
        assert "p.d.a" not in st and st[" p.d.a"] == "enabled" and st["P.d.a"] == "enabled"

    def test_bool_true_is_not_one(self):
        assert core.registry_status([{"table_name": "p.d.a", "rls_enabled": True}])["p.d.a"] == "disabled"

    def test_null_table_name_ignored(self):
        assert core.registry_status([{"table_name": None, "rls_enabled": 1}]) == {}

    @pytest.mark.parametrize("fields", [
        [("table_name", "STRING", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],
        [("table_name", "STRING", "NULLABLE"), ("rls_enabled", "INT64", "NULLABLE"), ("status", "INTEGER", "REQUIRED")],
    ])
    def test_validate_fields_ok(self, fields):
        core.validate_registry_fields(fields)

    @pytest.mark.parametrize("fields", [
        [("rls_enabled", "INTEGER", "REQUIRED")],
        [("table_name", "STRING", "REQUIRED")],
        [("table_name", "STRING", "REQUIRED"), ("rls_enabled", "FLOAT", "REQUIRED")],
        [("table_name", "BYTES", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED")],
        [("table_name", "STRING", "REQUIRED"), ("rls_enabled", "INTEGER", "REPEATED")],
    ])
    def test_validate_fields_bad(self, fields):
        with pytest.raises(ValueError):
            core.validate_registry_fields(fields)
