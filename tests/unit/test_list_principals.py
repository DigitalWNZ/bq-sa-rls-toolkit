"""
list_principals.py 新方案（2026-10-18）：列出指定项目 / 组织下的所有 SA 和 user，不能遗漏，全部使用权威 API。
  来源 1  SA 清单：范围内每个 ACTIVE 项目 IAM serviceAccounts.list（含无授权 / 已禁用）；组织范围先递归列出文件夹 / 项目
  来源 2  账号目录：只在组织范围，用执行账号自己的凭证调用 Admin SDK Directory 列出该组织全部 user（含暂停 / 归档）；
          执行账号需为有「用户 → 读取」权限的 Workspace / Cloud Identity 管理员；读不到 [ERROR]、其余照写、退出码 1
  来源 3  BQ 相关授权：组织 / 文件夹 / 项目 getIamPolicy（只指定项目时不读上层）、数据集 ACL、每张表 getIamPolicy；
          只纳入含 bigquery.tables.getData 的角色（自定义角色读权限列表；读不到角色定义时宁可多列并 [WARN]）；Group 递归展开
  不再调用 Cloud Asset；输出 3 列 email, principal_type, home_project。
"""

import csv

import pytest

import gcp_ops as ops
import list_principals
from tests.unit.fakes import FakeWorld, install

ORG, ORG2 = "111", "222"
CUST = "C0trip"
P1, P2, P3, P_DEL, P_OUT = "prod", "dev", "deep", "old-proj", "outside"
F1, F2 = "folders/10", "folders/20"


def b(role, *members):
    return {"role": role, "members": list(members)}


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    # 组织 111：prod 直接在组织下；dev 在 folders/10 下；deep 在 folders/10/folders/20 下；old-proj 待删除
    w.crm_children[f"organizations/{ORG}"] = {"folders": [F1], "projects": [(P1, "ACTIVE"), (P_DEL, "DELETE_REQUESTED")]}
    w.crm_children[F1] = {"folders": [F2], "projects": [(P2, "ACTIVE")]}
    w.crm_children[F2] = {"folders": [], "projects": [(P3, "ACTIVE")]}
    w.org_customer[ORG] = CUST
    # 来源 1：各项目自己的 SA（含没有任何授权的）
    w.project_sas[P1] = ["etl@prod.iam.gserviceaccount.com", "idle@prod.iam.gserviceaccount.com",
                         "disabled-sa@prod.iam.gserviceaccount.com"]
    w.project_sas[P2] = ["dev-sa@dev.iam.gserviceaccount.com"]
    w.project_sas[P3] = ["deep-sa@deep.iam.gserviceaccount.com"]
    w.project_sas[P_DEL] = ["ghost@old-proj.iam.gserviceaccount.com"]
    w.project_sas[P_OUT] = ["outsider@outside.iam.gserviceaccount.com"]
    # 来源 2：账号目录（含没有任何授权的 user、暂停 / 归档的 user、第二域名）
    w.directory[CUST] = ["alice@trip.com", "dave@trip.com", "suspended@trip.com", "archived@trip.com", "eve@ctrip.com"]
    # 来源 3：授权
    w.iam_policies[f"organizations/{ORG}"] = [b("roles/bigquery.dataViewer", "user:orgreader@partner.com"),
                                              b("roles/storage.admin", "user:gcs-only@partner.com")]
    w.iam_policies[F1] = [b("roles/viewer", "serviceAccount:folder-sa@other.iam.gserviceaccount.com")]
    w.iam_policies[f"projects/{P1}"] = [
        b("roles/bigquery.dataViewer", "serviceAccount:ext@partner-proj.iam.gserviceaccount.com",
          "group:bi-team@trip.com", "deleted:user:gone@trip.com?uid=1", "domain:trip.com", "allUsers"),
        b("roles/bigquery.jobUser", "user:jobonly@partner.com"),                         # 不能读数据
        b("projects/prod/roles/customReader", "user:custom@partner.com"),               # 自定义角色含 getData
        b("organizations/111/roles/customMeta", "user:custommeta@partner.com"),         # 自定义角色不含 getData
        b("roles/owner", "user:Owner@Vendor.com"),
    ]
    w.iam_policies[f"projects/{P2}"] = []
    w.iam_policies[f"projects/{P3}"] = []
    w.role_perms["projects/prod/roles/customReader"] = {"bigquery.tables.getData", "bigquery.tables.get"}
    w.role_perms["organizations/111/roles/customMeta"] = {"bigquery.tables.get"}
    # 数据集 ACL（旧式角色 / 预定义角色 / iamMember / 特殊条目）
    w.add_table("prod.dw.orders", rls_enabled=None)
    w.add_table("prod.dw.orders_view", rls_enabled=None)
    w.add_table("dev.sandbox.t1", rls_enabled=None)
    w.dataset_acl["prod.dw"] = [("READER", "userByEmail", "acl-reader@partner.com"),
                                ("WRITER", "groupByEmail", "acl-g@trip.com"),
                                ("roles/bigquery.metadataViewer", "userByEmail", "meta@partner.com"),
                                ("roles/bigquery.dataViewer", "iamMember", "serviceAccount:svc@p9.iam.gserviceaccount.com"),
                                ("READER", "specialGroup", "projectReaders"),
                                (None, "view", {"projectId": "prod", "datasetId": "dw", "tableId": "v"})]
    w.dataset_acl["dev.sandbox"] = []
    # 表级 IAM
    w.table_iam["prod.dw.orders"] = [b("roles/bigquery.dataViewer", "user:table-reader@vendor.com"),
                                     b("roles/bigquery.metadataViewer", "user:table-meta@vendor.com")]
    w.table_iam["prod.dw.orders_view"] = [b("roles/bigquery.dataViewer", "serviceAccount:view-sa@p8.iam.gserviceaccount.com")]
    # Group
    w.groups["bi-team@trip.com"] = [("ana@trip.com", "USER"), ("nested@trip.com", "GROUP")]
    w.groups["nested@trip.com"] = [("svc-in-group@p7.iam.gserviceaccount.com", "SERVICE_ACCOUNT")]
    w.groups["acl-g@trip.com"] = [("carol@vendor.com", "USER"), ("ext-g@other.com", "GROUP")]
    w.groups["ext-g@other.com"] = None
    install(monkeypatch, w, list_principals)
    return w


def run(tmp_path, *args, name="principals.csv"):
    out = tmp_path / name
    code = list_principals.main([*args, "-o", str(out)])
    rows = read_csv(out) if out.exists() else []
    return code, {r["email"]: r for r in rows}, out


ORG_EXPECTED = {
    # 来源 1：所有 ACTIVE 项目的 SA（含无授权 / 已禁用；多层文件夹）
    "etl@prod.iam.gserviceaccount.com", "idle@prod.iam.gserviceaccount.com", "disabled-sa@prod.iam.gserviceaccount.com",
    "dev-sa@dev.iam.gserviceaccount.com", "deep-sa@deep.iam.gserviceaccount.com",
    # 来源 2：账号目录全部 user（含无授权 / 暂停 / 归档 / 第二域名）
    "alice@trip.com", "dave@trip.com", "suspended@trip.com", "archived@trip.com", "eve@ctrip.com",
    # 来源 3：BQ 相关授权（含 getData 的角色）
    "orgreader@partner.com",                                   # 组织层
    "folder-sa@other.iam.gserviceaccount.com",                 # 文件夹层（roles/viewer 含 getData）
    "ext@partner-proj.iam.gserviceaccount.com", "custom@partner.com", "owner@vendor.com",   # 项目层
    "acl-reader@partner.com", "svc@p9.iam.gserviceaccount.com",                           # 数据集 ACL
    "table-reader@vendor.com", "view-sa@p8.iam.gserviceaccount.com",                      # 表 / 视图 IAM
    "ana@trip.com", "svc-in-group@p7.iam.gserviceaccount.com", "carol@vendor.com",        # Group 展开（含嵌套）
}


# =========================================================================== #
# 正常系
# =========================================================================== #
class TestNormal:
    def test_lp_n_01_org_scope_lists_everything(self, world, tmp_path):
        code, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        assert code == 0 and set(rows) == ORG_EXPECTED

    def test_lp_n_02_sa_without_any_grant_listed(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert "idle@prod.iam.gserviceaccount.com" in rows and "disabled-sa@prod.iam.gserviceaccount.com" in rows

    def test_lp_n_03_directory_users_without_grant_listed_in_org_scope(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        for u in ("dave@trip.com", "suspended@trip.com", "archived@trip.com", "eve@ctrip.com"):
            assert rows[u]["principal_type"] == "user"

    def test_lp_n_04_project_scope_no_directory_no_ancestors(self, world, tmp_path):
        code, rows, _ = run(tmp_path, "--projects", P1)
        assert code == 0
        assert "dave@trip.com" not in rows                           # 不读账号目录
        assert "orgreader@partner.com" not in rows                   # 不读组织层授权
        assert "folder-sa@other.iam.gserviceaccount.com" not in rows
        assert "dev-sa@dev.iam.gserviceaccount.com" not in rows      # 其它项目的 SA 不在范围
        assert {"ext@partner-proj.iam.gserviceaccount.com", "acl-reader@partner.com", "table-reader@vendor.com",
                "ana@trip.com"} <= set(rows)
        assert world.calls["directory"] == 0

    def test_lp_n_05_role_filter_get_data_only(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        for gone in ("gcs-only@partner.com", "jobonly@partner.com", "custommeta@partner.com",
                     "meta@partner.com", "table-meta@vendor.com"):
            assert gone not in rows

    def test_lp_n_06_legacy_dataset_roles_mapped(self, world, tmp_path):
        world.dataset_acl["prod.dw"] += [("OWNER", "userByEmail", "dsowner@partner.com"),
                                         ("WRITER", "userByEmail", "dswriter@partner.com")]
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert {"dsowner@partner.com", "dswriter@partner.com", "acl-reader@partner.com"} <= set(rows)

    def test_lp_n_07_columns_and_types(self, world, tmp_path):
        _, rows, out = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        with open(out, encoding="utf-8-sig") as f:
            assert next(csv.reader(f)) == ["email", "principal_type", "home_project"]
        assert rows["etl@prod.iam.gserviceaccount.com"] == {"email": "etl@prod.iam.gserviceaccount.com",
                                                             "principal_type": "serviceAccount", "home_project": "prod"}
        assert rows["owner@vendor.com"] == {"email": "owner@vendor.com", "principal_type": "user", "home_project": ""}
        emails = [r["email"] for r in read_csv(out)]
        assert emails == sorted(emails)

    def test_lp_n_08_service_agent_from_grants(self, world, tmp_path):
        world.iam_policies[f"projects/{P1}"].append(
            b("roles/bigquery.dataViewer", "serviceAccount:service-1@gcp-sa-bigquery.iam.gserviceaccount.com"))
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert rows["service-1@gcp-sa-bigquery.iam.gserviceaccount.com"]["principal_type"] == "serviceAgent"

    def test_lp_n_09_inactive_projects_skipped_with_note(self, world, tmp_path, capsys):
        code, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        err = capsys.readouterr().err
        assert code == 0 and "ghost@old-proj.iam.gserviceaccount.com" not in rows
        assert "[NOTE]" in err and P_DEL in err

    def test_lp_n_10_org_and_project_overlap_dedup(self, world, tmp_path):
        _, r1, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q", name="a.csv")
        _, r2, _ = run(tmp_path, "--organizations", ORG, "--projects", P1, name="b.csv")
        assert set(r1) == set(r2)

    def test_lp_n_11_project_outside_org_added(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--organizations", ORG, "--projects", P_OUT)
        assert "outsider@outside.iam.gserviceaccount.com" in rows

    def test_lp_n_12_exclusions(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q",
                         "--exclude-members", "DAVE@trip.com", "--exclude-patterns", "*@prod.iam.gserviceaccount.com")
        assert "dave@trip.com" not in rows and not any(e.endswith("@prod.iam.gserviceaccount.com") for e in rows)
        assert "alice@trip.com" in rows

    def test_lp_n_13_files_with_bom_crlf(self, world, tmp_path):
        orgs = tmp_path / "orgs.csv"
        orgs.write_bytes(f"\ufeff{ORG}\r\n".encode("utf-8"))
        projects = tmp_path / "projects.csv"
        projects.write_text(f"  {P_OUT}  \r\n\r\n", encoding="utf-8")
        code, rows, _ = run(tmp_path, "--organizations", str(orgs), "--projects", str(projects))
        assert code == 0 and "dave@trip.com" in rows and "outsider@outside.iam.gserviceaccount.com" in rows

    def test_lp_n_14_parallel_levels_same_result(self, world, tmp_path):
        _, r1, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q", "--parallel", "1", name="a.csv")
        _, r32, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q", "--parallel", "32", name="b.csv")
        assert r1 == r32

    def test_lp_n_15_role_definitions_cached(self, world, tmp_path):
        world.table_iam["prod.dw.orders"] += [b("roles/bigquery.dataViewer", f"user:u{i}@vendor.com") for i in range(20)]
        run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        assert world.role_lookups["roles/bigquery.dataViewer"] == 1

    def test_lp_n_16_every_table_iam_read_including_views(self, world, tmp_path):
        run(tmp_path, "--projects", P1)
        assert world.calls["table_iam"] == 2

    def test_lp_n_17_default_output_file(self, world, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert list_principals.main(["--projects", P1]) == 0
        assert (tmp_path / "principals.csv").exists()

    def test_lp_n_18_project_number_scope(self, world, tmp_path):
        world.project_sas["123456789012"] = ["sa@p.iam.gserviceaccount.com"]
        world.iam_policies["projects/123456789012"] = []
        code, rows, _ = run(tmp_path, "--projects", "123456789012")
        assert code == 0 and "sa@p.iam.gserviceaccount.com" in rows

    def test_lp_n_19_conditional_bindings_included(self, world, tmp_path):
        world.iam_policies[f"projects/{P1}"].append(
            {"role": "roles/bigquery.dataViewer", "members": ["user:temp@vendor.com"],
             "condition": {"title": "until 2027", "expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}})
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert "temp@vendor.com" in rows

    def test_lp_n_20_no_cloud_asset_calls(self, world, tmp_path):
        for name in ("asset_search_service_accounts", "asset_search_iam_policies", "asset_search_datasets"):
            assert not hasattr(ops, name)
        run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        assert world.calls.get("asset", 0) == 0


# =========================================================================== #
# 异常系
# =========================================================================== #
class TestAbnormal:
    def test_lp_a_01_scope_required(self, world):
        with pytest.raises(SystemExit) as e:
            list_principals.main(["-o", "x.csv"])
        assert e.value.code == 2

    def test_lp_a_02_org_only_without_quota_project_uses_resolved_default(self, world, tmp_path):
        code, rows, _ = run(tmp_path, "--organizations", ORG)            # 不再要求 --quota-project
        assert code == 0 and "dave@trip.com" in rows

    @pytest.mark.parametrize("bad", ["abc", "12a", "organizations/x", "1;2"])
    def test_lp_a_03_bad_org_id(self, world, bad):
        with pytest.raises(SystemExit):
            list_principals.main(["--organizations", bad, "--quota-project", "q", "-o", "x.csv"])

    def test_lp_a_04_directory_unavailable_error_but_rest_written(self, world, tmp_path, capsys):
        world.directory_error = RuntimeError("403 Not Authorized to access this resource/api")
        code, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        err = capsys.readouterr().err
        assert code == 1 and "[ERROR]" in err and "用户 → 读取" in err and "管理员" in err
        assert "etl@prod.iam.gserviceaccount.com" in rows and "dave@trip.com" not in rows

    def test_lp_a_05_project_sa_list_failure_reported(self, world, tmp_path, capsys):
        world.fail_resources.add(f"sa:{P2}")
        code, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        err = capsys.readouterr().err
        assert code == 1 and P2 in err and "[ERROR]" in err
        assert "etl@prod.iam.gserviceaccount.com" in rows                   # 其它项目照常

    @pytest.mark.parametrize("res", [f"iam:organizations/{ORG}", f"iam:{F1}", f"iam:projects/{P1}",
                                     "datasets:prod", "acl:prod.dw", "tables:prod.dw", "table_iam:prod.dw.orders",
                                     f"crm:{F1}", f"customer:{ORG}"])
    def test_lp_a_06_any_read_failure_is_error_never_silent(self, world, tmp_path, capsys, res):
        world.fail_resources.add(res)
        code, _, out = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        assert code == 1 and "[ERROR]" in capsys.readouterr().err and out.exists()

    def test_lp_a_07_unknown_role_definition_included_with_warn(self, world, tmp_path, capsys):
        world.iam_policies[f"projects/{P1}"].append(b("projects/prod/roles/unreadable", "user:maybe@vendor.com"))
        world.role_errors.add("projects/prod/roles/unreadable")
        code, rows, _ = run(tmp_path, "--projects", P1)
        err = capsys.readouterr().err
        assert "maybe@vendor.com" in rows and "[WARN]" in err and "projects/prod/roles/unreadable" in err
        assert code == 0

    def test_lp_a_08_unresolvable_and_cyclic_groups(self, world, tmp_path, capsys):
        world.groups["bi-team@trip.com"].append(("bi-team@trip.com", "GROUP"))
        code, rows, _ = run(tmp_path, "--projects", P1)
        err = capsys.readouterr().err
        assert code == 0 and "ext-g@other.com" in err and "ana@trip.com" in rows

    def test_lp_a_09_csv_formula_injection_neutralized(self, world, tmp_path):
        world.dataset_acl["prod.dw"].append(("READER", "userByEmail", '=HYPERLINK("http://evil")@x.com'))
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert all(not e.startswith(("=", "+", "-", "@")) for e in rows)

    def test_lp_a_10_odd_members_skipped(self, world, tmp_path):
        world.iam_policies[f"projects/{P1}"].append(b("roles/bigquery.dataViewer", "allAuthenticatedUsers",
                                                      "principalSet://iam.googleapis.com/locations/global/workforcePools/p/*",
                                                      "projectViewer:prod", "deleted:serviceAccount:x@p.iam.gserviceaccount.com?uid=2"))
        code, rows, _ = run(tmp_path, "--projects", P1)
        assert code == 0 and not any("allauthenticated" in e or "principalset" in e or e.startswith("projectviewer") for e in rows)

    @pytest.mark.parametrize("pat", ["[", "*(", "\\", "?*[]"])
    def test_lp_a_11_exclude_pattern_weird_chars(self, world, tmp_path, pat):
        assert run(tmp_path, "--projects", P1, "--exclude-patterns", pat)[0] == 0

    def test_lp_a_12_empty_org(self, world, tmp_path):
        world.crm_children[f"organizations/{ORG2}"] = {"folders": [], "projects": []}
        world.org_customer[ORG2] = "C0empty"
        world.directory["C0empty"] = []
        code, rows, _ = run(tmp_path, "--organizations", ORG2, "--quota-project", "q")
        assert code == 0 and rows == {}

    def test_lp_a_13_removed_columns_flags_not_needed(self, world, tmp_path):
        _, rows, _ = run(tmp_path, "--projects", P1)
        assert all(set(r) == {"email", "principal_type", "home_project"} for r in rows.values())

    @pytest.mark.parametrize("flag", ["--folder", "--organization", "--group", "--include-iam-bound", "--copilot-members"])
    def test_lp_a_14_removed_or_abbreviated_flags_rejected(self, world, flag):
        with pytest.raises(SystemExit):
            list_principals.main(["--projects", P1, flag, "x", "-o", "x.csv"])


class TestDirectoryWithOwnCredentials:
    def test_lp_d_01_org_scope_reads_directory_with_executor_credentials(self, world, tmp_path):
        code, rows, _ = run(tmp_path, "--organizations", ORG, "--quota-project", "q")
        assert code == 0 and world.directory_calls == [CUST] and "dave@trip.com" in rows

    def test_lp_d_02_directory_sa_flag_removed(self, world):
        with pytest.raises(SystemExit) as e:
            list_principals.main(["--organizations", ORG, "--quota-project", "q",
                                  "--directory-sa", "x@p.iam.gserviceaccount.com", "-o", "x.csv"])
        assert e.value.code == 2

    def test_lp_d_03_project_scope_does_not_read_directory(self, world, tmp_path):
        code, _, _ = run(tmp_path, "--projects", P1)
        assert code == 0 and world.directory_calls == []

    def test_lp_d_04_one_directory_read_per_customer(self, world, tmp_path):
        world.crm_children[f"organizations/{ORG2}"] = {"folders": [], "projects": []}
        world.org_customer[ORG2] = CUST                         # 两个组织属于同一个账号目录
        run(tmp_path, "--organizations", f"{ORG},{ORG2}", "--quota-project", "q")
        assert world.directory_calls == [CUST]
