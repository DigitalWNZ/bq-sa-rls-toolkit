#!/usr/bin/env python3
"""
根据 bq_sa_audit.py 的输出，创建 Google Group、加入 SA，并为指定表添加 RLS（允许该 group 访问全部行）。

流程:
  1. 读取 bq_sa_audit.py 生成的 CSV，按 --members 选择 SA:
       all  -> 所有 SA
       bq   -> 仅 has_bq_permission = True 的 SA
       jobs -> 仅 has_submitted_jobs = True 的 SA
  2. 通过 Cloud Identity API 创建 group（已存在则复用）
  3. 把选中的 SA 加入 group（已是成员则跳过）
  4. 在目标表上创建 Row Access Policy:
       CREATE OR REPLACE ROW ACCESS POLICY <name> ON <table>
       GRANT TO ("group:<group>") FILTER USING (TRUE)
  5. 可选 --grant-table-viewer: 给 group 授予该表的 roles/bigquery.dataViewer
     （RLS 只过滤行，本身不授予读表权限）

默认是 dry-run，只打印将执行的操作；加 --apply 才真正执行。

示例:
  python setup_group_rls.py \\
      --audit-csv bq_sa_audit.csv --members bq \\
      --group-email bq-sa-all-rows@example.com \\
      --table my-project.my_dataset.my_table_rls_test \\
      --gcloud-account admin@example.com --grant-table-viewer

  # 确认无误后执行（表上原本无 RLS 时需加 --force-first-policy）
  python setup_group_rls.py ... --apply

所需权限:
  - Cloud Identity: Groups Admin（或对该 group 的 owner/manager 权限）
  - BigQuery: bigquery.rowAccessPolicies.create / update / list，bigquery.tables.setIamPolicy（可选）
"""

import argparse
import csv
import sys

from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from gcp_auth import get_credentials


def log(msg):
    print(msg, file=sys.stderr)


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes", "y")


# --------------------------------------------------------------------------- #
# 1. 读取 SA 列表
# --------------------------------------------------------------------------- #
def load_members(csv_path, mode):
    members = []
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if mode == "bq" and not truthy(row.get("has_bq_permission")):
                continue
            if mode == "jobs" and not truthy(row.get("has_submitted_jobs")):
                continue
            members.append(row["service_account"].strip().lower())
    # 去重并保持顺序
    return list(dict.fromkeys(m for m in members if m))


# --------------------------------------------------------------------------- #
# 2/3. Cloud Identity Group
# --------------------------------------------------------------------------- #
def resolve_customer_id(creds, project):
    """通过项目所属 Organization 获取 Cloud Identity customer ID（如 C0xxxxxx）。"""
    crm = discovery.build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)
    ancestry = crm.projects().getAncestry(projectId=project, body={}).execute()
    org = next((a["resourceId"]["id"] for a in ancestry.get("ancestor", [])
                if a["resourceId"]["type"] == "organization"), None)
    if not org:
        raise RuntimeError(f"项目 {project} 不在任何 Organization 下，请用 --customer-id 指定")
    info = crm.organizations().get(name=f"organizations/{org}").execute()
    return info["owner"]["directoryCustomerId"]


def lookup_group(ci, group_email):
    try:
        return ci.groups().lookup(groupKey_id=group_email).execute()["name"]
    except HttpError as e:
        if e.resp.status in (403, 404):
            return None
        raise


def ensure_group(ci, group_email, display_name, customer_id, apply):
    name = lookup_group(ci, group_email)
    if name:
        log(f"[GROUP] 已存在: {group_email} ({name})")
        return name
    log(f"[GROUP] 创建 {group_email} (parent=customers/{customer_id})")
    if not apply:
        return None
    body = {
        "parent": f"customers/{customer_id}",
        "groupKey": {"id": group_email},
        "displayName": display_name or group_email,
        "labels": {"cloudidentity.googleapis.com/groups.discussion_forum": ""},
    }
    ci.groups().create(body=body, initialGroupConfig="WITH_INITIAL_OWNER").execute()
    name = lookup_group(ci, group_email)
    if not name:
        raise RuntimeError(f"创建 group {group_email} 后无法查询到，请检查权限")
    log(f"  -> 创建成功: {name}")
    return name


def existing_members(ci, group_name):
    result = set()
    if not group_name:
        return result
    req = ci.groups().memberships().list(parent=group_name, pageSize=200)
    while req is not None:
        resp = req.execute()
        for m in resp.get("memberships", []):
            key = m.get("preferredMemberKey", {}).get("id")
            if key:
                result.add(key.lower())
        req = ci.groups().memberships().list_next(req, resp)
    return result


def add_members(ci, group_name, members, apply):
    current = existing_members(ci, group_name)
    added, skipped, failed = 0, 0, []
    for sa in members:
        if sa in current:
            skipped += 1
            continue
        log(f"[MEMBER] 添加 {sa}")
        if not apply:
            added += 1
            continue
        try:
            ci.groups().memberships().create(
                parent=group_name,
                body={"preferredMemberKey": {"id": sa}, "roles": [{"name": "MEMBER"}]},
            ).execute()
            added += 1
        except HttpError as e:
            if e.resp.status == 409:
                skipped += 1
            else:
                log(f"  [WARN] 添加 {sa} 失败: {e}")
                failed.append(sa)
    log(f"[MEMBER] 新增 {added}，已存在 {skipped}，失败 {len(failed)}")
    return failed


# --------------------------------------------------------------------------- #
# 4/5. BigQuery RLS
# --------------------------------------------------------------------------- #
def parse_table(table):
    parts = table.replace(":", ".").split(".")
    if len(parts) != 3:
        raise ValueError(f"表名格式应为 project.dataset.table，实际: {table}")
    return parts


def list_row_access_policies(creds, project, dataset, table):
    bqapi = discovery.build("bigquery", "v2", credentials=creds, cache_discovery=False)
    policies = []
    req = bqapi.rowAccessPolicies().list(projectId=project, datasetId=dataset, tableId=table)
    while req is not None:
        resp = req.execute()
        policies.extend(resp.get("rowAccessPolicies", []))
        req = bqapi.rowAccessPolicies().list_next(req, resp)
    return [p["rowAccessPolicyReference"]["policyId"] for p in policies]


def create_rls(client, table, policy_name, group_email, location, apply):
    project, dataset, tbl = parse_table(table)
    ddl = (
        f"CREATE OR REPLACE ROW ACCESS POLICY `{policy_name}`\n"
        f"ON `{project}.{dataset}.{tbl}`\n"
        f'GRANT TO ("group:{group_email}")\n'
        f"FILTER USING (TRUE)"
    )
    log(f"[RLS] 执行 DDL (location={location}):\n{ddl}")
    if apply:
        client.query(ddl, location=location).result()
        log("  -> RLS 创建成功")


def grant_table_viewer(client, table, group_email, apply):
    role = "roles/bigquery.dataViewer"
    member = f"group:{group_email}"
    policy = client.get_iam_policy(table)
    for b in policy.bindings:
        if b["role"] == role and member in b["members"]:
            log(f"[IAM] {member} 已拥有表级 {role}")
            return
    log(f"[IAM] 授予 {member} 表级 {role}")
    if apply:
        policy.bindings.append({"role": role, "members": {member}})
        client.set_iam_policy(table, policy)
        log("  -> 授权成功")


# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(description="创建 group、加入 SA，并为表添加允许全部行的 RLS")
    p.add_argument("--audit-csv", required=True, help="bq_sa_audit.py 输出的 CSV")
    p.add_argument("--members", choices=["all", "bq", "jobs"], default="bq",
                   help="all=所有 SA；bq=有 BQ 权限的 SA；jobs=提交过作业的 SA（默认 bq）")
    p.add_argument("--group-email", required=True, help="group 邮箱，如 bq-sa@your-domain.com")
    p.add_argument("--group-display-name", default=None)
    p.add_argument("--customer-id", default=None,
                   help="Cloud Identity customer ID（如 C0xxxxxx）；默认从 --project 的 Organization 自动获取")
    p.add_argument("--table", required=True,
                   help="要添加 RLS 的表 project.dataset.table")
    p.add_argument("--project", default=None,
                   help="用于计费 / quota / 运行 BQ 作业的项目（默认取 --table 所在项目）")
    p.add_argument("--gcloud-account", default=None,
                   help="使用指定 gcloud 账号的 token，而不是 ADC（如 admin@example.com）")
    p.add_argument("--policy-name", default="sa_group_all_rows", help="Row Access Policy 名称")
    p.add_argument("--grant-table-viewer", action="store_true",
                   help="同时给 group 授予表级 roles/bigquery.dataViewer")
    p.add_argument("--skip-group", action="store_true",
                   help="跳过 group 创建与成员管理，只做 RLS（group 已由其他方式维护时）")
    p.add_argument("--force-first-policy", action="store_true",
                   help="表上原本没有任何 RLS 时也继续创建（会导致其他用户看不到任何行）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认 dry-run")
    args = p.parse_args()
    args.project = args.project or parse_table(args.table)[0]

    mode = "APPLY" if args.apply else "DRY-RUN"
    log(f"===== 模式: {mode} =====")

    creds = get_credentials(args.gcloud_account, args.project)

    # Step 1: SA 列表
    members = load_members(args.audit_csv, args.members)
    log(f"[CSV] 按 '{args.members}' 选出 {len(members)} 个 SA")

    # Step 2/3: Group & 成员
    failed = []
    if not args.skip_group:
        ci = discovery.build("cloudidentity", "v1", credentials=creds, cache_discovery=False)
        customer_id = args.customer_id or resolve_customer_id(creds, args.project)
        log(f"[GROUP] customer ID: {customer_id}")
        group_name = ensure_group(ci, args.group_email, args.group_display_name,
                                  customer_id, args.apply)
        failed = add_members(ci, group_name, members, args.apply)

    # Step 4: RLS
    project, dataset, tbl = parse_table(args.table)
    client = bigquery.Client(project=args.project, credentials=creds)
    table_obj = client.get_table(f"{project}.{dataset}.{tbl}")
    location = client.get_dataset(f"{project}.{dataset}").location

    existing = list_row_access_policies(creds, project, dataset, tbl)
    log(f"[RLS] 表上已有的 Row Access Policy: {existing or '无'}")
    if not existing or existing == [args.policy_name]:
        log("  [WARNING] 表上目前没有其他 RLS。一旦创建 RLS，未被任何 policy 覆盖的用户"
            "将查询不到任何行！如需保留其他用户访问，请另建对应 policy。")
        if args.apply and not existing and not args.force_first_policy:
            log("  已中止。确认后请加 --force-first-policy 重新执行。")
            sys.exit(2)

    create_rls(client, table_obj.full_table_id.replace(":", "."), args.policy_name,
               args.group_email, location, args.apply)

    # Step 5: 表级读权限（可选）
    if args.grant_table_viewer:
        grant_table_viewer(client, table_obj, args.group_email, args.apply)

    log(f"===== 完成 ({mode}) =====")
    if failed:
        log(f"以下 SA 加入 group 失败: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
