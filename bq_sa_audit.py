#!/usr/bin/env python3
"""
BigQuery Service Account 审计脚本

对输入的每个项目:
  1. 列出项目下所有 Service Account
  2. 检查每个 SA 是否拥有任何 BigQuery 权限
     - 项目级 IAM（在所有输入项目中查找；会展开角色，判断是否包含 bigquery.* 权限，
       因此 roles/owner、roles/editor、自定义角色等也能被识别）
     - 可选：数据集级 ACL（--check-datasets）
  3. 通过 INFORMATION_SCHEMA.JOBS 检查 SA 是否提交过作业（在所有输入项目、指定区域中查找）

最后输出一张表格（终端）+ CSV 文件。

用法:
  # 自动识别区域（扫描所有输入项目的数据集 location）
  python bq_sa_audit.py --projects proj-a proj-b
  # 自动识别 + 额外追加区域
  python bq_sa_audit.py --projects proj-a proj-b --extra-regions asia-east2
  # 手动指定区域
  python bq_sa_audit.py --projects proj-a proj-b --regions us asia-east1
  python bq_sa_audit.py --projects-file projects.txt --days 180 --check-datasets -o result.csv

认证: 默认使用 Application Default Credentials（gcloud auth application-default login），
      或用 --gcloud-account 指定一个已 gcloud auth login 的账号；--quota-project 覆盖配额项目。

所需权限（对每个项目，详见 README.md）:
  - iam.serviceAccounts.list
  - resourcemanager.projects.getIamPolicy
  - iam.roles.get（展开自定义角色权限）
  - bigquery.datasets.get（自动识别区域 / --check-datasets）
  - bigquery.jobs.listAll + bigquery.jobs.create（查询 INFORMATION_SCHEMA.JOBS）
  - quota project 上的 serviceusage.services.use
"""

import argparse
import csv
import sys
from collections import defaultdict

from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from gcp_auth import get_credentials

BQ_PERMISSION_PREFIX = "bigquery."


def log(msg):
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# 1. 列出 Service Account
# --------------------------------------------------------------------------- #
def list_service_accounts(iam, project):
    accounts = []
    req = iam.projects().serviceAccounts().list(name=f"projects/{project}", pageSize=100)
    while req is not None:
        resp = req.execute()
        accounts.extend(resp.get("accounts", []))
        req = iam.projects().serviceAccounts().list_next(req, resp)
    return accounts


# --------------------------------------------------------------------------- #
# 2. BigQuery 权限检查
# --------------------------------------------------------------------------- #
class RoleResolver:
    """获取角色包含的权限列表，并带缓存。"""

    def __init__(self, iam):
        self.iam = iam
        self.cache = {}

    def permissions(self, role):
        if role in self.cache:
            return self.cache[role]
        perms = []
        try:
            if role.startswith("roles/"):
                r = self.iam.roles().get(name=role).execute()
            elif role.startswith("projects/"):
                r = self.iam.projects().roles().get(name=role).execute()
            elif role.startswith("organizations/"):
                r = self.iam.organizations().roles().get(name=role).execute()
            else:
                r = {}
            perms = r.get("includedPermissions", [])
        except HttpError as e:
            log(f"  [WARN] 无法获取角色 {role} 的权限: {e.reason if hasattr(e, 'reason') else e}")
            # 回退：按角色名粗略判断
            perms = ["bigquery.unknown"] if "bigquery" in role.lower() else []
        self.cache[role] = perms
        return perms

    def has_bq(self, role):
        return any(p.startswith(BQ_PERMISSION_PREFIX) for p in self.permissions(role))


def collect_project_iam_bq_grants(crm, resolver, projects):
    """
    返回 {sa_email: [ "project:role[ (conditional)]", ... ]}
    只记录包含 bigquery.* 权限的角色。
    """
    grants = defaultdict(list)
    for project in projects:
        log(f"[IAM] 读取 {project} 的 IAM Policy ...")
        try:
            policy = crm.projects().getIamPolicy(
                resource=project, body={"options": {"requestedPolicyVersion": 3}}
            ).execute()
        except HttpError as e:
            log(f"  [WARN] 获取 {project} IAM Policy 失败: {e}")
            continue
        for b in policy.get("bindings", []):
            role = b["role"]
            sa_members = [m for m in b.get("members", []) if m.startswith("serviceAccount:")]
            if not sa_members or not resolver.has_bq(role):
                continue
            cond = " (conditional)" if b.get("condition") else ""
            for m in sa_members:
                email = m.split(":", 1)[1].lower()
                grants[email].append(f"{project}:{role}{cond}")
    return grants


def collect_dataset_acl_bq_grants(bq_clients, projects):
    """
    返回 {sa_email: [ "project.dataset:ROLE", ... ]}  —— 数据集级 ACL 授权
    """
    grants = defaultdict(list)
    for project in projects:
        client = bq_clients(project)
        log(f"[DATASET] 扫描 {project} 的数据集 ACL ...")
        try:
            datasets = list(client.list_datasets(project=project))
        except Exception as e:  # noqa: BLE001
            log(f"  [WARN] 列出 {project} 数据集失败: {e}")
            continue
        for ds_item in datasets:
            try:
                ds = client.get_dataset(ds_item.reference)
            except Exception as e:  # noqa: BLE001
                log(f"  [WARN] 读取数据集 {ds_item.dataset_id} 失败: {e}")
                continue
            for entry in ds.access_entries:
                eid = (entry.entity_id or "")
                if not isinstance(eid, str):
                    continue
                # userByEmail 或 iamMember(serviceAccount:xxx)
                if eid.startswith("serviceAccount:"):
                    eid = eid.split(":", 1)[1]
                if eid.endswith("gserviceaccount.com"):
                    grants[eid.lower()].append(f"{project}.{ds.dataset_id}:{entry.role}")
    return grants


# --------------------------------------------------------------------------- #
# 3. INFORMATION_SCHEMA.JOBS 作业检查
# --------------------------------------------------------------------------- #
JOBS_SQL = """
SELECT
  LOWER(user_email) AS user_email,
  COUNT(*)          AS job_count,
  MAX(creation_time) AS last_job_time
FROM `{project}`.`region-{region}`.INFORMATION_SCHEMA.JOBS
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
  AND user_email LIKE '%gserviceaccount.com'
GROUP BY user_email
"""


def detect_regions(bq_clients, projects):
    """
    自动识别区域：扫描所有输入项目的数据集 location，取并集（小写）。
    取并集而不是按项目分别取，是因为作业运行在被查询数据所在的区域，
    项目 A 里的作业可能查询的是项目 B 中其他区域的数据。
    """
    regions = set()
    for project in projects:
        client = bq_clients(project)
        log(f"[REGION] 识别 {project} 的数据集区域 ...")
        try:
            for ds_item in client.list_datasets(project=project):
                # datasets.list 的返回中通常包含 location，避免逐个 get_dataset
                loc = ds_item._properties.get("location")
                if not loc:
                    try:
                        loc = client.get_dataset(ds_item.reference).location
                    except Exception as e:  # noqa: BLE001
                        log(f"  [WARN] 读取数据集 {ds_item.dataset_id} 失败: {e}")
                        continue
                if loc:
                    regions.add(loc.lower())
        except Exception as e:  # noqa: BLE001
            log(f"  [WARN] 列出 {project} 数据集失败: {e}")
    return sorted(regions)


def collect_job_stats(bq_clients, projects, regions, days):
    """
    返回 {sa_email: {"job_count": int, "last_job_time": datetime, "where": set()}}
    """
    stats = defaultdict(lambda: {"job_count": 0, "last_job_time": None, "where": set()})
    for project in projects:
        client = bq_clients(project)
        for region in regions:
            sql = JOBS_SQL.format(project=project, region=region, days=days)
            log(f"[JOBS] 查询 {project} / region-{region} ...")
            try:
                rows = client.query(sql).result()
            except Exception as e:  # noqa: BLE001
                log(f"  [WARN] 查询 {project} region-{region} 失败: {e}")
                continue
            for r in rows:
                s = stats[r.user_email]
                s["job_count"] += r.job_count
                if s["last_job_time"] is None or r.last_job_time > s["last_job_time"]:
                    s["last_job_time"] = r.last_job_time
                s["where"].add(f"{project}/{region}")
    return stats


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
COLUMNS = [
    "project",
    "service_account",
    "display_name",
    "disabled",
    "has_bq_permission",
    "bq_iam_roles",
    "bq_dataset_acls",
    "has_submitted_jobs",
    "job_count",
    "last_job_time",
    "job_locations",
]


def print_table(rows):
    show = ["project", "service_account", "has_bq_permission", "has_submitted_jobs",
            "job_count", "last_job_time"]
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) if rows else len(c) for c in show}
    line = " | ".join(c.ljust(widths[c]) for c in show)
    print(line)
    print("-+-".join("-" * widths[c] for c in show))
    for r in rows:
        print(" | ".join(str(r[c]).ljust(widths[c]) for c in show))


def main():
    p = argparse.ArgumentParser(description="审计 Service Account 的 BigQuery 权限与作业提交情况")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--projects", nargs="+", help="项目 ID 列表")
    g.add_argument("--projects-file", help="每行一个项目 ID 的文件")
    p.add_argument("--regions", nargs="+", default=None,
                   help="INFORMATION_SCHEMA 区域，如 us eu asia-east1。"
                        "不指定时自动从所有项目的数据集 location 中识别")
    p.add_argument("--extra-regions", nargs="+", default=[],
                   help="在自动识别（或 --regions）结果之外额外追加的区域")
    p.add_argument("--days", type=int, default=180,
                   help="查询最近 N 天的作业（JOBS 视图最多保留 180 天）")
    p.add_argument("--check-datasets", action="store_true",
                   help="同时检查数据集级 ACL（项目/数据集多时较慢）")
    p.add_argument("-o", "--output", default="bq_sa_audit.csv", help="CSV 输出路径")
    p.add_argument("--quota-project", default=None,
                   help="API 计费/配额项目（覆盖 ADC 默认的 quota project）")
    p.add_argument("--gcloud-account", default=None,
                   help="使用指定 gcloud 账号的 token，而不是 ADC（如 admin@example.com）")
    args = p.parse_args()

    if args.projects:
        projects = args.projects
    else:
        with open(args.projects_file) as f:
            projects = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    creds = get_credentials(args.gcloud_account, args.quota_project)
    iam = discovery.build("iam", "v1", credentials=creds, cache_discovery=False)
    crm = discovery.build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)

    _bq_cache = {}

    def bq_clients(project):
        if project not in _bq_cache:
            _bq_cache[project] = bigquery.Client(project=project, credentials=creds)
        return _bq_cache[project]

    # Step 1: SA 列表
    sa_by_project = {}
    for project in projects:
        log(f"[SA] 列出 {project} 的 Service Accounts ...")
        try:
            sa_by_project[project] = list_service_accounts(iam, project)
        except HttpError as e:
            log(f"  [WARN] 列出 {project} SA 失败: {e}")
            sa_by_project[project] = []

    # Step 2: BigQuery 权限
    resolver = RoleResolver(iam)
    iam_grants = collect_project_iam_bq_grants(crm, resolver, projects)
    ds_grants = collect_dataset_acl_bq_grants(bq_clients, projects) if args.check_datasets else {}

    # Step 3: 作业提交
    if args.regions:
        regions = [r.lower() for r in args.regions]
    else:
        regions = detect_regions(bq_clients, projects)
        if not regions:
            log("[REGION] 未识别到任何数据集区域，回退为 us")
            regions = ["us"]
    regions = sorted(set(regions) | {r.lower() for r in args.extra_regions})
    log(f"[REGION] 将查询以下区域: {', '.join(regions)}")
    job_stats = collect_job_stats(bq_clients, projects, regions, args.days)

    # 汇总
    rows = []
    for project in projects:
        for sa in sa_by_project[project]:
            email = sa["email"].lower()
            roles = iam_grants.get(email, [])
            acls = ds_grants.get(email, [])
            js = job_stats.get(email)
            rows.append({
                "project": project,
                "service_account": sa["email"],
                "display_name": sa.get("displayName", ""),
                "disabled": sa.get("disabled", False),
                "has_bq_permission": bool(roles or acls),
                "bq_iam_roles": "; ".join(roles),
                "bq_dataset_acls": "; ".join(acls),
                "has_submitted_jobs": bool(js),
                "job_count": js["job_count"] if js else 0,
                "last_job_time": js["last_job_time"].isoformat() if js else "",
                "job_locations": "; ".join(sorted(js["where"])) if js else "",
            })

    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    print()
    print_table(rows)
    print(f"\n共 {len(rows)} 个 Service Account，完整结果已写入 {args.output}")


if __name__ == "__main__":
    main()
