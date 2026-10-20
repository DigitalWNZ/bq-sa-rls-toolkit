#!/usr/bin/env python3
"""
列出指定组织 / 项目下的全部 SA 和 user（白名单候选，Doc 第 1 步）。不遗漏，全部使用权威 API（不使用 Cloud Asset）。

范围（可多个、可叠加）:
  --organizations   组织数字 ID
  --projects        Project ID（或项目编号）
  值可直接写（逗号 / 空格分隔），也可写单列无表头的 .csv 文件，可混用。

来源（取并集去重）:
  1. SA 清单（不遗漏）：范围内每个 ACTIVE 项目用 IAM serviceAccounts.list 列出全部 SA（含已禁用、没有任何授权的）。
     组织范围先用 Resource Manager 递归列出组织下全部文件夹和项目；非 ACTIVE（待删除）的项目跳过并 [NOTE]。
  2. 账号目录（不遗漏，只在组织范围）：用执行账号自己的凭证调用 Admin SDK Directory API，列出该组织账号目录里的
     全部 user（含暂停 / 归档，所有域名）。执行账号需是有「用户 → 读取」权限的 Workspace / Cloud Identity 管理员
     （GCP 的组织管理员等 IAM 角色不起作用）。只指定项目时不读账号目录。
  3. BigQuery 相关授权（找出不属于上面两类的账号：其它项目的 SA、外部域的 user、Google 服务代理，以及只指定项目时的 user）:
     - 组织 / 文件夹 / 项目的 IAM 策略（Resource Manager getIamPolicy）；只指定项目时只读该项目，不读上层继承的授权
     - 每个数据集的 ACL（BigQuery datasets.list + datasets.get）
     - 每张表 / 视图的 IAM 策略（BigQuery tables.getIamPolicy）
     只纳入含 bigquery.tables.getData（能读表数据）的角色：基本角色 Owner / Editor / Viewer、BigQuery 数据角色、
     数据集旧式 ACL 的 READER / WRITER / OWNER 都算；自定义角色读取其权限列表判断；读不到角色定义时宁可多列并 [WARN]。
     带条件的授权同样纳入。其中出现的 Group 用 Cloud Identity 递归展开；展不开的组只提示。
     GCS、Pub/Sub 等非 BigQuery 资源上的授权不纳入。
  跳过：deleted:、domain:、allUsers、allAuthenticatedUsers、principalSet:// 、specialGroup、授权视图 / 例程 / 数据集等非具体账号。
  任何项目 / 文件夹 / 数据集 / 表 / 账号目录读取失败都打印 [ERROR] 并以退出码 1 结束（其余结果照常写入 CSV），绝不悄悄跳过。

输出: CSV（UTF-8 BOM，默认 principals.csv），列 email, principal_type, home_project（三列都由邮箱推算）。
运行日志: 屏幕输出原样另存到 logs/list_principals_<YYYYMMDD_HHMMSS>.log（--log-dir 可改目录；四个脚本相同）。
文件参数均为单列、无表头的 .csv。

示例:
  python list_principals.py --organizations 123456789012          # 执行账号 / quota 项目自动确定（见下）
  python list_principals.py --projects projects.csv --exclude-patterns 'copilot-*@*'

执行账号与 quota 项目（四个脚本相同）:
  账号：--gcloud-account → gcloud 当前活动账号（gcloud auth login 后的那个）→ application-default 凭证 → 报错
  quota 项目：--quota-project → gcloud 默认项目（gcloud config set project）→ application-default 凭证的 quota 项目 → 报错

运行者权限（授予执行账号）:
  - GCP（在组织上授予，均为只读）：roles/browser（组织信息、列文件夹 / 项目）、roles/iam.securityReviewer（IAM 策略、
    列 SA、读自定义角色、表 IAM 策略）、roles/bigquery.metadataViewer（列数据集、读数据集 ACL、列表）
  - Workspace / Cloud Identity：有「用户 → 读取」（读账号目录）和「群组 → 读取」（展开 Group）权限的管理员
  - quota 项目：启用 cloudresourcemanager、iam、bigquery、cloudidentity、admin（Admin SDK）API；执行账号在该项目上有
    roles/serviceusage.serviceUsageConsumer（四个脚本相同；缺少时 API 调用报 403 USER_PROJECT_DENIED）
  - 读不到某个自定义角色的定义（iam.roles.get 无权限）时，按「能读表数据」处理并 [WARN]（宁可多列）

退出码: 0 成功；1 部分读取失败（其余结果仍写入 CSV）；2 参数错误
"""

import argparse
import csv
import sys
import threading

import gcp_ops as ops
import rls_core as core
from apply_bypass_rls import run_main
from gcp_auth import AuthConfigError, describe_auth, resolve_auth

_MEMBER_TYPES = {"USER", "SERVICE_ACCOUNT"}


def build_parser():
    p = argparse.ArgumentParser(description="列出指定组织 / 项目下的全部 SA 和 user", allow_abbrev=False)
    p.add_argument("--organizations", nargs="*", action="extend", default=[], help="组织数字 ID，逗号或空格分隔；也可写 .csv 文件")
    p.add_argument("--projects", nargs="*", action="extend", default=[], help="Project ID，逗号或空格分隔；也可写 .csv 文件")
    p.add_argument("--exclude-members", nargs="*", default=[], help="从输出中去掉这些邮箱")
    p.add_argument("--exclude-patterns", nargs="*", default=[], help="从输出中去掉匹配这些通配符的邮箱，如 copilot-*@*")
    p.add_argument("-o", "--output", default="principals.csv")
    p.add_argument("--quota-project", default=None, help="quota / 运行查询与 DDL 的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--parallel", type=int, default=16, help="并行读取的并发数（默认 16）")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    ops.add_log_dir_arg(p)
    return p


class RoleChecker:
    """角色是否含 bigquery.tables.getData；同一角色只查询一次（线程安全）。读不到角色定义时视为含有（宁可多列）。"""

    def __init__(self, ctx):
        self.ctx = ctx
        self._cache = {}
        self._lock = threading.Lock()
        self.unknown = set()

    def __call__(self, role):
        if not role:
            return False
        with self._lock:
            if role in self._cache:
                return self._cache[role]
        try:
            ok = core.GET_DATA_PERMISSION in ops.role_permissions(self.ctx, role)
        except Exception as e:  # noqa: BLE001
            ok = True
            with self._lock:
                if role not in self.unknown:
                    self.unknown.add(role)
                    ops.log(f"[WARN] 读不到角色 {role} 的定义（{str(e)[:150]}），按「能读表数据」处理，其成员照常列出")
        with self._lock:
            self._cache[role] = ok
        return ok


def _main(argv):
    p = build_parser()
    args = p.parse_args(argv)
    ops.start_log_file("list_principals", args.log_dir)
    try:
        orgs = list(dict.fromkeys(core.org_scope(o).split("/", 1)[1] for o in core.collect_values(args.organizations)))
        projects_arg = list(dict.fromkeys(core.project_scope(x).split("/", 1)[1] for x in core.collect_values(args.projects)))
    except (ValueError, OSError) as e:
        p.error(str(e))
    if not (orgs or projects_arg):
        p.error("请指定 --organizations 或 --projects")
    try:
        auth = resolve_auth(args.gcloud_account, args.quota_project)
    except AuthConfigError as e:
        ops.log(f"[ERROR] {e}")
        return 2
    ops.log(describe_auth(auth))
    ctx = ops.Ctx(auth.creds, auth.project)
    workers = max(1, args.parallel)
    has_get_data = RoleChecker(ctx)

    failed = False
    emails, groups = set(), set()
    projects, iam_resources, customers = [], [], []

    def add_unique(lst, items):
        for x in items:
            if x not in lst:
                lst.append(x)

    # ---- 范围展开 ----
    for org in orgs:
        org_res = f"organizations/{org}"
        add_unique(iam_resources, [org_res])
        try:
            folders, active, inactive = ops.list_org_descendants(ctx, org)
            add_unique(iam_resources, folders)
            add_unique(projects, active)
            ops.log(f"[ORG] {org_res}: {len(folders)} 个文件夹、{len(active)} 个 ACTIVE 项目")
            if inactive:
                ops.log(f"[NOTE] {org_res}: 跳过 {len(inactive)} 个非 ACTIVE（待删除）项目: {sorted(inactive)}")
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] {org_res}: 列出文件夹 / 项目失败: {e}")
        try:
            add_unique(customers, [ops.org_directory_customer(ctx, org)])
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] {org_res}: 读取账号目录 customer ID 失败: {e}")
    add_unique(projects, projects_arg)
    add_unique(iam_resources, [f"projects/{x}" for x in projects])

    # ---- 来源 1：各项目的 SA 清单 ----
    for prj, res, err in ops.parallel_map(lambda x: ops.project_service_accounts(ctx, x), projects,
                                          workers=workers, desc="sa"):
        if err:
            failed = True
            ops.log(f"[ERROR] 项目 {prj}: 列出 SA 失败: {err}")
            continue
        emails |= set(res)
        ops.log(f"[SA] 项目 {prj}: {len(res)} 个 SA")

    # ---- 来源 2：账号目录（只组织范围） ----
    for cust in customers:
        try:
            users = ops.directory_users(ctx, cust)
            emails |= set(users)
            ops.log(f"[DIR] 账号目录 {cust}: {len(users)} 个 user")
        except Exception as e:  # noqa: BLE001
            failed = True
            hint = "" if ops.DIRECTORY_HINT in str(e) else f"。{ops.DIRECTORY_HINT}"
            ops.log(f"[ERROR] 账号目录 {cust}: {e}{hint}")

    # ---- 来源 3：BigQuery 相关授权 ----
    def take(principals_groups):
        nonlocal emails, groups
        pr, gs = principals_groups
        emails |= pr
        groups |= gs
        return len(pr) + len(gs)

    n = 0
    for res_name, res, err in ops.parallel_map(lambda r: ops.resource_iam_bindings(ctx, r), iam_resources,
                                               workers=workers, desc="iam"):
        if err:
            failed = True
            ops.log(f"[ERROR] {res_name}: 读取 IAM 策略失败: {err}")
            continue
        n += take(core.binding_members(res, has_get_data))
    ops.log(f"[IAM] {len(iam_resources)} 个组织 / 文件夹 / 项目：能读表数据的授权对象 {n} 个")

    datasets = []
    for prj, res, err in ops.parallel_map(lambda x: ops.project_datasets(ctx, x), projects, workers=workers,
                                          desc="datasets"):
        if err:
            failed = True
            ops.log(f"[ERROR] 项目 {prj}: 列出数据集失败: {err}")
            continue
        datasets += res

    n = 0
    for ds, res, err in ops.parallel_map(lambda d: ops.dataset_access(ctx, d), datasets, workers=workers, desc="acl"):
        if err:
            failed = True
            ops.log(f"[ERROR] 数据集 {ds}: 读取 ACL 失败: {err}")
            continue
        n += take(core.acl_members(res, has_get_data))
    ops.log(f"[ACL] {len(datasets)} 个数据集：能读表数据的授权对象 {n} 个")

    tables = []
    for ds, res, err in ops.parallel_map(lambda d: ops.dataset_tables(ctx, d), datasets, workers=workers,
                                         desc="tables"):
        if err:
            failed = True
            ops.log(f"[ERROR] 数据集 {ds}: 列出表失败: {err}")
            continue
        tables += res

    n = 0
    for t, res, err in ops.parallel_map(lambda x: ops.table_iam_bindings(ctx, x), tables, workers=workers,
                                        desc="table_iam"):
        if err:
            failed = True
            ops.log(f"[ERROR] 表 {t}: 读取 IAM 策略失败: {err}")
            continue
        n += take(core.binding_members(res, has_get_data))
    ops.log(f"[TABLE] {len(tables)} 张表 / 视图：能读表数据的授权对象 {n} 个")

    # ---- Group 展开 ----
    for g, res, err in ops.parallel_map(lambda g: ops.expand_group(ctx, g), sorted(groups),
                                        workers=workers, desc="group"):
        if err:
            failed = True
            ops.log(f"[ERROR] 展开 group:{g} 失败: {err}")
            continue
        members, unresolved = res
        if not members and not unresolved:
            ops.log(f"  [WARN] 无法展开 group:{g}（外部域或无权限），其中的成员未列出")
            continue
        for email, info in members.items():
            if info["type"] in _MEMBER_TYPES or (info["type"] == "UNKNOWN" and email.endswith("gserviceaccount.com")):
                emails.add(email)
        for ug, via in unresolved:
            ops.log(f"  [WARN] group:{g} 中的嵌套组 {ug} 无法展开（外部域或无权限），其中的成员未列出")
    if groups:
        ops.log(f"[GROUP] 展开了 {len(groups)} 个 Group")

    rows = core.build_principal_rows(emails, core.split_items(args.exclude_members),
                                     core.split_items(args.exclude_patterns))
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=core.PRINCIPAL_COLUMNS)
        w.writeheader()
        w.writerows(core.csv_safe_row(r) for r in rows)
    by_type = {}
    for r in rows:
        by_type[r["principal_type"]] = by_type.get(r["principal_type"], 0) + 1
    scope_desc = f"{len(orgs)} 个组织、{len(projects)} 个项目"
    ops.log(f"===== 完成：{scope_desc}，共 {len(rows)} 个主体 "
            f"（{', '.join(f'{k} {v}' for k, v in sorted(by_type.items())) or '无'}），已写入 {args.output} =====")
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
