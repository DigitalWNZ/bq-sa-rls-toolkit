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
     - 组织 / 文件夹 / 项目的 IAM 策略（Resource Manager getIamPolicy）；只指定项目时，同样读取该项目全部上级文件夹 / 组织的
       策略（getAncestry 找上级），不漏从组织 / 文件夹继承的授权（效果同 Console 项目 IAM 页面的「继承」行）
     - 每个数据集的 ACL（BigQuery datasets.list + datasets.get）
     - 每张表 / 视图的 IAM 策略（BigQuery tables.getIamPolicy）
     只纳入能读表数据的角色：含 bigquery.tables.getData 的角色（BigQuery 数据角色、数据集旧式 ACL 的 READER / WRITER /
     OWNER 等；自定义角色读取其权限列表判断，读不到角色定义时宁可多列并 [WARN]），以及基本角色 Owner / Editor / Viewer
     （它们的 IAM 权限里没有 getData，但每个数据集的 ACL 默认带特殊组 projectOwners / projectWriters / projectReaders，
     项目的基本角色持有者借此能读表，所以一律按能读处理，不管授在项目、文件夹还是组织上）。
     带条件的授权同样纳入。其中出现的 Group 用 Cloud Identity 递归展开。
     GCS、Pub/Sub 等非 BigQuery 资源上的授权不纳入。
  4. 授权视图 / 数据集 / 例程（只提示）：数据集 ACL 授权了其它项目的视图 / 数据集 / 例程时，能查询它们的人也能间接读到数据；
     这些项目不在本次扫描范围内时 [NOTE] 列出（不影响退出码），需要的话把它们加入 --projects 重跑。
  跳过：deleted:、domain:、allUsers、allAuthenticatedUsers、principal:// / principalSet://、specialGroup 等非具体账号。
  任何项目 / 文件夹 / 数据集 / 表 / 账号目录读取失败都打印 [ERROR] 并以退出码 1 结束（其余结果照常写入 CSV），绝不悄悄跳过。
  展不开的 Group 一律作为 principal_type = group 写入 CSV（成员未展开），按域名分两类：
    - 外部域（不属于本组织域名）：Cloud Identity 不允许读取其它组织的 Group → [NOTE]，不影响退出码；
    - 本组织域名的 Group 读不到（多半缺「群组 → 读取」权限），或展开出错（API 未启用、限流重试用尽等）→ [ERROR] + 退出码 1。
    本组织域名 = 组织的主域名（组织显示名称）+ 账号目录里 user 的域名（只在组织范围）+ 跑脚本账号的域名（SA 除外）。
    只指定项目时不读账号目录，辅助域名（如 ctrip.com）的 Group 会按外部域处理（照样写入 CSV）。

输出: CSV（UTF-8 BOM，默认 principals.csv），列 email, principal_type, home_project（三列都由邮箱推算）；
  principal_type ∈ serviceAccount / user / serviceAgent / group（group = 展不开的 Group）。
运行日志: 屏幕输出原样另存到 logs/list_principals_<YYYYMMDD_HHMMSS>.log（--log-dir 可改目录；四个脚本相同）。
文件参数均为单列、无表头的 .csv。

示例:
  python list_principals.py --organizations 123456789012          # 执行账号 / quota 项目自动确定（见下）
  python list_principals.py --projects projects.csv --exclude-patterns 'copilot-*@*'

执行账号与 quota 项目（四个脚本相同）:
  账号：--gcloud-account → gcloud 当前活动账号（gcloud auth login 后的那个）→ application-default 凭证 → 报错
  quota 项目：--quota-project → gcloud 默认项目（gcloud config set project）→ application-default 凭证的 quota 项目 → 报错

运行者权限（授予执行账号）:
  - GCP（在组织上授予，均为只读）：roles/browser（组织信息与主域名、列文件夹 / 项目、getAncestry 找项目的上级）、
    roles/iam.securityReviewer（组织 / 文件夹 / 项目的 IAM 策略、列 SA、读自定义角色、表 IAM 策略）、
    roles/bigquery.metadataViewer（列数据集、读数据集 ACL、列表）
  - Workspace / Cloud Identity：有「用户 → 读取」（读账号目录）和「群组 → 读取」（展开 Group）权限的管理员
  - quota 项目：启用 cloudresourcemanager、iam、bigquery、cloudidentity、admin（Admin SDK）API；执行账号在该项目上有
    roles/serviceusage.serviceUsageConsumer（四个脚本相同；缺少时 API 调用报 403 USER_PROJECT_DENIED）
  - 读不到某个自定义角色的定义（iam.roles.get 无权限）时，按「能读表数据」处理并 [WARN]（宁可多列）

退出码: 0 成功（外部域的 Group 展不开不算失败）；1 部分读取失败 / 本组织域名的 Group 展不开（其余结果仍写入 CSV）；2 参数错误
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
        if role in core.BASIC_ROLES:          # 基本角色：IAM 权限里没有 getData，但数据集默认 ACL 的特殊组
            return True                       # projectOwners / Writers / Readers 让它们能读表 → 按能读处理，不查定义
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
    own_domains = set()                               # 本组织域名（小写）：判断读不到的 Group 是否外部域

    def add_unique(lst, items):
        for x in items:
            if x not in lst:
                lst.append(x)

    def add_org_domain(org_id):
        """组织的 (customer ID, 主域名)；主域名加入 own_domains。失败返回 None 并 [ERROR]。"""
        nonlocal failed
        try:
            cust, dom = ops.org_info(ctx, org_id)
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] organizations/{org_id}: 读取组织信息（账号目录 customer ID、主域名）失败: {e}")
            return None
        if dom:
            own_domains.add(dom)
        return cust

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
        cust = add_org_domain(org)
        if cust:
            add_unique(customers, [cust])
        elif cust is not None:
            failed = True
            ops.log(f"[ERROR] {org_res}: 组织信息中没有账号目录 customer ID")

    # --projects 指定的项目：补读其上级文件夹 / 组织的策略（继承的授权只在上级策略里，项目自己的策略中没有）。
    # 已由 --organizations 递归列出的项目，其上级已在 iam_resources 中，不再读取
    covered = set(projects)
    need = [x for x in projects_arg if x not in covered]
    ancestors = []
    for prj, res, err in ops.parallel_map(lambda x: ops.project_ancestors(ctx, x), need, workers=workers,
                                          desc="ancestry"):
        if err:
            failed = True
            ops.log(f"[ERROR] 项目 {prj}: 读取上级文件夹 / 组织失败（需要组织层 Browser）: {err}")
            continue
        add_unique(ancestors, res)
    new_ancestors = [a for a in ancestors if a not in iam_resources]
    add_unique(iam_resources, new_ancestors)
    if new_ancestors:
        ops.log(f"[ANCESTOR] --projects 指定的 {len(need)} 个项目的上级 {len(new_ancestors)} 个："
                f"{', '.join(new_ancestors)}")
    for a in new_ancestors:
        if a.startswith("organizations/"):
            add_org_domain(a.split("/", 1)[1])
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
            own_domains.update(d for d in (core.email_domain(u) for u in users) if d)
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
            hint = "" if res_name.startswith("projects/") else "（读取文件夹 / 组织的 IAM 策略需要组织层 Security Reviewer）"
            ops.log(f"[ERROR] {res_name}: 读取 IAM 策略失败{hint}: {err}")
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
    scanned = set(projects)
    outside_refs = {}                                 # 范围外的项目 -> ["授权视图 p.d.v → 数据集 x.y", ...]
    for ds, res, err in ops.parallel_map(lambda d: ops.dataset_access(ctx, d), datasets, workers=workers, desc="acl"):
        if err:
            failed = True
            ops.log(f"[ERROR] 数据集 {ds}: 读取 ACL 失败: {err}")
            continue
        n += take(core.acl_members(res, has_get_data))
        for kind, ref, prj in core.authorized_refs(res):
            if prj not in scanned:
                outside_refs.setdefault(prj, []).append(f"{kind} {ref} → 数据集 {ds}")
    ops.log(f"[ACL] {len(datasets)} 个数据集：能读表数据的授权对象 {n} 个")
    if outside_refs:
        ops.log(f"[NOTE] 以下 {len(outside_refs)} 个项目中的视图 / 数据集 / 例程被授权读取本次范围内的数据集，"
                "但这些项目不在本次扫描范围内；能查询它们的 user / SA 也能间接读到数据，需要的话请把这些项目加入 "
                "--projects 重跑（或改用 --organizations）：\n"
                + "\n".join(f"  - {p}：" + "；".join(sorted(set(v))) for p, v in sorted(outside_refs.items())))

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
    # 读不到的 Group 一律作为 group 写入 CSV（成员未展开，不能当作「没有成员」），按原因分两类：
    #   外部域（403 / 404 且域名不属于本组织）：Cloud Identity 不允许读取其它组织的 Group → [NOTE]，不影响退出码
    #   本域读不到（多半缺「群组 → 读取」权限），或 API 未启用 / 限流重试用尽等配置问题 → [ERROR] + 退出码 1
    me = (auth.impersonated or auth.account or "").lower()
    if me and not me.endswith("gserviceaccount.com") and core.email_domain(me):
        own_domains.add(core.email_domain(me))
    if groups:
        ops.log(f"[DOMAIN] 本组织域名（用于判断读不到的 Group 是否外部域）: {', '.join(sorted(own_domains)) or '无'}")
    external, own_failed = {}, {}                     # group -> 原因

    for g, res, err in ops.parallel_map(lambda g: ops.expand_group(ctx, g), sorted(groups),
                                        workers=workers, desc="group"):
        if err:
            failed = True
            reason = str(err)
            if any(h in reason.lower() for h in ops._CONFIG_ERROR_HINTS):
                reason = f"Cloud Identity API 未在 quota 项目启用，或执行账号不能使用 quota 项目: {reason}"
            own_failed[g] = reason[:300]
            ops.log(f"[ERROR] 展开 group:{g} 失败: {reason[:500]}；已作为 group 写入 CSV，其成员未列入")
            continue
        members, unresolved, reasons = res
        for email, info in members.items():
            if info["type"] in _MEMBER_TYPES or (info["type"] == "UNKNOWN" and email.endswith("gserviceaccount.com")):
                emails.add(email)
        for ug, via in unresolved:
            if ug in external or ug in own_failed:
                continue                              # 同一个组嵌在多个组里：只报一次
            reason = reasons.get(ug, ops.GROUP_UNREADABLE_REASON)
            where = f"（group:{g} 中的嵌套组）" if ug != g else ""
            if core.is_own_domain(ug, own_domains):
                failed = True
                own_failed[ug] = reason
                ops.log(f"[ERROR] 展开 group:{ug}{where} 失败：{reason}；该 Group 属于本组织域名，应当能读取，"
                        "请确认跑脚本的 user / SA 有「群组 → 读取」权限；已作为 group 写入 CSV，其成员未列入")
            else:
                external[ug] = reason
                ops.log(f"[NOTE] group:{ug}{where} 是外部域的 Group（Cloud Identity 不允许读取其它组织的 Group），"
                        "已作为 group 写入 CSV，成员未展开")
    if groups:
        parts = ([f"外部域 {len(external)} 个（已写入 CSV）"] if external else []) + \
                ([f"本域未能展开 {len(own_failed)} 个"] if own_failed else [])
        ops.log(f"[GROUP] 共 {len(groups)} 个 Group，" + ("、".join(parts) if parts else "全部展开"))

    rows = core.build_principal_rows(emails, core.split_items(args.exclude_members),
                                     core.split_items(args.exclude_patterns), groups=set(external) | set(own_failed))
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
    if external:
        ops.log(f"[NOTE] 以下 {len(external)} 个外部域 Group 已作为 group 写入 CSV，成员未展开"
                "（Cloud Identity 不允许读取其它组织的 Group）：\n" + "\n".join(f"  - {g}" for g in sorted(external)))
    if own_failed:
        ops.log(f"[ERROR] 以下 {len(own_failed)} 个 Group 未能展开（Group 本身已写入 CSV），其成员未列入 CSV，"
                "请用有 Group 读取权限的账号重跑或手工核对：\n" + "\n".join(f"  - {g}" for g in sorted(own_failed)))
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
