#!/usr/bin/env python3
"""
列出指定组织 / 项目下的全部主体（白名单候选，Doc 第 1 步）：SA、user、Group 以及其它授权对象，
不看角色、不判断能否读 BigQuery 表数据。全部使用权威 API（不使用 Cloud Asset）。

范围（可多个、可叠加）:
  --organizations   组织数字 ID
  --projects        Project ID（或项目编号）
  值可直接写（逗号 / 空格分隔），也可写单列无表头的 .csv 文件，可混用。

来源（取并集去重；CSV 的 source 列写明每个主体在哪里、以什么角色被找到）:
  1. SA 清单：范围内每个 ACTIVE 项目用 IAM serviceAccounts.list 列出全部 SA（含已禁用、没有任何授权的）。
     组织范围先用 Resource Manager 递归列出组织下全部文件夹和项目；待删除（非 ACTIVE）项目也尝试列出其中的 SA
     （不读这些项目的 IAM / 数据集 / 表），接口拒绝时只打 [NOTE]。实测：从组织继承的权限对待删除项目不生效，
     只有直接在该项目上有权限的账号能列出；只靠组织层权限（RUNBOOK 0.2）的账号会得到 404 → [NOTE]。
  2. 账号目录（只在组织范围）：用执行账号自己的凭证列出该组织账号目录里的全部 user（Admin SDK Directory API，
     含暂停 / 归档，所有域名）和全部 Group（Cloud Identity groups.list；只列组名、不展开）。执行账号需是有
     「用户 → 读取」「群组 → 读取」权限的 Workspace / Cloud Identity 管理员（GCP 的 IAM 角色不起作用）。
     只指定项目时不读账号目录。
  3. 授权记录中的全部授权对象（不看角色）:
     - 组织 / 文件夹 / 项目的 IAM 策略（Resource Manager getIamPolicy）；只指定项目时，读取该项目及其全部上级
       文件夹 / 组织的策略（getAncestry 找上级；授在上级的角色会继承到本项目）
     - 每个数据集的 ACL（BigQuery datasets.list + datasets.get）
     - 每张表 / 视图的 IAM 策略（BigQuery tables.getIamPolicy）
     带条件的授权同样纳入。非具体账号也写入 CSV：domain:（principal_type = domain）、allUsers / allAuthenticatedUsers
     （public）、principal:// / principalSet://（federated）、deleted:（deleted，已删除账号残留的授权）。
     数据集 ACL 的 projectOwners / projectWriters / projectReaders 特殊组跳过（就是项目 IAM 中的 Owner / Editor / Viewer）。
  4. Group 展开一层：只展开第 3 处授权记录中出现的 Group；直接成员中的 user / SA 列出，成员中的 Group 只列组名
     （嵌套组，不再展开）。账号目录里没有授权的 Group 只列组名、不展开。
  5. 授权视图 / 数据集 / 例程（只提示）：数据集 ACL 授权了其它项目的视图 / 数据集 / 例程时，能查询它们的人也能间接读到数据；
     这些项目不在本次扫描范围内时 [NOTE] 列出（不影响退出码），需要的话把它们加入 --projects 重跑。
  任何项目 / 文件夹 / 数据集 / 表 / 账号目录读取失败都打印 [ERROR] 并以退出码 1 结束（其余结果照常写入 CSV），绝不悄悄跳过。
  唯一例外：列出表之后、读取它的 IAM 之前表被删除（getIamPolicy 返回 404）→ [NOTE] 表已不存在，跳过（不影响退出码）。
  展不开的 Group（第 4 处）照样写入 CSV（source 末尾注明未展开），按域名分两类：
    - 外部域（不属于本组织域名）：Cloud Identity 不允许读取其它组织的 Group → [NOTE]，不影响退出码；
    - 本组织域名的 Group 读不到（多半缺「群组 → 读取」权限），或展开出错（API 未启用、限流重试用尽等）→ [ERROR] + 退出码 1。
    本组织域名 = 组织的主域名（组织显示名称）+ 账号目录里 user 的域名（只在组织范围）+ 跑脚本账号的域名（SA 除外）。
  不受管理的个人 Google 账号（用公司域名注册、不在账号目录里）只有出现在授权记录或 Group 成员中时才会列出。

输出: CSV（UTF-8 BOM，默认 principals.csv），三列 email, principal_type, source:
  principal_type ∈ serviceAccount / serviceAgent / user / group / domain / public / federated / deleted；
  非邮箱的主体 email 列写原始值（如 trip.com、allAuthenticatedUsers、principalSet://…、deleted:user:a@x.com?uid=1）；
  source 写「位置: 角色」，多处用「；」分隔，最多列 5 处（超过时写「…共 N 处」）。
运行日志: 屏幕输出原样另存到 logs/list_principals_<YYYYMMDD_HHMMSS>.log（--log-dir 可改目录；五个脚本相同）。
文件参数均为单列、无表头的 .csv。

示例:
  python list_principals.py --organizations 123456789012          # 执行账号 / quota 项目自动确定（见下）
  python list_principals.py --projects projects.csv --exclude-patterns 'copilot-*@*'

执行账号与 quota 项目（五个脚本相同）:
  账号：--gcloud-account → gcloud 当前活动账号（gcloud auth login 后的那个）→ application-default 凭证 → 报错
  quota 项目：--quota-project → gcloud 默认项目（gcloud config set project）→ application-default 凭证的 quota 项目 → 报错

运行者权限（授予执行账号）:
  - GCP（在组织上授予，均为只读）：roles/browser（组织信息与主域名、列文件夹 / 项目、getAncestry 找项目的上级）、
    roles/iam.securityReviewer（组织 / 文件夹 / 项目的 IAM 策略、列 SA、表 IAM 策略）、
    roles/bigquery.metadataViewer（列数据集、读数据集 ACL、列表）
  - Workspace / Cloud Identity：有「用户 → 读取」（读账号目录的 user）和「群组 → 读取」（列出 / 展开 Group）权限的管理员
  - quota 项目：启用 cloudresourcemanager、iam、bigquery、cloudidentity、admin（Admin SDK）API；执行账号在该项目上有
    roles/serviceusage.serviceUsageConsumer（五个脚本相同；缺少时 API 调用报 403 USER_PROJECT_DENIED）

退出码: 0 成功（外部域的 Group 展不开不算失败）；1 部分读取失败 / 本组织域名的 Group 展不开（其余结果仍写入 CSV）；2 参数错误
"""

import argparse
import csv
import sys

import gcp_ops as ops
import rls_core as core
from apply_bypass_rls import run_main
from gcp_auth import AuthConfigError, describe_auth, resolve_auth

_SKIP_GROUP_MEMBER_TYPES = {"SHARED_DRIVE", "CBCM_BROWSER"}      # 共享云端硬盘、Chrome 浏览器等不是主体
GROUPS_HINT = "列出账号目录的 Group 需要执行账号有 Workspace / Cloud Identity 的「群组 → 读取」管理员权限，且 quota 项目已启用 Cloud Identity API"
TABLE_GONE_MSG = "表已不存在（扫描期间被删除），跳过"


def build_parser():
    p = argparse.ArgumentParser(description="列出指定组织 / 项目下的全部主体（SA、user、Group 等）", allow_abbrev=False)
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


def iam_where(resource):
    """IAM 策略所在资源 -> source 中的位置描述。"""
    kind, _, rid = resource.partition("/")
    if kind == "organizations":
        return "组织 IAM"
    if kind == "folders":
        return f"文件夹 IAM {resource}"
    return f"项目 IAM {rid}"


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

    failed = False
    book = core.PrincipalBook()                       # 主体 -> 类型、来源
    granted_groups = set()                            # 授权记录（第 3 处）中出现的 Group：展开一层
    projects, pending, iam_resources, customers = [], [], [], []
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

    def take(items):
        """[(值, 类型, 来源)] 写入 book；返回不同主体的个数。"""
        for value, ptype, src in items:
            book.add(value, ptype, src)
            if ptype == "group":
                granted_groups.add(value)
        return len({v for v, _, _ in items})

    # ---- 范围展开 ----
    for org in orgs:
        org_res = f"organizations/{org}"
        add_unique(iam_resources, [org_res])
        try:
            folders, active, inactive = ops.list_org_descendants(ctx, org)
            add_unique(iam_resources, folders)
            add_unique(projects, active)
            add_unique(pending, inactive)
            ops.log(f"[ORG] {org_res}: {len(folders)} 个文件夹、{len(active)} 个 ACTIVE 项目"
                    + (f"、{len(inactive)} 个待删除项目（只列其中的 SA）" if inactive else ""))
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] {org_res}: 列出文件夹 / 项目失败: {e}")
        cust = add_org_domain(org)
        if cust:
            add_unique(customers, [cust])
        elif cust is not None:
            failed = True
            ops.log(f"[ERROR] {org_res}: 组织信息中没有账号目录 customer ID")

    # --projects 指定的项目：补读其上级文件夹 / 组织的策略（授在上级的角色继承到本项目，只记录在上级策略里）。
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
    pending = [x for x in pending if x not in projects]
    add_unique(iam_resources, [f"projects/{x}" for x in projects])

    # ---- 来源 1：各项目的 SA 清单（待删除项目也尝试，失败只提示） ----
    for prj, res, err in ops.parallel_map(lambda x: ops.project_service_accounts(ctx, x), projects + pending,
                                          workers=workers, desc="sa"):
        is_pending = prj in pending
        if err:
            if is_pending:
                ops.log(f"[NOTE] 待删除项目 {prj}: 列不出其中的 SA（{str(err)[:200]}）；"
                        "这些 SA 若在其它地方有授权，仍会从授权记录中列出")
                continue
            failed = True
            ops.log(f"[ERROR] 项目 {prj}: 列出 SA 失败: {err}")
            continue
        src = f"项目 SA: {prj}" + ("（待删除项目）" if is_pending else "")
        for email in res:
            book.add(email, core.principal_type(email), src)
        ops.log(f"[SA] {'待删除项目' if is_pending else '项目'} {prj}: {len(res)} 个 SA")

    # ---- 来源 2：账号目录的 user 与 Group（只组织范围） ----
    for cust in customers:
        n_users = n_groups = None
        try:
            users = ops.directory_users(ctx, cust)
            for u in users:
                book.add(u, "user", "账号目录")
            own_domains.update(d for d in (core.email_domain(u) for u in users) if d)
            n_users = len(users)
        except Exception as e:  # noqa: BLE001
            failed = True
            hint = "" if ops.DIRECTORY_HINT in str(e) else f"。{ops.DIRECTORY_HINT}"
            ops.log(f"[ERROR] 账号目录 {cust}: 列出 user 失败: {e}{hint}")
        try:
            dir_groups = ops.directory_groups(ctx, cust)
            for g in dir_groups:
                book.add(g, "group", "账号目录 Group")
            n_groups = len(dir_groups)
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] 账号目录 {cust}: 列出 Group 失败: {str(e)[:300]}。{GROUPS_HINT}")
        if n_users is not None or n_groups is not None:
            ops.log(f"[DIR] 账号目录 {cust}: "
                    + "、".join(x for x in (f"{n_users} 个 user" if n_users is not None else "",
                                           f"{n_groups} 个 Group" if n_groups is not None else "") if x))

    # ---- 来源 3：授权记录中的全部授权对象（不看角色） ----
    n = 0
    for res_name, res, err in ops.parallel_map(lambda r: ops.resource_iam_bindings(ctx, r), iam_resources,
                                               workers=workers, desc="iam"):
        if err:
            failed = True
            hint = "" if res_name.startswith("projects/") else "（读取文件夹 / 组织的 IAM 策略需要组织层 Security Reviewer）"
            ops.log(f"[ERROR] {res_name}: 读取 IAM 策略失败{hint}: {err}")
            continue
        n += take(core.binding_members(res, iam_where(res_name)))
    ops.log(f"[IAM] {len(iam_resources)} 个组织 / 文件夹 / 项目：授权对象 {n} 个")

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
        n += take(core.acl_members(res, f"数据集 ACL {ds}"))
        for kind, ref, prj in core.authorized_refs(res):
            if prj not in scanned:
                outside_refs.setdefault(prj, []).append(f"{kind} {ref} → 数据集 {ds}")
    ops.log(f"[ACL] {len(datasets)} 个数据集：授权对象 {n} 个")
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

    n, gone = 0, 0
    for t, res, err in ops.parallel_map(lambda x: ops.table_iam_bindings(ctx, x), tables, workers=workers,
                                        desc="table_iam"):
        if err and ops.is_not_found_error(err):
            # 列出表之后、读取它的 IAM 之前表被删除（404）：表已不存在，它的授权也随之失效 → 只提示，不影响退出码
            gone += 1
            ops.log(f"[NOTE] 表 {t}: {TABLE_GONE_MSG}")
            continue
        if err:
            failed = True
            ops.log(f"[ERROR] 表 {t}: 读取 IAM 策略失败: {err}")
            continue
        n += take(core.binding_members(res, f"表 IAM {t}"))
    ops.log(f"[TABLE] {len(tables)} 张表 / 视图：授权对象 {n} 个"
            + (f"（其中 {gone} 张扫描期间已被删除，跳过）" if gone else ""))

    # ---- 第 4 处：授权记录中的 Group 展开一层 ----
    # 直接成员中的 user / SA 列出；成员中的 Group 只列组名（嵌套组，不再展开）。
    # 读不到的 Group 照样写入 CSV（source 末尾注明未展开），按原因分两类：
    #   外部域（403 / 404 且域名不属于本组织）：Cloud Identity 不允许读取其它组织的 Group → [NOTE]，不影响退出码
    #   本域读不到（多半缺「群组 → 读取」权限），或 API 未启用 / 限流重试用尽等配置问题 → [ERROR] + 退出码 1
    me = (auth.impersonated or auth.account or "").lower()
    if me and not me.endswith("gserviceaccount.com") and core.email_domain(me):
        own_domains.add(core.email_domain(me))
    if granted_groups:
        ops.log(f"[DOMAIN] 本组织域名（用于判断读不到的 Group 是否外部域）: {', '.join(sorted(own_domains)) or '无'}")
    external, own_failed, nested = {}, {}, set()      # group -> 原因；嵌套组

    def fetch(g):
        reasons = {}
        return ops.group_members_typed(ctx, g, reasons), reasons

    for g, res, err in ops.parallel_map(fetch, sorted(granted_groups), workers=workers, desc="group"):
        if err:
            failed = True
            reason = str(err)
            if any(h in reason.lower() for h in ops._CONFIG_ERROR_HINTS):
                reason = f"Cloud Identity API 未在 quota 项目启用，或执行账号不能使用 quota 项目: {reason}"
            own_failed[g] = reason[:300]
            book.note(g, "未能展开")
            ops.log(f"[ERROR] 展开 group:{g} 失败: {reason[:500]}；已作为 group 写入 CSV，其成员未列入")
            continue
        members, reasons = res
        if members is None:
            reason = reasons.get(g, ops.GROUP_UNREADABLE_REASON)
            if core.is_own_domain(g, own_domains):
                failed = True
                own_failed[g] = reason
                book.note(g, "未能展开")
                ops.log(f"[ERROR] 展开 group:{g} 失败：{reason}；该 Group 属于本组织域名，应当能读取，"
                        "请确认跑脚本的 user / SA 有「群组 → 读取」权限；已作为 group 写入 CSV，其成员未列入")
            else:
                external[g] = reason
                book.note(g, "外部域，未展开")
                ops.log(f"[NOTE] group:{g} 是外部域的 Group（Cloud Identity 不允许读取其它组织的 Group），"
                        "已作为 group 写入 CSV，成员未展开")
            continue
        for email, mtype in members:
            email = email.lower()
            if mtype in _SKIP_GROUP_MEMBER_TYPES:
                continue
            if mtype == "GROUP":
                nested.add(email)
                book.add(email, "group", f"Group 成员: {g}（嵌套组，未展开）")
            else:
                book.add(email, core.principal_type(email), f"Group 成员: {g}")
    if granted_groups:
        parts = [f"嵌套组 {len(nested)} 个（只列组名）"] + \
                ([f"外部域 {len(external)} 个（未展开）"] if external else []) + \
                ([f"本域未能展开 {len(own_failed)} 个"] if own_failed else [])
        ops.log(f"[GROUP] 授权记录中的 Group {len(granted_groups)} 个，展开一层：" + "、".join(parts))

    rows = core.build_principal_rows(book, core.split_items(args.exclude_members),
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
