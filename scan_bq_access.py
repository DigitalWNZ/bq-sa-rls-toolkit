#!/usr/bin/env python3
"""
T2 存量账号扫描：找出对目标表有读/写权限或真实读写过目标表的所有主体，按读写分类，
生成白名单候选清单（供 whitelist_groups.py --scan-csv 使用）。

扫描范围（针对每张目标表）:
  1. 项目级 IAM（展开角色为权限，判断 bigquery.tables.getData / updateData）
  2. 数据集级 ACL（legacy READER/WRITER/OWNER 及 IAM 角色）
  3. 表级 IAM
  4. INFORMATION_SCHEMA.JOBS 最近 N 天真实读写过目标表的账号（可兜底 Folder/Org 继承）
     - 作业历史存放在"提交作业的项目"里：跨项目作业需用 --job-projects 追加扫描提交项目，
       或 --jobs-scope organization 用 JOBS_BY_ORGANIZATION 一次覆盖全组织
     - 同时检测对目标数据集的通配符表查询（table_*），表启用 RLS 后此类查询会失败（R5）；
       组织级视图没有 query 列，--jobs-scope organization 时跳过这一项
  5. 授权视图 / 授权数据集（R1，默认开启，--no-authorized 关闭）：目标数据集 ACL 里授权的视图 / 数据集，
     其项目 / 数据集 / 视图三层 IAM 里的读者也列出来（经由视图查询时底表 RLS 同样生效）；只追一层
  6. 可选 --analyze-scope：对每张目标表（及上面的授权视图 / 数据集）调用 Cloud Asset analyzeIamPolicy，
     展开 Group（含嵌套）并包含组织 / 文件夹层级的继承授权，sources 里标注 "via group:..."
  扫描范围可用 --tables/--tables-file 指定表，或 --datasets 指定数据集（展开为全部表）
Copilot SA（--copilot-members / --copilot-patterns）会被标记并排除出白名单建议；候选里的 Group 会递归展开，
组内（含嵌套组）有 Copilot SA 的组也不给建议（--no-expand-groups 关闭展开）。
结束时输出 [PROJECTS]：扫描到的（非 Copilot）SA 所属项目，--sa-projects-out 可写成项目列表文件，
作为 list_project_sas.py --projects-file 的输入。

输出 CSV 列:
  principal, principal_type, can_read, can_write, suggested_group(write/read/空),
  sources, jobs_read_count, jobs_write_count, wildcard_jobs, copilot, note

示例:
  python scan_bq_access.py --tables p.d.t1,p.d.t2 --jobs-days 90 \\
      --copilot-patterns 'copilot-*@*' --copilot-members api-sa@p.iam.gserviceaccount.com -o scan.csv
"""

import argparse
import csv
import sys
from collections import defaultdict

from google.cloud import bigquery

import gcp_ops as ops
from gcp_ops import RoleResolver
import rls_core as core
from gcp_auth import get_credentials

COLUMNS = ["principal", "principal_type", "can_read", "can_write", "suggested_group", "sources",
           "jobs_read_count", "jobs_write_count", "wildcard_jobs", "copilot", "note"]


class Acc:
    def __init__(self):
        self.read = self.write = False
        self.sources = []
        self.jobs_read = self.jobs_write = 0
        self.wildcard = 0

    def add(self, read, write, source):
        if read or write:
            self.read |= read
            self.write |= write
            if source not in self.sources:
                self.sources.append(source)


def scan(ctx, tables, jobs_days, regions=None, job_projects=None, jobs_scope="project",
         analyze_scope=None, follow_authorized=True):
    acc = defaultdict(Acc)
    resolver = RoleResolver(ctx.iam)
    rw_cache = {}

    def role_rw(role):
        if role not in rw_cache:
            rw_cache[role] = core.classify_permissions(resolver.permissions(role))
        return rw_cache[role]

    projects = sorted({core.parse_table(t)[0] for t in tables})
    datasets = sorted({core.parse_table(t)[:2] for t in tables})

    for project in projects:
        ops.log(f"[IAM] 项目 {project}")
        for b in ops.project_policy(ctx, project).get("bindings", []):
            r, w = role_rw(b["role"])
            cond = "(conditional)" if b.get("condition") else ""
            for m in b.get("members", []):
                acc[core.normalize_member(m)].add(r, w, f"project:{b['role']}{cond}")

    for p, d in datasets:
        ops.log(f"[IAM] 数据集 {p}.{d}")
        ds = ctx.bq.get_dataset(f"{p}.{d}")
        for member, role in ops.dataset_member_roles(ds):
            rw = core.classify_legacy_dataset_role(role) or role_rw(role)
            acc[member].add(*rw, f"dataset:{d}:{role}")

    for t in tables:
        ops.log(f"[IAM] 表 {t}")
        for role, members in ops.table_iam_bindings(ctx, t):
            r, w = role_rw(role)
            for m in members:
                acc[core.normalize_member(m)].add(r, w, f"table:{t.split('.')[-1]}:{role}")

    # 授权视图 / 授权数据集（R1）：目标数据集 ACL 里授权的视图 / 数据集在读目标表的数据，
    # 通过它们查询时底表的 RLS 按查询者身份生效，所以它们的读者也要进白名单。只追一层。
    auth_views, auth_datasets = [], []
    if follow_authorized:
        for p, d in datasets:
            v, ds_ = ops.dataset_authorized(ctx.bq.get_dataset(f"{p}.{d}"))
            auth_views += v
            auth_datasets += ds_
        auth_views, auth_datasets = sorted(set(auth_views)), sorted(set(auth_datasets))
        for v in auth_views:
            vp, vd, vt = core.parse_table(v)
            ops.log(f"[AUTH-VIEW] 授权视图 {v}")
            tag = f"authorized-view:{v}"
            try:
                for b in ops.project_policy(ctx, vp).get("bindings", []):
                    r, w = role_rw(b["role"])
                    for m in b.get("members", []):
                        acc[core.normalize_member(m)].add(r or w, False, f"{tag}/project:{b['role']}")
                for member, role in ops.dataset_member_roles(ctx.bq.get_dataset(f"{vp}.{vd}")):
                    rw = core.classify_legacy_dataset_role(role) or role_rw(role)
                    acc[member].add(rw[0] or rw[1], False, f"{tag}/dataset:{vd}:{role}")
                for role, members in ops.table_iam_bindings(ctx, v):
                    r, w = role_rw(role)
                    for m in members:
                        acc[core.normalize_member(m)].add(r or w, False, f"{tag}/table:{role}")
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] 读取授权视图 {v} 的权限失败: {e}")
        for ad in auth_datasets:
            ap, adn = ad.split(".")
            ops.log(f"[AUTH-DATASET] 授权数据集 {ad}")
            tag = f"authorized-dataset:{ad}"
            try:
                for b in ops.project_policy(ctx, ap).get("bindings", []):
                    r, w = role_rw(b["role"])
                    for m in b.get("members", []):
                        acc[core.normalize_member(m)].add(r or w, False, f"{tag}/project:{b['role']}")
                for member, role in ops.dataset_member_roles(ctx.bq.get_dataset(ad)):
                    rw = core.classify_legacy_dataset_role(role) or role_rw(role)
                    acc[member].add(rw[0] or rw[1], False, f"{tag}/dataset:{role}")
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] 读取授权数据集 {ad} 的权限失败: {e}")

    # analyzeIamPolicy：展开 Group（含嵌套）并包含组织 / 文件夹层级的继承授权
    if analyze_scope:
        targets = [(t, False) for t in tables] + [(v, True) for v in auth_views] + [(d, True) for d in auth_datasets]
        for ref, via_auth in targets:
            res = ops.bq_full_resource_name(ref)
            ops.log(f"[ANALYZE] {ref}（{analyze_scope}）")
            try:
                results, full = ops.analyze_access(ctx, analyze_scope, res,
                                                   [core.READ_PERMISSION, core.WRITE_PERMISSION])
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] analyzeIamPolicy 失败: {e}")
                continue
            if not full:
                ops.log("  [WARN] 分析结果不完整（fullyExplored=false），可能有授权没有列出")
            for row in core.analysis_principals(results):
                src = core.analysis_source(row)
                if via_auth:
                    src = f"authorized:{ref}/{src}"
                acc[row["principal"]].add(row["read"] or row["write"],
                                          row["write"] and not via_auth, src)

    if jobs_days > 0:
        all_tables = sorted(core.fq(t) for t in tables)
        all_datasets = sorted({".".join(core.parse_table(t)[:2]) for t in tables})
        region_set = set(regions or [])
        if not region_set:
            region_set = {ctx.location(*core.parse_table(t)[:2]).lower() for t in tables}
        # C2：作业历史按"作业提交所在项目"存放，跨项目作业要扫其他项目；organization 作用域一次覆盖全组织
        if jobs_scope == "organization":
            job_sources = [(projects[0], r) for r in sorted(region_set)]
        else:
            job_sources = [(p, r) for p in sorted(set(projects) | set(job_projects or []))
                           for r in sorted(region_set)]
        wildcard_pat = core.wildcard_pattern(all_datasets)
        for p, region in job_sources:
            label = "组织" if jobs_scope == "organization" else p
            ops.log(f"[JOBS] {label} / region-{region}（最近 {jobs_days} 天）")
            try:
                rows = ops.run_query(
                    ctx, core.jobs_access_sql(p, region, jobs_days, scope=jobs_scope), region,
                    [bigquery.ArrayQueryParameter("tables", "STRING", all_tables)])
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] 作业历史查询失败: {e}")
                continue
            for r in rows:
                a = acc[core.normalize_member(r.user_email, default_prefix="user")]
                if r.mode == "WRITE":
                    a.jobs_write += r.job_count
                else:
                    a.jobs_read += r.job_count
            # E3：通配符表查询（有 RLS 的表不支持 table_*）。只有 JOBS_BY_PROJECT 有 query 列
            if jobs_scope == "organization":
                ops.log("  [INFO] 组织级作业视图没有 query 列，跳过通配符表查询检测；"
                        "需要检测时请按项目扫描（默认作用域 + --job-projects）")
                continue
            try:
                wrows = ops.run_query(
                    ctx, core.wildcard_jobs_sql(p, region, jobs_days, scope=jobs_scope), region,
                    [bigquery.ScalarQueryParameter("pattern", "STRING", wildcard_pat)])
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] 通配符查询检测失败: {e}")
                continue
            for r in wrows:
                acc[core.normalize_member(r.user_email, default_prefix="user")].wildcard += r.job_count
                ops.log(f"  [WARN] {r.user_email} 最近 {jobs_days} 天有 {r.job_count} 次通配符表查询"
                        f"（目标数据集 {all_datasets}），表启用 RLS 后此类查询会失败（R5）")
    return acc


def to_rows(acc, copilot_members, copilot_patterns):
    rows = []
    for principal, a in sorted(acc.items()):
        if not (a.read or a.write or a.jobs_read or a.jobs_write or a.wildcard):
            continue
        ptype = principal.split(":")[0] if ":" in principal else ""
        copilot = core.is_copilot_member(principal, copilot_members, copilot_patterns)
        notes = []
        if copilot:
            group = ""
            notes.append("Copilot SA，已排除出白名单")
        elif a.write or a.jobs_write:
            group = "write"
        elif a.read or a.jobs_read:
            group = "read"
        else:
            group = ""
        if not a.sources and (a.jobs_read or a.jobs_write):
            notes.append("仅出现在作业历史（可能来自 Folder/Org 继承或已回收权限），请人工确认")
        if core.is_service_agent(principal):
            notes.append("Google 托管服务代理，确认该服务是否读写目标表后再决定是否加白名单")
        if a.sources and all(src.startswith(("authorized-view:", "authorized-dataset:", "authorized:"))
                             for src in a.sources):
            notes.append("只通过授权视图 / 授权数据集访问目标数据（经由视图查询时底表 RLS 同样生效）")
        if a.sources and all(" via group:" in src for src in a.sources):
            notes.append("经由 Group 获得权限：可以把该账号单独加白名单，或把整个 Group 加入白名单（需确认组内没有 Copilot SA）")
        if a.wildcard:
            notes.append(f"最近有 {a.wildcard} 次通配符表查询（table_*），表启用 RLS 后会失败，需改写 SQL（R5）")
        if ptype in ("specialGroup", "domain", "allUsers", "allAuthenticatedUsers") or ptype.startswith("project"):
            notes.append("非具体账号，无法加入 Group，请人工处理")
            group = ""
        rows.append({
            "principal": principal, "principal_type": ptype,
            "can_read": a.read, "can_write": a.write, "suggested_group": group,
            "sources": "; ".join(a.sources), "jobs_read_count": a.jobs_read,
            "jobs_write_count": a.jobs_write, "wildcard_jobs": a.wildcard,
            "copilot": copilot, "note": "; ".join(notes),
        })
    return rows


def main():
    p = argparse.ArgumentParser(description="扫描目标表的存量读写账号（白名单候选）")
    p.add_argument("--tables", nargs="*", default=[], help="project.dataset.table，可逗号分隔")
    p.add_argument("--tables-file", default=None)
    p.add_argument("--datasets", nargs="*", default=[],
                   help="project.dataset 列表，展开为其中全部表（客户按数据集提供扫描范围时使用）")
    p.add_argument("--jobs-days", type=int, default=90, help="作业历史天数，0 关闭（默认 90）")
    p.add_argument("--job-projects", nargs="*", default=[],
                   help="额外扫描这些项目的作业历史（跨项目提交、读写目标表的作业只出现在提交项目里）")
    p.add_argument("--jobs-scope", choices=["project", "organization"], default="project",
                   help="organization：查 JOBS_BY_ORGANIZATION 一次覆盖全组织（需组织级 bigquery.jobs.listAll）")
    p.add_argument("--regions", nargs="*", default=[], help="作业历史区域，默认取表所在数据集位置")
    p.add_argument("--analyze-scope", default=None,
                   help="用 Cloud Asset analyzeIamPolicy 补充：organizations/<id> | folders/<id> | projects/<id>。"
                        "展开 Group（含嵌套）并包含该范围内的继承授权（组织范围才能看到 Folder / Org 层）")
    p.add_argument("--no-expand-groups", action="store_true",
                   help="不递归展开候选里的 Group（默认展开：组内含 Copilot SA 的组不给白名单建议）")
    p.add_argument("--no-authorized", action="store_true",
                   help="不追踪目标数据集 ACL 里的授权视图 / 授权数据集的读者")
    p.add_argument("--copilot-members", nargs="*", default=[])
    p.add_argument("--copilot-patterns", nargs="*", default=[])
    p.add_argument("-o", "--output", default="scan_bq_access.csv")
    p.add_argument("--sa-projects-out", default=None,
                   help="把扫描到的 SA 所属项目写成项目列表文件（供 list_project_sas.py --projects-file 使用）")
    p.add_argument("--project", default=None, help="quota / 运行查询的项目（默认第一张表的项目）")
    p.add_argument("--gcloud-account", default=None)
    args = p.parse_args()

    tables = core.split_items(args.tables) + (core.read_list_file(args.tables_file)
                                               if args.tables_file else [])
    datasets = core.split_items(args.datasets)
    if not tables and not datasets:
        p.error("请指定 --tables / --tables-file / --datasets")
    first = (tables or datasets)[0].replace(":", ".")
    project = args.project or first.split(".")[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)
    for d in datasets:   # E4：按数据集范围展开为表
        pd = d.replace(":", ".")
        found = [f"{pd}.{t.table_id}" for t in ctx.bq.list_tables(pd) if t.table_type == "TABLE"]
        ops.log(f"[SCOPE] 数据集 {pd}: {len(found)} 张表")
        tables += found
    tables = list(dict.fromkeys(core.fq(t) for t in tables))

    analyze_scope = None
    if args.analyze_scope:
        analyze_scope = args.analyze_scope.strip()
        if not analyze_scope.startswith(("organizations/", "folders/", "projects/")):
            p.error("--analyze-scope 格式：organizations/<id> | folders/<id> | projects/<id>")
    acc = scan(ctx, tables, args.jobs_days, core.split_items(args.regions) or None,
               core.split_items(args.job_projects), args.jobs_scope,
               analyze_scope=analyze_scope, follow_authorized=not args.no_authorized)
    rows = to_rows(acc, core.split_items(args.copilot_members),
                   core.split_items(args.copilot_patterns))
    # 候选里的 Group 要递归展开：组内有 Copilot SA 的组不能整组加入白名单（否则 Copilot 命中 FILTER TRUE）
    if not args.no_expand_groups:
        for r in rows:
            if r["principal_type"] != "group" or not r["suggested_group"]:
                continue
            g = core.member_email(r["principal"])
            if ops.group_members_typed(ctx, g) is None:
                r["note"] = "; ".join(filter(None, [r["note"], "无法展开该组（外部域或无权限），加入白名单前请确认组内没有 Copilot SA"]))
                continue
            members, unresolved = ops.expand_group(ctx, g)
            bad = [(e, i["via"]) for e, i in sorted(members.items())
                   if core.is_copilot_member(e, core.split_items(args.copilot_members),
                                             core.split_items(args.copilot_patterns))]
            if bad:
                r["suggested_group"] = ""
                r["note"] = "; ".join(filter(None, [r["note"], "组内含 Copilot SA（" + ", ".join(
                    f"{e} 路径 {' > '.join(v)}" for e, v in bad[:3]) + "），不能整组加入白名单；请把组内的存量账号单独加入"]))
            elif unresolved:
                r["note"] = "; ".join(filter(None, [r["note"], "组内有无法展开的嵌套组，加入白名单前请确认没有 Copilot SA"]))
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    n_w = sum(r["suggested_group"] == "write" for r in rows)
    n_r = sum(r["suggested_group"] == "read" for r in rows)
    n_c = sum(r["copilot"] for r in rows)
    n_wc = sum(1 for r in rows if r["wildcard_jobs"])
    for r in rows:
        print(f"{r['suggested_group'] or '-':5} {r['principal']}  [{r['sources']}] "
              f"jobs(r/w)={r['jobs_read_count']}/{r['jobs_write_count']} {r['note']}")
    print(f"\n共 {len(rows)} 个主体：写白名单候选 {n_w}，读白名单候选 {n_r}，Copilot 排除 {n_c}，"
          f"使用过通配符查询 {n_wc}。结果已写入 {args.output}（请客户审核后再加组）")
    # 扫描结果里出现的 SA 分别属于哪些项目：作为 list_project_sas.py 项目列表的数据来源（而不是靠人列）
    home = core.sa_home_projects(r["principal"] for r in rows if not r["copilot"])
    ops.log(f"[PROJECTS] 涉及的 SA 所属项目 {len(home)} 个（可作为 list_project_sas.py 的项目列表）: "
            + ", ".join(home))
    if args.sa_projects_out:
        with open(args.sa_projects_out, "w", encoding="utf-8") as f:
            f.write("# scan_bq_access.py 发现的 SA 所属项目（数字为项目号）\n" + "".join(f"{x}\n" for x in home))
        ops.log(f"[PROJECTS] 已写入 {args.sa_projects_out}")


if __name__ == "__main__":
    sys.exit(main())
