#!/usr/bin/env python3
"""
T7 Copilot 权限体系：批量创建权限 SA，并完成 Impersonation 与表级授权（文档 Step 6）。

步骤:
  1. SA 配额检查（单项目默认 100 个，超限 exit 2，不做任何变更）
  2. API SA 数据权限检查：API SA 不得拥有任何目标表/条件表的读数据权限（否则 exit 3）；
     并报告项目级拥有 serviceAccountTokenCreator 等扮演权限的主体（它们可绕过 API SA 直接扮演权限 SA）
  3. 创建（或复用）所有涉及的 Google Group（Group A/B 与公共组）
  4. 批量创建权限 SA；在每个权限 SA 上只授予 API SA roles/iam.serviceAccountTokenCreator
  5. 权限 SA 加入其表级 Group（1 SA 1 Group）以及公共组 --all-group
  6. 按 --grants-file 为 Group 授予表级（或数据集级）roles/bigquery.dataViewer
  7. 公共组授予条件表（adm_user_mem_copilot_condition）单表 dataViewer，及查询项目 roles/bigquery.jobUser

输入（二选一）:
  A. 直接读客户权限表：--auth-dataset auth-proj.auth（按文档默认表名，可用 --bind-table/--group-table/--grant-table 覆盖）
       权限 SA -> Group：adm_user_mem_copilot_user_bind ⋈ adm_user_mem_copilot_condition(sa) ⋈ adm_user_mem_copilot_group
       Group -> 表范围：adm_user_mem_copilot_grant_tb ⋈ adm_user_mem_copilot_group
  B. CSV：
       --sa-file     account_id,group[,display_name]
       --grants-file group,resource   resource 为 project.dataset.table 或 project.dataset
  两种方式都会校验「一 SA 一 Group」，违反则 exit 1 且不做任何变更。

示例:
  python setup_copilot_sas.py --project p --api-sa copilot-api@p.iam.gserviceaccount.com \\
      --auth-dataset auth-proj.auth --all-group copilot-all@x.com \\
      --condition-table auth-proj.auth.adm_user_mem_copilot_condition --apply

退出码: 0 成功；1 输入有误 / 一 SA 多 Group / 部分失败；2 超出 SA 配额；3 API SA 拥有数据读权限；
        4 存在项目级扮演风险（仅 --strict-impersonation）
"""

import argparse
import csv
import sys

import gcp_ops as ops
from gcp_ops import RoleResolver
import rls_core as core
from gcp_auth import get_credentials

TOKEN_CREATOR = "roles/iam.serviceAccountTokenCreator"
DATA_VIEWER = "roles/bigquery.dataViewer"
JOB_USER = "roles/bigquery.jobUser"


def read_csv(path, required):
    with open(path, encoding="utf-8-sig") as f:
        rows = [{k.strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]
    for c in required:
        if rows and c not in rows[0]:
            raise ValueError(f"{path} 缺少列 {c}")
    return rows


def api_sa_data_access(ctx, api_sa, project, tables, datasets):
    """返回 API SA 拥有数据读权限的位置列表。"""
    member = f"serviceAccount:{api_sa}"
    resolver = RoleResolver(ctx.iam)
    can_read = lambda role: core.classify_permissions(resolver.permissions(role))[0]  # noqa: E731
    found = []
    for b in ops.project_policy(ctx, project).get("bindings", []):
        if member in [core.normalize_member(m) for m in b.get("members", [])] and can_read(b["role"]):
            found.append(f"project {project}: {b['role']}")
    for d in sorted(datasets):
        for m, role in ops.dataset_member_roles(ctx.bq.get_dataset(d)):
            rw = core.classify_legacy_dataset_role(role) or core.classify_permissions(
                resolver.permissions(role))
            if m == member and rw[0]:
                found.append(f"dataset {d}: {role}")
    for t in sorted(tables):
        for role, members in ops.table_iam_bindings(ctx, t):
            if member in [core.normalize_member(m) for m in members] and can_read(role):
                found.append(f"table {t}: {role}")
    return found


def main():
    p = argparse.ArgumentParser(description="批量创建 Copilot 权限 SA 并授权")
    p.add_argument("--project", required=True, help="权限 SA 所在项目")
    p.add_argument("--api-sa", required=True, help="Copilot 后端 API SA 邮箱")
    p.add_argument("--all-group", required=True, help="所有权限 SA 的公共组（条件表读权限 + jobUser）")
    p.add_argument("--condition-table", required=True, help="adm_user_mem_copilot_condition 全名")
    src = p.add_argument_group("输入来源（二选一：直接读客户权限表，或 CSV）")
    src.add_argument("--auth-dataset", default=None,
                     help="权限表所在 project.dataset；按文档默认表名读取 user_bind / group / grant_tb")
    src.add_argument("--bind-table", default=None, help="adm_user_mem_copilot_user_bind 全名（覆盖默认）")
    src.add_argument("--group-table", default=None, help="adm_user_mem_copilot_group 全名（覆盖默认）")
    src.add_argument("--grant-table", default=None, help="adm_user_mem_copilot_grant_tb 全名（覆盖默认）")
    src.add_argument("--sa-file", default=None, help="CSV: account_id,group[,display_name]")
    src.add_argument("--grants-file", default=None, help="CSV: group,resource")
    p.add_argument("--job-project", default=None, help="承载查询的项目（默认 --project）")
    p.add_argument("--customer-id", default=None)
    p.add_argument("--initial-config", choices=["WITH_INITIAL_OWNER", "EMPTY"], default="EMPTY")
    p.add_argument("--sa-limit", type=int, default=core.SA_PER_PROJECT_LIMIT)
    p.add_argument("--strict-impersonation", action="store_true",
                   help="发现项目级可扮演任意 SA 的主体时中止（exit 4）")
    p.add_argument("--gcloud-account", default=None)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    project = args.project
    job_project = args.job_project or project
    api_sa = args.api_sa.lower()
    cond = core.fq(args.condition_table)
    all_group = args.all_group.lower()
    table_mode = bool(args.auth_dataset or args.bind_table or args.grant_table)
    if not args.sa_file and not table_mode:
        p.error("请指定 --sa-file，或用 --auth-dataset / --bind-table 直接读取权限表")
    if not args.grants_file and not table_mode:
        p.error("请指定 --grants-file，或用 --auth-dataset / --grant-table 直接读取权限表")

    ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode} =====")

    # 0. 输入：权限 SA -> Group（表 5 ⋈ 表 1 ⋈ 表 3），Group -> 授权范围（表 4 ⋈ 表 3）
    try:
        if args.sa_file:
            sa_rows = read_csv(args.sa_file, ["account_id", "group"])
            ops.log(f"[SOURCE] 权限 SA 清单: {args.sa_file}（{len(sa_rows)} 行）")
        else:
            bind = core.auth_table("bind", args.auth_dataset, args.bind_table)
            grp_t = core.auth_table("group", args.auth_dataset, args.group_table)
            sa_rows = [dict(r.items()) for r in ops.run_query(
                ctx, core.bind_sa_group_sql(bind, cond, grp_t), ctx.table_location(bind))]
            ops.log(f"[SOURCE] 权限 SA 清单: {bind} ⋈ {cond} ⋈ {grp_t}（{len(sa_rows)} 行）")
            sa_suffix = f"@{project}.iam.gserviceaccount.com"
            for r in sa_rows:
                if "@" in str(r.get("sa", "")) and not str(r["sa"]).lower().endswith(sa_suffix):
                    ops.log(f"  [WARN] 条件表中的 {r['sa']} 不在项目 {project} 下，"
                            f"将按 account id 在 {project} 创建/复用，请确认 --project 是否正确")
        if args.grants_file:
            grant_rows = read_csv(args.grants_file, ["group", "resource"])
            ops.log(f"[SOURCE] 表级授权范围: {args.grants_file}（{len(grant_rows)} 行）")
        else:
            grant_t = core.auth_table("grant", args.auth_dataset, args.grant_table)
            grp_t = core.auth_table("group", args.auth_dataset, args.group_table)
            grant_rows = [dict(r.items()) for r in ops.run_query(
                ctx, core.grant_scope_sql(grant_t, grp_t), ctx.table_location(grant_t))]
            ops.log(f"[SOURCE] 表级授权范围: {grant_t} ⋈ {grp_t}（{len(grant_rows)} 行）")
        sas = core.parse_sa_rows(sa_rows)
        grants = core.parse_grant_rows(grant_rows)
    except ValueError as e:
        ops.log(f"[ERROR] 输入有误: {e}")
        return 1
    if not sas:
        ops.log("[ERROR] 权限 SA 清单为空")
        return 1
    conflicts = core.sa_group_conflicts(sas)
    if conflicts:
        for aid, groups in conflicts.items():
            ops.log(f"[ERROR] 一 SA 一 Group：{core.sa_email(aid, project)} 同时映射到 {groups}")
        ops.log("已中止，未做任何变更。请修正 adm_user_mem_copilot_user_bind（或 sas.csv）后重试。")
        return 1
    ops.log(f"[INPUT] 权限 SA {len(sas)} 个，表级授权 {len(grants)} 条，一 SA 一 Group: OK")

    # 1. 配额
    existing = set(ops.list_sas(ctx, project))
    to_create = [a for a, _, _ in sas if core.sa_email(a, project) not in existing]
    try:
        if to_create:
            core.check_sa_quota(len(existing), len(to_create), args.sa_limit)
    except ValueError as e:
        ops.log(f"[QUOTA] {e}")
        return 2
    ops.log(f"[QUOTA] 现有 {len(existing)} 个 SA，新建 {len(to_create)} 个，上限 {args.sa_limit}: OK")

    # 2. API SA 数据权限
    tables = {res for _, res in grants if res.count(".") == 2} | {cond}
    datasets = {res for _, res in grants if res.count(".") == 1} | {
        ".".join(core.parse_table(t)[:2]) for t in tables}
    found = api_sa_data_access(ctx, api_sa, project, tables, datasets)
    if found:
        for f in found:
            ops.log(f"[API-SA] {api_sa} 拥有数据读权限: {f}")
        ops.log("API SA 数据权限检查: FAILED（API SA 只能通过扮演权限 SA 查询，请先回收上述权限）")
        return 3
    ops.log("API SA 数据权限检查: OK")

    # 2b. 项目级可扮演任意 SA 的主体（会绕过"只有 API SA 能扮演权限 SA"）
    resolver = RoleResolver(ctx.iam)
    risks = core.impersonation_risks(ops.project_policy(ctx, project).get("bindings", []),
                                     resolver.permissions, allowed=[api_sa])
    agents = sorted({m for m, _ in risks if core.is_service_agent(m)})
    actionable = [(m, r) for m, r in risks if not core.is_service_agent(m)]
    for m, role in actionable:
        ops.log(f"[IMPERSONATION-RISK] {m} 通过项目级 {role} 可扮演项目内任意 SA（含权限 SA）")
    if agents:
        ops.log(f"[IMPERSONATION-INFO] 另有 {len(agents)} 个 Google 托管服务代理具备扮演能力"
                f"（由 Google 管理，通常无需处理）")
    if actionable:
        ops.log("  建议：回收上述项目级扮演权限，或把权限 SA 放在独立项目中")
        if args.strict_impersonation:
            return 4
    else:
        ops.log("项目级扮演风险检查: OK")

    groups = sorted({g for _, g, _ in sas} | {g for g, _ in grants} | {all_group})
    ops.log(f"[PLAN] Group: {groups}")
    for a, g, _ in sas:
        ops.log(f"[PLAN] SA {core.sa_email(a, project)} -> {g}, {all_group}; TokenCreator <- {api_sa}")
    for g, res in grants:
        ops.log(f"[PLAN] {DATA_VIEWER} on {res} -> group:{g}")
    ops.log(f"[PLAN] {DATA_VIEWER} on {cond} -> group:{all_group}")
    ops.log(f"[PLAN] {JOB_USER} on project {job_project} -> group:{all_group}")
    if not args.apply:
        return 0

    failed = False

    def step(desc, fn):
        nonlocal failed
        try:
            changed = fn()
            ops.log(f"  [{'OK' if changed else 'EXISTS'}] {desc}")
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"  [ERROR] {desc}: {e}")

    # 3. Group
    customer_id = args.customer_id
    names = {}
    for g in groups:
        name = ops.lookup_group(ctx, g)
        if not name:
            customer_id = customer_id or ops.resolve_customer_id(ctx, project)
            name, _ = ops.ensure_group(ctx, g, customer_id, initial_config=args.initial_config)
            ops.log(f"[GROUP] 已创建 {g}")
        names[g] = name
    members = {g: ops.group_members(ctx, n) for g, n in names.items()}

    # 4/5. SA
    for a, g, display in sas:
        email, created = ops.create_sa(ctx, project, a, display)
        ops.log(f"[SA] {email} {'已创建' if created else '已存在'}")
        step(f"{TOKEN_CREATOR} on {email} -> {api_sa}",
             lambda: ops.sa_add_role(ctx, email, TOKEN_CREATOR, f"serviceAccount:{api_sa}"))
        for grp in (g, all_group):
            if email not in members[grp]:
                step(f"{email} 加入 {grp}", lambda: ops.add_group_member(ctx, names[grp], email))

    # 6. 表级 / 数据集级授权
    for g, res in grants:
        if res.count(".") == 2:
            step(f"{DATA_VIEWER} on {res} -> group:{g}",
                 lambda: ops.table_add_role(ctx, res, DATA_VIEWER, f"group:{g}"))
        else:
            step(f"READER on dataset {res} -> group:{g}",
                 lambda: ops.dataset_add_reader(ctx, res, f"group:{g}"))

    # 7. 条件表 + jobUser
    step(f"{DATA_VIEWER} on {cond} -> group:{all_group}",
         lambda: ops.table_add_role(ctx, cond, DATA_VIEWER, f"group:{all_group}"))
    step(f"{JOB_USER} on project {job_project} -> group:{all_group}",
         lambda: ops.project_add_role(ctx, job_project, JOB_USER, f"group:{all_group}"))

    ops.log(f"===== 完成 ({mode}) =====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
