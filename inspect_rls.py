#!/usr/bin/env python3
"""
RLS 巡检：逐表核对白名单 policy 与 Copilot policy 是否符合预期，并检查白名单 Group 是否混入 Copilot SA。

检查项:
  1. 白名单 policy（rls_bypass_full_access）存在、过滤条件为 TRUE、包含所有 --bypass-groups
  2. 对映射表中有配置的表：Copilot policy 存在、包含所有 --copilot-groups、
     过滤条件与"按当前映射表 + 表 schema 生成的条件"一致（检测映射变更或被手工改动）
  3. 白名单 Group（默认 = --bypass-groups）成员中不得出现 Copilot SA——递归展开嵌套组检查，
     读不到的嵌套组（外部域 / 无权限）给提醒
  4. 条件表按 sa 聚簇（R4）
  5. Copilot 组成员：一 SA 只在一个组（问题）、API SA 不在组中（问题）、
     成员没有条件行 / 条件行不在任何组（提醒，不影响退出码）
  6. --acl-table：白名单名册表（adm_user_mem_copilot_acl_group_sa）与白名单 Group 实际成员双向比对，
     组里多出的账号、名册里还没加组的账号都算问题（探针 SA 用 --probe-sa 排除）

示例:
  python inspect_rls.py --tables-file tables.txt \\
      --mapping-table p.auth.adm_user_mem_copilot_tb_col_mapping \\
      --condition-table p.auth.adm_user_mem_copilot_condition \\
      --bypass-groups full-write@x.com,full-read@x.com --copilot-groups copilot-high@x.com,copilot-low@x.com \\
      --copilot-patterns 'copilot-*@*' --copilot-members copilot-api@p.iam.gserviceaccount.com

退出码: 0 无问题；1 发现问题
"""

import argparse
import sys

import gcp_ops as ops
import rls_core as core
from apply_copilot_rls import load_mapping, table_schema
from gcp_auth import get_credentials


def main():
    p = argparse.ArgumentParser(description="RLS 策略与白名单巡检")
    p.add_argument("--tables", nargs="*", default=[])
    p.add_argument("--tables-file", default=None)
    p.add_argument("--mapping-table", default=None)
    p.add_argument("--mapping-csv", default=None)
    p.add_argument("--condition-table", default=None)
    p.add_argument("--default-project", default=None)
    p.add_argument("--bypass-groups", nargs="+", required=True)
    p.add_argument("--copilot-groups", nargs="*", default=[])
    p.add_argument("--whitelist-groups", nargs="*", default=[],
                   help="检查成员的白名单 Group（默认 = --bypass-groups 中的 group）")
    p.add_argument("--copilot-members", nargs="*", default=[])
    p.add_argument("--copilot-patterns", nargs="*", default=[])
    p.add_argument("--case-insensitive", action="store_true", help="与 apply_copilot_rls.py 保持一致")
    p.add_argument("--api-sa", default=None, help="Copilot API SA（检查它不在 Copilot 组中）")
    p.add_argument("--acl-table", default=None,
                   help="白名单名册表 adm_user_mem_copilot_acl_group_sa 全名；给出后与白名单 Group 实际成员双向比对")
    p.add_argument("--write-group", default=None,
                   help="名册 acl_group 为 write 类标识时对应的 Group（默认从 --bypass-groups 里找名字含 write 的）")
    p.add_argument("--read-group", default=None, help="同上，read 类")
    p.add_argument("--probe-sa", default=None, help="探针 SA（名册比对时忽略）")
    p.add_argument("--bypass-policy-name", default=core.BYPASS_POLICY)
    p.add_argument("--policy-name", default=core.COPILOT_POLICY)
    p.add_argument("--project", default=None)
    p.add_argument("--gcloud-account", default=None)
    args = p.parse_args()

    tables = core.split_items(args.tables) + (core.read_list_file(args.tables_file)
                                               if args.tables_file else [])
    if not tables:
        p.error("请指定 --tables 或 --tables-file")
    tables = list(dict.fromkeys(core.fq(t, args.default_project) for t in tables))
    if (args.mapping_table or args.mapping_csv) and not args.condition_table:
        p.error("使用映射表时需要 --condition-table")
    project = args.project or core.parse_table(tables[0])[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)

    bypass = [core.normalize_member(g) for g in core.split_items(args.bypass_groups)]
    copilot = [core.normalize_member(g) for g in core.split_items(args.copilot_groups)]
    mapping = {}
    if args.mapping_table or args.mapping_csv:
        mapping = load_mapping(ctx, args.mapping_table, args.mapping_csv,
                               args.default_project or project)
    cond = core.fq(args.condition_table) if args.condition_table else None

    n_issues = 0
    for t in tables:
        expected = None
        issues = []
        if t in mapping:
            schema = table_schema(ctx, t)
            errs = core.validate_mapping_against_schema(mapping[t], schema)
            if errs:
                issues += [f"映射配置错误: {e}" for e in errs]
            else:
                expected = core.build_copilot_filter(
                    mapping[t], cond, column_types={c: schema[c][0] for c, _ in mapping[t]},
                    case_insensitive=args.case_insensitive)
        issues += core.inspect_policies(ops.list_policies(ctx, t), bypass, copilot, expected,
                                        args.bypass_policy_name, args.policy_name)
        if issues:
            n_issues += len(issues)
            for i in issues:
                print(f"[ISSUE] {t}: {i}")
        else:
            print(f"[OK] {t}" + ("" if expected else "（无 Copilot 映射，仅检查白名单 policy）"))

    wl = [core.member_email(g) for g in (core.split_items(args.whitelist_groups) or
                                          [g for g in bypass if g.startswith("group:")])]
    members = {}
    for g in wl:
        name = ops.lookup_group(ctx, g)
        if not name:
            print(f"[ISSUE] 白名单 Group {g} 不存在或无权限查看")
            n_issues += 1
            continue
        members[g] = sorted(ops.group_members(ctx, name))
    for i in core.inspect_whitelist_membership(members, core.split_items(args.copilot_members),
                                               core.split_items(args.copilot_patterns)):
        print(f"[ISSUE] {i}")
        n_issues += 1
    # P0：递归展开白名单组里的嵌套组，Copilot SA 藏在嵌套组里同样会命中 FILTER TRUE
    n_warns = 0
    expanded = {g: ops.expand_group(ctx, g) for g in members}
    issues, warns = core.inspect_nested_copilot(expanded, core.split_items(args.copilot_members),
                                                core.split_items(args.copilot_patterns))
    for i in issues:
        print(f"[ISSUE] {i}")
    for w in warns:
        print(f"[WARN] {w}")
    n_issues += len(issues)
    n_warns += len(warns)

    # 白名单名册（adm_user_mem_copilot_acl_group_sa）是事实来源：与 Group 实际成员双向比对
    if args.acl_table:
        acl = core.fq(args.acl_table)
        rows = [dict(r.items()) for r in ops.run_query(
            ctx, f"SELECT sa, acl_group FROM `{acl}`", ctx.table_location(acl))]
        wg = next((g for g in wl if g.endswith("write") or "write" in g), None)
        rg = next((g for g in wl if g.endswith("read") or "read" in g), None)
        try:
            roster = core.acl_roster(rows, args.write_group or wg, args.read_group or rg)
        except ValueError as e:
            print(f"[ISSUE] {e}")
            n_issues += 1
            roster = {}
        actual = {g: set(ms) for g, ms in members.items()}
        wanted = {g: {core.member_email(m) for m in ms} for g, ms in roster.items()}
        for i in core.inspect_acl_roster(actual, wanted,
                                         ignore=[args.probe_sa] if args.probe_sa else []):
            print(f"[ISSUE] {i}")
            n_issues += 1
        print(f"[ACL] 名册 {acl}: {len(rows)} 行，已与 {len(members)} 个白名单 Group 比对")

    # E2：条件表聚簇、Copilot SA 归属 / 条件行 / API SA
    if cond:
        for i in core.inspect_condition_clustering(ctx.bq.get_table(cond).clustering_fields):
            print(f"[ISSUE] {i}")
            n_issues += 1
    if copilot and cond:
        cop_members = {}
        for g in copilot:
            if not g.startswith("group:"):
                continue
            name = ops.lookup_group(ctx, core.member_email(g))
            if not name:
                print(f"[ISSUE] Copilot Group {g} 不存在或无权限查看")
                n_issues += 1
                continue
            cop_members[g] = ops.group_members(ctx, name)
        issues, warns = core.inspect_copilot_membership(cop_members, ops.condition_sas(ctx, cond),
                                                        api_sa=args.api_sa)
        for i in issues:
            print(f"[ISSUE] {i}")
        for w in warns:
            print(f"[WARN] {w}")
        n_issues += len(issues)
        n_warns += len(warns)

    print(f"\n巡检完成：{len(tables)} 张表，{len(members)} 个白名单 Group，"
          f"发现 {n_issues} 个问题，{n_warns} 个提醒")
    return 1 if n_issues else 0


if __name__ == "__main__":
    sys.exit(main())
