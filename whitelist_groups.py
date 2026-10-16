#!/usr/bin/env python3
"""
T3 全局白名单 Group：创建读/写白名单 Group，批量加入存量账号，并做生效探针验证。
也用于 T5"热修补白名单"——只把遗漏账号加入 Group，不改动任何 RLS。

安全防呆:
  任何命中 --copilot-members / --copilot-patterns 的主体（Copilot API SA、权限 SA）出现在待加入名单中时，
  直接中止（exit 2），不做任何变更——它们一旦进入白名单，行级权限会被 FILTER TRUE 旁路。
  名单里的 Group（group:xxx）会被递归展开（含嵌套组），嵌套成员命中 Copilot 规则同样中止；
  有读不到的嵌套组（外部域 / 无权限）时也中止，除非加 --allow-unverified-groups。

探针验证（--probe-sa + --probe-dataset）:
  把探针 SA 加入每个白名单 Group，在探针数据集下建一张只授予该 Group 的 FILTER TRUE 探针表，
  以探针 SA 身份轮询查询，直到能看到数据，确认 BigQuery 已识别 Group 成员关系后才算完成。
  前提：执行账号对探针 SA 有 roles/iam.serviceAccountTokenCreator；探针 SA 有 roles/bigquery.jobUser。

名单来源（可叠加）:
  --write-members / --read-members / *-file   命令行或文件
  --scan-csv                                  scan_bq_access.py / list_project_sas.py 的输出（按 suggested_group 分配）
  --acl-table                                 客户的白名单名册表 adm_user_mem_copilot_acl_group_sa（sa, acl_group）
  --acl-out                                   把最终名单按 sa,acl_group 导出，供客户回填名册表

示例:
  # 预览（从扫描结果生成），并导出名册
  python whitelist_groups.py --write-group full-write@x.com --read-group full-read@x.com \\
      --scan-csv scan.csv --copilot-patterns 'copilot-*@*' --acl-out acl.csv
  # 从名册表建组 + 探针
  python whitelist_groups.py --write-group full-write@x.com --read-group full-read@x.com \\
      --acl-table auth-proj.auth.adm_user_mem_copilot_acl_group_sa --copilot-patterns 'copilot-*@*' \\
      --probe-sa probe@p.iam.gserviceaccount.com --probe-dataset p.rls_probe --apply
  # 热修补：把漏掉的账号加入读白名单
  python whitelist_groups.py --read-group full-read@x.com --read-members etl2@p.iam.gserviceaccount.com --apply

退出码: 0 成功；1 名册有误、部分失败或探针未通过；2 名单中混入 Copilot SA（未做任何变更）
"""

import argparse
import csv
import sys

import gcp_ops as ops
import rls_core as core
from gcp_auth import get_credentials


def load_scan_csv(path):
    write, read = [], []
    with open(path, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if r.get("suggested_group") == "write":
                write.append(r["principal"])
            elif r.get("suggested_group") == "read":
                read.append(r["principal"])
    return write, read


def addable_email(member):
    """只有 user / group / serviceAccount 可以加入 Group。"""
    prefix = member.split(":")[0]
    return core.member_email(member) if prefix in ("user", "group", "serviceAccount") else None


def main():
    p = argparse.ArgumentParser(description="创建读/写白名单 Group 并批量加入存量账号")
    p.add_argument("--write-group", default=None, help="全局写白名单 Group 邮箱")
    p.add_argument("--read-group", default=None, help="全局读白名单 Group 邮箱")
    p.add_argument("--write-members", nargs="*", default=[])
    p.add_argument("--read-members", nargs="*", default=[])
    p.add_argument("--write-members-file", default=None)
    p.add_argument("--read-members-file", default=None)
    p.add_argument("--scan-csv", default=None, help="scan_bq_access.py 的输出，按 suggested_group 分配")
    p.add_argument("--acl-table", default=None,
                   help="白名单名册表 adm_user_mem_copilot_acl_group_sa 全名（列 sa, acl_group），直接作为名单来源")
    p.add_argument("--acl-out", default=None,
                   help="把本次最终名单按 sa,acl_group 导出为 CSV，供客户回填白名单名册表")
    p.add_argument("--copilot-members", nargs="*", default=[], help="Copilot API SA / 权限 SA 邮箱")
    p.add_argument("--copilot-patterns", nargs="*", default=[], help="Copilot SA 邮箱通配符，如 copilot-*@*")
    p.add_argument("--allow-unverified-groups", action="store_true",
                   help="名单中的 Group 含有无法展开的嵌套组（外部域 / 无权限）时仍继续（默认中止）")
    p.add_argument("--customer-id", default=None)
    p.add_argument("--project", default=None, help="quota 项目；建 group 时也用于获取 customer ID")
    p.add_argument("--initial-config", choices=["WITH_INITIAL_OWNER", "EMPTY"], default="EMPTY",
                   help="EMPTY：执行账号不会成为组成员（推荐，需 Groups Admin）")
    p.add_argument("--probe-sa", default=None)
    p.add_argument("--probe-dataset", default=None, help="project.dataset，用于创建探针表")
    p.add_argument("--probe-timeout", type=int, default=600)
    p.add_argument("--gcloud-account", default=None)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    plan = {}
    for group, members, mfile in ((args.write_group, args.write_members, args.write_members_file),
                                  (args.read_group, args.read_members, args.read_members_file)):
        if group:
            plan[group.lower()] = [core.normalize_member(m, "user") for m in
                                   core.split_items(members) +
                                   (core.read_list_file(mfile) if mfile else [])]
    if args.scan_csv:
        w, r = load_scan_csv(args.scan_csv)
        for group, extra in ((args.write_group, w), (args.read_group, r)):
            if extra and not group:
                p.error("--scan-csv 包含该类账号，但未指定对应的 --write-group/--read-group")
            if group:
                plan[group.lower()] += extra
    if not plan:
        p.error("至少指定 --write-group 或 --read-group")

    project = args.project or (args.probe_dataset.split(".")[0] if args.probe_dataset else None)
    ctx = None
    if args.acl_table:
        # 名册表是白名单的事实来源：sa + acl_group（Group 邮箱，或以 write/read 结尾的标识）
        acl = core.fq(args.acl_table)
        ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)
        rows = [dict(r.items()) for r in ops.run_query(
            ctx, f"SELECT sa, acl_group FROM `{acl}`", ctx.table_location(acl))]
        try:
            roster = core.acl_roster(rows, args.write_group, args.read_group)
        except ValueError as e:
            ops.log(f"[ERROR] {e}")
            return 1
        ops.log(f"[SOURCE] 白名单名册 {acl}: {len(rows)} 行")
        for group, members in roster.items():
            plan[group] += members

    copilot_members = core.split_items(args.copilot_members)
    copilot_patterns = core.split_items(args.copilot_patterns)
    rejected = []
    for group in plan:
        plan[group] = list(dict.fromkeys(plan[group]))
        _, bad = core.filter_whitelist_members(plan[group], copilot_members, copilot_patterns)
        rejected += [(group, m) for m in bad]
    if rejected:
        for group, m in rejected:
            ops.log(f"[REJECT] {m} 命中 Copilot SA 名单/规则，禁止加入白名单 {group}")
        ops.log("已中止，未做任何变更。请从名单中移除上述账号后重试。")
        return 2

    # P0：名单里的 Group 要递归展开检查——Copilot SA 藏在嵌套组里同样会命中 FILTER TRUE
    nested = [(wl, m) for wl in plan for m in plan[wl] if m.startswith("group:")]
    if nested:
        ctx = ctx or ops.Ctx(get_credentials(args.gcloud_account, project), project)
        unverified = []
        for wl, m in nested:
            g = core.member_email(m)
            if ops.group_members_typed(ctx, g) is None:
                unverified.append((wl, g, [g]))
                continue
            members, unresolved = ops.expand_group(ctx, g)
            bad = [(e, i["via"]) for e, i in sorted(members.items())
                   if core.is_copilot_member(e, copilot_members, copilot_patterns)]
            for e, via in bad:
                rejected.append((wl, e))
                ops.log(f"[REJECT] {m} 的嵌套成员 {e}（路径 {' > '.join(via)}）命中 Copilot SA 名单/规则，"
                        f"禁止把该组加入白名单 {wl}")
            unverified += [(wl, ug, via + [ug]) for ug, via in unresolved]
            if not bad:
                ops.log(f"[NESTED] {m}: 递归展开 {len(members)} 个成员，未发现 Copilot SA")
        if rejected:
            ops.log("已中止，未做任何变更。请把上述 Copilot SA 移出这些组，或不要把这些组加入白名单。")
            return 2
        for wl, ug, path in unverified:
            ops.log(f"[UNVERIFIED] 加入 {wl} 的组里有无法展开的组 {ug}（路径 {' > '.join(path)}，外部域或无权限），"
                    f"无法确认其中没有 Copilot SA")
        if unverified and not args.allow_unverified_groups:
            ops.log("已中止，未做任何变更。确认这些组里没有 Copilot SA 后加 --allow-unverified-groups，"
                    "或改为直接加入具体账号。")
            return 2

    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode} =====")
    for group, members in plan.items():
        ops.log(f"[PLAN] {group}: {len(members)} 个成员")
        for m in members:
            e = addable_email(m)
            ops.log(f"  {group} <- {e}" if e else f"  [SKIP] {m} 不是具体账号，无法加入 Group")
    if args.acl_out:
        with open(args.acl_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["sa", "acl_group"])
            for group, members in plan.items():
                for m in members:
                    if addable_email(m):
                        w.writerow([addable_email(m), group])
        ops.log(f"[ACL-OUT] 名单已导出到 {args.acl_out}（sa,acl_group），可回填白名单名册表")
    if not args.apply:
        return 0

    ctx = ctx or ops.Ctx(get_credentials(args.gcloud_account, project), project)
    failed = False
    customer_id = args.customer_id
    for group, members in plan.items():
        name = ops.lookup_group(ctx, group)
        if not name:
            if not customer_id:
                if not project:
                    ops.log(f"[ERROR] group {group} 不存在，创建需要 --customer-id 或 --project")
                    return 1
                customer_id = ops.resolve_customer_id(ctx, project)
            name, _ = ops.ensure_group(ctx, group, customer_id, initial_config=args.initial_config)
            ops.log(f"[GROUP] 已创建 {group} ({name})")
        current = ops.group_members(ctx, name)
        targets = [addable_email(m) for m in members if addable_email(m)]
        if args.probe_sa:
            targets.append(args.probe_sa.lower())
        added = 0
        for e in dict.fromkeys(targets):
            if e in current:
                continue
            try:
                added += ops.add_group_member(ctx, name, e)
            except Exception as ex:  # noqa: BLE001
                failed = True
                ops.log(f"  [ERROR] 加入 {e} 失败: {ex}")
        ops.log(f"[MEMBER] {group}: 新增 {added}，已存在 {len(current & set(targets))}")

    if args.probe_sa:
        if not args.probe_dataset:
            ops.log("[ERROR] --probe-sa 需要同时指定 --probe-dataset")
            return 1
        for group in plan:
            ok = ops.probe_group(ctx, group, args.probe_sa.lower(), args.probe_dataset,
                                 timeout=args.probe_timeout)
            if ok:
                ops.log(f"[PROBE] {group} 已生效")
            else:
                failed = True
                ops.log(f"[PROBE] {group} 在 {args.probe_timeout}s 内未生效，请勿继续挂载 RLS")
    else:
        ops.log("[NOTE] 未做探针验证；挂载 RLS 前请确认 Group 成员关系已生效（通常 1~5 分钟）")
    ops.log(f"===== 完成 ({mode}) =====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
