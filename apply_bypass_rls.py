#!/usr/bin/env python3
"""
T4 为白名单 Group 批量授予 FILTER TRUE 策略（存量业务零感知的旁路保护）。

对每张目标表创建/维护同一条 policy（默认 rls_bypass_full_access），一次性授予所有白名单 Group:
  CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access` ON `表`
  GRANT TO ("group:full-write@x.com", "group:full-read@x.com") FILTER USING (TRUE)

安全规则:
  - 表上原本没有任何 RLS 时（首条 policy 会触发 Implicit Deny），必须加 --force-first-policy，
    否则整批中止（exit 2），不做任何变更。请先完成 whitelist_groups.py 的探针验证。
  - 表上已有同名 policy 但授权对象/过滤条件不同 -> [CONFLICT] 跳过该表（不覆盖别人的 policy）；
    加 --merge 时对授权对象取并集（过滤条件不同时仍冲突）。
  - 已一致 -> [NOOP]。
  - 版本前置检查：目标项目最近 N 天若有查询作业运行在 STANDARD 版本 Reservation 上，整批中止（exit 5）。
  - --verify-sa 挂载后验证：以白名单 SA 身份 SELECT 1 ... LIMIT 1（要求分区过滤的表自动加条件），
    看到数据即通过；--verify-mode count 改为 COUNT(*) 与元数据行数比对。

示例:
  python apply_bypass_rls.py --tables-file tables.txt \\
      --groups full-write@x.com,full-read@x.com --force-first-policy --apply

退出码: 0 成功；1 有冲突/失败/验证失败；2 首条 policy 未加 --force-first-policy（未做任何变更）；
        5 目标项目最近有作业运行在 STANDARD 版本（未做任何变更）
"""

import argparse
import sys

import gcp_ops as ops
import rls_core as core
from gcp_auth import get_credentials


def main():
    p = argparse.ArgumentParser(description="批量为白名单 Group 授予 FILTER TRUE 策略")
    p.add_argument("--tables", nargs="*", default=[])
    p.add_argument("--tables-file", default=None)
    p.add_argument("--groups", nargs="+", required=True, help="白名单 Group（可写 user:/serviceAccount: 前缀）")
    p.add_argument("--policy-name", default=core.BYPASS_POLICY)
    p.add_argument("--merge", action="store_true", help="同名 policy 授权对象不同时取并集")
    p.add_argument("--force-first-policy", action="store_true")
    p.add_argument("--project", default=None, help="quota / 运行 DDL 的项目（默认第一张表的项目）")
    p.add_argument("--verify-sa", default=None,
                   help="挂载后验证用的白名单 SA（需在白名单 Group 中、有表读权限，执行账号可扮演它）")
    p.add_argument("--verify-timeout", type=int, default=300)
    p.add_argument("--verify-mode", choices=["sample", "count"], default="sample",
                   help="sample：查到任意一行即通过（默认，成本极低）；count：COUNT(*) 与元数据行数比对")
    p.add_argument("--skip-edition-check", action="store_true",
                   help="跳过 Reservation 版本检查（RLS 不支持 Standard 版本）")
    p.add_argument("--edition-days", type=int, default=7, help="版本检查回看最近 N 天的作业")
    p.add_argument("--gcloud-account", default=None)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    tables = core.split_items(args.tables) + (core.read_list_file(args.tables_file)
                                               if args.tables_file else [])
    if not tables:
        p.error("请指定 --tables 或 --tables-file")
    tables = list(dict.fromkeys(core.fq(t) for t in tables))
    grantees = [core.normalize_member(g) for g in core.split_items(args.groups)]
    project = args.project or core.parse_table(tables[0])[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode}  policy={args.policy_name}  grantees={grantees} =====")

    # C3: Reservation 版本前置检查——Standard 版本不支持 RLS，挂上策略后存量查询会失败
    if not args.skip_edition_check:
        blocked = False
        for proj, region in sorted({(core.parse_table(t)[0], ctx.table_location(t).lower()) for t in tables}):
            try:
                rows = [dict(r.items()) for r in ops.run_query(
                    ctx, core.edition_usage_sql(proj, region, args.edition_days), region)]
            except Exception as e:  # noqa: BLE001
                ops.log(f"[EDITION] {proj}/{region}: 无法读取作业历史（{str(e)[:120]}），跳过版本检查")
                continue
            std = core.standard_edition_usage(rows)
            if std:
                blocked = True
                for res, n in std:
                    ops.log(f"[EDITION] {proj}/{region}: 最近 {args.edition_days} 天有 {n} 个查询作业运行在 "
                            f"STANDARD 版本 Reservation {res}，RLS 不支持 Standard")
            elif not rows:
                ops.log(f"[EDITION] {proj}/{region}: 最近 {args.edition_days} 天没有查询作业，无法判断版本，请人工确认")
            else:
                ops.log(f"[EDITION] {proj}/{region}: OK（{', '.join(sorted({(r['edition'] or 'on-demand') for r in rows}))}）")
        if blocked:
            ops.log("已中止，未做任何变更。请先完成 Reservation 切换到 Enterprise（RUNBOOK 阶段 1），"
                    "确认后可用 --skip-edition-check 跳过。")
            return 5

    plans = {}
    for t in tables:
        plans[t] = core.plan_policy_upsert(ops.list_policies(ctx, t), args.policy_name, "TRUE",
                                           grantees, merge=args.merge)
    first = [t for t, pl in plans.items() if pl.first_policy and pl.action == "create"]
    if first:
        ops.log(f"[WARNING] 以下 {len(first)} 张表目前没有任何 RLS，创建后未被授权的账号将查不到数据:")
        for t in first:
            ops.log(f"  - {t}")
        if args.apply and not args.force_first_policy:
            ops.log("已中止，未做任何变更。确认白名单 Group 已生效（探针通过）后加 --force-first-policy。")
            return 2

    failed = False
    for t, pl in plans.items():
        if pl.action == "noop":
            ops.log(f"[NOOP] {t}")
            continue
        if pl.action == "conflict":
            failed = True
            ops.log(f"[CONFLICT] {t}: {pl.reason}（如需合并授权对象请加 --merge）")
            continue
        ddl = core.build_bypass_policy_ddl(t, pl.grantees, args.policy_name)
        ops.log(f"[{pl.action.upper()}] {t}\n{ddl}")
        if args.apply:
            try:
                ops.run_ddl(ctx, ddl, ctx.table_location(t))
            except Exception as e:  # noqa: BLE001
                failed = True
                ops.log(f"  [ERROR] {e}")

    if args.apply and args.verify_sa:
        # 实测：新建 policy 后白名单账号可能有十几秒到数十秒看到 0 行 / DML 报
        # "does not have full access"。以白名单账号身份轮询，直到行数与表元数据一致。
        for t in tables:
            status, detail = ops.verify_full_access(ctx, t, args.verify_sa, args.verify_timeout,
                                                    mode=args.verify_mode)
            if status == "ok":
                ops.log(f"[VERIFY-OK] {t}: {args.verify_sa} {detail}")
            elif status == "skip":
                ops.log(f"[VERIFY-SKIP] {t}: {detail}")
            else:
                failed = True
                ops.log(f"[VERIFY-FAIL] {t}: {detail}")
    elif args.apply:
        ops.log("[NOTE] 未做挂载后验证；新 policy 生效有短暂窗口，建议用 --verify-sa 指定一个白名单账号验证")
    ops.log(f"===== 完成 ({mode}) =====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
