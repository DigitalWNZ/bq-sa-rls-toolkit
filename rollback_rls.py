#!/usr/bin/env python3
"""
回退：删除目标表上的 RLS 规则（apply_bypass_rls.py / apply_copilot_rls.py 的逆操作，Doc 第 8 步）。

参数的值可直接写（逗号 / 空格分隔），也可写单列无表头的 .csv 文件，可混用。

目标表（必填，可叠加）:
  --tables（project.dataset.table，反引号可选；不支持 project:dataset.table）、--datasets（project.dataset）、--projects

删除哪些规则:
  --principals     邮箱（Group / SA / user 均可，不分类型）：删除授权对象里含这些邮箱的规则（能覆盖手工建的规则）
  --policy-names   规则名
  两者同时给出时取交集；**两者都不给 = 删除目标表上的全部规则**

删光提示: 某张表的规则将被全部删除时（删除后所有有读表权限的账号都能看到全部数据），
  这些表会在日志中列出，只作提示，不拦截。表上规则全部要删时使用 DROP ALL ROW ACCESS POLICIES。

日志: 演练和执行时都逐条打印被删除规则的完整内容（表、规则名、授权对象、过滤条件）和 DDL。
  读取授权对象受 BigQuery 配额限制（IamPolicy 请求 1500 次/分钟），脚本自动限速。
--verify-sa: 删除后扮演该 SA 逐表查询，打印「可见 N 行 / 表共 M 行」，只报告不判定。
--parallel: 同时处理的表数（默认 16）；同一张表上的操作始终顺序执行。

示例:
  python rollback_rls.py --datasets trip-prod.dw --principals group_copilot@trip.com --apply
  python rollback_rls.py --tables tables.csv --policy-names rls_bypass_full_access_g_x_com --apply
  python rollback_rls.py --tables tables.csv --apply          # 删除这些表上的全部规则

退出码: 0 成功；1 有表处理失败；2 参数错误（未做任何变更）
"""

import argparse
import sys

import gcp_ops as ops
import rls_core as core
from apply_bypass_rls import add_scope_args, read_scope, run_main, workers
from gcp_auth import AuthConfigError, describe_auth, resolve_auth

DROP_ALL_MSG = "[NOTE] 以下这些表的 RLS 规则将被全部删除（删除后所有有读表权限的账号都能看到全部数据）："


def _main(argv):
    p = argparse.ArgumentParser(description="删除目标表上的 RLS 规则", allow_abbrev=False)
    add_scope_args(p)
    p.add_argument("--principals", nargs="*", action="extend", default=[], help="邮箱（Group / SA / user），逗号或空格分隔；也可写 .csv 文件")
    p.add_argument("--policy-names", nargs="*", action="extend", default=[], help="规则名，逗号或空格分隔；也可写 .csv 文件")
    p.add_argument("--verify-sa", default=None, help="删除后扮演该 SA 查询可见行数（只报告）")
    p.add_argument("--quota-project", default=None, help="quota / 运行查询与 DDL 的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认只演练")
    args = p.parse_args(argv)

    try:
        tables, datasets, projects, _ = read_scope(args)
        principals = {core.member_email(x) for x in core.collect_values(args.principals)}
        names = set(core.collect_values(args.policy_names))
    except (ValueError, OSError) as e:
        ops.log(f"[ERROR] {e}")
        return 2
    if not (tables or datasets or projects):
        ops.log("[ERROR] 请指定 --tables / --datasets / --projects 中的至少一项")
        return 2

    try:
        auth = resolve_auth(args.gcloud_account, args.quota_project)
    except AuthConfigError as e:
        ops.log(f"[ERROR] {e}")
        return 2
    ops.log(describe_auth(auth))
    ctx = ops.Ctx(auth.creds, auth.project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    scope = (f"主体 {sorted(principals)} " if principals else "") + (f"规则名 {sorted(names)}" if names else "")
    ops.log(f"===== 模式: {mode}  删除范围: {scope or '全部规则'}  并行: {workers(args)} =====")

    try:
        table_list = ops.expand_tables(ctx, tables, datasets, projects)
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 展开目标表失败: {e}")
        return 1
    ops.log(f"[SCAN] 共 {len(table_list)} 张表")

    # 阶段 1：并行读取规则并生成计划。按主体筛选时读取全部授权对象（BigQuery 配额 1500 次/分钟，脚本自动限速）；
    # 只按规则名删除时只读取这些规则的授权对象；全部删除时读取全部（都用于日志追查）
    grantees_for = None if (principals or not names) else names

    def plan(t):
        policies = ops.list_policies(ctx, t, grantees_for=grantees_for)
        return core.plan_rollback(policies, principals or None, names or None), len(policies)

    plans, failed = {}, False
    for t, res, err in ops.parallel_map(plan, table_list, workers=workers(args), desc="plan"):
        if err:
            failed = True
            ops.log(f"[ERROR] {t}: 读取现有规则失败: {err}")
        elif res[0].to_drop:
            plans[t] = res

    emptied = sorted(t for t, (pl, _) in plans.items() if pl.drop_all)
    if emptied:                                   # 只作提示，不拦截
        ops.log(DROP_ALL_MSG + "\n" + "\n".join(f"  - {t}" for t in emptied))

    # 阶段 2：并行执行
    def execute(t):
        pl, n_all = plans[t]
        lines = [f"[TABLE] {t}（共 {n_all} 条规则，删除 {len(pl.to_drop)} 条）"]
        for pol in pl.to_drop:
            g = pol["grantees"] if pol["grantees"] is not None else "（未读取）"
            lines.append(f"  [DROP] `{pol['id']}` grantees={g} filter={pol['filter']}")
        ddls = [core.drop_all_ddl(t)] if pl.drop_all else [core.drop_policy_ddl(t, pol["id"]) for pol in pl.to_drop]
        for ddl in ddls:
            lines.append(f"    DDL: {ddl}")
            if args.apply:
                ops.run_ddl(ctx, ddl, ctx.table_location(t))
        if pl.drop_all:
            lines.append("  [NOTE] 该表已没有任何 RLS 规则，所有有读表权限的账号都能看到全部数据")
        return lines, len(pl.to_drop)

    total = 0
    for t, res, err in ops.parallel_map(execute, list(plans), workers=workers(args), desc="ddl"):
        if err:
            failed = True
            ops.log(f"  [ERROR] {t}: {err}")
            continue
        lines, n = res
        ops.log("\n".join(lines))
        total += n

    if args.apply and args.verify_sa:
        def visible(t):
            return ops.count_visible(ctx, t, args.verify_sa)
        for t, res, err in ops.parallel_map(visible, table_list, workers=workers(args), desc="verify"):
            if err:
                ops.log(f"[VISIBLE] {t}: {args.verify_sa} 查询失败: {str(err)[:200]}")
            else:
                ops.log(f"[VISIBLE] {t}: {args.verify_sa} 可见 {res[0]} 行 / 表共 {res[1]} 行")
    ops.log(f"===== 完成 ({mode})：{len(plans)} 张表，共 {total} 条规则 =====")
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
