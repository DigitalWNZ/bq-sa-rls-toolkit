#!/usr/bin/env python3
"""
给一个或多个 Group 统一授予一批表的表级读权限（BigQuery Data Viewer，roles/bigquery.dataViewer；Doc 第 3 步）。
新增业务表后重跑即可：已经授过权的表不做改动（NOOP）。

参数的值可直接写（逗号 / 空格分隔），也可写单列无表头的 .csv 文件，可混用、可重复累加:
  --groups（必填）  Group 邮箱：裸邮箱，不带 group: 前缀，不能是 SA（校验规则与 apply_bypass_rls --group 相同）
  --tables / --datasets / --projects（至少一类，可叠加）:
      表 project.dataset.table（反引号可选；显式写的视图也授权）；数据集 / 项目展开为其中全部普通表（视图不包括）

处理:
  - 角色固定为 roles/bigquery.dataViewer；只看这张表自己的 IAM（数据集 / 项目层级的授权不读、不改）；
  - 逐表: 所有 Group 都已在无条件的 dataViewer 授权里 -> [NOOP]；缺少的 Group -> [GRANT]（只加缺少的）；
    其它角色、其它成员原样保留（BigQuery 表级 IAM 只支持 v1 策略，没有条件授权）；
  - 并发修改冲突（etag）-> 重新读取、重新合并后重试；
  - 表不存在 -> [SKIP]，其余照常，退出码 1；
  - 不看登记表、不检查 RLS: 表上还没有任何 RLS 规则时，授权后 Group 成员能看到全部数据；
  - 不提供撤销（需要时手工处理）。
Group 不存在: 执行时 BigQuery 报「Group … does not exist」-> 不等待重试，立即停止（第一张需要变更的表先单独执行，
  它失败则其余表都不执行，退出码 2）。Group 刚创建 / 刚改成员时等几分钟后重跑。
配额: 每张表读、写 IAM 各一次，受 BigQuery IamPolicy 配额限制（脚本自动限速，约每分钟 700 张表）。
运行日志: 屏幕输出原样另存到 logs/grant_table_viewer_<YYYYMMDD_HHMMSS>.log（--log-dir 可改目录）。

示例:
  python grant_table_viewer.py --groups group_high@trip.com,group_low@trip.com --tables tables.csv          # 演练
  python grant_table_viewer.py --groups groups.csv --datasets trip-prod.dw --apply                          # 执行

退出码: 0 成功；1 有表跳过 / 失败；2 参数错误 / 无法确定执行账号 / 第一张表即报 Group 不存在（未做任何变更）
"""

import argparse
import sys

import gcp_ops as ops
import rls_core as core
from apply_bypass_rls import (abort_summary, add_scope_args, execute_tables, log_group_abort, read_scope, run_main,
                              workers)
from gcp_auth import AuthConfigError, describe_auth, resolve_auth

GROUPS_MISSING_HINT = "若 Group 刚创建或刚改过成员，同步到 BigQuery 需要几分钟，请稍后重跑；否则请检查 --groups 是否拼错"


def _main(argv):
    p = argparse.ArgumentParser(description="给 Group 统一授予表级 BigQuery Data Viewer", allow_abbrev=False)
    p.add_argument("--groups", nargs="*", action="extend", required=True,
                   help="Group 邮箱（裸邮箱，不带前缀，不能是 SA），逗号或空格分隔；也可写 .csv 文件")
    add_scope_args(p)
    p.add_argument("--quota-project", default=None,
                   help="quota / 运行查询的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认只演练")
    ops.add_log_dir_arg(p)
    args = p.parse_args(argv)
    ops.start_log_file("grant_table_viewer", args.log_dir)

    try:
        groups = core.parse_groups(core.collect_values(args.groups))
        tables, datasets, projects, _ = read_scope(args)
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
    ops.log(f"===== 模式: {mode}  角色: {core.VIEWER_ROLE}（表级）  Group: {len(groups)} 个  并行: {workers(args)} =====")
    ops.log("[GROUPS]\n" + "\n".join(f"  - group:{g}" for g in groups))

    try:
        table_list = ops.expand_tables(ctx, tables, datasets, projects)
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 展开目标表失败: {e}")
        return 1
    ops.log(f"[SCAN] 共 {len(table_list)} 张表")

    # 阶段 1：并行读取每张表的 IAM，计算缺少哪些 Group
    failed, plans, counts = False, {}, {}

    def bump(k):
        counts[k] = counts.get(k, 0) + 1

    for t, policy, err in ops.parallel_map(lambda x: ops.table_iam_policy(ctx, x), table_list,
                                           workers=workers(args), desc="iam"):
        if err and ops.is_not_found_error(err):
            failed = True
            bump("SKIP")
            ops.log(f"[SKIP] {t}: 表不存在（可能已被删除）")
        elif err:
            failed = True
            bump("ERROR")
            ops.log(f"[ERROR] {t}: 读取 IAM 策略失败: {ops.brief_error(err)}")
        else:
            plans[t] = core.plan_table_viewer(policy, groups)

    # 阶段 2：执行（执行模式先单独执行第一张需要变更的表：BigQuery 报 Group 不存在则立即停止）
    def mutate(policy):
        missing, _ = core.plan_table_viewer(policy, groups)          # 以最新读到的策略为准（并发修改后重算）
        return core.add_viewer_members(policy, missing) if missing else None

    def execute(t):
        missing, have = plans[t]
        if not missing:
            return [f"[NOOP] {t}"], True, False
        lines = [f"[GRANT] {t}: 新增 {[f'group:{g}' for g in missing]}"
                 + (f"；已有 {[f'group:{g}' for g in have]}" if have else "")]
        if args.apply:
            try:
                ops.update_table_iam(ctx, t, mutate)
            except Exception as e:  # noqa: BLE001
                lines.append(f"  [ERROR] {ops.brief_error(e)}")
                return lines, False, ops.is_principal_missing_error(e)
        return lines, True, False

    def on_result(t, res, err):
        nonlocal failed
        if err:
            failed = True
            bump("ERROR")
            ops.log(f"[ERROR] {t}: {err}")
            return
        lines, ok, _ = res
        ops.log("\n".join(lines))
        failed = failed or not ok
        bump(("GRANT" if plans[t][0] else "NOOP") if ok else "ERROR")

    status, not_run = execute_tables(sorted(plans), execute, workers(args), args.apply,
                                     lambda t: bool(plans[t][0]), on_result)
    if status != "ok":
        code = log_group_abort(status, not_run, None, what="--groups 中有 Group ", detail="（是哪个见上方 [ERROR]）",
                               hint=GROUPS_MISSING_HINT)
        ops.log(abort_summary(mode, status, not_run, counts))
        return code
    ops.log(f"===== 完成 ({mode})：" + ("，".join(f"{k} {v}" for k, v in sorted(counts.items())) or "无") + " =====")
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
