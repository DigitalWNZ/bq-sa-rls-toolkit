#!/usr/bin/env python3
"""
为一个白名单 Group 在目标表上设置 FILTER TRUE 行级规则（Doc 第 3 步）：
该 Group 的成员不受行级过滤、可见全部记录（前提是本来就有读表权限；本脚本不授予读表权限）。

每个 Group 单独一条规则，规则名 rls_bypass_full_access_<邮箱，小写，非字母数字换成 _>:
  CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access_<group>` ON `表`
  GRANT TO ("group:<group>") FILTER USING (TRUE)
一次只处理一个 Group（--group），ReadOnly、Writable 各运行一次。

目标表（可叠加；每个参数的值可直接写（逗号 / 空格分隔），也可写单列无表头的 .csv 文件，可混用）:
  --tables     project.dataset.table（反引号可选，如 `trip-prod.dw.orders`；不支持 project:dataset.table）
  --datasets   project.dataset（展开为其中全部表）
  --projects   Project ID（展开为项目内全部表）
  三类至少给出一类（任给其一即可），都不给则报错（退出码 2）。

双重保证: 最终表 = (--tables ∪ --datasets 展开 ∪ --projects 展开) ∩ 登记表中 rls_enabled = 1 的表。
  --registry-table 必填：登记表（adm_user_mem_copilot_tb），只读 table_name、rls_enabled 两列（不看 status）；
  table_name 按原始字符串精确比较；不在登记表或 rls_enabled ≠ 1 的表逐张打印 [SKIP]，不授权（退出码不受影响）；
  同一 table_name 有多行且 rls_enabled 不一致 -> [WARN] + [SKIP]，退出码 1。
逐表判断: 无同名规则 -> [CREATE]；同名且内容相同 -> [NOOP]；同名但内容不同 -> [REPLACE]（日志打印被覆盖的旧内容）。
首次设置提示: 表上原本没有任何 RLS 时，新建第一条会让未被授权的账号查到 0 行；
  这些表会在日志中列出（「将为以下这些表首次设置RLS规则」），只作提示，不拦截。
--verify-sa: 执行后扮演该 Group 里的一个 SA 查表，300 秒内查到任意一行即通过。
--parallel: 同时处理的表数（默认 16）；同一张表上的操作始终顺序执行。

示例:
  python apply_bypass_rls.py --group group_existingsa_read@domain.com --tables tables.csv \\
      --registry-table trip-bq-admin.bq_auth.adm_user_mem_copilot_tb
  python apply_bypass_rls.py ... --apply --verify-sa reader@prod.iam.gserviceaccount.com

退出码: 0 成功；1 DDL 执行失败 / 验证失败 / 登记表记录冲突；2 参数错误 / 登记表不可用（未做任何变更）
"""

import argparse
import os
import sys

import gcp_ops as ops
import rls_core as core
from gcp_auth import AuthConfigError, describe_auth, resolve_auth

VERIFY_TIMEOUT = 300                       # --verify-sa：新规则生效最多等待的秒数
FIRST_POLICY_MSG = "[NOTE] 将为以下这些表首次设置RLS规则（未被任何规则授权的账号将查到 0 行）："


def log_first_policy_tables(tables):
    """只作提示：列出将首次设置 RLS 的表（按表名排序）。apply_copilot_rls.py 共用。"""
    if tables:
        ops.log(FIRST_POLICY_MSG + "\n" + "\n".join(f"  - {t}" for t in sorted(tables)))


# --------------------------------------------------------------------------- #
# 与 rollback_rls.py 共用的参数 / 辅助
# --------------------------------------------------------------------------- #
def add_scope_args(p):
    p.add_argument("--tables", nargs="*", action="extend", default=[],
                   help="project.dataset.table（反引号可选），逗号或空格分隔；也可写 .csv 文件（单列无表头）")
    p.add_argument("--datasets", nargs="*", action="extend", default=[], help="project.dataset（展开为其中全部表）；也可写 .csv 文件")
    p.add_argument("--projects", nargs="*", action="extend", default=[], help="Project ID（展开为项目内全部表）；也可写 .csv 文件")
    p.add_argument("--parallel", type=int, default=16, help="同时处理的表数（默认 16；实测 32 以内 DDL 吞吐线性增长、无后端错误，48 时 BigQuery 开始大量返回暂时性错误，建议不超过 32）")


def read_scope(args):
    """返回 (tables, datasets, projects, 默认项目)；格式错误抛 ValueError。"""
    tables = list(dict.fromkeys(core.parse_table_arg(t) for t in core.collect_values(args.tables)))
    datasets = list(dict.fromkeys(core.parse_dataset_arg(d) for d in core.collect_values(args.datasets)))
    projects = core.collect_values(args.projects)
    for x in projects:
        core.project_scope(x)
    first = (tables + datasets + projects or [""])[0].split(".")[0] or None
    return tables, datasets, projects, first


def load_registry(ctx, registry):
    """读取登记表 -> {table_name 原值: 状态}；表不存在 / 列不对 / 读不到时抛 ValueError。"""
    if not ops.table_exists(ctx, registry):
        raise ValueError(f"登记表 {registry} 不存在（--registry-table）")
    core.validate_registry_fields(ops.table_fields(ctx, registry))
    try:
        rows = ops.read_registry_rows(ctx, registry)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"读取登记表 {registry} 失败: {e}") from e
    return core.registry_status(rows)


def filter_by_registry(table_list, status, registry):
    """(可授权的表, 冲突表数)；未开启的表逐张打印 [SKIP]（按表名排序），冲突的表另加 [WARN]。"""
    allowed, conflicts = [], 0
    for t in sorted(table_list):
        st = status.get(t)
        if st == "enabled":
            allowed.append(t)
        elif st == "conflict":
            conflicts += 1
            ops.log(f"[WARN] {t}: 登记表中有多条记录且 rls_enabled 不一致（既有 1 又有其它值），按未开启处理")
            ops.log(f"[SKIP] {t}: 登记表记录冲突，不授权")
        elif st == "disabled":
            ops.log(f"[SKIP] {t}: 登记表中 rls_enabled ≠ 1，不授权")
        else:
            ops.log(f"[SKIP] {t}: 不在登记表 {registry} 中，不授权")
    keep = set(allowed)
    return [t for t in table_list if t in keep], conflicts


def workers(args):
    return max(1, args.parallel)


def run_main(fn, argv):
    """统一的顶层错误处理：意外异常打印 [ERROR] 并返回 1（RLS_DEBUG=1 时抛出完整堆栈）。"""
    try:
        return fn(argv)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        ops.log("[ERROR] 已被用户中断")
        return 130
    except Exception as e:  # noqa: BLE001
        if os.environ.get("RLS_DEBUG"):
            raise
        ops.log(f"[ERROR] {type(e).__name__}: {str(e)[:500]}")
        return 1


# --------------------------------------------------------------------------- #
def _main(argv):
    p = argparse.ArgumentParser(description="为一个白名单 Group 设置 FILTER TRUE 行级规则", allow_abbrev=False)
    p.add_argument("--group", required=True, help="白名单 Group 邮箱（只能一个）")
    add_scope_args(p)
    p.add_argument("--registry-table", required=True,
                   help="登记表 project.dataset.table（adm_user_mem_copilot_tb）：只有其中 rls_enabled = 1 的表才授权")
    p.add_argument("--quota-project", default=None, help="quota / 运行查询与 DDL 的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--verify-sa", default=None,
                   help="挂载后验证用的 SA（在该 Group 中、有表读权限、执行账号可扮演）：300 秒内查到任意一行即通过")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认只演练")
    args = p.parse_args(argv)

    groups = core.split_items([args.group])
    if len(groups) != 1:
        ops.log(f"[ERROR] --group 只能指定一个 Group，收到 {len(groups)} 个: {groups}")
        return 2
    group = core.member_email(groups[0])
    grantee = f"group:{group}"
    policy_name = core.bypass_policy_name(group)
    try:
        core.build_policy_ddl("p.d.t", policy_name, [grantee], "TRUE")   # 提前校验 Group 邮箱
        tables, datasets, projects, _ = read_scope(args)
        registry = core.parse_table_arg(args.registry_table)
    except (ValueError, OSError) as e:
        ops.log(f"[ERROR] {e}")
        return 2
    if not (tables or datasets or projects):
        ops.log("[ERROR] 请指定 --tables、--datasets、--projects 中的至少一项")
        return 2

    try:
        auth = resolve_auth(args.gcloud_account, args.quota_project)
    except AuthConfigError as e:
        ops.log(f"[ERROR] {e}")
        return 2
    ops.log(describe_auth(auth))
    ctx = ops.Ctx(auth.creds, auth.project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode}  规则: {policy_name}  授权对象: {grantee}  并行: {workers(args)} =====")
    try:
        status = load_registry(ctx, registry)
    except ValueError as e:
        ops.log(f"[ERROR] {e}")
        return 2

    try:
        scope_list = ops.expand_tables(ctx, tables, datasets, projects)
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 展开目标表失败: {e}")
        return 1
    table_list, conflicts = filter_by_registry(scope_list, status, registry)
    skipped = len(scope_list) - len(table_list)
    ops.log(f"[SCAN] 目标范围 {len(scope_list)} 张表；登记表中已开启 {len(table_list)} 张，跳过 {skipped} 张")

    # 阶段 1：并行读取现有规则（只读取本规则名的授权对象），生成计划
    failed = conflicts > 0
    plans = {}
    for t, pl, err in ops.parallel_map(
            lambda t: core.plan_upsert(ops.list_policies(ctx, t, grantees_for={policy_name}),
                                       policy_name, "TRUE", [grantee]),
            table_list, workers=workers(args), desc="plan"):
        if err:
            failed = True
            ops.log(f"[ERROR] {t}: 读取现有规则失败: {err}")
        else:
            plans[t] = pl

    log_first_policy_tables([t for t, pl in plans.items() if pl.first_policy and pl.action == "create"])

    # 阶段 2：并行执行（每张表一条 DDL）
    def execute(t):
        pl = plans[t]
        lines = []
        if pl.action == "noop":
            return [f"[NOOP] {t}"], True
        ddl = core.build_policy_ddl(t, policy_name, [grantee], "TRUE")
        lines.append(f"[{pl.action.upper()}] {t}\n{ddl}")
        if pl.action == "replace":
            lines.append(f"  被覆盖的旧内容: grantees={pl.old['grantees']} filter={pl.old['filter']}")
        if args.apply:
            try:
                ops.run_ddl(ctx, ddl, ctx.table_location(t))
            except Exception as e:  # noqa: BLE001
                lines.append(f"  [ERROR] {e}")
                return lines, False
        return lines, True

    counts = {"SKIP": skipped} if skipped else {}
    for t, res, err in ops.parallel_map(execute, list(plans), workers=workers(args), desc="ddl"):
        if err:
            failed = True
            ops.log(f"[ERROR] {t}: {err}")
            continue
        lines, ok = res
        ops.log("\n".join(lines))
        failed = failed or not ok
        counts[plans[t].action.upper()] = counts.get(plans[t].action.upper(), 0) + 1

    # 阶段 3：挂载后验证（并行）
    if args.apply and args.verify_sa:
        def verify(t):
            return ops.verify_full_access(ctx, t, args.verify_sa, VERIFY_TIMEOUT, mode="sample")
        for t, res, err in ops.parallel_map(verify, list(plans), workers=workers(args), desc="verify"):
            status, detail = ("fail", str(err)) if err else res
            if status == "ok":
                ops.log(f"[VERIFY-OK] {t}: {args.verify_sa} {detail}")
            elif status == "skip":
                ops.log(f"[VERIFY-SKIP] {t}: {detail}")
            else:
                failed = True
                ops.log(f"[VERIFY-FAIL] {t}: {detail}")
    elif args.apply:
        ops.log("[NOTE] 未做挂载后验证；新规则生效有短暂窗口，建议用 --verify-sa 指定该 Group 里的一个 SA 验证")
    ops.log(f"===== 完成 ({mode})：" + ("，".join(f"{k} {v}" for k, v in sorted(counts.items())) or "无") + " =====")
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
