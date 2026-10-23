#!/usr/bin/env python3
"""
为白名单（一个 Group，或多个 user / group / SA）在目标表上设置 FILTER TRUE 行级规则（Doc 第 3 步）：
被授权的账号不受行级过滤、可见全部记录（前提是本来就有读表权限；本脚本不授予读表权限）。

两种用法（每次运行二选一，同时给或都不给 -> 参数错误，退出码 2）:
  --group <Group 邮箱>: 每个 Group 单独一条规则，规则名 rls_bypass_full_access_<邮箱，小写，非字母数字换成 _>:
    CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access_<group>` ON `表`
    GRANT TO ("group:<group>") FILTER USING (TRUE)
    一次只处理一个 Group，ReadOnly、Writable 各运行一次。
  --principals <主体...> --policy-name <后缀>: 多个 user / group / SA 共用一条规则（减少每张表的规则数）:
    CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access_<后缀>` ON `表`
    GRANT TO ("group:a@x", "user:b@x", "serviceAccount:c@p.iam.gserviceaccount.com") FILTER USING (TRUE)
    - 每个主体都必须带前缀 user: / group: / serviceAccount:（不带前缀、domain: / allUsers 等 -> 退出码 2）；
      可直接写值，也可写单列无表头的 .csv 文件；
    - --policy-name 只写后缀（小写字母、数字、下划线），脚本自动加前缀 rls_bypass_full_access_；
    - 完整名单: 规则的授权对象 = 本次 --principals 的全部；与表上现有的同名规则不同就 REPLACE，
      日志逐表列出「将新增 / 将移除」的主体（少写的主体会被去掉，对应账号立刻失去全部可见）；
    - 同名即覆盖，不检查是否与 --group 建的规则撞名（请自行避免）；
    - 其余（登记表、首次设置提示、--verify-sa、Group 不存在立即停止、退出码）与 --group 相同。

目标表 = 登记表中 rls_enabled = 1 的全部表（不再扫描项目 / 数据集，耗时与项目大小无关）:
  --registry-table 必填：登记表（adm_user_mem_copilot_tb），只读 table_name、rls_enabled 两列（不看 status）；
  table_name 须为 project.dataset.table（反引号可选），格式不对 -> [WARN] + [SKIP]，退出码 1；
  同一 table_name 有多行且 rls_enabled 不一致 -> [WARN] + [SKIP]，退出码 1；
  rls_enabled ≠ 1 的表不处理，只在 [SCAN] 行汇总数量；
  登记表里有、但表实际不存在（如已被 drop）-> [SKIP] 表不存在，其余表照常，退出码 1；
  登记了视图 -> BigQuery 拒绝建规则（视图不支持 RLS），[ERROR]，退出码 1。
  不再支持 --tables / --datasets / --projects（传入即参数错误，退出码 2）。
逐表判断: 无同名规则 -> [CREATE]；同名且内容相同 -> [NOOP]；同名但内容不同 -> [REPLACE]（日志打印被覆盖的旧内容）。
首次设置提示: 表上原本没有任何 RLS 时，新建第一条会让未被授权的账号查到 0 行；
  这些表会在日志中列出（「将为以下这些表首次设置RLS规则」），只作提示，不拦截。
--verify-sa: 执行后扮演该 Group 里的一个 SA 查表，300 秒内查到任意一行即通过。
--parallel: 同时处理的表数（默认 16）；同一张表上的操作始终顺序执行。
运行日志: 屏幕输出原样另存到 logs/apply_bypass_rls_<YYYYMMDD_HHMMSS>.log（--log-dir 可改目录）。

示例:
  python apply_bypass_rls.py --group group_existingsa_read@domain.com \\
      --registry-table trip-bq-admin.bq_auth.adm_user_mem_copilot_tb
  python apply_bypass_rls.py ... --apply --verify-sa reader@prod.iam.gserviceaccount.com
  python apply_bypass_rls.py --registry-table ... --policy-name existing_all \\
      --principals group:group_existingsa_read@domain.com,serviceAccount:etl@prod.iam.gserviceaccount.com
  python apply_bypass_rls.py --registry-table ... --policy-name existing_all --principals principals.csv --apply

Group（或 --principals 中的主体）不存在: 执行时 BigQuery 报「… does not exist」→ 不等待重试，立即停止（第一张需要变更的表先单独执行，
  它失败则其余表都不执行，退出码 2）。Group 刚创建 / 刚改成员时等几分钟后重跑。
退出码: 0 成功；1 DDL 执行失败 / 验证失败 / 登记表记录冲突或表名格式不对 / 表不存在；2 参数错误 / 登记表不可用 / 第一张表即报 Group 不存在（未做任何变更）
"""

import argparse
import os
import sys
import threading

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
# 参数 / 辅助（add_scope_args、read_scope 只给 rollback_rls.py 用：apply_bypass_rls 只看登记表）
# --------------------------------------------------------------------------- #
PARALLEL_HELP = "同时处理的表数（默认 16；实测 32 以内 DDL 吞吐线性增长、无后端错误，48 时 BigQuery 开始大量返回暂时性错误，建议不超过 32）"


def add_scope_args(p):
    p.add_argument("--tables", nargs="*", action="extend", default=[],
                   help="project.dataset.table（反引号可选），逗号或空格分隔；也可写 .csv 文件（单列无表头）")
    p.add_argument("--datasets", nargs="*", action="extend", default=[], help="project.dataset（展开为其中全部表）；也可写 .csv 文件")
    p.add_argument("--projects", nargs="*", action="extend", default=[], help="Project ID（展开为项目内全部表）；也可写 .csv 文件")
    p.add_argument("--parallel", type=int, default=16, help=PARALLEL_HELP)


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


GROUP_MISSING_HINT = "若 Group 刚创建或刚改过成员，同步到 BigQuery 需要几分钟，请稍后重跑；否则请检查 --group 是否拼错"


def execute_tables(tables, execute, n_workers, apply, needs_change, on_result):
    """
    逐表执行。execute(t) -> (lines, ok, group_missing)；on_result(t, res, err) 负责打印与计数。
    执行模式下先单独执行第一张需要变更的表：BigQuery 报 Group 不存在 → 立即停止，其余表都不执行
    （返回 "abort_first"，此时未做任何变更）。并行阶段再出现 Group 不存在 → 尚未开始的表不再执行（"abort_mid"）。
    返回 (状态, 未执行的需要变更的表数)——NOOP 的表本来就不需要执行，不计入。
    """
    first = next((t for t in tables if needs_change(t)), None) if apply else None
    if first is not None:
        res = execute(first)
        on_result(first, res, None)
        if res[2]:
            return "abort_first", sum(1 for t in tables if t != first and needs_change(t))
    rest = [t for t in tables if t != first]
    stop = threading.Event()

    def guarded(t):
        if stop.is_set() and needs_change(t):
            return None
        res = execute(t)
        if res[2]:
            stop.set()
        return res

    not_run = 0
    for t, res, err in ops.parallel_map(guarded, rest, workers=n_workers, desc="ddl"):
        if res is None and err is None:
            not_run += 1
            continue
        on_result(t, res, err)
    return ("abort_mid" if stop.is_set() else "ok"), not_run


PRINCIPAL_MISSING_HINT = "若主体刚创建或 Group 刚改过成员，同步到 BigQuery 需要几分钟，请稍后重跑；否则请检查 --principals 是否拼错、前缀是否写对"


def log_group_abort(status, not_run, group, what=None, hint=GROUP_MISSING_HINT, detail=""):
    """
    execute_tables 中止时的说明；返回该情况下的退出码（abort_first = 2：未做任何变更）。
    what: 「…不存在」的主语（默认「Group <group> 」；--principals 时为「--principals 中有授权对象」）；detail 紧跟「不存在」。
    """
    what = what or f"Group {group} "
    if status == "abort_first":
        ops.log(f"[ERROR] BigQuery 报 {what}不存在{detail}，已停止：其余 {not_run} 张需要变更的表未执行，未做任何变更。{hint}")
        return 2
    ops.log(f"[ERROR] 执行中 BigQuery 报 {what}不存在{detail}，已停止：{not_run} 张需要变更的表未执行。{hint}")
    return 1


def abort_summary(mode, status, not_run, counts):
    """中止时的汇总行：第一张即失败 → 未做任何变更；中途失败 → 已完成的计数 + 未执行数。"""
    if status == "abort_first":
        return f"===== 中止 ({mode})：未做任何变更，{not_run} 张需要变更的表未执行 ====="
    done = "，".join(f"{k} {v}" for k, v in sorted(counts.items())) or "无"
    return f"===== 中止 ({mode})：{done}；{not_run} 张需要变更的表未执行 ====="


def run_main(fn, argv):
    """统一的顶层错误处理：意外异常打印 [ERROR] 并返回 1（RLS_DEBUG=1 时抛出完整堆栈）；结束时关闭本次日志文件。"""
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
    finally:
        ops.stop_log_file()


# --------------------------------------------------------------------------- #
def _main(argv):
    p = argparse.ArgumentParser(description="为白名单设置 FILTER TRUE 行级规则（--group 一个 Group 一条规则，"
                                            "或 --principals 多个主体共用一条规则）", allow_abbrev=False)
    who = p.add_mutually_exclusive_group(required=True)          # 二选一：都不给 / 都给 -> argparse 报错，退出码 2
    who.add_argument("--group", default=None, help="白名单 Group 邮箱（只能一个；与 --principals 二选一）")
    who.add_argument("--principals", nargs="*", action="extend", default=None,
                   help="多个主体共用一条规则（与 --group 二选一）：每个都必须带前缀 user: / group: / serviceAccount:，"
                        "逗号或空格分隔；也可写 .csv 文件（单列无表头）。完整名单：规则的授权对象 = 这里的全部")
    p.add_argument("--policy-name", default=None,
                   help="与 --principals 搭配时必填：规则名后缀（小写字母、数字、下划线），"
                        "脚本自动加前缀 rls_bypass_full_access_")
    p.add_argument("--registry-table", required=True,
                   help="登记表 project.dataset.table（adm_user_mem_copilot_tb）：处理其中 rls_enabled = 1 的全部表")
    p.add_argument("--parallel", type=int, default=16, help=PARALLEL_HELP)
    p.add_argument("--quota-project", default=None, help="quota / 运行查询与 DDL 的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--verify-sa", default=None,
                   help="挂载后验证用的 SA（在该 Group 中、有表读权限、执行账号可扮演）：300 秒内查到任意一行即通过")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认只演练")
    ops.add_log_dir_arg(p)
    args = p.parse_args(argv)
    ops.start_log_file("apply_bypass_rls", args.log_dir)

    shared = args.principals is not None
    if shared and args.policy_name is None:
        ops.log("[ERROR] 使用 --principals 时必须同时给 --policy-name（规则名后缀，如 existing_all）")
        return 2
    if not shared and args.policy_name is not None:
        ops.log("[ERROR] --policy-name 只能与 --principals 搭配；--group 的规则名由 Group 邮箱自动生成")
        return 2
    group = None
    try:
        if shared:
            grantees = core.parse_bypass_principals(core.collect_values(args.principals))
            policy_name = core.shared_bypass_policy_name(args.policy_name)
        else:
            groups = core.split_items([args.group])
            if len(groups) != 1:
                ops.log(f"[ERROR] --group 只能指定一个 Group，收到 {len(groups)} 个: {groups}")
                return 2
            group = core.group_email(groups[0])                    # Group 邮箱格式（不能是 SA、不能带 user: 等前缀）
            grantees = [f"group:{group}"]
            policy_name = core.bypass_policy_name(group)
        core.build_policy_ddl("p.d.t", policy_name, grantees, "TRUE")   # 提前校验授权对象与规则名
        registry = core.parse_table_arg(args.registry_table)
    except (ValueError, OSError) as e:
        ops.log(f"[ERROR] {e}")
        return 2
    grantee = ", ".join(grantees)

    try:
        auth = resolve_auth(args.gcloud_account, args.quota_project)
    except AuthConfigError as e:
        ops.log(f"[ERROR] {e}")
        return 2
    ops.log(describe_auth(auth))
    ctx = ops.Ctx(auth.creds, auth.project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    if shared:
        ops.log(f"===== 模式: {mode}  规则: {policy_name}  授权对象: {len(grantees)} 个（共用一条规则）  并行: {workers(args)} =====")
        ops.log(f"[PRINCIPALS] 规则 {policy_name} 的授权对象共 {len(grantees)} 个（完整名单，与现有规则不同的表将 REPLACE）：\n"
                + "\n".join(f"  - {g}" for g in grantees))
    else:
        ops.log(f"===== 模式: {mode}  规则: {policy_name}  授权对象: {grantee}  并行: {workers(args)} =====")
    try:
        status = load_registry(ctx, registry)
    except ValueError as e:
        ops.log(f"[ERROR] {e}")
        return 2

    # 目标表 = 登记表中 rls_enabled = 1 的全部表
    table_list, bad_names, conflicts, n_disabled = core.registry_targets(status)
    for name in bad_names:
        ops.log(f"[WARN] 登记表 table_name {name!r} 不是 project.dataset.table 格式")
        ops.log(f"[SKIP] {name}: 登记表表名格式不对，不授权")
    for name in conflicts:
        ops.log(f"[WARN] {name}: 登记表中有多条记录且 rls_enabled 不一致（既有 1 又有其它值），按未开启处理")
        ops.log(f"[SKIP] {name}: 登记表记录冲突，不授权")
    ops.log(f"[SCAN] 登记表中 rls_enabled = 1 的表 {len(table_list)} 张；rls_enabled ≠ 1 的 {n_disabled} 张不处理")

    # 阶段 1：并行读取现有规则（只读取本规则名的授权对象），生成计划；表不存在 -> [SKIP]
    failed = bool(bad_names or conflicts)
    skipped = len(bad_names) + len(conflicts)

    def plan_table(t):
        if not ops.table_exists(ctx, t):
            return None
        return core.plan_upsert(ops.list_policies(ctx, t, grantees_for={policy_name}), policy_name, "TRUE", grantees)

    plans = {}
    for t, pl, err in ops.parallel_map(plan_table, table_list, workers=workers(args), desc="plan"):
        if err:
            failed = True
            ops.log(f"[ERROR] {t}: 读取现有规则失败: {err}")
        elif pl is None:
            failed = True
            skipped += 1
            ops.log(f"[SKIP] {t}: {core.TABLE_NOT_FOUND_MSG}")
        else:
            plans[t] = pl

    log_first_policy_tables([t for t, pl in plans.items() if pl.first_policy and pl.action == "create"])

    # 阶段 2：执行（每张表一条 DDL；执行模式先单独执行第一张，BigQuery 报 Group 不存在则立即停止）
    def execute(t):
        pl = plans[t]
        lines = []
        if pl.action == "noop":
            return [f"[NOOP] {t}"], True, False
        ddl = core.build_policy_ddl(t, policy_name, grantees, "TRUE")
        lines.append(f"[{pl.action.upper()}] {t}\n{ddl}")
        if pl.action == "replace":
            lines.append(f"  被覆盖的旧内容: grantees={pl.old['grantees']} filter={pl.old['filter']}")
            if shared:
                added, removed = core.grantee_diff(pl.old["grantees"], grantees)
                lines.append(f"  将新增: {added or '无'}")
                lines.append(f"  将移除: {removed or '无'}")
        if args.apply:
            try:
                ops.run_ddl(ctx, ddl, ctx.table_location(t), retry_missing_principal=False)
            except Exception as e:  # noqa: BLE001
                lines.append(f"  [ERROR] {e}")
                return lines, False, ops.is_principal_missing_error(e)
        return lines, True, False

    counts = {"SKIP": skipped} if skipped else {}

    def on_result(t, res, err):
        nonlocal failed
        if err:
            failed = True
            ops.log(f"[ERROR] {t}: {err}")
            return
        lines, ok, _ = res
        ops.log("\n".join(lines))
        failed = failed or not ok
        key = plans[t].action.upper() if ok else "ERROR"         # 执行失败的表计入 ERROR，不计入其计划动作
        counts[key] = counts.get(key, 0) + 1

    status, not_run = execute_tables(list(plans), execute, workers(args), args.apply,
                                     lambda t: plans[t].action != "noop", on_result)
    if status != "ok":
        code = (log_group_abort(status, not_run, group, what="--principals 中有授权对象", detail="（是哪个见上方 [ERROR]）",
                                hint=PRINCIPAL_MISSING_HINT)
                if shared else log_group_abort(status, not_run, group))
        ops.log(abort_summary(mode, status, not_run, counts))
        return code

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
