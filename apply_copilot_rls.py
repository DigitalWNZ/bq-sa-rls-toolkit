#!/usr/bin/env python3
"""
为 Copilot Group 设置行级规则（Doc 第 7 步）：每张表给 --group 建一条规则，组内每个 SA / user 按条件表各自只看到规定的数据。

数据来源（三张表都必填，格式 project.dataset.table）:
  --condition-table  adm_user_mem_copilot_condition（id, sa, region[], prdtype[], refername[] ...）
                     客户业务人员为每个 SA / user 指定可见的维度值；某维度为 NULL / 空数组 = 该维度全部可见
  --mapping-table    adm_user_mem_copilot_tb_col_mapping（table_name, col_name, to_name）
                     每张业务表里与维度对应的真实列名（col_name）及维度正式名称（to_name）
  --registry-table   adm_user_mem_copilot_tb（table_name, rls_enabled, ...）
                     只有其中 rls_enabled = 1 的表才建规则（与 apply_bypass_rls.py 规则一致）
  --group            Copilot Group 邮箱（只能一个）；新增的 SA / user 加入这个 Group 即可
  表名一律写 project.dataset.table（反引号可选，如 `trip-bq-admin.bq_auth.adm_user_mem_copilot_tb`；不支持冒号写法）

处理逻辑:
  1. 维度 = 条件表中除 id、sa 外的 ARRAY<STRING> 列（运行时读取表结构；以后加列不用改代码；status 等非数组列不算）
  2. 选表：映射表中 to_name 属于维度的行（一张表可有多行 = 多个维度）；无效行忽略；
     再与登记表 rls_enabled = 1 的表取交集（table_name 原始字符串精确比较，不看 status）：
     未开启 / 未登记的表逐张 [SKIP]；同名多行 rls_enabled 不一致 -> [WARN] + [SKIP]，退出码 1；
     登记为开启、但映射表中没有任何校验维度的表 -> [SKIP]，不建规则
  3. 每张表一条规则，规则名 rls_copilot_<group 邮箱，小写，非字母数字换成 _>，GRANT TO ("group:<group>")；
     过滤条件为子查询，按 SESSION_USER() 实时查条件表（改条件值、新增账号都立即生效，无需重跑）:
       <col_name> IN (SELECT v FROM 条件表 c, UNNEST(c.<维度>) v WHERE c.sa = SESSION_USER())
       OR EXISTS (... c.<维度> IS NULL OR ARRAY_LENGTH(c.<维度>) = 0)
     多个维度用 AND 连接；非 STRING 列 CAST 为 STRING。
  需要重跑的情况：映射表 / 登记表变化（新增表、改维度）、条件表新增维度列。规则内容相同 -> NOOP。

账号生效的前提（脚本不检查，由客户维护）: ① 账号在 --group 里；② 条件表里有该账号的行；
  ③ --group 对条件表有读权限（BigQuery 以查询者身份执行子查询）。组内成员因此能读到整张条件表。

安全与校验:
  - 条件表 sa 值不是小写 / 有首尾空白 / 带 user: 等前缀 / 不是邮箱 -> 这些账号永远匹配不到 SESSION_USER()（查到 0 行）：[WARN]，退出码 1
  - 同一 sa 在条件表中有多行 -> 各维度独立判断会出现交叉组合：[WARN]，退出码 1
  - 条件表为空 -> [NOTE]，规则照建（组内成员都查到 0 行）
  - 同名规则：内容相同 -> NOOP；授权对象或过滤条件不同 -> REPLACE（审核 CSV 的 note 记录旧内容）
  - 每张表最多 400 条规则：已满且需要新建 -> [SKIP]，退出码 1
  - 映射列不存在 / REPEATED / RECORD / 类型不支持 -> 跳过该表
  - 条件表 / 映射表是否设置 RLS 只看登记表：客户应把它们登记为 rls_enabled = 0
  - 表上原本没有任何 RLS 时只在日志中提示（[NOTE]）；现存账号会查到 0 行，可用 apply_bypass_rls.py 为其 Group 补上

输出: 审核 CSV（默认 copilot_rls_plan.csv），每张表一行，只含 CREATE / REPLACE：
  table, policy_name, action, dimensions, filter, note（执行模式另加 result）
--tables: 只处理这些表（值或单列无表头的 .csv 文件，可混用）。
--parallel: 同时处理的表数（默认 16）。

示例:
  python apply_copilot_rls.py --group group_copilot@trip.com \\
      --condition-table auth-proj.auth.adm_user_mem_copilot_condition \\
      --mapping-table auth-proj.auth.adm_user_mem_copilot_tb_col_mapping \\
      --registry-table auth-proj.auth.adm_user_mem_copilot_tb
  python apply_copilot_rls.py ... --apply

退出码: 0 成功；1 有表被跳过 / 失败、条件表数据有问题、登记表记录冲突；2 参数错误 / 登记表不可用 / 无法确定执行账号（未做任何变更）
"""

import argparse
import csv
import sys

import gcp_ops as ops
import rls_core as core
from apply_bypass_rls import filter_by_registry, load_registry, log_first_policy_tables, run_main
from gcp_auth import AuthConfigError, describe_auth, resolve_auth


def write_plan_csv(path, entries, apply):
    cols = core.COPILOT_PLAN_COLUMNS_APPLY if apply else core.COPILOT_PLAN_COLUMNS
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(core.csv_safe_row(e) for e in entries if e["action"] in ("CREATE", "REPLACE"))


def check_condition_sa(counts):
    """条件表 sa 列的数据问题 -> 是否有问题（[WARN] 已打印）。"""
    raw = list(counts)
    bad = False
    if not raw:
        ops.log("[NOTE] 条件表中没有任何 sa 记录：规则照建，但组内成员都会查到 0 行")
        return False
    unnormalized = core.unnormalized_sa_values(raw)
    invalid = core.invalid_sa_values(raw)
    unnormalized = [v for v in unnormalized if v not in invalid]
    dup = core.duplicate_sa_values(counts)
    if invalid:
        bad = True
        ops.log("[WARN] 条件表 sa 列存在不是裸邮箱的值（带 user: / group: 等前缀、allUsers、乱码），"
                f"这些值永远匹配不到 SESSION_USER()，对应账号会查到 0 行，请修正条件表: {invalid}")
    if unnormalized:
        bad = True
        ops.log("[WARN] 条件表 sa 列存在非小写或带首尾空白的值，子查询按原值与 SESSION_USER() 精确比较，"
                f"这些账号会查到 0 行，请修正条件表: {unnormalized}")
    if dup:
        bad = True
        ops.log("[WARN] 条件表中以下 sa 有多行：各维度独立判断，会看到不同行之间维度值的交叉组合，"
                f"请确认是否预期: {dup}")
    ops.log(f"[PRINCIPAL] 条件表共 {len(raw)} 个 sa")
    return bad


def _main(argv):
    p = argparse.ArgumentParser(description="为 Copilot Group 设置行级规则（每张表一条）", allow_abbrev=False)
    p.add_argument("--group", required=True, help="Copilot Group 邮箱（只能一个）")
    p.add_argument("--condition-table", required=True, help="条件表 project.dataset.table")
    p.add_argument("--mapping-table", required=True, help="映射表 project.dataset.table")
    p.add_argument("--registry-table", required=True,
                   help="登记表 project.dataset.table（adm_user_mem_copilot_tb）：只有其中 rls_enabled = 1 的表才建规则")
    p.add_argument("--tables", nargs="*", action="extend", default=[], help="只处理这些表（project.dataset.table，反引号可选）；也可写 .csv 文件")
    p.add_argument("-o", "--output", default="copilot_rls_plan.csv", help="审核 CSV")
    p.add_argument("--parallel", type=int, default=16, help="同时处理的表数（默认 16；建议不超过 32）")
    p.add_argument("--quota-project", default=None,
                   help="quota / 运行查询与 DDL 的项目（默认 gcloud 默认项目，其次 application-default 凭证的 quota 项目）")
    p.add_argument("--gcloud-account", default=None, help="执行账号（默认 gcloud 当前活动账号，其次 application-default 凭证）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认只演练")
    args = p.parse_args(argv)
    workers = max(1, args.parallel)

    groups = core.split_items([args.group])
    if len(groups) != 1:
        ops.log(f"[ERROR] --group 只能指定一个 Group，收到 {len(groups)} 个: {groups}")
        return 2
    try:
        group = core.copilot_group(groups[0])
        cond = core.parse_table_arg(args.condition_table)
        mapping_table = core.parse_table_arg(args.mapping_table)
        registry = core.parse_table_arg(args.registry_table)
        only_tables = list(dict.fromkeys(core.parse_table_arg(t) for t in core.collect_values(args.tables)))
    except (ValueError, OSError) as e:
        ops.log(f"[ERROR] {e}")
        return 2
    policy_name = core.copilot_policy_name(group)
    grantee = f"group:{group}"
    try:
        core.build_policy_ddl("p.d.t", policy_name, [grantee], "TRUE")      # 提前校验
    except ValueError as e:
        ops.log(f"[ERROR] {e}")
        return 2

    try:
        auth = resolve_auth(args.gcloud_account, args.quota_project)
    except AuthConfigError as e:
        ops.log(f"[ERROR] {e}")
        return 2
    ops.log(describe_auth(auth))
    ctx = ops.Ctx(auth.creds, auth.project)
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode}  规则: {policy_name}  授权对象: {grantee}  条件表: {cond}  并行: {workers} =====")
    failed = False
    try:
        status = load_registry(ctx, registry)
    except ValueError as e:
        ops.log(f"[ERROR] {e}")
        return 2

    # 1. 维度
    try:
        dims, warns = core.condition_dimensions(ops.table_fields(ctx, cond))
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 读取条件表结构失败: {e}")
        return 1
    for w in warns:
        ops.log(f"[WARN] {w}")
    ops.log(f"[DIM] 维度: {', '.join(dims) or '（无）'}")
    if not dims:
        ops.log("[ERROR] 条件表中没有可用作维度的 ARRAY<STRING> 列（除 id、sa 外），无法生成规则")
        return 1

    # 2. 选表
    try:
        rows = ops.read_mapping_rows(ctx, mapping_table)
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 读取映射表失败: {e}")
        return 1
    mapping, ignored = core.select_copilot_tables(rows, dims, default_project=core.parse_table(mapping_table)[0])
    for msg in ignored:
        ops.log(f"[IGNORE] {msg}")
    if rows and not mapping:
        ops.log(f"[ERROR] 映射表 {len(rows)} 行全部无效（table_name 格式错误或 to_name 不是维度），请检查映射表")
        return 1
    if only_tables:
        mapping = {t: cols for t, cols in mapping.items() if t in only_tables}
    with_dims = set(mapping)
    allowed, conflicts = filter_by_registry(list(mapping), status, registry)     # 登记表 rls_enabled = 1 才建规则
    failed = failed or conflicts > 0
    mapping = {t: mapping[t] for t in allowed}
    # 没有任何校验维度的表（登记为开启的表，或 --tables 指定的表）：不建规则
    enabled = set()
    for name, st in status.items():
        if st == "enabled":
            try:
                enabled.add(core.fq(name))
            except ValueError:
                pass
    for t in sorted((set(only_tables) if only_tables else enabled) - with_dims):
        ops.log(f"[SKIP] {t}: 映射表中没有该表的校验维度，不建规则")
    for t, cols in mapping.items():
        ops.log(f"[MAP] {t}: " + ", ".join(f"{c}->{d}" for c, d in cols))

    # 3. 条件表数据检查（只提醒，不影响建规则）
    try:
        counts = ops.condition_sa_counts(ctx, cond)
    except Exception as e:  # noqa: BLE001
        ops.log(f"[ERROR] 读取条件表失败: {e}")
        return 1
    failed = check_condition_sa(counts) or failed

    # 4. 逐表规划（并行；只读取本规则名的授权对象）
    def plan_table(table):
        cols = mapping[table]
        schema = ops.table_schema(ctx, table)
        errors = core.validate_mapping_against_schema(cols, schema)
        if errors:
            return {"skip": "; ".join(errors)}
        flt = core.build_copilot_filter(cols, cond, column_types={c: schema[c][0] for c, _ in cols})
        existing = ops.list_policies(ctx, table, grantees_for={policy_name})
        pl = core.plan_upsert(existing, policy_name, flt, [grantee])
        entry = {"table": table, "policy_name": policy_name, "action": pl.action.upper(),
                 "dimensions": ", ".join(d for _, d in cols), "filter": flt, "note": ""}
        if pl.action == "create" and core.remaining_policy_slots(len(existing)) <= 0:
            return {"skip": f"该表已达 {core.MAX_POLICIES_PER_TABLE} 条规则上限，无法新建 {policy_name}"}
        if pl.action == "replace":
            entry["note"] = f"原过滤条件: {pl.old['filter']}; 原授权对象: {pl.old['grantees']}"
        return {"entry": entry, "first": pl.first_policy and pl.action == "create"}

    plans, first_tables = {}, []
    for table, res, err in ops.parallel_map(plan_table, sorted(mapping), workers=workers, desc="plan"):
        if err:
            failed = True
            ops.log(f"[SKIP] {table}: {err}")
        elif "skip" in res:
            failed = True
            ops.log(f"[SKIP] {table}: {res['skip']}")
        else:
            plans[table] = res["entry"]
            if res["first"]:
                first_tables.append(table)
    log_first_policy_tables(first_tables)          # 只作提示，不拦截；现存账号可用 apply_bypass_rls.py 补上

    # 5. 执行（表之间并行；每张表一条 DDL）
    def execute(table):
        e = plans[table]
        if e["action"] == "NOOP":
            return [f"[NOOP] {table}"], True
        ddl = core.build_policy_ddl(table, policy_name, [grantee], e["filter"])
        lines = [f"[{e['action']}] {table}\n{ddl}"]
        if e["note"]:
            lines.append(f"  {e['note']}")
        if args.apply:
            try:
                ops.run_ddl(ctx, ddl, ctx.table_location(table))
                e["result"] = "OK"
            except Exception as ex:  # noqa: BLE001
                e["result"] = f"ERROR: {str(ex)[:300]}"
                lines.append(f"  [ERROR] {ex}")
                return lines, False
        return lines, True

    for table, res, err in ops.parallel_map(execute, list(plans), workers=workers, desc="ddl"):
        if err:
            failed = True
            ops.log(f"[ERROR] {table}: {err}")
            continue
        lines, ok = res
        ops.log("\n".join(lines))
        failed = failed or not ok

    entries = [plans[t] for t in sorted(plans)]
    counts_by_action = {}
    for e in entries:
        counts_by_action[e["action"]] = counts_by_action.get(e["action"], 0) + 1
    write_plan_csv(args.output, entries, args.apply)
    ops.log(f"[CSV] 审核文件已写入 {args.output}（每张表一行，只含 CREATE / REPLACE）")
    ops.log(f"===== 完成 ({mode})：" + ("，".join(f"{k} {v}" for k, v in sorted(counts_by_action.items())) or "无")
            + " =====")
    return 1 if failed else 0


def main(argv=None):
    return run_main(_main, argv)


if __name__ == "__main__":
    sys.exit(main())
