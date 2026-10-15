#!/usr/bin/env python3
"""
T8 按映射表为多张目标表动态生成 Copilot 行级策略（RLS Subquery，文档 Step 7）。

每张表的过滤字段可以不同（列名、个数、嵌套层级、类型都可以不同），由映射表驱动:
  adm_user_mem_copilot_tb_col_mapping(table_name, col_name, to_name)
    table_name: project.dataset.table（或 dataset.table + --default-project）
    col_name:   目标表真实列名，支持嵌套路径 a.b
    to_name:    条件表标准维度 region / prdtype / refername
对每张表只为其映射到的维度生成条件（多维度 AND）：
  列值 ∈ UNNEST(condition.<维度>)  OR  condition.<维度> 为 NULL/空数组（全量通配）
  身份 = SESSION_USER()（即 Copilot 权限 SA）；非 STRING 列自动 CAST 为 STRING；
  --case-insensitive 时两侧用 UPPER() 比较（R6）。

安全与校验:
  - 目标表必须已存在白名单 policy（默认 rls_bypass_full_access），否则整批中止（exit 2），
    防止先挂 Copilot policy 触发 Implicit Deny 导致存量业务中断。
  - 按表 schema 校验映射：列不存在 / REPEATED / RECORD / 不支持类型 -> 跳过该表（exit 1），其他表照常处理。
  - 已一致 -> [NOOP]；过滤条件或授权对象变化（映射表或 Group 调整）-> [REPLACE]。

示例:
  python apply_copilot_rls.py --mapping-table p.auth.adm_user_mem_copilot_tb_col_mapping \\
      --condition-table p.auth.adm_user_mem_copilot_condition \\
      --groups copilot-high@x.com,copilot-low@x.com --apply
  # 只处理部分表（灰度推广 30% / 50% ...）
  python apply_copilot_rls.py ... --tables-file batch1.txt --apply

退出码: 0 成功；1 部分表失败/被跳过；2 缺少白名单 policy（未做任何变更）
"""

import argparse
import csv
import sys

import gcp_ops as ops
import rls_core as core
from gcp_auth import get_credentials


def load_mapping(ctx, mapping_table, mapping_csv, default_project):
    if mapping_csv:
        with open(mapping_csv, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    else:
        t = core.fq(mapping_table)
        rows = [dict(r.items()) for r in ops.run_query(
            ctx, f"SELECT table_name, col_name, to_name FROM `{t}`", ctx.table_location(t))]
    return core.parse_mapping_rows(rows, default_project)


def table_schema(ctx, table):
    return core.flatten_schema(ctx.bq.get_table(table).schema)


def plan_tables(ctx, mapping, condition_table, groups, bypass_name, policy_name, case_insensitive=False):
    """返回 [(table, action, ddl_or_reason)]，action ∈ create/replace/noop/skip/nobypass。"""
    out = []
    for table, cols in mapping.items():
        try:
            schema = table_schema(ctx, table)
        except Exception as e:  # noqa: BLE001
            out.append((table, "skip", f"读取表失败: {e}"))
            continue
        errors = core.validate_mapping_against_schema(cols, schema)
        if errors:
            out.append((table, "skip", "; ".join(errors)))
            continue
        types = {c: schema[c][0] for c, _ in cols}
        flt = core.build_copilot_filter(cols, condition_table, column_types=types,
                                        case_insensitive=case_insensitive)
        existing = ops.list_policies(ctx, table)
        if not any(p["id"] == bypass_name for p in existing):
            out.append((table, "nobypass", f"缺少白名单 policy `{bypass_name}`"))
            continue
        cur = next((p for p in existing if p["id"] == policy_name), None)
        ddl = core.build_policy_ddl(table, policy_name, groups, flt)
        if cur is None:
            out.append((table, "create", ddl))
        elif (core.normalize_filter(cur["filter"]) == core.normalize_filter(flt)
              and {core.normalize_member(g) for g in cur["grantees"]} == set(groups)):
            out.append((table, "noop", ""))
        else:
            out.append((table, "replace", ddl))
    return out


def main():
    p = argparse.ArgumentParser(description="按映射表为多张表动态生成 Copilot RLS Subquery 策略")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--mapping-table", help="BigQuery 映射表 project.dataset.table")
    src.add_argument("--mapping-csv", help="映射 CSV（列 table_name,col_name,to_name）")
    p.add_argument("--condition-table", required=True, help="adm_user_mem_copilot_condition 全名")
    p.add_argument("--groups", nargs="+", required=True, help="Copilot 表级 Group（Group A/B）")
    p.add_argument("--tables", nargs="*", default=[], help="只处理这些表（默认映射表中的全部表）")
    p.add_argument("--tables-file", default=None)
    p.add_argument("--default-project", default=None, help="映射表 table_name 为 dataset.table 时补全项目")
    p.add_argument("--bypass-policy-name", default=core.BYPASS_POLICY)
    p.add_argument("--policy-name", default=core.COPILOT_POLICY)
    p.add_argument("--case-insensitive", action="store_true",
                   help="两侧用 UPPER() 比较（业务表与条件表大小写不一致时，R6）；巡检需带同样参数")
    p.add_argument("--project", default=None, help="quota / 运行 DDL 的项目（默认条件表所在项目）")
    p.add_argument("--gcloud-account", default=None)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    cond = core.fq(args.condition_table)
    project = args.project or core.parse_table(cond)[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, project), project)
    groups = [core.normalize_member(g) for g in core.split_items(args.groups)]
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode}  policy={args.policy_name}  grantees={groups} =====")

    mapping = load_mapping(ctx, args.mapping_table, args.mapping_csv,
                           args.default_project or project)
    only = core.split_items(args.tables) + (core.read_list_file(args.tables_file)
                                             if args.tables_file else [])
    if only:
        only = [core.fq(t, args.default_project or project) for t in only]
        missing = [t for t in only if t not in mapping]
        for t in missing:
            ops.log(f"[SKIP] {t}: 映射表中没有该表的过滤字段配置")
        mapping = {t: mapping[t] for t in only if t in mapping}
    for t, cols in mapping.items():
        ops.log(f"[MAP] {t}: " + ", ".join(f"{c}->{d}" for c, d in cols))

    plans = plan_tables(ctx, mapping, cond, groups, args.bypass_policy_name, args.policy_name,
                        args.case_insensitive)
    nobypass = [(t, r) for t, a, r in plans if a == "nobypass"]
    if nobypass:
        for t, r in nobypass:
            ops.log(f"[ABORT] {t}: {r}")
        ops.log("已中止，未做任何变更。请先用 apply_bypass_rls.py 为这些表挂载白名单 policy。")
        return 2

    failed = bool(only and len(mapping) < len(only))
    for t, action, detail in plans:
        if action == "noop":
            ops.log(f"[NOOP] {t}")
        elif action == "skip":
            failed = True
            ops.log(f"[SKIP] {t}: {detail}")
        else:
            ops.log(f"[{action.upper()}] {t}\n{detail}")
            if args.apply:
                try:
                    ops.run_ddl(ctx, detail, ctx.table_location(t))
                except Exception as e:  # noqa: BLE001
                    failed = True
                    ops.log(f"  [ERROR] {e}")
    ops.log(f"===== 完成 ({mode}) =====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
