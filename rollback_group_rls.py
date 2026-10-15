#!/usr/bin/env python3
"""
回退脚本：删除表上的 BigQuery Row Access Policy（setup / apply_bypass / apply_copilot 的逆操作）。

输入:
  1. group 列表（可选）: --groups / --groups-file
  2. 表列表: --tables / --tables-file（也可用 --datasets / --projects 扫描）
  3. policy 名称（可选）: --policy-names，只处理这些名称的 policy
     （例如只撤掉 Copilot 策略 rls_copilot_subquery_policy，保留白名单 rls_bypass_full_access）

行为:
  - 提供 group 列表: 删除授权对象中包含任一 group 的 policy；--strip-only 时只剥离这些 group
  - 未提供 group 列表: 删除（--policy-names 范围内的）所有 policy；未指定 --policy-names 时 DROP ALL
  - 表上所有 policy 都要删除时使用 DROP ALL ROW ACCESS POLICIES（BigQuery 不允许单独删除最后一条）
  - --backup-dir: 变更前把该表全部 policy（过滤条件、授权对象、可重放 DDL）备份为 JSON

可选（需提供 group 列表）:
  --revoke-table-viewer  移除这些 group 在表上的 roles/bigquery.dataViewer
  --delete-group         最后删除这些 Cloud Identity group

默认 dry-run；加 --apply 才真正执行。

示例:
  # 一键回退：删除这些表上所有 RLS（先备份）
  python rollback_group_rls.py --tables-file tables.txt --backup-dir backup/ --apply
  # 只撤掉 Copilot 策略
  python rollback_group_rls.py --tables-file tables.txt --policy-names rls_copilot_subquery_policy --apply
  # 删除与指定 group 相关的 RLS
  python rollback_group_rls.py --groups g1@x.com,g2@x.com --tables p.d.t1 --apply

注意: 删除表上最后一条 RLS 后，该表恢复为"无行级过滤"，所有有表读权限的用户都能看到全部行。
"""

import argparse
import json
import os
import sys
import time

import gcp_ops as ops
import rls_core as core
from gcp_auth import get_credentials

VIEWER_ROLE = "roles/bigquery.dataViewer"


def collect_tables(ctx, tables, datasets, projects):
    result = [core.fq(t) for t in tables]
    ds_list = [tuple(d.replace(":", ".").split(".")) for d in datasets]
    for project in projects:
        try:
            ds_list += [(project, d.dataset_id) for d in ctx.bq.list_datasets(project=project)]
        except Exception as e:  # noqa: BLE001
            ops.log(f"[WARN] 列出 {project} 数据集失败: {e}")
    for project, dataset in ds_list:
        try:
            for t in ctx.bq.list_tables(f"{project}.{dataset}"):
                if t.table_type in ("TABLE", "EXTERNAL"):
                    result.append(f"{project}.{dataset}.{t.table_id}")
        except Exception as e:  # noqa: BLE001
            ops.log(f"[WARN] 列出 {project}.{dataset} 表失败: {e}")
    return list(dict.fromkeys(result))


def backup(table, policies, backup_dir):
    os.makedirs(backup_dir, exist_ok=True)
    items = []
    for p in policies:
        try:
            ddl = core.build_policy_ddl(table, p["id"], p["grantees"], p["filter"])
        except ValueError:
            ddl = None   # 例如授权对象含已删除主体，无法直接重放
        items.append({**p, "ddl": ddl})
    path = os.path.join(backup_dir, f"{table}.{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"table": table, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "policies": items}, f, ensure_ascii=False, indent=2)
    ops.log(f"  [BACKUP] {path}")


def run(ctx, ddl, location, apply):
    ops.log(f"    DDL: {ddl}")
    if apply:
        ops.run_ddl(ctx, ddl, location)
        ops.log("    -> 完成")


def rollback_table(ctx, table, members, strip_only, policy_names, backup_dir, apply):
    policies = ops.list_policies(ctx, table)
    if not policies:
        return 0
    plan = core.plan_rollback(policies, members, strip_only, policy_names)
    if not plan.to_drop and not plan.to_update:
        return 0
    full = f"`{table}`"
    loc = ctx.table_location(table)
    ops.log(f"[TABLE] {table}  (共 {len(policies)} 条 RLS，删除 {len(plan.to_drop)} 条，"
            f"剥离 {len(plan.to_update)} 条)")
    if backup_dir and apply:
        backup(table, policies, backup_dir)
    for p, others in plan.to_update:
        ops.log(f"  [STRIP] `{p['id']}` 保留 {others}")
        run(ctx, core.build_policy_ddl(table, p["id"], others, p["filter"]), loc, apply)
    for p in plan.to_drop:
        ops.log(f"  [DROP] `{p['id']}` filter={p['filter']} grantees={p['grantees']}")
    if plan.drop_all:
        run(ctx, f"DROP ALL ROW ACCESS POLICIES ON {full}", loc, apply)
        ops.log("  [NOTE] 回退后该表已没有任何 RLS，所有有表读权限的用户可见全部行")
    else:
        for p in plan.to_drop:
            run(ctx, f"DROP ROW ACCESS POLICY `{p['id']}` ON {full}", loc, apply)
    return len(plan.to_drop) + len(plan.to_update)


def delete_groups(ctx, members, apply):
    for m in sorted(members):
        if not m.startswith("group:"):
            continue
        email = core.member_email(m)
        name = ops.lookup_group(ctx, email)
        if not name:
            ops.log(f"[GROUP] {email} 不存在或无权限查看，跳过")
            continue
        ops.log(f"[GROUP] 删除 {email} ({name})")
        if apply:
            ctx.ci.groups().delete(name=name).execute()
            ops.log("  -> 完成")


def main():
    p = argparse.ArgumentParser(
        description="删除表上与指定 group 相关的 RLS；不指定 group 时删除表上所有 RLS")
    p.add_argument("--groups", nargs="*", default=[],
                   help="group 邮箱列表（也可写 user:/serviceAccount: 等带前缀的主体）")
    p.add_argument("--groups-file", default=None)
    p.add_argument("--tables", nargs="*", default=[])
    p.add_argument("--tables-file", default=None)
    p.add_argument("--datasets", nargs="*", default=[])
    p.add_argument("--projects", nargs="*", default=[])
    p.add_argument("--policy-names", nargs="*", default=[], help="只处理这些名称的 policy")
    p.add_argument("--backup-dir", default=None, help="变更前备份 policy 的目录")
    p.add_argument("--quota-project", default=None)
    p.add_argument("--gcloud-account", default=None)
    p.add_argument("--strip-only", action="store_true")
    p.add_argument("--revoke-table-viewer", action="store_true")
    p.add_argument("--delete-group", action="store_true")
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    groups = core.split_items(args.groups) + (core.read_list_file(args.groups_file)
                                               if args.groups_file else [])
    members = {core.normalize_member(g) for g in groups}
    tables = core.split_items(args.tables) + (core.read_list_file(args.tables_file)
                                               if args.tables_file else [])
    datasets, projects = core.split_items(args.datasets), core.split_items(args.projects)
    policy_names = set(core.split_items(args.policy_names)) or None
    if not (tables or datasets or projects):
        p.error("至少指定 --tables / --tables-file / --datasets / --projects 之一")
    if not members and (args.revoke_table_viewer or args.delete_group or args.strip_only):
        p.error("--revoke-table-viewer / --delete-group / --strip-only 需要同时指定 group 列表")

    quota = args.quota_project or (tables + datasets + projects)[0].replace(":", ".").split(".")[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, quota), quota)
    mode = "APPLY" if args.apply else "DRY-RUN"
    ops.log(f"===== 模式: {mode} =====")
    if members:
        ops.log(f"[SCOPE] 删除与以下主体相关的 RLS: {sorted(members)}")
    else:
        ops.log("[SCOPE] 未指定 group —— 将删除目标表上"
                + (f"名称为 {sorted(policy_names)} 的 RLS" if policy_names else "的【所有】RLS"))

    table_list = collect_tables(ctx, tables, datasets, projects)
    ops.log(f"[SCAN] 共 {len(table_list)} 张表待检查")
    total = touched = 0
    failed = False
    for t in table_list:
        try:
            n = rollback_table(ctx, t, members, args.strip_only, policy_names,
                               args.backup_dir, args.apply)
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"  [ERROR] 处理 {t} 失败: {e}")
            continue
        if n:
            total += n
            touched += 1
        if args.revoke_table_viewer:
            try:
                if args.apply:
                    removed = ops.table_remove_role(ctx, t, VIEWER_ROLE, members)
                else:
                    removed = members & ops.table_role_members(ctx, t, VIEWER_ROLE)
                if removed:
                    ops.log(f"  [IAM] 移除 {sorted(removed)} 在 {t} 上的 {VIEWER_ROLE}")
            except Exception as e:  # noqa: BLE001
                ops.log(f"  [WARN] 处理 {t} 表级 IAM 失败: {e}")

    if args.delete_group:
        delete_groups(ctx, members, args.apply)
    ops.log(f"===== 完成 ({mode})：{touched} 张表，共处理 {total} 条 RLS =====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
