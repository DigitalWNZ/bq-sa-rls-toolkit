#!/usr/bin/env python3
"""
回退脚本：删除表上的 BigQuery Row Access Policy（setup_group_rls.py 的逆操作）。

输入:
  1. group 列表（可选）: --groups / --groups-file
  2. 表列表（必填其一）: --tables / --tables-file（也可用 --datasets / --projects 扫描）

行为:
  - 提供了 group 列表:
      检查每张表上的 RLS，只要某条 policy 的 grantees 中包含任一指定 group，就删除整条 policy。
      （加 --strip-only 则不删除整条，只从 grantees 中去掉这些 group；
        若去掉后没有剩余 grantee，仍然删除）
  - 未提供 group 列表:
      删除这些表上的所有 RLS（DROP ALL ROW ACCESS POLICIES）。

grantees 通过 rowAccessPolicies.getIamPolicy 读取（以 roles/bigquery.filteredDataViewer 成员形式返回）。

可选（仅在提供 group 列表时可用）:
  --revoke-table-viewer  同时移除这些 group 在表上的 roles/bigquery.dataViewer
  --delete-group         最后删除这些 Cloud Identity group

默认 dry-run；加 --apply 才真正执行。

示例:
  # 删除与指定 group 相关的 RLS
  python rollback_group_rls.py \\
      --groups bq-sa-all-rows@example.com other-group@example.com \\
      --tables my-project.my_dataset.t1 my-project.my_dataset.t2 \\
      --gcloud-account admin@example.com

  # 删除这些表上的所有 RLS
  python rollback_group_rls.py --tables-file tables.txt --gcloud-account admin@example.com

  # 确认后执行
  python rollback_group_rls.py ... --apply

说明:
  - group 列表中可直接写邮箱（默认视为 group:），也可写带前缀的主体，
    如 user:alice@x.com、serviceAccount:sa@p.iam.gserviceaccount.com。
  - BigQuery 不允许用 DROP ROW ACCESS POLICY 删除表上最后一条 policy，脚本会自动改用
    DROP ALL ROW ACCESS POLICIES（此时表上只剩这一条，不会误删）。
  - 删除表上最后一条 RLS 后，该表恢复为"无行级过滤"，所有有表读权限的用户都能看到全部行。
"""

import argparse
import sys

from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from gcp_auth import get_credentials

RLS_ROLE = "roles/bigquery.filteredDataViewer"
VIEWER_ROLE = "roles/bigquery.dataViewer"


def log(msg):
    print(msg, file=sys.stderr)


def split_ref(ref, n):
    parts = ref.replace(":", ".").split(".")
    if len(parts) != n:
        raise ValueError(f"格式错误（应为 {'project.dataset.table' if n == 3 else 'project.dataset'}）: {ref}")
    return parts


def read_list_file(path):
    with open(path) as f:
        return split_items(l for l in f if not l.strip().startswith("#"))


def split_items(values):
    """把参数值按逗号/空白拆开，支持 --tables "a,b" 或 --tables "a b" 的写法。"""
    out = []
    for v in values:
        out.extend(x for x in v.replace(",", " ").split() if x)
    return out


def normalize_member(m):
    """邮箱默认视为 group:；已带前缀（user:/group:/serviceAccount:/domain: 等）则保留。"""
    m = m.strip()
    if ":" not in m:
        m = f"group:{m}"
    prefix, _, rest = m.partition(":")
    return f"{prefix}:{rest.lower()}"


# --------------------------------------------------------------------------- #
# 收集表
# --------------------------------------------------------------------------- #
def collect_tables(client, tables, datasets, projects):
    result = [tuple(split_ref(t, 3)) for t in tables]
    ds_list = [tuple(split_ref(d, 2)) for d in datasets]
    for project in projects:
        try:
            ds_list += [(project, d.dataset_id) for d in client.list_datasets(project=project)]
        except Exception as e:  # noqa: BLE001
            log(f"[WARN] 列出 {project} 数据集失败: {e}")
    for project, dataset in ds_list:
        try:
            for t in client.list_tables(f"{project}.{dataset}"):
                if t.table_type in ("TABLE", "EXTERNAL"):
                    result.append((project, dataset, t.table_id))
        except Exception as e:  # noqa: BLE001
            log(f"[WARN] 列出 {project}.{dataset} 表失败: {e}")
    return list(dict.fromkeys(result))


# --------------------------------------------------------------------------- #
# RLS 读取
# --------------------------------------------------------------------------- #
def list_policies(bqapi, project, dataset, table, with_grantees=True):
    """返回 [{"id", "filter", "grantees": [..]}]"""
    raw = []
    req = bqapi.rowAccessPolicies().list(projectId=project, datasetId=dataset, tableId=table)
    while req is not None:
        resp = req.execute()
        raw.extend(resp.get("rowAccessPolicies", []))
        req = bqapi.rowAccessPolicies().list_next(req, resp)

    result = []
    for p in raw:
        pid = p["rowAccessPolicyReference"]["policyId"]
        grantees = []
        if with_grantees:
            resource = (f"projects/{project}/datasets/{dataset}/tables/{table}"
                        f"/rowAccessPolicies/{pid}")
            iam = bqapi.rowAccessPolicies().getIamPolicy(resource=resource, body={}).execute()
            for b in iam.get("bindings", []):
                if b.get("role") == RLS_ROLE:
                    grantees.extend(b.get("members", []))
        result.append({"id": pid, "filter": p.get("filterPredicate", "TRUE"),
                       "grantees": grantees})
    return result


# --------------------------------------------------------------------------- #
# 回退操作
# --------------------------------------------------------------------------- #
def run_ddl(client, ddl, location, apply):
    log(f"    DDL: {ddl}")
    if apply:
        client.query(ddl, location=location).result()
        log("    -> 完成")


def drop_all(client, full, location, apply):
    run_ddl(client, f"DROP ALL ROW ACCESS POLICIES ON {full}", location, apply)
    log("  [NOTE] 回退后该表已没有任何 RLS，所有有表读权限的用户可见全部行")


def rollback_table(client, bqapi, fq, location, members, strip_only, apply):
    """
    members 为空集合 -> 删除表上所有 RLS
    否则             -> 删除（或剥离）与 members 相关的 RLS
    返回处理的 policy 数
    """
    project, dataset, table = fq
    full = f"`{project}.{dataset}.{table}`"
    try:
        policies = list_policies(bqapi, project, dataset, table, with_grantees=True)
    except HttpError as e:
        log(f"[WARN] 读取 {project}.{dataset}.{table} 的 RLS 失败: {e}")
        return 0
    if not policies:
        return 0

    # ---- 未指定 group：删除全部 ----
    if not members:
        log(f"[TABLE] {project}.{dataset}.{table}  删除全部 {len(policies)} 条 RLS:")
        for p in policies:
            log(f"  [DROP] `{p['id']}` filter={p['filter']} grantees={p['grantees']}")
        drop_all(client, full, location, apply)
        return len(policies)

    # ---- 指定 group：只处理相关 policy ----
    to_drop, to_update = [], []
    for p in policies:
        normalized = {normalize_member(g) for g in p["grantees"]}
        if not normalized & members:
            continue
        others = [g for g in p["grantees"] if normalize_member(g) not in members]
        if strip_only and others:
            to_update.append((p, others))
        else:
            to_drop.append(p)
    if not to_drop and not to_update:
        return 0

    log(f"[TABLE] {project}.{dataset}.{table}  (共 {len(policies)} 条 RLS，"
        f"删除 {len(to_drop)} 条，剥离 {len(to_update)} 条)")

    for p, others in to_update:
        log(f"  [STRIP] `{p['id']}` 去掉 {sorted(set(p['grantees']) - set(others))}，保留 {others}")
        grant = ", ".join(f'"{g}"' for g in others)
        run_ddl(client,
                f"CREATE OR REPLACE ROW ACCESS POLICY `{p['id']}` ON {full} "
                f"GRANT TO ({grant}) FILTER USING ({p['filter']})",
                location, apply)

    for p in to_drop:
        log(f"  [DROP] `{p['id']}` filter={p['filter']} grantees={p['grantees']}")

    if len(to_drop) == len(policies):
        # 表上所有 policy 都要删 -> 一条 DROP ALL 即可（也规避"不能删最后一条"的限制）
        drop_all(client, full, location, apply)
    else:
        # 还会剩下其他 policy，逐条删除是安全的
        for p in to_drop:
            run_ddl(client, f"DROP ROW ACCESS POLICY `{p['id']}` ON {full}", location, apply)

    return len(to_drop) + len(to_update)


def revoke_table_viewer(client, fq, members, apply):
    table_id = ".".join(fq)
    policy = client.get_iam_policy(table_id)
    removed = set()
    for b in policy.bindings:
        if b["role"] == VIEWER_ROLE:
            hit = {m for m in b["members"] if normalize_member(m) in members}
            if hit:
                b["members"] = set(b["members"]) - hit
                removed |= hit
    if not removed:
        return
    log(f"  [IAM] 移除 {sorted(removed)} 在 {table_id} 上的 {VIEWER_ROLE}")
    if apply:
        policy.bindings = [b for b in policy.bindings if b["members"]]
        client.set_iam_policy(table_id, policy)
        log("    -> 完成")


def delete_groups(creds, members, apply):
    ci = discovery.build("cloudidentity", "v1", credentials=creds, cache_discovery=False)
    for m in sorted(members):
        if not m.startswith("group:"):
            continue
        email = m.split(":", 1)[1]
        try:
            name = ci.groups().lookup(groupKey_id=email).execute()["name"]
        except HttpError as e:
            if e.resp.status in (403, 404):
                log(f"[GROUP] {email} 不存在或无权限查看，跳过")
                continue
            raise
        log(f"[GROUP] 删除 {email} ({name})")
        if apply:
            ci.groups().delete(name=name).execute()
            log("  -> 完成")


# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="删除表上与指定 group 相关的 RLS；不指定 group 时删除表上所有 RLS")
    # 输入 1：group 列表（可选）
    p.add_argument("--groups", nargs="*", default=[],
                   help="group 邮箱列表（也可写 user:/serviceAccount: 等带前缀的主体）")
    p.add_argument("--groups-file", default=None, help="每行一个 group 的文件")
    # 输入 2：表列表
    p.add_argument("--tables", nargs="*", default=[], help="project.dataset.table 列表")
    p.add_argument("--tables-file", default=None, help="每行一个 project.dataset.table 的文件")
    p.add_argument("--datasets", nargs="*", default=[], help="project.dataset 列表（扫描其中所有表）")
    p.add_argument("--projects", nargs="*", default=[], help="项目列表（扫描其中所有表）")
    # 其他
    p.add_argument("--quota-project", default=None,
                   help="计费/运行 DDL 的项目（默认取第一个表/数据集/项目所在项目）")
    p.add_argument("--gcloud-account", default=None, help="使用指定 gcloud 账号的 token，而不是 ADC")
    p.add_argument("--strip-only", action="store_true",
                   help="policy 同时授予了其他主体时，只去掉指定 group 而不删除整条 policy")
    p.add_argument("--revoke-table-viewer", action="store_true",
                   help="同时移除这些 group 在表上的 roles/bigquery.dataViewer（需指定 group）")
    p.add_argument("--delete-group", action="store_true", help="最后删除这些 group（需指定 group）")
    p.add_argument("--apply", action="store_true", help="真正执行；默认 dry-run")
    args = p.parse_args()

    groups = split_items(args.groups) + (read_list_file(args.groups_file) if args.groups_file else [])
    members = {normalize_member(g) for g in groups}
    tables = split_items(args.tables) + (read_list_file(args.tables_file) if args.tables_file else [])
    args.datasets = split_items(args.datasets)
    args.projects = split_items(args.projects)

    if not (tables or args.datasets or args.projects):
        p.error("至少指定 --tables / --tables-file / --datasets / --projects 之一")
    if not members and (args.revoke_table_viewer or args.delete_group or args.strip_only):
        p.error("--revoke-table-viewer / --delete-group / --strip-only 需要同时指定 group 列表")

    quota = args.quota_project or (tables + args.datasets + args.projects)[0] \
        .replace(":", ".").split(".")[0]
    mode = "APPLY" if args.apply else "DRY-RUN"
    log(f"===== 模式: {mode} =====")
    if members:
        log(f"[SCOPE] 删除与以下主体相关的 RLS: {sorted(members)}")
    else:
        log("[SCOPE] 未指定 group —— 将删除目标表上的【所有】RLS")

    creds = get_credentials(args.gcloud_account, quota)
    client = bigquery.Client(project=quota, credentials=creds)
    bqapi = discovery.build("bigquery", "v2", credentials=creds, cache_discovery=False)

    table_list = collect_tables(client, tables, args.datasets, args.projects)
    log(f"[SCAN] 共 {len(table_list)} 张表待检查")

    loc_cache = {}
    total, touched = 0, 0
    for fq in table_list:
        ds_key = f"{fq[0]}.{fq[1]}"
        if ds_key not in loc_cache:
            try:
                loc_cache[ds_key] = client.get_dataset(ds_key).location
            except Exception as e:  # noqa: BLE001
                log(f"[WARN] 读取数据集 {ds_key} 失败: {e}")
                loc_cache[ds_key] = None
        if loc_cache[ds_key] is None:
            continue
        try:
            n = rollback_table(client, bqapi, fq, loc_cache[ds_key], members,
                               args.strip_only, args.apply)
        except Exception as e:  # noqa: BLE001
            log(f"  [ERROR] 处理 {'.'.join(fq)} 失败: {e}")
            continue
        if n:
            total += n
            touched += 1
        if args.revoke_table_viewer:
            try:
                revoke_table_viewer(client, fq, members, args.apply)
            except Exception as e:  # noqa: BLE001
                log(f"  [WARN] 处理 {'.'.join(fq)} 表级 IAM 失败: {e}")

    if args.delete_group:
        delete_groups(creds, members, args.apply)

    log(f"===== 完成 ({mode})：{touched} 张表，共处理 {total} 条 RLS =====")


if __name__ == "__main__":
    main()
