#!/usr/bin/env python3
"""
白名单候选（宽松版）：列出项目列表下的全部 Service Account，生成白名单候选清单。

与 scan_bq_access.py（按目标表扫描 IAM + 作业历史，较保守）互补：
  - scan_bq_access.py   只列出对目标表"有权限或真实访问过"的账号
  - list_project_sas.py 列出给定项目列表中"所有"SA，避免遗漏（例如权限来自 Folder/Org、
                        近期没跑过作业、或通过 View 间接访问的调度 SA）

处理逻辑:
  1. 对 --projects / --projects-file 中的每个项目，调用 IAM API 列出项目内全部 SA
     （含默认计算 SA、App Engine SA 等用户管理的 SA）
  2. 可选 --include-iam-bound：同时把各项目 IAM Policy 中出现的 serviceAccount 成员也列出
     （跨项目 SA、Google 托管服务代理等）
  3. 多个项目中重复出现的 SA 合并为一行，sources 记录来源（项目:project-sa / 项目:iam-binding）
  4. 排除：命中 --copilot-members / --copilot-patterns 的 Copilot SA；已禁用 SA（除非 --include-disabled）
  5. 其余 SA 的 suggested_group 统一设为 --group（write 或 read）

输出 CSV 与 scan_bq_access.py 列兼容（另含 display_name、disabled），可直接作为
whitelist_groups.py --scan-csv 的输入；也可以与 scan 结果一起审核。

示例:
  python list_project_sas.py --projects proj-a,proj-b,proj-c --group write \\
      --copilot-patterns 'copilot-*@*' --copilot-members copilot-api@p.iam.gserviceaccount.com -o all_sas.csv
  python list_project_sas.py --projects-file projects.txt --include-iam-bound -o all_sas.csv

退出码: 0 成功；1 部分项目读取失败（其余项目结果仍写入 CSV）
"""

import argparse
import csv
import sys

import gcp_ops as ops
import rls_core as core
from gcp_auth import get_credentials

COLUMNS = ["principal", "principal_type", "can_read", "can_write", "suggested_group", "sources",
           "jobs_read_count", "jobs_write_count", "copilot", "note", "display_name", "disabled"]


def main():
    p = argparse.ArgumentParser(description="列出项目列表下的全部 SA，生成白名单候选")
    p.add_argument("--projects", nargs="*", default=[], help="项目列表，空格或逗号分隔")
    p.add_argument("--projects-file", default=None, help="每行一个项目 ID")
    p.add_argument("--group", choices=["write", "read"], default="write",
                   help="SA 建议加入的白名单（默认 write）")
    p.add_argument("--include-iam-bound", action="store_true",
                   help="同时列出各项目 IAM Policy 中出现的 SA（跨项目 SA、服务代理）")
    p.add_argument("--include-disabled", action="store_true", help="已禁用的 SA 也建议加入")
    p.add_argument("--copilot-members", nargs="*", default=[])
    p.add_argument("--copilot-patterns", nargs="*", default=[])
    p.add_argument("-o", "--output", default="project_sas.csv")
    p.add_argument("--quota-project", default=None, help="默认第一个项目")
    p.add_argument("--gcloud-account", default=None)
    args = p.parse_args()

    projects = list(dict.fromkeys(
        core.split_items(args.projects) +
        (core.read_list_file(args.projects_file) if args.projects_file else [])))
    if not projects:
        p.error("请指定 --projects 或 --projects-file")
    quota = args.quota_project or projects[0]
    ctx = ops.Ctx(get_credentials(args.gcloud_account, quota), quota)

    sas, failed = [], False
    for project in projects:
        try:
            found = ops.list_sa_details(ctx, project)
            ops.log(f"[SA] {project}: 项目内 {len(found)} 个 SA")
            sas += [{**s, "project": project, "source": "project-sa"} for s in found]
        except Exception as e:  # noqa: BLE001
            failed = True
            ops.log(f"[ERROR] 列出 {project} 的 SA 失败: {e}")
            continue
        if args.include_iam_bound:
            try:
                bound = {core.member_email(m) for b in ops.project_policy(ctx, project).get("bindings", [])
                         for m in b.get("members", []) if m.startswith("serviceAccount:")}
                ops.log(f"[IAM] {project}: IAM 绑定中出现 {len(bound)} 个 SA")
                sas += [{"email": e, "project": project, "display_name": "", "disabled": False,
                         "source": "iam-binding"} for e in sorted(bound)]
            except Exception as e:  # noqa: BLE001
                failed = True
                ops.log(f"[ERROR] 读取 {project} IAM Policy 失败: {e}")

    rows = core.build_sa_whitelist_rows(
        sas, args.group, core.split_items(args.copilot_members),
        core.split_items(args.copilot_patterns), args.include_disabled)
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    for r in rows:
        print(f"{r['suggested_group'] or '-':5} {r['principal']}  [{r['sources']}] {r['note']}")
    n_in = sum(1 for r in rows if r["suggested_group"])
    n_cop = sum(1 for r in rows if r["copilot"])
    print(f"\n{len(projects)} 个项目，共 {len(rows)} 个 SA：建议加入 {args.group} 白名单 {n_in} 个，"
          f"排除 Copilot SA {n_cop} 个，其他排除 {len(rows) - n_in - n_cop} 个。"
          f"结果已写入 {args.output}（请客户审核后再加组）")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
