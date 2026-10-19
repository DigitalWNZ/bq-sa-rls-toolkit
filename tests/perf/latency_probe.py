#!/usr/bin/env python3
"""测量真实环境单次 API 调用延迟（各 N 次取中位数），供 simulate.py 的估算使用。"""

import os
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import gcp_ops as ops  # noqa: E402
import rls_core as core  # noqa: E402
from gcp_auth import get_credentials  # noqa: E402
from tests.integration import itlib as L  # noqa: E402


def med(fn, n=8):
    xs = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append(time.perf_counter() - t0)
    return statistics.median(xs)


def main():
    table = sys.argv[1] if len(sys.argv) > 1 else f"{L.PROJECT}.rls_perf.t0001"
    ctx = ops.Ctx(get_credentials(L.ACCOUNT, L.PROJECT), L.PROJECT)
    p, d, t = core.parse_table(table)
    pols = ops.list_policies(ctx, table, grantees_for=set())
    name = pols[0]["id"] if pols else None
    res = f"projects/{p}/datasets/{d}/tables/{t}/rowAccessPolicies/{name}"
    out = {}
    out["list_policies"] = med(lambda: ops.list_policies(ctx, table, grantees_for=set()))
    if name:
        out["policy_iam"] = med(lambda: ctx.bqapi.rowAccessPolicies().getIamPolicy(resource=res, body={}).execute())
    out["get_table"] = med(lambda: ctx.bq.get_table(table))
    out["list_tables"] = med(lambda: list(ctx.bq.list_tables(f"{p}.{d}")), n=3)
    out["query"] = med(lambda: ops.run_query(ctx, "SELECT 1", "US"), n=3)
    ddl = core.build_policy_ddl(table, "latency_probe", [f"user:{L.ACCOUNT}"], "FALSE")
    out["ddl"] = med(lambda: ops.run_ddl(ctx, ddl, "US"), n=5)
    out["datasets"] = med(lambda: ops.project_datasets(ctx, L.PROJECT), n=3)
    out["dataset_acl"] = med(lambda: ops.dataset_access(ctx, f"{p}.{d}"))
    out["table_iam"] = med(lambda: ops.table_iam_bindings(ctx, table))
    out["iam_policy"] = med(lambda: ops.resource_iam_bindings(ctx, f"projects/{L.PROJECT}"), n=3)
    out["sa_list"] = med(lambda: ops.project_service_accounts(ctx, L.PROJECT), n=3)
    out["role"] = med(lambda: ops.role_permissions(ctx, "roles/bigquery.dataViewer"), n=3)
    out["group"] = med(lambda: ops.group_members_typed(ctx, L.G_READ), n=3)
    print("REAL_LATENCY = {" + ", ".join(f'"{k}": {v:.3f}' for k, v in out.items()) + "}", flush=True)
    remaining = ops.list_policies(ctx, table, grantees_for=set())
    if len(remaining) <= 1:
        ops.run_ddl(ctx, core.drop_all_ddl(table), "US")          # 最后一条不能单独 DROP
    else:
        ops.run_ddl(ctx, core.drop_policy_ddl(table, "latency_probe"), "US")


if __name__ == "__main__":
    main()
