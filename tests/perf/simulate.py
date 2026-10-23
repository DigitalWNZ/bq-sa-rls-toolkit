#!/usr/bin/env python3
"""
性能模拟：在内存模拟的 GCP 上以指定规模运行 4 个脚本，输出脚本自身耗时和 API 调用次数。

  python tests/perf/simulate.py --tables 1000 --new 500 --existing 100
  python tests/perf/simulate.py --tables 50 --new 20 --existing 10 --latency   # 带模拟网络延迟，比较 --parallel 1 / 8

API 调用次数乘以真实环境测得的单次延迟（tests/perf/run_perf.py 的输出），即可估算真实耗时。
"""

import argparse
import contextlib
import io
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402  (借用 monkeypatch)

import apply_bypass_rls  # noqa: E402
import apply_copilot_rls  # noqa: E402
import list_principals  # noqa: E402
import rls_core as core  # noqa: E402
import rollback_rls  # noqa: E402
from tests.unit.fakes import REG, FakeWorld, install, fake_auth  # noqa: E402

P, DS = "perf-proj", "dw"
COND, MAP = f"{P}.auth.adm_user_mem_copilot_condition", f"{P}.auth.adm_user_mem_copilot_tb_col_mapping"
G_R, G_W = "group_existingsa_read@domain.com", "group_existingsa_write@domain.com"
G_COP = "group_copilot@domain.com"            # Copilot Group：每张表一条规则（2026-10-18 起）

# 真实环境单次调用延迟（秒）：来自 Argolis 实测（run_perf.py），用于估算
REAL_LATENCY = {"list_policies": 0.242, "policy_iam": 0.300, "get_table": 0.332, "list_tables": 5.644, "query": 0.973,
                "ddl": 1.331, "dataset_acl": 0.300, "group": 0.582,
                "table_iam": 0.300, "iam_policy": 0.300, "sa_list": 0.300, "datasets": 0.300, "role": 0.200,
                "crm": 0.300}   # 2026-10-18 Argolis 实测中位数（table_iam 等新增项为估计值，可用 latency_probe.py 实测）


ALL_DIMS = (("region", "region"), ("prd_type", "prdtype"), ("refername", "refername"))


def table_dims(i, n_tables):
    """表 i 含哪些维度列：按 50% / 30% / 10% / 10% 分为 三个都有 / 两个 / 一个 / 一个都没有。"""
    frac = i / n_tables
    k = 3 if frac < 0.5 else 2 if frac < 0.8 else 1 if frac < 0.9 else 0
    return ALL_DIMS[:k]


def build_world(n_tables, n_new, n_existing, latency=None):
    w = FakeWorld()
    if latency:
        w.latency = dict(latency)
    tables = [f"{P}.{DS}.t{i:04d}" for i in range(n_tables)]
    for i, t in enumerate(tables):
        schema = {c: ("STRING", "NULLABLE") for c, _ in table_dims(i, n_tables)}
        schema["amount"] = ("INT64", "NULLABLE")
        w.add_table(t, schema=schema)
    w.add_table(COND, rls_enabled=0)                       # 业务表都登记为 rls_enabled=1；条件表 / 映射表未开启
    w.add_table(MAP, rls_enabled=0)
    new = [f"copilot-{i:04d}@{P}.iam.gserviceaccount.com" if i % 2 else f"user{i:04d}@domain.com" for i in range(n_new)]
    existing = [f"etl-{i:04d}@{P}.iam.gserviceaccount.com" for i in range(n_existing)]
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"),
                                ("region", "STRING", "REPEATED"), ("prdtype", "STRING", "REPEATED"),
                                ("refername", "STRING", "REPEATED")]
    w.condition_sas[COND] = list(new)                      # 只有新增账号，不含存量账号
    w.mapping_rows[MAP] = [{"table_name": t, "col_name": c, "to_name": d}
                           for i, t in enumerate(tables) for c, d in table_dims(i, n_tables)]
    # list_principals 数据：项目自己的全部 SA（存量 + 新增）、项目 IAM 里 20 个 user、
    # 数据集 ACL 里两个含全部存量 SA 的 Group + 50 个新增账号；每张表的 IAM 策略为空
    w.project_sas[P] = existing + [x for x in new if x.endswith("gserviceaccount.com")]
    w.iam_policies[f"projects/{P}"] = [
        {"role": "roles/viewer", "members": [f"user:analyst{i:03d}@domain.com" for i in range(20)] + [f"group:{G_R}"]}]
    w.dataset_acl[f"{P}.{DS}"] = ([("READER", "groupByEmail", G_W), ("READER", "groupByEmail", G_R)]
                                 + [("READER", "userByEmail", e) for e in new[:50]])
    w.groups[G_R] = [(e, "SERVICE_ACCOUNT") for e in existing[: n_existing // 2]]
    w.groups[G_W] = [(e, "SERVICE_ACCOUNT") for e in existing[n_existing // 2:]]
    return w, tables, new, existing


def timed(fn):
    buf = io.StringIO()
    t0 = time.perf_counter()
    with contextlib.redirect_stderr(buf):
        code = fn()
    return code, time.perf_counter() - t0, buf.getvalue()


def run(n_tables, n_new, n_existing, parallel, latency=None):
    mp = pytest.MonkeyPatch()
    w, tables, new, existing = build_world(n_tables, n_new, n_existing, latency)
    install(mp, w)
    for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
        mp.setattr(mod, "resolve_auth", fake_auth)
    tmp = tempfile.mkdtemp()
    auth = ["--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG, "--group", G_COP]
    par = ["--parallel", str(parallel)]
    rows = []

    def step(name, fn, allow=(0,)):
        before = dict(w.calls)
        code, secs, log = timed(fn)
        delta = {k: w.calls[k] - before.get(k, 0) for k in w.calls if w.calls[k] - before.get(k, 0)}
        est = sum(REAL_LATENCY.get(k, 0) * v for k, v in delta.items())
        summary = log.strip().rsplit("=====", 2)[-2].strip() if "=====" in log else ""
        rows.append((name, code, secs, delta, est, summary))
        assert code in allow, f"{name} 退出码 {code}\n{log[-2000:]}"

    step("1 list_principals", lambda: list_principals.main(["--projects", P, "-o", f"{tmp}/p.csv", *par]))
    byp = ["--registry-table", REG]                         # 第 3 步：只看登记表
    step("3 apply_bypass (read 组)", lambda: apply_bypass_rls.main(
        ["--group", G_R, *byp, "--apply", *par]))
    step("3 apply_bypass (write 组)", lambda: apply_bypass_rls.main(
        ["--group", G_W, *byp, "--apply", *par]))
    step("7 apply_copilot 首次（每表一条 Group 规则）", lambda: apply_copilot_rls.main([*auth, "-o", f"{tmp}/c.csv", "--apply", *par]))
    step("7 apply_copilot 重跑(NOOP)", lambda: apply_copilot_rls.main([*auth, "-o", f"{tmp}/c.csv", "--apply", *par]))
    w.condition_sas[COND].append(f"late@{P}.iam.gserviceaccount.com")     # 新增账号：只写条件表（并加入 Group），规则不变
    step("7 apply_copilot 新增 1 账号后重跑(NOOP)", lambda: apply_copilot_rls.main([*auth, "-o", f"{tmp}/c.csv", "--apply", *par]))
    step("8 rollback Copilot Group 规则（按主体）", lambda: rollback_rls.main(
        ["--datasets", f"{P}.{DS}", "--principals", G_COP, "--apply", *par]))
    step("8 rollback 全部", lambda: rollback_rls.main(
        ["--datasets", f"{P}.{DS}", "--apply", *par]))
    mp.undo()
    return rows, 3                                                          # 每表：2 条 bypass + 1 条 Copilot


def fmt_calls(d):
    return ", ".join(f"{k} {v:,}" for k, v in sorted(d.items(), key=lambda kv: -kv[1]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tables", type=int, default=1000)
    ap.add_argument("--new", type=int, default=500)
    ap.add_argument("--existing", type=int, default=100)
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--latency", action="store_true", help="按 REAL_LATENCY 真正 sleep（只适合小规模）")
    a = ap.parse_args()
    lat = {k: v / 10 for k, v in REAL_LATENCY.items()} if a.latency else None     # 带延迟时按 1/10 缩放以便运行
    n3, n2, n1 = int(a.tables * 0.5), int(a.tables * 0.3), int(a.tables * 0.1)
    n0 = a.tables - n3 - n2 - n1
    print(f"规模：{a.tables} 张业务表（三个维度列都有 {n3}、两个 {n2}、一个 {n1}、一个都没有 {n0}）"
          f"；映射表 {n3 * 3 + n2 * 2 + n1} 行；条件表 {a.new} 行（仅新增账号）；{a.existing} 个存量账号；"
          f"--parallel {a.parallel}" + ("；模拟延迟 = 真实延迟 / 10" if a.latency else ""))
    rows, n_pol = run(a.tables, a.new, a.existing, a.parallel, lat)
    print(f"（Group 级别：每张有维度的表 1 条 Copilot 规则，与账号数无关；需要 Copilot 规则的表 {n3 + n2 + n1} 张）\n")
    print("| 步骤 | 退出码 | 脚本自身耗时 | API 调用次数 | 结果 | 按实测延迟估算的串行网络时间 |")
    print("|---|---|---|---|---|---|")
    for name, code, secs, calls, est, summary in rows:
        print(f"| {name} | {code} | {secs:.1f}s | {fmt_calls(calls)} | {summary} | {est / 3600:.1f} 小时 |")


if __name__ == "__main__":
    main()
