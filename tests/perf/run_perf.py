#!/usr/bin/env python3
"""
真实环境性能测试（Argolis），规格：
  1000 张业务表：500 张有 region / prd_type / refername 三列，300 张只有两列，100 张只有一列，100 张一列都没有
  1 张映射表：三列的表 3 行、两列 2 行、一列 1 行、没有的 0 行（共 2200 行）
  1 张条件表：新增账号各一行（不含存量账号）
  500 个新增 SA（全部加入 Copilot Group）+ 100 个存量 SA（分属 ReadOnly / Writable 两个 Group）
  Copilot 规则为 Group 级别：每张有维度的表 1 条（2026-10-18 起），与账号数无关

GCP 限制（不是脚本的限制）:
  - 每个项目最多 100 个 SA → 账号分布在主项目 + 6 个 SA 池项目（--pool-projects）

  RLS_IT=1 RLS_IT_PROJECT=... RLS_IT_ACCOUNT=... RLS_IT_DOMAIN=... \\
  python tests/perf/run_perf.py --parallel 32
资源默认保留（SA / Group / 数据集复用）。
"""

import argparse
import csv
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from google.cloud import bigquery  # noqa: E402
from googleapiclient.errors import HttpError  # noqa: E402

import rls_core as core  # noqa: E402
from tests.integration import conftest as C  # noqa: E402
from tests.integration import itlib as L  # noqa: E402

DS, AUTH_DS, PFX = "rls_perf", "rls_perf_auth", "rlsperf"
G_R, G_W = L.grp("perf-read"), L.grp("perf-write")
G_COP = L.grp("perf-copilot")                       # Copilot Group：全部新增账号
T_COND = f"{L.PROJECT}.{AUTH_DS}.adm_user_mem_copilot_condition"
T_MAP = f"{L.PROJECT}.{AUTH_DS}.adm_user_mem_copilot_tb_col_mapping"
T_REG = f"{L.PROJECT}.{AUTH_DS}.adm_user_mem_copilot_tb"      # apply_bypass_rls.py 的登记表
ALL_DIMS = (("region", "region"), ("prd_type", "prdtype"), ("refername", "refername"))
VALUES = ", ".join(f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)"
                   for r, p, f, a in L.ROWS)


def tbl(i):
    return f"{L.PROJECT}.{DS}.t{i:04d}"


def table_dims(i, n):
    frac = i / n
    return ALL_DIMS[:3 if frac < 0.5 else 2 if frac < 0.8 else 1 if frac < 0.9 else 0]


def log(msg):
    print(f"[perf] {msg}", file=sys.stderr, flush=True)


def pmap(fn, items, workers=16):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))


# --------------------------------------------------------------------------- #
# 账号：主项目 + SA 池项目
# --------------------------------------------------------------------------- #
def assign_projects(n_new, n_existing, pools, main_cap=100):
    """返回 (new_emails, existing_emails)：先填主项目剩余容量，再依次填池项目（每个 ≤ 100）。"""
    iam = L.api("iam", "v1")
    used = len(iam.projects().serviceAccounts().list(name=f"projects/{L.PROJECT}", pageSize=100).execute().get("accounts", []))
    want = [("ex", i) for i in range(n_existing)] + [("cp", i) for i in range(n_new)]
    slots = []
    # 主项目：已有的 rlsperf-* 继续用，剩余容量再放新的
    existing_main = {a["email"] for a in iam.projects().serviceAccounts().list(
        name=f"projects/{L.PROJECT}", pageSize=100).execute().get("accounts", [])}
    for kind, i in want:
        email = f"{PFX}-{kind}-{i:03d}@{L.PROJECT}.iam.gserviceaccount.com"
        if email in existing_main:
            slots.append((kind, i, L.PROJECT))
    remaining = [(k, i) for k, i in want if (k, i, L.PROJECT) not in slots]
    free_main = max(0, main_cap - used)
    for k, i in remaining[:free_main]:
        slots.append((k, i, L.PROJECT))
    remaining = remaining[free_main:]
    for pool in pools:
        for k, i in remaining[:100]:
            slots.append((k, i, pool))
        remaining = remaining[100:]
    assert not remaining, f"SA 池容量不足，还差 {len(remaining)} 个（请增加 --pool-projects）"
    new = sorted(f"{PFX}-{k}-{i:03d}@{p}.iam.gserviceaccount.com" for k, i, p in slots if k == "cp")
    existing = sorted(f"{PFX}-{k}-{i:03d}@{p}.iam.gserviceaccount.com" for k, i, p in slots if k == "ex")
    return new, existing


def ensure_sa(email):
    account_id, project = email.split("@")[0], email.split("@")[1].split(".")[0]
    iam = L.api("iam", "v1")
    try:                                            # 先查是否已存在：create 的配额检查在 409 之前，配额用尽时已存在的也返回 429
        iam.projects().serviceAccounts().get(name=f"projects/{project}/serviceAccounts/{email}").execute()
        return 0
    except HttpError as e:
        if e.resp.status != 404:
            raise
    for attempt in range(20):
        try:
            iam.projects().serviceAccounts().create(
                name=f"projects/{project}",
                body={"accountId": account_id, "serviceAccount": {"displayName": account_id}}).execute()
            return 1
        except HttpError as e:
            if e.resp.status == 409:
                return 0
            if e.resp.status in (429, 503) and attempt < 19:      # 「每分钟每项目创建 SA 数」配额：等满一分钟再试
                time.sleep(20 + 10 * attempt)
                continue
            raise
        except (TimeoutError, OSError):
            time.sleep(10)
    raise RuntimeError(f"创建 SA {email} 多次失败")


def project_bindings(role, members):
    crm = L.api("cloudresourcemanager", "v1").projects()

    def op():
        pol = crm.getIamPolicy(resource=L.PROJECT, body={}).execute()
        b = next((b for b in pol.setdefault("bindings", []) if b["role"] == role), None)
        if b is None:
            b = {"role": role, "members": []}
            pol["bindings"].append(b)
        missing = [m for m in members if m not in b["members"]]
        if missing:
            b["members"] += missing
            crm.setIamPolicy(resource=L.PROJECT, body={"policy": pol}).execute()
    L.eventually(op, timeout=300, interval=10, desc=f"project {role}")


# --------------------------------------------------------------------------- #
# 表
# --------------------------------------------------------------------------- #
def create_tables(n, workers):
    client = L.bq()
    for ds_id in (DS, AUTH_DS):
        ds = bigquery.Dataset(f"{L.PROJECT}.{ds_id}")
        ds.location = L.LOCATION
        client.create_dataset(ds, exists_ok=True)
    t0 = time.time()

    def mk(i):
        cols = [c for c, _ in table_dims(i, n)]
        select = ", ".join(cols + ["amount"]) if cols else "amount"
        # 一列都没有的表仍保留 amount 和一个无关列
        if not cols:
            select = "amount, CONCAT('x', CAST(amount AS STRING)) AS note"
        L.bq().query(f"CREATE OR REPLACE TABLE `{tbl(i)}` AS SELECT {select} FROM UNNEST([{VALUES}])",
                     location=L.LOCATION).result()
    pmap(mk, range(n), workers=workers)
    log(f"业务表 {n} 张重建完成（{time.time() - t0:.0f}s）")


def create_auth_tables(n_tables, new):
    q = lambda sql: L.bq().query(sql, location=L.LOCATION).result()  # noqa: E731
    q(f"CREATE OR REPLACE TABLE `{T_COND}` (id STRING, sa STRING, region ARRAY<STRING>, prdtype ARRAY<STRING>, "
      f"refername ARRAY<STRING>, status INT64) CLUSTER BY sa")
    regions = ["HK", "SG", "US"]
    for start in range(0, len(new), 200):
        rows = ", ".join(f"('c{i}', '{e}', ['{regions[i % 3]}'], [], [], 1)" for i, e in enumerate(new[start:start + 200], start))
        q(f"INSERT INTO `{T_COND}` (id, sa, region, prdtype, refername, status) VALUES {rows}")
    maps = [f"STRUCT('{tbl(i)}' AS table_name, '{c}' AS col_name, '{d}' AS to_name)"
            for i in range(n_tables) for c, d in table_dims(i, n_tables)]
    q(f"CREATE OR REPLACE TABLE `{T_MAP}` AS SELECT * FROM UNNEST([{', '.join(maps)}])")
    q(f"CREATE OR REPLACE TABLE `{T_REG}` (id STRING NOT NULL, table_name STRING NOT NULL, rls_enabled INT64 NOT NULL, "
      f"status INT64 NOT NULL, create_time TIMESTAMP NOT NULL, update_time TIMESTAMP NOT NULL)")
    q(f"INSERT INTO `{T_REG}` (id, table_name, rls_enabled, status, create_time, update_time) "
      f"SELECT GENERATE_UUID(), FORMAT('{L.PROJECT}.{DS}.t%04d', i), 1, 1, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP() "
      f"FROM UNNEST(GENERATE_ARRAY(0, {n_tables - 1})) AS i")
    log(f"条件表 {len(new)} 行；映射表 {len(maps)} 行；登记表 {n_tables} 行（全部 rls_enabled=1）")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tables", type=int, default=1000)
    ap.add_argument("--new", type=int, default=500)
    ap.add_argument("--existing", type=int, default=100)
    ap.add_argument("--pool-projects", default=",".join(f"rls-sapool-harrishe-{i}" for i in range(1, 7)))
    ap.add_argument("--parallel", type=int, default=32)
    ap.add_argument("--report", default="perf_report.md")
    a = ap.parse_args()
    assert L.ENABLED and L.PROJECT and L.ACCOUNT and L.DOMAIN, "需要 RLS_IT=1 RLS_IT_PROJECT RLS_IT_ACCOUNT RLS_IT_DOMAIN"
    pools = [p for p in a.pool_projects.split(",") if p]
    timings = []

    def step(name, fn, note=""):
        t0 = time.time()
        out = fn()
        secs = time.time() - t0
        timings.append((name, secs, note() if callable(note) else note))
        log(f"{name}: {secs:.0f}s")
        return out

    # ---- 准备 ----
    log("准备环境 ...")
    new, existing = assign_projects(a.new, a.existing, pools)
    t0 = time.time()
    # SA 创建配额按「每项目每分钟」计：把不同项目的账号交错排列，让各项目同时推进
    by_proj = {}
    for e in new + existing:
        by_proj.setdefault(e.split("@")[1], []).append(e)
    interleaved = [e for grp in zip(*[lst + [None] * (max(map(len, by_proj.values())) - len(lst))
                                      for lst in by_proj.values()]) for e in grp if e]
    created = sum(pmap(ensure_sa, interleaved, workers=2 * len(by_proj)))
    log(f"账号 {len(new)} 新增 + {len(existing)} 存量（新建 {created}，{time.time() - t0:.0f}s）；"
        f"分布: " + ", ".join(f"{p}:{sum(1 for e in new + existing if f'@{p}.' in e)}" for p in [L.PROJECT] + pools))
    customer = L.customer_id()
    for g in (G_R, G_W, G_COP):
        L.ensure_group(g, customer)
    pmap(lambda e: L.set_group_member(G_COP, e), new, workers=4)
    half = len(existing) // 2
    pmap(lambda e: L.set_group_member(G_R, e), existing[:half], workers=4)
    pmap(lambda e: L.set_group_member(G_W, e), existing[half:], workers=4)
    probe_cp = next(e for e in new if f"@{L.PROJECT}." in e)             # 主项目里的一个新增账号，用于查询验证
    probe_ex = next(e for e in existing if f"@{L.PROJECT}." in e)
    project_bindings("roles/bigquery.jobUser", [f"serviceAccount:{probe_cp}", f"serviceAccount:{probe_ex}"])
    admin = f"user:{L.ACCOUNT}"
    for e in (probe_cp, probe_ex):
        C._sa_binding(e, "roles/iam.serviceAccountTokenCreator", admin)
    step("准备: 重建 1000 张表", lambda: create_tables(a.tables, 16))
    create_auth_tables(a.tables, new)
    C._dataset_access(DS, [("READER", "groupByEmail", G_R), ("WRITER", "groupByEmail", G_W), ("READER", "userByEmail", probe_cp)])
    C._dataset_access(AUTH_DS, [("READER", "userByEmail", probe_cp)])
    L.eventually(lambda: L.amounts(probe_ex, tbl(1)), desc="existing ready")
    L.eventually(lambda: L.amounts(probe_cp, tbl(1)), desc="copilot ready")

    # ---- 运行 ----
    par = ["--parallel", str(a.parallel)]
    auth = ["--condition-table", T_COND, "--mapping-table", T_MAP, "--registry-table", T_REG, "--group", G_COP]
    tmp = "/tmp/rls_perf"
    os.makedirs(tmp, exist_ok=True)
    byp = ["--registry-table", T_REG]                          # 第 4 步：只看登记表（全部业务表都登记为 rls_enabled = 1）
    n_dim_tables = sum(1 for i in range(a.tables) if table_dims(i, a.tables))
    last = {}

    def cli(script, *args, allow=(0,)):
        code, out = L.run_cli(script, *args, timeout=6 * 3600)
        last["out"] = out
        assert code in allow, f"{script} 退出码 {code}\n{out[-3000:]}"
        return code

    def summary():
        o = last.get("out", "")
        return o.strip().rsplit("=====", 2)[-2].strip() if "=====" in o else ""

    step("1 list_principals (项目范围)", lambda: cli("list_principals.py", "--projects", L.PROJECT, "-o", f"{tmp}/p.csv", *par),
         note=lambda: f"输出 {sum(1 for _ in csv.DictReader(open(f'{tmp}/p.csv', encoding='utf-8-sig')))} 个主体")
    step("4 apply_bypass (ReadOnly 组)", lambda: cli(
        "apply_bypass_rls.py", "--group", G_R, *byp, "--apply", *par),
        note=summary)
    step("4 apply_bypass (Writable 组)", lambda: cli(
        "apply_bypass_rls.py", "--group", G_W, *byp, "--apply", *par), note=summary)
    step("4 apply_bypass 重跑 (全部 NOOP)", lambda: cli(
        "apply_bypass_rls.py", "--group", G_W, *byp, "--apply", *par), note=summary)
    step("8 apply_copilot 演练", lambda: cli("apply_copilot_rls.py", *auth, "-o", f"{tmp}/c0.csv", *par), note=summary)
    step("8 apply_copilot 执行（每表一条 Group 规则）", lambda: cli("apply_copilot_rls.py", *auth, "-o", f"{tmp}/c1.csv", "--apply", *par),
         note=lambda: summary() + f"；审核 CSV {sum(1 for _ in csv.DictReader(open(f'{tmp}/c1.csv', encoding='utf-8-sig')))} 行")
    step("8 apply_copilot 重跑（全部 NOOP）", lambda: cli("apply_copilot_rls.py", *auth, "-o", f"{tmp}/c2.csv", "--apply", *par),
         note=summary)
    step("验证: 新增账号在三列表上只见 HK", lambda: L.expect_amounts(probe_cp, tbl(1), L.HK, timeout=900))
    step("验证: 新增账号在无维度列的表上 0 行", lambda: L.expect_amounts(probe_cp, tbl(a.tables - 1), []))
    step("验证: 存量账号可见全部", lambda: L.expect_amounts(probe_ex, tbl(1), L.ALL_AMOUNTS))
    step("9 rollback Copilot Group 规则（按主体，读取授权对象）", lambda: cli(
        "rollback_rls.py", "--datasets", f"{L.PROJECT}.{DS}", "--principals", G_COP, "--apply", *par), note=summary)
    step("9 rollback 全部（带授权对象日志）", lambda: cli(
        "rollback_rls.py", "--datasets", f"{L.PROJECT}.{DS}", "--apply", *par), note=summary)

    # ---- 报告 ----
    lines = [f"# 真实环境性能测试（{time.strftime('%Y-%m-%d %H:%M')} UTC）", "",
             f"项目 `{L.PROJECT}`（账号分布在主项目 + {len(pools)} 个 SA 池项目）；{a.tables} 张业务表（三列 {a.tables // 2}、两列 "
             f"{int(a.tables * 0.3)}、一列 {a.tables // 10}、无 {a.tables // 10}），映射表 {a.tables // 2 * 3 + int(a.tables * 0.3) * 2 + a.tables // 10} 行，"
             f"条件表 {a.new} 行（仅新增账号），{a.existing} 个存量账号（2 个白名单 Group），`--parallel {a.parallel}`。",
             f"需要 Copilot 规则的表 {n_dim_tables} 张；每张表 2 条 bypass + 1 条 Copilot Group 规则（{a.new} 个账号都在 Group 里）。", "",
             "| 步骤 | 耗时 | 结果 |", "|---|---|---|"]
    for name, secs, note in timings:
        lines.append(f"| {name} | {secs:.0f}s（{secs / 60:.1f} 分） | {note} |")
    report = "\n".join(lines)
    with open(a.report, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)


if __name__ == "__main__":
    main()
