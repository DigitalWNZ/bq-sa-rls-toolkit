"""
真实环境稳定性测试（模拟非正常操作）：
  r10 apply_copilot 运行中进程被强制杀死（kill -9）→ 重跑收敛、再跑全部 NOOP
  r11 rollback 运行中按 Ctrl-C（SIGINT）→ 很快退出（退出码 130、无堆栈、不再处理剩下的表）→ 重跑完成
  r12 两个 apply_copilot 同时运行 → 都成功、每张表恰好一条 Copilot 规则
  r13 apply_bypass 与 apply_copilot 同时运行 → 都成功、互不覆盖
依赖 world fixture，在 test_z_abnormal.py 之后运行（文件名排序）；使用 20 张独立的表 stab_tNN，用完自行清理。
"""

import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.integration import itlib as L
from tests.integration.test_e2e import BYP_R, COP_G

pytestmark = pytest.mark.integration

N = 20
TABLES = [L.tbl(f"stab_t{i:02d}") for i in range(N)]
MAP = L.tbl("stab_mapping", L.AUTH_DATASET)


def q(sql):
    return L.run_sql(sql)


def copilot_args(out, *extra):
    return ["--condition-table", L.T_COND, "--mapping-table", MAP, "--registry-table", L.T_REGISTRY,
            "--group", L.G_COPILOT, "-o", str(out), *extra]


def popen(script, *args):
    cmd = [sys.executable, os.path.join(L.ROOT, script), "--gcloud-account", L.ACCOUNT, "--quota-project", L.PROJECT, *args]
    print("\n$ " + " ".join(cmd), file=sys.stderr)
    return subprocess.Popen(cmd, cwd=L.ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def all_policies():
    with ThreadPoolExecutor(max_workers=10) as ex:
        return dict(zip(TABLES, ex.map(L.policies, TABLES)))


def policy_ids(table):
    """只列规则名（不读授权对象）：脚本运行中规则随时可能被删，避免「列出后再读 IAM」时的 404 竞争。"""
    p, d, t = table.split(".")
    resp = L.api("bigquery", "v2").rowAccessPolicies().list(projectId=p, datasetId=d, tableId=t).execute()
    return {it["rowAccessPolicyReference"]["policyId"] for it in resp.get("rowAccessPolicies", [])}


def n_with(name):
    with ThreadPoolExecutor(max_workers=10) as ex:
        return sum(1 for ids in ex.map(policy_ids, TABLES) if name in ids)


def wait_until(cond, timeout=600, interval=2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(interval)
    return False


def assert_copilot_converged():
    pols = all_policies()
    bad = {t: sorted(p) for t, p in pols.items()
           if COP_G not in p or p[COP_G]["grantees"] != {f"group:{L.G_COPILOT}"}
           or sum(1 for k in p if k.startswith("rls_copilot_")) != 1}
    assert not bad, bad


def rollback_copilot():
    code, log = L.run_cli("rollback_rls.py", "--tables", ",".join(TABLES), "--principals", L.G_COPILOT, "--apply")
    assert code == 0, log
    assert n_with(COP_G) == 0


@pytest.fixture(scope="module")
def stab(world):
    values = ", ".join(f"STRUCT('{r}' AS region, '{p}' AS prd_type, '{f}' AS refername, {a} AS amount)" for r, p, f, a in L.ROWS)
    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda t: q(f"CREATE OR REPLACE TABLE `{t}` AS SELECT * FROM UNNEST([{values}])"), TABLES))
    maps = ", ".join(f"STRUCT('{t}' AS table_name, 'region' AS col_name, 'region' AS to_name)" for t in TABLES)
    q(f"CREATE OR REPLACE TABLE `{MAP}` AS SELECT * FROM UNNEST([{maps}])")
    reg = ", ".join(f"(GENERATE_UUID(), '{t}', 1, 1, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())" for t in TABLES)
    q(f"INSERT INTO `{L.T_REGISTRY}` (id, table_name, rls_enabled, status, create_time, update_time) VALUES {reg}")
    yield
    q(f"DELETE FROM `{L.T_REGISTRY}` WHERE STARTS_WITH(table_name, '{L.PROJECT}.{L.DATASET}.stab_t')")
    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda t: q(f"DROP TABLE IF EXISTS `{t}`"), TABLES + [MAP]))


def test_r10_sigkill_mid_copilot_then_rerun_converges(stab, tmp_path):
    p = popen("apply_copilot_rls.py", *copilot_args(tmp_path / "k.csv", "--apply", "--parallel", "1"))
    started = wait_until(lambda: n_with(COP_G) >= 2 or p.poll() is not None, timeout=600)
    p.kill()                                                              # kill -9：不给脚本任何清理机会
    out = p.communicate(timeout=60)[0]
    done = n_with(COP_G)
    assert started and 0 < done < N, (done, out[-2000:])                  # 确实中途被杀
    code, log = L.run_cli("apply_copilot_rls.py", *copilot_args(tmp_path / "r.csv", "--apply"))
    assert code == 0 and "Traceback" not in log, log
    assert f"NOOP {done}" in log or "NOOP" in log, log                     # 被杀之前建好的规则不重建
    assert_copilot_converged()
    code, log = L.run_cli("apply_copilot_rls.py", *copilot_args(tmp_path / "r2.csv", "--apply"))
    assert code == 0 and f"NOOP {N}" in log, log                           # 再跑全部 NOOP


def test_r11_ctrl_c_mid_rollback_stops_promptly_then_rerun(stab, tmp_path):
    assert n_with(COP_G) == N
    p = popen("rollback_rls.py", "--tables", ",".join(TABLES), "--principals", L.G_COPILOT, "--apply", "--parallel", "2")
    started = wait_until(lambda: n_with(COP_G) <= N - 2 or p.poll() is not None, timeout=600)
    t0 = time.time()
    p.send_signal(signal.SIGINT)                                          # 相当于用户按 Ctrl-C
    out = p.communicate(timeout=300)[0]
    stopped_in = time.time() - t0
    left = n_with(COP_G)
    assert started and p.returncode == 130, (p.returncode, out[-2000:])
    assert "已被用户中断" in out and "Traceback" not in out, out[-2000:]
    assert left > 0 and stopped_in < 120, (left, stopped_in)              # 没有把剩下的表跑完
    code, log = L.run_cli("rollback_rls.py", "--tables", ",".join(TABLES), "--principals", L.G_COPILOT, "--apply")
    assert code == 0, log
    assert n_with(COP_G) == 0


def test_r12_two_copilot_runs_at_once(stab, tmp_path):
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(L.run_cli, "apply_copilot_rls.py", *copilot_args(tmp_path / f"{i}.csv", "--apply", "--parallel", "8"))
                for i in range(2)]
        res = [f.result() for f in futs]
    assert [c for c, _ in res] == [0, 0], [log[-3000:] for _, log in res]
    assert_copilot_converged()
    rollback_copilot()


def test_r13_bypass_and_copilot_at_once(stab, tmp_path):
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(L.run_cli, "apply_bypass_rls.py", "--registry-table", L.T_REGISTRY, "--group", L.G_READ,
                       "--tables", ",".join(TABLES), "--apply", "--parallel", "8")
        f2 = ex.submit(L.run_cli, "apply_copilot_rls.py", *copilot_args(tmp_path / "c.csv", "--apply", "--parallel", "8"))
        (c1, l1), (c2, l2) = f1.result(), f2.result()
    assert (c1, c2) == (0, 0), (l1[-3000:], l2[-3000:])
    assert_copilot_converged()
    pols = all_policies()
    assert all(BYP_R in p and p[BYP_R]["grantees"] == {f"group:{L.G_READ}"} for p in pols.values()), pols
