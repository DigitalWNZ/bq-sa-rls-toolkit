"""
稳定性测试（模拟多种非正常操作）：中断后重跑、部分失败后重跑、多个实例并发、运行中表被删除、
运行中条件表 / 登记表变化、暂时性错误、损坏的输入文件、超大规模、输出文件不可写、反复重跑。
目标：任何情况下不留下不一致的状态、不输出 Python 堆栈；重跑后收敛到正确结果。

运行：.venv/bin/python -m pytest tests/stability -v
"""

import threading
import time

import pytest

import apply_bypass_rls
import apply_copilot_rls
import gcp_ops as ops
import list_principals
import rls_core as core
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

P = "trip-prod"
TABLES = [f"{P}.dw.t{i:03d}" for i in range(40)]
COND = "trip-bq-admin.bq_auth.adm_user_mem_copilot_condition"
MAP = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping"
G = "group_existingsa_read@trip.com"
G_COP = "group_copilot@trip.com"
BYP, COP = core.bypass_policy_name(G), core.copilot_policy_name(G_COP)


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    for t in TABLES:
        w.add_table(t, schema={"region": ("STRING", "NULLABLE")})
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
    w.condition_sas[COND] = ["a@trip.com", "b@trip.com"]
    w.mapping_rows[MAP] = [{"table_name": t, "col_name": "region", "to_name": "region"} for t in TABLES]
    w.project_sas[P] = ["a@trip-prod.iam.gserviceaccount.com"]
    install(monkeypatch, w)
    for mod in (apply_bypass_rls, apply_copilot_rls, rollback_rls, list_principals):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def bypass(*args):
    return apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--datasets", f"{P}.dw", *args])


def copilot(tmp_path, *args, name="c.csv"):
    return apply_copilot_rls.main(["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP,
                                   "--registry-table", REG, "-o", str(tmp_path / name), *args])


def copilot_rules(world):
    return {t: [p for p in world.policies(t) if p["id"] == COP] for t in TABLES if t in world.tables}


def assert_converged(world):
    rules = copilot_rules(world)
    assert all(len(v) == 1 and v[0]["grantees"] == [f"group:{G_COP}"] for v in rules.values()), \
        {t: v for t, v in rules.items() if len(v) != 1}


class _Interrupt:
    """在第 n 次 DDL 时抛出指定异常（模拟 Ctrl-C / 进程被杀 / 网络断开）。"""

    def __init__(self, n, exc):
        self.n, self.exc, self.count = n, exc, 0

    def __call__(self, ddl):
        self.count += 1
        if self.count == self.n:
            raise self.exc


# =========================================================================== #
# 中断 / 部分失败后重跑
# =========================================================================== #
class TestInterruptAndRerun:
    def test_s01_keyboard_interrupt_then_rerun_converges(self, world, tmp_path, capsys):
        world.ddl_hook = _Interrupt(15, KeyboardInterrupt())
        code = copilot(tmp_path, "--apply", "--parallel", "1")
        assert code in (1, 130) and "Traceback" not in capsys.readouterr().err
        done = sum(1 for v in copilot_rules(world).values() if v)
        assert 0 < done < len(TABLES)                                      # 确实中途停下
        world.ddl_hook = None
        assert copilot(tmp_path, "--apply") == 0
        assert_converged(world)
        n = len(world.ddl_log)
        assert copilot(tmp_path, "--apply") == 0 and len(world.ddl_log) == n   # 再跑全部 NOOP

    def test_s28_ctrl_c_with_parallel_stops_promptly(self, world, tmp_path, capsys):
        # --parallel > 1 时按 Ctrl-C：没开始的表必须取消（修复前 with ThreadPoolExecutor 退出时会把剩下的表全部跑完）
        hook = _Interrupt(5, KeyboardInterrupt())

        def slow(ddl):                                                     # 真实 DDL 需要数秒；这里每条 20ms
            hook(ddl)
            time.sleep(0.02)
        world.ddl_hook = slow
        code = copilot(tmp_path, "--apply", "--parallel", "4")
        assert code in (1, 130) and "Traceback" not in capsys.readouterr().err
        assert hook.count <= 5 + 2 * 4, hook.count                         # 只多跑完正在执行的几条（修复前 = 40）
        assert sum(1 for v in copilot_rules(world).values() if v) < len(TABLES)
        world.ddl_hook = None
        assert copilot(tmp_path, "--apply") == 0
        assert_converged(world)

    def test_s02_connection_lost_mid_run_then_rerun(self, world, tmp_path, capsys):
        world.ddl_hook = _Interrupt(10, ConnectionResetError("Connection reset by peer"))
        code = copilot(tmp_path, "--apply", "--parallel", "4")
        assert code == 1 and "Traceback" not in capsys.readouterr().err
        world.ddl_hook = None
        assert copilot(tmp_path, "--apply") == 0
        assert_converged(world)

    def test_s03_partial_ddl_failures_then_rerun(self, world, tmp_path):
        world.fail_ddl_on.update(TABLES[:5])
        assert copilot(tmp_path, "--apply") == 1
        assert all(not copilot_rules(world)[t] for t in TABLES[:5])
        world.fail_ddl_on.clear()
        assert copilot(tmp_path, "--apply") == 0
        assert_converged(world)

    def test_s04_bypass_interrupted_then_rerun(self, world, capsys):
        world.ddl_hook = _Interrupt(7, KeyboardInterrupt())
        assert bypass("--apply", "--parallel", "1") in (1, 130)
        world.ddl_hook = None
        assert bypass("--apply") == 0
        assert all(world.policy(t, BYP) for t in TABLES)
        assert "Traceback" not in capsys.readouterr().err

    def test_s05_rollback_interrupted_then_rerun(self, world, tmp_path):
        copilot(tmp_path, "--apply")
        world.ddl_hook = _Interrupt(12, KeyboardInterrupt())
        assert rollback_rls.main(["--datasets", f"{P}.dw", "--principals", G_COP, "--apply", "--parallel", "1"]) in (1, 130)
        world.ddl_hook = None
        assert rollback_rls.main(["--datasets", f"{P}.dw", "--principals", G_COP, "--apply"]) == 0
        assert all(not v for v in copilot_rules(world).values())

    def test_s06_ten_reruns_are_idempotent(self, world, tmp_path):
        copilot(tmp_path, "--apply")
        bypass("--apply")
        n = len(world.ddl_log)
        for _ in range(10):
            assert copilot(tmp_path, "--apply") == 0 and bypass("--apply") == 0
        assert len(world.ddl_log) == n


# =========================================================================== #
# 并发
# =========================================================================== #
class TestConcurrency:
    def _run_threads(self, fns):
        results, errors = [None] * len(fns), []

        def wrap(i, fn):
            try:
                results[i] = fn()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)
        ths = [threading.Thread(target=wrap, args=(i, fn)) for i, fn in enumerate(fns)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        assert not errors, errors
        return results

    def test_s07_two_copilot_runs_at_once(self, world, tmp_path):
        codes = self._run_threads([lambda: copilot(tmp_path, "--apply", name="a.csv"),
                                   lambda: copilot(tmp_path, "--apply", name="b.csv")])
        assert codes == [0, 0]
        assert_converged(world)

    def test_s08_bypass_and_copilot_at_once(self, world, tmp_path):
        codes = self._run_threads([lambda: bypass("--apply"), lambda: copilot(tmp_path, "--apply")])
        assert codes == [0, 0]
        assert_converged(world)
        assert all(world.policy(t, BYP) for t in TABLES)

    def test_s09_rollback_racing_copilot_then_rerun_converges(self, world, tmp_path):
        copilot(tmp_path, "--apply")
        codes = self._run_threads([
            lambda: rollback_rls.main(["--datasets", f"{P}.dw", "--principals", G_COP, "--apply"]),
            lambda: copilot(tmp_path, "--apply", name="x.csv")])
        assert all(c in (0, 1) for c in codes)
        assert copilot(tmp_path, "--apply", name="y.csv") == 0             # 再跑一次即收敛
        assert_converged(world)

    def test_s10_many_tables_high_parallelism(self, world, tmp_path):
        for i in range(400):
            t = f"{P}.big.t{i:04d}"
            world.add_table(t, schema={"region": ("STRING", "NULLABLE")})
            world.mapping_rows[MAP].append({"table_name": t, "col_name": "region", "to_name": "region"})
        assert copilot(tmp_path, "--apply", "--parallel", "64") == 0
        assert sum(1 for t in world.tables if world.policy(t, COP)) == 440
        assert len(world.ddl_log) == len(set(world.ddl_log)) == 440


# =========================================================================== #
# 运行中环境变化
# =========================================================================== #
class TestEnvironmentChanges:
    def test_s11_table_deleted_during_run(self, world, tmp_path, capsys):
        victim = TABLES[3]

        def drop(ddl):
            if world.tables.get(victim) is not None and f"`{victim}`" in ddl:
                del world.tables[victim]
                raise RuntimeError(f"404 Not found: Table {victim} was not found")
        world.ddl_hook = drop
        code = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and "Traceback" not in err and victim in err
        assert all(copilot_rules(world)[t] for t in TABLES if t != victim)

    def test_s12_table_missing_before_run_isolated(self, world, tmp_path, capsys):
        del world.tables[TABLES[0]]
        world.datasets[f"{P}.dw"].remove(TABLES[0])
        code = copilot(tmp_path, "--apply")
        assert code == 1 and f"[SKIP] {TABLES[0]}" in capsys.readouterr().err
        assert all(world.policy(t, COP) for t in TABLES[1:])

    def test_s13_dimension_removed_between_runs(self, world, tmp_path):
        world.condition_fields[COND].append(("prdtype", "STRING", "REPEATED"))
        world.tables[TABLES[0]]["schema"]["p"] = ("STRING", "NULLABLE")
        world.mapping_rows[MAP].append({"table_name": TABLES[0], "col_name": "p", "to_name": "prdtype"})
        copilot(tmp_path, "--apply")
        assert "UNNEST(c.prdtype)" in world.policy(TABLES[0], COP)["filter"]
        world.condition_fields[COND] = [f for f in world.condition_fields[COND] if f[0] != "prdtype"]
        code = copilot(tmp_path, "--apply")
        assert code == 0 and "prdtype" not in world.policy(TABLES[0], COP)["filter"]   # REPLACE 收窄

    def test_s14_registry_disabled_between_runs_keeps_rule_until_rollback(self, world, tmp_path, capsys):
        copilot(tmp_path, "--apply")
        world.unregister(TABLES[0]).register(TABLES[0], 0)
        copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert f"[SKIP] {TABLES[0]}" in err and world.policy(TABLES[0], COP)    # 脚本不自动删除
        assert rollback_rls.main(["--tables", TABLES[0], "--principals", G_COP, "--apply"]) == 0
        assert world.policy(TABLES[0], COP) is None

    def test_s15_condition_table_emptied_between_runs(self, world, tmp_path, capsys):
        copilot(tmp_path, "--apply")
        world.condition_sas[COND] = []
        code = copilot(tmp_path, "--apply")
        assert code == 0 and "[NOTE]" in capsys.readouterr().err
        assert_converged(world)

    def test_s16_mapping_table_unreadable(self, world, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(ops, "read_mapping_rows", lambda ctx, t: (_ for _ in ()).throw(RuntimeError("403 Access Denied")))
        code = copilot(tmp_path, "--apply")
        err = capsys.readouterr().err
        assert code == 1 and world.ddl_log == [] and "403" in err and "Traceback" not in err

    def test_s17_registry_unreadable(self, world, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(ops, "read_registry_rows", lambda ctx, t: (_ for _ in ()).throw(RuntimeError("503 backendError")))
        assert copilot(tmp_path, "--apply") == 2 and bypass("--apply") == 2 and world.ddl_log == []

    def test_s18_list_policies_fails_for_some_tables(self, world, tmp_path, monkeypatch, capsys):
        orig = ops.list_policies

        def flaky(ctx, t, grantees_for=None, workers=4):
            if t in TABLES[:3]:
                raise TimeoutError("timed out")
            return orig(ctx, t, grantees_for=grantees_for, workers=workers)
        monkeypatch.setattr(ops, "list_policies", flaky)
        code = copilot(tmp_path, "--apply")
        assert code == 1 and all(world.policy(t, COP) for t in TABLES[3:])
        assert "Traceback" not in capsys.readouterr().err


# =========================================================================== #
# 暂时性错误（真实 gcp_ops 代码路径）
# =========================================================================== #
class TestTransientErrors:
    def test_s19_run_ddl_retries_rate_limit_and_backend_errors(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(ops.time, "sleep", lambda s: sleeps.append(s))
        attempts = []

        class _Job:
            def result(self):
                attempts.append(1)
                if len(attempts) == 1:
                    raise RuntimeError("403 Exceeded rate limits: too many table update operations")
                if len(attempts) == 2:
                    raise RuntimeError("400 Failed to create row access policy: null")
                return []

        class _BQ:
            def query(self, *a, **k):
                return _Job()

        class _Ctx:
            bq = _BQ()
        ops.run_ddl(_Ctx(), "CREATE ...", "US")
        assert len(attempts) == 3 and sleeps == [2.0, 4.0]

    def test_s20_run_ddl_does_not_retry_real_errors(self, monkeypatch):
        monkeypatch.setattr(ops.time, "sleep", lambda s: None)

        class _BQ:
            def query(self, *a, **k):
                raise RuntimeError("400 Row access policies are not supported on views")

        class _Ctx:
            bq = _BQ()
        with pytest.raises(RuntimeError):
            ops.run_ddl(_Ctx(), "CREATE ...", "US")


# =========================================================================== #
# 损坏的输入 / 环境问题
# =========================================================================== #
class TestBadInputs:
    def test_s21_binary_garbage_csv(self, world, tmp_path, capsys):
        f = tmp_path / "t.csv"
        f.write_bytes(bytes(range(256)) * 4)
        try:
            code = apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--tables", str(f), "--apply"])
        except SystemExit as e:
            code = e.code
        assert code == 2 and world.ddl_log == [] and "Traceback" not in capsys.readouterr().err

    def test_s22_gbk_encoded_csv(self, world, tmp_path, capsys):
        f = tmp_path / "t.csv"
        f.write_bytes("项目.数据集.表\n".encode("gbk"))
        code = apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--tables", str(f), "--apply"])
        assert code == 2 and world.ddl_log == [] and "Traceback" not in capsys.readouterr().err

    def test_s23_huge_list_file(self, world, tmp_path):
        f = tmp_path / "t.csv"
        f.write_text("\n".join(TABLES * 250) + "\n", encoding="utf-8")       # 10000 行（含大量重复）
        assert apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--tables", str(f), "--apply"]) == 0
        assert len(world.ddl_log) == len(TABLES)

    def test_s24_csv_is_a_directory(self, world, tmp_path, capsys):
        d = tmp_path / "dir.csv"
        d.mkdir()
        code = apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--tables", str(d), "--apply"])
        assert code == 2 and "Traceback" not in capsys.readouterr().err

    def test_s25_output_csv_unwritable(self, world, tmp_path, capsys):
        code = apply_copilot_rls.main(["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP,
                                       "--registry-table", REG, "-o", str(tmp_path / "no" / "such" / "dir.csv")])
        err = capsys.readouterr().err
        assert code == 1 and "[ERROR]" in err and "Traceback" not in err

    def test_s26_keyboard_interrupt_in_list_principals(self, world, tmp_path, monkeypatch):
        monkeypatch.setattr(ops, "project_service_accounts", lambda ctx, p: (_ for _ in ()).throw(KeyboardInterrupt()))
        assert list_principals.main(["--projects", P, "-o", str(tmp_path / "p.csv")]) in (1, 130)

    def test_s27_empty_strings_and_whitespace_args(self, world, capsys):
        assert apply_bypass_rls.main(["--group", G, "--registry-table", REG, "--tables", "", " ", "--apply"]) == 2
        assert rollback_rls.main(["--tables", " ", "--principals", G]) == 2
        assert "Traceback" not in capsys.readouterr().err
