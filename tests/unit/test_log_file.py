"""
运行日志文件：4 个脚本把屏幕输出（stderr）原样另存到 <log-dir>/<脚本名>_<YYYYMMDD_HHMMSS>.log。
默认目录 logs/（测试中由 tests/conftest.py 指向每个用例的临时目录）；建不了只 [WARN]；argparse 错误 / --help 不写。
"""

import os
import re
import threading
import time

import pytest

import apply_bypass_rls
import apply_copilot_rls
import gcp_ops as ops
import list_principals
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

P = "trip-prod"
T1, T2 = f"{P}.dw.orders", f"{P}.dw.gone"
COND = f"{P}.auth.adm_user_mem_copilot_condition"
MAP = f"{P}.auth.adm_user_mem_copilot_tb_col_mapping"
G_COP, G_R = "group_copilot@trip.com", "group_read@trip.com"
SA_A = "copilot-a@trip-prod.iam.gserviceaccount.com"
NAME_RE = r"(?P<script>[a-z_]+)_(?P<stamp>\d{8}_\d{6})(_\d+)?\.log"

SCRIPTS = {
    "list_principals": (list_principals, ["--projects", P, "-o", "{tmp}/p.csv"]),
    "apply_bypass_rls": (apply_bypass_rls, ["--group", G_R, "--tables", T1, "--registry-table", REG]),
    "apply_copilot_rls": (apply_copilot_rls, ["--group", G_COP, "--condition-table", COND, "--mapping-table", MAP,
                                              "--registry-table", REG, "-o", "{tmp}/c.csv"]),
    "rollback_rls": (rollback_rls, ["--tables", T1, "--principals", G_COP]),
}


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    w.add_table(T1, schema={"region": ("STRING", "NULLABLE")})
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"),
                                ("region", "STRING", "REPEATED")]
    w.condition_sas[COND] = [SA_A]
    w.mapping_rows[MAP] = [{"table_name": T1, "col_name": "region", "to_name": "region"}]
    w.project_sas[P] = [SA_A]
    install(monkeypatch, w)
    for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
        monkeypatch.setattr(mod, "resolve_auth", fake_auth)
    return w


def run(name, tmp_path, *extra):
    mod, args = SCRIPTS[name]
    return mod.main([a.replace("{tmp}", str(tmp_path)) for a in args] + list(extra))


def log_files(d):
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", list(SCRIPTS))
def test_l01_default_dir_content_identical_to_screen(world, tmp_path, capsys, name):
    code = run(name, tmp_path)
    err = capsys.readouterr().err
    assert code == 0, err
    files = log_files(ops.DEFAULT_LOG_DIR)
    assert len(files) == 1
    m = re.fullmatch(NAME_RE, files[0])
    assert m and m["script"] == name
    path = os.path.join(ops.DEFAULT_LOG_DIR, files[0])
    assert read(path) == err                                           # 与屏幕输出逐字相同
    assert err.splitlines()[0] == f"[LOG] 日志文件: {path}"            # 第一行提示日志位置


def test_l02_custom_log_dir_created(world, tmp_path, capsys):
    d = tmp_path / "a" / "b" / "my_logs"
    code = run("apply_copilot_rls", tmp_path, "--log-dir", str(d))
    err = capsys.readouterr().err
    assert code == 0
    files = log_files(d)
    assert len(files) == 1 and read(d / files[0]) == err
    assert log_files(ops.DEFAULT_LOG_DIR) == []


def test_l03_unwritable_dir_warns_and_continues(world, tmp_path, capsys):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")                                            # 同名文件挡住目录
    code = run("apply_copilot_rls", tmp_path, "--log-dir", str(blocker))
    err = capsys.readouterr().err
    assert code == 0
    assert err.splitlines()[0].startswith("[WARN] 无法创建日志文件") and "本次只输出到屏幕" in err
    assert "[LOG]" not in err and "===== 完成" in err


@pytest.mark.skipif(os.geteuid() == 0, reason="root 不受目录权限限制")
def test_l03b_permission_denied_warns_and_continues(world, tmp_path, capsys):
    d = tmp_path / "ro"
    d.mkdir()
    d.chmod(0o500)
    try:
        code = run("apply_bypass_rls", tmp_path, "--log-dir", str(d))
    finally:
        d.chmod(0o700)
    err = capsys.readouterr().err
    assert code == 0 and "[WARN] 无法创建日志文件" in err and log_files(d) == []


def test_l04_same_second_never_overwrites(world, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(time, "strftime", lambda fmt, *a: "20261020_143005")
    run("apply_copilot_rls", tmp_path)
    first = capsys.readouterr().err
    run("apply_copilot_rls", tmp_path, "--apply")
    second = capsys.readouterr().err
    files = log_files(ops.DEFAULT_LOG_DIR)
    assert files == ["apply_copilot_rls_20261020_143005.log", "apply_copilot_rls_20261020_143005_2.log"]
    assert read(os.path.join(ops.DEFAULT_LOG_DIR, files[0])) == first
    assert read(os.path.join(ops.DEFAULT_LOG_DIR, files[1])) == second


@pytest.mark.parametrize("argv", [["--no-such-flag"], ["--help"], []])
def test_l05_argparse_error_or_help_writes_nothing(world, tmp_path, capsys, argv):
    with pytest.raises(SystemExit):
        apply_copilot_rls.main(argv)                                   # [] = 缺必填参数
    capsys.readouterr()
    assert log_files(ops.DEFAULT_LOG_DIR) == []


def test_l06_validation_error_exit2_is_logged(world, tmp_path, capsys):
    code = run("apply_copilot_rls", tmp_path, "--group", f"{G_COP},second@trip.com")
    err = capsys.readouterr().err
    assert code == 2 and "[ERROR] --group 只能指定一个" in err
    files = log_files(ops.DEFAULT_LOG_DIR)
    assert len(files) == 1 and read(os.path.join(ops.DEFAULT_LOG_DIR, files[0])) == err


def test_l07_ctrl_c_is_logged(world, tmp_path, capsys, monkeypatch):
    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(ops, "condition_sa_counts", boom)
    code = run("apply_copilot_rls", tmp_path)
    err = capsys.readouterr().err
    assert code == 130
    content = read(os.path.join(ops.DEFAULT_LOG_DIR, log_files(ops.DEFAULT_LOG_DIR)[0]))
    assert content == err and content.rstrip().endswith("[ERROR] 已被用户中断")


def test_l08_skip_reason_recorded(world, tmp_path, capsys):
    # 客户关心的场景：被跳过的表（不在 CSV、也不在 Cloud Audit Logs 里）在日志文件中可查
    world.register(T2, 1)
    world.mapping_rows[MAP].append({"table_name": T2, "col_name": "region", "to_name": "region"})
    code = run("apply_copilot_rls", tmp_path, "--apply")
    capsys.readouterr()
    content = read(os.path.join(ops.DEFAULT_LOG_DIR, log_files(ops.DEFAULT_LOG_DIR)[0]))
    assert code == 1 and f"[SKIP] {T2}: 表不存在（可能已被删除），请检查映射表 / 登记表" in content


def test_l09_concurrent_lines_not_interleaved(tmp_path, capsys):
    path = ops.start_log_file("t", str(tmp_path))
    lines = [f"[T{t:02d}] line {i:04d} " + "x" * 80 for t in range(32) for i in range(500)]

    def worker(t):
        for i in range(500):
            ops.log(lines[t * 500 + i])
    threads = [threading.Thread(target=worker, args=(t,)) for t in range(32)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    ops.stop_log_file()
    got = read(path).splitlines()[1:]                                  # 第一行是 [LOG]
    assert sorted(got) == sorted(lines)                                # 行数一致、每行完整
    assert read(path) == capsys.readouterr().err                       # 文件与屏幕顺序也一致（同一把锁）


def test_l10_write_failure_does_not_break_script(world, tmp_path, capsys, monkeypatch):
    real_start = ops.start_log_file

    class Broken:
        def write(self, s):
            raise OSError("No space left on device")

        def flush(self):
            pass

        def close(self):
            pass

    def start(script, log_dir=None):
        p = real_start(script, log_dir)
        ops._log_file.close()
        monkeypatch.setattr(ops, "_log_file", Broken())
        return p
    monkeypatch.setattr(ops, "start_log_file", start)
    code = run("apply_copilot_rls", tmp_path)
    err = capsys.readouterr().err
    assert code == 0 and "===== 完成" in err and "Traceback" not in err


def test_l11_consecutive_runs_separate_files(world, tmp_path, capsys):
    run("apply_bypass_rls", tmp_path)
    a = capsys.readouterr().err
    run("rollback_rls", tmp_path)
    b = capsys.readouterr().err
    files = log_files(ops.DEFAULT_LOG_DIR)
    assert [re.fullmatch(NAME_RE, f)["script"] for f in files] == ["apply_bypass_rls", "rollback_rls"]
    assert read(os.path.join(ops.DEFAULT_LOG_DIR, files[0])) == a
    assert read(os.path.join(ops.DEFAULT_LOG_DIR, files[1])) == b
    assert ops._log_file is None                                       # 运行结束即关闭
    ops.log("after")                                                   # 结束后的输出不再写入任何文件
    assert read(os.path.join(ops.DEFAULT_LOG_DIR, files[1])) == b
