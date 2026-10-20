"""全部测试共用：进程内调用 main() 时，运行日志写到每个用例自己的临时目录，不在仓库目录里留下 logs/。"""

import pytest

import gcp_ops as ops


@pytest.fixture(autouse=True)
def _isolated_log_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(ops, "DEFAULT_LOG_DIR", str(tmp_path / "logs"))
    yield
    ops.stop_log_file()
