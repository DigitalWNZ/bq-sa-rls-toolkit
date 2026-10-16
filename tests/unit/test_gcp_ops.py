"""gcp_ops 中不依赖 GCP 的部分：指数退避重试。"""

import pytest
from googleapiclient.errors import HttpError

import gcp_ops as ops


class _Resp(dict):
    def __init__(self, status):
        super().__init__()
        self.status = status
        self.reason = "x"


class _Req:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def execute(self):
        self.calls += 1
        o = self.outcomes.pop(0)
        if isinstance(o, int):
            raise HttpError(_Resp(o), b"err")
        return o


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    waits = []
    monkeypatch.setattr(ops.time, "sleep", lambda s: waits.append(s))
    return waits


def test_retries_429_and_5xx_with_exponential_backoff(no_sleep):
    req = _Req([429, 503, {"ok": 1}])
    assert ops.execute_with_backoff(req, attempts=5) == {"ok": 1}
    assert req.calls == 3 and no_sleep == [2.0, 4.0]


def test_non_transient_error_raises_immediately(no_sleep):
    req = _Req([403])
    with pytest.raises(HttpError):
        ops.execute_with_backoff(req)
    assert req.calls == 1 and no_sleep == []


def test_gives_up_after_attempts(no_sleep):
    req = _Req([429, 429, 429])
    with pytest.raises(HttpError):
        ops.execute_with_backoff(req, attempts=3)
    assert req.calls == 3
