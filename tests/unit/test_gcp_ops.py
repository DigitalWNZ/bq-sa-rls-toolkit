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
    assert req.calls == 3 and len(no_sleep) == 2
    assert 1.0 <= no_sleep[0] <= 3.0 and 2.0 <= no_sleep[1] <= 6.0        # 2 / 4 秒 × 随机抖动 [0.5, 1.5)


def test_403_rate_limit_is_retried(no_sleep):
    class _R(_Req):
        def execute(self):
            self.calls += 1
            o = self.outcomes.pop(0)
            if isinstance(o, int):
                raise HttpError(_Resp(o), b"Quota exceeded ... rateLimitExceeded")
            return o
    req = _R([403, {"ok": 1}])
    assert ops.execute_with_backoff(req, attempts=3) == {"ok": 1} and req.calls == 2


def test_rate_limiter_spacing(no_sleep):
    rl = ops.RateLimiter(rpm=600)            # 0.1s 间隔；sleep 被 fixture 记录而不是真正等待
    for _ in range(4):
        rl.wait()
    assert len(no_sleep) == 3 and all(0.05 <= w <= 0.35 for w in no_sleep)


def test_retry_backs_off_on_rate_limit_message(no_sleep):
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("403 Exceeded rate limits: too many table update operations")
        return "done"
    assert ops.retry(fn, timeout=100) == "done" and len(calls) == 3
    assert no_sleep[:2] == [2.0, 4.0]


def test_non_transient_error_raises_immediately(no_sleep):
    req = _Req([403])
    with pytest.raises(HttpError):
        ops.execute_with_backoff(req)
    assert req.calls == 1 and no_sleep == []


def test_opaque_bigquery_ddl_error_is_retried(no_sleep):
    """BigQuery 高并发 DDL 下偶发 'Failed to create row access policy: null'（reason=invalid），按暂时性错误退避重试。"""
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 4:
            raise RuntimeError("400 Failed to create row access policy: null")
        return "done"
    assert ops.retry(fn, desc="DDL", timeout=300) == "done" and len(calls) == 4
    assert no_sleep[:3] == [2.0, 4.0, 8.0]


def test_real_ddl_failure_reason_is_not_retried(no_sleep):
    """带具体原因的 DDL 失败（如表不支持 RLS）不重试，立即抛出。"""
    calls = []

    def fn():
        calls.append(1)
        raise RuntimeError("400 Row access policies are not supported on views")
    with pytest.raises(RuntimeError):
        ops.retry(fn, desc="DDL", timeout=300)
    assert len(calls) == 1 and no_sleep == []


def test_gives_up_after_attempts(no_sleep):
    req = _Req([429, 429, 429])
    with pytest.raises(HttpError):
        ops.execute_with_backoff(req, attempts=3)
    assert req.calls == 3


class _Meta:
    num_rows = 6
    time_partitioning = None
    range_partitioning = None
    require_partition_filter = False


class _FakeBQ:
    def get_table(self, t):
        return _Meta()


class _Ctx:
    project = "p"
    creds = object()
    bq = _FakeBQ()

    def table_location(self, t):
        return "US"


def test_verify_fails_fast_when_sa_cannot_be_impersonated(monkeypatch, no_sleep):
    """扮演失败是永久性错误：立即返回 fail，不在 300 秒内反复重试。"""
    class _Client:
        def __init__(self, *a, **k):
            pass

        def query(self, *a, **k):
            raise RuntimeError("('Unable to acquire impersonated credentials', 'Permission iam.serviceAccounts.getAccessToken denied')")
    monkeypatch.setattr(ops.bigquery, "Client", _Client)
    monkeypatch.setattr(ops, "impersonate", lambda creds, sa: object())
    status, detail = ops.verify_full_access(_Ctx(), "p.d.t", "ghost@p.iam.gserviceaccount.com", timeout=300)
    assert status == "fail" and "无法扮演" in detail and no_sleep == []


def test_verify_retries_transient_zero_rows_until_visible(monkeypatch, no_sleep):
    seq = [[], [], [1]]

    class _Job:
        def __init__(self, rows):
            self.rows = rows

        def result(self):
            return self.rows

    class _Client:
        def __init__(self, *a, **k):
            pass

        def query(self, *a, **k):
            return _Job(seq.pop(0))
    monkeypatch.setattr(ops.bigquery, "Client", _Client)
    monkeypatch.setattr(ops, "impersonate", lambda creds, sa: object())
    status, _ = ops.verify_full_access(_Ctx(), "p.d.t", "r@p.iam.gserviceaccount.com", timeout=300)
    assert status == "ok" and len(no_sleep) == 2
