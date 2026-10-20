"""
RLS 工具集的 GCP 操作封装（BigQuery / IAM / Resource Manager / Cloud Identity / Admin SDK）。
DDL 对 IAM / Group 传播延迟做了重试；只读 API 对 429 / 5xx 做指数退避。
"""

import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import cached_property

import google_auth_httplib2
import httplib2
from google.api_core.exceptions import NotFound
from google.auth import impersonated_credentials
from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

import rls_core as core

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
HTTP_TIMEOUT = int(os.environ.get("RLS_HTTP_TIMEOUT", "120"))   # googleapiclient 默认无超时，死连接会让线程永久挂起


def log(msg):
    """打印到屏幕（stderr）；已开启日志文件时原样写入一份（多线程加锁，行不交错）。"""
    with _log_lock:
        print(msg, file=sys.stderr, flush=True)
        if _log_file is not None:
            try:
                _log_file.write(f"{msg}\n")
                _log_file.flush()
            except (OSError, ValueError):
                pass                      # 写盘失败（如磁盘满）不影响脚本本身


# --------------------------------------------------------------------------- #
# 运行日志文件：屏幕输出原样另存一份（默认当前目录下的 logs/）
# --------------------------------------------------------------------------- #
DEFAULT_LOG_DIR = "logs"
_log_lock = threading.RLock()
_log_file = None


def add_log_dir_arg(parser):
    parser.add_argument("--log-dir", default=None,
                        help=f"运行日志保存目录（默认当前目录下的 {DEFAULT_LOG_DIR}/；每次运行一个新文件，内容与屏幕输出相同）")


def start_log_file(script, log_dir=None):
    """
    创建 <log_dir>/<script>_<YYYYMMDD_HHMMSS>.log（同名已存在则加 _2、_3 …，绝不覆盖），之后 log() 同时写入该文件。
    创建失败只打印 [WARN]，脚本照常运行。返回文件路径或 None。
    """
    global _log_file
    stop_log_file()
    d = log_dir or DEFAULT_LOG_DIR
    stamp = time.strftime("%Y%m%d_%H%M%S")
    f = path = None
    try:
        os.makedirs(d, exist_ok=True)
        for n in range(1, 1000):
            path = os.path.join(d, f"{script}_{stamp}{'' if n == 1 else f'_{n}'}.log")
            try:
                f = open(path, "x", encoding="utf-8")       # 'x'：已存在就换名
                break
            except FileExistsError:
                continue
        if f is None:
            raise OSError(f"{d} 中同名日志文件过多")
    except OSError as e:
        log(f"[WARN] 无法创建日志文件（目录 {d}）: {e}；本次只输出到屏幕")
        return None
    with _log_lock:
        _log_file = f
    log(f"[LOG] 日志文件: {path}")
    return path


def stop_log_file():
    global _log_file
    with _log_lock:
        if _log_file is not None:
            try:
                _log_file.close()
            except OSError:
                pass
            _log_file = None


# --------------------------------------------------------------------------- #
# 重试
# --------------------------------------------------------------------------- #
_PROPAGATION_HINTS = ("does not exist", "not found or permission denied", "invalid principal",
                      "unknown principal", "is not a valid", "concurrent policy changes",
                      "there were concurrent", "etag")


def is_propagation_error(e):
    if isinstance(e, HttpError) and e.resp.status == 409:
        return True
    msg = str(e).lower()
    return any(h in msg for h in _PROPAGATION_HINTS)


_RATE_LIMIT_HINTS = ("rate limit", "ratelimitexceeded", "quota exceeded", "quotaexceeded",
                     "resource exhausted", "resourceexhausted", "too many", "try again later",
                     "backenderror", "internalerror",
                     # BigQuery 在高并发 DDL 下偶发的无具体原因的后端错误（reason=invalid，message 以 ": null" 结尾），
                     # 实测成簇出现、几秒后自行恢复；按暂时性错误指数退避重试（2026-10-18 性能测试中约 27% 的 DDL 遇到）
                     "row access policy: null")


def is_rate_limit_error(e):
    msg = str(e).lower()
    return any(h in msg for h in _RATE_LIMIT_HINTS)


# 授权对象不存在。BigQuery 实际报错（2026-10-20 实测）:
#   "Failed to create row access policy: IAM setPolicy failed for RowAccessPolicy <名> on table <表>:
#    Group <邮箱> does not exist."
# Group 真不存在（拼错）与刚创建 / 刚改成员尚未同步，报的是同一句话；apply 脚本对此不再重试，立即停止。
_PRINCIPAL_MISSING_RE = re.compile(
    r"\b(group|user|serviceaccount|service account)\s+[^\s:]+@[^:]*?\s+does\s+not\s+exist", re.I)


def is_principal_missing_error(e):
    return bool(_PRINCIPAL_MISSING_RE.search(" ".join(str(e).split())))


def retry(fn, desc="", timeout=300, interval=10, retry_if=is_propagation_error):
    """
    传播延迟类错误（retry_if）固定间隔重试；速率限制 / 后端暂时性错误指数退避（2, 4, ... 最长 60s）；
    两类都在 timeout 内重试，超时抛出最后一次异常。
    """
    deadline = time.time() + timeout
    backoff = 2.0
    while True:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            now = time.time()
            if now >= deadline:
                raise
            if is_rate_limit_error(e):
                wait = min(backoff, 60.0, max(0.0, deadline - now))
                backoff *= 2
            elif retry_if(e):
                wait = min(interval, max(0.0, deadline - now))
            else:
                raise
            log(f"    [retry] {desc}: {str(e)[:150]}（{wait:.0f}s 后重试）")
            time.sleep(wait)


_TRANSIENT_STATUS = {429, 500, 502, 503, 504}


def execute_with_backoff(req, desc="", attempts=10, base=2.0, cap=60.0):
    """执行 googleapiclient 请求；429 / 5xx / 网络错误按指数退避重试（2, 4, 8, ... 最长 60s，带随机抖动）。"""
    for i in range(attempts):
        try:
            return req.execute()
        except HttpError as e:
            transient = e.resp.status in _TRANSIENT_STATUS or (e.resp.status == 403 and is_rate_limit_error(e))
            if not transient or i == attempts - 1:
                raise
            err = f"HTTP {e.resp.status}"
        except (ConnectionError, TimeoutError, OSError) as e:
            if i == attempts - 1:
                raise
            err = type(e).__name__
        wait = min(cap, base ** (i + 1)) * (0.5 + random.random())
        log(f"    [retry] {desc}: {err}，{wait:.0f}s 后重试（{i + 1}/{attempts - 1}）")
        time.sleep(wait)


class RateLimiter:
    """线程安全的令牌桶：每分钟最多 rpm 次，多线程共享。"""

    def __init__(self, rpm):
        self.interval = 60.0 / max(1, rpm)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


# BigQuery 配额「IamPolicy requests per minute per user」= 1500（实测触发 429；1400 时仍偶发）；默认 1200。可用 RLS_IAM_RPM 覆盖
IAM_POLICY_RPM = int(os.environ.get("RLS_IAM_RPM", "1200"))
_iam_limiter = RateLimiter(IAM_POLICY_RPM)


# --------------------------------------------------------------------------- #
# 上下文
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, creds, project):
        self.creds = creds
        self.project = project
        self._loc = {}
        self._lock = threading.Lock()
        self._tls = threading.local()

    def _build(self, name, version):
        """googleapiclient 的 Resource（底层 httplib2）不是线程安全的：每个线程各建一份。"""
        key = f"{name}/{version}"
        svc = getattr(self._tls, key, None)
        if svc is None:
            http = google_auth_httplib2.AuthorizedHttp(self.creds, http=httplib2.Http(timeout=HTTP_TIMEOUT))
            svc = discovery.build(name, version, http=http, cache_discovery=False)
            setattr(self._tls, key, svc)
        return svc

    @cached_property
    def bq(self):
        return bigquery.Client(project=self.project, credentials=self.creds)

    @property
    def bqapi(self):
        return self._build("bigquery", "v2")

    @property
    def ci(self):
        return self._build("cloudidentity", "v1")

    def location(self, project, dataset):
        key = f"{project}.{dataset}"
        with self._lock:
            loc = self._loc.get(key)
        if loc is None:
            loc = self.bq.get_dataset(key).location
            with self._lock:
                self._loc[key] = loc
        return loc

    def table_location(self, table):
        p, d, _ = core.parse_table(table)
        return self.location(p, d)


# --------------------------------------------------------------------------- #
# 并行
# --------------------------------------------------------------------------- #
def parallel_map(fn, items, workers=8, desc=""):
    """
    对每个 item 调用 fn(item)，最多 workers 个并发；返回与 items 同序的 [(item, result, exception)]。
    单个 item 失败不影响其他 item（异常放在第三项）。
    """
    items = list(items)
    results = [None] * len(items)

    def run_one(i):
        try:
            return i, fn(items[i]), None
        except Exception as e:  # noqa: BLE001
            return i, None, e

    if workers <= 1 or len(items) <= 1:
        for i in range(len(items)):
            _, r, e = run_one(i)
            results[i] = (items[i], r, e)
        return results
    ex = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=desc or "rls")
    try:
        for fut in as_completed([ex.submit(run_one, i) for i in range(len(items))]):
            i, r, e = fut.result()
            results[i] = (items[i], r, e)
    except BaseException:
        # Ctrl-C 等：取消还没开始的任务（否则 with 退出时会把剩下的表全部跑完），正在执行的那几条等它自然结束
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    ex.shutdown(wait=True)
    return results


# --------------------------------------------------------------------------- #
# BigQuery：查询 / DDL / RLS / 表
# --------------------------------------------------------------------------- #
def run_query(ctx, sql, location, params=None):
    cfg = bigquery.QueryJobConfig(query_parameters=params or [])
    return list(ctx.bq.query(sql, location=location, job_config=cfg).result())


def run_ddl(ctx, ddl, location, retry_missing_principal=True):
    """
    执行一条 DDL。retry_missing_principal=False 时，「授权对象（Group 等）不存在」不按传播延迟重试、立即抛出
    （apply 脚本使用：Group 写错时不再每张表空等 300 秒）；速率限制、并发修改冲突等仍自动重试。
    """
    if retry_missing_principal:
        retry_if = is_propagation_error
    else:
        def retry_if(e):
            return is_propagation_error(e) and not is_principal_missing_error(e)
    retry(lambda: ctx.bq.query(ddl, location=location).result(), desc="DDL", timeout=300, retry_if=retry_if)


def list_policies(ctx, table, grantees_for=None, workers=4):
    """
    [{"id","filter","grantees"}]。rowAccessPolicies.list 不返回授权对象，要逐条 getIamPolicy：
      grantees_for=None   -> 全部读取（回退按主体匹配时需要）
      grantees_for=集合   -> 只读取这些名字的规则，其余 grantees 为 None（apply_* 只关心自己那条）
    """
    p, d, t = core.parse_table(table)
    api = ctx.bqapi.rowAccessPolicies()
    raw, req = [], api.list(projectId=p, datasetId=d, tableId=t)
    while req is not None:
        resp = execute_with_backoff(req, desc=f"list policies {table}")
        raw.extend(resp.get("rowAccessPolicies", []))
        req = api.list_next(req, resp)
    out = [{"id": it["rowAccessPolicyReference"]["policyId"], "filter": it.get("filterPredicate", "TRUE"),
            "grantees": None} for it in raw]
    want = [x for x in out if grantees_for is None or x["id"] in grantees_for]

    def fetch(x):
        res = f"projects/{p}/datasets/{d}/tables/{t}/rowAccessPolicies/{x['id']}"
        _iam_limiter.wait()                                   # 全局限速，避免触发 1500 次/分钟的配额
        pol = execute_with_backoff(ctx.bqapi.rowAccessPolicies().getIamPolicy(resource=res, body={}),
                                   desc=f"policy IAM {x['id']}")
        return [m for b in pol.get("bindings", []) if b.get("role") == core.RLS_GRANTEE_ROLE
                for m in b.get("members", [])]

    for x, grantees, err in parallel_map(fetch, want, workers=workers, desc="iam"):
        if err:
            raise err
        x["grantees"] = grantees
    return out


def expand_tables(ctx, tables, datasets, projects):
    """
    表 / 数据集内全部表 / 项目内全部表 -> 去重后的 project.dataset.table 列表。
    展开数据集和项目时只取普通表（TABLE），视图等不支持 RLS 的对象跳过；显式列出的表原样保留。
    """
    out = [core.fq(t) for t in tables]
    ds_list = [core.parse_dataset(d) for d in datasets]
    for project in projects:
        ds_list += [(project, d.dataset_id) for d in ctx.bq.list_datasets(project=project)]
    for project, dataset in ds_list:
        for t in ctx.bq.list_tables(f"{project}.{dataset}"):
            if t.table_type == "TABLE":
                out.append(f"{project}.{dataset}.{t.table_id}")
    return list(dict.fromkeys(out))


def table_fields(ctx, table):
    """顶层字段 [(name, type, mode)]。"""
    return [(f.name, f.field_type, f.mode or "NULLABLE") for f in ctx.bq.get_table(core.fq(table)).schema]


def table_exists(ctx, table):
    try:
        ctx.bq.get_table(core.fq(table))
        return True
    except NotFound:
        return False


def table_schema(ctx, table):
    """{路径: (类型, mode)}，嵌套字段用 a.b。"""
    return core.flatten_schema(ctx.bq.get_table(core.fq(table)).schema)


def read_mapping_rows(ctx, mapping_table):
    t = core.fq(mapping_table)
    return [dict(r.items()) for r in run_query(
        ctx, f"SELECT table_name, col_name, to_name FROM `{t}`", ctx.table_location(t))]


def read_registry_rows(ctx, registry_table):
    """登记表 [{"table_name", "rls_enabled"}]（原值，不规范化）。"""
    t = core.fq(registry_table)
    return [dict(r.items()) for r in run_query(
        ctx, f"SELECT table_name, rls_enabled FROM `{t}`", ctx.table_location(t))]


def condition_sa_counts(ctx, condition_table):
    """条件表 sa 列 {原值: 行数}（不做任何规范化；NULL 和空串除外）。"""
    t = core.fq(condition_table)
    rows = run_query(ctx, f"SELECT sa, COUNT(*) AS n FROM `{t}` WHERE sa IS NOT NULL AND TRIM(sa) != '' GROUP BY sa",
                     ctx.table_location(t))
    return {r["sa"]: r["n"] for r in rows}


# --------------------------------------------------------------------------- #
# 扮演与挂载后验证
# --------------------------------------------------------------------------- #
def impersonate(source_creds, target):
    return impersonated_credentials.Credentials(
        source_credentials=source_creds, target_principal=target,
        target_scopes=SCOPES, lifetime=3600)


def table_partitioning(tbl):
    """bigquery.Table -> visibility_probe_sql 需要的分区描述（无分区返回 None）。"""
    if tbl.time_partitioning:
        return {"require_filter": bool(tbl.require_partition_filter),
                "field": tbl.time_partitioning.field, "kind": "time"}
    if tbl.range_partitioning:
        return {"require_filter": bool(tbl.require_partition_filter),
                "field": tbl.range_partitioning.field, "kind": "range"}
    return None


def _is_impersonation_error(e):
    msg = str(e)
    return "Unable to acquire impersonated credentials" in msg or "iam.serviceAccounts.getAccessToken" in msg


def verify_full_access(ctx, table, sa_email, timeout=300, interval=10, mode="sample"):
    """
    以 sa_email 身份轮询探测查询，确认其能看到数据。返回 (status, detail)，status ∈ ok / fail / skip。
      sample（默认）: SELECT 1 ... LIMIT 1，看到任意一行即通过
      count         : SELECT COUNT(*) 与元数据行数比对
    表元数据行数为 0 时无法验证，返回 skip。
    """
    table = core.fq(table)
    meta = ctx.bq.get_table(table)
    expected = meta.num_rows or 0
    if expected == 0:
        return "skip", "表元数据行数为 0，无法通过查询验证可见性"
    sql = core.visibility_probe_sql(table, table_partitioning(meta), mode=mode)
    client = bigquery.Client(project=ctx.project, credentials=impersonate(ctx.creds, sa_email))
    loc = ctx.table_location(table)
    start, last = time.time(), ""
    while True:
        try:
            rows = list(client.query(sql, location=loc).result())
            if mode == "count":
                n = rows[0].n
                if n >= expected:
                    return "ok", f"{n} 行（{time.time() - start:.0f}s）"
                last = f"只可见 {n}/{expected} 行"
            elif rows:
                return "ok", f"可见数据（{time.time() - start:.0f}s）"
            else:
                last = "查询返回 0 行（未命中规则或 Group 尚未生效）"
        except Exception as e:  # noqa: BLE001
            if _is_impersonation_error(e):          # 永久性错误：等待也不会好转，立即失败
                return "fail", f"无法扮演 {sa_email}（需要对它有 roles/iam.serviceAccountTokenCreator，或该 SA 不存在）: {str(e)[:200]}"
            last = str(e)[:200]
        if time.time() - start >= timeout:
            return "fail", f"{timeout}s 内未达到可见: {last}"
        log(f"    [verify] {table}: {last}")
        time.sleep(interval)


def count_visible(ctx, table, sa_email):
    """以 sa_email 身份查 COUNT(*)，返回 (可见行数, 表元数据行数)。只报告，不重试。"""
    table = core.fq(table)
    meta = ctx.bq.get_table(table)
    sql = core.visibility_probe_sql(table, table_partitioning(meta), mode="count")
    client = bigquery.Client(project=ctx.project, credentials=impersonate(ctx.creds, sa_email))
    rows = list(client.query(sql, location=ctx.table_location(table)).result())
    return rows[0].n, meta.num_rows or 0


# --------------------------------------------------------------------------- #
# Cloud Identity Groups（只读：展开成员）
# --------------------------------------------------------------------------- #
_CONFIG_ERROR_HINTS = ("user_project", "quota project", "service_disabled", "has not been used",
                       "is disabled", "serviceusage")


def _is_unreadable_group_error(e):
    """403 / 404 且不是配置问题（API 未启用、quota 项目无权限）→ 该 Group 读不到（无权限 / 外部域 / 不存在）。"""
    return (isinstance(e, HttpError) and e.resp.status in (403, 404)
            and not any(h in str(e).lower() for h in _CONFIG_ERROR_HINTS))


GROUP_UNREADABLE_REASON = "无权读取（外部域的 Group，或执行账号没有 Group 读取权限；不存在的 Group 也返回同样的错误）"


def lookup_group(ctx, email):
    """Group 的资源名；读不到返回 None。配置错误、限流重试用尽、网络错误等向上抛出。"""
    try:
        return execute_with_backoff(ctx.ci.groups().lookup(groupKey_id=email), desc=f"lookup group {email}")["name"]
    except HttpError as e:
        if _is_unreadable_group_error(e):
            return None
        raise


def group_members_typed(ctx, group_email, reasons=None):
    """
    Group 直接成员 [(email, type)]；type 为 USER / SERVICE_ACCOUNT / GROUP / ...；空组返回 []。
    读不到（无权限 / 外部域 / 不存在）返回 None，并把原因写入 reasons[group_email]。
    Cloud Identity API 未启用、quota 项目无权限、限流 / 5xx / 网络错误重试用尽等**向上抛出**，由调用方记 [ERROR]。
    """
    def unreadable(e):
        if reasons is not None:
            reasons[group_email] = f"{GROUP_UNREADABLE_REASON}: HTTP {e.resp.status}"
        return None

    try:
        name = execute_with_backoff(ctx.ci.groups().lookup(groupKey_id=group_email),
                                    desc=f"lookup group {group_email}")["name"]
    except HttpError as e:
        if _is_unreadable_group_error(e):
            return unreadable(e)
        raise
    out, api = [], ctx.ci.groups().memberships()
    req = api.list(parent=name, pageSize=200, view="FULL")
    try:
        while req is not None:
            resp = execute_with_backoff(req, desc=f"list members {group_email}")
            out.extend((m["preferredMemberKey"]["id"].lower(), m.get("type"))
                       for m in resp.get("memberships", []))
            req = api.list_next(req, resp)
    except HttpError as e:
        if _is_unreadable_group_error(e):
            return unreadable(e)
        raise
    return out


def expand_group(ctx, group_email, max_depth=10):
    """
    递归展开 Group（含嵌套组）-> (members, unresolved, reasons)。
    unresolved [(group, via)]：读不到的组（含最外层的组本身，此时 via 为 []）；reasons {group: 原因}。
    """
    cache, reasons = {}, {}

    def fetch(g):
        if g not in cache:
            cache[g] = group_members_typed(ctx, g, reasons)
        return cache[g]
    members, unresolved = core.expand_group(group_email, fetch, max_depth=max_depth)
    return members, unresolved, reasons


# --------------------------------------------------------------------------- #
# list_principals：全部使用权威 API（不使用 Cloud Asset，其搜索索引可能漏掉资源）
# --------------------------------------------------------------------------- #
DIRECTORY_HINT = ("读取账号目录需要：① 执行账号是 Workspace / Cloud Identity 管理员，且具有「用户 → 读取」权限"
                  "（如超级管理员、用户管理管理员，或只含该权限的自定义管理员角色）；② quota 项目已启用 Admin SDK API"
                  "（admin.googleapis.com）")


def _paged(api_method, next_method, key, desc, **kwargs):
    out, req = [], api_method(**kwargs)
    while req is not None:
        resp = execute_with_backoff(req, desc=desc)
        out.extend(resp.get(key, []))
        req = next_method(req, resp)
    return out


def list_org_descendants(ctx, org_id):
    """组织下递归的 (文件夹名列表, ACTIVE 项目 ID 列表, 非 ACTIVE 项目 ID 列表)；Resource Manager v3。"""
    crm = ctx._build("cloudresourcemanager", "v3")
    folders, active, inactive = [], [], []
    todo = [f"organizations/{org_id}"]
    while todo:
        parent = todo.pop(0)
        subs = _paged(crm.folders().list, crm.folders().list_next, "folders", f"list folders {parent}", parent=parent)
        for f in subs:
            folders.append(f["name"])
            todo.append(f["name"])
        for prj in _paged(crm.projects().list, crm.projects().list_next, "projects", f"list projects {parent}",
                          parent=parent, showDeleted=True):
            (active if prj.get("state") == "ACTIVE" else inactive).append(prj["projectId"])
    return folders, active, inactive


def org_directory_customer(ctx, org_id):
    """组织对应的 Cloud Identity / Workspace customer ID（organizations.get 的 directoryCustomerId）。"""
    crm = ctx._build("cloudresourcemanager", "v3")
    org = execute_with_backoff(crm.organizations().get(name=f"organizations/{org_id}"), desc=f"get org {org_id}")
    return org["directoryCustomerId"]


def directory_users(ctx, customer):
    """
    账号目录里的全部 user（含暂停 / 归档，所有域名）。用执行账号自己的凭证（与其它调用相同）调用 Admin SDK Directory API；
    能否读取由执行账号在 Admin 控制台中的管理员权限决定（GCP IAM 角色不起作用）。
    """
    svc = ctx._build("admin", "directory_v1")
    try:
        users = _paged(svc.users().list, svc.users().list_next, "users", f"list users {customer}",
                       customer=customer, maxResults=500, projection="basic", showDeleted="false")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"读取账号目录失败: {str(e)[:300]}。{DIRECTORY_HINT}") from e
    return [u["primaryEmail"].lower() for u in users if u.get("primaryEmail")]


def resource_iam_bindings(ctx, resource):
    """organizations/<id> / folders/<id> / projects/<id> 的 IAM 策略 bindings（requestedPolicyVersion 3，含条件绑定）。"""
    crm = ctx._build("cloudresourcemanager", "v3")
    kind = resource.split("/", 1)[0]
    api = {"organizations": crm.organizations(), "folders": crm.folders(), "projects": crm.projects()}[kind]
    pol = execute_with_backoff(api.getIamPolicy(resource=resource, body={"options": {"requestedPolicyVersion": 3}}),
                               desc=f"getIamPolicy {resource}")
    return pol.get("bindings", [])


def project_service_accounts(ctx, project):
    """项目自己的全部 SA（IAM serviceAccounts.list；含已禁用、没有任何授权的）。"""
    iam = ctx._build("iam", "v1")
    accts = _paged(iam.projects().serviceAccounts().list, iam.projects().serviceAccounts().list_next, "accounts",
                   f"list SAs {project}", name=f"projects/{project}", pageSize=100)
    return [a["email"].lower() for a in accts]


def project_datasets(ctx, project):
    return [f"{project}.{d.dataset_id}" for d in ctx.bq.list_datasets(project=project)]


def dataset_access(ctx, dataset):
    """数据集 ACL -> [(role, entity_type, entity_id)]（role 为 READER / WRITER / OWNER 或 roles/...）。"""
    p, d = core.parse_dataset(dataset)
    return [(e.role, e.entity_type, e.entity_id) for e in ctx.bq.get_dataset(f"{p}.{d}").access_entries]


def dataset_tables(ctx, dataset):
    """数据集内全部表（含视图 / 物化视图 / 外部表；它们都可以单独授权）。"""
    return [f"{t.project}.{t.dataset_id}.{t.table_id}" for t in ctx.bq.list_tables(dataset)]


def table_iam_bindings(ctx, table):
    p, d, t = core.parse_table(table)
    _iam_limiter.wait()                                   # 与 rowAccessPolicies.getIamPolicy 共用 BigQuery IamPolicy 配额
    pol = execute_with_backoff(ctx.bqapi.tables().getIamPolicy(
        resource=f"projects/{p}/datasets/{d}/tables/{t}", body={}), desc=f"table getIamPolicy {table}")
    return pol.get("bindings", [])


def role_permissions(ctx, role):
    """角色包含的权限（预定义 / 基本角色 roles/...；自定义角色 organizations/x/roles/y、projects/p/roles/y）。"""
    iam = ctx._build("iam", "v1")
    if role.startswith("organizations/"):
        req = iam.organizations().roles().get(name=role)
    elif role.startswith("projects/"):
        req = iam.projects().roles().get(name=role)
    else:
        req = iam.roles().get(name=role)
    return set(execute_with_backoff(req, desc=f"get role {role}").get("includedPermissions", []))
