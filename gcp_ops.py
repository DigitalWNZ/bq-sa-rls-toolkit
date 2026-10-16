"""
RLS 工具集的 GCP 操作封装（BigQuery / IAM / Resource Manager / Cloud Identity）。
所有写操作都对 IAM/Group 传播延迟做了重试。
"""

import sys
import time
from functools import cached_property

from google.auth import impersonated_credentials
from google.cloud import bigquery
from googleapiclient import discovery
from googleapiclient.errors import HttpError

import rls_core as core

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


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


def retry(fn, desc="", timeout=300, interval=10, retry_if=is_propagation_error):
    deadline = time.time() + timeout
    while True:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            if time.time() >= deadline or not retry_if(e):
                raise
            log(f"    [retry] {desc}: {str(e)[:150]}")
            time.sleep(interval)


_TRANSIENT_STATUS = {429, 500, 502, 503, 504}


def execute_with_backoff(req, desc="", attempts=6, base=2.0):
    """执行 googleapiclient 请求；429 / 5xx / 网络错误按指数退避重试（2, 4, 8, ... 秒）。"""
    for i in range(attempts):
        try:
            return req.execute()
        except HttpError as e:
            if e.resp.status not in _TRANSIENT_STATUS or i == attempts - 1:
                raise
            err = f"HTTP {e.resp.status}"
        except (ConnectionError, TimeoutError, OSError) as e:
            if i == attempts - 1:
                raise
            err = type(e).__name__
        wait = base ** (i + 1)
        log(f"    [retry] {desc}: {err}，{wait:.0f}s 后重试（{i + 1}/{attempts - 1}）")
        time.sleep(wait)


# --------------------------------------------------------------------------- #
# 上下文
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, creds, project):
        self.creds = creds
        self.project = project
        self._loc = {}

    def _build(self, name, version):
        return discovery.build(name, version, credentials=self.creds, cache_discovery=False)

    @cached_property
    def bq(self):
        return bigquery.Client(project=self.project, credentials=self.creds)

    @cached_property
    def bqapi(self):
        return self._build("bigquery", "v2")

    @cached_property
    def iam(self):
        return self._build("iam", "v1")

    @cached_property
    def crm(self):
        return self._build("cloudresourcemanager", "v1")

    @cached_property
    def ci(self):
        return self._build("cloudidentity", "v1")

    @cached_property
    def asset(self):
        return self._build("cloudasset", "v1")

    def location(self, project, dataset):
        key = f"{project}.{dataset}"
        if key not in self._loc:
            self._loc[key] = self.bq.get_dataset(key).location
        return self._loc[key]

    def table_location(self, table):
        p, d, _ = core.parse_table(table)
        return self.location(p, d)


# --------------------------------------------------------------------------- #
# BigQuery：查询 / DDL / RLS
# --------------------------------------------------------------------------- #
def run_query(ctx, sql, location, params=None):
    cfg = bigquery.QueryJobConfig(query_parameters=params or [])
    return list(ctx.bq.query(sql, location=location, job_config=cfg).result())


def run_ddl(ctx, ddl, location):
    retry(lambda: ctx.bq.query(ddl, location=location).result(), desc="DDL", timeout=300)


def list_policies(ctx, table):
    """[{"id","filter","grantees"}]；grantees 通过 rowAccessPolicies.getIamPolicy 读取。"""
    p, d, t = core.parse_table(table)
    api = ctx.bqapi.rowAccessPolicies()
    raw, req = [], api.list(projectId=p, datasetId=d, tableId=t)
    while req is not None:
        resp = req.execute()
        raw.extend(resp.get("rowAccessPolicies", []))
        req = api.list_next(req, resp)
    out = []
    for item in raw:
        pid = item["rowAccessPolicyReference"]["policyId"]
        res = f"projects/{p}/datasets/{d}/tables/{t}/rowAccessPolicies/{pid}"
        pol = api.getIamPolicy(resource=res, body={}).execute()
        grantees = [m for b in pol.get("bindings", []) if b.get("role") == core.RLS_GRANTEE_ROLE
                    for m in b.get("members", [])]
        out.append({"id": pid, "filter": item.get("filterPredicate", "TRUE"), "grantees": grantees})
    return out


# --------------------------------------------------------------------------- #
# IAM：表 / 数据集 / 项目 / SA
# --------------------------------------------------------------------------- #
def table_role_members(ctx, table, role):
    pol = ctx.bq.get_iam_policy(core.fq(table))
    return {core.normalize_member(m) for b in pol.bindings if b["role"] == role for m in b["members"]}


def table_iam_bindings(ctx, table):
    return [(b["role"], list(b["members"])) for b in ctx.bq.get_iam_policy(core.fq(table)).bindings]


def table_add_role(ctx, table, role, member):
    """返回 True 表示新增。"""
    table = core.fq(table)

    def op():
        pol = ctx.bq.get_iam_policy(table)
        for b in pol.bindings:
            if b["role"] == role and member in b["members"]:
                return False
        pol.bindings.append({"role": role, "members": {member}})
        ctx.bq.set_iam_policy(table, pol)
        return True
    return retry(op, desc=f"table IAM {member}")


def table_remove_role(ctx, table, role, members):
    """移除 members（已规范化）在表上的 role；返回实际移除的成员。"""
    table = core.fq(table)
    pol = ctx.bq.get_iam_policy(table)
    removed = set()
    for b in pol.bindings:
        if b["role"] == role:
            hit = {m for m in b["members"] if core.normalize_member(m) in members}
            if hit:
                b["members"] = set(b["members"]) - hit
                removed |= hit
    if removed:
        pol.bindings = [b for b in pol.bindings if b["members"]]
        ctx.bq.set_iam_policy(table, pol)
    return removed


_ENTITY_FOR_PREFIX = {"group": "groupByEmail", "user": "userByEmail",
                      "serviceAccount": "userByEmail", "domain": "domain"}


def dataset_add_reader(ctx, dataset, member):
    """数据集级授予 READER（等同 dataViewer）。返回 True 表示新增。"""
    prefix, _, email = member.partition(":")
    entity = _ENTITY_FOR_PREFIX[prefix]

    def op():
        ds = ctx.bq.get_dataset(dataset)
        if any(e.entity_id and e.entity_id.lower() == email and e.role == "READER"
               for e in ds.access_entries):
            return False
        ds.access_entries = list(ds.access_entries) + [
            bigquery.AccessEntry("READER", entity, email)]
        ctx.bq.update_dataset(ds, ["access_entries"])
        return True
    return retry(op, desc=f"dataset ACL {member}")


def dataset_member_roles(ds):
    """数据集 ACL -> [(member, role)]，跳过授权视图/routine/dataset。"""
    out = []
    for e in ds.access_entries:
        if not e.role or not isinstance(e.entity_id, str):
            continue
        t, eid = e.entity_type, e.entity_id
        if t == "userByEmail":
            member = core.normalize_member(eid, default_prefix="user")
        elif t == "groupByEmail":
            member = f"group:{eid.lower()}"
        elif t == "domain":
            member = f"domain:{eid.lower()}"
        elif t == "specialGroup":
            member = f"specialGroup:{eid}"
        elif t == "iamMember":
            member = core.normalize_member(eid)
        else:
            continue
        out.append((member, e.role))
    return out


def dataset_authorized(ds):
    """数据集 ACL 里的授权视图 / 授权数据集 -> core.authorized_entries 的 (views, datasets)。"""
    return core.authorized_entries([(e.entity_type, e.entity_id) for e in ds.access_entries])


def project_policy(ctx, project):
    return ctx.crm.projects().getIamPolicy(
        resource=project, body={"options": {"requestedPolicyVersion": 3}}).execute()


def project_add_role(ctx, project, role, member):
    def op():
        pol = project_policy(ctx, project)
        for b in pol.setdefault("bindings", []):
            if b["role"] == role and not b.get("condition"):
                if member in b["members"]:
                    return False
                b["members"].append(member)
                break
        else:
            pol["bindings"].append({"role": role, "members": [member]})
        ctx.crm.projects().setIamPolicy(resource=project, body={"policy": pol}).execute()
        return True
    return retry(op, desc=f"project IAM {member}")


def list_sas(ctx, project):
    return [s["email"] for s in list_sa_details(ctx, project)]


def list_sa_details(ctx, project):
    """[{"email","display_name","disabled"}]"""
    out, api = [], ctx.iam.projects().serviceAccounts()
    req = api.list(name=f"projects/{project}", pageSize=100)
    while req is not None:
        resp = req.execute()
        out.extend({"email": a["email"].lower(), "display_name": a.get("displayName", ""),
                    "disabled": bool(a.get("disabled"))} for a in resp.get("accounts", []))
        req = api.list_next(req, resp)
    return out


def create_sa(ctx, project, account_id, display_name=None):
    """返回 (email, created)。"""
    email = core.sa_email(account_id, project)
    try:
        ctx.iam.projects().serviceAccounts().create(
            name=f"projects/{project}",
            body={"accountId": account_id,
                  "serviceAccount": {"displayName": display_name or account_id}}).execute()
        return email, True
    except HttpError as e:
        if e.resp.status == 409:
            return email, False
        raise


def sa_add_role(ctx, sa_email, role, member):
    api = ctx.iam.projects().serviceAccounts()
    res = f"projects/-/serviceAccounts/{sa_email}"

    def op():
        pol = api.getIamPolicy(resource=res).execute()
        for b in pol.setdefault("bindings", []):
            if b["role"] == role:
                if member in b["members"]:
                    return False
                b["members"].append(member)
                break
        else:
            pol["bindings"].append({"role": role, "members": [member]})
        api.setIamPolicy(resource=res, body={"policy": pol}).execute()
        return True
    return retry(op, desc=f"SA IAM {sa_email}")


def impersonate(source_creds, target, delegates=()):
    return impersonated_credentials.Credentials(
        source_credentials=source_creds, target_principal=target,
        delegates=list(delegates), target_scopes=SCOPES, lifetime=3600)


# --------------------------------------------------------------------------- #
# Cloud Identity Groups
# --------------------------------------------------------------------------- #
def resolve_customer_id(ctx, project):
    anc = ctx.crm.projects().getAncestry(projectId=project, body={}).execute()
    org = next((a["resourceId"]["id"] for a in anc.get("ancestor", [])
                if a["resourceId"]["type"] == "organization"), None)
    if not org:
        raise RuntimeError(f"项目 {project} 不在 Organization 下，请用 --customer-id 指定")
    return ctx.crm.organizations().get(name=f"organizations/{org}").execute()["owner"][
        "directoryCustomerId"]


_CONFIG_ERROR_HINTS = ("user_project", "quota project", "service_disabled", "has not been used",
                       "is disabled", "serviceusage")


def lookup_group(ctx, email):
    try:
        return ctx.ci.groups().lookup(groupKey_id=email).execute()["name"]
    except HttpError as e:
        if e.resp.status in (403, 404) and not any(h in str(e).lower() for h in _CONFIG_ERROR_HINTS):
            return None
        raise


def ensure_group(ctx, email, customer_id, display_name=None, initial_config="WITH_INITIAL_OWNER"):
    """返回 (group_name, created)。"""
    name = lookup_group(ctx, email)
    if name:
        return name, False
    ctx.ci.groups().create(
        initialGroupConfig=initial_config,
        body={"parent": f"customers/{customer_id}", "groupKey": {"id": email},
              "displayName": display_name or email,
              "labels": {"cloudidentity.googleapis.com/groups.discussion_forum": ""}}).execute()
    name = retry(lambda: lookup_group(ctx, email) or (_ for _ in ()).throw(
        RuntimeError(f"group {email} does not exist yet")), desc="group lookup", timeout=120)
    return name, True


def group_members(ctx, group_name):
    out, api = set(), ctx.ci.groups().memberships()
    req = api.list(parent=group_name, pageSize=200)
    while req is not None:
        resp = req.execute()
        out.update(m["preferredMemberKey"]["id"].lower() for m in resp.get("memberships", []))
        req = api.list_next(req, resp)
    return out


def group_members_typed(ctx, group_email):
    """Group 直接成员 [(email, type)]；type 为 USER / SERVICE_ACCOUNT / GROUP / ...。读不到时返回 None。"""
    try:
        name = lookup_group(ctx, group_email)
    except Exception:  # noqa: BLE001
        return None
    if not name:
        return None
    out, api = [], ctx.ci.groups().memberships()
    req = api.list(parent=name, pageSize=200, view="FULL")
    try:
        while req is not None:
            resp = execute_with_backoff(req, desc=f"list members {group_email}")
            out.extend((m["preferredMemberKey"]["id"].lower(), m.get("type"))
                       for m in resp.get("memberships", []))
            req = api.list_next(req, resp)
    except HttpError as e:
        if e.resp.status in (403, 404):
            return None
        raise
    return out


def expand_group(ctx, group_email, max_depth=10):
    """递归展开 Group（含嵌套组），返回 core.expand_group 的 (members, unresolved)。"""
    cache = {}

    def fetch(g):
        if g not in cache:
            cache[g] = group_members_typed(ctx, g)
        return cache[g]
    return core.expand_group(group_email, fetch, max_depth=max_depth)


def add_group_member(ctx, group_name, email):
    """返回 True 表示新增。"""
    try:
        retry(lambda: ctx.ci.groups().memberships().create(
            parent=group_name,
            body={"preferredMemberKey": {"id": email}, "roles": [{"name": "MEMBER"}]}).execute(),
            desc=f"add {email}", retry_if=lambda e: not (isinstance(e, HttpError)
                                                          and e.resp.status == 409)
            and is_propagation_error(e))
        return True
    except HttpError as e:
        if e.resp.status == 409:
            return False
        raise


# --------------------------------------------------------------------------- #
# 挂载后验证
# --------------------------------------------------------------------------- #
def table_partitioning(tbl):
    """bigquery.Table -> visibility_probe_sql 需要的分区描述（无分区返回 None）。"""
    if tbl.time_partitioning:
        return {"require_filter": bool(tbl.require_partition_filter),
                "field": tbl.time_partitioning.field, "kind": "time"}
    if tbl.range_partitioning:
        return {"require_filter": bool(tbl.require_partition_filter),
                "field": tbl.range_partitioning.field, "kind": "range"}
    return None


def verify_full_access(ctx, table, sa_email, timeout=300, interval=10, mode="sample"):
    """
    以 sa_email 身份轮询探测查询，确认其命中了 FILTER TRUE 策略。返回 (status, detail)，
    status ∈ ok / fail / skip。
      sample（默认）: SELECT 1 ... LIMIT 1，看到任意一行即通过（扫描量极小；表要求分区过滤时自动加条件）
      count         : SELECT COUNT(*) 与元数据行数比对（大表成本高；含流式缓冲时以 >= 判断）
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
    start = time.time()
    last = ""
    while True:
        try:
            rows = list(client.query(sql, location=loc).result())
            if mode == "count":
                n = rows[0].n
                if n >= expected:
                    return "ok", f"{n} 行（{time.time() - start:.0f}s）"
                last = f"只可见 {n}/{expected} 行"
            else:
                if rows:
                    return "ok", f"可见数据（{time.time() - start:.0f}s）"
                last = "查询返回 0 行（未命中 TRUE 策略或 Group 尚未生效）"
        except Exception as e:  # noqa: BLE001
            last = str(e)[:200]
        if time.time() - start >= timeout:
            return "fail", f"{timeout}s 内未达到可见: {last}"
        log(f"    [verify] {table}: {last}")
        time.sleep(interval)


def condition_sas(ctx, condition_table):
    """条件表中出现的 sa（小写集合）。"""
    t = core.fq(condition_table)
    return {r.sa for r in run_query(ctx, f"SELECT DISTINCT LOWER(sa) AS sa FROM `{t}` WHERE sa IS NOT NULL",
                                     ctx.table_location(t))}


# --------------------------------------------------------------------------- #
# 角色 -> 权限 展开（带缓存）
# --------------------------------------------------------------------------- #
class RoleResolver:
    def __init__(self, iam):
        self.iam = iam
        self.cache = {}

    def permissions(self, role):
        if role in self.cache:
            return self.cache[role]
        perms = []
        try:
            if role.startswith("roles/"):
                r = self.iam.roles().get(name=role).execute()
            elif role.startswith("projects/"):
                r = self.iam.projects().roles().get(name=role).execute()
            elif role.startswith("organizations/"):
                r = self.iam.organizations().roles().get(name=role).execute()
            else:
                r = {}
            perms = r.get("includedPermissions", [])
        except HttpError as e:
            log(f"  [WARN] 无法获取角色 {role} 的权限: {getattr(e, 'reason', e)}")
            perms = ["bigquery.unknown"] if "bigquery" in role.lower() else []
        self.cache[role] = perms
        return perms

    def has_bq(self, role):
        return any(p.startswith("bigquery.") for p in self.permissions(role))


# --------------------------------------------------------------------------- #
# Group 生效探针
# --------------------------------------------------------------------------- #
def probe_group(ctx, group_email, probe_sa, dataset, timeout=600, interval=15):
    """
    在 dataset 下为 group 建一张探针表（1 行），挂 FILTER TRUE policy 只授予该 group，
    给 probe_sa 表级 dataViewer，然后以 probe_sa 身份查询，直到能看到 1 行
    （证明 BigQuery 已识别 probe_sa 的 group 成员关系）。
    前提: probe_sa 已加入 group；执行账号可扮演 probe_sa；probe_sa 有 jobUser。
    """
    p, d = dataset.split(".")
    local = core.sanitize_identifier(group_email.split("@")[0])
    table = f"{p}.{d}._rls_probe_{local}"
    loc = ctx.location(p, d)
    run_ddl(ctx, f"CREATE TABLE IF NOT EXISTS `{table}` AS SELECT 1 AS x", loc)
    run_ddl(ctx, core.build_policy_ddl(table, "probe", [f"group:{group_email}"], "TRUE"), loc)
    table_add_role(ctx, table, "roles/bigquery.dataViewer", f"serviceAccount:{probe_sa}")
    probe_client = bigquery.Client(project=ctx.project, credentials=impersonate(ctx.creds, probe_sa))
    deadline = time.time() + timeout
    while True:
        try:
            n = list(probe_client.query(f"SELECT COUNT(*) AS n FROM `{table}`",
                                        location=loc).result())[0].n
            if n == 1:
                return True
            log(f"    [probe] {group_email}: 仍不可见 (rows={n})")
        except Exception as e:  # noqa: BLE001
            log(f"    [probe] {group_email}: {str(e)[:150]}")
        if time.time() >= deadline:
            return False
        time.sleep(interval)


# --------------------------------------------------------------------------- #
# Cloud Asset Inventory：组织 / 文件夹范围的 SA 与 IAM 绑定盘点（不依赖项目列表）
# --------------------------------------------------------------------------- #
def asset_search_service_accounts(ctx, scope):
    """scope 内全部 SA（searchAllResources，assetType=iam.googleapis.com/ServiceAccount）。"""
    api, out = ctx.asset.v1(), []
    req = api.searchAllResources(scope=scope, assetTypes=["iam.googleapis.com/ServiceAccount"], pageSize=500)
    while req is not None:
        resp = execute_with_backoff(req, desc=f"searchAllResources {scope}")
        out.extend(resp.get("results", []))
        req = api.searchAllResources_next(req, resp)
    return out


def asset_search_iam_policies(ctx, scope, query):
    """scope 内命中 query 的 IAM 策略（组织 / 文件夹 / 项目 / 数据集 / 表 等任何层级）。"""
    api, out = ctx.asset.v1(), []
    req = api.searchAllIamPolicies(scope=scope, query=query, pageSize=500)
    while req is not None:
        resp = execute_with_backoff(req, desc=f"searchAllIamPolicies {scope}")
        out.extend(resp.get("results", []))
        req = api.searchAllIamPolicies_next(req, resp)
    return out


def bq_full_resource_name(ref):
    """'p.d.t' -> //bigquery.googleapis.com/projects/p/datasets/d/tables/t；'p.d' -> 数据集。"""
    parts = ref.replace(":", ".").split(".")
    base = f"//bigquery.googleapis.com/projects/{parts[0]}/datasets/{parts[1]}"
    return base + (f"/tables/{parts[2]}" if len(parts) == 3 else "")


def analyze_access(ctx, scope, full_resource_name, permissions):
    """
    analyzeIamPolicy：谁在 full_resource_name 上拥有 permissions 中任一权限。
    展开 Group（含嵌套）并包含资源层级上的继承绑定（组织 / 文件夹 / 项目 / 数据集）。
    返回 (analysisResults, fully_explored)。
    """
    req = ctx.asset.v1().analyzeIamPolicy(
        scope=scope,
        analysisQuery_resourceSelector_fullResourceName=full_resource_name,
        analysisQuery_accessSelector_permissions=list(permissions),
        analysisQuery_options_expandGroups=True,
        analysisQuery_options_outputGroupEdges=True)
    main = execute_with_backoff(req, desc=f"analyzeIamPolicy {full_resource_name}").get("mainAnalysis", {})
    return main.get("analysisResults", []), bool(main.get("fullyExplored"))
