"""单元测试用的假 GCP 环境：在内存里模拟表、RLS 规则、IAM、账号目录、Group、数据集 ACL。

install(monkeypatch, world) 会把 gcp_ops 里被业务脚本调用的函数替换成操作 world 的假实现，
因此业务脚本可以完整跑通（参数解析 → 计划 → 执行 DDL → 输出），但不访问 GCP。
"""

import re

from google.api_core.exceptions import NotFound

import gcp_ops as ops
import rls_core as core

_CREATE_RE = re.compile(
    r"CREATE OR REPLACE ROW ACCESS POLICY `(?P<name>[^`]+)`\s+ON `(?P<table>[^`]+)`\s+"
    r"GRANT TO \((?P<grant>.*?)\)\s+FILTER USING \((?P<filter>.*)\)\s*$", re.S)
_DROP_RE = re.compile(r"DROP ROW ACCESS POLICY `(?P<name>[^`]+)` ON `(?P<table>[^`]+)`")
_DROP_ALL_RE = re.compile(r"DROP ALL ROW ACCESS POLICIES ON `(?P<table>[^`]+)`")

# list_principals：常见角色的权限（只列与判断相关的；未列出的角色视为「读不到角色定义」）
GET_DATA = "bigquery.tables.getData"
DEFAULT_ROLE_PERMS = {
    "roles/owner": {GET_DATA, "resourcemanager.projects.get"}, "roles/editor": {GET_DATA}, "roles/viewer": {GET_DATA},
    "roles/bigquery.admin": {GET_DATA}, "roles/bigquery.dataOwner": {GET_DATA}, "roles/bigquery.dataEditor": {GET_DATA},
    "roles/bigquery.dataViewer": {GET_DATA}, "roles/bigquery.metadataViewer": {"bigquery.tables.get"},
    "roles/bigquery.jobUser": {"bigquery.jobs.create"}, "roles/bigquery.user": {"bigquery.jobs.create"},
    "roles/storage.admin": {"storage.buckets.get"},
}

# apply_bypass_rls.py 的登记表（adm_user_mem_copilot_tb）；add_table 默认把表登记为 rls_enabled=1
REG = "trip-bq-admin.bq_auth.adm_user_mem_copilot_tb"
REG_FIELDS = [("id", "STRING", "REQUIRED"), ("table_name", "STRING", "REQUIRED"), ("rls_enabled", "INTEGER", "REQUIRED"),
              ("status", "INTEGER", "REQUIRED"), ("create_time", "TIMESTAMP", "REQUIRED"),
              ("update_time", "TIMESTAMP", "REQUIRED")]


class FakeWorld:
    def __init__(self):
        self.tables = {}          # fq -> {"policies": [..], "schema": {..}, "rows": int}
        self.datasets = {}        # "p.d" -> [tables]
        self.ddl_log = []         # 执行过的 DDL
        self.fail_ddl_on = set()  # 这些表执行 DDL 时抛错
        # list_principals（全部权威 API）
        self.crm_children = {}    # "organizations/1" / "folders/2" -> {"folders": [...], "projects": [(id, state)]}
        self.org_customer = {}    # org id -> Cloud Identity customer id
        self.directory = {}       # customer id -> [user email]
        self.directory_error = None
        self.directory_calls = []  # [customer]
        self.project_sas = {}     # project -> [SA email]
        self.iam_policies = {}    # "organizations/1" / "folders/2" / "projects/p" -> [binding]
        self.dataset_acl = {}     # "p.d" -> [(role, entity_type, entity_id)]
        self.table_iam = {}       # "p.d.t" -> [binding]
        self.role_perms = {k: set(v) for k, v in DEFAULT_ROLE_PERMS.items()}
        self.role_errors = set()  # 读角色定义失败的角色
        self.role_lookups = {}    # role -> 查询次数
        self.groups = {}          # group email -> [(member, type)] 或 None（读不到）
        self.fail_resources = set()   # "sa:p" / "iam:projects/p" / "datasets:p" / "acl:p.d" / "tables:p.d" / "table_iam:p.d.t" / "crm:folders/1" / "customer:1"
        # copilot
        self.condition_fields = {}   # table -> [(name, type, mode)]
        self.condition_sas = {}      # table -> [email]
        self.mapping_rows = {}       # table -> [{"table_name","col_name","to_name"}]
        # bypass 登记表
        self.registry_rows = {REG: []}   # table -> [{"table_name","rls_enabled","status"}]
        self.registry_fields = {REG: list(REG_FIELDS)}
        # 验证
        self.visible = {}         # (table, sa) -> (n, total)
        self.verify_result = {}   # (table, sa) -> (status, detail)
        # API 调用计数（性能测量用）
        self.calls = {"list_policies": 0, "policy_iam": 0, "ddl": 0, "get_table": 0, "list_tables": 0,
                      "dataset_acl": 0, "group": 0, "query": 0, "crm": 0, "iam_policy": 0, "sa_list": 0,
                      "datasets": 0, "table_iam": 0, "role": 0, "directory": 0}
        self.latency = {}         # 可选：每类调用的模拟耗时（秒），用于估算
        import threading
        self._lock = threading.Lock()
        self._ddl_lock = threading.RLock()
        self.ddl_hook = None          # 可选：每次执行 DDL 前调用 ddl_hook(ddl)，用于模拟中断 / 表被删除等

    # ---- 构造辅助 ----
    def add_table(self, fq, policies=(), schema=None, rows=10, rls_enabled=1):
        """rls_enabled：登记到 REG 的值；None 表示不登记。"""
        p, d, _ = core.parse_table(fq)
        self.tables[fq] = {"policies": [dict(x) for x in policies],
                           "schema": schema or {}, "rows": rows}
        self.datasets.setdefault(f"{p}.{d}", []).append(fq)
        if rls_enabled is not None:
            self.register(fq, rls_enabled)
        return self

    def register(self, table_name, rls_enabled=1, status=1, registry=REG):
        self.registry_rows.setdefault(registry, []).append(
            {"table_name": table_name, "rls_enabled": rls_enabled, "status": status})
        return self

    def unregister(self, table_name, registry=REG):
        self.registry_rows[registry] = [r for r in self.registry_rows[registry] if r["table_name"] != table_name]
        return self

    def policies(self, fq):
        return self.tables[fq]["policies"]

    def policy(self, fq, name):
        return next((p for p in self.policies(fq) if p["id"] == name), None)

    def hit(self, kind, n=1):
        with self._lock:
            self.calls[kind] = self.calls.get(kind, 0) + n
        if self.latency.get(kind):
            import time
            time.sleep(self.latency[kind] * n)

    def list_policies(self, table, grantees_for=None):
        self.hit("list_policies")
        t = core.fq(table)
        if t not in self.tables:
            raise RuntimeError(f"404 Not found: Table {t}")
        with self._ddl_lock:
            pols = [dict(p) for p in self.policies(t)]
        out = []
        for p in pols:
            want = grantees_for is None or p["id"] in grantees_for
            if want:
                self.hit("policy_iam")
            out.append({"id": p["id"], "filter": p["filter"], "grantees": list(p["grantees"]) if want else None})
        return out

    # ---- DDL 解释器 ----
    def run_ddl(self, ddl):
        self.hit("ddl")
        with self._ddl_lock:                      # 真实 BigQuery 的单条 DDL 是原子的
            self._run_ddl(ddl)

    def _run_ddl(self, ddl):
        if self.ddl_hook:
            self.ddl_hook(ddl)
        self.ddl_log.append(ddl)
        m = _CREATE_RE.match(ddl.strip())
        if m:
            t = m["table"]
            if t in self.fail_ddl_on:
                raise RuntimeError(f"boom on {t}")
            grantees = re.findall(r'"([^"]+)"', m["grant"])
            pols = self.policies(t)
            pols[:] = [p for p in pols if p["id"] != m["name"]]
            pols.append({"id": m["name"], "filter": m["filter"], "grantees": grantees})
            return
        m = _DROP_RE.match(ddl.strip())
        if m:
            t = m["table"]
            if t in self.fail_ddl_on:
                raise RuntimeError(f"boom on {t}")
            pols = self.policies(t)
            if len(pols) == 1:
                raise RuntimeError("use a DROP ALL statement instead")
            pols[:] = [p for p in pols if p["id"] != m["name"]]
            return
        m = _DROP_ALL_RE.match(ddl.strip())
        if m:
            t = m["table"]
            if t in self.fail_ddl_on:
                raise RuntimeError(f"boom on {t}")
            self.policies(t).clear()
            return
        raise AssertionError(f"无法解析的 DDL: {ddl}")


def fake_auth(gcloud_account=None, quota_project=None):
    """替代 gcp_auth.resolve_auth：不访问 gcloud。"""
    from gcp_auth import Auth
    return Auth(object(), gcloud_account or "tester@x.com", "--gcloud-account" if gcloud_account else "fake",
                quota_project or "fake-quota", "--quota-project" if quota_project else "fake")


class FakeCtx:
    def __init__(self, creds=None, project=None):
        self.creds, self.project = creds, project

    def table_location(self, table):
        return "US"


def install(monkeypatch, world, script_module=None):
    """替换 gcp_ops 中业务脚本会调用的函数；script_module 给出时同时替换它的 resolve_auth。"""
    monkeypatch.setattr(ops, "Ctx", FakeCtx)
    if script_module is not None:
        monkeypatch.setattr(script_module, "resolve_auth", fake_auth)

    def expand_tables(ctx, tables, datasets, projects):
        out = [core.fq(t) for t in tables]
        for d in datasets:
            p, ds = core.parse_dataset(d)
            world.hit("list_tables")
            out += world.datasets.get(f"{p}.{ds}", [])
        for p in projects:
            for key, ts in world.datasets.items():
                if key.split(".")[0] == p:
                    world.hit("list_tables")
                    out += ts
        return list(dict.fromkeys(out))

    monkeypatch.setattr(ops, "expand_tables", expand_tables)
    monkeypatch.setattr(ops, "list_policies",
                        lambda ctx, t, grantees_for=None, workers=4: world.list_policies(t, grantees_for))
    monkeypatch.setattr(ops, "run_ddl", lambda ctx, ddl, loc: world.run_ddl(ddl))
    monkeypatch.setattr(ops, "verify_full_access",
                        lambda ctx, t, sa, timeout=300, mode="sample":
                        world.verify_result.get((t, sa), ("ok", "可见数据（0s）")))
    monkeypatch.setattr(ops, "count_visible",
                        lambda ctx, t, sa: world.visible.get((t, sa), (0, world.tables[t]["rows"])))
    def table_schema(ctx, t):
        world.hit("get_table")
        t = core.fq(t)
        if t not in world.tables:                 # 与真实 BigQuery 客户端一致：表不存在抛 NotFound（404）
            raise NotFound(f"Not found: Table {t}")
        return world.tables[t]["schema"]

    monkeypatch.setattr(ops, "table_schema", table_schema)
    monkeypatch.setattr(ops, "table_exists",
                        lambda ctx, t: core.fq(t) in world.tables or core.fq(t) in world.condition_fields
                        or core.fq(t) in world.mapping_rows or core.fq(t) in world.registry_rows)

    def table_fields(ctx, t):
        t = core.fq(t)
        return world.registry_fields[t] if t in world.registry_fields else world.condition_fields[t]

    monkeypatch.setattr(ops, "table_fields", table_fields)

    def read_registry_rows(ctx, t):
        world.hit("query")
        return [{"table_name": r["table_name"], "rls_enabled": r["rls_enabled"]}
                for r in world.registry_rows[core.fq(t)]]

    monkeypatch.setattr(ops, "read_registry_rows", read_registry_rows)
    def condition_sa_counts(ctx, t):
        world.hit("query")
        out = {}
        for v in world.condition_sas[core.fq(t)]:
            if v and v.strip():
                out[v] = out.get(v, 0) + 1
        return out

    def read_mapping_rows(ctx, t):
        world.hit("query")
        return [dict(r) for r in world.mapping_rows[core.fq(t)]]

    monkeypatch.setattr(ops, "condition_sa_counts", condition_sa_counts)
    monkeypatch.setattr(ops, "read_mapping_rows", read_mapping_rows)

    def guard(key):
        if key in world.fail_resources:
            raise RuntimeError(f"403 Permission denied on {key}")

    def list_org_descendants(ctx, org_id):
        folders, active, inactive = [], [], []
        todo = [f"organizations/{org_id}"]
        while todo:
            parent = todo.pop(0)
            guard(f"crm:{parent}")
            world.hit("crm")
            node = world.crm_children.get(parent, {"folders": [], "projects": []})
            folders += node["folders"]
            todo += node["folders"]
            for pid, state in node["projects"]:
                (active if state == "ACTIVE" else inactive).append(pid)
        return folders, active, inactive

    def org_directory_customer(ctx, org_id):
        guard(f"customer:{org_id}")
        return world.org_customer[org_id]

    def directory_users(ctx, customer):
        world.hit("directory")
        with world._lock:
            world.directory_calls.append(customer)
        if world.directory_error:
            raise world.directory_error
        return list(world.directory.get(customer, []))

    def resource_iam_bindings(ctx, resource):
        guard(f"iam:{resource}")
        world.hit("iam_policy")
        return [dict(x) for x in world.iam_policies.get(resource, [])]

    def project_service_accounts(ctx, project):
        guard(f"sa:{project}")
        world.hit("sa_list")
        return list(world.project_sas.get(project, []))

    def project_datasets(ctx, project):
        guard(f"datasets:{project}")
        world.hit("datasets")
        return sorted(k for k in world.datasets if k.split(".")[0] == project)

    def dataset_access(ctx, d):
        guard(f"acl:{d}")
        world.hit("dataset_acl")
        return list(world.dataset_acl.get(d, []))

    def dataset_tables(ctx, d):
        guard(f"tables:{d}")
        world.hit("list_tables")
        return list(world.datasets.get(d, []))

    def table_iam_bindings(ctx, t):
        guard(f"table_iam:{t}")
        world.hit("table_iam")
        return [dict(x) for x in world.table_iam.get(t, [])]

    def role_permissions(ctx, role):
        world.hit("role")
        with world._lock:
            world.role_lookups[role] = world.role_lookups.get(role, 0) + 1
        if role in world.role_errors or role not in world.role_perms:
            raise RuntimeError(f"404 role {role} not found or permission denied")
        return set(world.role_perms[role])

    def expand_group(ctx, g, max_depth=10):
        def fetch(x):
            world.hit("group")
            return world.groups.get(x)
        return core.expand_group(g, fetch, max_depth)

    for name, fn in (("list_org_descendants", list_org_descendants), ("org_directory_customer", org_directory_customer),
                     ("directory_users", directory_users), ("resource_iam_bindings", resource_iam_bindings),
                     ("project_service_accounts", project_service_accounts), ("project_datasets", project_datasets),
                     ("dataset_access", dataset_access), ("dataset_tables", dataset_tables),
                     ("table_iam_bindings", table_iam_bindings), ("role_permissions", role_permissions),
                     ("expand_group", expand_group)):
        monkeypatch.setattr(ops, name, fn)
