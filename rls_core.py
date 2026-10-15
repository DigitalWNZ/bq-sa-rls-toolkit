"""
RLS 工具集的纯逻辑核心（不访问 GCP，便于单元测试）。

包含：输入解析、权限读写分类、Copilot SA 防混入、白名单/Copilot RLS DDL 生成、
策略合并计划、回退计划、巡检、SA 配额校验、作业历史 SQL。
"""

import fnmatch
import re
from dataclasses import dataclass, field

BYPASS_POLICY = "rls_bypass_full_access"
COPILOT_POLICY = "rls_copilot_subquery_policy"
DIMENSIONS = ("region", "prdtype", "refername")
SA_PER_PROJECT_LIMIT = 100

READ_PERMISSION = "bigquery.tables.getData"
WRITE_PERMISSION = "bigquery.tables.updateData"
RLS_GRANTEE_ROLE = "roles/bigquery.filteredDataViewer"

_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*$")
_DATASET_RE = re.compile(r"^[A-Za-z0-9_]+$")
_TABLE_RE = re.compile(r"^[A-Za-z0-9_\-$]+$")
_COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REGION_RE = re.compile(r"^[a-z0-9\-]+$")
_SA_ID_RE = re.compile(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$")
_GRANTEE_RE = re.compile(r"^[A-Za-z]+:[^\"'`\s]+$|^allUsers$|^allAuthenticatedUsers$")
_SPECIAL_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


# --------------------------------------------------------------------------- #
# 输入解析
# --------------------------------------------------------------------------- #
def split_items(values):
    """按逗号/空白拆分，支持 ["a,b", "c d"] -> [a, b, c, d]。"""
    out = []
    for v in values:
        out.extend(x for x in str(v).replace(",", " ").split() if x)
    return out


def read_list_file(path):
    with open(path) as f:
        return split_items(l for l in f if not l.strip().startswith("#"))


def normalize_member(m, default_prefix="group"):
    """
    规范化 IAM 主体:
      - 无前缀邮箱: *.gserviceaccount.com -> serviceAccount:，其他 -> default_prefix:
      - 有前缀: 保留前缀，邮箱小写
      - allUsers / allAuthenticatedUsers / deleted:... 原样保留
    """
    m = m.strip()
    if m in _SPECIAL_MEMBERS or m.startswith("deleted:"):
        return m
    if ":" not in m:
        prefix = "serviceAccount" if m.lower().endswith("gserviceaccount.com") else default_prefix
        return f"{prefix}:{m.lower()}"
    prefix, _, rest = m.partition(":")
    return f"{prefix}:{rest.lower()}"


def member_email(m):
    """'serviceAccount:x@y' -> 'x@y'；无前缀原样返回（小写）。"""
    return m.split(":")[-1].lower() if ":" in m else m.lower()


def parse_table(ref, default_project=None):
    """'p.d.t' / 'p:d.t' / 'd.t'(需 default_project) -> (p, d, t)，并校验标识符防注入。"""
    parts = ref.strip().replace(":", ".").split(".")
    if len(parts) == 2 and default_project:
        parts = [default_project] + parts
    if len(parts) != 3:
        raise ValueError(f"表名格式应为 project.dataset.table: {ref}")
    p, d, t = parts
    if not (_PROJECT_RE.match(p) and _DATASET_RE.match(d) and _TABLE_RE.match(t)):
        raise ValueError(f"非法的表标识符: {ref}")
    return p, d, t


def fq(table, default_project=None):
    return ".".join(parse_table(table, default_project))


# --------------------------------------------------------------------------- #
# 权限分类
# --------------------------------------------------------------------------- #
def classify_permissions(perms):
    """返回 (can_read, can_write)。"""
    perms = set(perms)
    return READ_PERMISSION in perms, WRITE_PERMISSION in perms


_LEGACY_DATASET_ROLES = {
    "READER": (True, False),
    "WRITER": (True, True),
    "OWNER": (True, True),
}


def classify_legacy_dataset_role(role):
    """数据集 ACL 中的 legacy 角色 -> (read, write)；非 legacy（roles/...）返回 None，由调用方展开。"""
    return _LEGACY_DATASET_ROLES.get(role)


# --------------------------------------------------------------------------- #
# Copilot SA 防混入
# --------------------------------------------------------------------------- #
def is_copilot_member(member, copilot_members=(), copilot_patterns=()):
    email = member_email(member)
    explicit = {member_email(c) for c in copilot_members}
    return email in explicit or any(fnmatch.fnmatch(email, p.lower()) for p in copilot_patterns)


def filter_whitelist_members(members, copilot_members=(), copilot_patterns=()):
    """返回 (allowed, rejected)，rejected 为命中 Copilot SA 名单/模式的主体。"""
    allowed, rejected = [], []
    for m in members:
        (rejected if is_copilot_member(m, copilot_members, copilot_patterns) else allowed).append(m)
    return allowed, rejected


_SERVICE_AGENT_RE = re.compile(
    r"^(service-\d+@.+\.gserviceaccount\.com"          # service-<项目号>@<服务>.iam.gserviceaccount.com
    r"|[^@]+@gcp-sa-[a-z0-9\-]+\.iam\.gserviceaccount\.com"  # 任意前缀@gcp-sa-*（如 BigQuery 连接 bqcx-*）
    r"|\d+@(cloudservices|cloudbuild)\.gserviceaccount\.com)$")


def is_service_agent(member):
    """Google 托管的服务代理（service-<项目号>@gcp-sa-*.iam.gserviceaccount.com 等）。"""
    return bool(_SERVICE_AGENT_RE.match(member_email(member)))


IMPERSONATION_PERMISSIONS = {
    "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.getOpenIdToken",
}


def impersonation_risks(bindings, role_permissions, allowed=()):
    """
    项目级 IAM 中能扮演项目内任意 SA 的主体（会绕过"只有 API SA 能扮演权限 SA"的设计）。
    role_permissions: role -> 权限列表 的函数。返回 [(member, role)]（排序）。
    """
    allowed = {member_email(a) for a in allowed}
    risks = set()
    for b in bindings:
        if not IMPERSONATION_PERMISSIONS & set(role_permissions(b["role"]) or []):
            continue
        for m in b.get("members", []):
            if member_email(m) not in allowed:
                risks.add((normalize_member(m), b["role"]))
    return sorted(risks)


def build_sa_whitelist_rows(sas, group, copilot_members=(), copilot_patterns=(),
                            include_disabled=False):
    """
    把项目内（及 IAM 绑定中出现的）全部 SA 生成白名单候选行，列与 scan_bq_access.py 的 CSV 兼容。
    sas: [{"email","project","display_name","disabled","source"}]；同一 SA 多次出现会合并来源。
    排除：Copilot SA；已禁用 SA（除非 include_disabled）。
    """
    if group not in ("write", "read"):
        raise ValueError(f"group 只能是 write 或 read: {group}")
    merged = {}
    for s in sas:
        email = s["email"].lower()
        m = merged.setdefault(email, {"display_name": s.get("display_name") or "",
                                      "disabled": bool(s.get("disabled")), "sources": []})
        src = f"{s.get('project', '')}:{s.get('source', 'project-sa')}"
        if src not in m["sources"]:
            m["sources"].append(src)
    rows = []
    for email, m in sorted(merged.items()):
        principal = f"serviceAccount:{email}"
        copilot = is_copilot_member(principal, copilot_members, copilot_patterns)
        notes, suggested = [], group
        if copilot:
            suggested = ""
            notes.append("Copilot SA，已排除出白名单")
        elif m["disabled"] and not include_disabled:
            suggested = ""
            notes.append("SA 已禁用，默认不加入（--include-disabled 可加入）")
        if is_service_agent(principal):
            notes.append("Google 托管服务代理")
        rows.append({
            "principal": principal, "principal_type": "serviceAccount",
            "can_read": "", "can_write": "", "suggested_group": suggested,
            "sources": "; ".join(m["sources"]), "jobs_read_count": 0, "jobs_write_count": 0,
            "copilot": copilot, "note": "; ".join(notes),
            "display_name": m["display_name"], "disabled": m["disabled"],
        })
    return rows


# --------------------------------------------------------------------------- #
# DDL 生成
# --------------------------------------------------------------------------- #
def _validate_grantees(grantees):
    if not grantees:
        raise ValueError("GRANT TO 至少需要一个授权对象")
    for g in grantees:
        if not _GRANTEE_RE.match(g):
            raise ValueError(f"非法的授权对象: {g}")


def build_policy_ddl(table, policy_name, grantees, filter_sql):
    if not _COLUMN_RE.match(policy_name):
        raise ValueError(f"非法的 policy 名称: {policy_name}")
    _validate_grantees(grantees)
    grant = ", ".join(f'"{g}"' for g in grantees)
    return (f"CREATE OR REPLACE ROW ACCESS POLICY `{policy_name}`\n"
            f"ON `{fq(table)}`\n"
            f"GRANT TO ({grant})\n"
            f"FILTER USING ({filter_sql})")


def sanitize_identifier(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


def build_bypass_policy_ddl(table, grantees, policy_name=BYPASS_POLICY):
    return build_policy_ddl(table, policy_name, grantees, "TRUE")


def _validate_column_path(col):
    parts = col.split(".")
    if not all(_COLUMN_RE.match(x) for x in parts):
        raise ValueError(f"非法的列名: {col}")
    return parts


def _validate_mapping(mapping):
    if not mapping:
        raise ValueError("过滤字段映射为空")
    for col, dim in mapping:
        if dim not in DIMENSIONS:
            raise ValueError(f"未知维度 {dim}，只支持 {DIMENSIONS}")
        _validate_column_path(col)


def _column_expr(col, column_types):
    expr = ".".join(f"`{x}`" for x in _validate_column_path(col))
    ctype = (column_types or {}).get(col)
    if ctype and ctype != "STRING":
        expr = f"CAST({expr} AS STRING)"
    return expr


def build_copilot_filter(mapping, condition_table, column_types=None, case_insensitive=False):
    """
    mapping: [(目标表列名, 维度名)]，列名可为嵌套路径 a.b；维度名 ∈ region/prdtype/refername。
    column_types: {列名: BigQuery 类型}，非 STRING 列会 CAST 为 STRING 再与条件表匹配。
    case_insensitive: 两侧都用 UPPER() 比较（R6 大小写标准化）。
    每个维度：列值 ∈ UNNEST(条件数组)，或条件数组为 NULL/空 时全量放行；多维度 AND。
    """
    _validate_mapping(mapping)
    cond = fq(condition_table)
    clauses = []
    for col, dim in mapping:
        lhs, rhs = _column_expr(col, column_types), "v"
        if case_insensitive:
            lhs, rhs = f"UPPER({lhs})", "UPPER(v)"
        clauses.append(
            f"({lhs} IN (SELECT {rhs} FROM `{cond}` AS c, "
            f"UNNEST(c.{dim}) AS v WHERE c.sa = SESSION_USER()) "
            f"OR EXISTS (SELECT 1 FROM `{cond}` AS c WHERE c.sa = SESSION_USER() "
            f"AND (c.{dim} IS NULL OR ARRAY_LENGTH(c.{dim}) = 0)))")
    return " AND ".join(clauses)


def build_copilot_policy_ddl(table, mapping, condition_table, grantees,
                             policy_name=COPILOT_POLICY, column_types=None, case_insensitive=False):
    return build_policy_ddl(table, policy_name, grantees,
                            build_copilot_filter(mapping, condition_table, column_types,
                                                 case_insensitive))


_TYPE_ALIASES = {"INTEGER": "INT64", "FLOAT": "FLOAT64", "BOOLEAN": "BOOL", "STRUCT": "RECORD"}
_FILTERABLE_TYPES = {"STRING", "INT64", "NUMERIC", "BIGNUMERIC", "BOOL", "DATE"}


def flatten_schema(fields, prefix=""):
    """bigquery SchemaField 列表 -> {路径: (类型, mode)}，嵌套字段用 a.b 表示。"""
    out = {}
    for f in fields:
        path = f"{prefix}{f.name}"
        ftype = _TYPE_ALIASES.get(f.field_type, f.field_type)
        out[path] = (ftype, f.mode or "NULLABLE")
        if f.fields:
            out.update(flatten_schema(f.fields, prefix=f"{path}."))
    return out


def validate_mapping_against_schema(mapping, schema):
    """校验映射的列在表中存在、非 REPEATED（含父字段）、类型可用于等值过滤。返回错误列表。"""
    errors = []
    for col, dim in mapping:
        if col not in schema:
            errors.append(f"列 {col}（维度 {dim}）在表中不存在")
            continue
        parts = col.split(".")
        repeated = [".".join(parts[:i]) for i in range(1, len(parts) + 1)
                    if schema.get(".".join(parts[:i]), ("", ""))[1] == "REPEATED"]
        ftype = schema[col][0]
        if repeated:
            errors.append(f"列 {col} 位于 REPEATED 字段 {repeated[0]} 中，不支持行级过滤")
        elif ftype == "RECORD":
            errors.append(f"列 {col} 是 RECORD，请映射到其中的具体子字段")
        elif ftype not in _FILTERABLE_TYPES:
            errors.append(f"列 {col} 类型 {ftype} 不支持（支持 {sorted(_FILTERABLE_TYPES)}）")
    return errors


def parse_mapping_rows(rows, default_project=None):
    """
    adm_user_mem_copilot_tb_col_mapping 行 -> {fq_table: [(col_name, to_name), ...]}
    """
    out = {}
    for r in rows:
        table = fq(r["table_name"], default_project)
        dim = str(r["to_name"]).strip().lower()
        col = str(r["col_name"]).strip()
        _validate_mapping([(col, dim)])
        lst = out.setdefault(table, [])
        if (col, dim) not in lst:
            lst.append((col, dim))
    return out


# --------------------------------------------------------------------------- #
# 策略合并计划
# --------------------------------------------------------------------------- #
_STRING_LITERAL_RE = re.compile(r"('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")")
_PUNCT_SPACE_RE = re.compile(r"\s*([(),.=<>+\-*/])\s*")


def normalize_filter(s):
    """
    规范化过滤条件以便比较：BigQuery 存储时会重新排版（去掉简单标识符的反引号、换行缩进、
    'EXISTS (' -> 'EXISTS('）。字符串字面量之外：去反引号、统一小写、压缩空白、去掉标点两侧空白；
    字符串字面量原样保留（'HK' 与 'hk' 不同）。
    """
    out = []
    for i, part in enumerate(_STRING_LITERAL_RE.split(str(s))):
        if i % 2:          # 字符串字面量
            out.append(part)
            continue
        part = " ".join(part.replace("`", "").lower().split())
        out.append(_PUNCT_SPACE_RE.sub(r"\1", part))
    norm = "".join(out).strip()
    return "TRUE" if norm == "true" else norm


@dataclass
class PolicyPlan:
    action: str               # create / noop / replace / conflict
    grantees: list
    first_policy: bool
    reason: str = ""


def plan_policy_upsert(existing, policy_name, filter_sql, grantees, merge=False):
    """
    existing: [{"id","filter","grantees"}]
    - 不存在同名 policy -> create
    - 同名且过滤条件、授权对象一致 -> noop
    - 同名但授权对象不同: merge=True -> replace(并集)，否则 conflict
    - 同名但过滤条件不同 -> conflict（避免覆盖别人的 policy）
    """
    want = list(dict.fromkeys(normalize_member(g) for g in grantees))
    first = len(existing) == 0
    cur = next((p for p in existing if p["id"] == policy_name), None)
    if cur is None:
        return PolicyPlan("create", want, first)
    if normalize_filter(cur["filter"]) != normalize_filter(filter_sql):
        return PolicyPlan("conflict", want, first,
                          f"同名 policy 过滤条件不同: {cur['filter']}")
    have = {normalize_member(g) for g in cur["grantees"]}
    if have == set(want):
        return PolicyPlan("noop", sorted(have), first)
    if not merge:
        return PolicyPlan("conflict", want, first,
                          f"同名 policy 授权对象不同: {sorted(have)}")
    union = sorted(have | set(want))
    if set(union) == have:
        return PolicyPlan("noop", union, first)
    return PolicyPlan("replace", union, first)


# --------------------------------------------------------------------------- #
# 回退计划
# --------------------------------------------------------------------------- #
@dataclass
class RollbackPlan:
    to_drop: list = field(default_factory=list)
    to_update: list = field(default_factory=list)   # [(policy, remaining_grantees)]
    drop_all: bool = False


def plan_rollback(policies, members, strip_only=False, policy_names=None):
    """
    members 为空 -> 删除（policy_names 范围内的）全部 policy
    否则       -> 删除授权对象含任一 member 的 policy；strip_only 时仅剥离这些 member
    drop_all: 表上所有 policy 都将被删除（需用 DROP ALL，规避"不能删最后一条"的限制）
    """
    members = {normalize_member(m) for m in members}
    candidates = [p for p in policies if not policy_names or p["id"] in policy_names]
    plan = RollbackPlan()
    for p in candidates:
        if not members:
            plan.to_drop.append(p)
            continue
        norm = [normalize_member(g) for g in p["grantees"]]
        if not set(norm) & members:
            continue
        others = [g for g, n in zip(p["grantees"], norm) if n not in members]
        if strip_only and others:
            plan.to_update.append((p, others))
        else:
            plan.to_drop.append(p)
    plan.drop_all = bool(plan.to_drop) and len(plan.to_drop) == len(policies)
    return plan


# --------------------------------------------------------------------------- #
# 巡检
# --------------------------------------------------------------------------- #
def inspect_policies(policies, bypass_grantees, copilot_grantees, expected_copilot_filter,
                     bypass_name=BYPASS_POLICY, copilot_name=COPILOT_POLICY):
    """返回问题列表（空 = 正常）。expected_copilot_filter 为 None 时不检查 Copilot policy。"""
    issues = []
    by_id = {p["id"]: p for p in policies}

    def check(name, grantees, expected_filter, filter_desc):
        p = by_id.get(name)
        if p is None:
            issues.append(f"`{name}` 缺失")
            return
        if normalize_filter(p["filter"]) != normalize_filter(expected_filter):
            issues.append(f"`{name}` {filter_desc}: {p['filter']}")
        have = {normalize_member(g) for g in p["grantees"]}
        for g in grantees:
            if normalize_member(g) not in have:
                issues.append(f"`{name}` 缺少授权对象 {g}")

    check(bypass_name, bypass_grantees, "TRUE", "过滤条件不是 TRUE")
    if expected_copilot_filter is not None:
        check(copilot_name, copilot_grantees, expected_copilot_filter, "过滤条件与映射表不一致")
    return issues


def inspect_whitelist_membership(group_members, copilot_members=(), copilot_patterns=()):
    """group_members: {group: [members]}；返回白名单组中混入 Copilot SA 的问题。"""
    issues = []
    for group, members in group_members.items():
        _, bad = filter_whitelist_members(members, copilot_members, copilot_patterns)
        issues.extend(f"白名单组 {group} 中混入 Copilot SA: {m}" for m in bad)
    return issues


# --------------------------------------------------------------------------- #
# 其他
# --------------------------------------------------------------------------- #
def check_sa_quota(existing, to_create, limit=SA_PER_PROJECT_LIMIT):
    if existing + to_create > limit:
        raise ValueError(
            f"SA 数量将达到 {existing + to_create}，超过单项目默认上限 {limit}；"
            f"请复用 SA 或申请配额")


def sa_account_id(s):
    aid = s.split("@")[0].strip().lower() if "@" in s else s.strip()
    if not _SA_ID_RE.match(aid):
        raise ValueError(f"非法的 SA account id（6-30 位小写字母/数字/-，字母开头）: {s}")
    return aid


def sa_email(account_id, project):
    return f"{sa_account_id(account_id)}@{project}.iam.gserviceaccount.com"


_JOBS_VIEWS = {"project": "JOBS_BY_PROJECT", "organization": "JOBS_BY_ORGANIZATION"}


def _jobs_view(project, region, scope):
    if not _PROJECT_RE.match(project) or not _REGION_RE.match(region):
        raise ValueError(f"非法的 project/region: {project} / {region}")
    if scope not in _JOBS_VIEWS:
        raise ValueError(f"scope 只能是 {sorted(_JOBS_VIEWS)}: {scope}")
    return f"`{project}`.`region-{region}`.INFORMATION_SCHEMA.{_JOBS_VIEWS[scope]}"


def jobs_access_sql(project, region, days, scope="project"):
    """
    统计最近 N 天真实读/写过目标表的账号（参数 @tables: ARRAY<STRING> of 'p.d.t'）。
    READ: referenced_tables 包含目标表；WRITE: destination_table 为目标表的 LOAD/COPY/DML/CTAS。
    scope=organization 时查 JOBS_BY_ORGANIZATION（需要组织级 bigquery.jobs.listAll），可覆盖跨项目作业。
    """
    return f"""
WITH j AS (
  SELECT user_email, job_type, statement_type, referenced_tables, destination_table
  FROM {_jobs_view(project, region, scope)}
  WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {int(days)} DAY)
),
acc AS (
  SELECT user_email, CONCAT(t.project_id, '.', t.dataset_id, '.', t.table_id) AS tbl, 'READ' AS mode
  FROM j, UNNEST(referenced_tables) AS t
  UNION ALL
  SELECT user_email,
         CONCAT(destination_table.project_id, '.', destination_table.dataset_id, '.',
                destination_table.table_id) AS tbl,
         'WRITE' AS mode
  FROM j
  WHERE destination_table.table_id IS NOT NULL
    AND (job_type IN ('LOAD', 'COPY')
         OR statement_type IN ('INSERT', 'UPDATE', 'DELETE', 'MERGE',
                               'CREATE_TABLE_AS_SELECT', 'TRUNCATE_TABLE'))
)
SELECT LOWER(user_email) AS user_email, tbl, mode, COUNT(*) AS job_count
FROM acc
WHERE tbl IN UNNEST(@tables)
GROUP BY 1, 2, 3
"""


# --------------------------------------------------------------------------- #
# C1 挂载后验证 / 探针：按分区要求生成探测 SQL
# --------------------------------------------------------------------------- #
def visibility_probe_sql(table, partitioning, mode="sample"):
    """
    partitioning: None 或 {"require_filter": bool, "field": str|None, "kind": "time"|"range"}
    mode=sample: SELECT 1 ... LIMIT 1（能看到任意一行即说明命中了 TRUE 策略，扫描量极小）
    mode=count : SELECT COUNT(*)（用于与元数据行数比对，大表成本高）
    表要求分区过滤时自动加 <分区列> IS NOT NULL（摄取时间分区用 _PARTITIONTIME）。
    """
    where = ""
    if partitioning and partitioning.get("require_filter"):
        field = partitioning.get("field")
        col = f"`{field}`" if field else "_PARTITIONTIME"
        where = f" WHERE {col} IS NOT NULL"
    if mode == "count":
        return f"SELECT COUNT(*) AS n FROM `{fq(table)}`{where}"
    return f"SELECT 1 FROM `{fq(table)}`{where} LIMIT 1"


# --------------------------------------------------------------------------- #
# C3 Reservation 版本前置检查
# --------------------------------------------------------------------------- #
def edition_usage_sql(project, region, days=7):
    """最近 N 天查询作业按 edition / reservation 的分布（edition 为 NULL 表示按需）。"""
    return f"""
SELECT edition, reservation_id, COUNT(*) AS n
FROM {_jobs_view(project, region, "project")}
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {int(days)} DAY)
  AND job_type = 'QUERY'
GROUP BY 1, 2
"""


def standard_edition_usage(rows):
    """返回 [(reservation_id, 作业数)]，仅 STANDARD 版本（RLS 不支持 Standard，查询会失败）。"""
    return [(r.get("reservation_id"), r.get("n", 0)) for r in rows
            if (r.get("edition") or "").upper() == "STANDARD"]


# --------------------------------------------------------------------------- #
# E2 巡检：Copilot SA 归属 / 条件行 / API SA / 条件表聚簇
# --------------------------------------------------------------------------- #
def inspect_copilot_membership(group_members, condition_sas, api_sa=None):
    """
    group_members: {copilot_group: {sa_email}}；condition_sas: 条件表中出现的 sa（小写）
    返回 (issues, warnings)：
      issue  : SA 同时在多个 Copilot 组；API SA 出现在 Copilot 组
      warning: Copilot 组成员没有条件行（会查不到任何数据）；条件行的 sa 不在任何 Copilot 组
    """
    issues, warns = [], []
    where = {}
    for g, members in group_members.items():
        for m in members:
            where.setdefault(member_email(m), []).append(g)
    api = member_email(api_sa) if api_sa else None
    cond = {s.lower() for s in condition_sas}
    for sa, groups in sorted(where.items()):
        if len(groups) > 1:
            issues.append(f"{sa} 同时属于多个 Copilot 组 {sorted(groups)}（约定一 SA 一组）")
        if api and sa == api:
            issues.append(f"API SA {sa} 出现在 Copilot 组 {sorted(groups)} 中（API SA 不应直接查询）")
        elif sa not in cond:
            warns.append(f"{sa} 在 Copilot 组中但条件表没有条件行（该 SA 将查不到任何数据）")
    for sa in sorted(cond - set(where)):
        warns.append(f"条件表中的 {sa} 不在任何 Copilot 组（没有表级权限，条件不会生效）")
    return issues, warns


def inspect_condition_clustering(clustering_fields):
    fields = list(clustering_fields or [])
    if not fields or fields[0] != "sa":
        return [f"条件表未按 sa 聚簇（当前 CLUSTER BY {fields or '无'}），RLS 子查询会扫描整表"]
    return []


# --------------------------------------------------------------------------- #
# E3 通配符表查询检测（R5：有 RLS 的表不支持 table_* 查询）
# --------------------------------------------------------------------------- #
def wildcard_pattern(datasets):
    """
    匹配 SQL 文本中对目标数据集的通配符表引用，如 `proj.dw.fact_*` 或 dw.events_*。
    datasets: ['project.dataset', ...]；项目限定可选（同名数据集的跨项目引用也会命中，宁多勿漏）。
    """
    alts = []
    for d in datasets:
        p, ds = d.replace(":", ".").split(".")
        alts.append(rf"(?:{re.escape(p)}[.:])?{re.escape(ds)}\.[A-Za-z0-9_]*\*")
    return r"(?i)`?(?:" + "|".join(alts) + r")`?"


def wildcard_jobs_sql(project, region, days, scope="project"):
    """最近 N 天使用过通配符表查询目标数据集的账号（参数 @pattern: STRING 正则）。"""
    return f"""
SELECT LOWER(user_email) AS user_email, COUNT(*) AS job_count
FROM {_jobs_view(project, region, scope)}
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {int(days)} DAY)
  AND job_type = 'QUERY' AND query IS NOT NULL
  AND REGEXP_CONTAINS(query, @pattern)
GROUP BY 1
"""


# --------------------------------------------------------------------------- #
# 客户权限表（文档「1014 最新权限表架构解析」8 张表中脚本会用到的 6 张）
# --------------------------------------------------------------------------- #
AUTH_TABLES = {
    "condition": "adm_user_mem_copilot_condition",      # RLS Lookup 主表：sa + 三个维度数组
    "mapping": "adm_user_mem_copilot_tb_col_mapping",   # 目标表过滤字段映射
    "group": "adm_user_mem_copilot_group",              # 表级权限组字典：id, group（Group 邮箱）
    "grant": "adm_user_mem_copilot_grant_tb",           # Group -> 授权表范围：group_id, table_name
    "bind": "adm_user_mem_copilot_user_bind",           # 用户绑定：condition_id(-> sa), group_id
    "acl": "adm_user_mem_copilot_acl_group_sa",         # 全量白名单名册：sa, acl_group
}


def auth_table(key, dataset=None, override=None):
    """权限表全名：显式 --xxx-table 优先，否则 --auth-dataset + 文档默认表名。"""
    if override:
        return fq(override)
    if not dataset:
        raise ValueError(f"需要 --auth-dataset 或 --{key}-table")
    parts = dataset.strip().replace(":", ".").split(".")
    if len(parts) != 2 or not (_PROJECT_RE.match(parts[0]) and _DATASET_RE.match(parts[1])):
        raise ValueError(f"--auth-dataset 格式应为 project.dataset: {dataset}")
    return f"{parts[0]}.{parts[1]}.{AUTH_TABLES[key]}"


def bind_sa_group_sql(bind_table, condition_table, group_table):
    """用户绑定表 -> (sa, group)：bind.condition_id -> condition.sa；bind.group_id -> group.group。"""
    b, c, g = fq(bind_table), fq(condition_table), fq(group_table)
    return (f"SELECT DISTINCT LOWER(c.sa) AS sa, LOWER(g.`group`) AS grp\n"
            f"FROM `{b}` AS b\n"
            f"JOIN `{c}` AS c ON c.id = b.condition_id\n"
            f"JOIN `{g}` AS g ON g.id = b.group_id\n"
            f"WHERE c.sa IS NOT NULL AND g.`group` IS NOT NULL")


def grant_scope_sql(grant_table, group_table):
    """Group 授权范围表 -> (group, resource)：grant_tb.group_id -> group.group。"""
    t, g = fq(grant_table), fq(group_table)
    return (f"SELECT DISTINCT LOWER(g.`group`) AS grp, t.table_name AS resource\n"
            f"FROM `{t}` AS t\n"
            f"JOIN `{g}` AS g ON g.id = t.group_id\n"
            f"WHERE t.table_name IS NOT NULL")


def _first(row, *keys):
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def parse_sa_rows(rows):
    """
    权限 SA 清单行 -> [(account_id, group_email, display_name)]，去重。
    兼容 CSV 列（account_id, group[, display_name]）和表查询列（sa, grp）。
    """
    out, seen = [], set()
    for i, r in enumerate(rows, 1):
        sa, grp = _first(r, "account_id", "sa"), _first(r, "group", "grp")
        if not sa or not grp:
            raise ValueError(f"第 {i} 行缺少 account_id/sa 或 group: {r}")
        item = (sa_account_id(sa), grp.lower(), _first(r, "display_name") or None)
        if item[:2] not in seen:
            seen.add(item[:2])
            out.append(item)
    return out


def sa_group_conflicts(sas):
    """「一 SA 一 Group」校验：返回 {account_id: [group, ...]}，只含映射到多个 Group 的 SA。"""
    groups = {}
    for aid, grp, _ in sas:
        groups.setdefault(aid, set()).add(grp)
    return {aid: sorted(g) for aid, g in sorted(groups.items()) if len(g) > 1}


def parse_grant_rows(rows):
    """授权范围行 -> [(group_email, resource)]；resource 为 p.d.t（表级）或 p.d（数据集级），去重。"""
    out, seen = [], set()
    for i, r in enumerate(rows, 1):
        grp, res = _first(r, "group", "grp"), _first(r, "resource", "table_name")
        if not grp or not res:
            raise ValueError(f"第 {i} 行缺少 group 或 resource: {r}")
        res = res.replace(":", ".")
        res = fq(res) if res.count(".") == 2 else res
        item = (grp.lower(), res)
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def resolve_acl_group(value, write_group=None, read_group=None):
    """
    白名单名册的 acl_group -> 白名单 Group 邮箱。
    接受：Group 邮箱（必须等于 --write-group / --read-group），或以 write / read 结尾的标识
    （如 group_full_write、full_read、WRITE）。
    """
    v = (value or "").strip().lower()
    w, r = (write_group or "").lower() or None, (read_group or "").lower() or None
    if "@" in v:
        if v in (w, r):
            return v
        raise ValueError(f"名册中的 acl_group {value} 不是 --write-group / --read-group 指定的 Group")
    if v.endswith("write"):
        if not w:
            raise ValueError(f"名册中 acl_group={value} 属于写白名单，但未指定 --write-group")
        return w
    if v.endswith("read"):
        if not r:
            raise ValueError(f"名册中 acl_group={value} 属于读白名单，但未指定 --read-group")
        return r
    raise ValueError(f"无法识别的 acl_group: {value}（应为 Group 邮箱，或以 write / read 结尾）")


def acl_roster(rows, write_group=None, read_group=None):
    """名册行 [{sa, acl_group}] -> {group_email: [规范化成员, ...]}；所有错误汇总后一次抛出。"""
    plan, errors = {}, []
    for i, r in enumerate(rows, 1):
        sa = _first(r, "sa")
        if not sa:
            errors.append(f"第 {i} 行 sa 为空")
            continue
        try:
            grp = resolve_acl_group(_first(r, "acl_group"), write_group, read_group)
        except ValueError as e:
            errors.append(f"第 {i} 行（{sa}）: {e}")
            continue
        members = plan.setdefault(grp, [])
        m = normalize_member(sa, "user")
        if m not in members:
            members.append(m)
    if errors:
        raise ValueError("白名单名册有误:\n  " + "\n  ".join(errors))
    return plan


def inspect_acl_roster(actual, roster, ignore=()):
    """
    把名册当作白名单的事实来源，与 Group 实际成员双向比对。
    actual / roster: {group_email: 可迭代的成员邮箱}；ignore: 忽略的账号（如探针 SA）。
    """
    ign = {m.lower() for m in ignore}
    issues = []
    for g in sorted(set(actual) | set(roster)):
        a = {m.lower() for m in actual.get(g, ())} - ign
        r = {m.lower() for m in roster.get(g, ())} - ign
        for m in sorted(a - r):
            issues.append(f"白名单组 {g} 的成员 {m} 不在白名单名册中（来历不明的全量权限，请补录名册或移出组）")
        for m in sorted(r - a):
            issues.append(f"白名单名册中的 {m} 还没有加入 {g}（存量任务可能查不到数据，请热修补）")
    return issues
