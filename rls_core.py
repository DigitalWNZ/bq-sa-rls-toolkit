"""
纯逻辑模块（不访问 GCP，便于单元测试）：
输入解析、规则命名、主体抽取、DDL 生成、Copilot 过滤条件、计划（CREATE / NOOP / REPLACE / 回退）。
"""

import csv
import fnmatch
import functools
import hashlib
import re
from dataclasses import dataclass, field

BYPASS_PREFIX = "rls_bypass_full_access_"
COPILOT_PREFIX = "rls_copilot_"
RLS_GRANTEE_ROLE = "roles/bigquery.filteredDataViewer"
MAX_POLICIES_PER_TABLE = 400          # BigQuery：每张表最多 400 条 RLS 规则
TABLE_NOT_FOUND_MSG = "表不存在（可能已被删除），请检查映射表 / 登记表"
POLICY_NAME_MAX = 256                 # BigQuery：规则名最长 256 字符

_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*$")
_DATASET_RE = re.compile(r"^[A-Za-z0-9_]+$")
_TABLE_RE = re.compile(r"^[A-Za-z0-9_\-$]+$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POLICY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_ORG_RE = re.compile(r"^\d+$")
_GRANTEE_RE = re.compile(r"^(user|group|serviceAccount|domain):[^\"'`\s\\]+$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
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
    """读取单列、无表头的 CSV：每行一个值；空行忽略；不支持注释；多列报错。"""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.reader(f), 1):
            cells = [c.strip() for c in row if c.strip()]
            if not cells:
                continue
            if len(cells) > 1:
                raise ValueError(f"{path} 第 {i} 行有多列，文件应为单列、无表头的 CSV")
            out.append(cells[0])
    return out


def _is_list_file(item):
    """以 .csv 结尾（不区分大小写）且不在反引号内的值当作单列文件。"""
    return item.lower().endswith(".csv") and not item.startswith("`")


def collect_values(values):
    """
    列表参数（--tables / --datasets / --projects / --principals / --policy-names / --organizations）：
    值用逗号或空格分隔；以 .csv 结尾的项读取为单列、无表头的 CSV 文件（文件不存在 -> OSError）；
    可混用；去重保序。
    """
    items = []
    for item in split_items(values or []):
        if _is_list_file(item):
            items.extend(read_list_file(item))
        else:
            items.append(item)
    return list(dict.fromkeys(items))


def _strip_backticks(value, what):
    v = str(value).strip()
    if v.startswith("`") or v.endswith("`"):
        if not (len(v) > 2 and v.startswith("`") and v.endswith("`")) or "`" in v[1:-1]:
            raise ValueError(f"{what}的反引号不配对或位置不对（应为 `project.dataset.table` 整体一对）: {value!r}")
        v = v[1:-1]
    return v


def parse_table_arg(value):
    """命令行 / 参数文件中的表名 -> 'project.dataset.table'：必须三段、点分隔，可带一对反引号；不接受 project:dataset.table。"""
    v = _strip_backticks(value, "表名")
    if ":" in v:
        raise ValueError(f"表名应为 project.dataset.table（点分隔，不支持 project:dataset.table 写法）: {value!r}")
    if len(v.split(".")) != 3:
        raise ValueError(f"表名应为 project.dataset.table（必须三段）: {value!r}")
    return fq(v)


def parse_dataset_arg(value):
    """命令行 / 参数文件中的数据集 -> 'project.dataset'：点分隔，可带一对反引号；不接受 project:dataset。"""
    v = _strip_backticks(value, "数据集名")
    if ":" in v:
        raise ValueError(f"数据集应为 project.dataset（点分隔，不支持 project:dataset 写法）: {value!r}")
    return ".".join(parse_dataset(v))


def normalize_member(m, default_prefix="group"):
    """
    规范化 IAM 主体：无前缀邮箱 -> *.gserviceaccount.com 为 serviceAccount:，其他为 default_prefix:；
    有前缀则保留前缀、邮箱小写；allUsers / allAuthenticatedUsers / deleted:... 原样保留。
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


def parse_dataset(ref):
    """'p.d' / 'p:d' -> (p, d)。"""
    parts = ref.strip().replace(":", ".").split(".")
    if len(parts) != 2 or not (_PROJECT_RE.match(parts[0]) and _DATASET_RE.match(parts[1])):
        raise ValueError(f"数据集格式应为 project.dataset: {ref}")
    return parts[0], parts[1]


def org_scope(org):
    """组织数字 ID（或 organizations/<id>） -> organizations/<id>（校验为数字）。"""
    o = str(org).strip()
    o = o[len("organizations/"):] if o.startswith("organizations/") else o
    if not _ORG_RE.match(o):
        raise ValueError(f"组织 ID 应为数字: {org}")
    return f"organizations/{o}"


def project_scope(project):
    """Project ID（全数字的 Project Number 也兼容） -> projects/<id>（校验格式）。"""
    p = str(project).strip()
    p = p[len("projects/"):] if p.startswith("projects/") else p
    if not _PROJECT_RE.match(p):
        raise ValueError(f"非法的项目 ID: {project}")
    return f"projects/{p}"


# --------------------------------------------------------------------------- #
# 规则命名
# --------------------------------------------------------------------------- #
def _policy_name(prefix, email):
    suffix = re.sub(r"[^a-z0-9]", "_", member_email(email))
    name = prefix + suffix
    if len(name) > POLICY_NAME_MAX:
        digest = hashlib.sha1(suffix.encode()).hexdigest()[:8]
        name = name[:POLICY_NAME_MAX - 9] + "_" + digest
    return name


def bypass_policy_name(group_email):
    """rls_bypass_full_access_<邮箱，小写，非字母数字换成 _>。"""
    return _policy_name(BYPASS_PREFIX, group_email)


def copilot_policy_name(email):
    """rls_copilot_<邮箱，小写，非字母数字换成 _>。"""
    return _policy_name(COPILOT_PREFIX, email)


def is_bypass_policy(name):
    return name.startswith(BYPASS_PREFIX) and len(name) > len(BYPASS_PREFIX)


# --------------------------------------------------------------------------- #
# list_principals：主体抽取
# --------------------------------------------------------------------------- #
PRINCIPAL_COLUMNS = ["email", "principal_type", "home_project"]

_SERVICE_AGENT_RE = re.compile(
    r"^(service-\d+@.+\.gserviceaccount\.com"
    r"|[^@]+@gcp-sa-[a-z0-9\-]+\.iam\.gserviceaccount\.com"
    r"|\d+@(cloudservices|cloudbuild)\.gserviceaccount\.com)$")
_SA_HOME_RES = [
    re.compile(r"^[^@]+@([a-z][a-z0-9\-]+)\.iam\.gserviceaccount\.com$"),
    re.compile(r"^([a-z][a-z0-9\-]+)@appspot\.gserviceaccount\.com$"),
    re.compile(r"^(\d+)-compute@developer\.gserviceaccount\.com$"),
]


def is_service_agent(email):
    return bool(_SERVICE_AGENT_RE.match(member_email(email)))


def principal_type(email):
    e = member_email(email)
    if is_service_agent(e):
        return "serviceAgent"
    return "serviceAccount" if e.endswith("gserviceaccount.com") else "user"


def sa_home_project(email):
    """SA 邮箱反推所属项目（gcp-sa-* 等服务代理不算，返回空）。"""
    e = member_email(email)
    if is_service_agent(e):
        return ""
    for rx in _SA_HOME_RES:
        m = rx.match(e)
        if m:
            return m.group(1)
    return ""


def split_iam_members(members):
    """
    IAM 成员列表 -> (principals, groups)：user: / serviceAccount: 进 principals，group: 进 groups；
    deleted:、domain:、allUsers 等非具体账号跳过。
    """
    principals, groups = set(), set()
    for m in members:
        if m.startswith("deleted:") or ":" not in m:
            continue
        prefix, _, rest = m.partition(":")
        if prefix in ("user", "serviceAccount"):
            principals.add(rest.lower())
        elif prefix == "group":
            groups.add(rest.lower())
    return principals, groups




GET_DATA_PERMISSION = "bigquery.tables.getData"
# 数据集旧式 ACL 角色 -> 对应的预定义角色（三者都含 bigquery.tables.getData）
LEGACY_DATASET_ROLES = {"READER": "roles/bigquery.dataViewer", "WRITER": "roles/bigquery.dataEditor",
                        "OWNER": "roles/bigquery.dataOwner"}


def dataset_role_name(role):
    """数据集 ACL 的 role 字段（READER / WRITER / OWNER 或 roles/...）-> IAM 角色名。"""
    return LEGACY_DATASET_ROLES.get(role, role) if role else role


def binding_members(bindings, role_ok):
    """
    IAM 策略 bindings [{"role","members",("condition")}] -> (principals, groups)，只取 role_ok(role) 为真的绑定。
    带条件的绑定同样纳入（宁可多列）。
    """
    principals, groups = set(), set()
    for bd in bindings:
        if not role_ok(bd.get("role")):
            continue
        p, g = split_iam_members(bd.get("members", []))
        principals |= p
        groups |= g
    return principals, groups


def acl_members(entries, role_ok):
    """
    数据集 ACL 条目 [(role, entity_type, entity_id)] -> (principals, groups)，只取 role_ok(角色) 为真的条目。
    userByEmail（含 SA 邮箱）-> principal；groupByEmail -> group；iamMember 按前缀；
    specialGroup（projectReaders 等，已由项目 IAM 覆盖）/ domain / view / routine / dataset 跳过。
    """
    principals, groups = set(), set()
    for role, etype, eid in entries:
        if not isinstance(eid, str) or etype not in ("userByEmail", "groupByEmail", "iamMember"):
            continue
        if not role_ok(dataset_role_name(role)):
            continue
        if etype == "userByEmail":
            principals.add(eid.strip().lower())
        elif etype == "groupByEmail":
            groups.add(eid.strip().lower())
        else:
            p, g = split_iam_members([eid])
            principals |= p
            groups |= g
    return principals, groups


def _member_type(email, mtype):
    if mtype:
        return mtype
    return "SERVICE_ACCOUNT" if email.endswith("gserviceaccount.com") else "UNKNOWN"


def expand_group(root, fetch, max_depth=10):
    """
    递归展开 Group。fetch(group_email) -> [(member_email, type)]，读不到时返回 None。
    返回 (members, unresolved)：members {email: {"type", "via": [root, ..., 直接所在的组]}}；
    unresolved [(group_email, via)]：读不到成员的嵌套组。
    """
    root = root.lower()
    members, unresolved, visited = {}, [], set()
    queue = [(root, [root])]
    while queue:
        group, path = queue.pop(0)
        if group in visited:
            continue
        visited.add(group)
        items = fetch(group)
        if items is None:
            if group != root:
                unresolved.append((group, path[:-1]))
            continue
        for email, mtype in items:
            email = email.lower()
            t = _member_type(email, mtype)
            if email not in members:
                members[email] = {"type": t, "via": list(path)}
            if t == "GROUP" and email not in visited and len(path) < max_depth:
                queue.append((email, path + [email]))
    return members, unresolved


def is_excluded(email, members=(), patterns=()):
    e = member_email(email)
    return e in {member_email(m) for m in members} or any(fnmatch.fnmatch(e, p.lower()) for p in patterns)


def build_principal_rows(emails, exclude_members=(), exclude_patterns=()):
    """
    主体邮箱集合 -> CSV 行（PRINCIPAL_COLUMNS，按邮箱排序）。三列都由邮箱本身推算：
    principal_type 看邮箱后缀，home_project 从 SA 邮箱反推（user / 服务代理为空）。
    """
    rows = []
    for email in sorted({member_email(e) for e in emails}):
        if is_excluded(email, exclude_members, exclude_patterns):
            continue
        rows.append({"email": email, "principal_type": principal_type(email), "home_project": sa_home_project(email)})
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
    if not _POLICY_RE.match(policy_name) or len(policy_name) > POLICY_NAME_MAX:
        raise ValueError(f"非法的规则名: {policy_name}")
    _validate_grantees(grantees)
    grant = ", ".join(f'"{g}"' for g in grantees)
    return (f"CREATE OR REPLACE ROW ACCESS POLICY `{policy_name}`\n"
            f"ON `{fq(table)}`\n"
            f"GRANT TO ({grant})\n"
            f"FILTER USING ({filter_sql})")


def drop_policy_ddl(table, policy_name):
    if not _POLICY_RE.match(policy_name) or len(policy_name) > POLICY_NAME_MAX:
        raise ValueError(f"非法的规则名: {policy_name}")
    return f"DROP ROW ACCESS POLICY `{policy_name}` ON `{fq(table)}`"


def drop_all_ddl(table):
    return f"DROP ALL ROW ACCESS POLICIES ON `{fq(table)}`"


def copilot_group(value):
    """
    --group 的值 -> 规范化的 Group 邮箱（小写）。必须是裸邮箱（不能带 group: 等前缀），不能是 SA 邮箱；
    引号 / 反引号 / 反斜杠等会被拒绝（防止转义出 DDL 字符串）。
    """
    e = str(value).strip().lower()
    if not _EMAIL_RE.match(e) or any(ch in e for ch in "\"'`\\ "):
        raise ValueError(f"--group 应为 Group 邮箱（如 group_copilot@domain.com，不带 group: 前缀）: {value!r}")
    if e.endswith("gserviceaccount.com"):
        raise ValueError(f"--group 不能是 SA 邮箱: {value!r}")
    return e


def invalid_sa_values(raw_values):
    """条件表 sa 列里不是裸邮箱的原值（带 user: / group: 等前缀、allUsers、乱码）：永远匹配不到 SESSION_USER()。"""
    return sorted({v for v in raw_values if isinstance(v, str) and not _EMAIL_RE.match(v.strip().lower())})


def duplicate_sa_values(counts):
    """{sa 原值: 行数} -> 有多行的 sa（各维度独立判断时，多行会产生交叉组合）。"""
    return sorted(sa for sa, n in counts.items() if n > 1)


# --------------------------------------------------------------------------- #
# apply_copilot_rls：维度、选表、过滤条件
# --------------------------------------------------------------------------- #
_TYPE_ALIASES = {"INTEGER": "INT64", "FLOAT": "FLOAT64", "BOOLEAN": "BOOL", "STRUCT": "RECORD"}
_FILTERABLE_TYPES = {"STRING", "INT64", "NUMERIC", "BIGNUMERIC", "BOOL", "DATE"}
_CONDITION_KEYS = {"id", "sa"}


def condition_dimensions(fields):
    """
    条件表字段 [(name, type, mode)] -> (维度列表, 警告)。
    维度 = 除 id、sa 外的列；只有 REPEATED STRING（ARRAY<STRING>）列可用作维度，其他列给警告并忽略。
    """
    names = {n.lower() for n, _, _ in fields}
    if "sa" not in names:
        raise ValueError("条件表缺少 sa 列")
    dims, warns = [], []
    for name, ftype, mode in fields:
        if name.lower() in _CONDITION_KEYS:
            continue
        if not _IDENT_RE.match(name):
            warns.append(f"条件表列 {name!r} 含有特殊字符，不作为维度")
        elif _TYPE_ALIASES.get(ftype, ftype) == "STRING" and (mode or "").upper() == "REPEATED":
            dims.append(name.lower())
        else:
            warns.append(f"条件表列 {name}（{ftype} {mode}）不是 ARRAY<STRING>，不作为维度")
    return dims, warns


def _validate_column_path(col):
    parts = col.split(".")
    if not all(_IDENT_RE.match(x) for x in parts):
        raise ValueError(f"非法的列名: {col}")
    return parts


def select_copilot_tables(rows, dimensions, default_project=None):
    """
    映射表行 -> ({fq_table: [(col_name, dim)]}, 忽略原因列表)。
    只看 to_name：to_name 属于维度的行才算；无效行忽略；一张表全部无效则整张表不出现。
    """
    dims = {d.lower() for d in dimensions}
    mapping, ignored = {}, []
    for r in rows:
        table_name = str(r.get("table_name") or "").strip()
        col = str(r.get("col_name") or "").strip()
        dim = str(r.get("to_name") or "").strip().lower()
        try:
            table = fq(table_name, default_project)
        except ValueError as e:
            ignored.append(f"{table_name}: {e}")
            continue
        if dim not in dims:
            ignored.append(f"{table}: to_name={dim or '(空)'} 不是条件表的维度，忽略该映射行")
            continue
        try:
            _validate_column_path(col)
        except ValueError as e:
            ignored.append(f"{table}: {e}")
            continue
        lst = mapping.setdefault(table, [])
        if (col, dim) not in lst:
            lst.append((col, dim))
    return mapping, ignored


def _column_expr(col, column_types):
    expr = ".".join(f"`{x}`" for x in _validate_column_path(col))
    ctype = (column_types or {}).get(col)
    if ctype and ctype != "STRING":
        expr = f"CAST({expr} AS STRING)"
    return expr


def build_copilot_filter(mapping, condition_table, column_types=None):
    """
    mapping: [(目标表列名 col_name, 维度 to_name)]。每个维度一段，多段 AND：
      列值 ∈ UNNEST(条件表.<维度>)（当前查询者 SESSION_USER() 的行）
      OR 当前查询者该维度为 NULL / 空数组（全部可见）
    """
    if not mapping:
        raise ValueError("过滤字段映射为空")
    cond = fq(condition_table)
    clauses = []
    for col, dim in mapping:
        if not _IDENT_RE.match(dim):
            raise ValueError(f"非法的维度名: {dim}")
        lhs = _column_expr(col, column_types)
        clauses.append(
            f"({lhs} IN (SELECT v FROM `{cond}` AS c, UNNEST(c.{dim}) AS v "
            f"WHERE c.sa = SESSION_USER()) "
            f"OR EXISTS (SELECT 1 FROM `{cond}` AS c WHERE c.sa = SESSION_USER() "
            f"AND (c.{dim} IS NULL OR ARRAY_LENGTH(c.{dim}) = 0)))")
    return " AND ".join(clauses)


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


# --------------------------------------------------------------------------- #
# 计划
# --------------------------------------------------------------------------- #
_STRING_LITERAL_RE = re.compile(r"('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")")
_PUNCT_SPACE_RE = re.compile(r"\s*([(),.=<>+\-*/])\s*")


@functools.lru_cache(maxsize=65536)
def normalize_filter(s):
    """
    规范化过滤条件以便比较：BigQuery 存储时会重新排版（去掉反引号、换行缩进、'EXISTS (' -> 'EXISTS('）。
    字符串字面量之外：去反引号、统一小写、压缩空白、去掉标点两侧空白；字符串字面量原样保留。
    """
    out = []
    for i, part in enumerate(_STRING_LITERAL_RE.split(str(s))):
        if i % 2:
            out.append(part)
            continue
        part = " ".join(part.replace("`", "").lower().split())
        out.append(_PUNCT_SPACE_RE.sub(r"\1", part))
    norm = "".join(out).strip()
    return "TRUE" if norm == "true" else norm


@dataclass
class PolicyPlan:
    action: str               # create / noop / replace / collision
    first_policy: bool        # 表上原本没有任何规则
    old: dict = None          # replace / collision 时的现有规则
    reason: str = ""


def plan_upsert(existing, policy_name, filter_sql, grantees, check_collision=False):
    """
    existing: 表上现有规则 [{"id","filter","grantees"}]
    - 无同名规则 -> create
    - 同名且过滤条件、授权对象都相同 -> noop
    - 同名但内容不同 -> replace
    - check_collision 且同名规则的授权对象里没有本次的主体（邮箱替换后撞名）-> collision
    """
    want = {normalize_member(g) for g in grantees}
    first = len(existing) == 0
    cur = next((p for p in existing if p["id"] == policy_name), None)
    if cur is None:
        return PolicyPlan("create", first)
    have = {normalize_member(g) for g in cur["grantees"]}
    if check_collision and not (want & have):
        return PolicyPlan("collision", first, cur,
                          f"规则名 {policy_name} 已被其他主体使用: {sorted(member_email(g) for g in have)}")
    if have == want and normalize_filter(cur["filter"]) == normalize_filter(filter_sql):
        return PolicyPlan("noop", first, cur)
    return PolicyPlan("replace", first, cur)


def remaining_policy_slots(existing_count):
    return max(0, MAX_POLICIES_PER_TABLE - existing_count)


@dataclass
class RollbackPlan:
    to_drop: list = field(default_factory=list)
    drop_all: bool = False        # 表上所有规则都将被删除（需用 DROP ALL）


def plan_rollback(policies, principals=None, policy_names=None):
    """
    principals: 邮箱集合（不分类型）；规则授权对象里有其中任一邮箱即匹配。
    policy_names: 规则名集合。两者都给时取交集；都不给时选中全部规则。
    """
    emails = {member_email(p) for p in principals} if principals else None
    names = set(policy_names) if policy_names else None
    plan = RollbackPlan()
    for p in policies:
        if names is not None and p["id"] not in names:
            continue
        if emails is not None and not ({member_email(g) for g in p["grantees"]} & emails):
            continue
        plan.to_drop.append(p)
    plan.drop_all = bool(plan.to_drop) and len(plan.to_drop) == len(policies)
    return plan


# --------------------------------------------------------------------------- #
# 挂载后验证 SQL
# --------------------------------------------------------------------------- #
def visibility_probe_sql(table, partitioning, mode="sample"):
    """
    mode=sample: SELECT 1 ... LIMIT 1；mode=count: SELECT COUNT(*)。
    表要求分区过滤时自动加 <分区列> IS NOT NULL（摄取时间分区用 _PARTITIONTIME）。
    """
    where = ""
    if partitioning and partitioning.get("require_filter"):
        col = f"`{partitioning['field']}`" if partitioning.get("field") else "_PARTITIONTIME"
        where = f" WHERE {col} IS NOT NULL"
    if mode == "count":
        return f"SELECT COUNT(*) AS n FROM `{fq(table)}`{where}"
    return f"SELECT 1 FROM `{fq(table)}`{where} LIMIT 1"


# --------------------------------------------------------------------------- #
# Copilot 审核 CSV
# --------------------------------------------------------------------------- #
COPILOT_PLAN_COLUMNS = ["table", "policy_name", "action", "dimensions", "filter", "note"]
COPILOT_PLAN_COLUMNS_APPLY = COPILOT_PLAN_COLUMNS + ["result"]

_CSV_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """输出到 CSV 前处理：以 = + - @ 制表符 回车 开头的字符串前加单引号，防止被 Excel 当作公式执行（CSV 注入）。"""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIX):
        return "'" + value
    return value


def csv_safe_row(row):
    return {k: csv_safe(v) for k, v in row.items()}


def unnormalized_sa_values(raw_values):
    """条件表 sa 列里不是「小写且无首尾空白」的原值。RLS 子查询按原值与 SESSION_USER() 精确比较，这些账号会查到 0 行。"""
    return sorted({v for v in raw_values if isinstance(v, str) and v != v.strip().lower()})


# --------------------------------------------------------------------------- #
# apply_bypass_rls：登记表（adm_user_mem_copilot_tb）
# --------------------------------------------------------------------------- #
REGISTRY_INT_TYPES = ("INTEGER", "INT64")


def validate_registry_fields(fields):
    """登记表必须有 table_name（STRING）和 rls_enabled（INT64）两列，且都不是数组；否则抛 ValueError。"""
    by_name = {name: (ftype, mode) for name, ftype, mode in fields}
    for col, types in (("table_name", ("STRING",)), ("rls_enabled", REGISTRY_INT_TYPES)):
        if col not in by_name:
            raise ValueError(f"登记表缺少 {col} 列")
        ftype, mode = by_name[col]
        if ftype not in types or mode == "REPEATED":
            raise ValueError(f"登记表 {col} 列类型应为 {'/'.join(types)}（非数组），实际为 {ftype} {mode}")


def registry_status(rows):
    """
    {table_name 原值: "enabled" | "disabled" | "conflict"}。table_name 按原始字符串比较，不做任何规范化；不看 status。
      所有行 rls_enabled == 1        -> enabled
      所有行 rls_enabled != 1        -> disabled（含 NULL / 其它数值）
      既有 1 又有其它值（同名多行）  -> conflict（按未开启处理）
    """
    seen = {}
    for r in rows:
        name = r.get("table_name")
        if name is None:
            continue
        v = r.get("rls_enabled")
        on = isinstance(v, int) and not isinstance(v, bool) and v == 1
        seen.setdefault(name, set()).add(on)
    return {name: ("conflict" if len(s) == 2 else "enabled" if True in s else "disabled") for name, s in seen.items()}
