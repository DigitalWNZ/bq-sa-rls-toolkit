# 测试报告

本文记录工具集的测试方法、测试用例、测试结果，以及测试过程中发现并修复的问题。

## 结论

| 层级 | 用例数 | 结果 | 耗时 |
|---|---|---|---|
| 单元测试（`tests/unit`，不访问 GCP） | 126 | ✅ 全部通过 | < 1 秒 |
| 集成测试（`tests/integration`，在真实 GCP 项目上运行） | 33 | ✅ 全部通过 | 约 17 分钟 |

最后一次完整运行：2026-10-16，在一个独立的测试项目上执行（Cloud Identity 测试域、项目 Owner + Groups Admin 的执行账号；具体标识不写入公开仓库）。

## 测试方法

- **先写测试，再写实现**：每个功能先写测试，确认测试因为功能缺失而失败，再写实现让它通过；发现 bug 时先补一个能复现的测试。
- **分两层**：
  - 纯逻辑（DDL 生成、各种决策、规范化、校验）放在 `rls_core.py`，用单元测试覆盖；
  - GCP 交互用集成测试覆盖，测试**通过命令行调用真实脚本**，结果用**独立于被测代码**的 GCP 客户端库来核对。
- **真实身份验证**：端到端验收通过"执行账号 → API SA → 权限 SA"的链式扮演真实发起查询，和 Copilot 后端的调用方式一致。
- **可重复运行**：测试环境的准备是幂等的。每次运行用 `CREATE OR REPLACE TABLE` 重建测试表，旧的 RLS 和表级 IAM 会一起清掉；SA 和 Group 复用。

## 运行方式

```bash
pip install -r requirements.txt pytest
python -m pytest tests/unit -q

export RLS_IT=1                         # 不设置时会跳过集成测试
export RLS_IT_PROJECT=<测试项目>
export RLS_IT_ACCOUNT=<执行账号：项目 Owner + Groups Admin，已 gcloud auth login>
export RLS_IT_DOMAIN=<Cloud Identity 域名>
python -m pytest tests/integration -v   # 用例按顺序执行，后面的用例依赖前面的结果（33 个，约 17 分钟）
```

---

## 一、单元测试（126 个）

文件：[tests/unit/test_rls_core.py](tests/unit/test_rls_core.py)、[tests/unit/test_gcp_auth.py](tests/unit/test_gcp_auth.py)

| 测试类 | 数量 | 覆盖内容 |
|---|:-:|---|
| `TestSplitItems` | 2 | 逗号、空白分隔的列表参数；忽略空项 |
| `TestNormalizeMember` | 6 | 不带前缀的邮箱默认当作 `group:`；`*.gserviceaccount.com` 识别为 SA；保留前缀并把邮箱转小写；`allUsers`、`deleted:` 原样保留 |
| `TestQualifiedTable` | 5 | `p.d.t` / `p:d.t` / `d.t` 加默认项目；**拒绝注入**（例如 `` t`; DROP ``）；拒绝段数不对的表名 |
| `TestClassifyPermissions` | 5 | `getData` 算读，`updateData` 算写；只有元数据权限时两者都不算；legacy 角色 READER / WRITER / OWNER |
| `TestCopilotGuard` | 3 | 按明确的账号或通配符识别 Copilot SA 并拒绝；不配置规则时全部放行 |
| `TestGenericPolicyDdl` | 4 | 通用 DDL 格式；**拒绝带引号的授权对象（防注入）**；标识符清洗；常量 |
| `TestBypassPolicy` | 8 | 白名单 DDL；没有授权对象时拒绝；create / noop / conflict / merge 四种决策；过滤条件不同时即使加 `--merge` 也冲突；首条策略的识别 |
| `TestCopilotPolicy` | 6 | 单维度条件的精确文本；多维度用 AND 连接；拒绝未知维度、非法列名、空映射；完整 DDL |
| `TestHeterogeneousTables` | 12 | **多表、字段各不相同**：同一维度在不同表里列名不同；非 STRING 列加 CAST；STRING 列不加 CAST；嵌套列 `a.b`；非法嵌套路径；按表结构校验（通过、列不存在、REPEATED / RECORD、不支持的类型）；schema 展开；**BigQuery 重新排版后的过滤条件和生成的条件判为一致**；真实变化仍能被识别 |
| `TestParseMappingRows` | 3 | 按表分组、补全项目、维度转小写；去重；拒绝非法维度 |
| `TestPlanRollback` | 7 | 不给 group 时全部删除；只删相关策略；共享策略默认整条删；`--strip-only` 只去掉 group；只剩最后一条时用 DROP ALL；按策略名过滤；匹配不区分大小写 |
| `TestInspect` | 7 | 全部正常；白名单策略缺失、缺少 Group、过滤条件不是 TRUE；Copilot 策略的过滤条件被改（忽略空白差异）；Copilot 策略缺失；白名单组混入 Copilot SA |
| `TestServiceAgent` | 2 | 识别 Google 托管服务代理（`service-<项目号>@`、`*@gcp-sa-*`，例如 BigQuery 连接的 `bqcx-*`、`@cloudservices`、`@cloudbuild`）；普通 SA、默认计算 SA 不算服务代理 |
| `TestImpersonationRisk` | 2 | 识别项目级扮演类权限（排除 API SA）；没有风险时返回空 |
| `TestProjectSaWhitelistRows` | 6 | 项目列表全量 SA：所有 SA 都建议加入指定的白名单；排除 Copilot SA（明确账号和通配符）；默认排除已禁用 SA（可以显式加入）；多个项目、多个来源的同一 SA 合并去重；标注服务代理；拒绝非法的 group 值 |
| `TestQuota` | 2 | 未超配额；超过 100 时报错 |
| `TestJobsSql` | 2 | 作业历史 SQL 同时统计读（referenced）和写（destination），用参数传表名；拒绝非法区域 |
| `TestAccountId` | 3 | 从邮箱或 ID 得到 account_id；拼出 SA 邮箱；拒绝非法 ID |
| `TestVisibilityProbeSql`（C1） | 6 | 探测 SQL：普通表 `SELECT 1 … LIMIT 1`；不要求分区过滤时不加 WHERE；列分区 / 摄取时间分区 / 范围分区要求过滤时分别加 `dt IS NOT NULL`、`_PARTITIONTIME IS NOT NULL`、`cust_id IS NOT NULL`；count 模式 |
| `TestEditionCheck`（C3） | 3 | 从作业分布中识别 STANDARD 版本的 Reservation；没有作业时返回空；SQL 指向正确的项目/区域并含 `edition` |
| `TestJobsSqlScope`（C2） | 3 | 默认 `JOBS_BY_PROJECT`；organization 作用域用 `JOBS_BY_ORGANIZATION`；拒绝未知作用域 |
| `TestCaseInsensitiveFilter`（E1） | 3 | `UPPER()` 包裹两侧；和 CAST 组合；默认大小写敏感 |
| `TestInspectCopilotMembership`（E2） | 6 | 全部正常；SA 同时在两个组是问题；没有条件行只是提醒；条件行不在任何组是提醒；API SA 在组里是问题；条件表聚簇检查 |
| `TestWildcardSql`（E3） | 2 | 通配符正则匹配 `` `p.dw.fact_*` `` 和 `dw.events_*`，不匹配普通表名；SQL 使用 `@pattern` 参数 |
| `TestAuthTables`（8 张表） | 6 | `--auth-dataset` + 文档默认表名推导出全名，显式表名优先；缺参数 / 格式错误时报错；读 `user_bind ⋈ condition ⋈ group`、`grant_tb ⋈ group` 的 SQL（`group` 是保留字必须反引号）；拒绝注入 |
| `TestSaRows`（8 张表） | 4 | 权限 SA 行同时兼容 CSV（`account_id,group`）和表查询（`sa,grp`）两种形状并去重；缺 group 报错；**一 SA 一 Group** 冲突检测；授权范围行解析 |
| `TestAclRoster`（8 张表） | 5 | 名册 `acl_group` 按 Group 邮箱或 `write` / `read` 后缀解析；未知值、邮箱不在白名单组、缺 `--write-group` 时报错；名册 → 建组计划；多行错误一次汇总；名册 vs. 组成员**双向比对**（忽略探针 SA） |
| `test_gcp_auth.py`（E6） | 3 | gcloud 凭证 refresh 调用 gcloud 并设置过期时间；过期后再次 refresh 拿到新 token；`get_credentials` 返回可刷新凭证；`with_quota_project` 保留账号 |

---

## 二、集成测试（33 个）

文件：[tests/integration/test_e2e.py](tests/integration/test_e2e.py)；测试环境准备：[conftest.py](tests/integration/conftest.py)；独立的核对工具：[itlib.py](tests/integration/itlib.py)

### 测试环境（每次运行由 fixture 准备）

| 资源 | 内容 |
|---|---|
| 数据集 `rls_it`（US） | 见下表 |
| `orders`、`sensitive`、`conflict_t`、`no_bypass_t`、`bad_mapping_t` | 6 行相同的数据，列为 `region / prd_type / refername / amount` |
| `orders_alt` | **字段不同的表**：同样的数据，列为 `area / ptype / meta STRUCT<ref, code> / amount` |
| `orders_part` | **分区表**：按 `dt` 分区且 `require_partition_filter=TRUE`（验证 C1 自动加分区过滤） |
| `adm_user_mem_copilot_condition` | `CLUSTER BY sa`；`cop-hi`：region=[HK,SG]，prdtype=[]（全部放行），refername=[REF_A]；`cop-lo`：region=[]，prdtype=[P1]，refername=[] |
| `adm_user_mem_copilot_tb_col_mapping` | orders 3 个维度；sensitive 只有 region；orders_alt 是 area→region、ptype→prdtype、meta.ref→refername；bad_mapping_t 映射到不存在的列；no_bypass_t 只有 region |
| `adm_user_mem_copilot_group` / `_grant_tb` / `_user_bind` | 文档 8 张表中的表级权限组字典（g1=高权限组、g2=低权限组）、Group 授权范围（与 CSV 版 grants 相同的 5 条）、用户绑定（c1→g1、c2→g2，即 cop-hi→高、cop-lo→低） |
| `adm_user_mem_copilot_acl_group_sa` | 白名单名册：etl→写白名单（写 Group 邮箱）、reader→`full_read`（写标识） |
| 测试准备时创建的 SA | `rlsit-api`（API SA）、`rlsit-etl`（存量写，数据集 WRITER）、`rlsit-reader`（存量读，表级 dataViewer）、`rlsit-probe`（探针）、`rlsit-late`（补加遗漏账号用）；均有 jobUser，执行账号可以扮演 |
| 被测脚本创建的资源 | Group：`rlsit-full-write/read`、`rlsit-copilot-high/low/all`；SA：`rlsit-cop-hi/lo/none` |

测试数据（region, prd_type, refername, amount）：
`(HK,P1,REF_A,1) (HK,P2,REF_B,2) (SG,P2,REF_A,3) (US,P1,REF_A,4) (US,P3,REF_C,5) (SG,P1,REF_C,6)`

### 用例与结果

| # | 用例 | 对应任务 | 验证内容 | 结果 |
|---|---|---|---|:-:|
| 1 | `test_t2_scan_classifies_read_write_and_jobs` | T2 | ETL 先执行 INSERT 和 DELETE、reader 执行查询和一次 `sens*` 通配符查询，然后扫描（`--job-projects` 传入同一项目验证去重）：ETL 判为**可写**、来源是数据集、建议进写白名单、作业历史里写次数 ≥ 1；reader 判为**只读**、来源是表级、读次数 ≥ 1、**`wildcard_jobs` ≥ 1 并有 R5 提醒**；同一项目的作业历史只扫一次 | ✅ |
| 1b | `test_t2_scan_org_scope_and_dataset_range` | T2 | `--datasets` 展开整个数据集；`--jobs-scope organization` 用组织级视图仍能找到 reader 的读作业和 ETL 的写作业 | ✅ |
| 2 | `test_t3_whitelist_rejects_copilot_sa` | T3 | 名单里混入 API SA 时退出码 2，**Group 成员没有任何变化** | ✅ |
| 3 | `test_t3_whitelist_plan_from_scan_csv` | T3 | 从扫描 CSV 生成计划：ETL 进写白名单、reader 进读白名单 | ✅ |
| 4 | `test_t3_whitelist_apply_with_probe` | T3 | 用 `EMPTY` 方式建两个 Group 并加入成员；**两条探针都输出"已生效"**；核对成员 | ✅ |
| 4b | `test_t3_whitelist_from_acl_table_and_acl_out` | T3 / 表 8 | **直接用白名单名册表建组**：计划里 etl 进写组、reader 进读组；`--acl-out` 导出的 CSV 恰好是两行 `sa,acl_group`（Group 邮箱）；再 `--apply` 幂等；名册里出现 `acl_group='vip'` 时退出码 1、**组成员与执行前完全一致** | ✅ |
| 5 | `test_t4_bypass_requires_force_on_first_policy` | T4 | 4 张表都没有 RLS 时，不加 `--force-first-policy` 返回退出码 2，**一条策略都没建** | ✅ |
| 6 | `test_t4_bypass_create_batch_multi_group_and_idempotent` | T4 | 5 张表（含字段不同的表、分区表）批量建策略，一条策略授予两个 Group、过滤条件为 TRUE；**版本前置检查输出 `[EDITION] … OK`**（测试项目为按需计费）；**再跑一次 5 张表都是 `[NOOP]`** | ✅ |
| 7 | `test_t4_bypass_conflict_then_merge` | T4 | 预先放一条同名、授权对象不同的策略：不加 `--merge` 返回 `[CONFLICT]`、退出码 1，策略不变；加 `--merge` 后授权对象合并 | ✅ |
| 8 | `test_t4_whitelisted_accounts_unaffected` | T4 | 白名单账号读全量数据，INSERT、DELETE 正常；**记录策略生效窗口：16–18 秒** | ✅ |
| 9 | `test_t4_verify_with_whitelisted_account` | T4 | 用白名单 SA 做 `--verify-sa`，orders、sensitive 和**要求分区过滤的 orders_part** 都是 `[VERIFY-OK]`（自动加了 `dt IS NOT NULL`）；`--verify-mode count` 显示 6 行；用没有权限的 API SA 验证时是 `[VERIFY-FAIL]`、退出码 1 | ✅ |
| 10 | `test_t7_quota_guard` | T7 | 设 `--sa-limit 5` 时退出码 2，**新 SA 没有被创建** | ✅ |
| 11 | `test_t7_setup_copilot_sas` | T7 | API SA 数据权限检查通过；项目级扮演风险主体全部被报告；3 个 SA 都存在；**每个 SA 上 TokenCreator 只授予 API SA**；Group 成员正确；orders 授权给高低两组、sensitive 只授权给高权限组；条件表授权给公共组；项目 jobUser 授权给公共组；**重复执行成功** | ✅ |
| 11a | `test_t7_setup_from_auth_tables` | T7 / 表 3·4·5 | `--auth-dataset` 直接读 `user_bind ⋈ condition ⋈ group`（2 行）和 `grant_tb ⋈ group`（5 行）：计划与 CSV 方式完全一致（cop-hi→高组、cop-lo→低组，6 条 dataViewer 计划，低组没有 sensitive）；`--apply` 后全部 `[EXISTS]`、没有 `[OK]` / `[ERROR]` | ✅ |
| 11c | `test_t7_rejects_sa_in_two_groups` | T7 | `sas.csv` 里 cop-hi 同时映射到高、低两组：退出码 1、输出"一 SA 一 Group"，**cop-hi 没有被加进低权限组** | ✅ |
| 11b | `test_list_project_sas_from_project_list` | 白名单候选（宽松） | **项目列表**（同一个项目同时出现在 `--projects` 和 `--projects-file` 里）：合并去重；etl、reader、late 都建议加入写白名单，而且每个来源只出现一次；cop-hi、cop-lo、cop-none、API SA 被排除（`copilot=True`）；`--include-iam-bound` 列出了服务代理；输出直接交给 `whitelist_groups.py --scan-csv`，计划里有 etl、没有 Copilot SA | ✅ |
| 12 | `test_t8_requires_bypass_policy` | T8 | 表上没有白名单策略时退出码 2，**没有建策略** | ✅ |
| 13 | `test_t8_apply_from_mapping_and_idempotent` | T8 | 按映射表生成：orders 包含 3 个维度，sensitive 只有 region；**再跑一次两张表都是 `[NOOP]`**（验证规范化比较） | ✅ |
| 14 | `test_t8_heterogeneous_columns_per_table` | T8 | **字段不同的表**：orders_alt 的条件里是 `area`、`ptype`、`meta.ref`，没有 `region`；bad_mapping_t 因为列不存在被跳过（退出码 1），**其他表不受影响**，它自己只保留白名单策略 | ✅ |
| 15 | `test_inspect_clean` | 巡检 | 3 张表都是 `[OK]`，退出码 0 | ✅ |
| 15b | `test_inspect_acl_roster_reconciliation` | 巡检 / 表 8 | `--acl-table --probe-sa`：名册与组一致时 0 问题（探针 SA 被忽略）；名册多一行 late → `[ISSUE] 还没有加入`；名册删掉 reader → `[ISSUE] 不在白名单名册中`；恢复后 0 问题 | ✅ |
| 16 | `test_inspect_detects_filter_drift_and_fix` | 巡检 | 手工把 sensitive 的 Copilot 策略改成 `region="HK"`，巡检报"过滤条件"问题；重跑 T8 后显示 `[REPLACE]`；再巡检恢复正常 | ✅ |
| 16b | `test_e1_case_insensitive_round_trip` | E1 | `--case-insensitive` 重建 sensitive 的策略，过滤条件含 `UPPER(`；不带参数巡检报不一致，带参数巡检正常；cop-hi 的过滤结果不变；再不带参数重建恢复 | ✅ |
| 16c | `test_e2_inspect_copilot_membership` | E2 | 带 `--api-sa` 巡检：cop-none 没有条件行只给 `[WARN]`、退出码 0、条件表聚簇正常；把 cop-hi 临时加进低权限组后巡检报"同时属于多个 Copilot 组"、退出码 1；移除后恢复 | ✅ |
| 17 | `test_t5_hot_patch_whitelist_and_inspect_membership` | T5 / 巡检 | 只把遗漏账号补进读白名单（不加 `--project`，验证 quota project 回退逻辑）；巡检能发现白名单组里混入"Copilot SA" | ✅ |
| 18 | `test_e2e_1_3_rows_filtered_and_job_identity_is_permission_sa` | Gate 2 ①③ | 通过扮演链：cop-hi 在 orders 看到 [1,3]，在 sensitive 看到 [1,2,3,6]，在 **orders_alt 看到 [1,3]**；cop-lo 在 orders 看到 [1,4,6]，在 **orders_alt 看到 [1,4,6]**；**作业身份是权限 SA** | ✅ |
| 19 | `test_e2e_1_low_group_cannot_read_high_table` | Gate 2 ① | cop-lo 查询 sensitive 报 Access Denied | ✅ |
| 20 | `test_e2e_2_no_condition_returns_nothing` | Gate 2 ② | 没有条件行的 cop-none 查到 0 行 | ✅ |
| 21 | `test_e2e_4_etl_writes_unaffected` | Gate 2 ④ | 两条策略都在时，ETL 执行 INSERT、UPDATE、DELETE 都正常 | ✅ |
| 22 | `test_e2e_5_whitelist_full_read` | Gate 2 ⑤ | reader 在两张表都读到全量 6 行 | ✅ |
| 23 | `test_e2e_api_sa_has_no_data_access_and_only_api_sa_can_impersonate` | Gate 2 补充 | API SA 直接查询报 Access Denied；**经由其他 SA（ETL）扮演权限 SA 被拒绝**（权限 SA 只信任 API SA） | ✅ |
| 24 | `test_t5_rollback_by_policy_name_with_backup` | T5 | 只撤掉 Copilot 策略，白名单策略保留；备份 JSON 包含两条策略，DDL 可以直接重新执行 | ✅ |
| 25 | `test_t5_rollback_all` | T5 | 6 张表的 RLS 全部清空 | ✅ |

### 其他手工验证
- `RUNBOOK.md` 里的 gcloud 扮演链写法（`CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="api-sa,权限-sa"`）已在测试环境验证，`SESSION_USER()` 返回的是权限 SA。
- 所有程序的 `--help` 和 `py_compile` 都检查通过。

---

## 三、测试中发现并修复的问题

| # | 发现于 | 现象 | 原因 | 处理 | 现在怎么防回归 |
|---|---|---|---|---|---|
| 1 | 用例 13 | 映射没变，重复执行仍然显示 `[REPLACE]` | **BigQuery 存储过滤条件时会重新排版**（去反引号、换行缩进、`EXISTS(`） | `normalize_filter` 改为不受排版影响的比较：字符串常量之外去反引号、转小写、压缩空白、去掉标点两侧空白；字符串常量保留 | 单元测试用 BigQuery 实际返回的文本做用例 |
| 2 | 用例 8 | 白名单策略刚建好时，白名单账号查到 0 行，INSERT 报 `does not have full access` | **新建策略在 BigQuery 里生效有一个短暂的不一致窗口**（即使探针已通过）。这是 BigQuery 的行为，不是脚本 bug | 新增 `--verify-sa` 挂载后验证；文档要求低峰执行、ETL 能重试 | 用例 8 记录窗口时长，用例 9 测试验证功能 |
| 3 | 用例 23 | 执行账号可以绕过 API SA，直接扮演权限 SA | 测试项目里，执行账号在项目级有 `roles/iam.serviceAccountTokenCreator`。**这是一个真实存在的安全风险** | `setup_copilot_sas.py` 新增项目级扮演风险检测（`[IMPERSONATION-RISK]`，`--strict-impersonation` 时中止）；测试改为验证权限 SA 只信任 API SA | 单元测试 `TestImpersonationRisk`；用例 11 断言风险主体都被报告 |
| 4 | 用例 17 | 补加遗漏账号时提示"Group 不存在"（Group 其实存在） | 用 gcloud 账号且没有 quota project 时，Cloud Identity 返回 403，脚本把它当成了"Group 不存在" | `lookup_group` 区分配置类的 403 和"不存在"；`gcp_auth` 在没指定 quota project 时回退到 gcloud 默认项目 | 用例 17 特意不传 `--project` |
| 5 | 扫描输出 | Google 托管服务代理被列为写白名单候选，扮演风险报告也被它们淹没 | 服务代理确实有权限，但由 Google 管理 | 扫描结果加备注；扮演风险分级显示（服务代理只汇总一行） | 单元测试 `TestServiceAgent` |
| 6 | 用例 2（第二次运行） | 测试第二次运行时失败 | 测试本身不能重复运行（上一轮的 Group 成员还在） | 改为比较执行前后成员不变 | — |
| 7 | 用例 14 | 断言失败 | 测试按带反引号的写法匹配，但 BigQuery 存储时去掉了反引号 | 断言改为先去掉反引号再比较 | — |
| 10 | 复查（C1） | `--verify-sa` 用 `COUNT(*)`：要求分区过滤的表会报错；大表全表扫描有成本；空表假通过 | 验证方式设计过重 | 改为 `SELECT 1 … LIMIT 1`，自动加分区过滤，空表输出 `[VERIFY-SKIP]`；保留 `--verify-mode count` | 单元测试 `TestVisibilityProbeSql`；用例 9 覆盖分区表 |
| 11 | 复查（C2） | 跨项目提交的作业扫不到 | 作业历史存放在提交项目 | 新增 `--job-projects` 和 `--jobs-scope organization` | 用例 1、1b |
| 12 | 复查（C3） | 没有 Reservation 版本前置检查 | — | `apply_bypass_rls.py` 查最近作业的 `edition`，发现 STANDARD 中止（退出码 5） | 单元测试 `TestEditionCheck`；用例 6 断言 `[EDITION] OK`（Standard 路径无法在测试项目复现，只有单元测试） |
| 9 | 用例 11b 的输出 | BigQuery 连接的服务代理（`bqcx-*@gcp-sa-bigquery-condel...`）和 `@cloudbuild` 没被识别为 Google 托管服务代理 | 原来的规则只认 `service-<项目号>@` 开头 | 规则扩展为：`*@gcp-sa-*.iam.gserviceaccount.com`，以及 `<项目号>@cloudservices/cloudbuild` | `TestServiceAgent` 增加对应用例 |
| 13 | 用例 1b | `--jobs-scope organization` 时通配符检测报 `400 Unrecognized name: query` | **`JOBS_BY_ORGANIZATION` 没有 `query` 列**（只有 `JOBS_BY_PROJECT` 有） | 组织级作用域明确跳过通配符检测并输出 `[INFO]`，文档注明 | 用例 1b 断言 `[INFO]` 且没有失败告警 |
| 14 | 用例 1 | reader 做 `sens*` 通配符查询报 403，用例失败 | 通配符表查询需要**数据集级**权限，reader 只有表级 dataViewer | 测试改由 ETL（数据集 WRITER）发起；文档补充这一限制。另外失败的尝试同样会计入作业历史，`wildcard_jobs` 的断言不再假设 reader 为 0 | 用例 1 |
| 15 | 用例 16b | 只给 sensitive 加 `--case-insensitive`，再带同样参数巡检 3 张表时报另外两张表不一致 | `--case-insensitive` 是**全局开关**，巡检按同一模式核对所有表 | 测试改为三张表统一切换再统一恢复；RUNBOOK 阶段 7 注明"所有表统一加" | 用例 16b |
| 16 | 8 张表复核 | 白名单名册表 `acl_group_sa` 完全没被程序使用；`group` / `grant_tb` / `user_bind` 只能靠人工导出 CSV；`setup_copilot_sas.py` 不校验"一 SA 一 Group" | 实现时只对照了条件表和映射表 | `setup_copilot_sas.py --auth-dataset` 直接读表并校验一 SA 一 Group；`whitelist_groups.py --acl-table/--acl-out`；`inspect_rls.py --acl-table` 双向比对 | 单元测试 `TestAuthTables` / `TestSaRows` / `TestAclRoster`；用例 4b、11a、11c、15b |
| 8 | 早期版本 | `DROP ROW ACCESS POLICY` 删最后一条策略时失败 | BigQuery 要求最后一条策略必须用 DROP ALL 删除 | 回退计划在"要删除全部策略"时改用 DROP ALL | `TestPlanRollback.test_last_policy_uses_drop_all`；用例 25 |

---

## 四、没有覆盖的部分

| 未覆盖 | 说明 / 建议 |
|---|---|
| `setup_copilot_sas.py` 的**数据集级**授权（`grants.csv` 的 resource 写到数据集） | 代码路径存在（`dataset_add_reader`），集成测试只覆盖了表级授权；客户用到时建议在演练环境先验证 |
| `apply_copilot_rls.py --mapping-csv`、`--default-project` | CSV 解析的逻辑和 BigQuery 映射表是同一套（`parse_mapping_rows` 有单元测试），没有单独做集成测试 |
| 非 STRING 列（INT64 等）的端到端过滤 | DDL 生成有单元测试；测试数据里没有放 INT64 列 |
| Reservation 版本检查的 STANDARD 路径 | 测试项目是按需计费，没有 Standard Reservation；判断逻辑有单元测试 |
| gcloud 凭证跨过 1 小时的真实刷新 | 刷新逻辑有单元测试（模拟过期）；没有做真实的 1 小时以上运行 |
| 当前版本回退脚本的 `--strip-only`、`--revoke-table-viewer`、`--delete-group` | 决策逻辑有单元测试；旧版本在测试环境实测过，重构后的版本没有重新跑集成测试 |
| 多区域、跨项目的目标表 | 测试环境只有一个项目、一个区域（US） |
| Folder/Org 层继承的权限 | 扫描脚本不直接扫描，靠作业历史兜底 |
| 大规模（上百张表、上百个 SA） | 没有做性能测试；SA 数量受单项目 100 个的上限约束 |
| Reservation 切换（Step 1） | 不在本工具集范围内（文档附带的 shell 脚本已有单独的实测报告） |
| Copilot 后端（S8）真实调用 | 用 SDK 和 gcloud 的扮演链模拟，和后端的调用方式等价 |

## 测试环境中保留的资源

测试项目中：
- 数据集 `rls_it`、`rlsit-*` 前缀的 SA 和 Group，重复运行可以复用；
- 测试给项目加了一些 IAM 绑定：fixture SA 的 jobUser、`rlsit-copilot-all` 的 jobUser，以及执行账号对 fixture SA 的 TokenCreator；
- 最后一个用例结束后，所有测试表上都已经没有 RLS。
