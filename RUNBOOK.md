# BigQuery RLS 演练 / 上线操作手册（Runbook）

本手册按实施方案的阶段编排。每一步都写明**要准备的输入**、**要运行的命令**、**要做的校验**，以及**失败时怎么回退**。

建议的节奏：
1. 先在**测试环境**完整演练一遍（5 张测试表，从阶段 0 到阶段 7，包括演练回退）；
2. 再用**首批 5 张正式表**灰度上线，观察 1–2 天；
3. 按 30% → 50% → 80% → 100% 分批推广。

> [!IMPORTANT]
> 所有会修改资源的脚本默认只演练（dry-run），**先不加 `--apply` 跑一遍，核对输出后再加 `--apply`**。每次执行都要保存终端输出，作为变更记录。

---

## 目录

- [阶段 0：准备](#阶段-0准备)
- [阶段 1：Reservation 切换到 Enterprise](#阶段-1reservation-切换到-enterprise)
- [阶段 2：扫描存量账号（Step 2）](#阶段-2扫描存量账号step-2)
- [阶段 3：建立白名单 Group 并验证生效（Step 3）](#阶段-3建立白名单-group-并验证生效step-3)
- [阶段 4：挂载 FILTER TRUE 白名单策略（Step 4）](#阶段-4挂载-filter-true-白名单策略step-4)
- [阶段 5：权限表准备（Step 5，客户）](#阶段-5权限表准备step-5客户)
- [阶段 6：创建 Copilot 权限 SA 并授权（Step 6）](#阶段-6创建-copilot-权限-sa-并授权step-6)
- [阶段 7：挂载 Copilot 行级策略（Step 7）](#阶段-7挂载-copilot-行级策略step-7)
- [阶段 8：巡检与端到端验收（Gate 2）](#阶段-8巡检与端到端验收gate-2)
- [阶段 9：分批推广](#阶段-9分批推广)
- [应急回退手册](#应急回退手册)
- [日常运维（Day-2）](#日常运维day-2)
- [附录 A：输入文件模板](#附录-a输入文件模板)
- [附录 B：退出码速查](#附录-b退出码速查)

---

## 阶段 0：准备

### 0.1 需要客户提供的输入

| 编号 | 输入 | 格式 / 示例 | 用在哪一步 |
|---|---|---|---|
| P1 | Reservation 名称、Admin Project、Location，以及关联的业务项目 | `admin-proj` / `US` / `std_res` | 阶段 1 |
| P2 | 本批目标表清单 | `batch_N.txt`，每行一个 `project.dataset.table` | 阶段 2、4、7、8 |
| P2-b | 项目列表（宽松版白名单用）：ETL、BI、调度、业务数据所在的全部项目 | `projects.txt`，每行一个项目 ID | 阶段 2 方式 B |
| P3 | 权限表所在的数据集（8 张表，见下表），至少要有条件表、映射表、group、grant_tb、user_bind、acl_group_sa | `auth-proj.auth` | 阶段 3、5、6、7、8 |
| P4 | 过滤字段映射表里本批表的配置已填好 | `adm_user_mem_copilot_tb_col_mapping` | 阶段 7、8 |
| P5-a | 白名单 Group 邮箱（写、读） | `group_full_write@domain`、`group_full_read@domain` | 阶段 3、4、8 |
| P5-b | Copilot Group 邮箱（高、低、公共） | `group_copilot_high@`、`group_copilot_low@`、`group_copilot_all_sa@` | 阶段 6、7、8 |
| P5-c | API SA 邮箱 | `copilot-api@proj.iam.gserviceaccount.com` | 阶段 2、3、6、8 |
| P5-d | 权限 SA 清单，以及每个 SA 属于哪个 Group | 直接来自 `user_bind ⋈ condition ⋈ group`；没有表时用 `sas.csv`（见[附录 A](#附录-a输入文件模板)） | 阶段 6 |
| P5-e | Group 可以访问哪些表 | 直接来自 `grant_tb ⋈ group`；没有表时用 `grants.csv`（见附录 A） | 阶段 6 |
| P5-f | Copilot SA 的命名规则 | 例如 `copilot-*@*`，用来防止 Copilot SA 混进白名单 | 阶段 2、3、8 |
| P5-g | 白名单名册表（阶段 2 审核结果回填进去，之后它就是白名单的事实来源） | `adm_user_mem_copilot_acl_group_sa`（`sa, acl_group`） | 阶段 3、8、Day-2 |

客户权限表（文档「1014 最新权限表架构解析」8 张表）和本工具集的关系：

| 表 | 作用 | 哪个程序用 |
|---|---|---|
| `adm_user_mem_copilot_condition` | RLS Lookup 主表：`sa` + `region/prdtype/refername` 数组 | `apply_copilot_rls.py`（子查询引用）、`setup_copilot_sas.py`（单表读权限）、`inspect_rls.py`（聚簇、成员核对） |
| `adm_user_mem_copilot_tb_col_mapping` | 每张目标表的过滤列 ↔ 标准维度 | `apply_copilot_rls.py`、`inspect_rls.py` |
| `adm_user_mem_copilot_group` | 表级权限组字典（`id, group`） | `setup_copilot_sas.py --auth-dataset` |
| `adm_user_mem_copilot_grant_tb` | Group → 可访问的表范围 | `setup_copilot_sas.py --auth-dataset` |
| `adm_user_mem_copilot_user_bind` | 绑定行级条件（→ `sa`）与表级 Group，一 SA 一 Group | `setup_copilot_sas.py --auth-dataset` |
| `adm_user_mem_copilot_acl_group_sa` | 全量白名单名册（`sa, acl_group`） | `whitelist_groups.py --acl-table`、`inspect_rls.py --acl-table` |
| `adm_user_mem_copilot_user` / `adm_user_mem_copilot_role` | 后端路由（登录用户 → bind → sa）/ 角色字典 | 不使用（Copilot 后端的职责） |

### 0.2 准备操作账号和辅助 SA

| 项 | 要求 |
|---|---|
| 操作账号 | 在 Google Admin Console 里有 **Groups Admin**（或 Super Admin）；在目标项目上有 `roles/bigquery.admin`（或 dataOwner + jobUser）、`roles/iam.serviceAccountAdmin`、`roles/resourcemanager.projectIamAdmin`。详细权限见 [README](README.md#权限要求) |
| 探针 SA（`probe-sa`） | 一个专用 SA，不能读任何业务表。授予它项目 `roles/bigquery.jobUser`；操作账号对它要有 `roles/iam.serviceAccountTokenCreator` |
| 验证 SA（`verify-sa`） | 一个**已在读白名单里**、对目标表有读权限的存量 SA（例如 IBA 报表 SA）；操作账号对它要有 TokenCreator |
| 探针数据集 | `ops-proj.rls_probe`，和目标表同一个 location |

### 0.3 准备本地环境

```bash
pip install -r requirements.txt
gcloud auth login ops@domain.com
export A="--gcloud-account ops@domain.com"
mkdir -p logs backup
```

**校验**
- [ ] `gcloud auth list` 里能看到操作账号；
- [ ] 每个脚本 `python <脚本> --help` 都能正常输出；
- [ ] quota project 上已启用 `bigquery`、`iam`、`cloudresourcemanager`、`cloudidentity` 这几个 API；
- [ ] 演练环境：已把 5 张正式表复制到测试数据集，`batch_test.txt` 里写的是这些测试表。

---

## 阶段 1：Reservation 切换到 Enterprise

不在本工具集范围内，使用实施方案文档附带的 `switch_reservation_assignments.sh`。

| 输入 | 命令 | 校验 |
|---|---|---|
| P1 | `./switch_reservation_assignments.sh <ADMIN_PROJECT> <LOC> <STD_RES> <ENT_RES> --dry-run`，确认后把 `--dry-run` 换成 `--yes` | 新 Assignment 都在 Enterprise Reservation 下；用 `INFORMATION_SCHEMA.JOBS_BY_PROJECT` 查一下，没有作业在配置里写死了旧 Reservation |

回退：把源和目标 Reservation 对调，再执行一次即可。

---

## 阶段 2：扫描存量账号（Step 2）

**目的**：找出所有会读、写目标表的存量账号，作为白名单候选。有两种方式，可以只用一种，也可以都用：

| 方式 | 程序 | 特点 | 什么时候选 |
|---|---|---|---|
| A. 按表精确扫描 | `scan_bq_access.py` | 只列出对目标表有权限或真实访问过的账号，并分读写 | 希望白名单尽量小 |
| B. 项目列表全量 SA（宽松） | `list_project_sas.py` | 列出给定项目列表中的**全部 SA**，宁多勿漏 | 担心漏掉账号（权限来自 Folder/Org、最近没跑作业、通过 View 间接访问等），希望"零中断"更稳 |

**输入**：P2（`batch_N.txt`）、P5-c、P5-f；方式 B 还需要**项目列表**（`projects.txt`，每行一个项目 ID，包括 ETL、BI、调度等所在的项目）

#### 方式 A：按表精确扫描

**示例输入** `batch_N.txt`
```
# 首批正式表
prod-proj.dw.fact_orders
prod-proj.dw.fact_booking
```

```bash
# 作业历史存放在"提交作业的项目"里：ETL / BI 从其他项目提交的作业要用 --job-projects 补上；
# 有组织级 bigquery.jobs.listAll 时可改用 --jobs-scope organization 一次覆盖全组织（该模式下不做通配符查询检测）
python scan_bq_access.py --tables-file batch_N.txt --jobs-days 90 \
    --job-projects etl-proj,bi-proj \
    --copilot-patterns 'copilot-*@*' --copilot-members copilot-api@proj.iam.gserviceaccount.com \
    -o scan_batch_N.csv $A | tee logs/02_scan.log
```

**处理逻辑（简述）**：读取每张目标表所在项目、数据集、表的 IAM，把角色展开成具体权限，按读（`tables.getData`）和写（`tables.updateData`）分类；再查最近 90 天作业历史里真实读写过这些表的账号（含 `--job-projects` 指定的提交项目），两者合并后输出 CSV；同时检测近期对目标数据集的通配符表查询。

**示例输出**（终端；每行格式 `建议组 主体 [权限来源] jobs(读/写次数) 备注`）
```
[IAM] 项目 prod-proj
[IAM] 数据集 prod-proj.dw
[IAM] 表 prod-proj.dw.fact_orders
[IAM] 表 prod-proj.dw.fact_booking
[JOBS] prod-proj / region-us（最近 90 天）
[JOBS] etl-proj / region-us（最近 90 天）
[JOBS] bi-proj / region-us（最近 90 天）
  [WARN] bi-adhoc@bi-proj.iam.gserviceaccount.com 最近 90 天有 3 次通配符表查询（目标数据集 ['prod-proj.dw']），表启用 RLS 后此类查询会失败（R5）
read  serviceAccount:bi-adhoc@bi-proj.iam.gserviceaccount.com  [project:roles/bigquery.dataViewer] jobs(r/w)=12/0 最近有 3 次通配符表查询（table_*），表启用 RLS 后会失败，需改写 SQL（R5）
-     serviceAccount:copilot-u-001@copilot-proj.iam.gserviceaccount.com  [] jobs(r/w)=21/0 Copilot SA，已排除出白名单; 仅出现在作业历史（可能来自 Folder/Org 继承或已回收权限），请人工确认
read  serviceAccount:iba-reader@bi-proj.iam.gserviceaccount.com  [table:fact_orders:roles/bigquery.dataViewer; table:fact_booking:roles/bigquery.dataViewer] jobs(r/w)=58/0
write serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com  [project:roles/bigquery.admin] jobs(r/w)=0/0 Google 托管服务代理，确认该服务是否读写目标表后再决定是否加白名单
write serviceAccount:zeus-etl@etl-proj.iam.gserviceaccount.com  [dataset:dw:WRITER] jobs(r/w)=93/48
-     specialGroup:projectReaders  [dataset:dw:READER] jobs(r/w)=0/0 非具体账号，无法加入 Group，请人工处理
write user:admin@domain  [project:roles/bigquery.admin; dataset:dw:OWNER] jobs(r/w)=141/149

共 7 个主体：写白名单候选 3，读白名单候选 2，Copilot 排除 1，使用过通配符查询 1。结果已写入 scan_batch_N.csv（请客户审核后再加组）
```
`scan_batch_N.csv` 的内容见[附录 A](#附录-a输入文件模板)。

**校验**
- [ ] 末尾汇总行显示"写白名单候选 X，读白名单候选 Y，Copilot 排除 Z"；
- [ ] **客户逐行审核 `scan_batch_N.csv`**，重点检查：
  - Zeus 调度 SA、IBA 报表 SA、管理员都在 `suggested_group` 列里（write 或 read）；
  - `note` 列写着"仅出现在作业历史"的账号：可能是 Folder/Org 层继承的权限，要确认是否加入；
  - `note` 列写着"Google 托管服务代理"的账号：确认这个服务是否读写目标表（例如 Pub/Sub 写入 BigQuery、Data Transfer），需要的话保留；
  - `note` 列写着"非具体账号"的行（如 `specialGroup:projectReaders`）：没法加入 Group，要确认对应的人和系统已有其他账号在白名单里；
  - `copilot=True` 的行不会进入白名单（这是正确的）；
  - `wildcard_jobs` 不为 0 的账号：近期用过 `table_*` 通配符查询，**表启用 RLS 后这类查询会失败**，要提前通知对应团队改写 SQL（R5）。
- [ ] 风险 R1：确认下游通过 View 访问这些表的系统账号也在 CSV 里；不在的话手工补充。
- [ ] 确认 `--job-projects` 覆盖了所有会提交作业访问这些表的项目（Zeus、IBA、Dataflow 等所在项目）。

#### 方式 B：项目列表全量 SA（宽松）

**示例输入** `projects.txt`
```
# ETL、BI、调度、业务数据所在的全部项目
prod-proj
etl-proj
bi-proj
# 即使把 Copilot 项目列进来，Copilot SA 也会被排除（只支持整行注释，不要写行尾注释）
copilot-proj
```

```bash
python list_project_sas.py --projects-file projects.txt --group write --include-iam-bound \
    --copilot-patterns 'copilot-*@*' --copilot-members copilot-api@proj.iam.gserviceaccount.com \
    -o project_sas_batch_N.csv $A | tee logs/02_list_sas.log
```

**处理逻辑（简述）**：列出列表中每个项目的全部 SA；加了 `--include-iam-bound` 时，各项目 IAM 中出现的跨项目 SA 和服务代理也会列出；多个项目里的同一个 SA 合并为一行；排除 Copilot SA 和已禁用的 SA；其余 SA 都建议加入 `--group` 指定的白名单。

**示例输出**（节选）
```
[SA] prod-proj: 项目内 18 个 SA
[IAM] prod-proj: IAM 绑定中出现 82 个 SA
[SA] etl-proj: 项目内 6 个 SA
[IAM] etl-proj: IAM 绑定中出现 31 个 SA
[SA] bi-proj: 项目内 4 个 SA
[IAM] bi-proj: IAM 绑定中出现 27 个 SA
[SA] copilot-proj: 项目内 3 个 SA
[IAM] copilot-proj: IAM 绑定中出现 20 个 SA
write serviceAccount:123456789012-compute@developer.gserviceaccount.com  [prod-proj:project-sa; prod-proj:iam-binding]
write serviceAccount:123456789012@cloudservices.gserviceaccount.com  [prod-proj:iam-binding] Google 托管服务代理
-     serviceAccount:copilot-api@proj.iam.gserviceaccount.com  [copilot-proj:project-sa] Copilot SA，已排除出白名单
-     serviceAccount:copilot-u-001@copilot-proj.iam.gserviceaccount.com  [copilot-proj:project-sa] Copilot SA，已排除出白名单
-     serviceAccount:copilot-u-002@copilot-proj.iam.gserviceaccount.com  [copilot-proj:project-sa] Copilot SA，已排除出白名单
write serviceAccount:iba-reader@bi-proj.iam.gserviceaccount.com  [bi-proj:project-sa; prod-proj:iam-binding]
write serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com  [prod-proj:iam-binding] Google 托管服务代理
write serviceAccount:zeus-etl@etl-proj.iam.gserviceaccount.com  [etl-proj:project-sa; prod-proj:iam-binding]
...

4 个项目，共 97 个 SA：建议加入 write 白名单 94 个，排除 Copilot SA 3 个，其他排除 0 个。结果已写入 project_sas_batch_N.csv（请客户审核后再加组）
```

**校验**
- [ ] 退出码为 0（为 1 时说明有项目读取失败，看 `[ERROR]` 行，补上权限后重跑）；
- [ ] 汇总行里"排除 Copilot SA"的数量和权限 SA 数量加 API SA（1 个）一致；
- [ ] **客户审核**：
  - 确认 `copilot=True` 的行包含所有权限 SA 和 API SA；
  - `note` 里标着"Google 托管服务代理"的账号：按需保留或删除；
  - 测试用、已废弃的 SA 可以删掉。

#### 审核结果回填白名单名册表（P5-g）

审核完的 CSV（两种方式格式相同，可以直接删行或改 `suggested_group` 列）有两种用法：

1. **推荐**：先用它生成名册、回填到客户的 `adm_user_mem_copilot_acl_group_sa`，之后阶段 3 从名册表建组，阶段 8 用名册表巡检。这样白名单只有一个事实来源：
   ```bash
   # 只生成名册（演练模式，不改任何资源）；两种方式的 CSV 可以一起传，重复账号自动去重
   python whitelist_groups.py --write-group group_full_write@domain --read-group group_full_read@domain \
       --scan-csv scan_batch_N.csv --copilot-patterns 'copilot-*@*' \
       --copilot-members copilot-api@proj.iam.gserviceaccount.com --acl-out acl_batch_N.csv $A
   bq load --source_format=CSV --skip_leading_rows=1 \
       auth-proj:auth.adm_user_mem_copilot_acl_group_sa acl_batch_N.csv sa:STRING,acl_group:STRING
   ```
   `acl_batch_N.csv` 的样子：
   ```
   sa,acl_group
   zeus-etl@etl-proj.iam.gserviceaccount.com,group_full_write@domain
   admin@domain,group_full_write@domain
   iba-reader@bi-proj.iam.gserviceaccount.com,group_full_read@domain
   bi-adhoc@bi-proj.iam.gserviceaccount.com,group_full_read@domain
   ```
2. 没有名册表时，审核后的 CSV 直接作为阶段 3 `--scan-csv` 的输入。

---

## 阶段 3：建立白名单 Group 并验证生效（Step 3）

**目的**：把存量账号放进读、写白名单 Group，并确认 BigQuery 已经识别到这些成员关系。

**输入**：白名单名册表（P5-g；没有名册表时用审核后的 `scan_batch_N.csv`）、P5-a、P5-f、探针 SA、探针数据集

**示例输入**：名册表 `auth-proj.auth.adm_user_mem_copilot_acl_group_sa`（`acl_group` 写 Group 邮箱，或者 `group_full_write` / `full_read` 这类以 write / read 结尾的标识都可以）

| sa | acl_group |
|---|---|
| `zeus-etl@etl-proj.iam.gserviceaccount.com` | `group_full_write@domain` |
| `admin@domain` | `group_full_write` |
| `iba-reader@bi-proj.iam.gserviceaccount.com` | `group_full_read@domain` |
| `bi-adhoc@bi-proj.iam.gserviceaccount.com` | `full_read` |

```bash
# 1) 先演练，核对每一行 "group <- 账号"（没有名册表时，把 --acl-table ... 换成 --scan-csv scan_batch_N.csv）
python whitelist_groups.py --write-group group_full_write@domain --read-group group_full_read@domain \
    --acl-table auth-proj.auth.adm_user_mem_copilot_acl_group_sa --copilot-patterns 'copilot-*@*' \
    --copilot-members copilot-api@proj.iam.gserviceaccount.com --project ops-proj $A | tee logs/03_whitelist_plan.log

# 2) 执行并做探针验证
python whitelist_groups.py --write-group group_full_write@domain --read-group group_full_read@domain \
    --acl-table auth-proj.auth.adm_user_mem_copilot_acl_group_sa --copilot-patterns 'copilot-*@*' \
    --copilot-members copilot-api@proj.iam.gserviceaccount.com \
    --project ops-proj --probe-sa probe-sa@ops-proj.iam.gserviceaccount.com \
    --probe-dataset ops-proj.rls_probe --apply $A | tee logs/03_whitelist_apply.log
```

**示例输出** 1) 演练
```
[SOURCE] 白名单名册 auth-proj.auth.adm_user_mem_copilot_acl_group_sa: 4 行
===== 模式: DRY-RUN =====
[PLAN] group_full_write@domain: 2 个成员
  group_full_write@domain <- zeus-etl@etl-proj.iam.gserviceaccount.com
  group_full_write@domain <- admin@domain
[PLAN] group_full_read@domain: 2 个成员
  group_full_read@domain <- iba-reader@bi-proj.iam.gserviceaccount.com
  group_full_read@domain <- bi-adhoc@bi-proj.iam.gserviceaccount.com
```

**示例输出** 2) 执行（Group 不存在时自动创建；`新增 3` = 2 个名单成员 + 探针 SA）
```
[SOURCE] 白名单名册 auth-proj.auth.adm_user_mem_copilot_acl_group_sa: 4 行
===== 模式: APPLY =====
[PLAN] group_full_write@domain: 2 个成员
  group_full_write@domain <- zeus-etl@etl-proj.iam.gserviceaccount.com
  group_full_write@domain <- admin@domain
[PLAN] group_full_read@domain: 2 个成员
  group_full_read@domain <- iba-reader@bi-proj.iam.gserviceaccount.com
  group_full_read@domain <- bi-adhoc@bi-proj.iam.gserviceaccount.com
[GROUP] 已创建 group_full_write@domain (groups/03x8tuzt1k2m9ab)
[MEMBER] group_full_write@domain: 新增 3，已存在 0
[GROUP] 已创建 group_full_read@domain (groups/01hmsyys0q7w5cd)
[MEMBER] group_full_read@domain: 新增 3，已存在 0
[PROBE] group_full_write@domain 已生效
[PROBE] group_full_read@domain 已生效
===== 完成 (APPLY) =====
```

**示例输出** 名单里混进了 Copilot SA 时（退出码 2，什么都没做）
```
[REJECT] serviceAccount:copilot-u-001@copilot-proj.iam.gserviceaccount.com 命中 Copilot SA 名单/规则，禁止加入白名单 group_full_read@domain
已中止，未做任何变更。请从名单中移除上述账号后重试。
```

**校验**
- [ ] 退出码为 0。**退出码 2** 表示名单里混入了 Copilot SA（脚本没有做任何变更），把输出里 `[REJECT]` 的账号从名册表（或 CSV）里删掉后重跑；**退出码 1** 且有 `[ERROR] 白名单名册有误` 说明名册表里有无法识别的 `acl_group` 值或空 `sa`，按提示修正；
- [ ] 输出里有 `[PROBE] group_full_write@domain 已生效` 和 `[PROBE] group_full_read@domain 已生效` 两行；
- [ ] 抽查：`gcloud identity groups memberships list --group-email=group_full_read@domain` 的结果和名册一致（会多一个探针 SA）。
- [ ] 说明：探针会在探针数据集里留下每个 Group 一张 1 行的表 `_rls_probe_<group>`（带一条只授予该 Group 的 TRUE 策略），下次探针会复用；不再需要时可以手工删除。

> [!CAUTION]
> **两条探针都通过之前，不能进入阶段 4。** Group 成员关系同步到 BigQuery 有 1–5 分钟延迟，过早挂策略会导致存量任务拿不到数据。

---

## 阶段 4：挂载 FILTER TRUE 白名单策略（Step 4）

**目的**：给每张目标表挂上 `rls_bypass_full_access`（授予两个白名单 Group，`FILTER USING (TRUE)`），让存量账号不受后续行级策略影响。

**输入**：P2、P5-a、验证 SA

**时间窗口**：选**业务低峰**，避开 Zeus 批量调度时段（原因见下方 WARNING）。

**前置条件**：阶段 1 已完成。脚本会自动检查最近 7 天的作业有没有运行在 STANDARD 版本上，有则中止（退出码 5）；按需计费或 Enterprise 才会继续。

```bash
# 1) 演练：确认每张表显示 [CREATE]（新建），或 [NOOP]（已存在且一致）
python apply_bypass_rls.py --tables-file batch_N.txt \
    --groups group_full_write@domain,group_full_read@domain $A | tee logs/04_bypass_plan.log

# 2) 执行，并在挂载后验证
python apply_bypass_rls.py --tables-file batch_N.txt \
    --groups group_full_write@domain,group_full_read@domain \
    --force-first-policy --verify-sa iba-reader@bi-proj.iam.gserviceaccount.com \
    --apply $A | tee logs/04_bypass_apply.log
```

**示例输出** 1) 演练（演练也会做版本检查和首条策略警告，但不会中止）
```
===== 模式: DRY-RUN  policy=rls_bypass_full_access  grantees=['group:group_full_write@domain', 'group:group_full_read@domain'] =====
[EDITION] prod-proj/us: OK（ENTERPRISE）
[WARNING] 以下 2 张表目前没有任何 RLS，创建后未被授权的账号将查不到数据:
  - prod-proj.dw.fact_orders
  - prod-proj.dw.fact_booking
[CREATE] prod-proj.dw.fact_orders
CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`
ON `prod-proj.dw.fact_orders`
GRANT TO ("group:group_full_write@domain", "group:group_full_read@domain")
FILTER USING (TRUE)
[CREATE] prod-proj.dw.fact_booking
CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`
ON `prod-proj.dw.fact_booking`
GRANT TO ("group:group_full_write@domain", "group:group_full_read@domain")
FILTER USING (TRUE)
[NOTE] 未做挂载后验证；新 policy 生效有短暂窗口，建议用 --verify-sa 指定一个白名单账号验证
===== 完成 (DRY-RUN) =====
```

**示例输出** 2) 执行 + 验证（第一张表等了 18 秒才可见，就是下方 WARNING 说的生效窗口）
```
===== 模式: APPLY  policy=rls_bypass_full_access  grantees=['group:group_full_write@domain', 'group:group_full_read@domain'] =====
[EDITION] prod-proj/us: OK（ENTERPRISE）
[WARNING] 以下 2 张表目前没有任何 RLS，创建后未被授权的账号将查不到数据:
  - prod-proj.dw.fact_orders
  - prod-proj.dw.fact_booking
[CREATE] prod-proj.dw.fact_orders
CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`
ON `prod-proj.dw.fact_orders`
GRANT TO ("group:group_full_write@domain", "group:group_full_read@domain")
FILTER USING (TRUE)
[CREATE] prod-proj.dw.fact_booking
CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`
ON `prod-proj.dw.fact_booking`
GRANT TO ("group:group_full_write@domain", "group:group_full_read@domain")
FILTER USING (TRUE)
[VERIFY-OK] prod-proj.dw.fact_orders: iba-reader@bi-proj.iam.gserviceaccount.com 可见数据（18s）
[VERIFY-OK] prod-proj.dw.fact_booking: iba-reader@bi-proj.iam.gserviceaccount.com 可见数据（2s）
===== 完成 (APPLY) =====
```
再跑一次会显示 `[NOOP] prod-proj.dw.fact_orders`、`[NOOP] prod-proj.dw.fact_booking`。

**示例输出** 三种会中止 / 需要处理的情况
```
# a) --apply 时没加 --force-first-policy（退出码 2，什么都没做）
[WARNING] 以下 2 张表目前没有任何 RLS，创建后未被授权的账号将查不到数据:
  - prod-proj.dw.fact_orders
  - prod-proj.dw.fact_booking
已中止，未做任何变更。确认白名单 Group 已生效（探针通过）后加 --force-first-policy。

# b) 最近 7 天有作业跑在 Standard 版本上（退出码 5，什么都没做）
[EDITION] prod-proj/us: 最近 7 天有 1532 个查询作业运行在 STANDARD 版本 Reservation admin-proj:US.std_res，RLS 不支持 Standard
已中止，未做任何变更。请先完成 Reservation 切换到 Enterprise（RUNBOOK 阶段 1），确认后可用 --skip-edition-check 跳过。

# c) 表上已有同名但授权对象不同的策略（这张表跳过，退出码 1）
[CONFLICT] prod-proj.dw.fact_orders: 同名 policy 授权对象不同: ['user:someone@domain']（如需合并授权对象请加 --merge）
```

**校验**
- [ ] 输出里每个"项目/区域"都有 `[EDITION] ... OK`。**退出码 5** 说明还有作业跑在 Standard 版本上，回到阶段 1；
- [ ] 退出码为 0；
- [ ] 每张表都有一行 `[VERIFY-OK]`（验证只查一行，几乎不产生扫描费用；要求分区过滤的表会自动加条件）。出现 `[VERIFY-SKIP]` 说明表是空的，无法通过查询验证；
- [ ] 出现 `[CONFLICT]`：说明表上已有同名但内容不同的策略。先查清楚是谁建的；确认可以合并后加 `--merge` 重跑；
- [ ] **S6 回归**（客户执行）：Zeus 跨天调度、IBA 报表、Console 查询全部正常，**观察 1–2 天**（正式表）。

> [!WARNING]
> **实测：策略刚创建后的约 16–18 秒内，白名单账号可能查到 0 行，DML 也可能报 `does not have full access ... due to row access policies`**，即使白名单 Group 已经生效。所以要选低峰执行、等 `--verify-sa` 通过，并确认 ETL 调度失败后会自动重试。

**失败时回退**：`python rollback_group_rls.py --tables-file batch_N.txt --backup-dir backup/ --apply $A`（删掉这些表上的全部 RLS，恢复到没有 RLS 的状态）。

---

## 阶段 5：权限表准备（Step 5，客户）

**客户负责**：创建 8 张权限表，并把权限数据同步进去（表的作用和脚本的对应关系见[阶段 0](#01-需要客户提供的输入)）。

**示例输入**：本手册样例环境下，脚本会读到的 6 张表内容见[附录 A](#附录-a输入文件模板)（条件表、映射表、名册表），以及：

| `adm_user_mem_copilot_group` | | `adm_user_mem_copilot_grant_tb` | | `adm_user_mem_copilot_user_bind` | | | |
|---|---|---|---|---|---|---|---|
| id | group | group_id | table_name | id | role_id | condition_id | group_id |
| g1 | group_copilot_high@domain | g1 | prod-proj.dw.fact_orders | b1 | r1 | c1（→ sa copilot-u-001） | g1 |
| g2 | group_copilot_low@domain | g1 | prod-proj.dw.fact_booking | b2 | r2 | c2（→ sa copilot-u-002） | g2 |
| | | g2 | prod-proj.dw.fact_orders | | | | |
| | | g2 | prod-proj.dw_public | | | | |

**Google 侧校验**（在 BigQuery 里执行，每条都应返回 0 行或符合期望）：

```sql
-- 1. 条件表 schema 与聚簇
SELECT column_name, data_type FROM `auth-proj.auth.INFORMATION_SCHEMA.COLUMNS`
WHERE table_name = 'adm_user_mem_copilot_condition';
-- 期望：id STRING、sa STRING；region / prdtype / refername 为 ARRAY<STRING>
SELECT column_name FROM `auth-proj.auth.INFORMATION_SCHEMA.COLUMNS`
WHERE table_name = 'adm_user_mem_copilot_condition' AND clustering_ordinal_position = 1;  -- 期望：sa（CLUSTER BY sa）

-- 2. 每个权限 SA 都有条件行，且一个 SA 只有一行
SELECT sa, COUNT(*) c FROM `auth-proj.auth.adm_user_mem_copilot_condition` GROUP BY sa HAVING c > 1;  -- 期望 0 行

-- 3. 映射表的维度值合法
SELECT * FROM `auth-proj.auth.adm_user_mem_copilot_tb_col_mapping`
WHERE LOWER(to_name) NOT IN ('region', 'prdtype', 'refername');  -- 期望 0 行

-- 4. 外键都能对上：bind -> condition / group，grant_tb -> group
SELECT b.* FROM `auth-proj.auth.adm_user_mem_copilot_user_bind` b
LEFT JOIN `auth-proj.auth.adm_user_mem_copilot_condition` c ON c.id = b.condition_id
LEFT JOIN `auth-proj.auth.adm_user_mem_copilot_group` g ON g.id = b.group_id
WHERE c.id IS NULL OR g.id IS NULL;                                                         -- 期望 0 行
SELECT t.* FROM `auth-proj.auth.adm_user_mem_copilot_grant_tb` t
LEFT JOIN `auth-proj.auth.adm_user_mem_copilot_group` g ON g.id = t.group_id WHERE g.id IS NULL;  -- 期望 0 行

-- 5. 一 SA 一 Group（setup_copilot_sas.py 也会检查，违反会中止）
SELECT LOWER(c.sa) sa, COUNT(DISTINCT b.group_id) n
FROM `auth-proj.auth.adm_user_mem_copilot_user_bind` b
JOIN `auth-proj.auth.adm_user_mem_copilot_condition` c ON c.id = b.condition_id
GROUP BY 1 HAVING n > 1;                                                                    -- 期望 0 行

-- 6. 名册表的 acl_group 都能识别（Group 邮箱，或以 write / read 结尾）
SELECT * FROM `auth-proj.auth.adm_user_mem_copilot_acl_group_sa`
WHERE sa IS NULL OR NOT (acl_group LIKE '%@%' OR LOWER(acl_group) LIKE '%write' OR LOWER(acl_group) LIKE '%read');  -- 期望 0 行

-- 7. 名册表里不能有 Copilot SA（whitelist_groups.py 也会拦截）
SELECT * FROM `auth-proj.auth.adm_user_mem_copilot_acl_group_sa` WHERE sa LIKE 'copilot-%';   -- 期望 0 行
```

- [ ] 风险 R6：和客户确认业务表里过滤列为 NULL 的行是否允许被查到，以及条件表和业务表的大小写是否一致。

---

## 阶段 6：创建 Copilot 权限 SA 并授权（Step 6）

**输入**：P3（权限表数据集，脚本直接读 `user_bind ⋈ condition ⋈ group` 和 `grant_tb ⋈ group`）、P5-b、P5-c

**示例输入**：阶段 5 的 `group` / `grant_tb` / `user_bind` 三张表和条件表。脚本从中得到：`copilot-u-001 → group_copilot_high`、`copilot-u-002 → group_copilot_low`；高权限组可读 `fact_orders`、`fact_booking`，低权限组可读 `fact_orders` 和整个 `dw_public` 数据集。

```bash
# 1) 演练：查看输入来源、一 SA 一 Group 校验、配额、API SA 数据权限检查、扮演风险、全部计划
python setup_copilot_sas.py --project copilot-proj --api-sa copilot-api@proj.iam.gserviceaccount.com \
    --auth-dataset auth-proj.auth --all-group group_copilot_all_sa@domain \
    --condition-table auth-proj.auth.adm_user_mem_copilot_condition $A | tee logs/06_sas_plan.log

# 2) 执行
python setup_copilot_sas.py ...（同上）... --apply $A | tee logs/06_sas_apply.log
```

没有权限表、只有清单文件时，把 `--auth-dataset auth-proj.auth` 换成 `--sa-file sas.csv --grants-file grants.csv`（格式见附录 A）。如果要从表里导出这两个 CSV，用的就是脚本内部的两条 SQL：
```sql
SELECT LOWER(c.sa) AS account_id, LOWER(g.`group`) AS `group`
FROM `auth-proj.auth.adm_user_mem_copilot_user_bind` b
JOIN `auth-proj.auth.adm_user_mem_copilot_condition` c ON c.id = b.condition_id
JOIN `auth-proj.auth.adm_user_mem_copilot_group` g ON g.id = b.group_id;
SELECT LOWER(g.`group`) AS `group`, t.table_name AS resource
FROM `auth-proj.auth.adm_user_mem_copilot_grant_tb` t
JOIN `auth-proj.auth.adm_user_mem_copilot_group` g ON g.id = t.group_id;
```

**示例输出** 1) 演练
```
===== 模式: DRY-RUN =====
[SOURCE] 权限 SA 清单: auth-proj.auth.adm_user_mem_copilot_user_bind ⋈ auth-proj.auth.adm_user_mem_copilot_condition ⋈ auth-proj.auth.adm_user_mem_copilot_group（2 行）
[SOURCE] 表级授权范围: auth-proj.auth.adm_user_mem_copilot_grant_tb ⋈ auth-proj.auth.adm_user_mem_copilot_group（4 行）
[INPUT] 权限 SA 2 个，表级授权 4 条，一 SA 一 Group: OK
[QUOTA] 现有 3 个 SA，新建 2 个，上限 100: OK
API SA 数据权限检查: OK
[IMPERSONATION-RISK] user:admin@domain 通过项目级 roles/iam.serviceAccountTokenCreator 可扮演项目内任意 SA（含权限 SA）
[IMPERSONATION-INFO] 另有 6 个 Google 托管服务代理具备扮演能力（由 Google 管理，通常无需处理）
  建议：回收上述项目级扮演权限，或把权限 SA 放在独立项目中
[PLAN] Group: ['group_copilot_all_sa@domain', 'group_copilot_high@domain', 'group_copilot_low@domain']
[PLAN] SA copilot-u-001@copilot-proj.iam.gserviceaccount.com -> group_copilot_high@domain, group_copilot_all_sa@domain; TokenCreator <- copilot-api@proj.iam.gserviceaccount.com
[PLAN] SA copilot-u-002@copilot-proj.iam.gserviceaccount.com -> group_copilot_low@domain, group_copilot_all_sa@domain; TokenCreator <- copilot-api@proj.iam.gserviceaccount.com
[PLAN] roles/bigquery.dataViewer on prod-proj.dw.fact_orders -> group:group_copilot_high@domain
[PLAN] roles/bigquery.dataViewer on prod-proj.dw.fact_booking -> group:group_copilot_high@domain
[PLAN] roles/bigquery.dataViewer on prod-proj.dw.fact_orders -> group:group_copilot_low@domain
[PLAN] roles/bigquery.dataViewer on prod-proj.dw_public -> group:group_copilot_low@domain
[PLAN] roles/bigquery.dataViewer on auth-proj.auth.adm_user_mem_copilot_condition -> group:group_copilot_all_sa@domain
[PLAN] roles/bigquery.jobUser on project copilot-proj -> group:group_copilot_all_sa@domain
```

**示例输出** 2) 执行（在演练输出之后继续打印；第二次执行全部变成 `[EXISTS]`）
```
[GROUP] 已创建 group_copilot_all_sa@domain
[GROUP] 已创建 group_copilot_high@domain
[GROUP] 已创建 group_copilot_low@domain
[SA] copilot-u-001@copilot-proj.iam.gserviceaccount.com 已创建
  [OK] roles/iam.serviceAccountTokenCreator on copilot-u-001@copilot-proj.iam.gserviceaccount.com -> copilot-api@proj.iam.gserviceaccount.com
  [OK] copilot-u-001@copilot-proj.iam.gserviceaccount.com 加入 group_copilot_high@domain
  [OK] copilot-u-001@copilot-proj.iam.gserviceaccount.com 加入 group_copilot_all_sa@domain
[SA] copilot-u-002@copilot-proj.iam.gserviceaccount.com 已创建
  [OK] roles/iam.serviceAccountTokenCreator on copilot-u-002@copilot-proj.iam.gserviceaccount.com -> copilot-api@proj.iam.gserviceaccount.com
  [OK] copilot-u-002@copilot-proj.iam.gserviceaccount.com 加入 group_copilot_low@domain
  [OK] copilot-u-002@copilot-proj.iam.gserviceaccount.com 加入 group_copilot_all_sa@domain
  [OK] roles/bigquery.dataViewer on prod-proj.dw.fact_orders -> group:group_copilot_high@domain
  [OK] roles/bigquery.dataViewer on prod-proj.dw.fact_booking -> group:group_copilot_high@domain
  [OK] roles/bigquery.dataViewer on prod-proj.dw.fact_orders -> group:group_copilot_low@domain
  [OK] READER on dataset prod-proj.dw_public -> group:group_copilot_low@domain
  [OK] roles/bigquery.dataViewer on auth-proj.auth.adm_user_mem_copilot_condition -> group:group_copilot_all_sa@domain
  [OK] roles/bigquery.jobUser on project copilot-proj -> group:group_copilot_all_sa@domain
===== 完成 (APPLY) =====
```

**示例输出** 会中止的情况（都不做任何变更）
```
# a) 同一个 SA 绑定了两个 Group（退出码 1）
[ERROR] 一 SA 一 Group：copilot-u-001@copilot-proj.iam.gserviceaccount.com 同时映射到 ['group_copilot_high@domain', 'group_copilot_low@domain']
已中止，未做任何变更。请修正 adm_user_mem_copilot_user_bind（或 sas.csv）后重试。

# b) 超过项目 SA 配额（退出码 2）
[QUOTA] SA 数量将达到 103，超过单项目默认上限 100；请复用 SA 或申请配额

# c) API SA 自己有数据读权限（退出码 3）
[API-SA] copilot-api@proj.iam.gserviceaccount.com 拥有数据读权限: project prod-proj: roles/bigquery.dataViewer
API SA 数据权限检查: FAILED（API SA 只能通过扮演权限 SA 查询，请先回收上述权限）
```

**校验**
- [ ] 输出有 `[INPUT] ... 一 SA 一 Group: OK`。**退出码 1** 且有 `[ERROR] 一 SA 一 Group` 说明 `user_bind` 里有 SA 绑了两个 Group，先修表；
- [ ] 输出有 `[QUOTA] ... OK`。**退出码 2** 表示超过 100 个 SA 的上限：先申请配额，或者让行权限相同的人共用一个 SA（风险 R3）；
- [ ] 输出有 `API SA 数据权限检查: OK`。**退出码 3** 表示 API SA 自己能读数据，必须先回收这些权限；
- [ ] **`[IMPERSONATION-RISK]`**：列出的主体能直接扮演任意权限 SA，绕过 API SA。要和客户逐个确认、回收；或者把权限 SA 放到一个单独的项目里。正式上线建议加 `--strict-impersonation`，存在风险时直接中止；
- [ ] `[PLAN]` 里的 SA → Group、Group → 表 和阶段 5 的表内容一致；
- [ ] 执行后每行显示 `[OK]`（新增）或 `[EXISTS]`（已存在），没有 `[ERROR]`；
- [ ] 抽查一个权限 SA：只有 API SA 对它有 TokenCreator。
  ```bash
  gcloud iam service-accounts get-iam-policy copilot-u-001@copilot-proj.iam.gserviceaccount.com
  # bindings:
  # - members: [serviceAccount:copilot-api@proj.iam.gserviceaccount.com]
  #   role: roles/iam.serviceAccountTokenCreator
  ```
- [ ] 客户完成 S8 后端改造（登录用户 → 查映射 → API SA 扮演权限 SA → 提交查询）。

---

## 阶段 7：挂载 Copilot 行级策略（Step 7）

**输入**：P4（映射表）、P3、P5-b、P2

**示例输入**：映射表和条件表的内容见[附录 A](#附录-a输入文件模板)。`fact_orders` 映射了三个维度，`fact_booking` 只映射了两个，而且列名不同、一个还是嵌套字段——脚本会按表分别生成条件。

```bash
# 1) 演练：核对每张表的 [MAP] 行（列名 -> 维度）和生成的 DDL
python apply_copilot_rls.py --mapping-table auth-proj.auth.adm_user_mem_copilot_tb_col_mapping \
    --condition-table auth-proj.auth.adm_user_mem_copilot_condition \
    --groups group_copilot_high@domain,group_copilot_low@domain \
    --tables-file batch_N.txt $A | tee logs/07_copilot_plan.log

# 2) 执行
python apply_copilot_rls.py ...（同上）... --apply $A | tee logs/07_copilot_apply.log
```

**示例输出** 执行（演练输出完全相同，只是首行是 `DRY-RUN`、不真正执行 DDL）
```
===== 模式: APPLY  policy=rls_copilot_subquery_policy  grantees=['group:group_copilot_high@domain', 'group:group_copilot_low@domain'] =====
[MAP] prod-proj.dw.fact_orders: region->region, prd_type->prdtype, refername->refername
[MAP] prod-proj.dw.fact_booking: area_code->region, ext.ref_name->refername
[CREATE] prod-proj.dw.fact_orders
CREATE OR REPLACE ROW ACCESS POLICY `rls_copilot_subquery_policy`
ON `prod-proj.dw.fact_orders`
GRANT TO ("group:group_copilot_high@domain", "group:group_copilot_low@domain")
FILTER USING ((`region` IN (SELECT v FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c, UNNEST(c.region) AS v WHERE c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c WHERE c.sa = SESSION_USER() AND (c.region IS NULL OR ARRAY_LENGTH(c.region) = 0))) AND (`prd_type` IN (SELECT v FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c, UNNEST(c.prdtype) AS v WHERE c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c WHERE c.sa = SESSION_USER() AND (c.prdtype IS NULL OR ARRAY_LENGTH(c.prdtype) = 0))) AND (`refername` IN (SELECT v FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c, UNNEST(c.refername) AS v WHERE c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c WHERE c.sa = SESSION_USER() AND (c.refername IS NULL OR ARRAY_LENGTH(c.refername) = 0))))
[CREATE] prod-proj.dw.fact_booking
CREATE OR REPLACE ROW ACCESS POLICY `rls_copilot_subquery_policy`
ON `prod-proj.dw.fact_booking`
GRANT TO ("group:group_copilot_high@domain", "group:group_copilot_low@domain")
FILTER USING ((`area_code` IN (SELECT v FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c, UNNEST(c.region) AS v WHERE c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c WHERE c.sa = SESSION_USER() AND (c.region IS NULL OR ARRAY_LENGTH(c.region) = 0))) AND (`ext`.`ref_name` IN (SELECT v FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c, UNNEST(c.refername) AS v WHERE c.sa = SESSION_USER()) OR EXISTS (SELECT 1 FROM `auth-proj.auth.adm_user_mem_copilot_condition` AS c WHERE c.sa = SESSION_USER() AND (c.refername IS NULL OR ARRAY_LENGTH(c.refername) = 0))))
===== 完成 (APPLY) =====
```
再跑一次：两张表都显示 `[NOOP]`；改了映射表再跑：对应表显示 `[REPLACE]` 和新的 DDL。

**示例输出** 三种异常
```
# a) 有表还没挂白名单策略（退出码 2，整批中止，什么都没做）
[MAP] prod-proj.dw.fact_new: region->region
[ABORT] prod-proj.dw.fact_new: 缺少白名单 policy `rls_bypass_full_access`
已中止，未做任何变更。请先用 apply_bypass_rls.py 为这些表挂载白名单 policy。

# b) 映射表配置错误（只跳过这张表，其他表照常，退出码 1）
[SKIP] prod-proj.dw.fact_booking: 列 area_cd（维度 region）在表中不存在

# c) 映射表里没有本批某张表的配置（跳过）
[SKIP] prod-proj.dw.fact_other: 映射表中没有该表的过滤字段配置
```

**校验**
- [ ] 如果阶段 5 确认业务表和条件表大小写不一致，命令要加 `--case-insensitive`（这是全局开关：所有表统一加，巡检时也要加）；
- [ ] 每张表的 `[MAP]` 行和映射表配置一致（不同表的列名、维度个数可以不同）；
- [ ] **退出码 2**（`[ABORT] 缺少白名单 policy`）：有表还没完成阶段 4，脚本没有做任何变更；
- [ ] **`[SKIP]` 加错误原因**（列不存在、在 REPEATED 字段里、类型不支持等）：修正映射表后重跑，其他表不受影响；
- [ ] 退出码为 0，每张表显示 `[CREATE]`、`[REPLACE]` 或 `[NOOP]`；
- [ ] 再跑一次演练，每张表都应显示 `[NOOP]`。

---

## 阶段 8：巡检与端到端验收（Gate 2）

### 8.1 巡检

```bash
python inspect_rls.py --tables-file batch_N.txt \
    --mapping-table auth-proj.auth.adm_user_mem_copilot_tb_col_mapping \
    --condition-table auth-proj.auth.adm_user_mem_copilot_condition \
    --bypass-groups group_full_write@domain,group_full_read@domain \
    --copilot-groups group_copilot_high@domain,group_copilot_low@domain \
    --copilot-patterns 'copilot-*@*' --copilot-members copilot-api@proj.iam.gserviceaccount.com \
    --api-sa copilot-api@proj.iam.gserviceaccount.com \
    --acl-table auth-proj.auth.adm_user_mem_copilot_acl_group_sa --probe-sa probe-sa@ops-proj.iam.gserviceaccount.com \
    $A | tee logs/08_inspect.log
```

**示例输出** 一切正常（退出码 0）
```
[OK] prod-proj.dw.fact_orders
[OK] prod-proj.dw.fact_booking
[ACL] 名册 auth-proj.auth.adm_user_mem_copilot_acl_group_sa: 4 行，已与 2 个白名单 Group 比对

巡检完成：2 张表，2 个白名单 Group，发现 0 个问题，0 个提醒
```

**示例输出** 有问题时（退出码 1；每种问题一行，`[WARN]` 不计入问题数）
```
[OK] prod-proj.dw.fact_orders
[ISSUE] prod-proj.dw.fact_booking: `rls_copilot_subquery_policy` 过滤条件与映射表不一致: region = "HK"
[ISSUE] 白名单组 group_full_read@domain 中混入 Copilot SA: copilot-u-003@copilot-proj.iam.gserviceaccount.com
[ISSUE] 白名单组 group_full_read@domain 的成员 someone@domain 不在白名单名册中（来历不明的全量权限，请补录名册或移出组）
[ISSUE] 白名单名册中的 zeus-etl2@etl-proj.iam.gserviceaccount.com 还没有加入 group_full_write@domain（存量任务可能查不到数据，请热修补）
[ACL] 名册 auth-proj.auth.adm_user_mem_copilot_acl_group_sa: 5 行，已与 2 个白名单 Group 比对
[ISSUE] copilot-u-001@copilot-proj.iam.gserviceaccount.com 同时属于多个 Copilot 组: ['group_copilot_high@domain', 'group_copilot_low@domain']
[WARN] copilot-u-009@copilot-proj.iam.gserviceaccount.com 在 Copilot 组中但条件表没有条件行（该 SA 将查不到任何数据）

巡检完成：2 张表，2 个白名单 Group，发现 5 个问题，1 个提醒
```

- [ ] 退出码为 0，每张表一行 `[OK]`，最后显示"发现 0 个问题"；
- [ ] 没有 `[ISSUE]`：过滤条件和映射表不一致（映射改了没重跑阶段 7，或策略被手工改过）、白名单组混入 Copilot SA、组成员与名册不一致、条件表未按 `sa` 聚簇、某个 SA 同时在高低两个组、API SA 在 Copilot 组里，都属于问题；
- [ ] 逐条看 `[WARN]`：Copilot 组里没有条件行的 SA 会查不到任何数据，确认是否符合预期；条件表里不在任何组的 SA 没有表级权限。

### 8.2 端到端五项验收

用 gcloud 的扮演链（API SA → 权限 SA）模拟 Copilot 后端。操作账号需要对 API SA 有 TokenCreator。

```bash
# 逗号分隔的扮演链：先扮演 API SA，再扮演权限 SA（已在测试环境验证）
export CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="copilot-api@proj.iam.gserviceaccount.com,copilot-u-001@copilot-proj.iam.gserviceaccount.com"
bq query --nouse_legacy_sql \
  'SELECT SESSION_USER() AS who, region, prd_type, refername, COUNT(*) AS n FROM `prod-proj.dw.fact_orders` GROUP BY 1,2,3,4'
unset CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
```

**示例输出**（`copilot-u-001` 的条件是 region ∈ {HK, SG}、refername = REF_A、产品不限）
```
+----------------------------------------------------+--------+----------+-----------+-----+
|                        who                         | region | prd_type | refername |  n  |
+----------------------------------------------------+--------+----------+-----------+-----+
| copilot-u-001@copilot-proj.iam.gserviceaccount.com | HK     | P1       | REF_A     | 812 |
| copilot-u-001@copilot-proj.iam.gserviceaccount.com | SG     | P2       | REF_A     | 377 |
+----------------------------------------------------+--------+----------+-----------+-----+
```
`who` 列应当是权限 SA 的邮箱，这同时验证了第 ③ 项；结果里不应出现 US 或 REF_B/REF_C。

| # | 验收项 | 怎么验证 | 期望结果 |
|---|---|---|---|
| ① | 有权限的用户返回的数据正确 | 用上面的扮演链，以一个已知条件（例如 region=['HK']）的权限 SA 查询；和管理员按同样条件手工过滤的结果对比 | 行数和分组完全一致；字段不同的表也要逐张验证 |
| ② | 无权限用户不返回数据 | 以一个没有条件行的权限 SA 查询；以低权限组 SA 查询高敏表 | 第一种返回 0 行；第二种报 `Access Denied: Table ...: User does not have permission to query table` |
| ③ | 作业身份是权限 SA | 见下方 SQL | `user_email` 是权限 SA，不是 API SA |
| ④ | ETL 写入不中断 | 观察 Zeus 跨天调度；或用 ETL SA 做一次 INSERT 加 DELETE | 全部成功 |
| ⑤ | 白名单可以读全量数据 | 以验证 SA 查 `COUNT(*)` | 和表元数据的行数一致 |

```sql
-- ③ 作业身份
SELECT user_email, job_id, creation_time
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
  AND REGEXP_CONTAINS(query, r'fact_orders') ORDER BY creation_time DESC LIMIT 10;
-- 期望 user_email = copilot-u-001@copilot-proj.iam.gserviceaccount.com
```

另外两项检查：
- [ ] API SA 直接查询目标表 → `Access Denied`；
- [ ] 测试表通过后，**正式表观察 1–2 天**，再签收 Gate 2。

---

## 阶段 9：分批推广

| 批次 | 时间 | 表范围 |
|---|---|---|
| 30% | 10-23 | `batch_30.txt` |
| 50% | 10-26 | `batch_50.txt` |
| 80% | 10-27 | `batch_80.txt` |
| 100% | 10-28 | `batch_100.txt` |

**每一批**都按顺序执行：阶段 2（只扫新增的表）→ 阶段 3（只补加新增账号，带探针）→ 阶段 4（带 `--verify-sa`）→ 阶段 7 → 阶段 8.1。所有脚本都可以重复执行，已经完成的部分会显示 `[NOOP]` 或 `[EXISTS]`。

**放行条件**：上一批巡检 0 个问题，且业务方确认 24 小时内没有异常。

---

## 应急回退手册

| 场景 | 现象 | 处理 | 命令 |
|---|---|---|---|
| A. 漏掉了某个存量账号 | 某个 ETL 或报表突然查到 0 行，或报 `does not have full access` | **热修补**：只把这个账号补进白名单，不动 RLS（约 1–5 分钟生效）；事后把它补进名册表，否则巡检会报"不在名册中" | `python whitelist_groups.py --read-group group_full_read@domain --read-members etl2@p.iam.gserviceaccount.com --copilot-patterns 'copilot-*@*' --apply $A`（写账号改用 `--write-group` 和 `--write-members`） |
| B. Copilot 策略有问题 | Copilot 返回的数据不对 | 只撤掉 Copilot 策略，保留白名单策略（Copilot 账号会查不到数据，存量业务不受影响） | `python rollback_group_rls.py --tables-file batch_N.txt --policy-names rls_copilot_subquery_policy --backup-dir backup/ --apply $A` |
| C. 大面积故障 | 存量业务大量报错 | **一键回退**：删除这些表上的全部 RLS | `python rollback_group_rls.py --tables-file batch_N.txt --backup-dir backup/ --apply $A` |
| D. 要恢复已删除的策略 | 回退后需要还原 | 用 `backup/*.json` 里每条策略的 `ddl` 字段重新执行 | `bq query --nouse_legacy_sql "$(jq -r '.policies[].ddl' backup/<file>.json)"`（逐条执行） |

**示例输出** 场景 A 热修补
```
===== 模式: APPLY =====
[PLAN] group_full_read@domain: 1 个成员
  group_full_read@domain <- etl2@p.iam.gserviceaccount.com
[MEMBER] group_full_read@domain: 新增 1，已存在 0
[NOTE] 未做探针验证；挂载 RLS 前请确认 Group 成员关系已生效（通常 1~5 分钟）
===== 完成 (APPLY) =====
```

**示例输出** 场景 B 只撤 Copilot 策略（先演练：去掉 `--apply`，输出相同但没有 `[BACKUP]` 和 `-> 完成`）
```
===== 模式: APPLY =====
[SCOPE] 未指定 group —— 将删除目标表上名称为 ['rls_copilot_subquery_policy'] 的 RLS
[SCAN] 共 2 张表待检查
[TABLE] prod-proj.dw.fact_orders  (共 2 条 RLS，删除 1 条，剥离 0 条)
  [BACKUP] backup/prod-proj.dw.fact_orders.20261023-220501.json
  [DROP] `rls_copilot_subquery_policy` filter=(region IN (
  SELECT
    v
  ...
)) grantees=['group:group_copilot_high@domain', 'group:group_copilot_low@domain']
    DDL: DROP ROW ACCESS POLICY `rls_copilot_subquery_policy` ON `prod-proj.dw.fact_orders`
    -> 完成
[TABLE] prod-proj.dw.fact_booking  (共 2 条 RLS，删除 1 条，剥离 0 条)
  [BACKUP] backup/prod-proj.dw.fact_booking.20261023-220503.json
  [DROP] `rls_copilot_subquery_policy` filter=(area_code IN (
  ...
    DDL: DROP ROW ACCESS POLICY `rls_copilot_subquery_policy` ON `prod-proj.dw.fact_booking`
    -> 完成
===== 完成 (APPLY)：2 张表，共处理 2 条 RLS =====
```

**示例输出** 场景 C 一键回退（最后一条策略只能用 `DROP ALL`，脚本自动处理）
```
===== 模式: APPLY =====
[SCOPE] 未指定 group —— 将删除目标表上的【所有】RLS
[SCAN] 共 2 张表待检查
[TABLE] prod-proj.dw.fact_orders  (共 2 条 RLS，删除 2 条，剥离 0 条)
  [BACKUP] backup/prod-proj.dw.fact_orders.20261023-221015.json
  [DROP] `rls_bypass_full_access` filter=TRUE grantees=['group:group_full_read@domain', 'group:group_full_write@domain']
  [DROP] `rls_copilot_subquery_policy` filter=(region IN (
  ...
    DDL: DROP ALL ROW ACCESS POLICIES ON `prod-proj.dw.fact_orders`
    -> 完成
  [NOTE] 回退后该表已没有任何 RLS，所有有表读权限的用户可见全部行
[TABLE] prod-proj.dw.fact_booking  (共 2 条 RLS，删除 2 条，剥离 0 条)
  ...
===== 完成 (APPLY)：2 张表，共处理 4 条 RLS =====
```
备份文件的内容见[附录 A](#附录-a输入文件模板)。

**回退后的校验**：`bq ls --row_access_policies prod-proj:dw.fact_orders` 的结果符合预期（场景 B 只剩 `rls_bypass_full_access`，场景 C 为空）；业务方确认恢复正常。

---

## 日常运维（Day-2）

| 事项 | 频率 | 操作 |
|---|---|---|
| 巡检 | 每日（建议放进定时任务） | 运行阶段 8.1 的命令（带 `--acl-table`），退出码不为 0 就告警 |
| 新增 ETL/BI 账号（风险 R7） | 开通账号时 | **先在名册表 `adm_user_mem_copilot_acl_group_sa` 加一行**，再跑阶段 3 的命令（`--acl-table`，已有成员会显示"已存在"）；写进客户的账号开通流程。紧急时先按场景 A 热修补，再补名册 |
| 新增目标表 | 按需 | 映射表加行 → 阶段 2 → 3 → 4 → 7 → 8.1 |
| 映射表修改 | 修改后 | 重跑阶段 7（会显示 `[REPLACE]`）→ 8.1 |
| 新增或调整权限 SA | 按需 | 客户更新 `user_bind` / `grant_tb`（或 `sas.csv` / `grants.csv`）→ 重跑阶段 6（已有的显示 `[EXISTS]`） |
| 清理探针表 | 项目结束后 | 删除探针数据集里的 `_rls_probe_*` 表（或整个探针数据集） |

---

## 附录 A：输入文件模板

本手册所有示例使用同一套样例环境，前后可以对照：

| 角色 | 样例值 |
|---|---|
| 业务表 | `prod-proj.dw.fact_orders`（列 `region`、`prd_type`、`refername`）、`prod-proj.dw.fact_booking`（列 `area_code`、`ext.ref_name`） |
| 权限表 | 数据集 `auth-proj.auth`：`adm_user_mem_copilot_condition`、`..._tb_col_mapping`、`..._group`、`..._grant_tb`、`..._user_bind`、`..._acl_group_sa` |
| 存量账号 | 写：`zeus-etl@etl-proj.iam.gserviceaccount.com`、`admin@domain`；读：`iba-reader@bi-proj.iam.gserviceaccount.com`、`bi-adhoc@bi-proj.iam.gserviceaccount.com` |
| Copilot | API SA `copilot-api@proj.iam.gserviceaccount.com`；权限 SA `copilot-u-001`（高权限）、`copilot-u-002`（低权限），都在 `copilot-proj` |
| Group | `group_full_write@domain`、`group_full_read@domain`、`group_copilot_high@domain`、`group_copilot_low@domain`、`group_copilot_all_sa@domain` |
| 辅助 | 探针 SA `probe-sa@ops-proj.iam.gserviceaccount.com`、探针数据集 `ops-proj.rls_probe`、验证 SA = `iba-reader` |

**batch_N.txt**（P2，`#` 开头为注释）
```
# 首批正式表
prod-proj.dw.fact_orders
prod-proj.dw.fact_booking
```

**projects.txt**（P2-b，宽松版白名单用；每行一个项目 ID）
```
# ETL、BI、调度、业务数据所在的全部项目
prod-proj
etl-proj
bi-proj
```

**scan_batch_N.csv**（阶段 2 的输出、阶段 3 的输入；两种扫描方式列相同，`list_project_sas.py` 多 `display_name`、`disabled` 两列）
```
principal,principal_type,can_read,can_write,suggested_group,sources,jobs_read_count,jobs_write_count,wildcard_jobs,copilot,note
serviceAccount:zeus-etl@etl-proj.iam.gserviceaccount.com,serviceAccount,True,True,write,dataset:dw:WRITER,93,48,0,False,
serviceAccount:iba-reader@bi-proj.iam.gserviceaccount.com,serviceAccount,True,False,read,table:fact_orders:roles/bigquery.dataViewer; table:fact_booking:roles/bigquery.dataViewer,58,0,0,False,
serviceAccount:bi-adhoc@bi-proj.iam.gserviceaccount.com,serviceAccount,True,False,read,project:roles/bigquery.dataViewer,12,0,3,False,最近有 3 次通配符表查询（table_*），表启用 RLS 后会失败，需改写 SQL（R5）
serviceAccount:copilot-u-001@copilot-proj.iam.gserviceaccount.com,serviceAccount,False,False,,,21,0,0,True,Copilot SA，已排除出白名单; 仅出现在作业历史（可能来自 Folder/Org 继承或已回收权限），请人工确认
specialGroup:projectReaders,specialGroup,True,False,,dataset:dw:READER,0,0,0,False,非具体账号，无法加入 Group，请人工处理
user:admin@domain,user,True,True,write,project:roles/bigquery.admin; dataset:dw:OWNER,141,149,0,False,
```
客户审核时只需要改 `suggested_group` 列（`write` / `read` / 留空表示不加），或直接删掉整行；其他列只是参考信息。

**sas.csv**（P5-d，可以从 `adm_user_mem_copilot_user_bind` 和 `adm_user_mem_copilot_group` 导出）
```
account_id,group,display_name
copilot-u-001,group_copilot_high@domain,HK sales lead
copilot-u-002,group_copilot_low@domain,
```
`account_id` 为 6–30 位，由小写字母、数字和 `-` 组成，以字母开头；一个 SA 只能属于一个 Group。

**grants.csv**（P5-e，可以从 `adm_user_mem_copilot_grant_tb` 导出；resource 写表名就授表级权限，写到数据集就授数据集级权限）
```
group,resource
group_copilot_high@domain,prod-proj.dw.fact_orders
group_copilot_high@domain,prod-proj.dw.fact_booking
group_copilot_low@domain,prod-proj.dw.fact_orders
group_copilot_low@domain,prod-proj.dw_public
```

**映射表** `adm_user_mem_copilot_tb_col_mapping`（P4；BigQuery 表，或 `--mapping-csv` 指定的 CSV）
```
table_name,col_name,to_name
prod-proj.dw.fact_orders,region,region
prod-proj.dw.fact_orders,prd_type,prdtype
prod-proj.dw.fact_orders,refername,refername
prod-proj.dw.fact_booking,area_code,region
prod-proj.dw.fact_booking,ext.ref_name,refername
```
同一个维度在不同表里列名可以不同（`region` ↔ `area_code`），也可以是嵌套字段（`ext.ref_name`）；一张表只映射它有的维度。

**条件表** `adm_user_mem_copilot_condition`（P3；客户维护，脚本只读。`NULL` 或空数组 = 该维度全部放行）

| sa | region | prdtype | refername | 含义 |
|---|---|---|---|---|
| `copilot-u-001@copilot-proj.iam.gserviceaccount.com` | `['HK','SG']` | `[]` | `['REF_A']` | 只能看 HK/SG 且 refername=REF_A 的行，产品类型不限 |
| `copilot-u-002@copilot-proj.iam.gserviceaccount.com` | `NULL` | `['P1']` | `NULL` | 只能看产品类型 P1 的行 |

**回退备份文件** `backup/prod-proj.dw.fact_orders.20261023-220501.json`（`rollback_group_rls.py --backup-dir` 生成；`ddl` 可直接执行以恢复）
```json
{
  "table": "prod-proj.dw.fact_orders",
  "time": "2026-10-23T22:05:01+0800",
  "policies": [
    {
      "id": "rls_bypass_full_access",
      "filter": "TRUE",
      "grantees": ["group:group_full_read@domain", "group:group_full_write@domain"],
      "ddl": "CREATE OR REPLACE ROW ACCESS POLICY `rls_bypass_full_access`\nON `prod-proj.dw.fact_orders`\nGRANT TO (\"group:group_full_read@domain\", \"group:group_full_write@domain\")\nFILTER USING (TRUE)"
    },
    {
      "id": "rls_copilot_subquery_policy",
      "filter": "(region IN (\n  SELECT\n    v\n  FROM ...",
      "grantees": ["group:group_copilot_high@domain", "group:group_copilot_low@domain"],
      "ddl": "CREATE OR REPLACE ROW ACCESS POLICY `rls_copilot_subquery_policy`\nON `prod-proj.dw.fact_orders`\nGRANT TO (...)\nFILTER USING (...)"
    }
  ]
}
```

---

## 附录 B：退出码速查

| 脚本 | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| scan_bq_access.py | 成功 | — | （参数错误） | — | — |
| list_project_sas.py | 成功 | 部分项目读取失败（其余项目已写入 CSV） | （参数错误） | — | — |
| whitelist_groups.py | 成功 | 名册表有误（未做任何变更）、部分失败或探针未通过 | 名单中混入 Copilot SA（未做任何变更） | — | — |
| apply_bypass_rls.py | 成功 | 有冲突、执行失败或验证失败 | 首条策略没加 `--force-first-policy`（未做任何变更） | — | — （5：最近有作业运行在 STANDARD 版本，未做任何变更） |
| setup_copilot_sas.py | 成功 | 输入有误 / 一 SA 多 Group（未做任何变更）、部分失败 | 超出 SA 配额 | API SA 有数据读权限 | 存在扮演风险（仅 `--strict-impersonation`） |
| apply_copilot_rls.py | 成功 | 有表被跳过或执行失败 | 缺少白名单策略（未做任何变更） | — | — |
| inspect_rls.py | 无问题 | 发现问题 | （参数错误） | — | — |
| rollback_group_rls.py | 成功 | 部分表处理失败 | （参数错误） | — | — |
