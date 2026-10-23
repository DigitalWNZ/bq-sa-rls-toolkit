# 测试

> 最新一次完整测试：2026-10-22；2026-10-23 新增的用例单独运行，全部通过。**五类测试全部 100% 通过。**

| 类别 | 位置 | 数量 | 结果 | 环境 |
|---|---|---|---|---|
| 1 单体测试 | `tests/unit/` | 829 | ✅ 829 / 829 | 本地（FakeWorld 模拟 BigQuery / IAM / Cloud Identity；Cloud Identity 部分另用 HttpMockSequence 模拟真实响应） |
| 2 系统测试 | `tests/integration/test_e2e.py`、`test_z_abnormal.py`、`test_z_shared_bypass.py`、`test_z_grant_viewer.py` | 52 | ✅ 52 / 52（全套约 24 分钟；r08、s01–s06、g01–g05 单独运行） | 真实 GCP（Argolis 测试组织） |
| 3 功能测试 | `tests/functional/test_requirements.py` | 31 | ✅ 31 / 31 | 本地；每条需求另有对应的系统测试用例 |
| 4 性能测试 | `tests/perf/run_perf.py`、`simulate.py` | 1000 表 × 500 新增 × 100 存量 | ✅ 全部步骤成功，0 重试、0 错误 | 真实 GCP + 本地模拟 |
| 5 稳定性测试 | `tests/stability/test_stability.py`、`tests/integration/test_zz_stability.py` | 28 + 4 | ✅ 32 / 32 | 本地 + 真实 GCP |

## 运行方式

```bash
pip install -r requirements.txt pytest

# 本地（单体 + 功能 + 稳定性），约 3 秒，不访问 GCP；Python 3.9 与 3.13 均已实测通过
python -m pytest tests/unit tests/functional tests/stability -q

# 真实环境（系统测试 + 真实稳定性测试），约 19 分钟；会在测试项目中建表、建 SA / Group、设置并删除 RLS 规则
RLS_IT=1 RLS_IT_PROJECT=<测试项目> RLS_IT_ACCOUNT=<执行账号> RLS_IT_DOMAIN=<域名> RLS_IT_ORG=<组织ID> \
  python -m pytest tests/integration -v

# 性能（真实环境）：账号分布在主项目 + SA 池项目（每个项目最多 100 个 SA）
RLS_IT=1 ... python tests/perf/run_perf.py --tables 1000 --new 500 --existing 100 \
  --pool-projects <池项目1>,<池项目2>,... --parallel 32 --report perf_report.md

# 性能（本地模拟，输出 API 调用次数与按实测延迟估算的耗时）
python tests/perf/simulate.py --tables 1000 --new 500 --existing 100
```

| 环境变量 | 作用 |
|---|---|
| `RLS_IT=1` | 启用真实环境测试（未设置时 `tests/integration` 全部跳过） |
| `RLS_IT_PROJECT` / `RLS_IT_ACCOUNT` / `RLS_IT_DOMAIN` / `RLS_IT_ORG` | 测试项目、执行账号（需已 `gcloud auth login`）、Group 所在域名、组织 ID |
| `RLS_IT_SA_POOL_PROJECT` | 可选：测试项目 SA 已达 100 个上限时，把 Copilot M 这个测试 SA 建在同组织的这个项目里（默认就是测试项目） |
| `RLS_IT_LOG_DIR` | 可选：被测脚本运行日志的保存目录（默认每次测试会话一个临时目录） |
| `RLS_IT_CLEANUP=1` | 测试结束后删除测试数据集（默认保留，下次运行会重建表并清掉旧规则） |

---

## 1. 单体测试（829）

用 `tests/unit/fakes.py` 中的 FakeWorld 模拟 GCP（表、规则、授权对象、登记表 / 条件表 / 映射表、IAM、账号目录、Group），直接调用四个脚本的 `main()`，断言退出码、日志、生成的 DDL 与最终规则状态。

| 文件 | 数量 | 内容 |
|---|---|---|
| `test_rls_core.py` | 132 | 纯逻辑：表名 / 主体解析、规则命名、DDL 生成与注入防护、过滤条件规范化、计划（CREATE / NOOP / REPLACE）、登记表判定、主体分类（user / SA / 服务代理 / group / domain / public / federated / deleted）、不看角色的授权抽取、`source` 格式（排序、去重、5 处上限、带条件、未展开标注）、本组织域名判断、授权视图 / 例程 / 数据集引用 |
| `test_params_simplified.py` | 83 | 参数：值 / `.csv` / 混用 / 去重 / BOM / CRLF / 多列报错 / 文件不存在；重复参数累加；表名格式（反引号可选、拒绝冒号写法与非三段）；被删除的旧参数（含 apply_bypass 的 `--tables` / `--datasets` / `--projects`）→ 退出码 2；`--parallel` 默认 16 |
| `test_abnormal_cases.py` | 130 | 异常系：参数误用、注入（表名、Group 邮箱、映射表、条件表列名与 sa 值、CSV 公式）、脏数据、部分失败隔离、并发一致性 |
| `test_bypass_registry.py` | 51 | apply_bypass 只看登记表：目标 = `rls_enabled = 1` 的全部表（不扫描项目 / 数据集）、`[SCAN]` 汇总、表名格式不对 / 冲突 `[WARN]` + `[SKIP]`、登记的表不存在 `[SKIP]`、登记了视图 `[ERROR]`、登记表不可用 |
| `test_copilot_group.py` | 59 | apply_copilot Group 级别：每表一条规则、精确 DDL（每个子查询带 `c.status = 1`）、多维度 AND、只有 status = 1 的行生效（0 / NULL / 其它值不生效）、缺 status 列 / 类型不对 → 退出码 2 零变更、`[NOTE]` 总行数与生效行数、新增账号无需重跑、改映射 REPLACE、400 条上限、sa 校验（只看 status = 1） |
| `test_list_principals.py` | 86 | list_principals：**列出全部主体、不看角色**（读不到数据的角色、自定义角色、非具体账号也列出）；无授权 SA、待删除项目的 SA（成功 / 拒绝）、账号目录的 user 与 Group、多层文件夹、条件授权、服务代理、读取失败报错；`--projects` 读上级文件夹 / 组织策略（多层、读取失败、去重、无上级）；**Group 只展开一层、嵌套组只列组名**；展不开的 Group（外部域 `[NOTE]` / 本域 `[ERROR]`、辅助域名、跑脚本账号域名）；`source` 列；范围外授权视图 `[NOTE]`；**扫描期间表被删除（读表 IAM 返回 404）→ `[NOTE]` 跳过、退出码 0、其余照常；403 / 400 / 5xx 及其它位置的 404 仍 `[ERROR]`** |
| `test_gate_removal.py` | 31 | 已去掉的「闸门」：只提示不拦截；旧参数被拒 |
| `test_scripts.py` | 35 | 四个脚本的主流程 |
| `test_normal_cases.py` | 28 | 正常系：每条设计决定一个用例，含第 1 → 4 → 8 → 9 步端到端流程 |
| `test_auth_defaults.py` | 18 | 执行账号 / quota 项目自动确定；确定不了 → 退出码 2 + 提示 |
| `test_review_fixes.py` | 27 | 独立审查报告的修复项：BigQuery 报 Group 不存在时不重试、第一张表即停止（退出码 2、其余零 DDL）、执行中途出现则停止未开始的表；apply_bypass `--group` 格式检查；映射表列名不区分大小写；rollback 中途失败仍输出已删规则内容；Cloud Identity 403 无权限 / API 未启用 / 429 重试 / 5xx 用尽 / 空组 / 嵌套组读不到（HttpMockSequence）；Cloud Identity 只取直接成员、列出账号目录 Group（分页） |
| `test_log_file.py` | 17 | 运行日志文件：四个脚本默认写 `logs/<脚本名>_<时间戳>.log`、内容与屏幕逐字相同、`--log-dir`、目录不可写只 `[WARN]`、同一秒不覆盖、argparse 错误 / `--help` 不写、Ctrl-C 与参数错误也记录、32 线程并发不交错、写盘失败不影响脚本 |
| `test_gcp_auth.py` | 19 | 凭证：活动账号、默认项目、回退 ADC、token 到期刷新；通过 gcloud 扮演 SA 时 `[AUTH]` 显示实际执行的 SA 与登录账号、扮演失败的提示 |
| `test_gcp_ops.py` | 14 | 重试分类、404 判定、限速、挂载后验证（扮演失败立即失败）、getAncestry 解析、组织信息（customer ID、主域名） |
| `test_shared_bypass.py` | 67 | apply_bypass `--principals` / `--policy-name`：前缀必填（不带前缀、`domain:`、`allUsers`、注入字符、类型与邮箱不符、同邮箱两种类型、空列表 → 退出码 2 且零 API 调用）、规则名后缀校验、与 `--group` 二选一、`.csv` 输入；一条规则含全部主体、顺序不同 NOOP、增减主体 REPLACE 并列出将新增 / 将移除、与 `--group` 规则共存、撞名按完整名单覆盖、user / SA / Group 不存在第一张表即停止；rollback `--principals` 只去掉指定主体（`[REMOVE]`，保留原过滤条件）、去光才删除、与 `--policy-names` 取交集、剩余授权对象无法重建 → `[ERROR]` 不动、DDL 失败报告 |
| `test_grant_table_viewer.py` | 32 | grant_table_viewer：`--groups` 校验（带前缀 / SA / 格式不对 / 为空 → 退出码 2 且零 API 调用）、范围必填、`.csv` 与去重、数据集 / 项目展开；演练不写入、执行后重跑全部 NOOP、只加缺少的 Group、其它角色与成员保留、写入的策略保持 v1；表不存在 `[SKIP]`、读 / 写失败 `[ERROR]` 其余照常；并发冲突（409）重新读取后重试、用尽报错；Group 不存在第一张表即停止；HTTP 报错只打印正文（不打印服务端堆栈）；运行日志 |

## 2. 系统测试（52，真实 GCP）

`conftest.py` 在测试项目中准备：业务表（含列名不同、分区表、映射到不存在的列、映射表里没有、登记为未开启、没有 bypass 的表；每张 9 行，含 HK / SG / US × mobile 数据）、条件表 / 映射表 / 登记表（条件表有 `status` 列，另有一行 `status = 0` 的停用行；条件表、映射表、登记表自身、备用映射表都登记为 `rls_enabled = 0`；映射表 / 登记表中另有一张实际不存在的 `dropped_t`）、7 个测试 SA（存量读 / 写、通过数据集 ACL 授权、Copilot A / B / N / M）、4 个 Group（ReadOnly、Writable、ACL、Copilot）及其权限。然后按方案文档顺序运行四个脚本，并**以各账号身份实际查表**验证可见性。

| 用例 | 验证内容 |
|---|---|
| test_01–04 | list_principals：项目范围列出的 SA 与 IAM API **完全一致**（含没有任何授权的）；组织范围含其它项目的 SA、账号目录全部 user 与全部 Group；`source` 列（项目 SA、项目 IAM Owner、数据集 ACL、Group 成员）；排除参数；不给账号 / quota 参数时自动确定；Argolis 组织 IAM 中的外部域 Group 只 `[NOTE]`、`source` 注明「外部域，未展开」、退出码 0 |
| test_01c | list_principals 项目范围：项目外的 SA **只在组织上**被授予 BigQuery Data Viewer（继承）→ 也被列出；结束后撤销组织授权 |
| test_01d | list_principals 项目范围：其它项目的 SA 在测试项目上**只有基本角色 Viewer** → 也被列出；结束后撤销 |
| test_01e | list_principals：外层 Group 在测试项目上只有 Browser（不看角色）→ 列出，`source` 正确；其嵌套组只列组名（「嵌套组，未展开」）；嵌套组的成员不展开 |
| test_10–14 | apply_bypass **只看登记表**：不给范围参数即处理 `rls_enabled = 1` 的全部表（`[SCAN]` 数量正确、未开启的表完全不碰）、登记的 `dropped_t` → `[SKIP] 表不存在`、退出码 1；首次设置提示；两个白名单 Group + `--verify-sa`；`--tables` / `--datasets` / `--projects` → 退出码 2；登记表错误 / 冲突；登记表改为开启后下次即处理；重跑 NOOP、实际可见全部、REPLACE 打印旧内容 |
| test_20–26 | apply_copilot：无 bypass 也照建、演练、执行（**运行日志文件与屏幕输出逐字相同**；映射表列名 `REGION` 与表中 `region` 大小写不同也正确）；**Group 不存在 → 第一张表即停止、退出码 2、所有表零变更、不再等待重试（test_22c，bypass 与 copilot 各一次）**；**表已被 drop → `[SKIP] 表不存在`，演练 / 执行都只跳过这一张**；**同一 Group 内 A 只看 HK、M 只看 HK 且 mobile（多维度 AND）、B（维度全空）看全部、user 只看 SG、不在条件表的 0 行；没有校验维度的表 Copilot 成员 0 行**；改条件表不跑脚本即生效；**新增账号不跑脚本即生效**；**`status` 改为 0 / NULL → 立即 0 行，改回 1 → 立即恢复（test_25b）**；**条件表缺 `status` 列 / 类型为 STRING → 退出码 2、零变更（test_25c）**；`[NOTE]` 条件表总行数与 status = 1 的行数；重跑 NOOP、改坏后 REPLACE |
| test_30–34 | rollback：不给筛选 = 全部（演练）、按 Copilot Group、按 user 与规则名、按 Group、删光不拦 |
| r01–r07 | 登记表里的视图不支持 RLS 且被隔离、视图误配进映射表、条件表脏数据（大小写 / 前缀 / 组邮箱 / 乱码 / 特殊列名）、大小写修正后无需重跑、user 执行账号、不可扮演的 `--verify-sa` 立即失败、错误的 gcloud 账号、rollback 不存在的数据集 / 表 |
| r08 | list_principals 扫描时**真实地**在列出表之后删掉一张表 → 真实 BigQuery 返回 404 → `[NOTE] 表已不存在（扫描期间被删除），跳过`、退出码 0、无 `[ERROR]`、其余主体照常写入 CSV |
| s01–s06 | `test_z_shared_bypass.py`：`--principals` 用 `.csv` 输入 Group + 2 个 SA → 每张表一条共享规则、授权对象正好 3 个，两个 SA 只靠它就看到全部；重跑 NOOP（顺序不同）；去掉一个 SA → REPLACE、日志「将移除」、该 SA 立刻 0 行；名单里有不存在的 user / SA → 第一张表即停止、退出码 2、零变更（BigQuery 原文 `User … does not exist` / `Service account … does not exist`）；参数错误；**50 个主体写进一条规则成功**；rollback `--principals` 只从两条共享规则里去掉该 SA（`[REMOVE]`），其余主体照常可见；`--policy-names` 整条删除 |
| g01–g05 | `test_z_grant_viewer.py`：Group（成员为对数据集没有读权限的 SA）授权前查表 403，`--apply` 后能读到全部行；表上原有的其它角色授权保留；重跑 NOOP；`--datasets` 只给缺少的表授权；Group 不存在 → 第一张表即停止、退出码 2、零变更（BigQuery 原文 `IAM setPolicy failed for Table …: Group … does not exist.`）；表不存在 `[SKIP]`、参数错误退出码 2；已有部分 Group 时只加缺少的 |

## 3. 功能测试（31：客户需求逐条映射）

`REQUIREMENTS` 字典把每条客户需求映射到本地用例和真实环境用例；`test_requirement_table_complete` 保证每条需求都有用例。

| # | 客户需求 | 真实环境用例 |
|---|---|---|
| F01 | list_principals 项目范围：列出项目里全部 SA（含没有任何授权的、已禁用的） | test_01 |
| F02 | 组织范围：递归所有文件夹下 ACTIVE 项目的全部 SA；待删除项目也尝试列出其中的 SA（失败只 `[NOTE]`） | test_02 |
| F03 | 组织范围：账号目录全部 user（含暂停 / 归档、多域名）与全部 Group | test_02 |
| F04 | 授权记录（组织 / 文件夹 / 项目 IAM、数据集 ACL、表 IAM）中的全部授权对象，不看角色（其它项目 SA、外部 user、服务代理、Group 及其直接成员） | test_01 / 02 |
| F05 | 输出 3 列 email, principal_type, source（在哪里、以什么角色被找到）；不使用 Cloud Asset | test_01 |
| F06 | apply_bypass：每个白名单 Group 一条 FILTER TRUE 规则，ReadOnly / Writable 各一次 | test_11 / 12 / 13 |
| F07 | apply_bypass：目标表 = 登记表中 rls_enabled = 1 的全部表，不扫描项目 / 数据集；`--tables` / `--datasets` / `--projects` 已删除（传入即参数错误） | test_10 / 11 / 11d / 11f |
| F08 | apply_bypass：只有 rls_enabled = 1 的表授权；不看 status；表名格式不对 / 同名冲突 `[WARN]` + `[SKIP]`、表不存在 `[SKIP]`，退出码 1，其余表照常 | test_10 / 11e / r01 |
| F09 | apply_copilot：每张表给 Copilot Group 建一条规则，过滤条件与客户 sample 一致；同组成员按条件表各看各的 | test_22 / 23 |
| F10 | 维度 = 条件表除 id、sa、status 外的 ARRAY\<STRING\> 列；表的维度 = 映射表 to_name；多维度 AND；只有 status = 1 的行生效（每个子查询都加 `c.status = 1`），条件表缺 status 列退出码 2 | test_21 / 22 / 23 / 25b / 25c |
| F11 | 只处理登记表 rls_enabled = 1 的表；没有校验维度的表 `[SKIP]`；表已不存在 `[SKIP]`、其余表照常 | test_21 / 22b |
| F12 | 新增 Copilot 账号：加入 Group + 条件表加一行即生效，无需重跑脚本 | test_25 |
| F13 | 457 / 500 个账号也不超过每表 400 条规则上限（每表每 Group 一条） | 性能测试 |
| F14 | 条件表 / 映射表是否设置 RLS 只由登记表控制 | test_11 / 21 |
| F15 | 没有「闸门」：copilot 不要求 bypass；bypass 首条只提示；rollback 无删光保护 | test_10 / 20 / 30 / 34 |
| F16 | rollback：按主体（Group / SA / user，含手工规则）、按规则名、或全部；两者取交集 | test_31–34 |
| F17 | 三个 RLS 脚本默认只演练，`--apply` 才执行 | test_10 / 21 / 30 |
| F18 | 参数精简：值或 `.csv`、可重复累加；表名 project.dataset.table（反引号可选、不支持冒号）；旧参数被拒；`--parallel` 默认 16 | test_11d / 32 |
| F19 | 执行账号 / quota 项目自动确定；确定不了退出码 2 + 提示 | test_04 |
| F20 | 出错不输出 Python 堆栈；退出码 0 / 1 / 2 语义 | r05 / r06 / r07 |
| F21 | 每次运行自动保存日志文件（默认 `logs/`、`--log-dir` 可改、内容与屏幕完全一致、建不了只警告、不覆盖不清理） | test_22 |
| F22 | list_principals 项目范围：含上级文件夹 / 组织授权中的主体（继承） | test_01c |
| F23 | 展不开的 Group 作为 group 写入 CSV；外部域 `[NOTE]` 不影响退出码，本组织域名的 `[ERROR]` 退出码 1 | test_02 |
| F24 | 只有基本角色或读不到数据的角色（Job User、Browser 等）的 user / SA 也列出 | test_01d |
| F25 | 授权视图 / 数据集 / 例程所在项目不在扫描范围时 `[NOTE]` 列出 | 本地 |
| F26 | 授权记录中的 Group 只展开一层；嵌套组只列组名 | test_01e |
| F27 | 非具体账号也写入 CSV（domain / public / federated / deleted） | 本地 |
| F28 | apply_bypass `--principals`（必须带前缀，值或 `.csv`）+ `--policy-name`：多个主体共用一条 FILTER TRUE 规则；完整名单，REPLACE 时列出将新增 / 将移除；`--group` 不变、二者只能给一个 | s01–s05 |
| F29 | rollback 按主体回退时只从规则里去掉这些主体（`[REMOVE]`），去光才删除整条 | s06 |
| F30 | grant_table_viewer：给多个 Group 统一授予多张表的表级 BigQuery Data Viewer；已授权 NOOP、只加缺少的、其它授权保留；Group 不存在第一张表即停止 | g01–g05 |

## 4. 性能测试

### 4.1 真实环境（2026-10-19，`--parallel 32`）

规模：**1000 张业务表**（三个维度列 500 张、两列 300、一列 100、无 100）、映射表 2200 行、条件表 500 行；**500 个新增 SA**（全部在 Copilot Group）+ **100 个存量 SA**（ReadOnly / Writable 各 50）。

| 步骤 | 耗时 | 结果 |
|---|---|---|
| list_principals（项目范围） | 67s | 127 个主体 |
| apply_bypass（ReadOnly 组） | 47s | CREATE 1000 |
| apply_bypass（Writable 组） | 47s | CREATE 1000 |
| apply_bypass 重跑 | 54s | NOOP 1000 |
| apply_copilot 演练 | 23s | CREATE 900（演练） |
| apply_copilot 执行 | 54s | CREATE 900；审核 CSV 900 行 |
| apply_copilot 重跑 | 52s | NOOP 900 |
| 可见性验证（新增账号只见 HK / 无维度表 0 行 / 存量账号可见全部） | 5s | ✅ |
| rollback Copilot Group 规则（按主体） | 179s | 900 张表 900 条 |
| rollback 全部 | 139s | 1000 张表 2000 条 |

全程 0 次重试、0 个错误。Copilot 规则为 Group 级别后，**耗时只与表数有关，与账号数无关**（457 个账号时的结果基本相同）。

### 4.2 本地模拟

`simulate.py` 用 FakeWorld 按真实规模运行，统计各 API 调用次数并按实测延迟估算串行网络时间：apply_copilot 首次 900 条 DDL、重跑 900 次 getIamPolicy；新增 1 个账号后重跑仍全部 NOOP。

## 5. 稳定性测试（模拟非正常操作）

共同断言：退出码符合语义、**不输出 Python 堆栈**、重跑后每张表恰好一条正确的规则。

### 5.1 本地（28）

| 类别 | 用例 |
|---|---|
| 中断后重跑 | S01 Ctrl-C 后重跑收敛、再跑全部 NOOP；S02 网络中断；S03 部分 DDL 失败；S04 bypass 中断；S05 rollback 中断；S06 连续重跑 10 次幂等；S28 `--parallel 4` 下 Ctrl-C 立即停止（不再处理剩下的表） |
| 并发 | S07 两个 copilot 同时运行；S08 bypass 与 copilot 同时运行；S09 rollback 与 copilot 竞争后重跑收敛；S10 大量表 + 高并发 |
| 运行中环境变化 | S11 运行中表被删除；S12 表事先不存在；S13 两次运行之间维度被删除；S14 登记表关闭后规则保留到 rollback；S15 条件表被清空；S16 映射表读不到；S17 登记表读不到；S18 部分表读规则失败 |
| 暂时性错误 | S19 速率限制 / 后端错误自动重试；S20 真正的错误不重试 |
| 损坏的输入 | S21 二进制乱码 CSV；S22 GBK 编码 CSV；S23 超大列表文件；S24 CSV 路径是目录；S27 空字符串 / 空白参数 |
| 输出 / 其它 | S25 输出 CSV 不可写；S26 list_principals 被中断 |

### 5.2 真实环境（4，`test_zz_stability.py`，20 张独立的表，用完删除）

| 用例 | 场景 | 结果 |
|---|---|---|
| r10 | apply_copilot 运行中进程被 **kill -9** | 被杀时部分表已建；重跑退出码 0、已建的 NOOP；再跑全部 NOOP |
| r11 | rollback 运行中 **Ctrl-C** | 退出码 130、「已被用户中断」、无堆栈、剩余表未处理；重跑完成 |
| r12 | **两个 apply_copilot 同时运行** | 都退出码 0；每表恰好一条 Copilot 规则 |
| r13 | **apply_bypass 与 apply_copilot 同时运行** | copilot 退出码 0；bypass 处理登记表中全部开启的表（只有不存在的 `dropped_t` 被 `[SKIP]`，退出码 1）；两种规则互不覆盖 |

---

## 测试中发现并修复的问题（2026-10-23，grant_table_viewer）

| 问题 | 发现方式 | 修复 |
|---|---|---|
| BigQuery 表级 IAM 只支持 v1 策略：写 `version: 3` 报 400 `Unsupported policy version 3` | 系统测试 g01 | 不再请求 / 写入 v3，保持读到的版本；假环境同样拒绝 v3，防止回归 |
| 400 报错详情里的服务端堆栈恰好含 etag 等字样，被误判为并发冲突而重试 4 次 | 系统测试 g01 | 并发冲突只认 HTTP 409（或正文为 concurrent policy changes） |
| HTTP 报错把几 KB 的服务端堆栈打进日志 | 系统测试 g03 | 只打印「HTTP 状态码 + 报错正文」 |

## 测试中发现并修复的问题（2026-10-19）

| 问题 | 发现方式 | 修复 |
|---|---|---|
| `--parallel > 1` 时 Ctrl-C 后仍把剩下的表全部跑完 | 稳定性 S28 | 中断时取消未开始的任务，只等正在执行的 DDL 结束 |
| 同一参数写多次只保留最后一次，会静默漏表 | 单体测试 | 列表参数改为累加 |
| `--verify-sa` 的 SA 无法扮演时空等 300 秒 | 单体 + 系统 r05 | 扮演失败立即 `[VERIFY-FAIL]` |

## 没有覆盖的部分

- list_principals 列出待删除项目的 SA：在 Argolis 手工实测（建临时项目 → 建 SA → 删除项目）。项目 Owner 能列出；只有组织层权限（RUNBOOK 0.2）的账号得到 404、只打 `[NOTE]`。单体测试覆盖两种情况，系统测试未自动化（每次都要留下一个 30 天的待删除项目）。
- 账号目录只在超级管理员身份下实测；其它 Workspace 管理员角色只按文档推断。
- 不给 `--gcloud-account` 且没有 gcloud 登录、回退 application-default 凭证的路径只做了单体测试。
- list_principals 在 10 万张表规模下的耗时为按单表延迟推算（约 1.5 小时），未实测。
