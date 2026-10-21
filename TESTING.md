# 测试

> 最新一次完整测试：2026-10-21。**五类测试全部 100% 通过。**

| 类别 | 位置 | 数量 | 结果 | 环境 |
|---|---|---|---|---|
| 1 单体测试 | `tests/unit/` | 701 | ✅ 701 / 701 | 本地（FakeWorld 模拟 BigQuery / IAM / Cloud Identity；Cloud Identity 部分另用 HttpMockSequence 模拟真实响应） |
| 2 系统测试 | `tests/integration/test_e2e.py`、`test_z_abnormal.py` | 37 | ✅ 37 / 37（约 20 分钟） | 真实 GCP（Argolis 测试组织） |
| 3 功能测试 | `tests/functional/test_requirements.py` | 26 | ✅ 26 / 26 | 本地；每条需求另有对应的系统测试用例 |
| 4 性能测试 | `tests/perf/run_perf.py`、`simulate.py` | 1000 表 × 500 新增 × 100 存量 | ✅ 全部步骤成功，0 重试、0 错误 | 真实 GCP + 本地模拟 |
| 5 稳定性测试 | `tests/stability/test_stability.py`、`tests/integration/test_zz_stability.py` | 28 + 4 | ✅ 32 / 32 | 本地 + 真实 GCP |

## 运行方式

```bash
pip install -r requirements.txt pytest

# 本地（单体 + 功能 + 稳定性），约 3 秒，不访问 GCP；Python 3.9 与 3.13 均已实测通过
python -m pytest tests/unit tests/functional tests/stability -q

# 真实环境（系统测试 + 真实稳定性测试），约 20 分钟；会在测试项目中建表、建 SA / Group、设置并删除 RLS 规则
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

## 1. 单体测试（701）

用 `tests/unit/fakes.py` 中的 FakeWorld 模拟 GCP（表、规则、授权对象、登记表 / 条件表 / 映射表、IAM、账号目录、Group），直接调用四个脚本的 `main()`，断言退出码、日志、生成的 DDL 与最终规则状态。

| 文件 | 数量 | 内容 |
|---|---|---|
| `test_rls_core.py` | 109 | 纯逻辑：表名 / 主体解析、规则命名、DDL 生成与注入防护、过滤条件规范化、计划（CREATE / NOOP / REPLACE）、登记表判定、CSV（含 group 行）、本组织域名判断、授权视图 / 例程 / 数据集引用 |
| `test_params_simplified.py` | 82 | 参数：值 / `.csv` / 混用 / 去重 / BOM / CRLF / 多列报错 / 文件不存在；重复参数累加；表名格式（反引号可选、拒绝冒号写法与非三段）；被删除的旧参数 → 退出码 2；`--parallel` 默认 16 |
| `test_abnormal_cases.py` | 129 | 异常系：参数误用、注入（表名、Group 邮箱、映射表、条件表列名与 sa 值、CSV 公式）、脏数据、部分失败隔离、并发一致性 |
| `test_bypass_registry.py` | 59 | apply_bypass 登记表双重保证：范围 ∩ `rls_enabled = 1`、精确比较、冲突、登记表不可用 |
| `test_copilot_group.py` | 54 | apply_copilot Group 级别：每表一条规则、精确 DDL、多维度 AND、status 不生效、新增账号无需重跑、改映射 REPLACE、400 条上限、sa 校验 |
| `test_list_principals.py` | 80 | list_principals：无授权 SA / user、多层文件夹、待删除项目、角色筛选、条件授权、服务代理、账号目录、读取失败报错、Group 展开；`--projects` 读上级文件夹 / 组织策略（多层、读取失败、去重、无上级）；展不开的 Group 写入 CSV（外部域 `[NOTE]` / 本域 `[ERROR]`、辅助域名、跑脚本账号域名、嵌套、排除）；**基本角色 Owner / Editor / Viewer 按能读表处理**（组织外 user / SA、`--projects` 下的 user 与其它项目的 SA、继承、Group、不查角色定义）；范围外授权视图 `[NOTE]` |
| `test_gate_removal.py` | 31 | 已去掉的「闸门」：只提示不拦截；旧参数被拒 |
| `test_scripts.py` | 36 | 四个脚本的主流程 |
| `test_normal_cases.py` | 28 | 正常系：每条设计决定一个用例，含第 1 → 3 → 7 → 8 步端到端流程 |
| `test_auth_defaults.py` | 18 | 执行账号 / quota 项目自动确定；确定不了 → 退出码 2 + 提示 |
| `test_review_fixes.py` | 26 | 独立审查报告的修复项：BigQuery 报 Group 不存在时不重试、第一张表即停止（退出码 2、其余零 DDL）、执行中途出现则停止未开始的表；apply_bypass `--group` 格式检查；映射表列名不区分大小写；rollback 中途失败仍输出已删规则内容；Cloud Identity 403 无权限 / API 未启用 / 429 重试 / 5xx 用尽 / 空组 / 嵌套组读不到（HttpMockSequence） |
| `test_log_file.py` | 17 | 运行日志文件：四个脚本默认写 `logs/<脚本名>_<时间戳>.log`、内容与屏幕逐字相同、`--log-dir`、目录不可写只 `[WARN]`、同一秒不覆盖、argparse 错误 / `--help` 不写、Ctrl-C 与参数错误也记录、32 线程并发不交错、写盘失败不影响脚本 |
| `test_gcp_auth.py` | 19 | 凭证：活动账号、默认项目、回退 ADC、token 到期刷新；通过 gcloud 扮演 SA 时 `[AUTH]` 显示实际执行的 SA 与登录账号、扮演失败的提示 |
| `test_gcp_ops.py` | 13 | 重试分类、限速、挂载后验证（扮演失败立即失败）、getAncestry 解析、组织信息（customer ID、主域名） |

## 2. 系统测试（37，真实 GCP）

`conftest.py` 在测试项目中准备：业务表（含列名不同、分区表、映射到不存在的列、映射表里没有、登记为未开启、没有 bypass 的表；每张 9 行，含 HK / SG / US × mobile 数据）、条件表 / 映射表 / 登记表（条件表、映射表、登记表自身、备用映射表都登记为 `rls_enabled = 0`；映射表 / 登记表中另有一张实际不存在的 `dropped_t`）、7 个测试 SA（存量读 / 写、通过数据集 ACL 授权、Copilot A / B / N / M）、4 个 Group（ReadOnly、Writable、ACL、Copilot）及其权限。然后按方案文档顺序运行四个脚本，并**以各账号身份实际查表**验证可见性。

| 用例 | 验证内容 |
|---|---|
| test_01–04 | list_principals：项目范围列出的 SA 与 IAM API **完全一致**（含没有任何授权的）；组织范围含其它项目的 SA、账号目录全部 user；排除参数；不给账号 / quota 参数时自动确定；Argolis 组织 IAM 中的外部域 Group 只 `[NOTE]` 并作为 group 写入 CSV、退出码 0 |
| test_01c | list_principals 项目范围：项目外的 SA **只在组织上**被授予 BigQuery Data Viewer（继承）→ 也被列出；结束后撤销组织授权 |
| test_01d | list_principals 项目范围：其它项目的 SA 在测试项目上**只有基本角色 Viewer** → 也被列出；结束后撤销 |
| test_10–14 | apply_bypass：首次设置提示、两个白名单 Group、项目范围、登记表筛选 / 错误 / 冲突、重跑 NOOP、实际可见全部、REPLACE 打印旧内容 |
| test_20–26 | apply_copilot：无 bypass 也照建、演练、执行（**运行日志文件与屏幕输出逐字相同**；映射表列名 `REGION` 与表中 `region` 大小写不同也正确）；**Group 不存在 → 第一张表即停止、退出码 2、所有表零变更、不再等待重试（test_22c，bypass 与 copilot 各一次）**；**表已被 drop → `[SKIP] 表不存在`，演练 / 执行都只跳过这一张**；**同一 Group 内 A 只看 HK、M 只看 HK 且 mobile（多维度 AND）、B（维度全空）看全部、user 只看 SG、不在条件表的 0 行；没有校验维度的表 Copilot 成员 0 行**；改条件表不跑脚本即生效；**新增账号不跑脚本即生效**；重跑 NOOP、改坏后 REPLACE |
| test_30–34 | rollback：不给筛选 = 全部（演练）、按 Copilot Group、按 user 与规则名、按 Group、删光不拦 |
| r01–r07 | 视图不支持 RLS 且被隔离、视图误配进映射表、条件表脏数据（大小写 / 前缀 / 组邮箱 / 乱码 / 特殊列名）、大小写修正后无需重跑、user 执行账号、不可扮演的 `--verify-sa` 立即失败、错误的 gcloud 账号、不存在的数据集 / 表 |

## 3. 功能测试（26：客户需求逐条映射）

`REQUIREMENTS` 字典把每条客户需求映射到本地用例和真实环境用例；`test_requirement_table_complete` 保证每条需求都有用例。

| # | 客户需求 | 真实环境用例 |
|---|---|---|
| F01 | list_principals 项目范围：列出项目里全部 SA（含没有任何授权的、已禁用的） | test_01 |
| F02 | 组织范围：递归所有文件夹下 ACTIVE 项目的全部 SA；待删除项目跳过 | test_02 |
| F03 | 组织范围：账号目录全部 user（含暂停 / 归档、多域名） | test_02 |
| F04 | 能读 BigQuery 表数据的授权中的外部账号（其它项目 SA、外部 user、服务代理、Group 成员递归）；不能读数据的角色不算 | test_01 / 02 |
| F05 | 输出 3 列 email, principal_type, home_project；不使用 Cloud Asset | test_01 |
| F06 | apply_bypass：每个白名单 Group 一条 FILTER TRUE 规则，ReadOnly / Writable 各一次 | test_11 / 12 / 13 |
| F07 | apply_bypass：目标 `--tables` / `--datasets` / `--projects` 任一（可叠加），都不给报错 | test_11b / 11d |
| F08 | 登记表双重保证：只有 rls_enabled = 1 的表授权；原始字符串精确比较；不看 status；冲突 `[WARN]` 退出码 1 | test_10 / 11c / 11e |
| F09 | apply_copilot：每张表给 Copilot Group 建一条规则，过滤条件与客户 sample 一致；同组成员按条件表各看各的 | test_22 / 23 |
| F10 | 维度 = 条件表除 id、sa 外的 ARRAY\<STRING\> 列；表的维度 = 映射表 to_name；多维度 AND；status 不生效 | test_21 / 22 |
| F11 | 只处理登记表 rls_enabled = 1 的表；没有校验维度的表 `[SKIP]`；表已不存在 `[SKIP]`、其余表照常 | test_21 / 22b |
| F12 | 新增 Copilot 账号：加入 Group + 条件表加一行即生效，无需重跑脚本 | test_25 |
| F13 | 457 / 500 个账号也不超过每表 400 条规则上限（每表每 Group 一条） | 性能测试 |
| F14 | 条件表 / 映射表是否设置 RLS 只由登记表控制 | test_11c / 21 |
| F15 | 没有「闸门」：copilot 不要求 bypass；bypass 首条只提示；rollback 无删光保护 | test_10 / 20 / 30 / 34 |
| F16 | rollback：按主体（Group / SA / user，含手工规则）、按规则名、或全部；两者取交集 | test_31–34 |
| F17 | 三个 RLS 脚本默认只演练，`--apply` 才执行 | test_10 / 21 / 30 |
| F18 | 参数精简：值或 `.csv`、可重复累加；表名 project.dataset.table（反引号可选、不支持冒号）；旧参数被拒；`--parallel` 默认 16 | test_11 / 32 |
| F19 | 执行账号 / quota 项目自动确定；确定不了退出码 2 + 提示 | test_04 |
| F20 | 出错不输出 Python 堆栈；退出码 0 / 1 / 2 语义 | r05 / r06 / r07 |
| F21 | 每次运行自动保存日志文件（默认 `logs/`、`--log-dir` 可改、内容与屏幕完全一致、建不了只警告、不覆盖不清理） | test_22 |
| F22 | list_principals 项目范围：含从组织 / 文件夹继承的能读表数据的授权 | test_01c |
| F23 | 展不开的 Group 作为 group 写入 CSV；外部域 `[NOTE]` 不影响退出码，本组织域名的 `[ERROR]` 退出码 1 | test_02 |
| F24 | 只有基本角色（Owner / Editor / Viewer）的 user / SA 也列出 | test_01d |
| F25 | 授权视图 / 数据集 / 例程所在项目不在扫描范围时 `[NOTE]` 列出 | 本地 |

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
| r13 | **apply_bypass 与 apply_copilot 同时运行** | 都退出码 0；两种规则互不覆盖 |

---

## 测试中发现并修复的问题（2026-10-19）

| 问题 | 发现方式 | 修复 |
|---|---|---|
| `--parallel > 1` 时 Ctrl-C 后仍把剩下的表全部跑完 | 稳定性 S28 | 中断时取消未开始的任务，只等正在执行的 DDL 结束 |
| 同一参数写多次只保留最后一次，会静默漏表 | 单体测试 | 列表参数改为累加 |
| `--verify-sa` 的 SA 无法扮演时空等 300 秒 | 单体 + 系统 r05 | 扮演失败立即 `[VERIFY-FAIL]` |

## 没有覆盖的部分

- 账号目录只在超级管理员身份下实测；其它 Workspace 管理员角色只按文档推断。
- 不给 `--gcloud-account` 且没有 gcloud 登录、回退 application-default 凭证的路径只做了单体测试。
- list_principals 在 10 万张表规模下的耗时为按单表延迟推算（约 1.5 小时），未实测。
