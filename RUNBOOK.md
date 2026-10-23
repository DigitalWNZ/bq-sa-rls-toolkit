# BigQuery RLS 上线操作手册（Runbook）

按方案文档的 8 个步骤逐步操作。每个脚本的参数细节见 [README.md](README.md)。
示例中的名字（`trip-prod`、`trip-bq-admin.bq_auth`、`group_*@trip.com`）请替换为实际值。

## 目录

- [阶段 0：准备](#阶段-0准备)
- [第 1 步：列出现有 SA 和 user](#第-1-步列出现有-sa-和-user)
- [第 2 步：现存账号加入白名单 Group（客户）](#第-2-步现存账号加入白名单-group客户)
- [第 3 步：为白名单 Group 设置 FILTER TRUE 规则](#第-3-步为白名单-group-设置-filter-true-规则)
- [第 4–6 步：新增账号、Copilot Group、条件表（客户）](#第-46-步新增账号copilot-group条件表客户)
- [第 7 步：为 Copilot Group 设置规则](#第-7-步为-copilot-group-设置规则)
- [验收](#验收)
- [日常运维](#日常运维)
- [第 8 步：应急回退](#第-8-步应急回退)
- [常见问题](#常见问题)
- [附录：退出码与日志速查](#附录退出码与日志速查)

---

## 阶段 0：准备

### 0.1 需要客户确定的内容

| 项 | 示例 |
|---|---|
| 跑脚本的 user / SA | `rls-admin@trip.com`（user）或 `rls-runner@trip-bq-admin.iam.gserviceaccount.com`（SA） |
| quota 项目（运行查询 / DDL、计配额的项目） | `trip-bq-admin` |
| 现存账号白名单 Group（只读 / 可写各一个） | `group_existingsa_read@trip.com`、`group_existingsa_write@trip.com` |
| Copilot Group（新增 SA / user 都加入它） | `group_copilot@trip.com` |
| 条件表、映射表、登记表的完整表名（建议放在独立数据集） | `trip-bq-admin.bq_auth.adm_user_mem_copilot_condition`、`…_tb_col_mapping`、`…_tb` |
| 要设置 RLS 的范围（组织 / 项目 / 数据集 / 表） | 组织 `123456789012`；数据集 `trip-prod.dw` |

三张表的结构见 [README：客户维护的三张表](README.md#客户维护的三张表)。

### 0.2 授予跑脚本的 user / SA 权限（一次）

1. 在 Google Cloud Console / APIs & Services，quota 项目上，开启以下 6 个 API：
   `cloudresourcemanager.googleapis.com`, `iam.googleapis.com`, `bigquery.googleapis.com`, `cloudidentity.googleapis.com`, `admin.googleapis.com`, `iamcredentials.googleapis.com`
   或使用命令行方式：
   ```bash
   gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com bigquery.googleapis.com \
       cloudidentity.googleapis.com admin.googleapis.com iamcredentials.googleapis.com --project <quota项目>
   ```
2. 在 admin.google.com 新建一个管理员角色，只勾选 **Users → Read** 和 **Groups → Read**，然后将这个角色分配给跑脚本的 user / SA。（目的：列出组织下所有的 user 和 Group，并展开 Group 成员）
3. 在 Google Cloud Console / IAM，组织层级，给跑脚本的 user / SA 授权：**Browser**、**Security Reviewer**、**BigQuery Metadata Viewer**。（目的：列出组织下所有项目和 SA，并读取各层级、数据集、表的 IAM 授权）
4. 在 Google Cloud Console / IAM，quota 项目上，给跑脚本的 user / SA 授权：**Service Usage Consumer**。（目的：允许以 quota 项目的名义调用 API）
5. 在 Google Cloud Console / IAM：
   - quota 项目上，授权 **BigQuery Job User**；（目的：运行 BigQuery 查询和 DDL）
   - 需要设 RLS 的业务表所在项目（或数据集）上，授权 **BigQuery Data Owner**；（目的：创建、修改、删除 RLS 规则）
   - 三张控制表（condition、mapping、copilot_tb）所在的项目（或数据集）上，授权 **BigQuery Data Viewer**。（目的：读取控制表）
6. （user 跑脚本时）在执行脚本的机器上执行一次 `gcloud auth login`；（SA 跑脚本时）由运维人员扮演该 SA（运维人员需对该 SA 有 Service Account Token Creator，并执行 `gcloud config set auth/impersonate_service_account <SA 邮箱>`），或在挂载了该 SA 的 GCE 虚拟机 / Cloud Run 上运行。

### 0.3 本地环境（一次）

```bash
git clone https://github.com/DigitalWNZ/bq-sa-rls-toolkit.git && cd bq-sa-rls-toolkit
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
gcloud auth login rls-admin@trip.com              # user 跑脚本时；SA 跑脚本时见 0.2 第 6 条
gcloud config set project trip-bq-admin           # 之后所有脚本都不用写 --gcloud-account / --quota-project
```

> [!TIP]
> 每次运行开头都会打印 `[LOG] 日志文件: logs/<脚本名>_<时间戳>.log`（屏幕输出会原样另存到这个文件，便于留档和事后排查）和 `[AUTH] 执行账号: …；quota 项目: …`（SA 跑脚本、通过 gcloud 扮演登录时显示为 `执行账号: <SA>（gcloud 扮演；登录账号 <登录人>）`），先确认这两行再继续。日志默认保存在当前目录的 `logs/`，可用 `--log-dir` 改到别处（需对该目录有写权限）。

---

## 第 1 步：列出现有 SA 和 user

```bash
python list_principals.py --organizations 123456789012 -o existing.csv
# 或只看部分项目（不读账号目录；含从组织 / 文件夹继承的授权）
python list_principals.py --projects trip-prod,trip-etl -o existing.csv
# 已知的新增 / Copilot 账号可直接排除
python list_principals.py --organizations 123456789012 --exclude-patterns 'copilot-*@*' -o existing.csv
```

- 输出 `existing.csv`：三列 `email, principal_type, source`。列出范围内的**全部主体，不看角色**（只有 Browser、Job User 等读不到数据的也列出），所以名单比较长，需要客户按 `source` 筛选：
  - `principal_type`：`serviceAccount` / `serviceAgent`（Google 服务代理）/ `user` / `group` / `domain`（整个域）/ `public`（`allUsers`、`allAuthenticatedUsers`）/ `federated`（Workforce / Workload Identity Federation）/ `deleted`（已删除账号残留的授权）。
  - `source`：在哪里、以什么角色被找到，如 `项目 IAM trip-prod: roles/bigquery.dataViewer`、`数据集 ACL trip-prod.dw: READER`、`Group 成员: bi-team@trip.com`、`账号目录`。只有 `组织 IAM: roles/browser` 这类读不到数据的来源的，可以不加白名单。
- `--organizations`：列出组织下全部项目的 SA（待删除项目也尝试列出；只靠组织层权限的账号通常列不出，打 `[NOTE] 待删除项目 …: 列不出其中的 SA`，不算错误）、账号目录里的全部 user 和全部 Group、各层级 IAM / 数据集 / 表授权中的全部主体。
- `--projects`：列出指定项目的全部 SA，以及该项目、其**上级文件夹 / 组织**（日志 `[ANCESTOR]` 行）、其数据集、其表的授权中的全部主体；不读账号目录。
- 退出码 1 = 部分读取失败（日志里的 `[ERROR]` 说明是哪个项目 / 文件夹 / 组织 / 数据集 / 表 / 账号目录 / Group），其余结果已写入；修好权限后重跑。
- `[NOTE] 表 …: 表已不存在（扫描期间被删除），跳过`：扫描过程中有人删了这张表，正常现象，不影响退出码，无需处理。
- **Group 只展开一层**：授权中出现的 Group，其直接成员中的 user / SA 逐个列出；成员中的 Group（嵌套组）只列组名，`source` 为「Group 成员: …（嵌套组，未展开）」——嵌套组里的人不会逐个出现，客户可整组加入白名单，或自行核对组员。
- **展不开的 Group**（`source` 末尾注明未展开）：
  - **外部域的组**（合作方的组、Google 管理的组等，日志 `[NOTE]`）：任何账号都读不到，不算错误。由客户判断是否需要列入白名单、如何处理（如向对方确认组内成员）。
  - **本组织域名的组**（日志 `[ERROR]`，退出码 1）：本应能读，多半是跑脚本的 user / SA 缺「群组 → 读取」权限（见 0.2 第 2 条）。修好后重跑，或在 Admin 控制台手工核对成员（其中的 SA / user 同样要加入白名单 Group）。
  - 本组织域名见日志 `[DOMAIN]` 行；只指定 `--projects` 时不读账号目录，辅助域名（如 `ctrip.com`）的组会被当作外部域（照样写入 CSV）。
- **`[NOTE] 以下 N 个项目中的视图 / 数据集 / 例程被授权读取本次范围内的数据集`**：能查询这些视图的人也能间接读到数据。需要的话把列出的项目加入 `--projects` 重跑，或改用 `--organizations`。
- 用公司域名注册、但不受公司管理的个人 Google 账号不在账号目录里，只有出现在授权或 Group 成员中时才会列出；完整名单请管理员在 Admin 控制台的「非受管用户转移工具」中导出。
- 规模参考：每张表读一次 IAM 策略，1000 张表约 1 分钟，10 万张表约 1.5 小时。

**客户审核**：从 CSV 中挑出现存的 SA / user，决定各自进 ReadOnly 还是 Writable Group。

## 第 2 步：现存账号加入白名单 Group（客户）

```bash
gcloud identity groups memberships add --group-email=group_existingsa_read@trip.com \
    --member-email=etl-reader@trip-prod.iam.gserviceaccount.com --billing-project=<quota项目>
```

- `--billing-project`：用 quota 项目（0.2 第 1 条已启用 Cloud Identity API）调用该 API；不加时 gcloud 会用执行命令者的默认项目，若该项目没启用 Cloud Identity API 会报 `SERVICE_DISABLED`。
- 成员变更在 BigQuery 生效通常需要几分钟。

## 第 3 步：为白名单 Group 设置 FILTER TRUE 规则

**3.1 登记表**：脚本**只处理**登记表中 `rls_enabled = 1` 的表（不扫描项目 / 数据集，与项目里有多少张表无关）。把要设置 RLS 的表登记为 `rls_enabled = 1`；三张客户表（条件表 / 映射表 / 登记表）登记为 `0`（或不登记）。`table_name` 写 `project.dataset.table`（反引号可选），脚本按原始字符串精确比较。

**3.2 演练**（不做变更）：

```bash
REG=trip-bq-admin.bq_auth.adm_user_mem_copilot_tb
python apply_bypass_rls.py --group group_existingsa_read@trip.com --registry-table $REG
```

检查日志：
- `[SCAN] 登记表中 rls_enabled = 1 的表 N 张；rls_enabled ≠ 1 的 M 张不处理`——确认 N 与预期一致（没有漏登记）；
- `[CREATE]` / `[NOOP]` / `[REPLACE]`：逐表计划；
- `[SKIP] … 表不存在`：登记了但表已被 drop 或表名写错（其余表照常，退出码 1）——清理登记表；
- `[NOTE] 将为以下这些表首次设置RLS规则`：这些表上还没有任何规则，建第一条后**未被授权的账号会查到 0 行**——确认现存账号都已在两个白名单 Group 里；
- `[WARN]`：登记表同一表名多行且 `rls_enabled` 不一致，或 `table_name` 不是三段格式（这张表跳过，退出码 1）。

> `--tables` / `--datasets` / `--projects` 已删除（传入即退出码 2）。

**3.3 执行**，ReadOnly、Writable 各一次。建议用 `--verify-sa` 指定组内一个有读表权限的 SA，执行后扮演它查表做挂载后验证（可选）。

- **前提**：在要扮演的 SA 上（Google Cloud Console / IAM & Admin → Service Accounts → 该 SA → Permissions），给跑脚本的 user / SA 授权：**Service Account Token Creator**。否则规则照常建好，但会报 `[VERIFY-FAIL] … 无法扮演`、退出码 1。

```bash
python apply_bypass_rls.py --group group_existingsa_read@trip.com  --registry-table $REG --apply \
    --verify-sa etl-reader@trip-prod.iam.gserviceaccount.com
python apply_bypass_rls.py --group group_existingsa_write@trip.com --registry-table $REG --apply
```

- `[VERIFY-OK]` = 通过；`[VERIFY-FAIL]` = 300 秒内查不到数据或无法扮演（退出码 1）。
- 重跑安全：已正确的表全部 `[NOOP]`。

## 第 4–6 步：新增账号、Copilot Group、条件表（客户）

1. 创建新增 SA（第 4 步）、为 Copilot SA 赋予扮演权限（第 5 步）。
2. 把全部新增 SA / user 加入 **Copilot Group**（第 6 步）。High / Low / All 等 Group 只用于表级读写权限，与 RLS 无关。
3. **给 Copilot Group 授予条件表读权限**（必需：规则里的子查询以查询者身份读条件表，否则查询业务表报 Access Denied）：

   ```bash
   bq query --project_id=<quota项目> --use_legacy_sql=false \
     "GRANT \`roles/bigquery.dataViewer\` ON TABLE \`trip-bq-admin.bq_auth.adm_user_mem_copilot_condition\` TO \"group:group_copilot@trip.com\""
   ```

   注意：组内成员因此能读到整张条件表。
4. 在条件表中为每个新增账号写一行：`sa` 用**小写裸邮箱**；`status` = **1**（只有 `status = 1` 的行生效，0 / NULL / 其它值等同没有这一行）；维度列为 `ARRAY<STRING>`，NULL / 空数组 = 该维度全部可见。条件表必须有 `status` 列（INT64），否则第 7 步报错退出（退出码 2，未做任何变更）。
5. 在映射表中为每张业务表写维度映射（`table_name, col_name, to_name`），并在登记表中把这些表登记为 `rls_enabled = 1`。

## 第 7 步：为 Copilot Group 设置规则

```bash
AUTH="--condition-table trip-bq-admin.bq_auth.adm_user_mem_copilot_condition \
      --mapping-table   trip-bq-admin.bq_auth.adm_user_mem_copilot_tb_col_mapping \
      --registry-table  trip-bq-admin.bq_auth.adm_user_mem_copilot_tb"

python apply_copilot_rls.py --group group_copilot@trip.com $AUTH            # 演练，输出 copilot_rls_plan.csv
python apply_copilot_rls.py --group group_copilot@trip.com $AUTH --apply    # 执行
```

演练时检查：
- `[DIM] 维度: …`：条件表识别出的维度列（`id`、`sa`、`status` 不是维度）；
- `[NOTE] 条件表共 N 行，其中 status = 1 的 M 行生效`：确认生效行数与预期一致；
- `[MAP] <表>: 列->维度`：每张表的映射是否正确；
- `[SKIP]`：未登记 / 未开启 / 没有维度 / 映射列不存在 / 表不存在（已被删除）的表；
- `[WARN]`：条件表 `sa` 值不规范（大写、空白、带前缀、非邮箱 → 这些账号查到 0 行）或同一 `sa` 多行（只看 `status = 1` 的行）；
- 审核 CSV `copilot_rls_plan.csv`：每张表一行，含 `action`（CREATE / REPLACE）、`dimensions`、`filter`。

规模参考（真实环境实测）：1000 张表（900 张有维度）执行 54 秒，重跑 52 秒（`--parallel 32`）；与账号数无关。

## 验收

以具体账号身份查询业务表，确认各自看到的数据。**前提**：在要扮演的 SA 上（Google Cloud Console / IAM & Admin → Service Accounts → 该 SA → Permissions），给跑脚本的 user / SA 授权：**Service Account Token Creator**。

```bash
# 以 SA 身份查询
CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=copilot-a@trip-ai.iam.gserviceaccount.com \
  bq --project_id=trip-bq-admin query --use_legacy_sql=false \
  'SELECT SESSION_USER() AS me, region, COUNT(*) AS n FROM `trip-prod.dw.orders` GROUP BY 1, 2'
```

> [!NOTE]
> 跑脚本的是 SA、且通过 gcloud 扮演登录（0.2 第 6 条）时，上面的环境变量会**替换**掉对该 SA 的扮演，变成登录人直接扮演目标 SA。此时要写成委托链 `CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=<跑脚本的 SA>,<目标 SA>`，前提改为在目标 SA 上给跑脚本的 SA 授 Service Account Token Creator。

| 账号 | 预期 |
|---|---|
| 白名单 Group 成员（现存账号） | 看到全部行 |
| Copilot Group 成员，条件表 region = ['US'] | 只看到 US |
| Copilot Group 成员，条件表维度全为空 | 看到全部行 |
| Copilot Group 成员，但条件表里没有它 | 0 行 |
| Copilot Group 成员，条件表里它的行 `status` ≠ 1 | 0 行 |
| 不在任何 Group 的账号 | 0 行 |

---

## 日常运维

| 场景 | 操作 | 是否跑脚本 |
|---|---|---|
| 新增 Copilot 账号 | 加入 Copilot Group + 条件表加一行 | **不用** |
| 修改某账号的可见范围 | 改条件表 | **不用**（实时生效） |
| 撤销 Copilot 账号 | 移出 Group、删除条件表行，或把 `status` 改为 0 | **不用** |
| 恢复 Copilot 账号 | 条件表 `status` 改回 1 | **不用** |
| 新增现存类账号（需要看全部） | 加入 ReadOnly / Writable Group | **不用** |
| 新增业务表 | 登记表加一行（`rls_enabled = 1`）+ 映射表加维度 → 依次跑第 3 步（两个白名单 Group）和第 7 步 | 要（只处理有变化的表） |
| 修改某表的映射维度 / 条件表新增维度列 | 跑第 7 步 | 要（变化的表 REPLACE） |
| 某表不再需要 RLS | 登记表改 `rls_enabled = 0`（第 3 步以后不再处理它），再用 rollback 删除该表规则 | 要 |
| 增加第二个 Copilot Group | 对新 Group 跑第 7 步（每表多一条规则） | 要 |

> [!IMPORTANT]
> 条件表、映射表、登记表决定了谁能看到什么，**只允许客户的权限系统写入**；审核时特别注意「维度为空数组 = 全部可见」。

**变更追查**：规则的创建 / 修改 / 删除都在 BigQuery 审计日志中（保留 400 天），查询方法见 [README：审计日志](README.md#审计日志)。

## 第 8 步：应急回退

先演练（不加 `--apply`）确认日志里列出的将删除规则，再执行。

```bash
# A. 撤销全部 Copilot 规则（Copilot 账号立即查到 0 行，白名单不受影响）
python rollback_rls.py --datasets trip-prod.dw --principals group_copilot@trip.com --apply

# B. 撤销某个白名单 Group 的规则
python rollback_rls.py --datasets trip-prod.dw --principals group_existingsa_write@trip.com --apply

# C. 按规则名删除
python rollback_rls.py --tables tables.csv --policy-names rls_copilot_group_copilot_trip_com --apply

# D. 删除目标表上的全部规则（表恢复为没有 RLS：所有有读表权限的账号都看到全部数据）
python rollback_rls.py --datasets trip-prod.dw --apply

# 删除后验证某 SA 的可见行数（只报告；前提同 3.3 的 --verify-sa）
python rollback_rls.py --datasets trip-prod.dw --principals group_copilot@trip.com --apply \
    --verify-sa copilot-a@trip-ai.iam.gserviceaccount.com
```

- `--principals` 按规则的**授权对象**匹配（能覆盖手工建的规则）；与 `--policy-names` 同时给出时取交集。
- 日志 `[NOTE]` 会列出「规则将被全部删除」的表，只提示不拦截。
- 日志逐条打印被删除规则的完整内容（规则名、授权对象、过滤条件），需要恢复时据此重跑第 3 / 7 步即可。

**中途中断怎么办**：任何脚本被 Ctrl-C（退出码 130）或进程被杀，都不会留下半条规则；直接重跑同一命令即可补齐，已完成的表会 `[NOOP]`（或在 rollback 中不再出现）。

---

## 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 退出码 2，`[ERROR] … gcloud auth login` | 没有登录或登录过期：`gcloud auth login <账号>` |
| 退出码 2，`[ERROR] … gcloud config set project` | 没有默认项目：`gcloud config set project <项目ID>`，或加 `--quota-project` |
| 报 403 `USER_PROJECT_DENIED` / `serviceusage.services.use` | 跑脚本的 user / SA 在 quota 项目上缺少 Service Usage Consumer（见 0.2 第 4 条） |
| 退出码 2，参数错误 | 旧参数已删除（如 `--tables-file`；apply_bypass 的 `--tables` / `--datasets` / `--projects`）；表名必须 `project.dataset.table`（不接受冒号写法）；`.csv` 文件不存在 |
| apply_copilot 退出码 2，`条件表缺少 status 列` / `status 列的类型是 …` | 条件表需要 `status INT64` 列（1 = 生效）：`ALTER TABLE … ADD COLUMN status INT64`，再把生效的行设为 1。未做任何变更 |
| 某表 `[SKIP] … 不在登记表`（apply_copilot） | 登记表 `table_name` 与映射表 / `--tables` 中的表名不完全一致（大小写、空格、少了项目名都算不一致） |
| apply_bypass 漏了某张表 | 它在登记表中不是 `rls_enabled = 1`，或 `table_name` 写法不对（看 `[SCAN]` 行的数量与 `[WARN]`） |
| `[ERROR] BigQuery 报 Group … 不存在，已停止` | `--group` 拼错，或 Group 刚创建 / 刚改过成员、还没同步到 BigQuery：核对拼写，或等几分钟后重跑。第一张表就失败时退出码 2、未做任何变更 |
| 某表 `[SKIP] … 表不存在（可能已被删除）` | 映射表 / 登记表里还有这张表，但它已被 drop 或表名写错：清理映射表 / 登记表中的记录（其余表不受影响，退出码 1） |
| Copilot 账号查到 0 行 | 依次检查：在 Copilot Group 里吗？条件表有该账号的行吗（小写裸邮箱）？该行 `status` 是 1 吗？维度值与业务列的值一致吗？Group 刚变更需等几分钟 |
| Copilot 账号查询报 Access Denied | Copilot Group 没有条件表读权限（见第 4–6 步第 3 点） |
| 现存账号突然查到 0 行 | 该表上有规则但没有它所在 Group 的 bypass 规则：用第 3 步补上（重跑只会 CREATE 缺的表） |
| `[VERIFY-FAIL] … 无法扮演` | 跑脚本的 user / SA 对 `--verify-sa` 指定的 SA 没有 Service Account Token Creator（见 3.3 前提），或该 SA 不存在 |
| 视图上 `[ERROR]` | BigQuery 视图不支持 RLS；从登记表 / 映射表 / `--tables` 中去掉视图 |
| 大量 `[retry]` | BigQuery 速率限制；脚本会自动退避重试。持续出现时降低 `--parallel`（建议不超过 32） |
| 组织范围 `[ERROR] 账号目录` | 跑脚本的 user / SA 没有 Admin 控制台的 Users → Read 角色（见 0.2 第 2 条）；其余结果已写入 CSV |
| `[WARN] 无法创建日志文件` | 当前目录（或 `--log-dir`）不可写：换到有写权限的目录运行，或用 `--log-dir` 指定；脚本本身照常执行，只是这次没有日志文件 |
| 事后想查某次运行跳过了哪些表 | 打开 `logs/` 中对应时间的日志文件，搜索 `[SKIP]`（审核 CSV 只记录要变更的表） |

---

## 附录：退出码与日志速查

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 部分失败或数据有问题（其余照常处理） |
| 2 | 参数错误 / 登记表不可用 / 条件表缺 `status` 列或类型不对 / 无法确定跑脚本的账号或 quota 项目 / 执行时第一张表即报 Group 不存在（**未做任何变更**） |
| 130 | 被 Ctrl-C 中断（重跑即可） |

| 日志 | 含义 |
|---|---|
| `[LOG]` | 运行日志文件位置（内容与屏幕输出完全相同） |
| `[CREATE]` / `[REPLACE]` / `[NOOP]` | 新建 / 覆盖（打印旧内容）/ 已正确无需改动 |
| `[DROP]` | rollback 将删除的规则 |
| `[SKIP]` | 跳过（附原因） |
| `[NOTE]` | 提示，不影响退出码（首次设置 RLS、将被全部删除的表、条件表总行数与 status = 1 的行数、没有 status = 1 的行、条件表中的非数组列不作为维度、展不开的外部域 Group、list_principals 扫描期间被删除的表） |
| `[WARN]` | 数据问题，多数情况退出码 1（登记表冲突 / 表名格式不对、条件表 sa 不规范 / 重复）；条件表列名含特殊字符不影响退出码 |
| `[ERROR]` | 失败 |
| `[VERIFY-OK]` / `[VERIFY-FAIL]` | 挂载后验证结果 |
