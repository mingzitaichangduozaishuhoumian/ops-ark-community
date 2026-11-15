# 常驻控制端升级至 0.17：保留配置、历史与权限

日期：2026-10-31，原件时间使用 UTC。发布冻结提交为 `4478b7146d6ee2262fb7038e069753e5199b9b00`，产品代码对应 `ff846f8bfae3b9103b7919c997ab65c9db4fa656`。

常驻控制端已于 **02:55:16 UTC** 切换至 **0.17.0**，容器为 `healthy`，当次验收确认手动模式已同步。**03:13:20 UTC** 的最终核验、只读 UI 定向补齐及预验材料清理均已完成。本次只升级控制端，没有升级任何目标的 Root 执行器或增加执行许可。

## 发布身份与运行配置

| 项目 | 已核对值 |
| --- | --- |
| 新镜像 | `sha256:c3f51b99b621d0dd5728ef2b5d7523966679dbfd1c03d2a08539cac8ba9fc7d9` |
| 新控制端 | `d374c0e870d311a49d47c1f35c150bb611450141cc589448e6e73b588cc42937` |
| 模式 | manual14，已同步 |
| API 发布 | 宿主 loopback `127.0.0.1:18010`，没有新增公网端口 |
| 应用身份与隔离 | UID 10001、单 worker、只读根、cap-drop ALL、no-new-privileges；秘密只读挂载，没有 Docker socket |
| 资源与生命周期 | 原 384 MiB RAM、0.5 CPU、128 PID、64 MiB tmpfs；Docker `MemorySwap` 总额原为 768 MiB，继续保持；`unless-stopped` 与 30 秒停止宽限保留 |
| 网络与日志 | 默认网络和原 guest 私网均保留；原 5 MiB × 2 日志上限保留 |

原 env、清单、secrets、控制台访问令牌及配置引用均按摘要核对保持。验收核对了原提供方配置和本地凭据引用的摘要，结果一致。

```text
72e53a127dcc03cb51415fd240380734148ad63bd1e39416af36b0171c5dc6fd
```

本轮模型实际调用为 **0**。`configured=true` 只证明部署端配置仍就绪，没有重新验证上游认证、余额或模型输出。本文不提供密钥、令牌、认证头或部署端私有凭据路径。

## 三目标、历史和 Root 边界保持

原登记目标仍为 `opsark-lab-cn`、`opsark-lab-intl`、`opsark-brotli-lab`，没有把新隔离验收 VM 加入常驻清单。三个既有终结任务及两份旧 AI 分析的完整对象在切换前后相同：两份任务仍为 verified7、一份仍为 rejected5，通知身份和计数保持；旧 AI 来源缺失也没有回填成新证据。

原有一份 disabled、已过期的自动 grant 原样保留。升级没有签发新 grant、退款或重置次数，没有新补丁、模型请求、服务激活或暂停恢复任务。

两台物理宿主及原受控 guest 的 **Root9** 运行文件、策略、sudoers、forced-command authorized_keys、文件权限、角色 UID/组及 manual14 模式原件在前后权限快照中完全相同。已有角色和主机密钥 pin 保持，没有运行新 Root 安装器，也没有把隔离实验的 Root11/交付14文件替换到常驻目标。

0.17 全局 capabilities 中出现服务激活和独立恢复，表示控制端软件包含这些接口，**不是目标 grant**。本常驻实例的 `service_activation` 与 `activation_recovery` 仍为 disabled；不能据能力标记推断旧 Root 支持或允许新动作。隔离实机闭环是另一份验收，见[激活后的独立暂停恢复实验](ACTIVATION_RECOVERY_LAB.md)。

## 冷备、离线预验与实际切换

构建只使用冻结的应用资产和锁文件，数据及秘密没有进入镜像。旧实例继续运行时，在断网副本中分别用新、旧镜像执行 **NoLifespan 的九个只读 GET**：不启动观察器，不调用远端 invoker、模型或真实目标。

离线数据库审核覆盖 **48 张旧表**。按新、旧版本初始化后的旧表逻辑内容一致；0.17 只在 `automatic.sqlite3` 新增两张空表：`activation_recoveries`、`activation_recovery_resolved_jobs`。`automation_mode` 的启动同步 pending 差异与旧版本已有行为对照核验，没有通过忽略整张模式表放过变化。

旧镜像在受控离线副本上读取新增 schema，不改变历史行；这是本轮副本兼容性结果，不是允许任意旧版本直接打开线上新版数据库的通用承诺。

真实切换仅停止唯一 owned 常驻 writer 一次。在写入停止后，用正式 `store_transfer.py` 对固定十库执行 SQLite backup，保存 SHA、表行数/逻辑摘要及 `quick_check`、`foreign_key_check`；旧 app、镜像、Compose、环境与凭据另行私有备份。没有只复制活跃数据库主文件，也没有删除 WAL、清空账本或让两个控制端同时写入。

切换只更换应用资产和发布镜像引用，沿用既有数据及配置。`cutover-result` 核对完整旧任务和 AI 对象相同、旧令牌/配置/运行限额保持、新执行及 AI 请求为零。首轮 `postcheck-first` 在 **03:01:15 UTC** 确认 healthy0.17/manual14sync，并核对 15 张历史及授权相关表。

最终 `postcheck-final` 在 **03:13:20 UTC** 将范围扩至 **18 张历史及授权相关表**，包含 reports、baselines 和 security AI；各表原行 SHA 与正式冷备相同。三个旧任务、两份旧 AI 完整对象保持，新补丁/激活/恢复/AI 请求为零。十库冷备全部 SHA、`quick_check` 和 `foreign_key_check` 通过，容器 `RestartCount=0`、`OOMKilled=false`；配置、密钥及角色权限的前后核对仍一致。

本次预检查也保留了一次失败：私有 helper 曾误请求不存在的 `/api/web-security/status`，得到 404 后在备份和停止 writer **之前**停止，没有改动运行服务或数据。修正为统一的 `/api/security/status` 后，才执行唯一一次真实停止和切换。原失败及明确 continuation 均留存，没有重放执行、扩大权限或泄漏密钥。

十库冷备不代替目标 Root 账本或秘密配置备份。若要回退，应先停止新 writer，保留升级后新增数据及其快照，核对旧镜像、配置与冷备的兼容性，再决定恢复范围；不能静默丢弃新增记录或用删除数据库的方式恢复额度。通用备份与权限约定见[常驻部署说明](../deploy/observer/README.md#迁移与停止)。

## 只读 UI 与旧 AI 历史

实际 1440/390 视口的版本、模式、原任务、禁用恢复及持续观察页面截图均保留。最后一次旧 AI 页面定向补齐 `ui-e33d424e674840d5a5446d0d285c080e` 退出码为 0，结果为 passed：两个旧分析在真实 UI 与 GET 中仍为 `completed`、`stale=true`、`applicable=false`、来源 `not_retained`；来源核验仍为 incomplete，没有重建旧证据或把历史结果变成可执行方案。实际显示提案为零，执行入口保持禁用。

该次审计没有 POST、PUT 或 DELETE，最后 11 个固定 API GET 快照均为 200，页面错误列表为空，1440/390 无横向溢出。三个旧任务、模式修订、提供方摘要和禁用恢复状态再次核对保持。

此前三段私有 UI harness 曾因选项等待、纵向截图保护和 AI dataset 缩写选择器错误失败，原报告及截图保留。最终结果是对未完成部分的**定向补齐**，不能改写成整段脚本从头重跑一次全部通过；没有为此修改产品代码、绕过权限或发送新的模型/修复请求。

## 持续观察已恢复，覆盖缺口保留

两物理宿主原 **60 秒 SSH/Web** 观察、三目标原 **3600 秒漏洞观察** 周期保持。切换后已取得新的 SSH/Web 观察时间和记录；例如 **03:02 UTC** 的前后对照表明，两侧 Web 与第一台 SSH 窗口继续读取。

第二台的 SSH 通道在 0.16 切换前及升级首轮仍为 **degraded：`projection_output_limit`**。这些原记录保留；到 **03:13 UTC** 最终自然轮询时，该通道已经为 `ok`，两台的 SSH/Web 窗口均取得新记录。期间没有调整输出限制或改动 Root helper，不能将这个自然窗口变化描述为本次代码修复，也不能据此宣称整机安全。

03:13 UTC 的首轮最终核验中，漏洞观察保留原 **partial** 结果、覆盖缺口和约 **03:22—03:24 UTC** 的三目标调度。随后按原周期自然运行：两宿主和原 guest 分别在 **03:23:19、03:24:12、03:24:27 UTC** 留下新的成功观察，状态仍为 partial，下次调度顺延至 **04:22—04:24 UTC**。03:24:53 UTC 的只读核验确认控制端仍 healthy0.17/manual14sync，没有新 AI 请求或暂停。本轮未强制扫描，也未提交补丁或发送模型请求；新的成功读取不表示全量 CVE 评估、漏洞已修复或整机安全。

## 预验清理与保留的回退材料

`preflight-cleanup` 只移除了三个已经退出、使用 network-none 的离线预验容器，三份冗余离线令牌副本及临时 env 副本。生产实例继续运行，生产配置、密钥和访问令牌保持；完整冷备、旧镜像、旧 app 及历史数据库副本均保留，没有通过清理删除历史证据或回退所需材料。

## 验证分层与适用边界

源代码本地回归的 **3160 项通过**、冻结镜像审核、断网副本预验、真实部署 readiness 和持续观察是不同证据。此前产品源 `ff846f8` 的 GitHub Actions 因账户账单/支出限制未执行测试，不能用本次部署 healthy 补记为 CI 通过。源回归也不能替代真实 SSH、供应商覆盖或上游模型认证。

本文所依据的私有逻辑原件包括 `recipe`、`preflight`、`permissions-before/after`、`offline-migration-audit`、`cutover-result`、`postcheck-first/final`、`observability-baseline-comparison`、`late-readonly-status`、只读 UI result/GET audit 和 `preflight-cleanup`。发布材料保存于不提交版本库的私有审计中，公开文档不附其绝对路径。

该记录证明本次控制端健康升级，以及配置、历史和权限保持；它没有扩大任何目标或执行权限，也不是两物理宿主的补丁修复、服务激活、上游模型认证或整机安全验收。资源限制继续采用既有 384 MiB/0.5 CPU/128 PID，不能套用独立 KVM 实验的无 swap 采样结论。
