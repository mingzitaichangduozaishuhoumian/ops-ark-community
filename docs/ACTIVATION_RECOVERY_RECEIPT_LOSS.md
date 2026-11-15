# Root 业务回执未交给控制端：第二台服务器隔离验收

验收日期：2026-10-31，原件时间使用 UTC。本轮打包源码为 `e4d8f0fe11aba9e3225169a777f07c4bff1b3a79`，产品运行代码沿用 `ff846f8bfae3b9103b7919c997ab65c9db4fa656` 的 **0.17.0**；相关应用、Web、Root 执行器和依赖文件之间没有业务代码差异。实验 run 为 `506a988b6c08c88e`。

真实补丁、服务激活、控制端未知状态、两次未知状态下的 stop/start、原 ID 对账、三阶段十库冷取证、归档及清理已完成。独立离线复核为 **1180/1180 通过**；资源报告仍为 **partial**，不作为完整容量或最低规格通过的证明。

本例与[第一台服务器的隔离验收](ACTIVATION_RECOVERY_LAB.md)分别留证。前例丢弃的是浏览器 HTTP 确认；本例在第二台授权 VPS 内验证独立的 **Root 返回值到控制端业务调用者** 之间的受控故障。

后续实验使用真实 TCP 重置和建连丢包，并将包头与同一恢复 ID 的 Root 原件对应。[TCP 中断验收](ACTIVATION_RECOVERY_NETWORK.md)

## 范围与真实前置件

在第二台授权测试 VPS 内新建独立 KVM 客体，配置为 **1 vCPU、1 GiB RAM、无 swap**。QMP 原件记录 `base-memory=1073741824`、一条 CPU、KVM enabled/present，客体 UUID 为 `04d18ca7-7281-514e-9292-ce961f9ee6ab`。Ubuntu、Docker、控制端、受限 SSH/Root 入口和普通 Brotli fixture 均位于这个客体中；浏览器运行在操作者 PC 上。

这是新的客体、角色凭据、数据库和原生账本。Bootstrap 没有种入任务或成功状态，模型未配置，安装和模型调用计数从零开始。镜像内 **64 份应用文件**逐项核对；Root 运行源 pin 为 **11 份代码**，交付文件共 **14 份**，包含安装器和两个 worker unit。后述故障 wrapper 是另外交付的实验层，不属于这些产品源文件。

环境准备将单个 `libbrotli1` 设置为旧版本 `1.1.0-2build2`，普通 `capacity-brotli-fixture.service` 实际加载 encoder、decoder、common 三个库。随后产品根据真实签名 Ubuntu APT、记录中的 **USN-8956-1** 及原生包状态，在受限自动授权下安装官方修复版本 `1.1.0-2ubuntu0.1`。环境准备与产品安装分别计数，操作者没有调用安装 POST 代替自动执行。

| 阶段 | 本轮实际结果 |
| --- | --- |
| 自动安装 | 产品安装一次，自动父任务到达 `installed_restart_pending`、修订 7，旧进程仍映射已替换库，原暂停存在；每日及总额度上限均为 1 |
| 独立服务激活 | 已同步 `assisted` 修订 2 下，一次真实预览、一次明确批准、一个原生重启意图；激活到达 `verified`、修订 6 |
| 服务验证 | fixture PID `11001 → 13797`，三份新库、旧映射数 0、新 SSH 和登记健康检查通过，原 finding 的供应商复扫通过 |
| 独立恢复 | 已同步 `manual` 修订 3 下，另行预览、批准一次；Root 完成恢复，但其真实业务返回值被独立实验层隐去，控制端先保留 `unknown` |
| 使用量 | Root 和控制端每日/总已用量均保持 `1/1`，上限仍为 `1/1`；没有续 grant、返还额度、重装或再次重启 fixture |
| 覆盖与模型 | 同范围观察中的本条确认受影响计数为 0，模型调用为 0；供应商覆盖仍有 partial/Ubuntu Pro 缺口，不等于整机漏洞清零 |

fixture 只对固定本机健康数据执行压缩和解压，不是客户业务、数据库或漏洞利用流量。本例没有覆盖关键服务重启例外。

## 故障准确发生在哪一层

独立实验 wrapper 使用受限的实验控制端入口加载未改产品，包裹其 invoker。恢复提交的真实路径为：

```text
一次真实 recovery submit
  → 原 SSH invoker 返回真实 parsed dict，status=verified
  → 未修改的产品 _receipt 校验器通过
  → wrapper 持久保存收到的 dict、隐去返回值的意图和事件链
  → 在业务 invoker 返回给控制端调用者之前抛出 UnknownPatchResult
  → 产品正常异常分支保存 Controller unknown，HTTP 返回 unknown
```

wrapper 在首次真实 dispatch 前已固定投递意图，故重启后不能借新调用再次派发。它没有伪造 Root 结果，没有改 Root 执行器、回执或 SQL 成功状态，也没有调用本地释放函数。产品的正常 `_finish` 持久对账尚未发生，因而控制端记录仍为 `receipt=None`、`root_outcome=None`、`local_released=false`，本地 latch 保持 active。

这是**收到真实 Root 返回值之后、交给控制端业务调用者之前的确定性故障注入**。它不是物理 socket 丢包检测，不是 SSH wire stdout 的逐字节故障证明，也不是浏览器 HTTP 确认丢弃；本例未触发或验收真实 socket 错误分类器。`wire_stdout_retained=false`、`client_http_acknowledgement_dropped=false` 均明确留证。wrapper 保存的是解析后 dict 的 canonical bytes；其 SHA 与独立读取的 Root 原生回执 raw SHA 相同，不能据此声称保留了原始 wire stdout。

实验层 wrapper SHA256 为 `4d473d30f08209f4ddf1e71b3a1a66f348b8e73b01f95665d97d6ee027a45463`。产品文件核对与这份实验层身份分别保留，不能将带故障入口的实验进程描述为没有插桩的常驻部署。

## 未知、重启与原 ID 对账

浏览器收到的是正常 HTTP **200 unknown JSON**。提交阶段真实正文为 `status=unknown`、`local_released=false`、`receipt=null`、`root_outcome=null`，并非浏览器故意丢掉了成功 HTTP 响应。原件审计记录一次恢复预览 POST、一次恢复批准 POST，随后只读取列表和缓存状态；这个阶段没有单 ID 恢复 GET。

取证分别独立读取 Root 原件、控制端 SQL 和缓存 API，不提前调用会对账的单 ID 恢复接口。三次全局冷取证均停止该实验控制端的所有应用写入者，并使用正式数据库快照流程保存 **10 个 SQLite 数据库**及 manifest。

| 冷取证阶段及 UTC | Root 原生状态 | 控制端记录和 latch | 累计恢复 dispatch / Root status |
| --- | --- | --- | --- |
| `unknown`，`2026-10-31T04:13:38.185129+00:00` | 回执 `verified`、`paused=false`，usage `1/1` | SQL `unknown`，无控制端回执，`local_released=false`，latch active=1 | `1 / 0` |
| `unknown_after_restart`，`2026-10-31T04:14:59.963377+00:00` | 相同 Root 原件及 SHA，仍未暂停 | 再次冷读仍为上述未知状态，没有提前释放 | `1 / 0` |
| `verified`，`2026-10-31T04:18:44.805899+00:00` | 相同 Root 原件及 SHA，usage 不变 | 原 ID 对账后 `verified`、回执存在、`local_released=true`，latch active=0 | `1 / 1` |

两次明确的 stop/start 针对同一个已装故障层的实验控制端容器，保持相同镜像、数据、目标和授权。实验 **VM 中 Docker 容器的宿主 PID** 依次为 `11170 → 16286 → 16839`；这不是物理 VPS 的 fixture PID，也不是重新创建 VM。第一次重启后的第二份冷 SQL 仍为 unknown；第二次重启后，缓存列表再次确认 unknown，随后才 GET 原恢复 ID。没有重新 dispatch，也没有自动查询原 Root 恢复 ID 来提前消除未知状态。第三份冷 SQL 已为对账后的 verified；该阶段只做全局停机冻结和冷取证，没有第三次 post-verified 重启。

完成未知状态取证后，操作者才运行 query-only。浏览器以 **POST 0、一次 GET 同一原恢复 ID**取得 `verified/local_released=true`。第一次对账触发一次原 Root status；后续已验证记录的读取使用缓存，第三阶段冷取证也明确核对了 cache-only 行为。这里的 Root status 计数仅指本条恢复的原生 status，不是所有激活/观察 RPC 或全部 HTTP GET 的总数。

恢复后父任务仍是 pending7，激活仍是 verified6，三阶段的原父任务、激活和恢复 raw SHA 均一致。模式保持 manual3，Root/控制端策略、grant、额度和 fixture PID `13797` 不变。功能收尾记录对账后观察 **155.446964 秒**，不代表长时间负载或整窗资源验收；记录中的安装、原生重启、原生恢复均各一份，模型调用为零。

## 身份与原始文件摘要

以下是业务身份和 Root 文件的原始 SHA256，不是访问凭据。raw SHA 与 `recovery_digest`、`receipt_digest` 是不同字段；哈希只能关联原件，不能单独认证来源。

| 原件 | 身份 | raw SHA256 |
| --- | --- | --- |
| 原自动父任务 pending7 | `eabf356ea9c367b4983587b4a85980ea` | `ff80031ca0de03c44b72b8162f49355e72052ed73ddad153801fecea08b22c70` |
| 独立激活 verified6 | `ba0b69a2613b7bec6980586430763cfd` | `d927d77686a3eab4bc0f40976365d943742618cfe3f92611e63686df657a63f7` |
| 独立恢复 verified | `f4d883211a4f23234959fdc79e96c322` | `694caeedbd94b20329abcb293e4b3f5430b40601c127843d37203d0109c904cc` |

Root 回执保存的原暂停 raw SHA 为 `e470f28b9312915e51bc07be09928f99794d4a167a48ae409e6506a87c2ebc96`。恢复后实际安全状态的 raw SHA 为 `8fd9dc26389c789c326b6bba9035b6ecaf2f7eac3499f3a13ffdcdd65568a71b`。旧暂停原件随独立计划/回执保留，不能把安全状态变化描述为原安装或激活账本被改写。

## UI、取景失败与实验时间

激活阶段原 execute 只有一次预览和一次批准；15 次原 ID GET 后，真实 native/API 已为 verified6，私有 harness 随后的截图保护以 `AssertionError` 退出，失败原件保留。只调整私有取景阶段、断言前布局记录和 instant 滚动后的 16px 顶部余量后，query-only 以 **POST 0、一次同原 ID GET**补齐了 1440/390 截图与 after 核对，没有重发激活，也没有改产品业务校验或水平 overflow 保护。

恢复 unknown 和 query-only verified 的桌面、手机原件均完整保留。unknown 页面明确提示“Root 可能已经接受批准，保留原 ID，只查询，不重新提交”；verified 页面只说明这一条原暂停完成对账，仍单独展示原 pending 历史。原 ID、原任务和激活关联在两种宽度均可见，无水平溢出、无页面错误。

现场 `timedatectl` 报告 `NTP=yes`、`NTPSynchronized=yes`，同时观测到 PC 比客体约慢 1.5 秒。这两个同步标志不等于 PC 与客体零时差。本轮没有通过修改 PC/VM 时钟、mock `Date` 或放宽 UI 的 +1 秒检查来凑预览。

仅在真实预览 HTTP 响应的 raw body 和元数据完整落盘后，私有浏览器 harness 增加明确的 **3 秒交付延迟**，再将同一响应原样 fulfill。激活和恢复的实测延迟分别为 **3.0162071 秒**、**3.0164155 秒**；正文、Root 时间、5 分钟 TTL 和产品校验未改。此项是可审计的预览交付网络时延，不是提交 HTTP 丢弃，也不是后续 Root→Controller 业务回执故障。

异常出口只输出静态异常类型，不附认证头、凭据、Playwright CallLog 或原始异常文本；本文也不附任何私有访问令牌或角色密钥。

## 与常驻实例的隔离

该实验位于第二台授权 VPS 内的新独立 VM，未把实验授权合并进常驻实例。实验前后，常驻 **0.17.0** 容器 `d374c0e8…`、镜像 `c3f51b99…` 保持，仍为已同步 **manual14**，服务激活及新恢复入口未启用。

`permanent-before` 与 `permanent-after` 记录环境、配置、密钥/token/provider 指纹和原有 **9 份 Root 运行文件**保持；**18 张既有历史/权限表**的行数和行摘要相同，原 3 条任务及 2 条旧 AI 记录保留，没有新增常驻任务、激活、恢复或 AI 请求，也没有为本轮实验重启常驻容器。持续观察产生的正常新记录不等于所有 SQLite 文件必须逐字节不变，不能把这 18 张表的核对扩写成所有运行数据完全冻结。

常驻升级及其旧数据兼容验收见[保留配置、历史和权限的 0.17 升级](PERSISTENT_UPGRADE_017.md)，与本例实验账本分别留证。

## 归档续接与独立离线复核

最终归档共 **299 个文件（含 manifest）**，压缩包 **2,564,997 字节**，SHA256 为：

```text
ccc5f7a5a48ccd5fc9a29e7d43789eeb60cc6cba1293296dd728772795eff5ac
```

下载端成员、大小和 SHA 核对通过，十库原始 manifest 保留，全部数据库 SHA、`quick_check`、`foreign_key_check` 通过。归档复用了第三阶段已经核验的十库备份，归档器没有再次停止控制端或生成新快照；当时 VM 和 fixture 仍保持运行。

归档并非首轮即成功。Producer 在三个冷阶段各生成 `fixture-maps.raw.txt` 与 `fixture-stat.raw.txt`，这六个合法 `native` 原件未被初次 allowlist 覆盖，程序因而 **fail-safe 停止**。原创建意图、失败和已有输出 prefix 都保留。明确 continuation 只补充这六个精确相对路径并纠正 `setup-packages.log` 日志名称，核对既有 prefix 字节和 SHA 未变；没有重新 stop/start、重做 SQLite 快照、重放 HTTP 或 RPC。

独立标准库审核器最终 **1180/1180 通过**，errors、failures、missing 均为空；重新计算的 **312 份原件 SHA 均未变化**。Root 元数据和原生账本、应用与前端文件、独立故障层及其追加事件链分别核对，包含三阶段数据库关联、真实 `.deb`、新旧库和进程映射。审核器不导入产品、不联系服务器或模型、不写 SQL；本地固定 Git 原件比对也不被当作来源认证或重新执行 APT 索引签名验证。检查数是一致性检查项目数，不是修复率或网络故障检测率。

## 资源观察与保留限制

采样器留下 **1219 个样本**，end 原件记录 elapsed **2440.091076787 秒，约 40 分 40 秒**；样本之间的实际跨度为 **2438.427136574 秒**。操作者通过 SIGINT 提前结束，原 reason 为 `interrupted`，请求的完整时长没有完成，分析器保持 **partial**。

最低采样 `MemAvailable` 为 **292,958,208 字节，约 279.39 MiB**。内存样本有效 1219、缺失/无效 0，采样和元数据缺口列表为空；swap 为 0，OOM kill 与最终内核 OOM 消息计数均为 0。这些是指定窗口内的记录，不包含首次采样前的全部启动过程，也不能捕捉所有样本间瞬时峰值。

QMP 实值独立确认 1 GiB、单 vCPU、KVM 和匹配客体 UUID。资源分析器仍保留 `guest_owner=false` 的旧标签关联限制、`all_checks_consistent=false`，end 的 `budget_configuration_verified=false` 也原样保留；没有以 QMP 值覆盖或改写原分析报告。没有冻结前的组件 cgroup 原件，`component_observations.provided=false`，不能补造控制台、Root worker 或组件的净开销峰值。

因此本轮只补充该真实有限闭环的采样记录，不把未满请求时长的窗口写成完整容量通过，也不从可用内存低水位推导进程 RSS、最低规格或长期并发承载能力。

## 清理与最终部署边界

本轮实验在 **2026-10-31 04:29 UTC** 完成清理。客体内两份角色私钥和访问令牌已移除，VM、实验控制端/QEMU owned 容器、秘密 `qcow2`、seed ISO、user-data，以及 PC 两份新临时私钥、18044 viewer 和 owned 工具镜像 `c63522c6…` 均已清理。已验证的公共云镜像缓存、公开密钥和证据保留，没有 prune 其它基础镜像。

物理宿主原有 9 份 Root 文件、策略、模式及 boot 身份保持；**32 个既有容器**的镜像和运行状态与实验前一致，包括常驻 `d374c0e8…` / `c3f51b99…`。清理后的 `permanent-post_cleanup` 在 `2026-10-31T04:29:25.725029+00:00` 再次记录 healthy、0.17.0、已同步 manual14；18 张历史/权限表及环境、配置、密钥/token/provider 和 Root 指纹保持，没有新增常驻任务、激活、恢复或 AI 请求。PC 上既有 8010 转发及其 OpenSSH 会话未动。

私有原件包括新 recipe/bootstrap、`parent-pending`、`post-activation-result`、`recovery-verification`、`acceptance-final`，三份 `receipt-loss-capture-*`、两份 `receipt-loss-start-*`、故障层事件链、HTTP/UI 审计、三阶段十库 manifest、归档续接/下载、`review-final`、资源分析与清理核对。公开文档不提供私有档案部署路径或凭据。

本例只验证这个新客体、指定普通服务和一次真实恢复的确定性故障边界。它不将测试层异常注入包装为真实网络丢包检测，也不增加全自动暂停解除、任意服务重启、整机无漏洞、长期并发或完整容量通过的承诺。权限及恢复边界继续以[恢复说明](RECOVERY.md)和[服务激活说明](SERVICE_ACTIVATION.md)为准。
