# AI 方案后的补丁执行与服务验证

验收日期：2026 年 10 月 29 日（Asia/Shanghai）；原始服务时间使用 UTC。

## 0.16 独立服务激活

本轮已将安装后的旧进程待办接入[受控服务激活](SERVICE_ACTIVATION.md)。两台新隔离环境分别验证明确批准、一次服务重启、原 finding 复扫、运行时与新 SSH，以及控制端重启后不重放；Intl 另验证环境漂移拒绝和客户端丢接受回执后的同 ID 查询。原父任务及安全状态不改写，持续观察使用独立激活事件。

两侧父补丁来源不同：Intl 一次模型分析和自动安装；CN 原模型结构校验失败，预算及失败原件保留，随后独立明确批准半自动补丁，不能合称两次 AI 自动成功。实际计数、证据限制、冷观察范围和后续恢复边界见上述记录；以下 0.15 管理员对照保留为当时事实。

## 0.15 单候选分析与真实补丁结果

运行源码 `b5ac2da07581f109a77754fb254e24e7f359d404`，版本 0.15.0。新格式每次让 AI 判断自动流程指定的一个候选，完整原扫描和完整目录继续归档，省略数量明确保留；v1 来源与旧失败身份不变。输出限制为一个 finding、一个 proposal 和简短理由，不提高原 `deepseek-v4-pro` 的 2048 输出上限，不自动改写不安全文本或重新发送失败请求。

两台授权 VPS 各建立全新隔离环境，签名 APT 准备旧包的设置与产品修复分别记录。原生 Root helper 与 a22 基线逐字节相同，未增加远端动作或物理宿主权限。

| 项目 | CN SQLite | Intl Expat |
| --- | --- | --- |
| 新 run | `0440d9e9fbc8` | `c79e65113970` |
| 完整原扫描 / 同包 finding 数 | 153 包 / 1 条 | 153 包 / 11 条 |
| 实际模型选择 | `candidate-1` | `candidate-10`，不是目录首项 |
| 分析 ID | `a7b63e672cf5bfa047d0e516ed4b0ffd` | `aaa5270cea152d90599a012abb3c1466` |
| 实际模型结果 | completed / stop / 输出 246、总 2357 token | completed / stop / 输出 229、总 2336 token |
| 原生任务 | `5c1104e0c079660fe07a1f0c0d8c8298` | `be99423365d8eaf822cf3d40ba034b5a` |
| 真实单次升级 | `3.45.1-1ubuntu2` → `3.45.1-1ubuntu2.8` | `2.6.1-2build1` → `2.6.1-2ubuntu0.6` |
| 产品最终状态 | `verified` / 修订 7 / 通知 1 | `installed_restart_pending` / 修订 7 / 通知 1 |
| 原产品运行时检查 | complete、旧进程 0 | complete、旧进程 2，保持暂停 |
| 模型 / 安装次数 | 各 1 | 各 1 |

SQLite 的 expected transaction、包 SHA、APT 内 hook、精确版本、dpkg 状态、供应商同 finding 复扫、运行时、HTTP/SSH 服务与新的专用 SSH 均通过。后台以原 job 和原 scope 登记复扫请求，结果 observation、watch scope 与 `not_affected_on_rescan` 事件关联一致。自动模式下真实重启控制端后，原件、模型次数、安装次数、任务、通知和配额均不变；该隔离单包闭环已通过。

Expat 的模型瓶颈已在本例解决：实际选中原自动候选对应的第 10 项，输入从上轮 4983 降为 2107 token，回复以 229 token 完整结束。Root 完成一次真实安装，原 11 条 finding 的包版本判断均不再受影响，HTTP 和新 SSH 通过；但原 worker 和 D-Bus 进程曾加载旧库，因此保留 `installed_restart_pending` 和持久暂停。worker 随后正常退出，D-Bus 仍持有旧映射。**不能把版本已更新或 11 条包判断不受影响，当作运行时已完全生效。** 非 verified 任务没有创建 verified 专用复扫队列，原导出因此仍为 `incomplete`、退出 2；源、v2 输入、模型及提案检查均通过，唯一关键缺件为该 job 的 `rescan:not_retained`。

为核实激活条件，实验管理员在保存原 pending Root 归档和一致十库快照后，仅重启该新 guest 内的 `dbus.service` 一次。操作前核定 guest ID、服务单元、cgroup、PID 和允许人工重启属性；PID 58 换为 1221。之后独立只读检查得到运行时 complete、旧映射 0、HTTP/SSH 与新连接正常、11 条原 CVE 判断均不受影响。原 job 文件、Root 暂停及其历史运行时检查未改写。这是**产品外管理员激活对照**，不是产品自动 verified；当前尚无独立的服务激活批准及回执通道。

两侧原 source 均为 v2，包含完整原扫描、完整目录、精确 selection 与实际单候选输入，在模型预算和意图之前固定。原件摘要：

| 摘要 | CN | Intl |
| --- | --- | --- |
| source_digest | `a6733068f8a7df5d6ea0274b84f48bccf5cd1c020ffd8f4517eccc2438823528` | `f6e4335537132269e75ccc03f7107dd13f9fe25e0106b7d0307b2e280cdd6757` |
| 完整 input_digest | `091b0cccf254c3b831ac0eb702f9461f379b845544cf3f4d6cde65bc40c5aa35` | `e52d6fcd5b302163cef1fd466a69b50bb1f32708cdbad85e7792cdd07f3b9e23` |
| 最终 Root 审计 SHA | `efc33334f221791a86cb0aedb533fd04edafff59070419ac72da38b0ee6bbd97` | `8d88e730b4295b96822d4df86ec2f6e3aaa2cb92a4e391612b9ae505d0878658` |

真实控制端重启、切 manual2 后原件保持；CN 三份 v2 导出 exit0，Intl 原始、重启及管理员激活后的三份导出均如实 incomplete2。0.14 两份原失败档使用 0.15 CLI 只读核验仍有效，字节和原摘要未改变。两侧已 manual2、归档十库及 Root、停止本轮容器并移除服务器和 PC 临时私钥副本；物理 manual14 与旧实验原件保留。

私有验收原件包括 CN 的 `CN_015_COMPLETE.md`、Intl 的 `INTL_015_COMPLETE.md`、各自的 `outcome.json`、三份 evidence、十库与 Root 归档；管理员激活 intent/result/after-activation 作为单独档案保存。SHA 表示内部一致性，不是来源签名。只有 CN SQLite 获得本轮完整自动修复结论，且限受控 Ubuntu 24.04 单包环境；不证明整机或任意业务进程均已修好。

仅标准库的独立核对为 CN 61/61、Intl 57/57，原产品案例共 118 项一致；管理员激活对照另有 23/23，通过不改变 Intl 原产品状态。两个报告分别保存在 `review/checks.safe.json` 与 `review/activation-checks.safe.json`，不将一致性数量当修复率。

本机全量回归 2524 通过、31 跳过，后补的 14 项接口/完整性集成另行通过；新增 Chromium 单候选四组与既有 13 组检查通过。最终跨平台 CI 八项全部通过：Linux 2563/1、Windows 2535/29、macOS 2546/18（通过/跳过），应用覆盖率约 92%。首轮 CI 的 Windows 任务在 84% 时达到 15 分钟时限，官方注解确认超时；记录保留。后续提交 `66b2d0a` 仅将 CI 时限调为 30 分钟，运行源码仍为上述 b5ac2da，没有删测或改变补丁代码。

升级验收确认既有控制端的配置、历史和持续观察保留，授权范围保持一致。镜像 `sha256:7cc6c124bf8ec5635d83731d47860731bbcd010f2a8c73a729da657d19e92d2e`，升级前十库和私有配置位于 `/var/lib/opsark-observer/audit/ai-before-45a9c26fd6a6`。真实旧记录下载和 1440/390 控制台验证没有新模型或写请求，历史来源仍明确缺失，不事后补造。

下一阶段优先实现运行时激活的独立权限、计划、预览批准、服务范围和验证回执。已安装的原任务、暂停记录与新的激活动作应分别留证，不能通过改写原状态或通用解除暂停来补齐闭环。更多包、关键服务和其他发行版需各自验收。

## 0.14 新包实验与失败原因（历史）

冻结代码 `f30b9b1954452d50debe4dfed701ae5b63bbb969` 增加 25 个固定响应拒绝原因，区分模型响应、JSON、结构、证据引用、候选选择和文本保护规则；本地准备及处理错误另列。控制台、证据导出和离线核验使用同一分类约定，不保存被拒绝的模型原文、异常正文或思维链。旧记录缺少原因时保持未知。另修复同一主机 ID 换目标后，历史任务可能关联新目标复扫的问题；原任务范围必须与当前修复目标和观察端同时一致。

在两台授权 VPS 的新隔离环境分别验证其他软件包。两宿主相关库已是修复版，因此仅在新 guest 内使用签名 APT 准备旧包，前后完整包差集恰为一包；这一步是实验设置，不能算产品修复。旧包和修复候选的实际 `.deb` SHA 及无声明 conffiles 均核对，执行器没有开放降级或额外依赖变化。

| 项目 | CN SQLite | Intl Expat |
| --- | --- | --- |
| run | `6ca1c26c06cf` | `293300f5f27c` |
| 公告 | [USN-8775-1](https://ubuntu.com/security/notices/USN-8775-1) | [USN-8813-1](https://ubuntu.com/security/notices/USN-8813-1) |
| 实验旧版本 → 官方修复候选 | `3.45.1-1ubuntu2` → `3.45.1-1ubuntu2.8` | `2.6.1-2build1` → `2.6.1-2ubuntu0.6` |
| 原扫描 / 同包发现数 | 153 包 / 1 条 | 153 包 / 11 条 |
| 唯一分析 ID | `1b4f8e42dbf885b5cedeed0e6de16590` | `ce18c6983572290d04fcdcf1f1eb06aa` |
| 实际结果 | `failed/model_response_not_usable` | `failed/output_truncated` |
| 静态原因 | `text/text_unsafe_instruction_or_claim` | `response_envelope/response_incomplete` |
| 提供方结束 / 输出及总 token | `stop` / 491、2418 | `length` / 2048、7031 |
| 模型次数 / 计划 / 补丁任务 / 修复安装 | 1 / 0 / 0 / 0 | 1 / 0 / 0 / 0 |

两侧均沿原分析 ID 停止，没有模型重试或安装；软件包保持实验旧版。CN 最终正文未保存，不能推测具体命中原句，或认定这次是误报。Intl 实际返回的 `finish_reason=length` 与 token 用量确认了输出上限。**本轮没有新增 Expat 或 SQLite 的正向修复验收结论。** 初始 SSH/Nginx/HTTP 基线不替代修复后验收。

真正 scheduled 安装前扫描先保存，再依次固定完整 source、登记模型预算和分析意图。CN source digest 为 `82bf0ff16502bd38b55e78286f4fda917fa084d57b7d99e76adeabbc2bdefcef`，Intl 为 `8369771162623f861d8683c549c55c50a9d0fce15de40f3ec22594a6b9104a05`。automatic1 下真实停止并重启控制端后，原件、分析、告警、预算和零安装计数一致；实际导出可离线重算完整原输入。两侧均切回 manual2，Root 与十库归档后停止本轮容器，服务器和 PC 实验密钥副本已清理。

仅标准库的独立离线核对 CN 46/46、Intl 41/41，共 **87/87 通过**，表示这两份失败证据完整一致，不是补丁成功、整机安全或来源签名。本机完整回归 2300 通过、31 跳过；冻结代码 CI 八项通过，含三控制端系统、三浏览器和原受管发行版诊断实验。

私有验收原件包括两侧 `original-outcome.evidence.json`、`after-restart.evidence.json`、`outcome.json`、`root-audit.tar.gz`、`closeout.json`，以及 `review/checks.safe.json`。CN Root 审计 SHA 为 `47a0c65b0a224847bca9d2f811a90e08957d4636ae260a0fd3c5441910fbebe0`；Intl 为 `f7dab029915f4a28da512687d2fe25fae3248624b118a84ebe68f7f9c6b6c492`。实验脚本的 setup 断言和简表取错字段另有原始记录保留，不改写历史输出；分类以原 `result` 为准。

升级验收确认原配置、历史和持续观察保留，未扩大执行授权。十库和私有配置在 `/var/lib/opsark-observer/audit/ai-before-4cb3f8c483d5` 备份。旧分析的来源仍明确为 `not_retained`，真实 API 和 1440/390 控制台下载验证未新增模型或写请求。

下一步优先处理多 CVE 的输出预算、同包候选与当前自动候选的明确对应，并把文本拒绝原因细分为固定子类。完成独立新实验后再扩大包和发行版范围；本轮失败身份及预算继续保留。

## 0.11.1 半自动执行验收（历史）

两台授权 VPS 各自的新隔离环境均完成了真实 AI 分析 → 候选选择 → 原生 Root 计划 → 本次用户授权下的半自动安装 → 同 finding 复扫 → 服务与新 SSH 验证。两条任务最终均为 `verified`、修订 7、通知数 1，每个环境的 dpkg 日志只有一次本次升级。

应用版本保持 **0.11.1**。本轮使用既有程序验证完整链路，没有修改 `src/` 或 `deploy/`，也没有扩大常驻实例的执行范围。

## 环境与权限

| 项目 | CN 隔离环境 | Intl 隔离环境 |
| --- | --- | --- |
| 物理宿主 | `198.51.100.22` | `192.0.2.87` |
| 新 run | `0c656495e911` | `54444c33afb2` |
| guest | `opsark-ai-cn-lab` | `opsark-ai-exec-intl` |
| guest 地址 | `172.29.232.2` | `172.29.231.10` |
| 临时控制端 | `opsark-ai-cn-controller` | `opsark-ai-exec-control-intl` |
| 控制端端口 | 宿主 loopback `18015` | 宿主 loopback `18015` |

guest 使用 Ubuntu 24.04、原生 systemd、APT/dpkg、OpenSSH 与 Nginx，属于共享宿主内核的 Docker 实验环境。guest 没有发布公网端口或绑定挂载宿主目录；临时控制端只发布 loopback 端口，以非 root 身份、只读根目录和受限资源运行。实验不等同于独立虚拟机或物理宿主修复验收。

两个新 guest 都使用九份源码 pin 的原生 Root helper、独立只读与修复 SSH 角色，以及仅允许 `libbrotli1` 的单包策略。管理员 root 私钥没有进入 guest 或控制端。没有配置自动 grant，也没有安装回执丢失、慢 dpkg 或 Python gate 等故障包装。

安装前均执行真实、成功的签名 APT 索引刷新，再以当时 UTC 和实际索引摘要登记凭证；没有用旧镜像时间冒充当前刷新。AI 在 manual0 下分析，随后局部控制端切换 assisted1，使用同一有效分析生成新修订对应的 Root 计划。批准和提交绑定精确计划摘要，模型文本不能提供执行权限。

## 可追溯身份与补丁

| 身份 | CN | Intl |
| --- | --- | --- |
| 有效分析 | `aa61c22480a7438952fd7d03d3430835` | `3c485408fc3dfdc7ec081c2a19a0a5ec` |
| 原生计划 | `111ec0a01ca7a084854b47657e8e8d35` | `14c3a34e87ea23943bbf84b89c6dc312` |
| 执行任务 | `e41729474a0cbec1e06546f8cc392b5c` | `c29b47d8bf4a271c454cd2d47894376f` |
| 计划摘要 | `d2971724b69682af855ee194e031d5fad6057f9609c8117631bff8e9ba8f34fa` | `1d904b600b0ea2bbd43b4bf0843950ec09329d46096c3d6aabdc25e5db327f7a` |
| 完成时间 UTC | `2026-10-29T01:15:36.973003Z` | `2026-10-29T01:14:21.151952Z` |

两份实验修复同一软件包条件：`libbrotli1:amd64` 从 `1.1.0-2build2` 升级至 `1.1.0-2ubuntu0.1`，依据 CVE-2026-111497 / [USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1)。候选 `.deb` SHA256 均为：

```text
70b188a86d81f30d7510aab30e25d638ed5037dded6691af1533952b71ac61de
```

Root 独立核验当前包、官方候选、修复版本、完整事务和 SHA。协议 3 APT hook 的回执与各自任务的期望事务摘要一致，事务只包含该包的 unpack/configure。实验旧包不能被描述为两台物理宿主仍在等待的补丁。

## 执行后的实际检查

| 检查 | 两个环境的结果 |
| --- | --- |
| 安装与 worker | APT 退出 0；systemd `Result=success`、`ExecMainStatus=0`、`NRestarts=0` |
| 精确包版本 | 实测均为 `1.1.0-2ubuntu0.1`；dpkg audit 无异常 |
| 单次安装 | 各自 dpkg 日志恰好一条本次旧版至修复版的 upgrade；各只有一个新 Root 任务 |
| 同 finding 复扫 | 原 finding ID 保持，`affected=false`、`vendor_evidence_fresh=true`；worker 复扫与随后显式控制台复扫一致 |
| 运行映射 | `status=complete`、扫描 11 个进程、`outdated_process_count=0`、无采集缺口 |
| 登记服务与 HTTP | `ssh.service`、`nginx.service` 均 active，登记 `/healthz` 返回 200 且正文匹配 |
| 新 SSH | worker 本地验证后，由专用修复身份建立的新连接通过；机制为 `sshd_connection_started_after_local_verification` |
| 原任务查询 | 后续 GET 保持 `verified`、修订 7、通知数 1，没有重新提交安装 |
| 修复后的建议边界 | 原 AI 记录变为 stale、`applicable=false`；旧提案重新申请计划返回 409；当前 eligible 候选数为 0 |

这里没有注入网站不可用故障，服务项证明登记服务在补丁前后健康，不能写成“故障站点已经恢复”。运行映射和服务检查范围均在各自 guest 内。

## 模型请求与失败保留

本轮固定使用 `deepseek-v4-pro`、`json_object`、`max_tokens=2048` 和显式 `thinking_mode=disabled`。三份请求都返回 `finish_reason=stop`，没有记录推理正文。

| 请求 | 状态 | 输出 tokens | 总 tokens |
| --- | --- | ---: | ---: |
| CN 首次 `485c9adf46463333d7c6fc423ddce86b` | 本地校验失败，零提案、零安装 | 404 | 2329 |
| CN 新分析 `aa61c22480a7438952fd7d03d3430835` | 完成，提案通过原校验 | 366 | 2291 |
| Intl `3c485408fc3dfdc7ec081c2a19a0a5ec` | 完成，提案通过原校验 | 410 | 2335 |
| 合计 | 三次独立请求 | 1180 | **6955** |

CN 首次失败的 ID 和审计记录保留，没有重新发送同一 ID。该次最终正文未保存，记录只含 `model_response_not_usable`，因此无法追溯到具体拒绝项，也不能声称首个模型输出已被修正。之后明确创建一次新分析，并在临时控制端启用诊断包装：请求、返回值和原校验规则均未改变，最终答案经密钥脱敏后只保存在私有调试文件。没有第三次 CN 请求，没有为通过验收放宽 guard。

表内 usage 来自三份实际响应，不包括前一阶段的模型接入实验，也不能替代提供方费用账单。切换局部模式和申请原生计划没有重新调用模型。

## 收尾与证据

两个局部控制端均已切回 manual2。验收前后核对了既有控制端的配置、历史和 Root 授权，结果一致；物理宿主没有执行本轮包安装。两个新 guest 与临时控制端都已停止，其临时 AI Key、只读角色与修复角色的部署私钥副本已移除。原生 Root 任务、计划、批准、hook、dpkg 日志和每个控制端的十库快照已归档。

| 档案 | CN | Intl |
| --- | --- | --- |
| 远端归档目录 | `/var/lib/opsark-ai-execution-lab/0c656495e911` | `/var/lib/opsark-ai-execution/54444c33afb2` |
| 十库快照子目录 | `final-backup/stores` | `final-stores` |
| 原生审计本地文件 | `root-audit.tar.gz`，187896 字节 | `root-ledger.tar.gz`，56560 字节 |
| 审计 SHA256 | `4aceabebd30e88e619f3eba30d739b6b3d9628dc7b8e8c29e967a1c99a897fb6` | `cfe6820571ac413535880936f33becb18170ca2edd202a6e238a61ae85f984b3` |

操作者私下保存验收回执，不提交到 Git。CN 的入口为 `cn/execution-proof.safe.json`、`final-verification.safe.json`、`closeout.safe.json`；Intl 的入口为 `intl/acceptance.safe.json`、`proof.safe.json`、`closeout.safe.json`。两侧均保存真实控制台的 1440/390 宽度 verified 截图，UI 错误 0，截图过程额外模型或修复提交 0。独立证据复核 **88/88 通过**，结果保存在 `review/checks.safe.json`；常驻及物理宿主后验核对也确认 manual14、原任务及既有观察服务保留。

本轮是既有 0.11.1 代码的实机闭环验收，没有为文档更新重跑旧 CI。79de4e1 的八项 CI 是应用代码基础的历史检查；本页的模型、APT、复扫、SSH 和服务结论来自上述实机记录。

## 结论的适用范围

此次证明的是两个受控 Ubuntu 单包实验中的 AI 方案衔接和补丁后验收。扫描整体仍为 `partial`，保留 Pro CVE 通道和 USN 窗口等覆盖缺口；同 finding 不再受影响、零 eligible 候选或任务 verified 均不能证明整机安全，也不代表任意漏洞都能自动修复。

AI 的 `planned/urgent` 是审阅建议，不是供应商严重级别或执行授权。当前备份只保存包元数据，`complete_restore_backup=false`；不承诺配置、业务数据或整个系统的一键回滚。后续实验应创建新的证据和计划，保留本轮已完成任务的身份与账本。
