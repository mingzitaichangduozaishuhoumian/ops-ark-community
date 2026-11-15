# SSH 防护事务开发候选

更新日期：2026 年 11 月 6 日。此功能在开发分支验证，主线 0.19 和常驻实例没有因此获得新的防护权限。本页记录实现边界，不是生产接入指南。

## 当前行为

固定动作仅为专用隔离网络 `198.18.241.0/28` 的单来源 SSH 临时阻断，TTL 固定 60 秒。默认没有专用登记或许可，执行关闭；普通只读采集凭据不能兼任防护身份。没有通用 Shell、公网封禁、Web WAF、DDoS 清洗或攻击转嫁能力。

控制台的“安全观察”页新增独立事务区。读取模式、观察许可、执行许可和 AI 要求分别展示。人工路径为：明确建立一次 120 秒观察窗口 → 查询原观察取得候选 → 预览完整白名单摘要并单独确认发送 → 准备清单 → 核对原任务、SHA256、模式版本及截止时间后精确批准 → 查询同一原任务。准备清单不执行封禁。撤销需要独立确认，服务会先重新查询原动作。

结果未知、断线或进程重启后保留原 RID、清单、用量和历史，只查询原任务；不自动重建许可、重放执行或延长 TTL。同一观察许可与上下文的首次任务由 SQLite 原子登记，不依赖浏览器状态或单进程锁。旧 owner 的观察任务不能被新进程重建发送许可。已过期的同一次观察不会因重复点击变成新任务。

手动模式允许明确请求的观察、AI 建议及部署端显式启用的[原任务只读跟进](DEFENSE_TASK_WATCH.md)，不开放准备/执行。半自动模式需要当前授权和清单的精确确认。Root auto 协议和控制端独立自动入口已实现局部测试，持续执行工作器尚未装配验收；`OPSARK_DEFENSE_WORKER_ENABLED=true` 明确拒绝启动，能力接口的持续执行标志保持 false。只读跟进器有独立默认关闭开关，不能把它或现有漏洞自动修复工作器算作此防护通道的持续执行能力。

## 准入和数据边界

- 三个独立固定 SSH 身份分别处理 query、arm 和 control；地址复用已登记主机、端口固定 22423、指纹精确固定。登记拒绝和采集/APT 身份混用，也比较同地址别名和实际公钥身份。
- Root 与控制端各自检查范围、策略、boot/listener binding、UTC 窗口、模式版本、许可、每日/总量和 TTL。观察、执行、AI 费用分别授权，任一存在不代表另一项开放。
- 补丁与防护共用全局模式协调器，短锁只保护最终本地准入。模式同步有持久化轮次，旧回执不能清除新失败或待同步。新 SSH 客户端在 exec/send 前重新检查准入；已经开始的请求仍按原任务对账。
- 防护事务表复用 `security.sqlite3`，不增加第十一库，不改变旧表、历史任务或已有授权。unknown latch 保留；最近五秒内同一原清单的可信 active query 只能作为精确撤销的额外条件，不能清除 latch、放行新 prepare/apply 或重置配额。
- 模型只收到临时候选/证据别名、固定分类、计数和固定 TTL。IP、账户、密钥、配置、Root 身份、原始认证日志和数据库原文不进入模型正文。完整来源先过防泄密门禁，再生成白名单；未知或敏感内容整次拒绝。
- AI 分析使用统一出站入口，最终发送再次检查模式、提供方指纹、原证据、独立费用许可和当前状态。费用按证据与提供方稳定去重，结果未知不退费重发。模型仅能选择固定枚举和临时候选，不提供命令；建议不能替代执行授权。要求 AI 的范围必须有当前同一候选与证据的完整 proof 才能准备/执行。
- 时间准入使用原账本的本地 120 秒窗口和固定 30 秒 deadline displacement 一致性预算，Root 原始截止时间精确绑定，Source/费用/proof 不重写。该差值含时钟和 SSH/arm 延迟，不能视为精确时钟偏移或 Root 实际余量。Root 自身 monotonic 和 UTC 审批仍独立执行，超预算停止；半自动审批在 Root 落后时可能保守拒绝。

## HTTP 合同

所有入口要求现有控制台认证和同源约束。路径、查询及正文使用严格 DTO，未知字段和类型拒绝，错误返回固定分类，不反射原始数据。

| 接口 | 行为 |
| --- | --- |
| `GET /api/ssh-defense/status` | 读取当前通道和许可状态 |
| `GET /api/hosts/{host}/ssh-defense/transactions` | 读取该目标原任务列表 |
| `GET .../transactions/{rid}` | 读取本地原任务及回执历史 |
| `POST .../arm` | `confirm_arm:true` 和预期模式版本；明确一次观察 |
| `POST .../prepare` | 原 cursor RID、来源引用、证据 hash 和预期模式版本 |
| `POST .../transactions/{rid}/apply` | 清单 hash、预期模式版本、`confirm_execute:true` |
| `POST .../transactions/{rid}/query` | 空正文；新 SSH 只查询原 RID |
| `POST .../transactions/{rid}/revoke` | 清单 hash、预期模式版本、`confirm_revoke:true` |
| `GET .../ai/preview` | 严格 cursor/source 查询参数；预览实际白名单 |
| `POST .../ai/analyses` | 输入摘要 hash、原 cursor/source、版本和 `confirm_send:true` |
| `GET .../ai/analyses/{analysis_id}` | 读取原分析，不重新调用模型 |
| `GET /api/ssh-defense/history-targets` | 本地分页读取旧任务目标，退役目标仍可查历史 |
| `GET .../transactions/{rid}/rechecks` | 本地分页读取原任务的 v2 复验记录和稳定 run_ref |
| `POST .../transactions/{rid}/rechecks` | 精确清单/profile hash、run_ref 和 `confirm_recheck:true`；新只读复验 |
| `GET .../transactions/{rid}/rechecks/{run_ref}` | 读原复验；重复读取不重新采集 |
| `POST .../transactions/{rid}/rechecks/{run_ref}/interrupt` | 满 120 秒后精确声明 hash 和明确确认，仅结束该只读 claim |
| `GET .../transactions/{rid}/handoff?run_ref=...` | 导出安全摘要；不发 SSH 或模型请求 |

## 验收与剩余工作

控制端、AI、API、登记和模式协调的假数据联合回归为 306 passed、1 个 POSIX 权限测试在 Windows 跳过；另有原 API/补丁/模式准入/模型出站回归 205 passed、1 个 POSIX 凭据测试跳过。独立安全定向回归八项通过。上述路径未调用真实服务器或模型。

浏览器分两层留证：七项真实 Chromium 测试使用经实际 DTO 校验的合成 API 合同，覆盖精确确认、未知结果、模式保存等待、主机切换、默认关闭和移动端；另两项通过 loopback Uvicorn 调用真实 main、静态资源、认证、API、服务与事务库，不拦截浏览器 API。后一层仍使用 FakeRoot 和提供方 MockTransport，单次 arm/prepare/apply/revoke、一次模型 HTTP，丢执行回执后只 query 原 RID 再撤销，旧历史、费用和 latch 保留；手动模式不新增动作。它不是实际 SSH/真实模型验收。Chromium、Firefox、WebKit 另分别通过现有五个合成合同、四档视口和真实临时后端回放/模式选择/客户摘要回归，这不扩大防护事务在其他浏览器的专属覆盖。

Root 协议的[原生验收](../tests/defense_requests_lab/README.md)与上述控制端测试分开：旧 16 次验收保留管理端回环丢回执的边界；新两台各有只读 socket 预检和真实 SSH socket 中断验收。新中断两次均查回原 RID、只消费一次、TTL 不升并自然恢复，控制台与 AI 验证标志仍为 false。测试容器、网络和私有阶段目录已清理；常驻实例未升级。

两台已分别完成[真实控制台、SSH 和模型联合验收](../tests/defense_controller_lab/README.md)：各一次模型分析与执行，apply 原 SSH socket 实际中断，在同一 Python 进程重建应用实例后重新登录，查询原 RID 并撤销；旧历史、费用和 latch 保留。原请求与 native marker、action/cursor/manifest 逐项对应，原有容器状态不变，实验资源和私有阶段目录已清理。新修正后的关联回归 421 passed/1 skipped，真实浏览器驱动的 17 项假数据回归通过。该记录与此前分层实验分别保留，没有将管理员健康探针算作产品业务复验。

防护配置可使用新增[加密交接 v2](SEALED_BACKUP.md#v2-防护配置交接)，真实 age 的三项 Windows 往返/错误身份/认证篡改用例通过，十库和 unknown/费用历史保真。新配置路径必须完整登记；v1 发现它们会拒绝而非静默遗漏。独立凭据引用不跟随，恢复不激活配置或续期许可。

两台另完成[正式只读 SSH 业务复验](../tests/defense_business_lab/README.md)：各保留同一原 action、一次 apply 与一次 revoke，模式改为手动后，从实际界面分别运行“通过/明确失败/超时”“通过/通过/超时”“三项全通过”。产品依次判为复验未通过、待验收和登记业务复验通过；三份旧记录在应用实例重建后仍可选择和导出。本轮没有新增模型调用，也不是补丁验收。原有容器状态相同，五个实验阶段及其容器、网络已清理。

复验声明绑定原任务、清单和执行前封存的检查 profile，按稳定 run_ref 领取一次。历史结论与当前新鲜度分开；新失败、未完成或过期证据不能沿用旧绿灯。交接摘要只输出固定状态、控制端时间和摘要引用，另核原授权、原执行生效回执、回执缺口与后续原任务查询，不导出原日志或凭据。新 v2 记录与旧裸记录分开，十库离线恢复另验证 WAL 和 Rowid 引用保真；这些测试没有代替新的真实 age 验收。

两侧原实验历史另完成真正的独立 Python 进程离线恢复：每侧两次启动、重新登录、逐份选择和导出原复验，十库和封存原件一致，零 SSH/模型出站，没有重采集或重执行。这不覆盖活 Root 重连、提交 intent 中断或容器/宿主重启。持续观察还需按[工作器阶段计划](SSH_DEFENSE_WORKER_PLAN.md)设计许可生命周期、容量、费用和原任务跟进。完成这些验收前，此候选不作为公网自主防御产品发布。

提交中断另有 `tests/test_defense_intent_process_crash.py` 的三项 tmp-only 实验：真正的子进程分别在 apply 意图提交后、取得 sendable 许可后，以及合成 Root 接受但本地尚未提交回执时 `os._exit`。恢复新服务 owner 后，重复 apply 两次均只查询同一原 RID；原请求字节、清单、审批派发状态、执行 reservation/consumption、合成已计费 AI 意图、模式和旧观察原件保持。第三项使用 FakeRoot，不是实际 SSH 中断；三项在 Windows 均通过，这份合成实验不作为实际 SSH 传输证据。

其后两台新隔离环境已完成[实际独立进程与在线 Root 联合验收](../tests/defense_live_process_lab/README.md)：精确 apply SSH socket 被销毁后，第一控制端进程退出，第二进程重新登录、查回同一原 RID；两侧均及时取得 active，再明确撤销、切手动，完成三轮正式 SSH 业务复验和旧报告导出。每侧 apply、usage 和 intent 均为 1，未追加模型调用，原有容器状态不变，本轮服务器实验资源和私有目录已清理。这份新证据不把前述离线实验扩充成在线验收，也不代表实际 SSH 发送阶段强杀、容器或宿主恢复；八项假数据驱动回归与三项提交中断测试分别留证。

新一轮另在两台完成[真正退出码 91 的提交后中断](../tests/defense_abrupt_process_lab/README.md)，原 sendable 意图、审批与使用量保留后只查询原 RID。随后两台[后台只读跟进](../tests/defense_task_watch_lab/README.md)各由真实线程自动查询三次，手动模式继续至自然到期，ACK 和第三进程重启不重置预算或重复告警；界面没有 POST query 替代后台。后一轮未做业务复验，摘要为待验收。209 项联合回归及六项后台驱动回归通过，新 watch/WAL 十库恢复另有两项测试，常驻未改。
