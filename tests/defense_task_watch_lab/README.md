# 原任务后台只读跟进的双机验收

2026-11-06，两台授权 VPS 的新隔离环境分别通过。控制端源码为 `ae52bb3b24e19bc263948808436601119372a9d6`，Root 继续使用未改动的 14 文件 LF 闭包，包 SHA256 为 `298250e7655599186799924c96c3e24a3ab06affb4f891df066402e06f346df9`。两侧运行前后 src/web 与相关驱动 SHA 一致，模型调用为 0。

## 真正由工作器查询

第一进程从真实界面批准一次 apply。目标 Root 实际完成动作并关闭该次精确 SSH socket，控制端在 `record_unavailable` 落库前 `os._exit(91)`。实际退出码、creation 绑定句柄和原 sendable 意图均核实；未给数据库补 unavailable observation。

第二独立进程使用原数据、原登记和唯一明确 host，显式启用 `defense_task_watch_enabled`，真实间隔为 30 秒。正式 `create_app` 的 lifespan 启动真实工作器线程，通过生产 readonly invoker 查询原 RID。界面只读取状态、切手动和标已阅，没有 POST query、arm、prepare、apply、revoke 或 rechecks 来代替工作器。

两侧首次自动查询均为 active。切手动后仍有后续后台尝试，最终由严格原任务查询确认自然 expired；没有自动撤销或延长 TTL。各侧共三个后台查询，分别一一对应同 RID 的 accepted Base observation，采集时间位于该 claim 的开始/完成时间内，manifest/action/cursor/scope/policy/boot/binding 均闭合。

相同 active 状态去重，事件只有 active、expired 两条。通过界面标记一条已阅后，原授权、模式、latch、使用量及跟进预算不变。第三独立进程继续真实运行至少 31.5 秒：lease epoch 前进，任务、事件、ACK、尝试次数、UTC 日预算与已完成尝试完全相同，没有重复查询、告警或执行。

## 结果与证据

| 项目 | 两侧实际结果 |
| --- | --- |
| 原 action / apply / Root usage / intent | 各 1 |
| 工作器后台查询 | 各 3 |
| 界面替代工作器的 HTTP query | 0 |
| 自动 revoke / 重复 apply | 0 |
| 已阅事件 | 各 1，重启保留 |
| 业务复验 | 没有运行，摘要保持待验收 |
| 模型调用 | 0 |

| 目标 | 浏览器 proof SHA256 | 原生生命周期 proof SHA256 |
| --- | --- | --- |
| `试验机 B` | `bed3ff5ec0e7c1971a944ee5ca36ff911760f8baf38d98a934783eabe29553dc` | `0496d5941bedbc51f443266e635a90c35b01b39a363af064189da5099e2a74f5` |
| `试验机 A` | `755a2cfddf7cffd7c4173927f5f568416538ba3c169ca79e5074c2a9ef6759b2` | `dc2e18186e6ed835a1bd9217b050c9276608461712fddc82c8f09eb8e5c29a75` |

operator proof 分别为 `b1c1f1dcf48e6acfdf02a237cd9200cbb5a2c9513c91910c87844ded66755bf7` 和 `82d5172cc1d78e824861f86140190b86d1fb0d757df6f93db6c735ea84088710`。汇总 `acceptance.safe.json` SHA256 为 `587f7d2552cac2a15926a7a5eb9f0320b084f5734e74b6511cb38e15785633f8`，安全原件保存在本地忽略目录。

独立 verifier 核对真实退出、原 apply 的 canonical JSON＋LF SHA 和原生 socket fault identity 绑定，另确认 Root CLI 完成、socket 精确消失一次、master/listener 保留。不能只用客户端 `UnknownDefenseResult` 断言物理网络故障。末次 ledger 的 usage=1、intent=1、kernel active=false；没有业务 collector SSH 会话，也没有将管理员 snapshot 当业务复验。

未复验 Markdown 从真实页面下载，对照同原 RID 当次 HTTP 导出 SHA，相等且为待验收，不包含原 RID、域名、原始日志、密钥或数据库原文。Root 到期与告警已阅都不能使业务验收通过。

## 测试、清理和限制

六项 tmp-only 驱动回归及独立源码审查通过，假数据入口只在测试文件，native 固定正式入口。209 项联合回归覆盖新旧 API、工作器、模式、界面、业务复验、真实子进程和十库恢复。握手 JSON 通过完整临时写入后原子、不可覆盖地发布，避免父进程读到空文件；相应三项回归及 Windows artifact 文件系统预检通过。

两个独立归档测试使用生产十库 snapshot/归档/核验/恢复路径，证明 watch lease、未完成 claim、尝试、退避、预算、ACK、游标、索引、rowid 与 WAL-only 已提交记录保真；恢复中不启动线程、网络或模型，未把该归档测试称为新原生 age 验收。

两台原有容器状态一致，本轮全部实验容器、网络及两个 root-private 阶段目录已清理。仅保留缓存工具镜像、本地受保护的合成凭据和原任务历史；常驻版本、配置、权限和历史未动。`试验机 B` 与另一任务的独立源码编译错峰，验收和清理完成后已交回资源，没有访问其支付主机或业务数据。

这里证明的是一次性原任务的只读状态跟进。没有新观察许可、自动生成处置、长期连续执行或公网防护；该功能仍默认关闭。新任务发现按页推进，租约、间隔、退避和预算会造成延迟，不提供即时性 SLA；首次仅查询到 expired 时不补造曾 active 的证据。容器重建、sshd 与宿主重启不在本轮范围。部署与恢复合同见[原任务跟进说明](../../docs/DEFENSE_TASK_WATCH.md)，后续自动会话与授权生命周期见[阶段计划](../../docs/SSH_DEFENSE_WORKER_PLAN.md)。
