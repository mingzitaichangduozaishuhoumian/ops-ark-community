# 原防护任务的正式 SSH 业务复验

2026-11-06 在两台授权 VPS 的新隔离环境完成。每侧只有一个原 action、一次 apply 和一次 revoke，随后从真实控制台对同一原 RID 进行三轮只读复验；没有补丁任务，也没有追加模型调用。业务结果由产品的 `run_business_readiness` 经正式只读 SSH 采集，不采用管理员回调给出的业务结果。

## 实际结果

| 阶段 | 检查 1 | 检查 2 | 检查 3 | 业务验收 |
| --- | --- | --- | --- | --- |
| 尚未复验 | 未运行 | 未运行 | 未运行 | 待验收 |
| mixed | 通过 | HTTP 503 明确不符 | 未取得完整回执 | 复验未通过 |
| timeout_only | 通过 | 通过 | 未取得完整回执 | 待验收 |
| restored | 通过 | 通过 | 通过 | 登记业务复验通过 |

依赖检查在 target loopback 的固定服务上延迟三秒，正式 helper 的两秒 socket 预算返回 `OPSARK_HTTP_READINESS_V1 inconclusive`、退出码 0；它不是 curl exit 28，也不是完整成功回执。产品正确归为 `inconclusive`，没有把传输/证据错误判成业务明确失败。

每侧三轮各用一个新 `run_ref`，对应同一原 action、manifest 和执行前业务 profile。模式切到手动后仍可运行只读复验。随后在同一 Python 进程内停止第一个 Uvicorn 生命周期、创建新应用实例并重新登录，三份旧记录仍可选择、下载。Root 最终 usage=1、intent=1、kernel active=false；执行未重放，原 apply 未确认、后续同任务查询和撤销历史保留。

| 目标 | 浏览器安全记录 SHA256 | 原生生命周期 SHA256 |
| --- | --- | --- |
| 第一台 `试验机 B` | `065357607e3b393d8854fac7df467a611a98b358b39cfca0e926b3aeb26c9abb` | `72eef17e7dc0a2765362004cdcd20b99b42ebb78b168e3bdc55749f14b32fa02` |
| 第二台 `试验机 A` | `f24147bec2f8272ab466222c24d7a4fe485b5ae1e334aa5e2b6c53d9b82383f2` | `6531d1629babaee1192ce5c4d8c6df25a350344cd7e12e926d5ee3176d36646a` |

第一侧保存实际下载摘要的 SHA，第二侧进一步保存复验前、三阶段及重建后旧报告的安全 Markdown，逐份断言当前/历史验收文案，并核对原文摘要 hash。第二侧运行源码前后 SHA 完全一致。汇总 `acceptance.safe.json` SHA256：`1d482ad9058203824a45b2b624579e0c1ba3d366ded9e671d4a3ab605ccd9b6a`。本地忽略目录保存实际记录，文档不包含私钥、配置、数据库行或原始日志。

## 正式只读接入

驱动为 `tests/ssh_defense_business_lab.py`，固定 14 文件 LF 闭包来自 `80ad09298e5cbd50fec551178edda80a13026076`，包 SHA256：`298250e7655599186799924c96c3e24a3ab06affb4f891df066402e06f346df9`。五个 Root 模块、原九文件驱动和正式 readonly 四脚本均未修改。

新增独立 `opsark-readonly`、第四把新测试密钥和 22422 SSH 入口。Root 三角色继续使用 22423，各 key 独立。正式安装器锁定账户；新实验 listener 使用 PAM，密码、交互认证、转发、TTY 和 user rc 仍禁用。检查策略只有三条 `commands_for_business` 生成的精确命令，helper 仅连 target `127.0.0.1:42180` 并本机比较 HTTP 状态和正文 hash，不返回正文。发布 ready 前，三次正式小回执均通过，未登记命令、错误 Root 角色 key、非管理来源均被拒绝。

`tests/defense_business_relay.py` 的独立固定 relay 为 `127.0.0.1:22422 → 管理 .4 → target .2:22422`；旧 Root relay 保持 22423。每连接均复核 owned container/network/image、精确挂载、capability、资源及来源，没有公开宿主端口、挂 Docker socket 或替换生产 collector/invoker。

## 初次拒绝和状态布局

最初夹具把 root-owned 0700 的空目录绑定到整个 `/var/lib`。正式安装器的 home/public authorized key 虽为 0755/0644，collector 仍无法穿过父目录，真实公钥认证被拒绝。新增只读降权预检确认 `first_blocker=var_lib`；预检仅用固定路径的 lstat/access，不读取私钥、Shadow 或文件内容。这三次安全失败独立留证，Root 动作和模型调用均为零。

修正仅在新 business 夹具：target 精确保留 code/authority 两项只读和 ready 一项可写 bind，Root 账本放在该 owned 容器可写层。初始化前拒绝既存/符号链接 Root 部署，父目录须 canonical、root-owned、不可组/其他写；不 chmod、迁移或接管已有部署。原 Root CLI 创建账本目录 0700、文件 0600，再由元数据预检验证。管理容器仍仅 code/key 两项只读挂载，资源/CAP 与上一轮保持。

该状态布局只验证同一容器内的 CLI 调用和控制台实例重建。`restart=no`，不覆盖容器重建、sshd 或宿主重启；容器删除会删除本轮 Root 账本，不能冒称持久部署恢复。运行和清理预算仍为 480+120 秒，容器 600 秒，Root 授权 300 秒、cursor 120 秒、动作 TTL 60 秒。

## 产品判定与覆盖边界

新 v2 复验与旧裸记录分开。首次 prepare 发包前持久封存业务检查 profile；缺原快照、原授权或本轮精确 Root 查询不能将全 passed 判绿。human approval 核原 apply 声明与使用状态，auto 则核预授权账本和回执；reserved 不作完整执行证明。`run_ref` 声明不可替换、领取一次，HTTP 回执丢失只查原 run；满 120 秒后可明确结束未完成的只读 claim，原记录仍待验收，迟到结果不能覆盖，新采集需新明确请求。

客户摘要只采用固定状态、UTC 时间、计数、序号检查和服务端任务引用 digest；旧历史不受当前权限或凭据可用性影响。当前结论额外复核公共 pin、Root 物理声明、更新复验和本轮业务新鲜度，Root 新查询不能给陈旧业务检查续期。新的不确定状态降为待验收，所选历史原件和 hash 保持。

最终模板另核“原执行与原任务对账”：原授权依据、提交意图、可信 active 回执、最近一次回执缺口及更大观察序号的原任务 query，分别标注控制端时间。明确 Root 拒绝不伪装成断线，仅 expired/revoked 也不补造已生效执行；摘要只说曾有回执未确认，不把未知原因写成已经证明的网络故障。最后 122 项相关服务测试、18 项独立定向复核，以及八项正式应用/浏览器/恢复回归通过。

服务器实验清理后，又从两侧保留的原生记录纯本地导出 `timeline-final-*.md`。没有再次 SSH、模型调用或执行；十库的全部表结构、行值、rowid 和 sqlite_sequence 逻辑摘要在导出前后相同。历史 failed/pending/passed 保持，因证据已超过当前新鲜度窗口，三份当前状态均为待验收。第一侧最终恢复摘要 SHA256 为 `76d3b4d6798d5d35c166b7951de745c16ac2e01a202b9e568d4fb94846698f42`，第二侧为 `419fec8abc09d02d0dfacb67c2e24b3de70ff5718702e3ee5f11a91b2995ff8a`。这六份补充导出没有覆盖先前浏览器实际下载的原件，也没有扩大原生实验范围。

582 项相关回归通过、1 项 POSIX 权限位测试在 Windows 跳过；21 项 Chromium 回归包括正式应用/ASGI/loopback UI 和合成 API 两种分层范围，另有真实驱动假传输回归。新 v2/WAL/Rowid 与十库离线恢复保真由两项独立新测试补齐，未把纯归档测试当成新的真实 age 验收。

## 独立 Python 进程的离线历史恢复

后续使用 `tests/defense_recheck_process_restart.py`，分别对两侧保留的本轮实验数据执行两次独立 Python/Uvicorn 启动，前一进程退出后才启后一进程。两次都通过正式 `create_app` 和原路径加载配置，再由 Chromium 登录、选择三个旧 run、下载并逐项核对同一 run 的 HTTP 摘要 SHA。四个实际 runtime PID 均已退出。

| 原实验记录 | 进程恢复 proof 文件 SHA256 |
| --- | --- |
| 第一台 `试验机 B` | `465446c2ff9c04426596bdc42250eb09bc80f84b9b79a603066efcc5044605ce` |
| 第二台 `试验机 A` | `de3d1580a1d73b995bcba6fcffd138aa4fc70421727db399f6a0a967c994e882` |

两侧均为三份历史 failed/pending/passed，当前因时效保持 pending。每个进程 34 次 GET/HEAD、零 SSH 或模型尝试；额外单独发一次 POST 证明测试只读屏障返回 405，未到业务服务。原配置由正式 loader 不透明读取，没有放进 argv、stdout 或导出材料。十库（包括本轮原本为空的库）的结构、全部行、hidden rowid、sqlite_sequence 和封存 v2 声明/claim/result，在启动前、两次退出后均一致；模式、使用量和 latch 包含在核对内，没有重做 action 或业务采集。

driver SHA256 为 `6899aed07ea69503c9aad7235b6f492a61cee05ed14c9ea65541e3b7fe2cb299`，产品源码为 `541625350c6138b724c870aca77a3adcd188e31d`。汇总 `process-restart-acceptance.safe.json` SHA256 为 `8f16e3d837bdaafed42782e697a7ec4278f0910828003fdc3abd509447409e53`。旧 Windows 文本文件保留 CRLF，之前记录的摘要 SHA 定义为 UTF-8/LF 文本；新 HTTP 导出保留原响应 LF 字节，汇总明确按前者规范比较，没有改写旧文件。

另有两个 tmp-only 假数据用例：完整的两个实际进程/Chromium 往返，额外保留未完成 claimed 且不重采集；AI 配置存在时拒绝本离线验收。这是当前冻结 schema/scope 的逻辑保真检查，启动仍执行正常初始化，不承诺任意旧版本免迁移、SQLite 文件字节完全相同或 OS 级全 socket 隔离。服务器实验已清理，所以该补充不覆盖活 Root 重连、提交意图中断、容器/sshd/宿主重启。

两台原有容器状态一致。本轮五个私有服务器阶段目录和全部实验容器/网络已清理，工具镜像留作后续实验，本地原任务和历史保留。常驻配置、历史、版本和权限未改。本轮不增加持续工作器、外部告警推送或公网防御范围；后续实现按[工作器阶段计划](../../docs/SSH_DEFENSE_WORKER_PLAN.md)推进。

私有草稿 PR #1 的 GitHub Checks 42128592589 返回失败，但各 job 注释均为账户付款/额度导致未启动，未运行测试步骤；不能把该状态记作代码用例失败或跨平台验收通过。

后续在两台新隔离环境补齐了[在线 Root 的独立控制端进程恢复](../defense_live_process_lab/README.md)，与本页的离线恢复、同进程应用重建分开留证。
