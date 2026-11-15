# 真实提交后、未知回执落库前的进程中断

2026-11-06，两台授权 VPS 的新隔离环境分别通过。执行源码为 `edd4d0e574cffba86cd0ef3a8241e12e5baa8493`；Root 保持原 14 文件 LF 闭包，包 SHA256 为 `298250e7655599186799924c96c3e24a3ab06affb4f891df066402e06f346df9`。没有修改原 Root 协议或权限，没有升级常驻实例。

## 中断点与恢复

第一控制端进程从真实界面半自动批准一次 apply。原生目标完成动作后，精确关闭该次 SSH socket；正式客户端返回同一 RID 的 `UnknownDefenseResult`。专属实验入口仅在校验原 request SHA、sendable、审批 used、执行 consumed、无 reply 和无 apply observation 后，在 `record_unavailable` 真正写入前 `os._exit(91)`。

父进程通过 creation FILETIME 绑定的实际 Windows 进程句柄，核退出码 91 和进程终结；不是正常关闭，也不是把 HTTP 503 当作强杀证据。浏览器收到 requestfailed、无 HTTP 响应。数据库仍保留原 `apply_sendable/query_required=true`，原 apply 意图存在、回执为空、apply observation 数为 0。

第二独立进程使用相同配置和数据目录启动、登录，核原请求、owner、清单、授权及使用量原件未替换，再只查询原 RID。两侧首次都得到可信 active，随后精确确认撤销一次、切手动，完成三轮正式只读 SSH 业务复验：

| 阶段 | 当轮结论 |
| --- | --- |
| 通过、HTTP 503 明确不符、证据不完整 | 复验未通过 |
| 通过、通过、证据不完整 | 待验收 |
| 三项全部通过 | 登记业务复验通过 |

旧 run 仍可选择、导出，下载逐项对应同一 run 当次 HTTP 摘要；sealed 原件保持。每侧只有一个 action、一次 apply，Root usage=1、intent=1，最终 kernel active=false。没有模型调用或重复 arm/prepare/apply。

## 独立证据

| 目标 | 浏览器 proof SHA256 | 原生生命周期 proof SHA256 |
| --- | --- | --- |
| `试验机 B` | `30152c69cfae2a10127aad6e0d44c2a7375bdf3c727740a9afcf11ed3144a3bf` | `742460752cf55121325cdc480780fa15ee5f9cdcdff5a42757150ee5d46a2a21` |
| `试验机 A` | `fa4648c535f09fb3d2fb342b25696555c33ed26f5a74a35a71a0a36b351c586b` | `0dab8f1ac26e35c618f28f89b8a13113cc2d331ba7740c28e179fb62441f0426` |

operator proof 分别为 `fe78bb0a88cafec3b80dd6beccec60e605887d6075f4252a3fb7b6100479f310`、`554a6041e2f70becbef0792c60162cb70519d64ff868bccbb4c9e72110c655f0`。汇总 `acceptance.safe.json` SHA256 为 `8ff08d7f3b3195713758f701b181f8c5deea08e05e0f7f2fefaeb68ae33c3fe7`，安全原件在本地忽略目录保留。

独立 verifier 将 Controller 原 apply 的 canonical JSON＋LF SHA 与原生 `apply_fault` 对照，并核原 RID、manifest/action/cursor 绑定、Root CLI 已完成、socket 一次精确消失及 master/listener 保留。`UnknownDefenseResult` 本身只是客户端归一化结果，不能独自证明物理 EOF；真实故障由这个独立 marker 闭合。

## 覆盖边界与清理

没有给数据库补造未提交的 unavailable observation。交接摘要按已经保存的提交和后续可信查询显示，不能把缺失记录写成已记录的网络事件；仅 expired 且从未取得 active 的分支保持当前待验收。这一负向分支用假数据另行验证，没有混入双机正向结果。由持久 sendable/缺直接回执推导更多交接提示，需要另有时序证据设计。

这只覆盖正式发送已发生并得到派发后未知结果、在本地记未知回执前退出的边界。它不代替 TCP 部分发送、发送前意图中断、Root 进程、容器重建或宿主断电；前两个意图边界已有[三个真实子进程的合成传输测试](../../docs/SSH_DEFENSE_REQUESTS.md)，不得合称全场景实机通过。

两台原有容器状态未变，本轮全部实验容器、网络和两个 root-private 阶段目录已清理。缓存工具镜像、本地受保护的合成凭据与原任务历史留作核验。没有复制原始日志、私钥、配置或数据库到仓库或模型；常驻配置、历史、版本和权限未改。
