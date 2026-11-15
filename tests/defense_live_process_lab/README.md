# 在线 Root 的控制端进程重启验收

2026-11-06，在两台授权 VPS 的新隔离环境完成。控制端运行于本地 Windows，使用两个真正独立的 Python/Uvicorn 进程；目标 Root 与正式只读 SSH collector 始终位于同一组新实验容器中。流程只重启控制端进程，实验容器、目标 sshd 和物理宿主保持运行，常驻实例未动，没有模型调用。

## 实际流程

1. 第一进程通过真实界面切半自动，明确 arm、触发五次固定认证失败、查询并准备原清单，只批准一次 apply。
2. 原生目标完成该动作后，只销毁绑定这次 apply 的精确 SSH socket，保留 master/listener；控制端实际得到 HTTP 503 和未确认回执。
3. 退出第一进程并确认实际 runtime 句柄已终结，第二独立进程使用原配置和同一数据目录启动、重新登录。原 RID 仍待对账，原 apply 请求字节与 SHA 未变。
4. 第二进程只查询同一原 RID。两侧实际首次查询均为 active，再精确确认撤销一次，随后切手动。没有第二次 arm、prepare 或 apply。
5. 通过正式 `run_business_readiness` 和只读 SSH，依次运行失败、超时、恢复三轮复验，选择旧 run 并逐份导出安全摘要。下载与同 run 当次直接 HTTP 导出的 SHA 相等，选择和导出前后 sealed 声明、claim、result 原件不变。

| 阶段 | 三项业务检查 | 当轮结论 |
| --- | --- | --- |
| mixed | 通过、HTTP 503 明确不符、证据不完整 | 复验未通过 |
| timeout_only | 通过、通过、证据不完整 | 待验收 |
| restored | 全部通过 | 登记业务复验通过 |

后续新 run 会改变当前投影，旧报告仍保留当时的历史结论。Root 查询不能给旧业务检查续期。所有实际摘要只含固定状态、控制端时间和摘要引用，不含来源原文、域名、原 RID、原始日志、凭据或数据库原文。

## 独立核对

每侧 Root 连接 18 次、正式业务 SSH 会话 3 次，原 Root usage=1、intent=1，最终内核集合为空。独立 verifier 核对原 RID、清单/action/cursor、Controller 原 apply 的 canonical JSON＋LF SHA、原生 `identity_binding_sha256` 和实际 socket fault marker；另确认 Root CLI 完成、精确 socket 消失一次、master/listener 保留及没有发送 session signal。它没有把 HTTP 503 单独当成实际网络故障证明，也没有把管理员 snapshot 当业务复验结果。

| 目标 | 浏览器 proof SHA256 | 原生生命周期 proof SHA256 |
| --- | --- | --- |
| 第一台 `试验机 B` | `1238153a94293ac64eaf70eed57f1a94b4f5c8c8169b8a247780cc845d73b4f8` | `c2208ff98ccd096dbb9ca9074b7ee05f49a633b68c5b713afe643a7ed3d041b5` |
| 第二台 `试验机 A` | `51f9e749e762f0fc4cc4f89d2989be3250314f7ae41e048a1feca764fc15735d` | `288e1435d697152640f5790fa5efb8f155c93fd69217bf2374ac18e0000fd466` |

operator proof SHA256 分别为 `f6069364c08697af44c680e46cf26386e52384ccca36fed8653aa5f61b96cbd6` 和 `2085f42f7512223a357d8580e567272e6558ab161c577c892c1123d29293f26f`。汇总 `acceptance.safe.json` SHA256 为 `b570e2bd4bcea5dd638b05a627855d45991b826bc1e3b9ecdcae8dc0ee4ce9ef`。安全记录位于本地忽略目录，未将私钥、配置或数据库上传仓库。

## 源码与测试

控制端执行源码为 `683559d0542d9664d119e4409685b9e6dfa5ebab`，两侧运行前后的 src/web 和驱动 SHA 一致。Root 使用原 `80ad09298e5cbd50fec551178edda80a13026076` 的 14 文件 LF 闭包，包 SHA 为 `298250e7655599186799924c96c3e24a3ab06affb4f891df066402e06f346df9`，与[上一轮正式 collector 实验](../defense_business_lab/README.md)相同；五个 Root 模块和四个正式只读脚本没有修改。

- `tests/defense_live_process.py`：`ddc24620a70d279518d30d855faa4f7936b63ac9ac66ab9cccd2dfd065559571`。
- `tests/browser_defense_live_process_smoke.py`：`9722378f120e03dd13e472104a32c19d8a676405bc39457784da66ef61d291bb`。
- `tests/test_defense_live_process.py`：`54ba2b0eb3dfc8eb4981f24ccfc178b3d17a621bb64d1cd9ffe8ae5091b9dc0d`。

八项 tmp-only 测试通过，含真实双进程/Chromium 的 active 和 expired 对照、配置阻断、退出超时、错误报告下载与进程创建时间失配。独立四项负面回归另通过；Ruff、类型和差异检查通过。Windows 持有实际 runtime 句柄，先比对 child creation FILETIME，失配只关闭、不保存或终止；优雅退出超时仅终止已验证并持有的句柄，避免按重用 PID 清理。

本轮两侧的真实首次查询均及时取得 active。假数据 expired 对照另证明：仅到期不能补造曾生效证据，三项全通过仍保持当前待验收，驱动只标 `reconciled_only`，不能被 native 完整通过门禁接受。

## 清理与剩余边界

两侧原有容器状态与运行前一致，全部本轮实验容器、网络和两份 root-private 阶段目录均已清理。仅保留原有缓存工具镜像、本地受保护的合成角色凭据和原任务历史，以供后续核验；没有读取原客户数据库或向模型发送数据。

这是收到未知回执后的优雅控制端进程退出与在线恢复，不等于在发送中强杀进程。`tests/test_defense_intent_process_crash.py` 的三个真正 `os._exit` 边界已用合成传输验证，但实际 SSH 提交边界仍待独立实机验收。Root 仍采用同容器可写层状态，不覆盖容器重建、sshd 或宿主重启。持续工作器、长期授权和公网防御仍按[阶段计划](../../docs/SSH_DEFENSE_WORKER_PLAN.md)推进；主线、常驻版本、配置、历史和权限未改。
