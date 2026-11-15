# 被保护 SSH 监听器替换后的绑定拒绝验收

2026-11-06，两台授权测试机尾号 `试验机 B`、`试验机 A` 分别在新的隔离环境完成本轮负向验收。控制端及实验入口对应 `6afd4a39042ec0e7da5de2e39471d4af7e7e4ee2`；它与后续 Linux 控制端矩阵是两份独立证据，不混用提交或计数。

每台先由真实界面明确切换 automatic、arm 并启动一次规则会话，正式后台 prepare/apply 各一次，取得原 apply 的 accepted ACK。第一控制端进程退出后，独立监督器仅替换一次持有的被保护 `22422` sshd；承载 Root 协议的 `22423` 保持。第二个真实控制端进程从界面只查询同一个原 RID。

本轮预期结果是：原 Root 绑定失效，新查询返回 `unknown / binding_changed`。它证明当前 v1 会保留不确定性，不能声明连接恢复后旧授权继续有效。

## 已实际核对的边界

- 旧 `22422` 子进程经持有的 PID、启动身份及 pidfd 回收，新 PID、启动时间、socket 与当前绑定确实改变。替换前后都核对没有在途 SSH 子会话；启动未就绪的已生成子进程也有清理身份。
- `22423` 的进程、socket、配置以及网络命名空间保持；公开 pin、私钥文件元数据、角色公钥/固定入口、sudoers、原配置与授权原件保持。私钥正文不读取、不计算内容哈希。认证日志保持同一 inode 与原前缀，允许新监听器追加启动记录。
- 原 Root ledger 全字节、grant、usage、intent、binding 与期限保持；查询后的最终本地快照再次核对同一 ledger SHA。Root usage/intent 各一；初始化、provision、nft 初始化及 Hostkey 生成的替换增量均为零。没有重绑 Root、续发许可或刷新动作 TTL。
- 真正的 Root 查询仍由原 `22423` CLI 和未修改的五个 Root 模块执行。辅助快照明确标记为本地原账本与当前监听器比较，`trusted_current_root_observation=false`，不能充当新的可信 Root 回执。
- 新回执是同一原 RID 的 `unknown / binding_changed`，控制端当前任务为 `unknown`、`query_required=true`、`current_result=null`。旧 last-confirmed `active` 原件仍可查，界面与交接摘要将其标为历史，不能用它代替当前查询结果。
- 控制端原 charge 身份、行数一、原请求/清单、source 与 session sidecar 保持；本地额度状态由 `consumed` 保守转为 `unknown`。这不是新增收费，也不是模型提供方扣款证明。两台模型调用均为零。
- 原历史 session 的 `completed` 保留。浏览器原正向驱动以固定负向观察哨兵结束，`base_completed=false`、`session_acceptance_passed=false`；只有独立的 `negative_acceptance_passed` 为真。fixture 的 completed 仅说明实验正常停止及资源退出。

两台各一次原执行、一次被保护监听器替换，合计四个真实控制端 Python 进程。第二进程只有一条原任务 query，没有 arm、prepare、apply、revoke 或模型调用。没有重新安装补丁或进行业务复验；客户摘要继续待验收，并说明“未取得可信查询”。

## 源码、环境与可复现范围

新增第 17 个受限实验入口，旧 16 文件及五个 Root 模块逐字节不变。只有在首次初始化之前，将新实验 authority 的 source map 封存为 17 文件；没有修改原 deployment/grant。公开固定版本为：

| 项目 | SHA256 / 提交 |
| --- | --- |
| 控制端与入口提交 | `6afd4a39042ec0e7da5de2e39471d4af7e7e4ee2` |
| `ssh_defense_binding_loss_lab.py` | `33812d5de6b379a6aef727af1898a614ae9681999bed1c8df3597ac58ea63639` |
| 17 文件确定性归档 | `dc39cd64bc29dc356bfbe68f126163d0e90a4c62416c9aabcd6ba50c63ff23a2` |
| 固定 profile | `protected-listener-binding-loss-once/v1` |
| profile SHA256 | `a089cf4260b18f62459b7cd9ca2b197a93312aa47257aa8dd8d9769df8583676` |

`试验机 B` 使用专属干净的 `6afd` checkout。其外层 operator/verifier 仅因工作树位置及对应 SHA 绑定形成变体，与 `试验机 A` 分别记录；汇总器核对各自脚本哈希，没有覆盖旧 used 脚本或把变体混成相同文件。

两侧沿用四容器、目标三处挂载，各 `192 MiB / 0.5 CPU / pids 96`，600 秒生命周期及 480 秒工作加 120 秒清理预算。不发布宿主端口，不改常驻配置与权限。`sshd_restart_supported` 仍为 false，`execution_continuation_supported` 始终为 false；该实验不是被保护服务重启恢复、容器/宿主重启恢复或长期防御支持证明。[阶段计划](../../docs/SSH_DEFENSE_WORKER_PLAN.md)继续约束未完成范围。

## 实际结果、失败记录与清理

| 授权宿主 | 成功负向 case | 原执行 / 替换 / 第二进程 query | binding proof SHA256 |
| --- | --- | --- | --- |
| 尾号 `试验机 B` | `binding-first` | `1 / 1 / 1` | `a8bf818ac2533d65a576f17065d9e067d72ad6e91a13441c2c4bc670856446dc` |
| 尾号 `试验机 A` | `binding-second-r2` | `1 / 1 / 1` | `5797dd1b27a219bbdf5a21e8841f6fd1fd1ed40ce83a80a957199e6c5d6535c5` |

两侧原监督进程均已终止，实验容器、网络及私有阶段目录已删除，既有容器状态与基线一致，已缓存的专属工具镜像保持。远端仅核对固定七份 JSON；基线 `before.json` 只保留哈希，其余六份安全 JSON 已归档。ready 内的私有文件引用、角色私钥及原始日志不复制。控制端的原任务和历史继续保留。

失败没有被改成成功：

- `试验机 A` 早期 `binding-second` 在本地 setup 遇到 SFTP v3 attributes 没有 `st_nlink`，尚未进入应用或执行动作，原 Root usage/intent 均为零。该次 operator 维持 `negative_acceptance_passed=false`，已独立按失败归档和清理；成功的 `binding-second-r2` 是另一新隔离环境。失败 operator SHA 为 `1bde438fb1c04f98f12db08fbce2e01604bb144b82287865c79fff2a7506368b`，失败清理 SHA 为 `3d762a9670b5650510ed4a1b1ac3bf2a62fc89cc1c6e628cf50d8aebc3bc0aed`。
- `试验机 B` 第一轮归档命令因本地参数顺序被拒，`remote_dispatch=false`、`fixture_or_action_replayed=false`。修正归档调用没有重跑动作；原 `archive-attempt-1.safe.json` SHA 为 `06121d88aab684526db8ad47a6b85899030b21736a45c1420baf32156548289c`。

双机本地汇总在忽略目录 `data/defense-binding-loss-aggregate-20261106/acceptance.safe.json`，SHA256 为 `c3d69f1f3f2b49cc0dfbea88d277d474ef259240a8f7812c9201d5fd64de6e2a`。它严格核对两份 binding/browser/base/operator/native/bootstrap/归档清理的实际文件 SHA 链，保留上述失败及归档调用错误；18 个内存破坏否定全部被拒，输出不覆盖既有记录。

逐案 verifier 已核真实 Root 回执、原任务与物理清理。本次汇总只读安全 JSON、公开脚本及公开源码归档，并仅对既有脱敏摘要计算文件哈希，未再连接服务器或读取数据库、私钥、原始日志；汇总不能替代原始验收，也不能升级业务待验收或继续执行权限。
