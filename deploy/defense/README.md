# 隔离环境的限时 SSH 来源阻断

本实验使用仅有回环接口的 Docker 容器和独立原生 `sshd`。执行器核对网络命名空间，并核实 SSH 主进程实际持有指定监听套接字和证据日志。规则只匹配发往 `127.0.0.1:22422` 的 IPv4 新 SSH 连接。实验候选来源是 `127.0.0.2` 和 `127.0.0.4`，管理来源 `127.0.0.3` 不在规则范围内。

## 本地授权和证据

管理员先确认目标来源，授权有效两分钟。授权保存当时的日志书签。执行器随后只采纳指定测试账号来自同一地址、至少五个不同客户端端口的原生公钥认证失败。窗口内同一来源有成功登录时拒绝动作。日志文件身份或原有内容改变、证据不完整、超限或缺少足够事件也会拒绝。日志原文和密钥指纹不进入命令输出。

```console
python3 -I deploy/defense/ssh_fixture.py initialize
python3 -I deploy/defense/ssh_fixture.py grant --source 127.0.0.2 --confirm
python3 -I deploy/defense/ssh_fixture.py apply --grant-id <id>
python3 -I deploy/defense/ssh_fixture.py status --action-id <id>
python3 -I deploy/defense/ssh_fixture.py revoke --action-id <id> --confirm
```

规则最多容纳一个来源，内核定时元素的有效期固定为 60 秒。执行器先持久化动作意图，再添加带同一动作编号的元素。重试只查询，无法延长有效期或重新添加到期动作。观察结果不明确时暂停新动作，等待核对。人工撤销要求独立确认，只删除同一动作的元素。[Netfilter 定时元素](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts)

## 实验范围

从源码仓库的 `tests/ssh_defense_lab.py` 启动实验。使用包含 `nftables`、OpenSSH 和 Python 3 的一次性容器，网络模式为 `none`，只为该容器增加 `NET_ADMIN`。实验脚本在容器内生成合成凭据和独立 SSH 配置。它不通过控制台、AI 或 SSH 远程写接口调用执行器。

```console
docker run --rm --pull never --network none --cap-add NET_ADMIN --security-opt no-new-privileges:true --mount type=bind,src=<管理员所有的源码目录>,dst=/opt/opsark-fixture,readonly --entrypoint /usr/bin/python3 sha256:<固定实验镜像> -I -B /opt/opsark-fixture/tests/ssh_defense_lab.py --fixture-script /opt/opsark-fixture/deploy/defense/ssh_fixture.py --confirm-isolated
```

当前是源码仓库的固定回环实验。公网和 NAT 来源、Docker 端口发布路径、IPv6、生产管理入口、事件洪峰和控制台失联后的同步都需要各自验收。

2026 年 11 月 5 日在授权测试机使用真实 OpenSSH 和 nftables 复跑。四次认证失败被拒绝，第五次满足证据条件后，只有该来源的 SSH 新连接超时。管理来源和另一测试来源可继续登录，同源 HTTP 正常。授权窗口内出现成功登录的来源被排除。重复提交没有延长封禁，执行器停止调用期间连接随内核到期恢复，旧动作不能重放。第二份独立授权经确认撤销后，目标 SSH 恢复。

## 私有桥接网络和回执中断

私网实验使用固定的 Docker 内部桥接网段 `198.18.241.0/28`。目标、候选、管理和对照来源运行在不同容器。执行器要求目标地址为 `198.18.241.2`，接口为 `eth0`，并核对连接网段和默认路由。私网规则仍只匹配指定监听器的 IPv4 新 SSH 连接。管理来源 `198.18.241.4` 保持在允许范围内。

测试中继只接受管理来源的固定请求。它在内核动作确认后主动重置 TCP 连接，客户端随后另建连接，以原动作编号查询状态。规则的剩余时间来自内核。源码中的实验入口为 `tests/ssh_defense_private_lab.py`。

```console
sudo python3 -I tests/ssh_defense_private_lab.py --root /var/lib/opsark-release-lab/<private-fixture> --image sha256:<固定实验镜像> --confirm-isolated
```

私网实验没有发布宿主机端口。该中继只用于验证回执中断，控制台写侧提交和完整同步协议仍需另行验收。

2026 年 11 月 5 日，授权测试机核对四个容器分别使用独立的内核网络命名空间。候选来源的真实认证失败触发限时阻断。执行确认后，管理端收到回执前的真实 TCP 复位，重新连接查到原动作。重复提交没有续期。管理 SSH、对照 SSH 和候选来源的 HTTP 均可访问。内核到期和独立确认撤销分别恢复了候选 SSH。回环版本也在同一源码上完整复跑。

## 控制台只读回查

私网夹具可为 OpsArk 单独启动 `198.18.241.2:22423` 只读 SSH 监听器。对控制台登记该地址、端口和 `opsark-readonly` 账号，并固定这台监听器的主机公钥。宿主机和生产监听器不属于此配置。

```toml
# 在对应的 [[hosts]] 中追加。每台隔离主机最多八项。
ssh_defense_action_ids = ["<已知动作的 32 位小写十六进制编号>"]
```

从源码把本目录三个 Python 模块布置到隔离目标的 `/usr/local/libexec/opsark-defense/deploy/defense/`，目录和文件均由管理员拥有。然后从登记导出精确的[只读 SSH 策略](../readonly/README.md)。策略只允许逐个登记的 `status-readonly`，该命令不会写目标账本、添加规则或续期。管理员本地的 `status` 仍可在确认内核项后持久化原意图的对账。

控制台在既有安全库保存最近一次确认的结果。连接不可用、目标证据未知、剩余时间反而增加或已终结动作又显示活动时，界面区分本次状态和历史观察。主机公钥登记变化后，旧观察不会用于新登记。公网和自动执行不在此入口范围内。

使用已固定的实验目标镜像和 OpsArk 控制台依赖镜像运行集成验收。实验编排启动实际控制台、临时只读 SSH 监听器和原生认证监听器，并将控制台数据目录留到重启后继续使用。

```console
sudo python3 -I tests/ssh_defense_private_lab.py --root /var/lib/opsark-release-lab/<private-fixture> --image sha256:<固定实验镜像> --controller-image sha256:<固定控制台依赖镜像> --confirm-isolated
```

2026 年 11 月 5 日，隔离实机补齐实际控制台的只读回查。丢失回执后，控制台通过固定指纹的独立只读 SSH 查询原动作。只读 SSH 监听器确实停止时，本次结果为不可用，先前确认的状态单独保留。恢复同一监听器并重启控制台后，历史记录和原动作编号一致，重新查询的剩余时间继续递减。控制台最终确认原动作到期，查询前后的目标账本 SHA-256 一致。写侧提交和自动执行仍需单独验收。

## 新增 Root 请求协议前置切片（尚未完成控制台写侧集成）

`ssh_requests.py` 是独立 v1 单行 JSON stdin dispatcher，固定使用上述 `private` 夹具。
旧 `ssh_fixture.py` 的 CLI 与旧只读入口保留。新入口直接调用原有真实 listener、命名空间、
证据和 nft 固定模板核验，不接受 profile、IP、TTL、Shell、配置路径或工具路径参数。

请求 envelope 严格为 `{"v":1,"op":"OP","request_id":"RID","scope_sha256":"SHA","body":{}}`。
RID/ref 是 32 位小写 hex，SHA 是 64 位小写 hex。单次输入必须为完整的单行 UTF-8 JSON
（含末尾 LF），最多 4096 bytes；重复/未知键、错类型、额外行、非有限数和过深嵌套均拒绝。
客户端先持久保存 RID，`prepare/apply/query/revoke` 始终使用同一动作 RID。
`arm`、`mode_sync` 各有独立 RID，跨 kind 或同 RID 异参均拒绝。

管理员只能在已核验的隔离目标本地显式初始化新账本：

```console
python3 -I -B deploy/defense/ssh_requests.py --initialize < administrator-deployment.json
```

初始化文档的精确格式如下；该文档不通过控制台 API、模型或 SSH 原始命令转发。
时间必须为 UTC `Z` 字符串，revision 为正整数，`max_uses` 为 1..8；来源只允许固定别名。
`policy_sha256` 必须等于 `request_protocol.POLICY_SHA256`，`scope_sha256` 由管理员预先绑定
目标登记、SSH 固定主机公钥、独立 defense 身份及该固定策略。示例占位符须替换为合法值。

```json
{"v":1,"scope_sha256":"SHA","policy_sha256":"POLICY_SHA256","observation_grant":{"grant_ref":"ID","not_before":"UTC","deadline_at":"UTC"},"defense_grants":[{"root_grant_ref":"ID","controller_grant_ref":"ID","mode":"semi","mode_revision":2,"not_before":"UTC","deadline_at":"UTC","max_uses":1,"source_aliases":["fixture-a","fixture-b"]}]}
```

初始化从不创建 nft 表；既有 private 原生夹具和空的精确受限规则必须已由管理员独立配置。
账本固定为 `/var/lib/opsark-ssh-defense-requests/requests.json`，逐级 nofollow/root 所有权核验，
目录 0700，文件 0600、单硬链接。该目录必须原先不存在；初始化失败留下的目录也不能重试
初始化来恢复额度。正常操作遇到目录/账本丢失、损坏或旧 boot/binding 时暂停，无自动恢复。
不复用、清空或重建 APT 与旧 `/run/opsark-ssh-defense/ledger.json`。备份回滚并非单一账本
自身可完全检测；任何恢复须独立人工核对控制端原 RID、已用额度和旧账本，恢复协议尚未实现。

传输需由后续管理员部署独立 SSH 身份、固定主机公钥、固定 forced-command，禁用任意命令
及转发。角色只能由该固定 argv 选择；stdin 和 `SSH_ORIGINAL_COMMAND` 不切换角色：

- 无参数：readonly，只允许 `query`。
- `--observe`：独立管理员观察身份，只允许 `arm/query`。
- `--control`：专用可信 defense 控制身份，允许 `mode_sync/prepare/apply/revoke/query`。
- `--initialize`：仅本地管理部署；不得出现在远程 forced-command 中。

dispatcher 从读取 stdin 前启用固定 20 秒 Linux real-time alarm，超时只输出固定不可确认错误。
管理员 forced-command 还应固定外层总墙钟超时和 kill-after（示例以 Root 权限运行；专用身份
及精确 sudo/forced-command 部署仍须另行核验）：

```console
/usr/bin/timeout --signal=TERM --kill-after=2s 22s /usr/bin/python3 -I -B /usr/local/libexec/opsark-defense/deploy/defense/ssh_requests.py --control
```

只读身份使用同一固定命令去掉 `--control`，观察身份固定为 `--observe`；不得拼接原始 SSH
命令或 stdin 参数。外层 timeout 使用独立进程组，覆盖 Python 和其 nft 子进程；实际 Linux
alarm/进程组终止仍待 native 验收。控制端观察超时绝不证明远端已停止，任何可能发送的动作
仍只按原 RID 查询。final gate 是本地准入点，不能承诺跨进程调度与内核事务的原子取消。

readonly 与 control 映射到同一个固定 defense principal，权限不同。裸确认、选择模式或
确认告警不产生 grant。当前初始化只部署一个一次性 observation grant；用尽后没有自动续发、
账本归档或新增授权入口。最多保留 8 个 cursor RID、8 个 action RID、32 个 mode RID，满即拒绝。
所有拒绝 tombstone、prepare 额度占用和 intent 已用额度永久保留，不自动清理或退款。

各 op 的 `body` 精确字段为：

```json
{"observation_grant_ref":"ID","policy_sha256":"SHA"}
{"cursor_id":"ID","source_ref":"ID","evidence_sha256":"SHA","policy_sha256":"SHA","mode":"semi|auto","mode_revision":2,"controller_grant_ref":"ID","root_grant_ref":"ID"}
{"manifest_sha256":"SHA","approval":null}
{"kind":"cursor|action|mode"}
{"manifest_sha256":"SHA","approval":{"approval_id":"ID","purpose":"revoke","request_id":"RID","manifest_sha256":"SHA","approved_at":"UTC","expires_at":"UTC"}}
{"mode":"manual|semi|auto","mode_revision":2,"policy_sha256":"SHA"}
```

顺序依次为 arm、prepare、apply、query、revoke、mode_sync。semi apply 的 approval 是与 revoke
相同的精确对象，`purpose` 改为 `apply`；auto apply 必须为 null。确认声明采用 `approved_at <= now < expires_at`，最长 120 秒，apply
确认还不能超过原 grant_deadline。Root 只验证专用可信控制身份的精确声明及预设范围，
不证明真人点击、不读取控制端本地 approval_id，也不把该 ID 当作可远查授权。
Root 自验预部署的 Root grant/模式/revision/来源/UTC 窗口/次数，并精确匹配 controller grant_ref；
控制端仍须独立核验自己的 grant、同步 ACK 和批准事务，本切片不能代替这些控制端检查。

管理员显式 arm 在后续事件发生前固定完整文件书签、真实 boot/listener/ns 和原始 120 秒期限。
arm ACK 丢失仅按原 arm RID 查询。cursor query 只回临时 source_ref、固定别名、分类、0..256
不同失败端口计数及 eligible 摘要。arm 前旧告警、缺 cursor 和管理来源均不能成为执行依据。
prepare 要求指定夹具账号同源 5 个不同端口失败且全尾部无任何同源成功，IPv4-mapped 成功
同样排除；轮转、截断、前缀改写、不完整/超限/非法证据拒绝。prepare 额外固定当时完整尾部，
apply 两次核验该前缀和全尾部。此书签协议不恢复 journal 跨轮转，也不能证明未观察到的
临时写入后回滚；日志和原生 listener 仍处于管理员可信边界。

prepare 不写 nft，在一次 durable commit 内写 RID→随机 action_id/cursor/精确 manifest/ready
以及唯一 cursor 绑定和额度占用。新 cursor/ref/action ID 与既有映射和同批 ID 碰撞时拒绝。manifest 是合同约定的精确对象，涵盖 RID/action_id、scope、
policy、cursor/source_ref、证据、boot/binding、模式/revision、双方 grant_ref、固定 60000ms 和
原 deadline_at；按 ASCII、排序键、无空白 canonical JSON 求 SHA-256。
apply 在同一排他锁中重核条件，先 fsync intent 与不可退款额度，再次核验后最多调用一次 add。
intent 固化不晚于原授权 deadline 的 5 秒 native 准入期限，越过后保持 unknown、不得 add。
intent 的观察上界按最晚准入 + 固定 nft 命令预算 + 60 秒计算：预算直接取现有
`ssh_fixture_nft._TIMEOUT` 的四倍（add 的三次命令和一次精确后验观察），不接收调用端参数。
这防止正常 native 排队时间被误扣进实际 60 秒元素 TTL；持久 active 仍以真实内核剩余 TTL
立即压紧 expiry_bound。只有 intent 且元素消失的记录仍 unknown，不据此确认过期。
重复请求不换书签、延长窗口、补发或续期。manual 或 mode/revision 不匹配时不能首次执行。

query 从不落盘、初始化、增减 nft、核准意图或修复状态。intent 可观察到原元素时回 active；
元素消失且没有持久 active/expiry_bound 时一直 unknown。只有持久 active、同 boot/binding、
精确受限规则空集合且越过保守 expiry_bound 才回 expired。TTL 来自内核并受原 monotonic
边界限制，旧终态不会重新变活动。unknown 阻止新动作。revoke 要求持久 confirmed active
和独立精确声明，先存 revoke_intent 再删除 exact action_id；重试仅观察，空集合本身不证明
revoked，只有终态已持久化且内核仍确认空集合才确认撤销；已撤销记录遇到任何 live 元素也回 unknown。

回执只有固定 metadata、ref、hash、UTC deadline、TTL、固定 reason_code 和候选摘要，
没有 IP、日志、账号、指纹、路径、密钥或原始异常。非零退出/固定 stderr 表示 unavailable，
客户端不得据此重发可能已发送的 apply。Root query(not_found) 也不证明可以安全重发。

本地验证命令（使用仓库现有环境，不创建额外环境）：

```console
python -m pytest tests/test_defense_requests.py tests/test_ssh_fixture_nft.py tests/test_ssh_fixture_executor.py tests/test_ssh_fixture_evidence.py tests/test_ssh_defense_status.py -q
ruff check deploy/defense/request_protocol.py deploy/defense/ssh_requests.py tests/test_defense_requests.py
ty check deploy/defense/request_protocol.py deploy/defense/ssh_requests.py tests/test_defense_requests.py
```

2026-11-05 Windows unit：新增 86 项；连同旧相关测试共 165 passed、1 skipped（原 Linux pipe
selector）。测试实际执行新 dispatcher、wire parser、manifest、状态机与 atomic-file serializer，
只替换 Linux dirfd/所有权/fsync-directory、listener、时钟、alarm 及 nft 边界；证据使用原有真实有界
解析器和合成日志。并发测试在线程互斥下验证同 RID/不同 RID/cursor 的事务结果；真实 flock
跨进程竞争、目录 fsync 的断电语义与 POSIX 所有权尚未 native 验收。

九类合同故障边界的本地覆盖和限制：

1. 控制端 RID 落盘前后：此 Root 切片不验证控制端 SQLite/发送准入，由后续控制端集成验收。
2. 控制端 dispatched 落盘后发送前：Root 仅提供严格只读 not_found；控制端不得重发仍待验。
3. prepare commit 前故障和 commit 后 ACK 丢失：文件重读分别为 not_found/原映射；arm ACK 丢失也复查原 RID。
4. ready 后 intent commit 前：文件保持 ready、0 add；控制端是否已 dispatch 决定能否首次 apply，Root 不虚构该事实。
5. intent commit 后 nft 前及 nft 抛错：原 RID unknown，额度不退、重试 0 补 add。
6. nft 生效而 active commit 前：原 RID 只读见 active；元素到期后因缺持久 active bound 保持 unknown。
7. active commit 前/后异常：重读原映射和额度，内核 TTL 递减、不刷新；真实控制台回执/提交丢失仍待验。
8. revoke intent 后、删除前/后、revoked commit 前：均 unknown，只读重试不再 remove，不把空集合当撤销成功。
9. 缺失/损坏/非规范账本、额度交叉引用破坏、scope/boot/binding 变化：拒绝或 unknown 且不重建；恶意备份回滚不能仅靠本账本完全检测。

其余 unit 覆盖旧/无 cursor、4/5/重复端口、同源成功与 mapped 成功、管理来源、轮转/截断/
前缀改写/不完整/超限、模式/revision、错确认摘要/期限/用途、grant 引用与 auto null 声明、
只读 0 写、TTL 增长与含 revoked 的终态复活拒绝、300ms native 延迟、准入超时、精确到期拒绝、随机 ID 碰撞和 stdin 超时固定错误。完整三模式控制台、可选 AI、独立 SSH 部署清单、真实
Root/OpenSSH/nft 的 60 秒到期/撤销/断连/重启和管理对照连接仍需隔离 native 验收；这些 unit
不构成控制台写侧全闭环或新 native 动作通过的声明。
