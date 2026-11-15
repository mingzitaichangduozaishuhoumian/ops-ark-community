# 原生 SSH RID 隔离验收

入口为 `tests/ssh_defense_requests_lab.py`。它验证固定 private profile 的 Root 请求协议、真实 OpenSSH 认证日志和容器网络命名空间中的 nft 元素，不部署到业务主机。此目录不包含真实凭据、配置、数据库或原始认证日志。

该驱动没有接入控制台三模式、AI、控制端事务存储或真实双许可服务。开发候选另有控制端实现和假数据回归，不能合并为本驱动的实机端到端证据。`missing-controller` 的含义仅是 **Root 拒绝不匹配的 `controller_grant_ref`**；它不证明控制端权限服务执行过事务。`root-auto` 仅验证管理员提前写入 Root 部署的 auto 授权允许 `approval:null`，不表示控制台自动模式已通过。

后续两台已通过独立的[控制台、真实 SSH 和真实模型联合实验](../defense_controller_lab/README.md)，使用新的生命周期和 apply-only 故障驱动。本目录原有记录、源码身份及 `console_and_ai_verified=false` 均保留其当时含义，不改写成后续结果。

## 环境和入口

仅在经授权的 Linux 实验服务器运行。管理员须提前创建 `/var/lib/opsark-release-lab` 下一个全新的私有子目录；该目录和源码所有祖先都必须为 root 所有、不可组/其他写，实验目录自身必须 `0700`。源码文件须 root 所有、不可组/其他写且只有一个硬链接。目录名称不接受 Docker mount 分隔符。

只接受已缓存的完整 `sha256:<64 hex>` image ID，拒绝 tag、自动拉取、构建和镜像声明的 volumes。镜像可包含自己的标签，容器必须精确保留这些标签并增加本次随机标签；网络仅含本次标签。

镜像需要 Python 3.11+ 的标准库，以及这些固定路径的工具：

```text
/usr/bin/python3        /usr/bin/ssh             /usr/bin/ssh-keygen
/usr/sbin/sshd          /usr/sbin/nft             /usr/sbin/useradd
/usr/bin/sudo           /usr/sbin/visudo          /usr/bin/timeout
/bin/sh                /bin/sleep
```

宿主编排只调用 `/usr/bin/docker --host unix:///var/run/docker.sock` 和宿主 `ssh-keygen`；不会调用宿主 nft、sshd、APT 或业务服务。Docker socket 仅由宿主编排使用，不挂入任何容器。

先单独运行自然过期正例，再运行独立撤销和其他用例。`--proof` 必须是实验根目录的一个全新 JSON 直接子文件，使用 `O_EXCL|O_NOFOLLOW` 创建，永不覆盖已有输出。

```sh
sudo /usr/bin/python3 -I -B tests/ssh_defense_requests_lab.py \
  --root /var/lib/opsark-release-lab/requests-native-20261105 \
  --image sha256:<64-hex-cached-image-id> \
  --proof /var/lib/opsark-release-lab/requests-native-20261105/positive-1.json \
  --case positive --confirm-isolated
```

随后将 `--case` 改为 `revoke`、`root-auto` 或下述故障用例，并为每次运行提供不同的全新 proof 文件。`--case all` 顺序运行全部 16 个用例，每个用例重新创建 target、scope、观察 cursor、初始化和私有账本；不会清空账本或重置额度来重复使用一次授权。两个只读 layout probe 不包含在 all 中。本轮新增 socket 机制须先单独 probe、再单独 case；已知受限平台的旧 PID case 仍会拒绝，因此不能把 all 作为本轮必过入口。隐藏的容器内部入口也要求 `--confirm-isolated` 和完整 image ID。

## 隔离与预算

固定内部 bridge `198.18.241.0/28`，IPv6 关闭，网关 `.1`，target `.2`，攻击候选 `.3`、对照 `.5`、保护管理 `.4`。真实受保护 SSH 为 `.2:22422`，Root JSON SSH 为 `.2:22423`，HTTP 对照为 `.2:22480`。所有容器只有该网络，无宿主端口、host network、host PID/IPC、设备透传或额外挂载。

每例最多同时存在四个容器，每个 `0.5 CPU / 192 MiB RAM / 192 MiB RAM+swap / 96 PID`；禁止重启，核心转储上限为零、文件描述符上限为 256。容器入口均为固定 `timeout -k 2s 180s`。客户端只读根文件系统、`cap-drop ALL`、`no-new-privileges:true`。

target 因真实 sshd 和 sudo 保留固定的 `AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, KILL, NET_ADMIN, SETGID, SETUID, SYS_CHROOT`，其 effective CAP 会在容器内再次精确核对。只有 target 允许 setuid；它没有 privileged、SYS_ADMIN、SYS_PTRACE 或 host namespace。启动前检查完整 Docker 安全配置和精确 bind 列表，启动后再次检查唯一网络和固定 IP；target 内还检查接口、地址/掩码、路由与进程的网络命名空间。

代码、假 key、公钥和部署数据只挂入本次生成的 root-private 工作区。target 的 `/var/lib` 挂到本次独占的私有空目录，以便固定 `/var/lib/opsark-ssh-defense-requests` 由 Root `--initialize` 创建一次；不引用宿主原有 `/var/lib` 内容。该挂载只含本例账本，随 owned 容器/目录清理。nft、sshd 配置和认证日志均位于 owned target 内。所有容器使用 `log-driver none`。

| 用例 | 单例墙钟上限 |
| --- | ---: |
| `positive`, `ssh-session-loss`, `intent-after-add`, `socket-interruption` | 各 150 秒 |
| `revoke`, `root-auto`, `intent-before-add` | 各 90 秒 |
| 其余 9 个拒绝用例 | 各 60 秒 |

总体预算为所选单例预算之和，另留固定 120 秒清理余量；`all` 的总上限为 1530 秒。两个 layout probe 各限 60 秒。所有子进程均有更短的固定超时和 stdout/stderr 硬读取上限。命令超时后会终止本次宿主 CLI 进程组，容器仍有自己的 180 秒上限。到达预算只表示实验未完成，不能视为产品协议失败或成功。

清理使用已记录的完整 ID 与精确本次标签复核后删除；网络中存在外来 endpoint 就拒绝清理。删除顺序为容器、网络、最后私有工作目录，不使用任何 global prune。只有清理正常完成的用例才会进入成功 proof。若 Docker daemon 不可用导致清理拒绝，运行会失败，不能把残留资源说成已清理。

## 实际路径和证据

首轮测试机正例在创建容器后、启动前被安全配置核对拒绝：Docker 将能力名返回为 `CAP_CHOWN` 等形式，原驱动仅比较 `CHOWN`。这一轮未启动目标服务或执行 Root 动作，失败 proof 保留，已核对本轮容器和网络全部清理。驱动只规范化一个可选的大写 `CAP_` 前缀，仍精确要求原九项能力，并拒绝未知、多余、缺失、重复和错误类型；21 项无 Docker 回归及额外畸形输入检查通过。新的原生正例须另用全新 fixture 和 proof，不能把此预检失败算成通过。

第二台测试机的首轮在创建网络后被同样的启动前门禁拒绝：旧 Docker 在 IPAM 中保留空 `IPRange`。诊断的新建空网络已清理，原实例容器状态一致。驱动仅接受原固定 Subnet/Gateway，附加的 IPRange 必须是空字符串；未知字段、非空范围、错误类型、额外配置及错误地址均拒绝，41 项无 Docker 回归通过。Internal、IPv6、标签和空 endpoint 等核对继续执行；这一轮也只保留为预检失败记录。

每个 target 先创建全新本地账户、假 host key 和假 client key，启动固定原生 sshd；管理员初始化空的精确 nft 规则后，Root 请求账本只初始化一次。角色入口为管理员所有的固定 `sshd Match User ForceCommand → sudo 精确无参数 wrapper → timeout 25s → python -I -B ssh_requests.py`：

* `opsark-defense-readonly` 不带角色 flag，仅 query；
* `opsark-defense-observe` 固定 `--observe`，可 arm；
* `opsark-defense-control` 固定 `--control`，可控制协议；

公钥仅允许管理 `.4`，禁止转发、TTY、user rc 和密码。请求通过 SSH stdin 传输一条完整 JSON，不通过 shell 参数、环境变量或日志传递。

正例顺序为：管理端 arm 120 秒 → `.3` 真实 sshd 产生五个不同源端口认证失败 → query 原 cursor → prepare 新 RID → 原 RID query 恢复相同 action/manifest → 精确 apply 声明 → 仅 query 原 RID 确认 active → 独立重复 apply 验证 → 原生 TTL 60 秒自然过期。过期等待期间不调用 dispatcher 或 nft，先以真实 SSH 成功证明连接恢复，再 query 原 RID 确认 expired。`revoke` 使用一个全新 target/scope/cursor/RID，通过精确声明撤销；`root-auto` 同样为独立 fixture，最后精确撤销恢复。

原 `positive`、`revoke`、`root-auto` 的 prepare 和 apply 丢回执经过真实 forced-command SSH，再在管理容器的私有回环 TCP 中继上 `SO_LINGER=0` 产生真实 RST。该中继先确认 native SSH 已得到合法 `ready`/`active`，随后丢弃其回执并 reset，调用者只得到结果绑定的 SHA。之后只能以已知原 RID query，核对 action/manifest/cursor 绑定 SHA，不创建新 cursor 或 RID。**这是“原生 SSH 完成之后的管理端回环跳丢回执”，不是 SSH socket 断网、SSH 加密流截断或进程在 intent 中途崩溃。** 独立 duplicate-apply 测试在 query-only 恢复已完成后才进行。

## 新增受控故障边界

新增三例仍使用全新私有 fixture、真实 Role SSH 和上述九项 CAP，Core 两个模块继续绑定 `51149482...ffd0ee` / `ebf2884f...422ac9`。这三个故障例及下述独立只读 probe 的 control wrapper 增加一个固定、管理员所有的测试 gate，再启动未经修改的 RootCLI；readonly 与 observe 入口保持原来的固定角色。

首次 `ssh-session-loss` 在 prepare 阶段以 exit 1 终态失败，不能记为会话丢失通过。旧证据没有 SSH rc/安全类别和目标端步骤，因此不能据空 cases 数组推断 prepare 是否持久化；若旧 workspace 已正常清理，也不能从已删除的账本恢复这一事实。下一次执行必须使用全新 scope/proof，不重复旧的未知动作。

诊断版在 `control-wrapper` 和 session master/祖先/candidate/程序/连接/socket/pidfd/signal 各检查前后，写入本次 target 内 root-private、`O_EXCL` 的固定 metadata JSON。只保留固定 step/status/error 类别、程序类别、namespace/UID/socket bool、计数与 refs；程序类别 `sshd_session` 只是观察值，不扩大现有 `/usr/sbin/sshd` kill 门禁。不记录实际路径、PID、原始请求、SSH stderr、key 或认证日志。错误时在 cleanup 前只读导出最近 24 步和 ledger phase/count/hash，写入失败 proof 的 `failure_diagnostic`，同时记录 SSH rc、stdout 字节数和闭合 stderr 类别。只有 stderr 精确等于本工具已登记的固定 LabError 单行时才细分类，其余一律 `unclassified_stderr`。未知 metadata 字段、类别或超限输出均拒绝导出。

可先单独运行 `--case ssh-session-layout`，其余 `--root/--image/--proof/--confirm-isolated` 与上述入口相同，probe 预算 60 秒且不包含在 `all` 中。它只在全新 fixture 初始化后执行固定 query，使用同一个 control wrapper 检查实际 SSH 祖先、严格程序门禁和 socket ownership；不 arm、prepare、apply 或发送信号，要求 ledger 原样不变。只有全部严格检查通过才返回 `state=observed`，此结果也不能算 session 丢失用例通过。若 probe 失败，安全 metadata 用于区分 sshd-session 布局、`/proc` 访问、祖先链或 socket 归属，再决定后续窄修复；不通过增加 CAP 或宽泛 kill 来绕过。

管理员随后在第一台服务器执行此 probe，已明确定位为 root monitor 的 `/proc/exe` 或 namespace 读取被拒绝：Root query 正常返回，master 验证、五层祖先和唯一候选均通过；`session_program_verify` 为 `proc_or_file_permission_denied`、程序类别 unreadable。账本仍 not_found/records=0/usage=0，没有 arm/prepare/apply/kill。不存在 monitor 为 sshd-session 的证据，原 PID 门禁继续保持拒绝。

### 精确 socket 中断

管理员已批准以新机制集成独立 `socket-interruption` 和无破坏 `ssh-socket-layout`。旧 `ssh-session-loss` / `ssh-session-layout` PID 路径继续保持原门禁，绝不通过捕获旧拒绝后 fallback 来调用 ss；intent shim 的直接 PPid 验证保持不变。两种机制不能混称。

该机制使用 target 现有 NET_ADMIN，对同一 owned network namespace 内当前唯一的完整 IPv4 TCP 四元组执行固定命令。唯一变量只能是从当前 kernel ESTABLISHED row 解析出的十进制 clientPort，不接收地址、表达式或命令参数：

```text
/usr/bin/ss -4 -n -t -K state established
  "( src = 198.18.241.2 and sport = :22423 and dst = 198.18.241.4 and dport = :<clientPort> )"
```

表达式作为单个 argv 传递，不经过 shell；不允许 wildcard、CIDR、or、额外谓词、其他 state、namespace 切换、PID 参数或其他工具路径。`ss -K` 可能静默跳过内核不支持关闭的 socket，不能把返回码零或工具输出当作成功。[ss(8) 上游手册](https://man7.org/linux/man-pages/man8/ss.8.html) 支持上述精确 src/dst/sport/dport 过滤语法，并分别说明 IPv4、TCP 与强制关闭选项。

运行门禁与证据：

1. 在固定镜像内确认 `/usr/bin/ss` 存在且为管理员所有的固定 ELF，绑定其 SHA；不满足则在 prepare/apply 前拒绝。管理员已在第一台缓存 89 镜像只读执行 `ss --help` 确认工具和 --kill 选项存在，没有执行 destroy；其余镜像仍各自检查，不能据此宣布内核支持。
2. 完整复核 target 自身 namespace/profile/CAP、Root scope/boot/native listener binding、固定 22423 master 及 wrapper 的有界祖先归属。采用新的 socket 归属证明，不读取或放宽已拒绝的 monitor exe/ns，也不发送 PID 信号。
3. RootCLI 正常完成并取得准备/执行回执后，仍先 fsync 原 RID/manifest/action 绑定 hash；检查唯一 `.4:<clientPort>→.2:22423` ESTABLISHED row，固定 tuple hash 和 inode ref。one-shot marker 不可覆盖。
4. wrapper 先用固定 `ss -4 -n -t -H state established <同一完整表达式>` 做无破坏读取，只接受一行匹配两端数字地址/端口的固定布局，之后再次检查 kernel 的 tuple/inode 未变。未匹配或工具输出不兼容即拒绝，不放宽解析。
5. wrapper 通过 root-private、prepare/apply 两个固定一次性 mailbox 提交关闭；现有 target 主循环在 SSH 进程树之外重新复核 scope/namespace/相同 tuple+inode+master 后处理。没有新增端口、通用队列或任意地址/命令输入。`O_EXCL` claim 不可删除重置，重复请求不再执行关闭。JSON 先 fsync，mode-gated ready/done 信号只在数据完整后发布。
6. target 主循环启动固定的单线程 helper，helper 只接受 prepare/apply 槽，直接父进程必须为创建 fixture 的原 Python 主进程（原 PID/starttime/exe/namespace）。helper 自行设置 Linux parent-death SIGKILL 后 exec 固定 ss argv；主循环另设 2 秒超时。没有在已有 HTTP 线程的进程中使用 Python preexec_fn。不向任何 sshd/SSH 会话进程发送 PID 信号；仅约束自有工具子进程的生命周期。
7. ss 实际执行后，独立 target 主循环必须记录闭合 rc、输出长度/类别和严格 afterAbsence；rc=0 但原 tuple 或 inode仍存在也记失败。关闭自己正在使用的 SSH socket 可能使 wrapper 立即消失，所以不能依赖 wrapper 自己写“已关闭”。后续只读 proof collector 必须取到主循环的 durable 结果，确认原 full tuple 与 inode 从所有 TCP 状态消失；原 SSH 客户端必须实测 255 且 stdout 空；两个 master 的身份和 native binding 保持，管理/对照 SSH、同源 HTTP 仍通，新 SSH 只 query 原 RID且不增加 usage/TTL。任一条件不满足就失败。

先单选 `--case ssh-socket-layout` 并使用新 proof：只 query、不 arm/prepare/apply，读取 ss 的精确过滤结果、检查唯一 tuple/namespace/scope；不会发布关闭 mailbox，也不会传 --kill。成功仅表示预检通过，不表示 SOCK_DESTROY 可用。随后在另一全新 scope/proof 单选 `--case socket-interruption`：分别丢 prepare/apply 的回执，再原 RID 回查、验证重复 apply 不写/不升 TTL和自然过期。故障层明确记为 `target_exact_ssh_socket_interruption`；proof 只输出 before tuple/inode hash、afterAbsence、ss SHA/rc、counts/state/ref/bool，不包含 raw ss 输出或动态端口。

这些条件必须在每个新镜像/内核上实测：工具可用性、SOCK_DESTROY 支持、权限与表达式兼容性、原 socket 消失、客户端 exit 255、master 保持及新 SSH/RID 恢复。本次两台结果见下表。ss 的四元组过滤没有“比较旧 inode 后原子关闭”的条件；只能在受控 fixture 内串行发起管理 SSH、双重核对 kernel row，并在不一致或源连接先消失时拒绝，不能宣称不存在时序窗口。该方案不证明路由掉线，也不证明旧 PID 门禁已通过。intent shim 对直接 RootCLI PPid/exe/namespace/starttime/pidfd 的原验证继续保留，须另行 native 验证。

`ssh-session-loss` 在 **目标端** gate 扣住 prepare/执行后的合法 Root 回执：RootCLI 已正常退出，gate 先 `fsync` 保存原请求/身份绑定 hash 和剩余 TTL，再从自身祖先链中确定当前 `.4→.2:22423` 会话的 root sshd monitor。monitor 必须是固定 request master 的直接子进程、同一网络命名空间、固定 sshd 程序，并实际持有唯一该连接的 socket；用 pidfd 固定 PID/starttime 后再次复核并终止。不会用名称扫描、killpg 或增加 SYS_PTRACE。无法在镜像上证明此归属就安全失败。

客户端必须实测 SSH `exit 255` 且 stdout 完全为空，再另建 SSH 用原 RID query 同一 action/manifest/cursor。两次丢回执分别覆盖 prepare 与 apply，TTL 不得高于丢失前已提交回执，重复 apply 不写账本或升 TTL；22423 master 和受保护 22422 listener 的身份必须保持，管理/对照 SSH 与同源 HTTP 持续可用。这是**目标端 SSH session 终止**，不称为路由掉线，也不要求或声称 TCP RST。

`intent-before-add` 和 `intent-after-add` 在初始化完成后，仅在 owned target 内将 `/usr/sbin/nft` 替换为明确的测试 shim。原生 ELF 复制到固定 root-private `/usr/sbin/opsark-nft-real`，每次调用校验其 SHA、所有权和权限；shim 自身 SHA 也绑定。**这属于受控 native 调用边界故障注入，不能称为未经修改的原生 nft 调用路径。** 原 nft Python 模块、RootCLI 和请求协议源码不变。

shim 的只读 argv 仅允许 Core 固定的 `list tables ip` 与 `--numeric-priority list table ip opsark_ssh_lab`，随后原样 exec 原生 ELF。唯一允许的写字节流必须精确等于：固定表/set、`.3`、60 秒、账本中原 action ID 的单条 `create element` 模板；删除、多行、其他来源/TTL/参数均拒绝。`O_EXCL` one-shot claim 不可重置；再次出现写会标记 unexpected-write 并拒绝。实际 add 计数限定为 0 或 1。

写 shim 必须确认直接父进程就是 root、同 namespace、精确 argv 的固定 RootCLI，且磁盘账本已为 `phase=intent`、cursor consumed、usage 恰为原 RID 一次、`expiry_bound=None`。shim 始终扣住 stdout，Core 无法完成该 nft 调用并保存 active。同步点在 shim 内自包含执行，不等待宿主调度或用 SIGSTOP 猜时序，并须落在 Core 固定 3 秒 nft 超时内：

| 用例 | 中断顺序 | 原 RID 预期 |
| --- | --- | --- |
| `intent-before-add` | 持久化 barrier → pidfd 终止并确认 RootCLI → 退出 shim；绝不调用原生 add | `unknown`，usage=1，真实 add=0，kernel 空 |
| `intent-after-add` | 同步原生 add 完成 → 持久化 barrier → pidfd 终止并确认 RootCLI → 退出 shim | 元素存活时可 query `active`；自然 TTL 消失后继续 `unknown`，usage=1，真实 add=1 |

原生 add 子进程另设 1 秒超时和 Linux parent-death SIGKILL，避免 shim 被外部超时终止后留下迟写进程。gate 再终止对应 SSH session，客户端无 JSON 后从全新 SSH 请求启动新的 RootCLI 查询；这里的“重启”指新的 CLI 进程，不重启容器、sshd master 或改变 ledger binding。

两类 intent 用例重复 query、原 prepare 和原 apply，要求账本 hash、usage、intent、真实 add 计数及绑定不变；after-add TTL 不升。after-add 等待期间只做管理/对照 SSH 和同源 HTTP 探测，先以候选真实 SSH 成功证明内核自然恢复，再 query 原 RID。由于 Core 从未持久化 active bound，最终仍为 `unknown/result_unknown`，不能记为 expired、回退额度、补写 active 或用新 RID 自动重试。当前 intent phase 的 revoke 也不会执行删除，该人工恢复边界保留。

安全 proof 只包含 counts、状态、hash、ref 和 bool：原 RID/action/cursor/manifest/evidence 绑定，原生失败/成功事件数和不同源端口数，账本 SHA 与记录/usage/intent 数，内核是否 active，回环 RST 的明确层次，TTL 不升，连接恢复，以及 owned 清理。它不包含私钥、公钥内容、原始 JSON 声明、原始认证日志或命令 stderr。

拒绝用例包括：

| 用例 | 实际检查 |
| --- | --- |
| `four-failures` | 4 个不同源端口失败不能 prepare |
| `same-port` | 一次 SSH 连接提供 5 把不同假 key；必须观测到 5 条原生失败事件、仅 1 个源端口，并拒绝 prepare |
| `success-seen` | 同一观察窗口存在真实成功登录即拒绝 |
| `missing-evidence` | 没有原生认证失败证据即拒绝 |
| `manual` | 默认 manual 下未同步 semi revision 的 prepare 被拒，usage/intent/native action 为零；可保留拒绝回执记录 |
| `missing-observation` | Root 拒绝不匹配的观察 grant ref |
| `missing-controller` | Root 拒绝不匹配的 controller grant ref |
| `missing-root` | Root 拒绝不匹配的 Root grant ref |
| `expired-grant` | Root 拒绝已到期的部署预授权 |

正例同时检查 readonly 的 mode/prepare/apply mutation 不改账本，semi 模式缺精确 apply 声明不改账本；生效期间重复验证管理 `.4` 原生 SSH、Root query、对照 `.5` 原生 SSH和同源 `.3` HTTP。duplicate apply 的证据为账本 hash/usage 不变且内核 TTL 不升；没有声称采集了所有 netlink 写事件的审计计数。

## 完成边界

此前第一台原有 12 例、第二台 positive/revoke/root-auto/manual 四例通过，共 16 次 native 验收，属于旧的回环回执丢失边界。2026-11-06 管理员另以提交 `9dc78bd4f45a2643af81b9302d132ef2e459cb2d` 的八文件 LF 源闭包，在两台授权服务器的新 scope 中分别执行只读 socket 预检和精确 socket 中断。driver SHA256 为 `db6048f38c0c750955dc8240264bd348a592e61b960f4c3ded35bfbc3c14e5c0`；Root 两模块保持前述身份。

| 目标 | 独立用例 | 实际耗时 | 安全 proof SHA256 |
| --- | --- | --- | --- |
| 第一台 `试验机 B` | `ssh-socket-layout`，不 arm/prepare/apply/destroy | 10.509 秒 | `5434191d2262cae7412421e12fb1a8ba1f8684593ae95e6dcc5cfba8f95674f0` |
| 第一台 `试验机 B` | `socket-interruption` | 97.812 秒 | `e9705c2a13f12f3f3b6be5330971066ac49a559b8c7d5c15931320faa95f40cc` |
| 第二台 `试验机 A` | `ssh-socket-layout`，不 arm/prepare/apply/destroy | 6.482 秒 | `a2b45e5616503826feb76348292d94f9cc33f63467bead303b8a5b88a39823ee` |
| 第二台 `试验机 A` | `socket-interruption` | 81.273 秒 | `132f0c83135d9c5ea52155f8187941b49d3c8b9f8a98985d11b0003409e6bfa3` |

两份中断用例均实测 prepare/apply 原 SSH 客户端 255 且无 JSON、新 SSH 只 query 同一原 RID、exact tuple/inode 消失、两个 listener 身份保持、重复 apply 账本不变/TTL 不升、自然到期后原 RID 不可重放，最终 usage=1、intent=1。管理/对照 SSH 和同源 HTTP 保持。所有 proof 的 `console_and_ai_verified=false`；这不验证路由掉线、宿主断电、控制台/真实模型联合执行或 intent 中途崩溃。

安全汇总 `native-socket-proof.json` SHA256 为 `5ab4fb523872d200e94ab4e4e8d5f777dbbbb6c9c07c32594f93700107a03b4e`，仅在忽略的本地验收目录归档。两侧共六个本轮私有阶段目录已在终态、所有权、路径、文件 hash 和无挂载检查后移除，实验容器/网络为零；早期两个安全失败也保留 JSON 元数据。工具镜像留作后续故障验收，常驻配置、历史及权限未修改。旧 PID 门禁继续拒绝，不用新机制掩盖旧失败；intent 两例仍待单独验收。

`fake_fault_regression()` 可通过 `runpy.run_path(...)` 单独调用，只检查精确 nft 写模板和有界 SSH 祖先候选；`fake_diagnostic_regression()` 检查闭合类别、metadata 白名单、非法字段/类型拒绝和 captured output 不泄露；`fake_socket_grammar_regression()` 检查唯一四元组、固定 ss argv、只读结果及保守 afterAbsence 语法；`fake_socket_worker_regression()` 在 RAM 替身中执行真实 worker，验证静默跳过、工具拒绝、tuple/master 改变均不通过，claim 不重复执行且不保存 raw stderr。它们不创建进程或 Docker 资源，不能证明 Linux pidfd、sshd monitor 布局、真实 socket、原生 nft 或子进程中断已经通过。此 driver 仍不覆盖 cursor 自身等满 120 秒后的拒绝、额外 wire 缺字段矩阵、路由/网络链路掉线、宿主崩溃/断电、控制台或 AI。
