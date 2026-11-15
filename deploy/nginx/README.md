# Nginx 单文件配置备份

管理员可以在受支持的 Linux 目标上保存经过核对的 `/etc/nginx/conf.d/` 单个普通 `.conf` 文件，文件须非空且不超过 256 KiB。先从可信的只读检查或本机审核记录取得 SHA-256，再传给 `capture`。备份目录应是管理员控制的私有目录下的一个新路径。

```console
sudo python3 -I config_snapshot.py capture /etc/nginx/conf.d/shop.conf --expected-sha256 <64-hex-digest> --output /private/backups/shop-before-change
sudo python3 -I config_snapshot.py inspect /private/backups/shop-before-change
```

`capture` 核对文件身份、权限和摘要，保存原字节并在最后写入完成清单。源文件变化、链接、目标已存在或权限异常时拒绝。备份正文和清单留在私有目录，命令只输出状态与摘要。

`inspect` 核验备份本身，再检查同机登记路径。`unchanged` 表示备份与当前磁盘文件匹配，`drift` 表示文件内容或身份已变化，`unavailable` 表示无法安全读取当前文件。备份被篡改时输出 `tampered` 并以非零状态退出。输出中的 `not_rehearsed` 表示还没有完成回退演练。备份文件可能包含敏感配置，按私有运维数据管理。

此入口仅覆盖单文件磁盘证据，当前运行进程的配置、关联站点和完整回退仍需独立验证。

隔离演练使用独立 Nginx 进程和两个同监听端口的测试站点。无效配置被真实语法检查拒绝，两个站点继续提供原响应。批准固定摘要的有效配置后，目标站点响应发生预期变化，对照站点保持正常。核对当前文件摘要和备份后，恢复原始字节并实际重载，两个站点均通过 HTTP 复查。过程见[隔离演练驱动](../../tests/nginx_restore_lab.py)。

## 准备变更预案

先核对同机快照，再把候选 `.conf` 放在 Nginx 配置树以外的管理员目录中。候选文件须为普通私有文件，和当前配置内容不同。将已核对的候选摘要交给 `prepare`，预案会保存独立的候选副本，绑定原快照、当前磁盘文件和十分钟有效期。

```console
sudo python3 -I config_snapshot.py prepare /private/backups/shop-before-change /private/staging/shop-candidate.conf --expected-sha256 <64-hex-digest> --output /private/plans/shop-change
sudo python3 -I config_snapshot.py inspect-plan /private/plans/shop-change
```

`ready` 表示预案材料与当前配置仍匹配。配置漂移、备份不可用、预案过期或文件被篡改分别显示不同状态。输出只含固定状态、预案编号、候选摘要和期限。预案的语法与批准状态分别保留为 `not_checked` 和 `not_approved`。完成语法验收和独立批准后，才能进入下一步处置。

## 隔离语法检查

`validate-plan` 只接受实验驱动中定义的单站点 `/healthz` 候选。使用管理员核对过的本地 Docker 镜像 ID，镜像需提供 `/usr/bin/python3` 和 `/usr/sbin/nginx`，且没有声明卷。候选文件经标准输入传入断网、非 root、只读的临时容器。结果只含语法结论和预案元数据，语法通过时批准状态仍为 `not_approved`。生产配置中的包含文件、证书、模块和关联站点需要另行验收。[Nginx 命令行说明](https://nginx.org/en/docs/switches.html) · [Docker 无网络驱动](https://docs.docker.com/engine/network/drivers/none/)

```console
sudo python3 -I config_snapshot.py validate-plan /private/plans/shop-change --image sha256:<local-image-id>
```

2026 年 11 月 5 日在测试机用真实 Nginx 验证了通过和失败两种结果。待核对的站点文件内容保持一致，实验容器结束后已删除，配置正文和诊断原文未进入结果。

## 记录本机批准

管理员核对预案编号与候选 SHA-256 后，可以用 `approve-plan` 记录一次明确批准。命令要求 `--confirm`，并使用绑定的本地镜像重新运行隔离语法检查。只有语法通过、预案仍在有效期内且当前文件与备份一致时，才保存私有审批回执。

```console
sudo python3 -I config_snapshot.py approve-plan /private/plans/shop-change --image sha256:<local-image-id> --expected-plan-id <plan-id> --expected-candidate-sha256 <64-hex-digest> --output /private/approvals/shop-change --confirm
sudo python3 -I config_snapshot.py inspect-approval /private/approvals/shop-change
```

回执绑定同机预案清单、候选摘要、验证镜像和原到期时间。文件漂移、预案过期和回执损坏会分别显示对应状态。此入口保存批准证据，站点写入、重载与回退仍需独立的受控执行流程。

## 隔离实例的单次执行

源码仓库提供[实机驱动](../../tests/nginx_fixture_action_acceptance.py)，由管理员在授权测试机上运行。它创建专用工作区、合成机器身份和断网 Nginx 双站点容器。运行入口只接受此类固定实验配置，核对容器、镜像、只读挂载和目标文件后再执行。

从审批回执先取得原任务编号。即使执行进程在回复之前中断，仍可用这个编号查回记录。

```console
sudo python3 -I fixture_runtime.py action-id --workspace <isolated-workspace> --approval <approval-directory>
sudo python3 -I fixture_runtime.py apply --workspace <isolated-workspace> --approval <approval-directory> --expected-approval-id <approval-id> --expected-candidate-sha256 <sha256> --container <container-id> --image sha256:<image-id> --confirm
sudo python3 -I fixture_runtime.py status --workspace <isolated-workspace> --action-id <original-action-id>
```

工作区内的 `actions` 账本先持久化意图，再原子替换配置。重载后，目标站点须返回候选响应，对照站点须保持正常，未知域名须被拒绝，才记录 `verified`。一次工作区只允许一条应用意图；已有编号重复提交只返回原回执。状态查询单独显示当前磁盘证据。比如写盘后、重载前中断，磁盘可显示 `candidate`，原任务仍显示 `unknown`。查询和重复调用均不会补做重载或自动回退。

执行前用 Linux `pidfd` 固定已核验的 Nginx 主进程，重载信号只发给该进程。内核无法固定进程、进程已退出或容器运行身份变化时拒绝继续执行。

实机演练分别在写盘后、重载前，以及 HTTP 已核对、终结回执还未写入时强制结束执行进程。两种情况下都查回原编号的 `unknown`，重复提交后文件身份和 HTTP 响应一致。

## 原任务对账与独立回退

配置原子替换并同步后，工具在发送重载信号前保存写入凭证，绑定精确文件身份及隔离运行实例的指纹。终结回执未知时，管理员可以查询原任务，再发起一次独立观察。

```console
sudo python3 -I fixture_runtime.py reconcile --workspace <isolated-workspace> --action-id <original-action-id> --container <container-id> --image sha256:<image-id>
```

只有同一文件身份、同一运行进程以及目标站点、对照站点和未知域名的 HTTP 证据均匹配时，才追加 `reconciliation_status: verified`。原任务的 `status: unknown` 和原回执保留。对账不修改配置、不发重载信号。同字节替换文件、容器重启、HTTP 仍返回旧配置或旧记录缺少写入凭证时，保持未知。

原任务已验证，或已有独立对账通过后，才能为同一工作区申请回退。回退要求人工确认原任务和备份摘要，并对备份原字节重新执行隔离语法检查。回退审批绑定当前候选文件身份、原运行实例及五分钟有效期。

```console
sudo python3 -I fixture_runtime.py approve-restore --workspace <isolated-workspace> --original-action-id <original-action-id> --approval <original-approval-directory> --expected-original-sha256 <backup-sha256> --output <restore-approval-directory> --container <container-id> --image sha256:<image-id> --confirm
sudo python3 -I fixture_runtime.py restore-id --workspace <isolated-workspace> --approval <restore-approval-directory>
sudo python3 -I fixture_runtime.py restore --workspace <isolated-workspace> --approval <restore-approval-directory> --expected-approval-id <restore-approval-id> --expected-original-sha256 <backup-sha256> --container <container-id> --image sha256:<image-id> --confirm
```

回退使用独立任务 ID，写入前持久化意图。执行时再次核对备份、磁盘、有效期和运行实例，原子恢复备份后只发一次重载信号，待实际 HTTP 复查通过才保存回退结果。重复调用只读回原回退回执。未知结果通过 `status` 查询该回退 ID，留待独立处置。

测试机实测了正常执行后的回退，以及重载成功但丢失回执、独立对账后的回退。重载前中断、同字节换文件和容器重启均不能补对账。两条回退路径都保留原任务的意图与结果，重载后重新核对目标和对照站点。全部验证限固定的隔离 Nginx 配置。

## 核对嵌套包含和共享站点

隔离驱动的 `--rich-context` 模式使用一棵固定的嵌套配置树。主配置经一个包含入口加载目标站点、对照站点和默认站点。依赖文件逐项列出，配置树和目标配置目录分别以只读方式挂载。

```console
sudo python3 -I fixture_runtime.py seal-context --workspace <isolated-workspace>
sudo python3 -I fixture_runtime.py prepare-context --workspace <isolated-workspace> --snapshot <backup-directory> --candidate <candidate-file> --expected-sha256 <candidate-sha256> --output <plan-directory>
sudo python3 -I fixture_runtime.py validate-context --workspace <isolated-workspace> --plan <plan-directory> --image sha256:<image-id>
sudo python3 -I fixture_runtime.py approve-context --workspace <isolated-workspace> --plan <plan-directory> --expected-plan-id <plan-id> --expected-candidate-sha256 <candidate-sha256> --output <approval-directory> --image sha256:<image-id> --confirm
```

私有封印记录四个依赖的内容摘要和文件身份，以及所在目录的身份。预案和审批绑定同一份依赖摘要。语法检查在断网容器中重建固定配置树，业务探针核对容器实际看到的文件身份与摘要。依赖漂移会阻止后续操作。即使同字节替换后重新生成封印，旧预案也不接受新封印。

测试机实测了嵌套配置下的执行、重载、对账和独立回退，也验证了各阶段的依赖漂移拒绝。另一次验收更换宿主依赖目录、重新封印并批准，容器仍持有旧目录。执行入口在写入前识别出挂载中的文件身份不符，保留目标配置和运行中的工作进程。

此模式覆盖显式嵌套包含和固定共享站点。通配包含、证书、动态模块、实际客户配置和其他 Nginx 运行环境仍需单独验收。

## 合成证书的 HTTPS 隔离验收

实机驱动的 `--tls-context` 模式为每个工作区生成一对短期合成证书和密钥。固定站点共用这张证书，证书包含目标、对照及未知域名三个实验名称。目录 `tls/` 由管理员拥有，组为隔离 Nginx 的 `65534`，目录权限为 `0750`，证书和密钥文件为 `0640`。配置校验与运行容器均仅本地只读挂载这份合成材料。[Nginx 的 HTTPS 与密钥权限说明](https://nginx.org/en/docs/http/configuring_https_servers.html)

```console
sudo python3 -I fixture_runtime.py seal-context --workspace <isolated-workspace> --tls
```

封印绑定公开证书的指纹，以及证书、密钥和目录的文件身份和权限。Python 核验只检查密钥的文件元数据。原生 Nginx 在隔离语法检查中打开本地密钥，验证它与证书匹配。运行探针连接回环地址，为三个已知名称分别校验 SNI 主机名和握手证书指纹，再检查站点响应。密钥和配置正文不会进入审批回执或命令输出。此模式使用合成材料和共享证书，实际客户密钥、证书链及证书轮换仍需单独验收。

测试机实测了 HTTPS 执行、重载后丢回执的独立对账和回退。另一对证书的密钥无法通过原生语法检查或审批。密钥权限放宽后，执行在写入前停止，目标文件和工作进程保持一致。HTTP 配置树也单独复跑。

## 独立 SNI 证书链

实机驱动的 `--chain-context` 模式为目标、对照和默认站点分别生成独立叶证书。每个链文件固定为叶证书后接中间证书，公开根证书单独保存。根和中间签名私钥在生成阶段结束前清理。隔离容器只读挂载三个叶私钥和公开证书材料，私钥文件继续仅通过元数据核验。

```console
sudo python3 -I fixture_runtime.py seal-context --workspace <isolated-workspace> --tls-chain
```

探针只信任实验根证书，逐个域名校验 SNI、主机名及对应叶证书指纹，并核对服务端发送的叶证书和中间证书顺序。支持链读取的 Python 直接检查已验证的 TLS 连接。Python 3.12 用同一回环监听器上的独立 OpenSSL 握手核对实际发送的链，再完成 HTTPS 业务检查。[Python 链读取接口](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.get_unverified_chain) · [OpenSSL 握手校验](https://docs.openssl.org/3.0/man1/openssl-s_client/)

证书轮换会使旧封印失效。新材料需要重新封印和批准，旧批准仍绑定原依赖摘要。如果容器仍持有旧挂载，即使已经生成新批准也会拒绝执行。此入口覆盖合成证书链的受控验收，生产证书和自动续期流程另需验收。

隔离实测中，缺少中间证书的目标连接无法仅凭根证书通过验证，对照站点仍正常。互换两个站点的证书与配对密钥后，语法仍可通过，但 SNI 主机名检查阻止写入。换成另一套有效材料后，原执行和回退批准均不能继续使用。新批准在旧挂载上也被拒绝，换到实际挂载新材料的隔离实例后才执行通过。

## 单站点续签交接

[续签验收驱动](../../tests/nginx_fixture_renewal_acceptance.py)使用同一根证书和中间证书签发目标站点的新叶证书。续签材料留在单独的隔离副本，候选目录名由当前工作区推导。两个实例都需要预先启动，各自使用独立的合成机器身份、私有动作账本和已封印的证书链配置。

```console
sudo python3 -I fixture_runtime.py renewal-candidate --workspace <isolated-workspace>
sudo python3 -I fixture_runtime.py prepare-renewal --workspace <isolated-workspace> --container <current-container-id> --candidate-container <candidate-container-id> --image sha256:<image-id> --expected-context-sha256 <current-context-sha256>
sudo python3 -I fixture_runtime.py inspect-renewal --workspace <isolated-workspace>
```

准备交接时，入口核对当前封印、两个容器的实际挂载和站点配置。目标站点的新叶证书须晚于原证书到期，整条链的可用期也须延长，并至少剩余一小时。候选通过隔离语法检测后，新旧两个实例均需通过真实 SNI、证书链和站点响应核验。对照和默认站点的证书链文件须保持一致。

通过后只在当前隔离工作区生成 `renewal-pending.json`。命令输出仅包含待审批状态、交接编号、封印摘要、目标叶证书指纹和有效期。相同材料和运行实例再次提交时复用原回执。原封印、材料或实例变化后重新提交会被拒绝，历史回执仍可只读查询。历史状态表示当时已通过交接核验，后续操作须重新检查。上线切换、生产证书与 ACME 签发需要单独验收。

测试机实测了双实例各自的 HTTPS 和证书链、CLI 回查和重复提交。错误的原封印、候选封印缺失、另一个有效信任根均被拒绝。原站点文件和新旧工作进程保持一致，交接回执的字节、权限和文件身份一致。

## 受控上游变更的主机程序

首轮目标为 Ubuntu 24.04 的独立登记主机。管理员从已核验的源码包安装主机程序。解包目录及其上层目录必须由 root 所有，其他账户无写权限。安装使用系统 Python 3.12 或更高版本。

```console
sudo /usr/bin/python3 -I -B /root/opsark-source/deploy/nginx/install_managed_helpers.py
```

安装程序生成三个空包标记，在临时目录用系统 Python 校验依赖导入，再发布到 `/usr/local/lib/opsark-nginx-action`。相同源码再次运行会核对文件与权限并返回相同包摘要。发现不同或不完整的既有目录时拒绝覆盖。回执只包含版本、安装状态、文件数和包摘要。

上面的命令只安装程序。初始化主机策略时，先准备一份由 root 所有、权限为 `0600` 的 JSON，核对其 SHA-256，再明确传入这两个值。

```console
sudo /usr/bin/python3 -I -B /root/opsark-source/deploy/nginx/install_managed_helpers.py \
  --policy /root/reviewed-nginx-policy.json --policy-sha256 <64位摘要>
```

策略只接受一个待变更的静态 HTTP 上游。填写 `schema_version` 为 `1`，`enabled` 为 `true`，`expires_at` 为将来的 UTC 时间。`target_file` 是 `conf.d` 下的文件名，`upstream_name` 与文件内的上游名称一致，`from_port` 和 `to_port` 对应两个不同的回环端口。`nginx_sha256` 与 `bwrap_sha256` 绑定实机程序，`context_files` 列出 Nginx 主配置显式引用的文件。`sites` 中每条记录包含 `site_id`、`host`、`listen_port`、`path`、`before_sha256` 和 `after_sha256`。至少登记一个预期响应改变的站点和一个响应保持相同的对照站点。响应摘要按 HTTP 200 的响应体字节计算。

初始化将原策略字节发布到 `/etc/opsark/nginx-action.json`，并在 `/var/lib/opsark/nginx-action` 下准备 `actions`、`backups`、`plans` 和 `startup` 四个 root 私有目录。重复初始化同一策略会核对原文件，遇到不同策略或不安全的目录权限会拒绝。完成后还需要独立的 SSH 账户和凭据、控制台登记和隔离机验收。

[`managed-systemd.conf`](managed-systemd.conf) 在同一次 `nginx.service` 启动前后核对完整配置图，并关联 systemd 调用和实际主进程。首次审批时必须验证完整启动配置。回退和对账沿用同一份启动凭证，并继续核对非目标配置与原任务的文件身份。见证失败时，Nginx 保持正常的服务启动流程，OpsArk 拒绝进入写入阶段。启动配置应由负责该台 Nginx 的管理员单独安装，受管配置的写入和重载由同一管理流程协调。

2026-11-13 在授权 Ubuntu 24.04 来宾机用 `72d46a2` 验证了该启动配置。实际 systemd `start-post`、主进程启动时间、显式配置入口、启动见证读回和两条回环业务检查均通过。来宾机随后恢复原服务配置并受控关机，闭合回执 SHA-256 为 `6b800fbda0d0848f3bc199f453f6fd64b0eade01b21b30a4d49d06c96c1aa2c0`。该次启动直接观察到已登记的主进程。暂未登记主进程时的候选确认仍由本地模拟覆盖，真实 SSH 角色和批准后的重载另行验收。

审批后如果在替换配置前中断，OpsArk 可以复验同一个原动作。只有确认原文件身份和字节、完整配置范围、同一次启动见证以及预览时的业务响应均一致，并且主机没有发布或重载记录，才会解除该动作对新预览的限制。原动作结果仍显示未知，后续变更需要新的预览和批准。未完成的回退即使确认未改动，也会保留原变更的回退限制，直到另一次回退通过复验。

## 专用 SSH 处置角色

使用一个独立的 `opsark-nginx-action` 账户和一对 Ed25519 密钥。控制端保管私钥，目标机只接收公钥。专用账户使用 `/bin/sh`、锁定密码、独立组和 root 所有的空主目录，权限由强制命令和 sudo 规则限定。控制台负责记录并核对用户批准，目标机将持有专用密钥的控制端视为受信执行端，并单独核对本机策略和动作范围。

1. 在管理员连接可用时，先核对运行中的 SSH 服务使用 Ubuntu 的默认配置入口。将 [`managed-sshd.conf`](managed-sshd.conf) 审阅为独立的 `/etc/ssh/sshd_config.d/00-opsark-nginx-action.conf`。如已有适用的 `Match`、`Include` 或环境变量规则，先核对其优先级及对现有账户的影响。角色配置依赖全局的 `StrictModes`、`PermitUserEnvironment`、`UsePAM` 和 `UseDNS` 边界。
2. 将 [`managed-sudoers.conf`](managed-sudoers.conf) 审阅为 `/etc/sudoers.d/opsark-nginx-action`，由 root 所有且权限为 `0440`。用 `visudo -c` 核对完整配置，再用 `sudo -l -U opsark-nginx-action` 核对该账户仅获准执行规则中列出的固定 Python 命令和参数。
3. 用 `sshd -t` 检查完整配置，再对实际控制端地址、本机监听地址和端口运行 `managed_role.py check-effective`。工具只输出角色配置的核对结果。保留原管理员连接，由管理员决定何时加载配置。
4. 用 `managed_role.py stage-key` 读取由 root 所有、已审核的公钥文件。将生成的 `/var/lib/opsark/nginx-action/authorized_keys.staged` 安装为 `/etc/ssh/opsark-nginx-action/authorized_keys`。目标公钥文件由 root 所有且权限为 `0644`，上层目录由 root 所有，普通用户无写权限。最后从控制端核对固定 SSH 指纹、允许的状态查询和拒绝边界，再登记控制端处置清单。

```console
sudo /usr/bin/python3 -I -B /usr/local/lib/opsark-nginx-action/deploy/nginx/managed_role.py \
  check-effective --peer <控制端IP> --local <监听IP> --port <SSH端口>
sudo /usr/bin/python3 -I -B /usr/local/lib/opsark-nginx-action/deploy/nginx/managed_role.py \
  stage-key --public-key /root/reviewed-nginx-action.pub
```

在控制端通过 `OPSARK_NGINX_ACTION_INVENTORY` 指定私有 JSON 的绝对路径。JSON 包含 `schema_version` 为 `1` 和 `targets`。在 `targets` 下以现有登记主机 ID 为键，填写专用 `key_file` 的绝对路径。`policy_digest` 取初始化回执中 `registration.policy_sha256` 的值。当前切片只登记一个处置目标。默认保持关闭，真实 SSH 登录和批准后重载分别验收。

使用 observer Compose 部署时，将登记 JSON 和专用密钥放在已有的只读 `secrets` 挂载中。登记中的 `key_file` 使用容器内 `/run/opsark/` 下的绝对路径。私有文件设为 `0600` 并交给容器用户 UID 10001。由部署者保存一个显式 Compose 覆盖文件，并将它加到该部署实际使用的 `-f` 列表末尾。

```yaml
services:
  observer:
    environment:
      OPSARK_NGINX_ACTION_INVENTORY: /run/opsark/nginx-actions.json
```

用 `docker compose config` 核对合并后的环境与只读挂载。额外覆盖文件和登记材料单独交接，私钥由部署者另行保管。现有十库和固定配置交接范围见[离线加密交接](../../docs/SEALED_BACKUP.md)。

## 实机审批、重载与回退

2026 年 11 月 13 日以 `da9c2f0` 在独立 Ubuntu 24.04 来宾机完成真实控制台 API 验收。专用 SSH 角色拒绝采集凭据、错误命令、PTY 和转发请求。客户端按固定指纹连接，发送完整请求后关闭写端，收到匹配策略和计划编号的只读回执。原生 `bubblewrap` 语法检查通过后，控制台只批准了一次上游变更。目标站点和对照站点通过实际重载后的业务复验。

回退使用另一份预览和一次独立批准，引用原变更并恢复原上游。两项业务复验通过。独立控制器进程读回两份原始回执，摘要一致，读取期间没有再次提交动作。来宾机受控关机，任务所属容器和网络已清理，宿主基线一致。闭合回执 SHA-256 为 `9b2e1d6c7a44373889fea0a7e31877f29ed5230add425da1fb8606c2a1d93d3a`。

本轮覆盖一个静态 HTTP 上游、一项受影响站点和一个对照站点。动作提交后断线的证据仍由本地故障测试覆盖。任意配置、TLS 续期切换和容器处置分别验收。
