# 持续 SSH 安全观察采集器

`read_journal.py` 是 Linux 上的 root 管理只读采集工具，远端仅依赖 Python 3 标准库和 systemd journal。它不启动防御动作，不修改 SSH/Nginx，不读取私钥、配置全文或任意文件，也不将原始认证日志传给控制台。

管理员审核后将文件以 root:root 0755 安装为 `/usr/local/libexec/opsark-security-read`。控制台使用已有专用非 root 账号和服务器端 guard，只允许以下无参数精确命令；不能用扩大 Shell 或 sudo 权限替代策略更新：

```text
LC_ALL=C timeout -k 1s 5s /usr/bin/python3 -I /usr/local/libexec/opsark-security-read
```

该命令需由管理员加入对应服务器的 root 所有精确策略。更新策略与部署采集器属于管理员部署；应用不会自行安装。文件及父目录必须保持 root 控制。移除该命令或独立采集公钥可撤销访问。

## 读取范围与证据

每次读取捕获时刻之前 15 分钟的系统 journal，最多 200 条，单位仅为 `ssh.service` 和明确命名的 `opsark-security-probe.service`。后者专用于授权的隔离演练，事件始终标记为 `controlled_probe`，不能展示为真实攻击。

实验单位只接受 root 管理的 `/usr/local/libexec/opsark-sshd-lab` 副本和 `_COMM=opsark-sshd-lab`、`SYSLOG_IDENTIFIER=opsark-security-probe`；不接受原始 `sshd` basename 的兼容回退。管理员需先核验副本与系统 sshd 的哈希相同、只监听 loopback，实测 journal 元数据及已有防护匹配条件，确认不会触发既有 Fail2ban 后才能生成失败事件。不能通过关闭现有防护来完成演练。真实 SSH 单位的允许路径与 comm 不因实验而放宽。

只识别完整单行的 Failed/Accepted password、publickey、keyboard-interactive 认证格式。Invalid user、连接关闭、启动等正常日志不重复记为认证失败。账号仅投影为 root、invalid、other 三类；不输出账号原文、完整 MESSAGE、密钥指纹或其他日志字段。

认证证据同时检查 journal 的 `_SYSTEMD_UNIT`、`_EXE`、`_COMM`，不能只信任 `SYSLOG_IDENTIFIER=sshd`。普通 logger 伪造标识或消息不会因此变成 SSH 认证证据。systemd 将下划线字段列为 journal 添加的可信元数据，而非下划线的 syslog 字段不做同等验证，见 [journal 字段定义](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html)。root 或系统完整性失陷仍超出这层来源验证能力。

`journalctl` 以 JSON 输出，字段可能是空值或数组；采集器拒绝不符合预期的认证元数据，并报告缺口。JSON 格式、输出字段和数量选项依据 [journalctl 文档](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)。

## 预算与缺口

- journal 固定由 GNU timeout 的 3 秒加 1 秒强制终止宽限监督，reader 另有 4 秒预算；stdout/stderr 合计 256 KiB，stdin 关闭，环境和 PATH 固定。124/137 超时退出明确记录为 `journal_timeout`，不能解释为完整窗口。
- 发回完整 JSON 最多 12 KiB、认证事件最多 80 条；达到投影上限会保留较新事件并明确标记部分覆盖，不发送截断 JSON。
- 200 条日志上限、输出/时间上限、权限警告、畸形记录、未知认证格式、重复/冲突 cursor 均明确记录。
- SSH 仍采用原有主机身份和独立密钥验证，无密钥代理或自动接受未知主机。
- 控制台严格核对窗口长度、微秒时间、时钟差不超过 120 秒、事件所在窗口、来源映射及规范 IP。时钟不符时不计入当前事件。

reader 会识别从 guard 已继承的全局锁 fd，并显式传给 journal 的 timeout 监督进程。识别只对固定 `/run/opsark-readonly.lock` 做 root 所有、0600、普通单链接文件及父目录校验，再检查 `/proc/self/fd` 最多 128 个条目的已有 fd 的 inode/dev；不打开 fd 指向的路径或跟随任意链接。不可信锁路径在启动子进程前拒绝，管理员直接运行、没有 guard fd 时可为空。即使 guard/reader 被杀，timeout 仍持有同一锁并按自己的期限结束查询；即使 journalctl 自行关闭额外 fd，也不能通过这层嵌套提前释放单机采集槽。不可中断的内核 I/O 仍服从操作系统的终止语义。

`complete` 仅代表本次受限查询和格式验证成功，不证明日志从未丢失、被清理，也不代表没有攻击或入侵。窗口重叠使用 scope + journal cursor 的稳定事件 ID 去重；原始 cursor 是不透明证据定位符，不作为命令参数执行。控制台离线超过回看窗口时须另行报告覆盖缺口。

## 传输约定

版本 1 JSON 字段为 `schema_version`、`window_started_us`、`window_ended_us`、`status`、`gaps`、`raw_records_seen`、`events`。时间是十进制 epoch 微秒字符串，状态为 complete/degraded/unavailable。事件仅含 cursor、occurred_us、unit、origin、kind、source_ip、method、account_type。

控制台用 `sha256(scope_hash + "\n" + cursor)` 形成事件 ID。scope 绑定登记目标和可信主机记录。相同 cursor 的重复投影只计一次；相互冲突的同 cursor 投影均不计数并保留缺口。传输失败、权限不足、畸形或截断不会被解释为空的健康窗口。

## 管理员受控 SSH 演练工具

`probe.py` 不加入采集策略，不交给模型或只读账号执行。管理员将该脚本安装为 root 所有工具后，仅使用固定动作：

```console
/usr/bin/python3 -I /root/reviewed-security-probe.py install
/usr/bin/python3 -I /root/reviewed-security-probe.py start
/usr/bin/python3 -I /root/reviewed-security-probe.py status
/usr/bin/python3 -I /root/reviewed-security-probe.py stop
```

`install` 只创建独立副本、固定配置与单个 systemd 单位，完成语法检查及 `daemon-reload`；不会启动或启用服务。副本与当前 `/usr/sbin/sshd` 字节相同，不读取或复制 HostKey 私钥内容，只在配置中引用现有路径。既有同名但无归属标记的路径被拒绝，已归属文件改变或系统 sshd 升级后需重新审核，不静默覆盖。

`start` 先核对归属、配置、空闲的 loopback 23999 端口和 `sshd -t`；只启动该实验单位。服务最长 900 秒，内存 128 MiB、32 个任务、CPU 20%，不自动重启或启用，不改原 SSH/Nginx/Fail2ban。`status` 仅返回副本摘要和最近三条 journal 的来源元数据，不返回 MESSAGE。`stop` 仅停止实验单位，不清空日志。

产生失败登录前，管理员必须检查真实 journal 的 comm/exe/unit/identifier 和现有防护规则，确认此专属副本不会命中真实 SSH 封禁匹配。`status.protection_rules_checked` 固定为 false，表示工具自身没有替管理员完成该项判断。只对授权 loopback 实验端口触发受控请求，结束后停止实验单位；不要向真实管理端口制造失败尝试，也不要关闭已有防护来让测试通过。
