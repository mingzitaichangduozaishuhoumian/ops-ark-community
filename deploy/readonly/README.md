# 服务端受限只读 SSH 采集

此部署资产为 Ubuntu/Debian 的专用 `opsark-readonly` 账号建立服务器端命令限制。管理员在已授权的目标上人工审核并安装；产品仍不接受 root 采集账号。它不创建 Docker 用户组成员、不授予 journal 用户组或通用 sudo，也不配置自动修复或封禁。

## 安装接口

先由部署者在控制台部署机的私有目录中，为每台服务器生成一把独立 Ed25519 采集密钥。以下示例用于 Linux Shell，文件名应与清单中的 `key_file` 一致，运行前确认该密钥文件尚未存在：

```console
umask 077
mkdir -p /absolute/private/ssh
ssh-keygen -q -t ed25519 -N '' -f /absolute/private/ssh/opsark-web-01-readonly
```

示例生成供服务读取的专用无口令密钥。私钥由部署者保管，限制为仅控制端服务身份可读；对应的 `.pub` 公钥用于目标机安装。接入向导负责核对服务器公钥和指纹、生成登记材料，登录密钥由部署者生成。Windows 部署同时核对私有目录和密钥文件的 ACL。

将私钥及已核验的 `known_hosts` 文件引用登记到清单后，导出单个目标的策略。该命令使用现有 `load_hosts` 校验，不连接 SSH，不打印凭据路径或内容，输出仅含固定命令与 argv：

```console
uv run python deploy/readonly/export_policy.py \
  --inventory /absolute/private-inventory.toml \
  --host-id registered-host-id \
  --output /absolute/private-policy.json
```

清单仍必须使用专用非 root 账号以及已有的独立密钥和可信主机文件引用。策略输出为 0600；更新同一路径会原子替换旧策略文件，拒绝符号链接。Windows 部署需同时核验输出目录 ACL。

管理员将本目录的 `install.py`、`guard.py`、`ssh_entry.py`、`http_readiness.py`、该机器的只读策略和采集公钥放入目标机上 root 所有且不可被其他用户写入的临时部署目录，例如 `/root/opsark-readonly-stage/`。上传的密钥材料仅为 `.pub` 公钥。策略和公钥文件必须由 root 所有，不能是符号链接。

```console
/usr/bin/python3 -I /root/opsark-readonly-stage/install.py \
  --policy /root/opsark-readonly-stage/readonly-policy.json \
  --public-key /root/opsark-readonly-stage/collector.pub
```

远端只依赖发行版 Python 3 标准库、sudo、useradd/usermod、visudo 和 GNU timeout；不安装项目 Python 包。安装器不更改或重载 SSH daemon。先确认服务器当前的有效 `AuthorizedKeysFile` 包含账号的 `.ssh/authorized_keys`，账号没有被全局 AllowUsers/DenyUsers 或其他认证策略排除。锁定密码后，仅该独立公钥可用于接入。

安装器创建：

| 路径 | 权限和用途 |
| --- | --- |
| `/usr/local/libexec/opsark-ssh-entry` | root:root 0755；OpenSSH 强制入口，把原始命令作为单个 argv 交给 sudo |
| `/usr/local/libexec/opsark-readonly-guard` | root:root 0755；确切命令与固定 argv 校验、执行及预算 |
| `/usr/local/libexec/opsark-http-readiness` | root:root 0755；降权后执行已登记的本机 HTTP 比对，仅输出有限状态 |
| `/etc/opsark/readonly-policy.json` | root:root 0600；该服务器专属命令表 |
| `/etc/opsark/readonly-installed.json` | root:root 0600；安装归属和策略摘要 |
| `/var/lib/opsark-readonly/.ssh/authorized_keys` | root:root 0644，父目录 root:root 0755；只能读公钥、不能自行添加或修改 |
| `/etc/sudoers.d/opsark-readonly` | root:root 0440；仅允许调用上述 guard |
| `/run/opsark-readonly.lock` | 运行时按需创建 root:root 0600；同机最多执行一个采集命令 |

公钥固定带 `restrict,no-user-rc,command="/usr/local/libexec/opsark-ssh-entry"`。这会拒绝该密钥的交互 Shell、PTY、SSH 转发、agent/X11 转发和用户 rc；SFTP/scp 也不能通过确切命令表。安装器拒绝接管预先存在的不相关账号、主目录或部署文件；如果首次安装中断，保留当前状态供管理员核查，不自动删除账号。后续仅可更新带匹配安装标记的同一部署。

安装归属标记会在新建账号后先记录 `in_progress`，最终记录 `complete`；中断时管理员核对该专用 UID 与路径后可按同一策略重试，不能删除归属检查来接管无关账号。安装时显式设置根所有的目录遍历权限，避免 umask 将公钥路径误变为账号无法读取的目录；helper 源文件通过文本读取后以 LF 安装，Windows checkout 的 CRLF 不会进入可执行 shebang。

## 策略格式

```json
{
  "schema_version": 1,
  "commands": {
    "LC_ALL=C timeout -k 1s 5s cat /etc/os-release": [
      "timeout", "-k", "1s", "5s", "cat", "/etc/os-release"
    ]
  }
}
```

控制台使用 `commands_for(host, scenario)` 为经过确认的具体主机、容器、站点和路径生成命令表，并加入 `commands_for_preflight(host)` 的八项固定预检和已确认的[业务就绪检查](../../docs/RUNNING.md#业务就绪检查)。预检额外包括固定 Compose 插件版本和默认本地 socket 的 Linux/rootful 模式查询；不执行项目、读取 Compose 配置或自动发现依赖。旧策略须由管理员重新导出、审核和安装，未更新时保持预检缺口，不自动授予命令权限。键增加固定 `LC_ALL=C `，值为该固定命令的 `shlex.split()`。每个目标单独审核，不把通配目标、任意路径或任意 Docker/Shell 命令交给采集账号。策略属于可信 root 部署配置，管理员仍可显式修改它；guard 不是不可信策略的安全审查器。

guard 不从调用者接收策略路径，不重新解析用户命令后执行；只精确查表，再执行表中预先登记的 argv。表中的固定工具探针和摘要检查可能使用 `sh -c`，其脚本文本完全来自 root 所有的登记策略。未经登记的空格变化、Shell 拼接、额外参数或其他请求均失败。策略及其父目录必须 root 所有、不能让组或其他用户写入，策略不能是符号链接或多重硬链接；重复 JSON 字段也拒绝。

明确登记 `compose_project` 后，导出器另加入该项目的固定标签/状态/发布端口命令，不读取 Env、完整 Labels、Command、Mounts、Compose 文件或日志。`container_binding_confirmed = false` 时，不生成占位容器的 inspect/logs 权限；网页确认只产生片段，管理员实际更新清单并重新审核策略后，才能采集选定容器。既有未设置此字段的登记保持原路径。[发现与确认合同](../../docs/COMPOSE_DISCOVERY.md)

执行使用固定 PATH、LC_ALL、HOME 和 Docker 配置路径，不继承调用方的 Python、Docker context/TLS、代理或分页器环境。stdin 关闭；子进程组有 6 秒墙钟预算，原有 GNU timeout 为 5 秒加 1 秒强制终止宽限；stdout/stderr 总共最多 16 KiB，溢出或超时有非零退出结果。系统审计只写事件、退出结果和命令摘要编号，不写原始命令、日志或响应内容。

同机使用经过 root 所有权、0600、普通单链接文件和 no-follow 校验的非阻塞全局文件锁；已有采集正在执行时以 75 退出，不排队、不执行请求，也不能通过多条 SSH 会话绕过控制台的并发限制。锁 fd 显式传给固定 timeout 子进程；即使 SSH 会话中断或 guard 被 SIGKILL，存活的命令仍持有锁，到命令结束才释放，不依赖 Python finally 执行。锁文件本身可以保留。

## 实机验收与撤销

### Nginx 错误日志窗口

可在已有专用只读账号的清单为一个具体站点设置 `nginx_error_window_enabled = true`。切换时先让该目标正在运行的调查结束，再导出、审核并安装该主机的精确策略。完成下面的助手安装后，重新启动控制端以载入清单，核对服务端策略已经移除原先的日志片段命令。网站调查随后改用只返回分类和计数的助手。助手未安装或未获授权时，报告保留证据不足。旧报告按其原有采集内容显示。

在目标机受信任的 root 所有目录中准备 `install_nginx_error_window.py`、`install_nginx_dependencies.py` 和 `nginx_error_window.py`。在新策略就绪后用管理员身份安装，并传入独立核验的助手文件摘要。

```console
/usr/bin/python3 -I /absolute/reviewed/install_nginx_error_window.py \
  --site shop.example.com --expected-sha256 <已核验的助手文件SHA256>
```

助手使用专用账号读取固定的 `/var/log/nginx/error.log`。部署者需确认 Nginx 以系统 UTC 写入标准错误日志。当前仅接受稳定的 root 所有单链接普通文件，父目录须由 root 所有且组和其他用户不可写。文件上限 128 KiB 和 512 行，且最早记录必须早于 15 分钟窗口起点。权限不足和文件缺失分别记录。其他时区、读途中轮转、超出预算和无法核实的窗口显示证据不足。安装不改动日志权限。

结果只统计当前文件内已识别且匹配登记站点的上游连接拒绝和超时。没有匹配事件时不推断业务是否正常。日志原文留在目标机，控制端和模型只使用各自已有的结构化证据入口。

管理员 SSH 保持原样。使用新采集密钥验证：允许的 OS/工具/状态检查能执行；`id`、Shell、追加 `;` 命令、SFTP、PTY、转发和错误密钥不能执行。核验账号无额外组、sudo 只列精确 helper。维护主机上，预期 503 与停止的旧容器必须使用维护态规则解释，不能作为自动恢复目标。

撤销时由管理员先移除该账号的授权公钥或锁定其 SSH 接入，再核对正在进行的会话；停止新调查后，可单独移除本安装拥有的 sudoers、helper 和策略。不要因为采集失败删除现有业务数据或改变业务服务。root 管理员、服务器操作系统工具和根文件系统完整性仍为信任前提；该入口不提供主机被攻陷后的可信证明。
