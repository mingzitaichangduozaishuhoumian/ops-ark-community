# 原生 Web 观察预算验收

本实验使用全新 Ubuntu 24.04 KVM 客体中的真实 `nginx.service`、journald、OpenSSH 和专用只读账号，核对有限日志窗口的分类、覆盖缺口、告警去重及模型失败边界。请求只发往客体的 `127.0.0.1:18880`，站点固定为 `opsark-lab.invalid`。

这里发布两份与已执行版本逐字节一致的脚本。

- [guest_setup.py](guest_setup.py) 在客体内核对身份和发行包，调用官方安装器，产生固定流量并读取原生 producer 摘要。
- [controller_checks.py](controller_checks.py) 在新控制端容器内通过真实回环 HTTP API 等待后台观察，核对历史、告警及模型失败结果。

虚拟机调度、管理传输和资源清理由操作者提供。仓库中的脚本不包含本轮私有传输、缓存位置、凭据、数据库或原始日志。

## 2026-11-05 实机记录

本轮运行的是 OpsArk 0.18.0 候选代码。发行包及烘焙镜像中的 74 个运行时文件均完成核对。

| 项目 | 绑定值 |
| --- | --- |
| 代码提交 | `f8cfeff6d29afbcb1395d62accaaaf6bc6ee13c2` |
| 发行包 SHA256 | `ce72614ff2afde088809a6508b7e85f6d53a5fdd1ecd0ed1795fcce0b23c13cc` |
| 运行时文件 SHA256 | `b5d4e7eaf1cbdce548037d51888c973dd4b4f1bc8a63593859b12c6bf438db20` |
| 本轮控制端镜像 | `sha256:b887c87e5967cffa01d71ced1594eb8dfbaef78a2d5288b895e9ae2482978ecb` |

重跑时由操作者重新构建并记录新的镜像摘要，再核对候选代码和运行时文件摘要。

本轮结果如下。通知计数为对应 Web 告警记录中的计数，通知渠道为控制台。

| 阶段 | 已验证结果 |
| --- | --- |
| 正常控制 | 20 次 GET 全部返回 200，API 取得 `complete` 的 20 条事件，Web 告警为 0。 |
| 有界混合流量 | 240 次 GET 中前 216 次返回 200，最后 24 次返回 500。`secret_probe`、`repo_probe`、`cms_probe` 各 8 次，并发上限为 2，任意一秒最多启动 19 次请求。 |
| 原生 reader | 一次独立帧为 12,199 字节，读取 200 条原生日志，保留 25 条分类事件，状态为 `degraded`。 |
| 覆盖缺口 | 实际返回 `journal_record_limit`、`projection_event_limit`、`projection_output_limit` 三项缺口。 |
| Web 告警 | 形成一条 `web_scan` 和一条 `observation_gap`。扫描的唯一事件计数为 24，两条告警各有 1 次通知，合计 2 次。没有产生比例型错误或慢请求告警。 |
| 重复采集与真实重启 | 新观察 ID 继续产生，原事件 ID、告警 ID、唯一计数、通知计数及历史观察保持一致。 |
| 只读认证暂不可用 | 仅临时禁用新建只读账号的授权公钥。API 明确记录 `unavailable`，新增一条采集失败告警，Web 告警及通知合计均为 3；原扫描计数 24 和旧证据仍可查询。 |
| 恢复授权 | 原样恢复公钥文件后，新的观察回到具有相同预算缺口的 `degraded`，原证据及扫描计数保留。 |
| 本地模型失败 | 一次明确预览、确认后发送一次请求。本地固定端点返回 HTTP 503，发送摘要通过白名单及确认摘要哈希核对；失败分析未缓存，后台规则继续产生新的观察。 |

七个证明阶段全部通过，共核对 9 份不可变观察记录。原生 producer 帧摘要和 API 归一化观察分别取证。

这些流量强度用于触发预算边界，不能据此推断生产吞吐能力。认证反例覆盖只读账号认证失败，未在该阶段制造物理网络中断。模型部分只覆盖新假凭据下的本地 HTTP 503，不扩展为真实模型、其他提供方、超时或重试去重结论。本实验不验收业务恢复、漏洞修复、入侵认定或 DDoS 防御。

## 环境与身份准备

管理员需要有权创建和清理独立 KVM 客体、Docker 容器及内部网络。使用支持 KVM 的 Linux 主机、固定摘要的工具镜像、已校验签名和 SHA256 的官方 Ubuntu 24.04 云镜像。核对基础 qcow2 没有外部 backing 文件及已有快照，再创建本轮专用磁盘覆盖层和 NoCloud seed。

本轮客体使用 1 个 vCPU、1024 MiB 内存。控制端运行阶段使用 0.5 CPU、192 MiB 内存、相同的 memory-swap 总额、64 个 PID，并关闭健康检查。外部调度器应分别记录虚拟机、工具容器和构建器的真实资源限制；应用运行额度不构成构建器额度证明。

每轮必须生成新的 UUID、管理密钥、客体主机密钥和只读采集密钥。管理私钥保留在操作者一侧。先通过独立管理通道核对本轮 UUID 和公开主机密钥，完成原生 NoCloud、PID1、journald 及 KVM 身份核验，再开放仅用于公共依赖安装的临时引导出口。

依赖安装使用固定的 `nginx`、`curl`、`python3`、`sudo` 包。基础云镜像还需提供 systemd、journald、OpenSSH、coreutils、`useradd`、`usermod`、`visudo` 和 `cloud-id`。安装时应防止默认 Nginx 站点自动启动，仅在确认 stock `sites-enabled/default` 指向 stock `sites-available/default` 后移除该符号链接。安装完成后移除临时出口并再次核对内部网络，保留独立管理通道。

客体内的固定暂存目录为 `/root/opsark-web-burst`，须由 root 所有且权限为 0700。准备以下文件。

| 路径 | 内容 |
| --- | --- |
| `app/` | 从核实过的候选发行包提取的源码，包含 `release-manifest.json`。 |
| `guest_setup.py` | 本目录的客体脚本，上传前后核对文件摘要。 |
| `release-identity.json` | 独立核实的 `commit` 与 `manifest_sha256`。 |
| `guest-identity.json` | 本轮 NoCloud 引导生成的身份记录。 |

`guest-identity.json` 使用以下固定结构，其中 UUID 必须来自本轮独立调度记录。

```json
{
  "schema_version": 1,
  "owner": "opsark-web-burst-v1",
  "vm_uuid": "<this-run-uuid>",
  "cloud_datasource": "NoCloud"
}
```

每次调用都需要从客体之外传入同一个 `--expected-vm-uuid`。脚本会比较该参数、实际 DMI UUID 与身份记录，并调用原生 `cloud-id`，在任何配置或证明文件写入前确认结果为 `nocloud`。客体自述文件不能替代这个独立参数。

## 配置 producer 与只读登记

先在客体中运行配置阶段。

```sh
/usr/bin/python3 -I -B /root/opsark-web-burst/guest_setup.py \
  --expected-vm-uuid '<this-run-uuid>' configure
```

该阶段创建具有实验归属标记的单个 loopback vhost，使用原生 `nginx.service`，再以当前文件摘要调用 [Web 官方安装器](../../deploy/web/README.md) 的 CAS 安装。它核对 `/usr/sbin/nginx`、`nginx.service` cgroup、journald 和安装文件摘要，返回安全的 `profile_digest` 等元数据。配置及就绪阶段不发送 HTTP 请求。

管理员随后在控制端一侧准备新登记，固定 `host_id=web-burst-kvm`、站点 `opsark-lab.invalid`、账号 `opsark-readonly`。SSH 地址、端口及公开主机密钥由本轮受控网络决定，可信主机文件必须使用独立核对的客体公钥。将返回的摘要登记为 `web_profile_digest`，使用同候选代码的 `scope_for_web` 计算 `web_scope_hash`。

使用锁定依赖的 Python 3.13 环境运行 [只读策略导出器](../../deploy/readonly/README.md)。

```sh
uv run python deploy/readonly/export_policy.py \
  --inventory '<absolute-new-private-inventory.toml>' \
  --host-id web-burst-kvm \
  --output '<absolute-new-readonly-policy.json>'
```

把新采集密钥的公钥和审核后的策略分别上传为客体内的 `collector.pub`、`readonly-policy.json`。采集私钥只在新控制端的专用配置中使用。执行官方只读账号安装与就绪检查。

```sh
/usr/bin/python3 -I -B /root/opsark-web-burst/guest_setup.py \
  --expected-vm-uuid '<this-run-uuid>' install
/usr/bin/python3 -I -B /root/opsark-web-burst/guest_setup.py \
  --expected-vm-uuid '<this-run-uuid>' readiness
```

只读登记允许的 Web 命令为下列固定命令。安装、流量生成和管理操作由独立管理员执行。

```text
LC_ALL=C timeout -k 1s 5s /usr/bin/python3 -I /usr/local/libexec/opsark-web-read
```

该客体不安装漏洞修复或防御写入执行器。所有流量源均标为 `controlled_web_probe`，vhost 只向 syslog 输出分类字段。真实 journal 来源还须同时满足 `_SYSTEMD_UNIT=nginx.service`、`_EXE=/usr/sbin/nginx`、`_COMM=nginx`、`SYSLOG_IDENTIFIER=opsark_web`。

## 新控制端与数据

使用经过发行包验证和运行时文件核对的烘焙应用镜像。控制端采用 UID/GID 10001、只读根文件系统、全部能力移除和 no-new-privileges，仅连接本轮内部网络。应用在容器内监听 `0.0.0.0:8010`，验收脚本仅通过回环 API 访问。管理调度器需要核对没有宿主端口发布。

运行容器只挂载新登记配置、新数据目录及本目录的验收脚本，分别位于 `/run/opsark`、`/app/data`、`/acceptance/controller_checks.py`。配置及脚本挂载只读。挂载权限应允许 UID 10001 遍历配置并读写新数据目录。

开启明确目标的后台只读观察，并将修复及真实 AI 配置保持为空。

```text
OPSARK_DATA_DIR=/app/data
OPSARK_INVENTORY=/run/opsark/inventory.toml
OPSARK_TOKEN=
OPSARK_OBSERVE_ENABLED=true
OPSARK_OBSERVE_HOSTS=web-burst-kvm
OPSARK_OBSERVE_INTERVAL=30
OPSARK_WEB_OBSERVE_ENABLED=true
OPSARK_PATCH_INVENTORY=
OPSARK_AUTOMATION_POLICY=
OPSARK_VULNERABILITY_SCAN_ENABLED=false
OPSARK_AI_BASE_URL=
OPSARK_AI_MODEL=
OPSARK_AI_KEY=
OPSARK_AI_KEY_FILE=
```

新数据目录由应用创建独立访问令牌。验收脚本仅在容器内读取该文件，通过真实 `127.0.0.1:8010` API 鉴权。脚本使用 `manual` 模式及 `execution_available=false` 作为入口边界。

在 UID 10001 所有、权限 0700 的 `/app/data/acceptance-web` 下写入权限 0600 的 `descriptor.json`。

```json
{
  "host_id": "web-burst-kvm",
  "domain": "opsark-lab.invalid",
  "web_scope_hash": "<actual-web-scope-sha256>",
  "profile_digest": "<actual-profile-sha256>",
  "data_dir": "/app/data"
}
```

## 执行与核对顺序

下列命令中的客体操作通过已固定身份的独立管理通道执行，控制端操作通过操作者核对过归属的容器执行。每个成功的验收阶段会保留原始证明；流量阶段中断后应检查未完成记录，不能直接重放以凑齐计数。重跑使用新 UUID、新磁盘和新数据目录，保留本轮 journal 直至证据归档。

1. 在客体运行 `normal`，产生 20 次正常请求。
2. 在控制端运行 `normal`，等待新的后台观察，核对完整采集和无 Web 扫描告警。
3. 在客体运行 `burst`，产生固定的 240 次请求。
4. 在客体运行 `producer-proof`，把返回的七键安全摘要保存为控制端的 `/app/data/acceptance-web/native-burst.json`，权限为 0600、所有者为 UID 10001。
5. 在控制端依次运行 `burst`、`repeat`，核对真实预算缺口和连续采集去重。
6. 由管理员真实重启同一个控制端容器，然后运行 `post-restart`。脚本还会核对 PID 命名空间和 PID1 启动代际发生变化。
7. 通过独立管理账号，仅临时禁用新只读账号的授权公钥，运行控制端 `ssh-unavailable`。随后逐字节恢复公钥文件和权限，再运行 `ssh-restored`。
8. 按下一节执行本地 503 模型反例。

客体流量及原生摘要命令使用同一形式。

```sh
/usr/bin/python3 -I -B /root/opsark-web-burst/guest_setup.py \
  --expected-vm-uuid '<this-run-uuid>' normal
# 后续分别将 normal 替换为 burst、producer-proof。
```

控制端检查通过实际容器执行。

```sh
docker exec '<owned-controller-id>' /app/.venv/bin/python -I -B \
  /acceptance/controller_checks.py \
  --descriptor /app/data/acceptance-web/descriptor.json normal
# 后续分别运行 burst、repeat、post-restart、ssh-unavailable、ssh-restored。
```

reader 的采集窗口为 900 秒，最多读取 200 条原生日志、保留 80 条事件、输出 12,288 字节。完整快照中的错误及慢请求比例告警使用 300 秒窗口。`producer-proof` 会从经摘要核对的两端源码读取并比较窗口常量，不改变已部署 producer 的策略。

`producer-proof` 有独立的有界进程及严格 JSON 检查，返回 `profile_digest`、`stdout_bytes`、`stdout_sha256`、`raw_records_seen`、`event_count`、`status`、`gaps`。它不增加流量，也不改写客体的正常或混合流量计数。

## 本地 503 模型反例

先运行控制端脚本的 `prepare-provider`，生成本轮新假凭据和空请求证明。密钥内容不输出。管理员以相同镜像、登记及数据目录重新创建控制端，仅将模型配置设为以下固定值。

```text
OPSARK_AI_PROVIDER=openai
OPSARK_AI_BASE_URL=http://127.0.0.1:18890/v1
OPSARK_AI_MODEL=opsark-web-fixture-503
OPSARK_AI_KEY=
OPSARK_AI_KEY_FILE=/app/data/acceptance-web/fake-provider-key
OPSARK_AI_RESPONSE_FORMAT=json_object
OPSARK_AI_TOKEN_LIMIT_PARAMETER=max_tokens
OPSARK_AI_THINKING_MODE=provider_default
OPSARK_AI_MAX_OUTPUT_TOKENS=1600
```

在新控制端容器内启动辅助端点，核对回环监听就绪，再执行一次 `model-503`。

```sh
docker exec -d '<owned-controller-id>' /app/.venv/bin/python -I -B \
  /acceptance/controller_checks.py \
  --descriptor /app/data/acceptance-web/descriptor.json --serve-provider
docker exec '<owned-controller-id>' /app/.venv/bin/python -I -B \
  /acceptance/controller_checks.py \
  --descriptor /app/data/acceptance-web/descriptor.json model-503
```

辅助端点只接受固定路由，返回固定 503，并核对系统提示摘要、分类字段白名单和用户确认过的预览摘要哈希。证明文件只记录请求次数、摘要哈希和白名单布尔结果。脚本会确认分析失败未缓存，并等待后续真实后台观察。

## 证明与清理

控制端的 `checkpoint.json` 保留阶段、观察 ID、时间和摘要，以及用于去重比较的告警计数。`provider-proof.json` 只含模型反例的安全元数据；原生七键摘要单独保存在 `native-burst.json`。本轮私有归档还记录发行包、运行时和资源身份，未随本说明发布。

完成或中止后，先保存带真实通过或未完成状态的安全证明，再按本轮 UUID、归属标签、精确容器及镜像 ID 清理资源。专用管理凭据、采集凭据、私有暂存目录和工具镜像由操作者逐项核对处理。

本轮已完成上述清理：控制端及镜像、新 VM/私网/覆盖盘/seed、专用工具镜像、远端控制数据和私有工具目录均已移除。本地新管理私钥也已定点删除，对外验收摘要只含标识、计数、文件摘要和布尔证明。原有容器、网络及公开云镜像缓存核对一致，常驻配置、权限及历史没有本轮变更。
