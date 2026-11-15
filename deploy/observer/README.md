# VPS 常驻持续观察控制端

此 Compose 在一台已授权的 Linux VPS 上运行控制端，通过登记的专用受限 SSH 密钥观察目标。浏览器和本机电脑关闭后，VPS 容器仍继续采集并保存控制台告警。0.8 可独立启用定期漏洞观察，以及已有的半自动补丁任务；0.9 增加双侧预授权的受限自动单包编排。定期观察器自身不生成或提交修复。通知默认保存在控制台，漏洞观察可另行配置[签名 Webhook](../../docs/VULNERABILITY_WATCH.md#可选签名-webhook)。

管理员只对已授权主机部署。目标来源以服务端清单和显式 `OPSARK_OBSERVE_HOSTS` 登记 ID 为准，不按密钥可登录范围发现或扩大目标。本轮实际部署由管理员私有流程限定到两台测试服务器；本目录不包含其地址、私钥或令牌。

## 明确准备构建目录与秘密挂载

将本目录的 `compose.yaml` 放到管理员控制的部署目录，使用以下布局：

```text
deployment/
  compose.yaml
  app/
    Dockerfile
    .dockerignore
    pyproject.toml
    uv.lock
    src/
    web/
  data/
  secrets/
    inventory.toml
    known_hosts
    node-a-key
    node-b-key
```

`app/` 只暂存经过审查的上述构建文件。不要复制工作区 `data/`、`.env`、私有清单、SSH 管理员目录或整个工作区作为构建上下文。应用 Dockerfile 以 UID 10001 的非 root 用户启动一个 worker；不覆盖为 root，不增加 worker 数量。

宿主部署目录由 root 控制并限制其他用户访问。`data/` 必须事先创建，所有者 UID 10001、权限 0700，供容器保存 SQLite 与访问令牌。`secrets/` 需对容器 UID 10001 可遍历，可使用 root 所有的 0755 或 UID 10001 所有的 0700，部署上级目录保持 root 私有；内部文件所有者 UID 10001、权限 0400。该目录只读挂载到 `/run/opsark`。Compose 不自动创建缺失的 bind 目录，以免用错误所有权隐式创建数据或秘密目录。

构建目录只含应用资产，镜像会明确设置源码与静态文件的读取/遍历权限，以适应管理员 0700 的私有 staging 目录；这不会改变数据或凭据的权限。关停容器留有 30 秒宽限，供后台有界采集结束并释放租约。

`node-a-key`、`node-b-key` 应是每台目标的独立只读采集私钥，不能使用管理员 root 私钥。可信主机记录应通过可信渠道核验。不要把任何私钥、访问令牌或部署运行数据提交到 Git，也不要打印秘密来确认部署。

清单中的凭据路径必须使用容器内路径，例如：

```toml
[credentials.node_a]
key_file = "/run/opsark/node-a-key"
known_hosts_file = "/run/opsark/known_hosts"

[credentials.node_b]
key_file = "/run/opsark/node-b-key"
known_hosts_file = "/run/opsark/known_hosts"

[[hosts]]
id = "node-a"
name = "测试目标 A"
address = "192.0.2.10"
username = "opsark-readonly"
credential = "node_a"
site_domain = "opsark-lab.invalid"
container_name = "opsark-lab-api"

[[hosts]]
id = "node-b"
name = "测试目标 B"
address = "192.0.2.20"
username = "opsark-readonly"
credential = "node_b"
site_domain = "opsark-lab.invalid"
container_name = "opsark-lab-api"
```

示例地址是文档保留地址，必须由管理员替换为实际授权目标；目标 ID、可选站点检查、容器和日志范围同样按实际登记。不要将未授权的共享服务加入清单。

## 部署前提

每台目标应已经安装并验收[受限采集入口](../readonly/README.md)。持续观察还需要 root 所有的安全日志读取 helper `/usr/local/libexec/opsark-security-read`，以及包含其固定安全采集命令的服务器端策略。升级读取组件后先重新导出、审核和部署确切策略，再启用观察；不能通过放开任意 Shell 或 Docker 权限来绕过策略失败。

日志读取缺失、权限不足、时间窗不完整或连接失败都会作为观察缺口/告警保留。容器健康检查只确认本机 API 进程响应；它不证明目标采集正常，也不证明服务器安全。使用认证后的“持续安全观察”状态和最近采集时间核对每台目标。

## 启动与隔离边界

在部署目录使用显式目标 ID：

```console
OPSARK_OBSERVE_HOSTS=node-a,node-b OPSARK_OBSERVE_INTERVAL=60 \
  docker compose --project-name opsark-observer up --build -d
```

服务名为 `observer`，容器名固定为 `opsark-observer`，带 `io.opsark.observer=v1` 标签。管理员须先核对同名对象是否属于本部署，不接管或替换无关容器。

控制端 API 只发布到 VPS 自身 `127.0.0.1:18010`。容器只读根文件系统、64 MiB `/tmp`、无额外 Linux 能力、禁止提权，不挂载 Docker socket，不使用特权模式；限制 384 MiB 内存、0.5 CPU、128 PID，日志最多 5 MiB × 2。重启策略为 `unless-stopped`：Docker 正常运行且未被管理员显式停止时可随其重启恢复；这不能替代 Docker/宿主机可用性监控。

兼容模型接口需部署端同时配置提供方 URL、模型名和一种凭据引用；后台观察器本身不会调用模型。人工分析需逐次确认，0.12 自动 AI 另需显式部署许可和独立预算。观察与告警保持只读，控制台已阅仅更新阅读状态，不等于事件已解决。

## 可选漏洞观察与补丁入口

使用独立于只读采集的 repair keys 和部署端 `patch-targets.json`，通过 `OPSARK_PATCH_INVENTORY=/run/opsark/patch-targets.json` 登记；可选 `OPSARK_AUTOMATION_POLICY=/run/opsark/automation-policy.json` 明确动作和包范围。两文件与私钥均留在只读 secrets 挂载，不接受浏览器临时上传命令、地址或私钥。

定期扫描默认关闭。设置 `OPSARK_VULNERABILITY_SCAN_ENABLED=true`、`OPSARK_VULNERABILITY_SCAN_HOSTS=node-a,node-b`、`OPSARK_VULNERABILITY_SCAN_INTERVAL=3600` 后，只对已登记目标执行串行只读扫描，完全失败 300 秒后重试。保留 partial/unavailable 和未知计数，详见[观察合同](../../docs/VULNERABILITY_WATCH.md)。

人工批准使用半自动通道；0.9 的自动后台还需明确的控制端和 root grant，并核对 UTC 窗口、期限、次数、证据和暂停状态。驱动、目标或策略范围变化会重置手动，模式同步完成后才可进入相应执行通道。Root 安装任务独立持久运行，控制端轮询原任务而不重发安装，详见[执行入口](../vulnerability/README.md)和[自动修复记录](../../docs/AUTOMATIC_REPAIR.md)。

若明确使用本机私网内的验收 guest，可附加 `-f compose.lab.yaml`；它要求已存在且核验归属的 `opsark-patch-lab` 外部网络。默认网络保持更高网关优先级，guest 主机密钥使用独立文件。普通部署不需要此 override，也不要把某台 PC 的 loopback 转发地址复制到服务器清单。

本轮 0.9 常驻实例另外保存部署端 `compose.release.yaml`，其 `observer.image` 指向已经构建并审核的发布镜像。重建该实例必须依次加载三份文件，保留部署端既有环境及 secrets 引用：

```console
docker compose --project-name opsark-observer \
  -f compose.yaml -f compose.lab.yaml -f compose.release.yaml \
  up -d --no-build --force-recreate observer
```

`compose.release.yaml` 是该部署的镜像 override，不包含在仓库的通用配置中；沿用已审核的文件和镜像，不用其他构建结果替换。只加载基础文件会遗漏 guest 私网，只加载前两份会遗漏本轮镜像选择。本轮已经按上述三文件方式完成控制端重建：任务、通知、配额和真实安装次数保留，guest 没有重启，收尾已同步切回手动。后续更新镜像须重新审核并更新该 override。

## 可选 OpenAI 兼容漏洞分析（0.11）

0.11 的新增内容在控制端完成：重建脱敏输入、请求模型分析、校验候选选择和保存来源关联，再请求现有 Root 入口生成新方案。它不升级目标的 Root 权限、不改包/动作允许名单、不签发 grant、不清暂停，也不启用自动模式。更新控制端时保留当前清单、模式、Root 策略绑定及所有未决身份；不能把模型配置当成执行授权。

此处是通用配置与操作约定；已有人工模型分析的实际记录见[漏洞 AI 说明](../../docs/VULNERABILITY_AI.md)。0.12 自动 AI、安装及持续观察衔接在两台测试服务器上待实际验收，协议替身与合成测试须单独标明。

推荐将提供方密钥保存在部署端 `secrets/provider-api-key`，仅包含单行凭据，由 UID 10001 所有、权限 0400，目录按前文只读挂载。通过部署端编辑器或秘密管理工具写入，不把实际密钥放在聊天、命令行、URL、Git 或构建上下文中。示例环境只含非秘密配置和容器内文件引用：

```dotenv
OPSARK_AI_PROVIDER=openai
OPSARK_AI_BASE_URL=https://provider.example.invalid/v1
OPSARK_AI_MODEL=your-model-id
OPSARK_AI_KEY_FILE=/run/opsark/provider-api-key
OPSARK_AI_RESPONSE_FORMAT=json_object
OPSARK_AI_TOKEN_LIMIT_PARAMETER=max_tokens
OPSARK_AI_MAX_OUTPUT_TOKENS=2048
OPSARK_AI_THINKING_MODE=provider_default
```

以上 URL 和模型名是占位值。`openai` 兼容模式将 `/chat/completions` 追加到配置的前缀。地址不包含认证信息、查询参数、百分号编码或片段。远程地址使用 HTTPS。容器中的 loopback 指向容器自身。

Claude 原生模式选择 `OPSARK_AI_PROVIDER=anthropic`、固定 `OPSARK_AI_BASE_URL=https://api.anthropic.com/v1`，同时设置 `json_prompt`、`max_tokens` 和 `provider_default`，并使用 Claude 提供方的模型名和独立密钥。原生和兼容接口均在格式转换前执行相同的摘要白名单检查。[Claude 接口参考](https://platform.claude.com/docs/en/api/messages/create?version=2023-06-01)

环境中的 `OPSARK_AI_KEY` 仍可兼容，但它与 `OPSARK_AI_KEY_FILE` 只能选择一种；改用文件时须移除旧环境密钥值。URL、模型名和一种凭据引用应同时配置。文件不存在、不可读、权限/类型不合格或读取中变化时，本次模型调用视为未就绪，不输出文件路径或内容；普通扫描、已存在的补丁任务和观察数据仍保留。文件内容按请求读取，轮换密钥不需要通过模型接口提交；更改地址、模型或环境选项则按既有发布流程重建控制端。

| 配置项 | 约定 |
| --- | --- |
| `OPSARK_AI_RESPONSE_FORMAT` | `json_object` 默认；提供方支持时可选 `json_schema`；显式选择 `json_prompt` 时只通过提示要求 JSON，不发送 `response_format` |
| `OPSARK_AI_TOKEN_LIMIT_PARAMETER` | 兼容默认 `max_tokens`；选择的模型需要时显式改为 `max_completion_tokens` |
| `OPSARK_AI_MAX_OUTPUT_TOKENS` | 默认 2048，可配置 256–8192；服务器还限制返回字节数、总调用期限及结构化字段 |
| `OPSARK_AI_THINKING_MODE` | 默认 `provider_default` 不发送额外参数；提供方确认支持时可显式设为 `enabled` 或 `disabled`，发送 `thinking.type`，不会自动切换 |

部分 OpenAI 推理模型需要 `max_completion_tokens`，而兼容服务对参数和格式的支持各不相同，应按实际模型配置。[Chat Completions 参考](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)与[结构化输出说明](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat)介绍这些选项。无论选何格式，都执行本地结构、证据引用和候选校验；提供方拒绝格式时不会自动切模式重试或再次计费发送。

更新部署目录的 Compose 环境和秘密文件后，沿用三份 Compose override 及 `--env-file` 配置启动。用已认证的 `GET /api/ai/status` 检查 `configured/provider_kind/provider_host/model_name/response_format/missing/provider_fingerprint`。这是本地配置状态，GET 不访问提供方、不验证余额或远端授权。密钥、文件路径和完整 Base URL 不从 API 返回，敏感值误填模型字段时也不能作为正常模型名回显。

实际分析须在控制台读取当前真实扫描、核对将发送的摘要，再明确发送。分析 ID、未知回执与历史绑定持久保存；超时后只查原记录，不能用自动重试证明没有计费。AI 只选择服务器生成的候选；生成 Root 方案及后续人工批准仍使用当前模式和 Root 原生摘要，见[接口合同](../../docs/API_CONTRACT.md#011-漏洞-ai-分析与-root-方案衔接)。

## 可选自动 AI 审查与持续复扫（0.12）

自动模型外发默认禁用。`ControlPolicy.automatic_ai` 缺省为 `null`，省略时保持原模式作用域和既有确定性自动流程。以下仅为合并进 `OPSARK_AUTOMATION_POLICY` 所指控制端 JSON 的禁用片段，不签发执行 grant：

```json
{
  "automatic_ai": {
    "enabled": false,
    "provider_fingerprint": null,
    "max_analyses_per_day": 1,
    "max_total_analyses": 1
  }
}
```

需要启用时，管理员先通过已认证的 `GET /api/ai/status` 取得配置就绪的 `provider_fingerprint`，再明确绑定该摘要和分析预算，修改部署策略并按原流程同步模式。两个次数上限均为 1–5 的整数。提供方配置、自动 AI 许可和当前 automatic 模式都不能替代既有控制端/root 双侧执行授权；Root9 helper 与 root grant 不增加 AI 字段、目标、动作或包权限。关闭 AI 许可也不会撤销已有确定性自动 grant，停止执行须按原模式及执行策略操作。

启用后，后台先持久登记原分析身份和独立次数，再最多外发一次脱敏证据；模型必须选择当前已核实候选，原生计划和安装继续独立验权。相同目标、finding、包版本及提供方的失败/未知候选，不因新扫描、换 grant 或 Root 策略变更自动付费重发。模型预算按目标分别统计，每日跨 grant、总量按当前 grant 累计，失败不退回次数。模型失败、未知或没有可用提案时停止本候选，不绕过 AI 提交。

控制台只展示当前许可、原分析与持久告警；`GET /api/automatic/status` 的 `ai` 含 `policy/requests/alerts/quotas/last_error`。`GET /api/automatic/ai/alerts` 读取告警；`POST /api/automatic/ai/alerts/{64hex}/ack` 只记录已阅，不分析、不安装、不重试、不恢复暂停。通知渠道仍是持久控制台事件，没有向外部人员发送消息。读取状态、原分析、计划、原任务和模式本身不调用模型。

带 AI 来源的原自动任务 verified 后，后台按原 job 持久去重登记只读复扫。只有显式启用且登记在漏洞观察目标内才会准入；沿原扫描租约执行真实新读取并 ingest，更新观察告警，不等固定一小时间隔。正在扫描后的迟到事件留给下一次新扫描，失败保留并按最多 300 秒退避，重启不丢身份。partial、未知计数与缺口仍保留，已阅和 verified 都不能证明整机安全。

两台测试服务器的新增自动链路待实际验收。完整配置、绑定、存储容量、15 项队列测试及三浏览器合成验证边界见[自动 AI 说明](../../docs/AUTOMATIC_AI.md)。

## 原来源归档与只读下载（0.13）

新版在现有 `vulnerability-ai.sqlite3` 中保存分析外发前的完整结构化扫描、原候选/输入、HostPublic、控制端策略、精确原资格判定时刻及无 key 的提供方六字段。它不是日志归档，不包含 stdout/stderr、私钥、控制台令牌或模型推理正文。手动分析同事务保存原身份及来源；自动流程先保留来源，再预留独立模型次数。来源不可覆写，独立 `source_digest_pin` 和必需标记防局部降级；不抵抗管理员整体改写数据库。

原身份仍限 1000；新源最多 128 份，单 scan 1 MiB、单 source 2 MiB、来源合计 64 MiB。AI 审计逻辑总预算 128 MiB，每份来源终身预留单分析上限 256 KiB，已完成或暂未接分析的来源也保留预留。到上限时停止新增，不删除旧身份重新计费；物理数据库及 WAL 仍需正常容量管理。

认证 `GET /api/vulnerability-ai/analyses/{host}/{analysis_id}/evidence` 只读取本地原快照与原身份关联，返回最多 4 MiB 的 JSON 附件，不读取当前提供方或凭据，不调用模型或目标。依赖变化时有限次双读，仍不一致或超限返回 409；这不是跨数据库全局原子快照。旧版本未留存的来源保持 `not_retained`，不能用当前扫描补历史，下载和离线结果会明确缺件。

控制台仅在新 `vulnerability_evidence` 能力存在时展示“导出证据包（含主机清单）”；损坏来源禁用，历史缺源可导出。附件包括主机清单、策略和完整提供方地址，按运维数据权限保存。仓库内先 `uv sync --locked`，再执行：

```console
uv run python tools/verify_evidence.py evidence.json
```

将 `evidence.json` 替换成实际下载文件名。该入口仅核验本地普通 JSON，不扫描、联网或执行包内代码。退出 0 表示内部一致，退出 2 的报告区分缺件 `incomplete` 与不一致 `invalid`。Root 原始 transaction/`.deb` 未缓存时不重造；SHA256 不是发行人签名或可信服务器认证，不能凭 valid 批准安装。

旧十库迁移无需增加数据库文件；AI 库初始化会新增来源表和 nullable pin 列。保留新表、原请求、预算与失败身份，提供方密钥仍分开私下备份；升级不复活旧失败或重新付费。0.13 新归档与下载的两台服务器实机验收待完成，当前软件与三浏览器验证见[完整说明](../../docs/VULNERABILITY_EVIDENCE.md)。

## 从本机访问

使用独立的管理员 SSH 通道做本地隧道，示例：

```console
ssh -N -L 127.0.0.1:8010:127.0.0.1:18010 administrator@192.0.2.10
```

按实际管理员账号、已核验主机记录和密钥引用连接，不把密钥内容放进命令或 URL。`opsark-readonly` 密钥禁止转发，不能用它建立此隧道。本机 8010 已占用时选择另一本地端口，打开对应 `http://127.0.0.1:端口/` 后使用部署实例令牌认证。隧道关闭只影响访问，VPS 上的观察进程继续运行。

首次启动在 `data/access-token` 生成令牌；管理员通过受控本机/部署终端读取，令牌不写 URL、浏览器持久存储或 Git。不要把控制台直接映射到公网来替代认证、TLS 和访问边界验收。

## 迁移与停止

先用无采集、无修复入口的候选验证版本、权限和数据，再冻结全部原写入者取最终快照。`store_transfer.py` 为固定白名单数据库使用 SQLite backup，生成文件 SHA、表行数/行摘要及安全记录清单；报告/基线按 ID 合并，冲突拒绝覆盖。它不处理令牌、env 或任何密钥，这些另行私下复制且不输出。

0.11 的备份白名单包含十个数据库：`reports.sqlite3`、`baselines.sqlite3`、`security.sqlite3`、`web-security.sqlite3`、`security-ai.sqlite3`、`patches.sqlite3`、`automation.sqlite3`、`vulnerability-watch.sqlite3`、`automatic.sqlite3` 和新增的 `vulnerability-ai.sqlite3`。旧部署尚未生成某库时，不据此伪造空历史；启用新版后须完整保留新库。

`automatic.sqlite3` 包含自动提交意图、用量、目标暂停、人工恢复审计，以及 0.12 自动模型请求身份/独立预算/告警；`vulnerability-ai.sqlite3` 保存固定模型请求身份、未知回执、输入与分析摘要、候选及 Root 方案来源关联；`vulnerability-watch.sqlite3` 还保存按原 job 去重的持久复扫队列及结果观察引用。这些记录不能从备份/恢复中省略，不能靠删库重新收费、补回次数或解除暂停。任务、通知去重等记录与其余数据库一并保留。远端 root 的任务、批准、安全暂停和恢复回执另外保留，控制端数据库不能替代它们；提供方密钥及环境配置也另行私下备份。

数据库之间没有全局事务，最终迁移期间保持全部写入停止。不要只复制活动 SQLite 主文件而遗漏 WAL。仅在带完整传输 manifest 的目标副本清旧 monitor lease，保留游标、去重、通知、未决提交等全部证据；manifest 留在迁移审计目录，不作为活动 data 的清理标记。

`clear-leases` 写入前会重新校验传输清单、文件集合、摘要和 SQLite 记录。有效的旧版部分备份和合并副本仍可处理。清单失配、WAL 或意外文件会拒绝，先核对来源并重新生成副本。

管理员可以用 `store_transfer.py verify` 核对完整十库快照，再用 `store_transfer.py rehearse` 准备独立恢复副本。离线核验和断网启动的验收步骤见[私有发布候选与恢复演练](../../docs/RELEASE_CHECK.md)。

本轮 0.8 的来源矩阵、单活动实例切换和实际持久化结果见[常驻迁移验收](../../docs/PERSISTENT_CONTROL.md)。回退必须保留新实例已经写入的数据，不能静默换回旧副本或让旧代码直接打开新版本数据库。

停止时由管理员对本项目执行 `docker compose --project-name opsark-observer stop`；它不修改被观察服务器的业务、防护或 SSH 配置。删除数据、轮换密钥和撤销目标授权分别按实际范围操作，不通过清理其他项目或共享服务实现停止。
