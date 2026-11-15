# 单次防护会话：隔离接入清单

本清单面向当前 0.19 私有开发候选的控制端入口，供维护者连接**已经单独核验的私有实验目标**。功能默认关闭。当前 Root v1 固定保护 `198.18.241.2:22422` 的 IPv4 SSH 新连接，来源仅为 `fixture-a` / `fixture-b`，管理来源为 `198.18.241.4`，协议监听端口为 `22423`。它不接受任意地址、Shell、端口或 TTL。

两台 Ubuntu/Debian 测试机上已验证的完整入口是受限实验编排与正式控制端的组合，见[实机验收记录](../tests/defense_session_lab/README.md)。仓库没有面向任意 Ubuntu/Debian 主机的通用 Root 安装器；下面的控制端配置不会创建远端账户、sudo 策略、Root 账本、私有网络或中继。尚未准备好目标时，应停在目标部署与信任核验阶段，不能把公网服务器填进清单试运行。

## 1. 先确认适用范围

- 使用新建的独立控制端数据目录和有明确生命周期的实验环境。不要套用到常驻实例、现有生产登记或现有授权。
- 管理员已在目标本地核验固定 Root v1、OpenSSH、nftables、网络命名空间、受保护监听器和证据日志；远程身份均为固定 forced-command，禁止任意命令、转发和远程初始化。
- 控制端已有获准的隔离传输路径。下面直接地址示例要求连接从已核验的管理来源到达私网目标；示例不会建立这条路径。实机验收使用的固定 loopback 中继只属于实验适配器，不能据此开放宿主端口或通用代理。
- 已从同一个目标取得并在本地核验其公开交接值：Root scope、固定 policy digest、boot、listener binding、观察许可引用、控制端许可引用、Root 执行许可引用及 UTC 起止时间。不要凭空生成这些字段来匹配控制端。
- 初始实验授权为 `auto`、wire revision `2`、Root `max_uses=1`；控制端每日与总执行上限均为 `1`。Root 的首次 arm 是一次性许可，不能通过换 RID、清空账本、重新初始化、还原旧备份或重启来续权。
- 三个防护角色的账号、公钥身份和私钥文件均独立，并与普通采集、业务复验和补丁身份分离。测试归档和 `data/` 中的实验密钥不得作为新的部署凭据。

原单次会话实验只证明**同一容器内控制端/CLI 进程重启后的原任务查询**。后续另在两台新环境通过了[22423 协议传输重启后的原任务查询](../tests/defense_transport_lab/README.md)，该结果不等于被保护服务重启、容器重建、宿主重启或账本恢复后可以继续执行。[后续协议边界](SSH_DEFENSE_WORKER_PLAN.md)仍适用。

## 2. 准备控制端文件

以下统一以新的 `/srv/opsark-session-lab` 为例。目录只让运行控制端的专用账号及管理员访问，配置和私钥使用 `0600`；所有路径为真实绝对路径，不使用符号链接、硬链接或共享可写文件。密钥正文由本地凭据管理流程部署，不放入 Git、聊天、网页表单或本文示例。

准备四组独立身份文件：一组已有只读采集身份，另三组为防护 `readonly`、`observe`、`control`。防护角色端口由程序固定为 `22423`，不是 JSON 中的自由参数。

| 文件 | 内容及来源 |
| --- | --- |
| `inventory.toml` | 已登记的普通只读主机与独立采集凭据引用 |
| `defense-inventory.json` | 同一主机 ID、三角色凭据引用、公开 Root 绑定 |
| `defense-policy.json` | 独立观察与执行授权；可选 AI 同意和费用上限 |
| `secrets/collector-key` | 本次独立实验的普通只读身份私钥 |
| `secrets/readonly-key`、`observe-key`、`control-key` | 本次独立实验的三个防护角色私钥 |
| `trust/collector-known-hosts` | 已在独立可信渠道核验的 `22422` 主机公钥 |
| `trust/defense-known-hosts` | 已在独立可信渠道核验的 `22423` 主机公钥 |

`known_hosts` 条目必须匹配实际登记地址和端口，例如防护监听器的条目主机部分为 `[198.18.241.2]:22423`。不能把普通 SSH 监听器的指纹当作防护监听器的信任，也不能仅凭一次未经核验的 `ssh-keyscan` 输出建立信任。`trusted_hosts_digest` 是整个相应 `known_hosts` 文件字节的 SHA256，不是 `ssh-keygen -l` 显示的公钥指纹；可在本机用 `sha256sum` 计算。文件变动后应重新核对登记，不自动接受新指纹。

`inventory.toml` 最小结构：

```toml
[credentials.lab_collector]
key_file = "/srv/opsark-session-lab/secrets/collector-key"
known_hosts_file = "/srv/opsark-session-lab/trust/collector-known-hosts"

[[hosts]]
id = "session-lab"
name = "隔离防护实验"
address = "198.18.241.2"
port = 22422
username = "opsark-readonly"
credential = "lab_collector"
site_domain = "business.opsark.invalid"
```

这只登记已有采集入口，不安装采集器，也没有登记业务复验。确需业务复验时，另按[正式只读采集部署](../deploy/readonly/README.md)登记经过确认的检查及其策略，不能用管理员探针代替产品复验。

`defense-inventory.json` 最小结构如下。所有 `<...>` 必须替换为同一目标的已核验交接值；引用不是可直接提交的占位授权。scope、policy、boot、binding 和文件摘要为 64 位小写十六进制值。

```json
{
  "schema_version": 1,
  "targets": {
    "session-lab": {
      "root_scope_sha256": "<ROOT_SCOPE_SHA256>",
      "root_policy_sha256": "<FIXED_POLICY_SHA256>",
      "boot_ref": "<ROOT_BOOT_REF>",
      "binding_ref": "<ROOT_BINDING_REF>",
      "roles": {
        "readonly": {
          "username": "opsark-defense-readonly",
          "key_file": "/srv/opsark-session-lab/secrets/readonly-key",
          "known_hosts_file": "/srv/opsark-session-lab/trust/defense-known-hosts",
          "trusted_hosts_digest": "<DEFENSE_KNOWN_HOSTS_FILE_SHA256>"
        },
        "observe": {
          "username": "opsark-defense-observe",
          "key_file": "/srv/opsark-session-lab/secrets/observe-key",
          "known_hosts_file": "/srv/opsark-session-lab/trust/defense-known-hosts",
          "trusted_hosts_digest": "<DEFENSE_KNOWN_HOSTS_FILE_SHA256>"
        },
        "control": {
          "username": "opsark-defense-control",
          "key_file": "/srv/opsark-session-lab/secrets/control-key",
          "known_hosts_file": "/srv/opsark-session-lab/trust/defense-known-hosts",
          "trusted_hosts_digest": "<DEFENSE_KNOWN_HOSTS_FILE_SHA256>"
        }
      }
    }
  }
}
```

三角色示例账号名必须已由目标管理员部署为相应固定角色。`readonly` 只允许 query；`observe` 允许 arm/query；`control` 允许固定协议操作。控制端不凭账号名授予 Root 权限。固定 policy digest 必须与当前 `opsark.defense_models.POLICY_SHA256` 和原目标交接一致，不是任意文件的摘要。

## 3. 配置两层授权

Root 本地授权与控制端策略须分别有效。下面的 `observation` 是控制端观察授权，其 ref 必须匹配 Root 观察许可；`execution.grant_ref` 与 Root 已登记的 `controller_grant_ref` 相同，`root_grant_refs` 则指向 Root 的独立执行许可。仅有一层许可、仅切换全自动模式或仅启用后台线程都不能执行。

下面示例只允许一个目标、一个固定来源别名和一次执行。时间使用同一交接中的真实 UTC `Z` 时间；控制端授权区间不得超过 24 小时，Root 实验许可可以更短。`windows` 仍参与检查，示例全天 UTC 窗口不延长 `expires_at` 或 Root 许可。

```json
{
  "enabled": true,
  "observation": {
    "enabled": true,
    "grant_ref": "<OBSERVATION_GRANT_REF>",
    "issued_at": "<OBSERVATION_NOT_BEFORE_UTC_Z>",
    "expires_at": "<OBSERVATION_DEADLINE_UTC_Z>",
    "host_ids": ["session-lab"],
    "target_scope_sha256": {"session-lab": "<ROOT_SCOPE_SHA256>"},
    "target_policy_sha256": {"session-lab": "<FIXED_POLICY_SHA256>"},
    "windows": [{"weekdays": [0, 1, 2, 3, 4, 5, 6], "start_minute": 0, "end_minute": 1440}]
  },
  "execution": {
    "enabled": true,
    "grant_ref": "<CONTROLLER_GRANT_REF>",
    "issued_at": "<EXECUTION_NOT_BEFORE_UTC_Z>",
    "expires_at": "<EXECUTION_DEADLINE_UTC_Z>",
    "host_ids": ["session-lab"],
    "target_scope_sha256": {"session-lab": "<ROOT_SCOPE_SHA256>"},
    "target_policy_sha256": {"session-lab": "<FIXED_POLICY_SHA256>"},
    "windows": [{"weekdays": [0, 1, 2, 3, 4, 5, 6], "start_minute": 0, "end_minute": 1440}],
    "root_grant_refs": {"session-lab": "<ROOT_GRANT_REF>"},
    "boot_refs": {"session-lab": "<ROOT_BOOT_REF>"},
    "binding_refs": {"session-lab": "<ROOT_BINDING_REF>"},
    "wire_revisions": [2],
    "source_aliases": ["fixture-a"],
    "max_actions_per_day": 1,
    "max_total_actions": 1
  },
  "ai": {"enabled": false, "requires_ai": false}
}
```

许可 ref 是管理员交接中的 32 位小写十六进制引用。这里不提供生成新 Root 许可、修改已有账本或初始化续权的命令。当前 v1 没有长期续发接口。

## 4. 从独立进程启用控制端

使用项目已安装的 Python 3.13 依赖环境。以下命令从仓库根目录启动一个**新的隔离控制端**，只监听 loopback；现有常驻实例不参与本流程。

```sh
export OPSARK_DATA_DIR=/srv/opsark-session-lab/data
export OPSARK_INVENTORY=/srv/opsark-session-lab/inventory.toml
export OPSARK_DEFENSE_INVENTORY=/srv/opsark-session-lab/defense-inventory.json
export OPSARK_DEFENSE_POLICY=/srv/opsark-session-lab/defense-policy.json
export OPSARK_DEFENSE_SESSION_ENABLED=true
export OPSARK_DEFENSE_WORKER_ENABLED=false
export OPSARK_DEFENSE_TASK_WATCH_ENABLED=false
export OPSARK_OBSERVE_ENABLED=false
export OPSARK_WEB_OBSERVE_ENABLED=false
export OPSARK_VULNERABILITY_SCAN_ENABLED=false
python -m uvicorn opsark.main:app --app-dir src --host 127.0.0.1 --port 8011 --workers 1
```

使用专用的干净进程环境，避免继承已有的补丁登记、自动化策略或模型凭据。规则路径不配置任何 `OPSARK_AI_*` 连接或凭据项。首次启动在本例独立数据目录创建访问令牌；由操作者在本机读取并登录，不把令牌放入 URL、命令参数或聊天。配置读取会由本地 SSH 库核验专用密钥身份，私钥正文只用于本地认证，不进入模型输入或安全摘要。

**固定 `compose.yaml` 不透传 `OPSARK_DEFENSE_SESSION_ENABLED`、防护登记、策略及 `OPSARK_AI_KEY_FILE`。在 `.env` 填这些值不会自动启用容器中的会话。** 本清单不修改 Compose、不增加挂载，也不扩大已有容器权限；直接进程配置与固定 Compose 部署是不同入口。网页也不能开启部署开关。`OPSARK_DEFENSE_WORKER_ENABLED=true` 仍不支持持续执行，不能拿它代替单次会话开关。

登录后只读取部署状态：`GET /api/ssh-defense/sessions/status` 应为 `enabled:true`、`running:true`、`continuous_execution:false`、`owned_sessions:0`；`GET /api/ssh-defense/status` 应有唯一已登记目标。没有启动会话时不应出现 prepare/apply 或模型调用。状态读取不是新许可。

## 5. 可选：要求真实 AI 分析

先停在未 arm、未启动会话的阶段配置 AI。当前完整实机会话验收覆盖 OpenAI 兼容 `/chat/completions` 接口；配置层还支持 Anthropic 原生接口，但本清单不把它列为本轮单次会话已验证的提供方。服务地址和模型名称由部署者核验，不从网页请求、日志或模型回答中接收。

OpenAI 兼容方式使用独立文件引用：

```sh
export OPSARK_AI_PROVIDER=openai
export OPSARK_AI_BASE_URL='https://<已核验的兼容服务主机>/v1'
export OPSARK_AI_MODEL='<该服务支持的模型名>'
export OPSARK_AI_KEY_FILE=/srv/opsark-session-lab/secrets/model-api-key
export OPSARK_AI_RESPONSE_FORMAT=json_object
export OPSARK_AI_TOKEN_LIMIT_PARAMETER=max_tokens
export OPSARK_AI_MAX_OUTPUT_TOKENS=512
export OPSARK_AI_THINKING_MODE=disabled
```

不要同时配置 `OPSARK_AI_KEY`。Key 文件由凭据管理流程写入原始 Key，使用 `0600`、受控所有权和单一硬链接，不加引号或 `Bearer` 前缀。远程地址必须使用 HTTPS，地址不能包含账号、密码、query 或 fragment；本地 HTTP 只允许 loopback。服务必须支持所选输出格式、令牌字段和 thinking 参数；兼容声明不能代替实际验收。

提供方 fingerprint 绑定地址、模型、输出格式、令牌字段、令牌上限及 thinking 模式，不包含 Key。可以在上述独立环境中，仅打印这个非秘密配置摘要：

```sh
PYTHONPATH=src python -c 'from opsark.config import load_settings; from opsark.ai_provider import provider_fingerprint; print(provider_fingerprint(load_settings()))'
```

该命令不调用模型、不读取 Key 正文，但 `load_settings()` 会准备本例独立数据目录及控制台令牌。将 fingerprint 填入同一 `defense-policy.json` 的 `ai` 字段：

```json
{
  "enabled": true,
  "requires_ai": true,
  "provider_fingerprint": "<PROVIDER_FINGERPRINT_SHA256>",
  "max_analyses_per_day": 1,
  "max_total_analyses": 1
}
```

重新启动本例隔离控制端后，认证读取 `/api/ai/status`，确认 `configured:true` 和相同 fingerprint，再核对防护状态要求 AI。配置或指纹改变应先停止；不能在已经绑定的会话中换模型、换费用身份或降级为规则路径。策略不要求 AI 的规则路径不会调用模型；要求 AI 的路径在不可用、拒绝或结果未知时停止，不重发已计费调用。

模型正文只允许固定分类、临时候选/证据别名、失败端口计数和固定 TTL。源 IP、账户、Root 绑定、私钥、令牌、配置文件、原始认证日志和数据库原文不得进入 prompt。完整来源先过防泄密门禁；敏感、未知或不符合白名单的内容整次拒绝，不能“编码成乱码后发送”。SSH 私钥保留本地；模型 API Key 仅用于授权服务的认证头，不进入 prompt、回执和摘要，这不等于认证 Key 从不发送给其所属服务。

## 6. 按顺序运行一次

1. 确认两侧 UTC、原许可剩余时间、账号、公钥信任和公开绑定一致。先把全局模式从新实例的初始手动切到全自动，并等待全部模式参与方同步成功、Root 完整 ACK。全新实例此时控制端 revision 为 `1`，wire revision 为 `2`。版本不符就停止，不通过来回切模式或重置数据库凑版本。
2. 在安全观察页明确确认一次“建立观察窗口”。保留其原 cursor RID，确认 arm 被接受。后台不会替用户 arm；有执行许可也不意味着可以省略这步。
3. 对该原观察启动“这一次防护会话”并确认。保留原 host、cursor、稳定 session_ref；仅提交一次启动。等待后续观察、可选 AI、准备和执行由正式后台推进，不再手动调用 prepare/apply 来帮助验收。
4. 来源必须在同一原窗口内达到固定证据要求。候选未到达会等待；另一候选、证据改变、权限失效、配额不足或预算不足会停止。会话不能选择公网目标或更改 TTL。
5. 正常 ACK 的会话可达到 `completed`；丢 ACK 或结果不确定时保留 `reconciliation_only` 与原费用/意图，只查询原 action RID。查询确认 active 或自然到期不会把未知会话重新升格为 completed。
6. 导出摘要并核对业务状态仍为“待验收”。会话 completed、Root active、自然到期都不是网站或业务恢复证明。后续业务复验必须单独使用原任务和执行前登记的只读检查；本例未登记检查时不应标通过。

| 预算 | 固定边界 |
| --- | --- |
| 原 arm 观察窗 | 控制端原创建/截止时间，最多 120 秒；Root 独立核时 |
| 单个动作 TTL | 60 秒，不续期 |
| 单次 AI | 最多 20 秒，并受原证据剩余 30 秒鲜度与 5 秒余量限制 |
| 会话内单次 SSH RPC | 最多 10 秒；不代表超时后远端已停止 |
| 执行前剩余预算 | AI 前至少 55 秒、准备前至少 35 秒、apply 前至少 15 秒；额外刷新另占查询预算 |

后台每 5 秒检查本进程明确启动的会话，阶段推进每周期最多 8 步；没有变化就等待。只读刷新只能查询原 cursor，全部候选及证据须与原选择相同，随后仍须通过普通 30 秒门禁。刷新不改原 AI 输入、permit、proof、费用、额度或原窗口。晚到候选可能来不及完成，这是停止条件，不是续权理由。

## 7. 停止、未知和重启

- 当前 boot 可精确停止原会话；停止先持久化门禁，再等待线程退出。不等待模型或 SSH 回应才阻止后续阶段。
- 停止会话、切手动或停用部署开关都不能撤回已在途的外部操作，也不保证删除已经生效的规则。人工撤销有独立授权、原清单和精确确认；本流程不自动 revoke。
- 启动回应丢失时只 GET 原 host/session_ref。prepare/apply 可能已发送或回执未知时，只查询原 RID，不能换 ref/RID、重复点击或另起会话重试。
- 控制端重启后原记录、费用和摘要保留。新 owner 没有旧发送权；旧 owner 换到新 lease epoch 也不能接续。界面允许读历史与只读对账，不应把旧会话显示为可以重新执行或停止。
- Root binding、日志身份、监听器或账本变化时保留未知并停止。当前没有用重建容器、恢复备份或重新初始化来继续原许可的流程。

验收至少分别保留规则 ACK、真实模型 ACK、真实 SSH 丢 ACK的独立记录，并证明同一场景只有一次 apply、重启后不重放/重收费、业务未复验仍待验收。每次实验还需单独核对原有资源状态并清理本次拥有的资源。配置示例可被当前控制端加载，不等于某台新服务器已经完成这些验收；[完整会话合同](DEFENSE_SINGLE_SESSION.md)与[协议限制](SSH_DEFENSE_WORKER_PLAN.md)优先于“全自动”名称带来的推断。
