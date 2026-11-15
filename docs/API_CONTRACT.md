# OpsArk 调查与受控修复接口约定

调查接口保持只读。Ubuntu 单包补丁任务需部署端授权：人工批准通道使用半自动的具体方案确认，0.9 自动后台另受独立预授权约束；不开放任意配置写入、封禁、限流或主机重启。

0.5 增加需认证的 `/api/security/status`、`/api/security/alerts`、单条告警与观察记录，以及显式已阅接口。后台采集范围由部署配置指定，API 不接受临时主机或远端命令；已阅不是风险解除。完整字段与保留边界见[持续观察接口说明](SECURITY_OBSERVATION.md)。

0.6 合并 SSH/Web 告警并增加分类证据及可选模型建议，见 [Web 说明](WEB_SECURITY_OBSERVATION.md)。0.6.1 先交付模式选择；0.7 将模式修订号同步至已登记修复入口，半自动安装需单独批准。隔离 guest 的半自动及 0.9 自动正向验收已通过；各类故障和恢复对照仍按实际记录分别列明，接口存在不等于验收完成。

应用使用 FastAPI、SQLite、Pydantic 和 Paramiko。前端采用独立的 HTML、CSS 和 JavaScript，由同一服务提供，不依赖前端构建工具。原 `prototype/` 保留为离线设计样例。

`POST /api/hosts/{host_id}/nginx-path-observation` 需要认证，正文只接受 `{}`。该入口沿用登记的只读业务检查。返回 `host_id`、`binding_digest`、UTC `observed_at`、`status` 和 `checks`。`checks` 与 `business-readiness` 使用同一结果格式，仅提供编号、结果状态、HTTP 状态码及匹配布尔值。主机列表的 `nginx_path_observation_binding_digest` 绑定 Nginx 登记范围、SSH 身份和业务检查配置。未登记主机返回 404，缺少相应登记或只读任务占用时返回 409。磁盘依赖观察继续使用自己的接口与证据时间。 [登记路径响应](NGINX_DEPENDENCIES.md#登记路径响应)

0.8 新增显式部署启用的定期漏洞观察、持久告警与只读状态。`GET /api/vulnerability-watch/status`、`/alerts`、`/alerts/{id}`、`/observations/{id}` 均需认证；`POST /api/vulnerability-watch/alerts/{id}/ack` 仅接受 `{acknowledge:true}`。列表只显示当前配置作用域，历史详情保留；已阅与单条复扫条件分开。字段、未知值及保留边界见[观察合同](VULNERABILITY_WATCH.md)。这些接口不会生成方案或提交修复。

0.9 新增 `capabilities.automatic_repair:true` 与受保护的 `GET /api/automatic/status`。自动后台使用现有扫描证据和部署端 grant，没有创建自动授权或提交自动任务的公开 API。0.10 新增 `capabilities.automatic_recovery:true` 与精确人工恢复接口；它依赖匹配的 root 执行器和完整原任务证据，不能作为任意清暂停的 reset。字段与操作边界见[自动修复合同](AUTOMATIC_REPAIR.md)和[人工恢复说明](RECOVERY.md)。

0.10.0 已完成常驻升级，原三目标处于已同步的 manual 修订 14，自动 grant 全部禁用；接口发布没有新增自动执行 grant 或扩大目标/软件包范围。带故障注入的真实路径使用独立实验目标，不能将其实验批准沿用到常驻目标，见[交付与实机记录](RECOVERY_LAB.md)。

0.11 增加 OpenAI 兼容的漏洞证据分析与受控候选选择接口。它将模型建议与确定性 Root 方案分开保存；模型不提交补丁、不修改 grant、不解除暂停。接口实现、兼容协议替身测试与真实付费模型验收分别记录，接口存在不表示部署端已配置 URL、模型名或凭据。

0.12 增加默认禁用的自动 AI 候选审查及独立模型次数预算，能力字段为 `capabilities.automatic_ai:true`。启用后，后台必须取得当前有效 AI 候选证明再进入原生自动规划及提交；原双侧执行 grant 保持独立。持久告警、只读复扫和部署方式见[自动 AI 合同](AUTOMATIC_AI.md)。两台测试服务器的新增自动链路待实际验收。

## 请求与权限

`GET /api/status` 返回版本和 `requires_auth: true`。其余 `/api/` 路由要求 `Authorization: Bearer <控制台令牌>`。令牌由部署者设置或本机首次启动生成，界面仅在当前页面内存保存。API 不接受任意命令、私钥正文、凭据路径或未登记的远程目标。

| 接口 | 返回或请求 |
| --- | --- |
| `GET /api/capabilities` | 调查 `mode: read_only`、模型配置、`ssh_hosts`、站点/基线/平台能力，以及 `vulnerability_remediation:true`；实际执行可用性另查模式及修复状态 |
| `GET /api/ai/status` | 只读提供方配置状态：`configured/provider_host/model_name/response_format/token_limit_parameter/max_output_tokens/thinking_mode/missing/provider_fingerprint`；配置就绪时返回非秘密提供方摘要，否则摘要为 `null`；不探测网络、不调用模型，不返回密钥、密钥文件路径或完整 Base URL |
| `GET /api/hosts` | `HostPublic[]`；仅公开登记信息，不含凭据路径 |
| `GET /api/samples` | `[{id, title, scenario, host_id}]`，全部标明回放来源 |
| `POST /api/investigations` | `{source, scenario, sample_id?, host_id?}`；返回完整 `Report` |
| `GET /api/reports/{id}/change-records` | 原报告的维护者陈述、登记可写状态和已核实观测 |
| `POST /api/reports/{id}/change-records` | `{request_id, kind, claimed_at}`；按原报告追加一条结构化陈述 |
| `GET /api/reports/{id}/change-records/{record_id}/handoff` | 下载该条陈述的独立脱敏附件 |
| `GET /api/reports/{id}/access-rechecks` | SSH 失联报告的复验历史、是否可运行及最近同范围基线的证据时点 |
| `POST /api/reports/{id}/access-rechecks` | `{external:"matched"\|"unreachable"\|"unavailable"}`；人工机外观察默认为 `unavailable`，返回同一原报告的新复验快照 |
| `GET /api/reports/{id}/access-rechecks/{receipt_id}/handoff` | 下载选定历史复验的脱敏摘要 |
| `GET /api/reports/{id}/container-rechecks` | SSH 容器原调查的业务复验历史，返回报告编号、可运行状态和已保存结果 |
| `POST /api/reports/{id}/container-rechecks` | `{request_id}`，只运行原调查登记的只读业务检查，并保存同一原报告的复验 |
| `GET /api/reports/{id}/container-rechecks/{receipt_id}/handoff` | 下载选定容器业务复验的脱敏摘要 |
| `GET /api/reports` | 最近报告的列表，每项含 `id,title,host_id,host_name,scenario,source,created_at,status,summary` |
| `GET /api/reports/{id}` | 完整 `Report` |
| `GET /api/reports/{id}/export` | Markdown 下载，区分回放与 SSH 采集，保留未解决事项 |
| `POST /api/reports/{id}/baseline` | `{confirm_observation_only:true}`，保存报告中的可解释观测字段，返回 `BaselineInfo` |
| `GET /api/baselines` | 最近基线摘要，包含来源与基线报告引用，不包含原始日志 |
| `POST /api/reports/{id}/explain` | `{confirm_send:true}`；明确同意发送脱敏摘要；返回 `AIExplanation`，并持久化到报告 |
| `GET /api/automation` | 当前 `mode`、`revision`、授权范围、`execution_available`、`supported_execution_modes`、`mode_sync_complete`、同步错误及边界说明 |
| `PUT /api/automation` | `{mode:"manual"\|"assisted"\|"automatic",expected_revision:非负整数}`；保存并同步模式，请求内不提交安装；后台另行核对自动预授权条件。旧版本返回 409，同步未完成返回 503 |
| `GET /api/automatic/status` | 自动后台运行/模式修订号/同步状态、非秘密 grant、每目标窗口/期限/配额/持续暂停、原任务、最近自动记录、持久 `recoveries` 列表，以及 `ai` 许可/预算/原分析/告警；只读缓存，不外发模型、提交或解除暂停 |
| `GET /api/automatic/ai/alerts` | 最多 100 条持久自动 AI 控制台告警，未阅优先；读取不触发分析或安装 |
| `POST /api/automatic/ai/alerts/{id}/ack` | 64 位小写十六进制原告警 ID；无需请求体，幂等标记已阅并返回原告警；不重试、不生成计划、不安装、不清暂停 |
| `POST /api/automatic/recovery-plans` | `{host_id,job_id,expected_mode_revision}`；在当前已授权且同步的 manual 模式，核验暂停原任务并返回 root 不可变恢复预览；不解除暂停 |
| `POST /api/automatic/recoveries` | `{host_id,recovery_id,expected_recovery_digest,expected_mode_revision,confirm_recover:true}`；明确批准当前有效预览，先持久保存意图，最多发送一次 root 恢复请求 |
| `GET /api/automatic/recoveries` | 有界持久恢复记录列表，优先待核实意图；不发起新恢复或安装 |
| `GET /api/automatic/recoveries/{host_id}/{recovery_id}` | 读取原恢复记录；对未决意图只查询原 root 回执，可据既有明确批准完成本地对账，不重发恢复动作 |
| `GET /api/remediation` | 修复配置、登记目标及最近扫描、任务列表、当前执行能力和模式同步状态 |
| `POST /api/remediation/scans` | `{host_id}`；对既有登记目标只读扫描并缓存原始覆盖状态、缺口及发现 |
| `POST /api/remediation/plans` | `{host_id,finding_id}`；由 root 入口生成并保存具体计划，返回 `plan_id`、`plan_digest`、模式修订号、过期时间及完整变化/验证要求 |
| `POST /api/remediation/jobs` | `{host_id,plan_id,expected_plan_digest,expected_mode_revision,confirm_execute:true,job_id}`；严格批准当前半自动单包计划，返回独立任务 |
| `GET /api/remediation/jobs/{host_id}/{job_id}` | 通过新 SSH 连接读取原任务，更新验证及控制端缓存；不重新提交安装 |
| `GET /api/vulnerability-ai/hosts/{host_id}/preview` | 从当前登记目标的已有真实扫描重建脱敏模型输入、候选目录和 `input_digest`；不发模型请求，也不触发 SSH 扫描 |
| `POST /api/vulnerability-ai/analyses` | `{host_id,analysis_id,expected_input_digest,confirm_send:true}`；明确同意发送当前预览，先持久保存固定分析身份，再最多发送一次模型请求 |
| `GET /api/vulnerability-ai/analyses` | 有界持久分析记录列表；原提交意图和未知记录优先，不发模型请求 |
| `GET /api/vulnerability-ai/analyses/{host_id}/{analysis_id}` | 读取原分析身份与历史结果，并根据当前本地扫描、授权及提供方配置标明 `stale/applicable`；不重发模型请求 |
| `GET /api/vulnerability-ai/analyses/{host_id}/{analysis_id}/evidence` | 认证读取原身份的本地证据附件；不扫描、不读取当前提供方或密钥、不外发模型、不执行修复；最多 4 MiB |
| `POST /api/vulnerability-ai/plans` | `{host_id,analysis_id,proposal_id,expected_analysis_digest,expected_mode_revision}`；重新核实提案和原始证据后，请求 Root 生成新方案；不提交安装 |

错误统一使用 HTTP 状态码与 `detail` 文本。未知样例、报告或主机返回 404；输入不符合模型返回 422；报告解释未配置模型时返回 409。漏洞 AI 分析则可持久返回 `disabled` 记录，表示未外发，不是模型分析成功。调查进程繁忙返回 409，收集结果中的连接失败、权限不足与超时作为证据缺口记录，不伪装成健康。

修复提交的 `job_id` 为客户端生成并复用的 32 位小写十六进制标识，方案摘要为 64 位十六进制，批准标志必须为布尔 `true`。目标/动作/包或重启影响超授权返回 403；方案、模式、状态变化及远端拒绝返回 409；存储、同步或可信连接不可用返回 503。`POST .../jobs` 也可返回带任务对象的 202（原提交或结果未知），或带拒绝任务对象的 409；202 不证明成功，必须查询原任务，不能换 ID 重发。

SSH 失联复验适用于网站调查中只有 SSH 连接失败证据的报告。原报告创建时绑定登记的 SSH 身份与业务检查范围，历史报告仍可查看。复验使用一个有时间预算的固定 SSH 会话和现有业务检查。任一检查明确失败，或人工机外观察为无法访问，记录为 `failed`。仅当 SSH 认证成功、全部登记业务检查通过且人工机外观察符合预期，记录才为 `accepted`。其余结果为 `pending`。机外观察由维护者输入。服务端不接受机外 URL 或命令，不运行外部探测、不调用模型，不变更原调查和历史快照。

`capabilities.container_report_rechecks:true` 提供容器原调查业务复验。新建 SSH 容器调查时一并绑定登记主机、可信 SSH 指纹及业务检查配置。登记漂移或旧报告没有原始绑定时，`can_run` 为 `false`，历史仍可读。运行前和采集后都核对登记。一项明确失败即为 `failed`，SSH 认证成功且全部登记项都通过才记为 `passed`，其余为 `pending`。复验只证明登记检查在当时的结果。

复验记录包含 `id`（`rr-` 加 32 位小写十六进制）、原报告编号、结束时间、SSH 认证状态、按登记顺序排列的检查状态和整体结论。每报告最多保存 20 条，已保存的同一 `request_id` 返回原回执。请求正文只带 32 位小写十六进制的 `request_id`。历史和附件都省略目标地址、检查标识及正文。复验及导出不会调用模型、触发处置或改写原调查。

变更记录仅可追加到范围仍与登记目标相符的 SSH 原报告。正文的 `request_id` 为 32 位小写十六进制。回复丢失后，使用完全相同的正文和请求号可查回同一记录；同号不同内容、登记范围变化或达到每报告 20 条的上限返回 409。历史保留原记录，下载使用 `cr-` 开头的记录编号。

`kind` 使用 `nginx_configuration`、`compose_configuration`、`image_update`、`application_configuration`、`service_restart` 或 `unknown`。声明时间为 `{precision,value}`，分别接受 `unknown` 搭配 null、`date` 搭配日历日期、`instant` 搭配带时区的秒级时刻。明确时刻统一为 UTC，未来时刻返回 422。控制端记录时间由服务端生成。请求没有自由文本字段。

历史接口的 `observation` 独立来自原报告及其已绑定的观测基线。仅已核实变化的字段会给出 `from_at` 和 `to_at`。区间描述两次观测间的差异，不能给出具体执行时刻、操作者或部署来源。新记录沿用报告库，旧报告、业务验收和原有交接附件不随陈述更新。操作只使用控制端存储。

对已启用 Nginx 日志窗口的 SSH 网站调查，`Report.nginx_error_window` 在取得本次日志观测结果时提供状态、UTC 观测时间和固定的 900 秒窗口。状态为 `observed`、`permission_denied`、`source_missing` 或 `inconclusive`。仅 `observed` 提供两个非负计数，其余状态的计数字段为 null。SSH 失联等尚未运行此检查的报告可省略整个字段。此结果只覆盖固定日志文件中已识别的同站点上游错误，业务可用性由独立检查判断。 [部署说明](../deploy/readonly/README.md#nginx-错误日志窗口)

未配置启用的本地自动 grant 时，`supported_execution_modes` 仍仅含 `assisted`；具备相应执行配置与 grant 后可包含 `automatic`。这只是驱动能力，不代表当前窗口或某目标获准安装。人工 `POST .../jobs` 保持半自动守卫，自动后台走内部的计划/预授权核验通道。控制端先持久保存提交意图，再发一次远端请求；不确定结果保留 `unknown`，只查询原任务并持续暂停。模式部分同步失败会停止新提交；安装已进入 dpkg 后不会因模式切换强杀。

自动状态中的 `hosts[].quota` 以 `daily_limit/daily_used/total_limit/total_used` 表示，未知用 `null`，不视为零。`maintenance_open` 由后台计算；`latch` 和 `latched_hosts` 保留原因、原任务及时间，包含已移出当前清单的历史暂停。`jobs` 保存 grant/finding/计划/任务引用与阶段状态，控制台不凭这些字段自行设置 `verified`。自动状态读取失败返回受控错误，旧快照不能证明当前仍可执行。

## 0.10 精确人工恢复

恢复入口只处理暂停原自动任务已经 `verified` 的情况。它不安装补丁、不重启、不修改模式、grant 或每日/总配额。真正 failed、rejected、unknown、安装中或待验收的任务继续阻断；旧任务缺少安装前文件清单时，也不能通过补造证据恢复。

控制端每次都重新校验当前 `ControlPolicy`：`enabled=true`、`allowed_actions` 含 `os_security_upgrade`、目标仍在 `host_ids`，并要求 manual 及模式同步完成。root 独立核验自己的启用状态、当前模式、策略、源码与真实任务。`automatic_recovery:true` 仅表示控制端提供接口，不证明远端已经升级或当前目标允许恢复。禁用策略下可读已有审计，不能借旧回执解除本地暂停。

`POST /recovery-plans` 成功时返回**平铺的 root 预览**，不是本地恢复记录 wrapper，主要字段如下：

| 字段 | 含义 |
| --- | --- |
| `schema_version/status` | `1` / `recovery_prepared` |
| `host_id/policy_digest/driver_source_digest` | 明确目标、当前 root 策略和受信任源码绑定 |
| `recovery_id/recovery_digest` | root 分配的 32 位小写十六进制 ID 与 64 位摘要；确认及后续查询沿用，不由客户端换 ID |
| `job_id/job_revision/job_digest` | 当前暂停关联原任务及精确修订、内容摘要 |
| `mode_revision/context_digest` | 人工模式修订及该次本地暂停上下文绑定；旧批准不能覆盖新的暂停 |
| `created_at/expires_at` | 含时区的时间；有效期大于零且不超过五分钟 |
| `eligible/checks/blockers` | 是否符合条件、逐项 `{id,status,detail}` 与阻碍列表；检查状态为 `passed/failed/unavailable` |
| `verification` | 当前版本、软件来源/包状态、登记服务与 HTTP、运行时、同 finding 复扫和末尾状态核验 |
| `root_safety_before/root_safety_digest/state_digest/transport_challenge` | Root 当前暂停、包/归档状态及预览后新 SSH 验证的绑定 |

`eligible=false` 的有效预览可正常返回，供界面展示阻碍；它不能被批准。未知、运行中或目标/模式不匹配等情况也可能直接返回 409。Root 在确认时重做慢检查，在末尾重新核对实际包、账本、策略与暂停，并以统一最终决策时间判断有效期；预览通过不保证稍后的批准通过。

确认请求的 `expected_recovery_digest` 必须精确匹配这份预览，修订号必须仍有效，`confirm_recover` 只能为布尔 `true`。省略、`false`、数字或字符串不视为批准。恢复范围未授权返回 403，身份、模式、证据或状态冲突返回 409，参数不合约定返回 422，可信回执或存储不可用返回受控 503；持久批准后的网络不确定性以原恢复记录的 `unknown` 保留。接口调用成功不等于本地暂停已解除。

`POST /recoveries`、`GET /recoveries` 和详情返回持久本地记录，包含 `host_id/recovery_id/recovery_digest/job_id/job_revision/job_digest/scope_hash/policy_digest/mode_revision/context_digest`、时间、`detail`、完整 root `plan`、`latch_before`、`receipt` 及 `local_released`。批准后记录 `confirmed_at`；完成本地恢复后记录 `resolved_at`。其中 `mode_revision` 是原批准的修订，不代替当前模式接口。

| `status` | 接口语义 |
| --- | --- |
| `prepared` | 预览已保存，没有批准或解除暂停 |
| `submission_intent` | 具体批准和固定恢复 ID 已持久保存，结果待核实 |
| `unknown` | 回执或本地对账未知；只 GET 原 ID，不重发确认或换新 ID |
| `verified` | 恢复核验完成；须同时检查 `local_released=true` 才可显示这次本地暂停已解除 |
| `rejected` | 恢复拒绝，暂停保留，旧请求不重发 |
| `superseded` | 原上下文、目标、策略或任务已变化，`local_released=false`；保留旧回执及 `root_outcome` 的已知或未知事实，对当前原因另行预览 |

恢复回执丢失后，详情 GET 只对账已经批准的原 ID。相同暂停及范围下，可在回到已授权的 manual 模式后继续核对该回执；不会创建新恢复动作。`superseded` 不是 Root 拒绝的同义词，更不能清除新的暂停。原任务、用量、旧暂停与恢复审计全部保留，具体流程和已完成的带故障注入实机路径见[恢复操作说明](RECOVERY.md)。

`hosts[].remote_status` 为后台每 30 秒读取的 root 状态缓存，含 `checked_at/status/remote`；`remote` 保留 root grant、窗口、用量及 `safety` 暂停。新提交只接受 60 秒内、作用域/策略/grant 摘要一致且条件已核实的缓存，用量结合本地记录取较大值。root 持续暂停同步为本地 latch，保留 root 原因和任务引用，不因后来成功而清除。HTTP GET 不发起 SSH 或改变授权；读取失败保留的旧快照不作为新授权。

## 0.11 漏洞 AI 分析与 Root 方案衔接

这些路由沿用控制台 Bearer 认证、同源修改边界、请求体限制和严格参数校验。请求不接受临时地址、命令、版本替换、私钥正文或模型密钥。`capabilities.vulnerability_ai=true` 表示提供此接口；`GET /api/ai/status` 的 `configured` 只表示配置具备调用条件，不证明凭据已被远端接受。

### 预览、发送与绑定

预览返回 `host_id/scan_id/collected_at/input_digest/input/catalog`、当前及来源模式修订、`provider_host/model_name/response_format/configured/fresh` 等字段。`input` 是实际发送的重建摘要：目标使用别名，保留有界的包/CVE/USN/版本、逐条证据引用、覆盖缺口和候选引用；不发送主机 IP、连接身份、信任摘要、原始日志、服务器文件正文、令牌或密钥。外层 `catalog` 是本地可信候选目录，不作为模型修改执行参数的入口。

每个目录项包含 `candidate_id/finding_id/action/package/architecture/current_version/candidate_version/fixed_version/advisory/cve/candidate_sha256/risk_level/requires_service_restart/requires_reboot/eligible/blockers`。`eligible=true` 只表示可选择进入确定性规划，不是完整事务已验证或允许安装；Root 仍须检查实际依赖、状态及重启影响。目录优先保留可规划项和明确受影响项，输入超出预算时明确记录省略与不确定性。

`analysis_id` 为客户端预先生成并复用的 32 位小写十六进制，`expected_input_digest` 为预览给出的 64 位摘要，`confirm_send` 必须是布尔 `true`。摘要绑定当前完整扫描及候选、主机/Root 策略作用域、控制端执行策略、提供方地址、模型与输出格式/预算；凭据不进入摘要或 API。不同分析身份的并发请求可能被拒绝；同一 ID 再次 POST 只读取原尝试，不再次付费发送。

模式名和修订保存在记录的 `source_mode/source_mode_revision` 中作审计。单纯从 manual 切换 assisted 不使已有事实分析失效，也不要求重新付费分析；生成 Root 方案时必须提供**当前**模式修订并重新授权。扫描、目标、权限策略、候选、供应商证据或模型配置变化，以及扫描超过十五分钟时，旧建议不能作为当前 Root 规划依据。

### 分析记录与未知结果

POST 与详情/列表返回本地记录，主要字段为 `host_id/analysis_id/status/created_at/updated_at/deadline_at/input_digest/analysis_digest/input/catalog/result/proposals/plans/source_mode/source_mode_revision/provider_host/model_name/response_format/stale/stale_reason/applicable/detail`。分析处理者内部身份不返回。

`result` 为校验后的模型建议：`summary/uncertainty/evidence_refs/finding_analyses/proposals/actions_executable/input_digest/model`。逐条分析的优先级和解释仍是模型判断；受影响、修复版本和候选事实来自服务器证据，模型不能改写。`actions_executable` 始终为 `false`，不存在模型生成的 Shell 或任意动作字段。

真正用于下一步请求的是记录顶层 `proposals[]`：服务器生成 `proposal_id` 并绑定 `candidate_id`、可信 `candidate`、解释与证据引用。客户端不得从模型文本提取命令或自己合成 `proposal_id`。只有 `status=completed`、`stale=false` 且 `applicable=true` 的建议可被选入规划。

| `status` | 含义 |
| --- | --- |
| `submission_intent` | 原分析身份已持久保存，模型请求结果待核实 |
| `completed` | 返回内容已通过本地结构和证据校验；不表示安装或服务恢复成功 |
| `stale` | 模型分析完成期间证据或配置已变化，保留历史，不适用于当前规划 |
| `unknown` | 提供方可能已处理或计费，但未取得可信结果；保留原 ID，只读查询，不自动重复发送 |
| `failed`、`refused` | 未得到可采用的分析或提供方拒绝，原扫描与任务不变；同 ID 不自动重发 |
| `disabled` | 提供方未配置完整或不可安全使用，没有发送当前分析 |

历史 `completed` 记录也可能在 GET 时动态变为 `stale=true/applicable=false`；完成时的建议及摘要保留。GET 只查本地审计及当前缓存，不向模型追问原请求，也不取得丢失的远端回复。未知模型请求没有通用的兼容 API 对账协议，不能把本地 GET 当成一定能补回响应的承诺。

明确的参数、证据或并发冲突返回 403/409/422 时发生在模型发送之前，可先重新读取预览；网络或 5xx 不能据此推断没有发送或没有计费，应保留原分析 ID。模型返回失败、拒绝、未知或处理中发生证据变化时，以持久记录状态表示，不通过静默重试或自动切换格式伪装成功。

### 失败原因的固定分类（0.14）

新分析在明确的拒绝点保存 `result.validation_failure={schema_version:1,stage,code}`。`stage` 为 `provider_response/response_envelope/json/schema/evidence/selection/text`，`code` 必须与程序中的固定枚举匹配。例如 `schema_contract_invalid` 表示字段、类型或长度不符合约定，`evidence_reference_invalid` 表示证据引用无效，`text_unsafe_instruction_or_claim` 表示文本触及命令、目的地或未经验证的完成声明规则。分类不保存模型原文、字段路径、Pydantic 输入、异常正文或思维链；不能由代码推断原回答具体包含什么内容。

这些明确拒绝保留 `failure_kind=model_response_not_usable`；输出上限仍为 `output_truncated`。本地输入尚未准备好、请求阶段失败与本地响应处理异常分别使用 `local_analysis_not_ready/local_input`、`provider_request_failed/provider_request`、`analysis_processing_failed/response_processing`（kind/stage）。超时未知、提供方拒绝和 HTTP 拒绝保留原语义。上述诊断不授予重试或执行权限，旧记录没有具体分类时不事后补造。认证证据导出和离线核验同时检查新增字段的固定结构。

### 单候选分析（0.15）

`GET /hosts/{host_id}/preview?candidate_id=candidate-N` 返回 v2 预览，`selection={kind:"single_candidate",candidate_id:"candidate-N"}` 仅引用服务端完整目录中的一项。`POST /analyses` 可带同一 `selection`，其内容必须与已确认的 `expected_input_digest` 一致。没有 selection 的旧请求继续使用 v1。主机、权限、事务或执行参数不由 selection 提供；预览仍只读，不调用模型。

v2 实际模型输入只保留该候选及对应 finding，明确原扫描、同包关联条目和省略数量；完整原扫描和完整目录仍归档。结果仍使用原六字段，但 summary 最多 280 字、每段理由 160 字、finding/proposal 各最多一项，保留覆盖缺口。校验规则、原预算和单次调用不放宽。控制台默认预览一个可选候选，改变范围后清除发送确认；迟到响应或不同范围的返回不能采用。

失败分析的来源不会随最新扫描覆盖。当未提交的 deferred 候选已被后续扫描更新、原分析时的候选投影不再留存，且分析/请求均 failed、没有任何关联执行引用时，导出保持原 source/request，候选为 null，并记录 `original_candidate_snapshot:not_retained`，离线结论为 incomplete。不会把当前候选重造为原件；completed 或有执行引用的路径继续要求严格原扫描绑定。

自动后台明确绑定当前原生候选，采用前和 Root 规划前重新校验结果及候选。计费身份继续使用原 `automatic-ai/v1` key，不因分析格式升级重发旧 failed/unknown；预算前已归档的原尝试沿原 ID、原版本继续，原上下文变化仍停止。文本拒绝新增 URL、命令/代码、路径、完成声明四个固定子码，旧泛码保留用于历史读取。

### 从提案生成 Root 方案

`POST /plans` 使用原 `analysis_id`、服务器给出的 32 位 `proposal_id`、`expected_analysis_digest` 及当前 `expected_mode_revision`。控制端要求已同步的 manual 或 assisted 模式，并重新校验当前启用策略、动作/目标/包允许名单、扫描时效及完整绑定；目标存在未决补丁任务时先对账原任务。模型不能批准 automatic 执行或解除持续暂停。

返回是**平铺的既有 Root 方案**，包含原生 `plan_id/plan_digest/mode_revision/expires_at/package_changes/finding/risk_level/verification_required` 等，不是 AI 记录 wrapper。控制端再对照 Root 完整摘要、原 finding 的关键字段、精确版本与 SHA、包/来源证明、当前状态和风险/重启影响；不一致时拒绝返回可采用方案，不提交安装。

AI 来源关联单独保存在原分析的 `plans[]` 中，含 `proposal_id/plan_id/plan_digest/mode_revision/expires_at/created_at`，不向 Root 方案添加会改变其摘要的 AI 字段。后续安装继续使用原 `POST /api/remediation/jobs` 的 assisted 具体批准、固定任务 ID 及验证规则；生成 AI 建议或 Root 方案都不等于批准安装。

分析审计存储位于 `vulnerability-ai.sqlite3`，纳入固定备份白名单。记录、原模型请求身份及未知结果不因重启清空；达到身份或单条预算时停止新请求，不靠删除旧 ID 重新收费。当前实现上限为 1000 条身份、单记录 256 KiB、列表 100 条，优先保留未决身份的可见性。

## 0.12 自动 AI 许可与持续复扫

`ControlPolicy.automatic_ai` 默认为 `null`，省略时保留旧模式作用域和确定性自动流程。显式许可含 `enabled/provider_fingerprint/max_analyses_per_day/max_total_analyses`；开启须同时有已启用的控制端策略和独立自动 grant。提供方摘要从已认证的 `/api/ai/status` 取得，默认每日/总分析上限各 1，均限制为 1–5 的整数。选择 automatic 或配置模型本身不增加执行或模型外发权限，Root grant 不增加 AI 字段。

`GET /api/automatic/status` 的 `ai` 包含 `enabled/policy/provider_fingerprint/requests/alerts/quotas/last_error`。`requests` 最多 100 条，只返回固定 `request_key/host_id/candidate_id/analysis_id/status` 与创建、更新和截止时间；状态为 `submission_intent/completed/failed/unknown/refused/stale`。`quotas` 按目标列出 `daily_used/total_used`，每日按 UTC 跨 grant 累计，总量按当前 grant 累计；许可及计数不可用时保留 `null`，不解释成零。

候选模型请求 key 不含扫描 ID、grant ID、Root 策略摘要或模式修订，失败和 unknown 不因更新这些字段而重发；采用结果仍需重新核对当前全部证据、权限和提供方绑定。模型意图及次数先持久保存再最多外发一次；未知请求保留原分析 ID，只读查询，没有通用兼容接口可保证补回丢失回复。读取计划、原分析、原任务和模式本身不增加模型调用。

告警含 `id/host_id/event_key/kind/detail/request_key/candidate_id/job_id/acknowledged/acknowledged_at/created_at/updated_at`；`acknowledged` 是布尔值。`analysis_completed` 表示 AI 提案已核验，`plan_ready` 表示随后原生计划已核验，`repair_verified` 仅表示原任务覆盖项验证通过。已阅接口只更新阅读状态，未认证 401、ID 无效或不存在 404、存储不可用 503；不要求旧漏洞观察已阅接口的 `{acknowledge:true}` 请求体。

带 AI 来源且已 verified 的原自动任务会登记持久只读复扫请求。后台仅对显式启用且登记的漏洞观察目标执行新扫描并 ingest，关联原 job、复扫请求和结果观察 ID；重复事件不重复提前扫描，正在读取后到达的事件需下一次新扫描。失败最多 300 秒后重试，重启保留未完成请求。无新的模型调用、安装或对外消息；通知仍为持久控制台事件。设计、配置和队列测试边界见[自动 AI 说明](AUTOMATIC_AI.md)。

## 0.13 原来源归档与证据附件

`capabilities.vulnerability_evidence=true` 表示提供原证据下载能力，不是当前来源已经留存或实机验收已完成。分析视图上的 `evidence_archive.status` 为 `retained/not_retained/invalid`；持久分析自身的 `source_archive` 则是严格 `{required:true,schema_version:1,source_digest}` 标记，独立 SQL `source_digest_pin` 防止局部删除或降级它。新必需原件损坏时停止采用；旧身份不补造历史来源，也不重发模型。

原来源与分析保存在同一 `vulnerability-ai.sqlite3`：完整结构化 scan 排除四个缓存字段 `received_at/notification_due/notification_count/last_notified_at`，连同原 catalog、模型 input、HostPublic、controller policy、无凭据的六字段 provider 及绑定 context 保存。精确 UTC `eligibility_evaluated_at` 用于重算原新鲜度；正常模式切换不改变原 input 身份。提供方未配置时 `base_url/model` 可为 `null`，来源完整与分析是否完成分别判断。手动先同事务保存原来源和身份；自动在独立模型预算意图之前保留原来源。

新源限 128 份、单 scan 1 MiB、单 source 2 MiB、source 合计 64 MiB；整个 AI 审计逻辑预算 128 MiB，每份源终身预留单条分析上限 256 KiB。原身份上限仍为 1000。超额停止新增，不静默截断、覆盖或删除旧身份来重新计费。

证据 GET 返回 `application/json` 附件 `opsark-evidence-{analysis_id}.json`，不缓存。顶层含 `schema_version/kind/exported_at/read_only/actions_executable/identity/source_archive/analysis/plans/jobs/automatic/rescan_requests/observations/missing_components/bundle_digest`；`read_only=true/actions_executable=false`。analysis 是原持久对象去 owner，不调用会读取当前配置的动态视图。plan/job/自动意图/复扫观察仅按原 ID 从本地缓存关联，未保存的原件列为缺失；Root 原始 transaction 与包文件未缓存时明确 `not_retained`。

组装对依赖内容和修订作稳定双读，最多两次，不承诺跨库全局原子。未认证 401；原分析不存在或 host/analysis 配对不符 404；必需原件、绑定、稳定性或预算失败 409。历史缺件允许 200 导出，离线结论仍为 `incomplete`。导出不调用 SSH/RPC、模型、扫描、安装或已阅接口，也不读取当前模型密钥。

完整结构、不可变来源、旧十库兼容、安全与测试边界见[证据归档说明](VULNERABILITY_EVIDENCE.md)。仓库 CLI 为 `uv run python tools/verify_evidence.py file.json`：退出 0 仅说明内部一致；退出 2 区分 `incomplete/invalid`。SHA 不是发行人签名，报告不授予执行权限。

0.14 的修复后复扫同时核对原任务的目标范围、当前修复目标与观察端捕获的目标。复用同一主机 ID 后若地址、可信主机密钥或策略变化，保留原任务及告警，但不把原任务关联到新目标扫描；新范围的定期观察仍独立运行。不改写既有历史队列或原证据。

## 服务激活（0.16）

认证前缀 `/api/service-activations` 使用独立激活身份，不修改原补丁任务或解除暂停。

| 方法 / 路径 | 行为 |
| --- | --- |
| `GET /` | 只读本地配置状态与缓存激活记录；不发 SSH |
| `POST /plans` | `{host_id,job_id,expected_mode_revision}`；手动/半自动核对原 `installed_restart_pending` 任务，返回独立预览记录，不重启 |
| `POST /` | `{host_id,activation_id,expected_activation_digest,expected_mode_revision,confirm_activate:true}`；仅当前已同步半自动模式批准一次 |
| `GET /{host_id}/{activation_id}` | 只读原缓存 ID；后台 monitor 负责新 SSH 查询和确认，不重发 submit |
| `POST /{host_id}/{activation_id}/acknowledge` | 仅记录已阅，不重启、重发或解除暂停 |
| `GET /{host_id}/{activation_id}/evidence` | 认证只读导出原激活计划、Root 回执、原安装快照和独立观察关联 |

`ControlPolicy.service_activation` 缺省为 None 且从旧序列化投影省略，不改变原 mode scope 或 v1/v2 证据。启用需明确 host_ids、allowed_packages、allowed_units、父级服务重启许可，且 `max_services_per_activation=1`；不会扩大父级目标或包。控制端不接受任意 unit、Shell、环境或“已验证”标志。Root 从当前真实旧库映射推导唯一已登记服务；关键 SSH、网络、容器基础设施和主机重启不在此版本范围，D-Bus 仅受控实验加独立 critical opt-in。

预览绑定原任务、安装前文件清单、Root 安全状态原字节、当前包及库映射、PID/starttime/exe/cgroup、服务配置/环境摘要、模式和五分钟有效期。批准意图先持久保存，Root 在独立 systemd worker 中重验后执行固定单服务重启，并重新核对包、供应商、进程、运行时和登记业务。最后只能经开始于检查之后的新专用 SSH 确认 `verified`；未知保留原 ID，不重放。查询或较晚回执不能伪造动作发生在有效期内。

激活预览使用已保留的可信父任务快照，由 Root 激活入口直接读取原 ledger 并比对摘要/修订，不通过会迁移历史 scope 元数据的旧补丁状态刷新来补快照。可信缓存缺失时明确拒绝；旧执行 scope 的 pending 安装状态查询也不会改写原文件。

原安装状态保持 `installed_restart_pending`，新记录的 `effective_status=activation_verified` 表示本次激活验证完成。原暂停仍保留，服务激活不等同于恢复自动通道。后台以 activation_id 排独立 `event_kind=service_activation` 复扫，`job_id=null`、`original_job_id` 关联父安装任务，防止把它冒称为原安装已 verified 的队列。目标和 watch scope 均重新核对。

新证据包 kind 为 `opsark-service-activation-evidence`、schema1，至多4MiB，两次稳定只读 SQLite 收集，无 SSH、密钥、当前提供方访问。Root 回执、原 job、队列和 observation 分别绑定，缺件明确记录；SHA 仅内部一致性。该 kind 与旧漏洞证据不同，旧 `tools/verify_evidence.py` 不解析此包。激活表和租约复用 patches.sqlite3，仍为十库；离线迁移只清传输副本中的两个 monitor lease，保留全部计划、原件和执行意图。

独立复扫导出补充：pending/claimed/failed 请求不能使包成为内部完整；complete 必须保留匹配的 `result_scan_id`、`result_observation_id`、作用域及新鲜采集时间，缺件保持 incomplete，矛盾返回 409，不从 latest 扫描回填。可选 `collection_evidence` 有独立 facts_digest 和 16KiB 上限，区分采集类型与供应商判定；`not_evaluated` 不允许供应商 findings，也不能宣称全部 CVE 已检查。`evidence_provenance` 明示合成父任务和各观察的采集/评估类型，内部一致性不等于漏洞覆盖。新 `tools/verify_activation_evidence.py` 对下载包做离线内部核对，完整一致退出0，incomplete/invalid退出2；不访问服务、当前密钥或模型，且不认证来源签名。

## 单次防护会话的本地只读提示

完整行为见[单次会话合同](DEFENSE_SINGLE_SESSION.md)与[隔离接入清单](DEFENSE_SESSION_SETUP.md)，默认关闭，不能授予长期执行权限。

`GET /api/hosts/{host}/ssh-defense/transactions/{rid}` 对 cursor 新增 `controller_observation`：`owned_by_current_boot` 为布尔值、`deadline_at` 为原控制端截止时间、`remaining_ms` 为本次读取时的严格整数 `0..120000`。其他事务 kind 返回 null。该提示不发 SSH、不写账本、不暴露 owner 原文；Root 的独立 UTC 不用于计算它。时钟回拨到原创建时间以前时余量归零。客户端可从请求开始按单调时钟保守扣时，仍须通过后端准入。

`GET /api/hosts/{host}/ssh-defense/sessions/{ref}/ai-receipt` 经过原认证和主机绑定，只在同一只读事务核对原历史，返回固定九键：`v/session_ref/analysis_id/status/decision/usage_state/input_digest/proof_sha256/actions_executable`。执行标志始终 false，不返回 provider、来源原文、别名表、prompt、自由文本或凭据。无 AI 意图时 status 为 not_required/not_started，其余五个可空分析字段均为 null；有意图但缺结果时保留 unknown 和原本地额度状态。quota 不是提供方账单回执。退役目标、旧 owner、许可到期或当前提供方不可用不会禁止历史读取，也不会恢复原发送权；损坏或跨主机整次 409，存储不可用 503，错误正文固定。

## 报告模型

以 `src/opsark/models.py` 的 Pydantic 模型为字段依据。`scenario` 为 `web_502`、`disk`、`container_restart` 或 `ssh_security`；`source` 为 `replay` 或 `ssh`。所有模型拒绝未知字段。

`Report` 包含可引用的事实、候选原因、证据、缺失信息和建议；`action.executable` 仍固定为 `false`，不会因 0.7 新增独立修复任务而改变。0.2 新增 `target`、`scope_hash` 和 `comparison`，旧报告按缺省字段兼容。调查恢复验收保留 `not_run` 或 `uncovered`；登记即时检查可返回 `passed`、`failed` 或 `error`，不自动结案。

修复扫描和任务使用独立模型及存储：USN 证据保留完整源/二进制版本、公告和稳定 `finding_id`；Pro 的无修复版本 `vulnerable` 只表示 `needs_vendor_review`，汇总行保留关联数及样例，不能当成已确认漏洞总数。任务结果区分 `verified`、`installed_restart_pending`、`reboot_pending`、`verification_failed`、`failed`、`rejected` 和 `unknown`，与调查报告及告警已阅分开。

0.3 新增 `compatibility`：状态 `compatible/unsupported/unknown`、系统/版本/架构、适配器、工具与证据编号。`compatible` 仅允许选择适配器，不等于版本已实机验收或服务健康。旧报告缺该字段时默认为未知。SSH 采集先做系统和工具预检，范围外或探针不完整时把后续检查保存为 `unavailable`；缺工具只跳过依赖项。详见[平台矩阵](PLATFORM_SUPPORT.md)。

证据中包含 `check_id`、目标、采集或读取时间、来源、状态、脱敏输出、截断标记和退出结果。AI 解释不覆盖诊断事实，也不产生可执行动作。

站点和基线的范围、确认及数据约束见[扩展约定](NEXT_STAGE_CONTRACT.md)。基线保存与调查共用串行锁，重复保存同一报告保持幂等，不能覆盖既有基线值。

## 部署登记

授权 Compose 发现为独立的只读接口，具体模型见 `src/opsark/compose_discovery.py`。[发现合同](COMPOSE_DISCOVERY.md)定义前置、总量和证据边界。

- `POST /api/hosts/{id}/compose-discovery` 仅接受空对象，项目来自部署清单，不接受客户端目标或 Docker 参数。
- `POST /api/hosts/{id}/compose-discovery/preview` 接受 `candidate_id/snapshot_digest/host_port`；服务端重新采集当前目标，旧快照、未知候选或非当前 TCP 发布端口整次 409，仅返回四行登记片段，不保存或执行。
- `GET /api/capabilities` 的 `host_compose_discovery` 表示接口存在；`GET /api/hosts` 对已登记项另给 `compose_discovery_configured` 和 `container_binding_confirmed` 布尔元数据。这些字段不加入调查的 `HostPublic` 或 AI 正文。

接入材料可省略容器名，但必须明确授权一个 `compose_project`；此时生成 `container_binding_confirmed=false`，容器状态和日志命令既不执行也不导出权限。原来明确填写容器的材料与旧清单保持原路径，缺省为已登记。预览返回 true 只是材料，不修改部署登记；管理员采纳和重审策略仍是独立步骤。接口与已有只读检查共用认证、目标限定和并发锁，不调用模型。

SSH 主机与凭据引用从部署者控制的 TOML 文件读取；API 只能选择已登记主机，地址限 IP 字面值。私钥和可信主机记录留在服务端。应用拒绝未知主机密钥，限制检查种类、执行时间和输出数量；Docker 检查固定目标主机的本地 rootful socket。具体预算见运行说明。

当前是单管理员实例，不提供多租户权限隔离。不同客户需要独立部署；该限制在实现隔离前保持显式标注。

部署端可选 `OPSARK_AUTOMATION_POLICY` 引用控制端授权 JSON，`OPSARK_PATCH_INVENTORY` 引用 `{schema_version:1,targets:{host_id:{key_file:独立私钥绝对文件引用,policy_digest:远端策略摘要}}}` JSON。修复目标必须已在原 SSH 清单登记，复用已核验的目标身份，修复私钥独立于只读密钥；API 不接收凭据正文或更改目标、包权限及执行选项。

默认策略禁用且范围为空；目标、策略或 driver 能力范围改变会使旧选择失效并回到手动。`execution_available:true` 只表示配置、执行驱动及模式同步能力就绪，不等于当前窗口、配额、任务已运行或验证成功。root 还需单独核验主机、策略、包状态及具体批准或自动 grant。部署细节见[固定修复入口](../deploy/vulnerability/README.md)、[自主修复合同](VULNERABILITY_REMEDIATION.md)及[自动授权配置](AUTOMATIC_REPAIR.md)。
