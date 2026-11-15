# 自动 AI 候选审查、预算与告警

本文中的物理测试宿主使用别名，原始身份保留在私有验收档案中。

适用于 0.12。自动 AI 默认关闭，独立于模型连接配置和自动补丁执行授权。新增链路为：真实扫描 → 已核实候选 → 一次模型分析与候选选择 → 当前原生计划核验 → 原双侧预授权提交 → 原任务验证 → 持久告警与只读观察复扫。

0.12.0 已部署，最终运行代码为 `a22fa02`；两台测试服务器各自的新隔离环境均完成后台定时扫描、真实模型分析、原生自动补丁执行、复扫、服务与新 SSH 验证，以及持久告警和观察结果更新。实验前后的核对确认既有控制端的配置、授权范围和历史保持一致。

## 本轮实机验收

| 项目 | CN 隔离环境 | Intl 隔离环境 |
| --- | --- | --- |
| 物理宿主 | 第一台授权测试机 | 第二台授权测试机 |
| 新实验 run | `296ba4772b3f` | `e877c83a5ed7` |
| 真实 AI 分析 | `f819d69dec2e32f8ec612b704d369c0f` | `5cd28282ff4f1a3ad41aeef3db2d1511` |
| 原生计划 | `9c11ea84fa705fff1d2a304e0b34a9be` | `fdedf511b0a4c3597a3156dc05cb1cda` |
| 自动任务 | `af0ee58a16a5a9cc4aa0256d27e9aef7` | `5aab49e1a2b4aded28410c31b67ea7fd` |
| 最终任务 | verified / 修订 7 / 通知 1 | verified / 修订 7 / 通知 1 |
| 模型请求 / DPKG 升级 | 各 1 次 | 各 1 次 |
| 修复后观察队列 | complete / 尝试 1 次 | complete / 尝试 1 次 |
| 收尾模式 | manual6 | manual2 |

操作者仅配置独立许可并切换模式，未人工 POST 扫描、模型分析、计划或安装接口来补齐链路。两份后台请求固定使用 `deepseek-v4-pro`、JSON object、2048 输出上限及显式关闭 thinking，分别返回 369/417 个输出 tokens、2294/2342 个总 tokens；usage 合计 4636，不是费用账单。

实际补丁是隔离 guest 内 `libbrotli1:amd64` 从 `1.1.0-2build2` 到 `1.1.0-2ubuntu0.1`，依据 [USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1)。两项任务的精确版本、协议 3 hook、完整单包事务和 SHA、dpkg audit、同 finding 官方复扫、运行映射 complete/outdated0、SSH/Nginx、登记 HTTP 200 与本地验证后新建的修复 SSH 连接均通过。

每个环境保存 `analysis_started`、`analysis_completed`、`plan_ready`、`repair_verified` 四类去重事件。任务 verified 后，持久复扫队列确实触发新读取并关联新的 scan/observation；观察事件为同一漏洞的 `not_affected_on_rescan`，同时保留部分覆盖提示。不是仅安装返回成功，也不是复用旧观察结果。

保持 automatic 重启或重建控制端后，模型请求、原任务、实际升级、通知、四个事件身份和复扫队列均不增加；标记已阅只改变原事件的已阅状态。两台真实 UI 的 1440/390 宽度均无页面错误，截图过程没有模型或安装提交。随后局部模式恢复手动，新 guest/controller 已停止，临时模型和角色部署密钥副本已移除，每台十库与 Root 审计已归档。

CN 首次后台动作使用 `1ba9f12`。Linux CI 随后发现 SQLite 临时 sidecar 在并发提交时消失会误报失败，控制端先后原地更新 `602f4db`、最终 `a22fa02`，保留原模型、任务及授权，未重新制造漏洞或安装；最终版本再次完成持久性检查。Intl 从零模型、零任务起步，直接使用最终 `a22fa02` 完成正向链路。修复保留文件类型、所有权、私有权限和永久账本丢失拒绝；没有为通过验收放宽 Root 或 AI 校验。

最终 CI 八项全部通过：Linux 2080/1、Windows 2052/29、macOS 2063/18（通过/跳过），三受管发行版与三浏览器通过。独立离线证据复核两台各 49 项通过，共 98 项，未有不符项；验收回执私下保存，不提交 Git。

本轮只证明两个共享宿主内核的 Ubuntu Docker guest 中这一单包的自动修复与登记服务健康，不证明整机安全或网站故障恢复。扫描仍为 partial，备份仅为包元数据。原安装前全量 raw scan 已被 latest 替换而未长期留存，保留的是原定期 observation、脱敏模型输入、意图、候选、完整原生计划与任务；不能声称已独立重算包含该 raw scan 的完整原 input_digest。

## 权限与默认行为

`ControlPolicy.automatic_ai` 默认是 `null`，省略时沿用既有确定性自动流程，并保持旧部署的模式作用域摘要；升级本身不会重置原模式修订。显式增加或修改这份策略属于授权配置变化，仍走原作用域校验及模式同步流程。

模型已配置、选择 `automatic`、存在自动 AI 许可，分别都不足以允许安装。启用 AI 还要求当前控制端策略和独立 `automatic` grant 已启用；后台继续核验明确目标、包/USN、风险、UTC 窗口、期限、次数、当前扫描与暂停状态。

本轮沿用既有 Root9 受限入口及控制端/root 双侧权限。`automatic_ai` 只属于控制端，不加入 root grant，不扩大原目标、动作、包范围或 SSH 权限。模型只能选择服务端 `eligible` 候选，不能生成安装参数、命令、新版本或权限。启用后若模型失败、未知、拒绝、提案不匹配或证据过期，本候选停止，不退回绕过 AI 的安装路径。原生规划和提交入口也会独立重验 AI 来源证明。

## 部署配置

在部署端 `OPSARK_AUTOMATION_POLICY` 指向的现有控制端 JSON 中增加以下**禁用片段**；它不是完整策略，也不创建自动执行 grant：

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

`enabled` 必须是布尔值；两个次数上限必须是 1–5 的整数，默认各 1。需要保持旧模式作用域时直接省略 `automatic_ai`，不要为展示默认值而写入这段新配置。显式关闭 AI 许可不会撤销另外已存在的确定性自动执行 grant；停用自动执行应按原模式和执行策略操作。

明确启用前，先按[常驻部署说明](../deploy/observer/README.md)配置提供方及部署端密钥文件，再通过已认证的 `GET /api/ai/status` 取得 `configured=true` 和非空 `provider_fingerprint`。将该 64 位小写十六进制摘要写入控制端许可，并由部署者明确设置 `enabled:true`。不要手拼摘要、填模型名代替摘要或沿用另一实例的值。

该 GET 只检查本地配置，不访问模型、不验证余额或远端授权。摘要绑定 Base URL、模型、响应格式、令牌参数、输出预算和 thinking 模式，不包含密钥；密钥轮换不自动产生新候选身份。提供方配置变化后，旧许可不匹配即阻断，需重新审查部署配置。Root 自动 grant 的生成及核验仍按[原自动修复合同](AUTOMATIC_REPAIR.md)执行。

## 一次外发与独立预算

自动模型请求先把固定身份、分析 ID、截止时间和预算占用持久写入 `automatic.sqlite3`，再调用既有漏洞 AI 服务；结构化分析保存在 `vulnerability-ai.sqlite3`。只有持有本次发送意图的处理者可以外发一次。控制端重启、HTTP 刷新或并发后台不会重发同一身份。

保存意图后及提供方入口完成白名单编码后，自动流程分别复核当前发送许可。准入前已生效的模式、授权、证据或提供方变化会阻止新外发，预算不退回、不重试。最终准入后按在途处理，不承诺取消已准入或已发送的请求；网络期间不持模式锁。[发送准入与复核边界](AI_DISPATCH_ADMISSION.md)

`request_key` 绑定公开目标作用域、`finding_id`、包名、当前版本、候选版本和提供方摘要。它**不包含扫描 ID、grant ID、Root 策略摘要或模式修订号**，因此刷新扫描、换 grant 或更新 Root 策略不能让同一候选重新请求模型。它们仍属于采用结果时必须匹配的证据及权限绑定；旧结果过期后保留历史并阻断，不因新扫描自动付费重做。当前扫描须在十五分钟内且与保存的完整分析绑定一致。

预算按目标分别计算：每日用量按 UTC 日期跨 grant 累计，总量按目标和当前 grant 累计。预算占用与 Root 安装每日/总次数分开；模型失败、拒绝、未知或没有可用提案都不退回次数。自动模型意图总账最多保留 5000 个身份，告警总账最多 10000 条；满后停止新登记，不删除旧身份绕过去重。既有漏洞 AI 分析存储还有自己的记录预算。

未决分析超过 120 秒转为 `unknown`。未知可能已经外发或计费，只查看原分析 ID；兼容模型接口没有通用的丢失响应补取协议，本地 GET 不承诺补回提供方响应。同一候选的 `failed/unknown/refused/stale` 都不自动重试，也不自动改模型、格式或输出预算。读取原分析、准备原生计划、查询原任务及保存操作模式本身不调用模型；在当前自动授权仍有效时，独立后台可能另行处理新的合格候选。

模型输出须通过已有严格 JSON、停止原因、证据引用和候选校验。`completed` 只表示 AI 候选判断被接受；`plan_ready` 才表示随后原生计划通过当前核验，两者都不等于安装或服务恢复成功。详细分析和人工通道见[漏洞 AI 说明](VULNERABILITY_AI.md)。

## 状态与控制台告警

能力字段 `capabilities.automatic_ai=true` 表示接口和界面可用，不表示部署已许可自动外发。已认证的 `GET /api/automatic/status` 返回 `ai`：

| 字段 | 含义 |
| --- | --- |
| `enabled/policy/provider_fingerprint` | 当前控制端 AI 许可及提供方绑定；未配置时 `policy` 为 `null` |
| `requests` | 最多 100 条，含 `request_key/host_id/candidate_id/analysis_id/status/created_at/updated_at/deadline_at`；处理者身份不返回 |
| `quotas` | 按当前 grant 目标给出 `daily_used/total_used`；上限来自 `policy`，读取失败时可为 `null` |
| `alerts` | 最多 100 条持久事件，已阅与处置结论分开 |
| `last_error` | 受控阻断说明；不能解释成模型或主机健康状态 |

请求状态为 `submission_intent/completed/failed/unknown/refused/stale`。告警种类包括 `analysis_started/analysis_completed/analysis_failed/analysis_unknown/no_proposal/plan_ready/repair_verified/repair_failed/blocked`。界面把 `analysis_completed` 显示为“AI提案已核验”，把 `plan_ready` 显示为“原生计划已核验”；`repair_verified` 只描述原任务覆盖的验证项。

`GET /api/automatic/ai/alerts` 读取持久列表，未阅优先；`POST /api/automatic/ai/alerts/{64位小写十六进制id}/ack` 无需请求体，只标记原告警已阅，返回该告警。重复已阅保持幂等。ID 无效或不存在返回 404，存储不可用返回受控 503，未认证返回 401。告警含 `id/host_id/event_key/kind/detail/request_key/candidate_id/job_id/acknowledged/acknowledged_at/created_at/updated_at`，无关联引用时为 `null`。

已阅不会创建或重试分析、计划、安装、恢复，也不清暂停、重置配额或改变模式。界面仅展示许可、原分析和告警，启用需修改部署配置；状态失败时历史数据不能证明当前可执行。登出清空面板，旧会话的迟到响应不能重新写回。

通知渠道为持久控制台事件及受控进程日志，不向邮件、Webhook 或外部人员发送消息。API 不输出模型密钥、密钥文件路径、完整 Base URL、原始日志/服务器文件或提供方原始响应及推理正文；保存并展示的是脱敏输入、经校验的结构化分析及有限诊断。

## 验证后立即更新持续观察

带 AI 来源证明的原自动任务达到 `verified` 后，后台持久登记只读复扫请求，唯一键为主机、当前观察作用域和原 32 位 job ID。仅对已显式启用定期漏洞扫描且登记在扫描目标内的主机准入；不会扩大目标、调用模型或再次安装。

新请求把下次扫描提前到当前，由原观察后台沿用独占租约尽快执行真实扫描并 `ingest`，更新既有漏洞观察事件。正在扫描时保留当前任务，扫描发出后才到达的请求不能被该次结果消费；多个扫描前请求可共用一次新读取。重复事件不改变已完成结果或反复提前调度。

队列状态为 `pending/claimed/complete/failed`；失败保留原事件，按原扫描失败策略最多 300 秒后重试。重启恢复未完成请求并重新读取，不能用历史扫描冒充补扫。成功关联 `result_observation_id/result_scan_id`，不延长观察记录原有保留期限。队列最多 5000 个身份，满后拒绝新登记并保留旧去重记录；禁用观察时保留历史，不启动复扫。

15 项队列测试覆盖重复及并发事件、多请求合并、迟到事件、失败退避、重启与 ingest 后中断、多个 worker 和租约丢失、作用域/开关限制及旧扫描拒绝。三浏览器另有 6 组合成界面契约；这些测试不访问真实服务器或模型。实际扫描的 partial/unavailable、覆盖缺口和“同一漏洞不再受影响”仍按[持续漏洞观察合同](VULNERABILITY_WATCH.md)解释，不能据此宣称整机安全。
