# AI 外发的发行验收边界

源码复核基线为 `9a6816da98e80e17b711945e6ab563f2c0498689`。当前发现五个模型 route、两个提供方适配，共用一个模型 HTTP 出口。以下是源码和合成测试覆盖清单，不是全产品、真实提供方或全部平台验收。

## 入口与白名单

| 可触发模型的入口 | 实际调用路径与 route | 允许进入模型正文的数据 |
| --- | --- | --- |
| `POST /api/reports/{id}/explain` | `main.explain_report → ai.explain → _project_report → diagnosis` | 分类事实/候选、检查状态、证据临时别名、覆盖计数；无原日志或渲染文本 |
| `POST /api/security/alerts/{id}/analyze`，SSH/Web 告警 | `main.security_analyze → security_ai.analyze_alert → guard_alert_source → _project_alert → security` | 事件/来源/站点临时别名、枚举、计数、相对时间跨度和覆盖约束；无 IP、URI、账号、UA、journal cursor |
| `POST /api/vulnerability-ai/analyses`，不选择单候选 | `VulnerabilityAIService.analyze → _egress_preview → vulnerability_ai.analyze → vulnerability` | CVE/USN 公开编号、供应商证据状态、覆盖/风险/动作枚举及 finding/evidence/candidate 别名；无包名、精确版本、原扫描或主机身份 |
| 同一接口，选择 `single_candidate` | `VulnerabilityAIService.analyze → vulnerability_ai_focus.analyze → focused` | 上述白名单中唯一候选、关联计数和范围限制；不把局部结论扩大为全机安全 |
| 自动漏洞流程 | `AutomaticMonitor._execute → AutomaticAIGate.require_proposal → VulnerabilityAIService.analyze → focused` | 复用单候选白名单及发送准入；没有新增 transport |
| `POST /api/hosts/{host}/ssh-defense/ai/analyses` | `DefenseAIService.analyze → validate_source → project_egress → ssh_defense` | `candidate-1/evidence-1`、固定分类、不同失败端口数、TTL 60 秒与省略数；无原 RID、Root 绑定或原证据 hash |
| 显式单次 SSH 会话 | `DefenseSessionWorker → DefenseSessionCoordinator._tick → DefenseAIService.analyze → ssh_defense` | 同一 SSH 白名单，另核原会话、费用和发送许可；没有独立模型出口 |

preview、status、历史分析和原 AI 回执 GET 不触发新的模型请求。计划生成接口读取既有分析并另行核验原生计划，不是另一次模型分析。

## 共同出口

五个 route 均调用 [ai_provider.request_document](../src/opsark/ai_provider.py)，先解析部署端提供方设置，再经 [ai_egress.guard_request](../src/opsark/ai_egress.py)：

1. 完整来源先检查密钥/令牌、SQL/数据库原文、类型及预算；调查采集在脱敏前保存阻断原因，后续解释不能把脱敏后的材料当成新许可。
2. 各入口将材料重建为有闭合字段、枚举和临时别名的白名单。无法分类的投影或请求字段被拒绝。
3. 公共门禁核对完整消息结构、模型、输出预算、固定 system、响应格式及该 route 的 `validate_egress`，返回脱离原调用者对象的副本。
4. `verify_current_dispatch` 在派发前及 HTTPX request hook 再检查当前授权。它处理模式、停止与租约变化；不能替代数据白名单。

唯一模型 HTTP 实现在 `ai_provider._request`：OpenAI 兼容接口使用 `/chat/completions`，Anthropic 使用固定官方 `/messages`，在门禁后做确定性转形。DeepSeek、Gemini 的兼容配置仍属于前一分支。禁止重定向和环境代理，未知结果不自动重发。

部署端模型 API Key 仅用于已配置服务的认证头，不进入 prompt、摘要或错误正文；这不表示提供方认证 Key 从不发送给其所属服务。SSH 私钥和数据库正文不属于模型白名单。更换提供方不放松这些条件。

`vulnerability_webhook` 的 HTTP 是独立通知通道，具有自己的配置和固定载荷；本清单不把它当作模型 route，也不据此声称其已通过 AI 外发门禁。

## 已有合成证据的层次

| 证据 | 已证明的范围 |
| --- | --- |
| `test_ai_egress` 的 investigation→explain 用例 | 脱敏前的令牌阻断会持久保留，完整 API 后续解释的 wire 请求为零 |
| 同文件的 late fact、尾部 Web event、SSH 未投影字段、兄弟候选用例 | PEM、令牌、SQL dump 即使在投影上限之外，仍使整次调用失败，MockTransport 请求为零 |
| 同文件正常 wire 用例 | diagnosis、security SSH/Web、vulnerability、focused 的实际序列化正文只含白名单；这是正常请求的内容检查，不是敏感源拒绝证据 |
| 同文件最终 body 篡改用例 | 未知字段、system/format/schema 篡改、非 JSON 类型、编码 endpoint 和共享凭据均拒绝。先有一次正常对照，因此阻断增量为零，不是整个测试累计调用为零 |
| 自动 focused 用例 | 最终 system 注入令牌被挡；scan SQL 在预算前被挡。原分析不自动重发 |
| `test_ai` / `test_security_ai` | 未分类事实、SQL、已知 Key、Authorization，以及非法分类/计数/类型，在 AsyncClient 构造前拒绝 |
| `test_defense_ai` | 两适配正常 wire 排除原身份；未知 source、rawSQL、token 和 Root schema 损坏会拒绝投影。这些投影函数用例不等于完整 API 的零出站证明 |
| `test_defense_session_ai` | 完整服务的未知 rawdb 注入在费用前拒绝，`ai_rows=0`、`calls=[]` |
| `test_claude_provider` / `test_ai_provider` | native 转形不能绕过公共门禁；Gemini 兼容配置仍走相同出口。部分用例先做正常请求，拒绝请求的增量为零 |

本轮选定的 10 个 pytest selector 共 **61 项通过、零失败**，并在真实 HTTPX sync/async transport 和 Paramiko connect 层另加拒绝计数，实际触达次数为 **0**。测试只使用临时合成资料和 MockTransport。未读取部署凭据或联系真实模型、SSH 服务器。

原运行未指定 JUnit，也未保留临时夹具。安全记录如实采用完成后的工具结果转录，包含固定 selector、原工具回执标识、计数及 44 个相关源码/测试文件与 `9a6816d` Git blob 的逐字节等价 hash；不伪造 JUnit 或声称事前捕获了这些 hash。

私有验收回执的 SHA256 `58a274a8453cc6c7e2572a4bdbfa65c578eaf10a7a1c92d06a2f0fe4c92b8133`。原件不随源码包发布。工作树有并行 collector、预检、平台及 UI 修改，本轮不代表整个发行包或全产品验证。

## 尚需闭合

新增 [发行出口矩阵](../tests/test_ai_egress_release_matrix.py) 已完成 **104 项通过、零失败、零跳过**；它与上述原 61 项分开记载，不倒改原工具结果转录。

| 新矩阵层级 | 用例数与准确范围 |
| --- | --- |
| 完整来源的业务引擎 | 32：diagnosis、security、vulnerability、focused × 四类 canary × 两适配。材料置于未投影尾部；无法分类类使用需要分类的字段中的非法值，不能将普通未投影文本的丢弃称为泄露 |
| SSH 来源投影 | 8：四类 × 两适配；直接调用严格来源投影，**不是完整 SSH 分析 API 或后台会话验收** |
| 最终提供方门禁 | 40：五 route × 四类 × 两适配；直接调用共享 provider 请求入口，**不是每个上层 API 的端到端证明** |
| 现有漏洞分析 API | 16：vulnerability/focused × 四类 × 两适配，TestClient、真实服务与分析引擎；合法准入后污染最终 body，并检查同一原 ID 不重发。这不是完整 main/浏览器验收 |
| 自动 focused 服务 | 8：OpenAI 兼容分支，四类 × 来源/最终 body。来源拒绝时没有 AI 预算意图；费用意图后阻断保留一个原意图，不重发。这不补作 Anthropic 自动流程验收 |

80 个核心格均先做有效配置和正常 Mock wire 对照，再检查阻断请求增量为零。四类是已知假 Key/令牌、合成 PEM、SQL/数据库 dump、无法分类字段。自动服务用例单独核对预算阶段；所有用例保持原执行权限，不提交 Root 动作。

本轮从启动前即保存固定 selector、45 个相关源码/测试 hash，运行中生成真实 JUnit，退出后重新取 hash。三个真实 transport 拒绝计数均为 0，各用例另有独立拒绝 guard 并在 teardown 检查无实际尝试；前后源码 hash 一致。没有读取部署凭据或联系真实供应方。矩阵文件 SHA256 为 `6d953aad02a130a67d4a58901380be7922ce7f9163d81436f15674399459cab0`。

以下安全验收原件私下保存，不随源码包发布：

- 真实 `junit.xml`：`87e07cb5198e482b35e45207e5da2cea29729bec4f1159b335f284ead2b8a4b8`。
- `started.safe.json`：`fae02a5337173fe084630cee682b9e898dd21b6d8766d62f737df64095c1713d`。
- `finished.safe.json`：`c78d7179caee013217422bea69fbd1e898b636d13c9432649adca65d77e41b0e`。
- 分层汇总 `summary.safe.json`：`abcb21fc0a351e44553fab0eb6d8520eaece0f70c06e5db70de5f889df886ce5`。

另有 [SSH 入口专项矩阵](../tests/test_ai_egress_ssh_entry_matrix.py)，独立完成 **32 项通过、零失败、零跳过**：两入口 × 两适配 × 四类 canary × 来源/最终 body，不与上面的 104 项合并解释覆盖范围。文件 SHA256 为 `29e3b4a3fde9de59632f803f3d5b9c1282986f2efdfa55de8a3de3cde3f5157a`。

| SSH 专项层级 | 实际验证范围 |
| --- | --- |
| 手动分析 HTTP route 与服务，16 项 | TestClient、真实登记 route 与 `DefenseAIService`，有有效认证和正常 Mock 对照；不是完整 main、浏览器或真实 SSH 验收 |
| 显式会话 AI 服务，16 项 | 使用真实 opaque session admission、会话 store 与 `DefenseAIService`；不是 coordinator/worker 的完整生命周期验收 |
| 两入口的来源层，合计 16 项 | 在未选中的候选中加入未知字段，真实 `source_time_bounds` 的严格 `DefenseSource` schema 拒绝整次来源，AI 意图/结果/动作均为零。四类内容均因这道结构边界拒绝，不能说成四种敏感内容检测器各自通过 |
| 两入口的最终 body 层，合计 16 项 | 在合法摘要后注入未知字段，由 adapter 转形之前的共享 `guard_request` 拒绝；保留一个失败分析和本地 `unknown` 费用意图，再读同一原分析不会重发、重置费用或产生动作。这是本地准入/配额状态，不是提供方账单 |

每格使用分开的正常与阻断 store，正常 Mock wire 为 1，随后阻断增量为 0；32 格合计正常 Mock wire 32。真实 HTTPX sync/async、Paramiko connect 和 `socket.create_connection` 拒绝计数均为 0；没有读取部署凭据或联系真实提供方。逐格安全记录、JUnit 原 node identity、七个相关源码文件和新测试的起止及当前 hash 已独立对照一致。

以下安全验收原件私下保存，不随源码包发布：

- 真实 `junit.xml`：`3ce44ae6d58d4c37da2b63cdde71396b0cd247d8eb33c6ba84058bb69ccf998e`。
- 含 32 个逐格安全记录 hash 的 `acceptance.safe.json`：`2ba0f10b604909d076afaf5ffd150187d5d55159e952270422595f29f9980191`。
- `source-before.safe.json`：`a4e47112daff0af52fb617edcd97af6fe9d30226b1224dd310f74233cf45aa28`。
- `source-after.safe.json`：`5a5d9556a4b1ee3b5a2b7575f648721e270b6aa9fa7bb5ba26ae74def981c600`。

同目录前两次运行原件仍保留：`attempt-1` 因测试夹具路径冲突停于 1 项失败；`attempt-2` 因测试对本地费用状态的预期不符，在已运行的 5 项中有 1 项失败。第三次修正测试预期后才是上述 32 项通过，不把前两次改记为产品通过，也没有修改生产门禁。

调查、安全分析的完整 main API、会话 coordinator/worker 的完整防泄密流程，以及更多提供方的真实接口，仍不能由这些合成测试推导。两个新增矩阵中的合成 PEM 标记均需独立整源复核，只能按对应路径和精确文件 SHA 登记包装例外；完整私钥块的拒绝和其余扫描规则保持不变。

这些记录不构成全产品、全部平台或真实模型的发行通过，不新增 AI 通道，也不扩大 Root 生命周期支持。缺少测试仍是覆盖缺口，不直接写成漏洞。
