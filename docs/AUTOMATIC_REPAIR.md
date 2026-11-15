# 预授权自动修复：配置、执行与验收边界

更新日期：2026 年 10 月 29 日。适用于 0.9 / 0.10 系列实现；实验时间使用 UTC。

0.12 增加可选的[自动 AI 候选审查、预算与告警](AUTOMATIC_AI.md)，并在两台新隔离环境完成后台全链路验收。本页保留早期确定性自动流程和 Root 合同；旧配置不会因升级获得自动模型调用许可。

本版把既有的扫描、单包计划、安装与验证连接成受限的后台流程。自动修复的权限来自部署者预先登记的目标、软件包、安全公告、UTC 维护窗口、有效期及配额。模型不提供执行权限，也不生成任意 Shell。

**实现与实机验收分别记录。** 0.7 已有半自动真实升级记录；本轮 0.9 另在既有宿主内、不公开端口的隔离 guest 上，使用真实扫描证据，自动完成一次计划、提交、安装与修复后验证。目标仅为 `libbrotli1` / `USN-8956-1`，有限 UTC 窗口内每日及累计各一次。两台物理宿主不启用 automatic，guest 结果不代表宿主漏洞清除。下文分别记录已完成结果和仍待实机对照的范围。当前没有 AI 提供方凭据，此流程不调用模型。

## 三种模式与权限

| 模式 | 当前行为 |
| --- | --- |
| `manual` | 可扫描、查看证据和方案，不提交新的修复任务 |
| `assisted` | 人工核对目标、精确变化及影响，批准当前有效计划后提交 |
| `automatic` | 后台仅对同时符合控制端与远端 root 预授权的单包候选准备、提交和跟进 |

模式选择和预授权是两份状态。`PUT /api/automation` 只保存并同步模式，不创建 grant、不扩大包或目标范围、不解除暂停，也不在请求内提交安装。有效预授权已存在时，后台随后可能按该模式运行，保存前应先核对范围。

未授权、到期、窗口外、配额耗尽、模式未同步及持续暂停分别显示。`execution_available` 说明执行驱动、配置和同步能力，不表示当前正处于维护窗口，更不表示已经安装或验证成功。

若已保存的模式显示待同步，在「能力」页读取当前状态，保持当前选项并点击「重新同步」。请求使用已保存的模式和修订号。若同步未确认，先重新读取状态再决定是否重试。同步后，仍有效的预授权可以按原窗口、证据和配额继续运行。

## 扫描与执行流程

定期观察器继续只读，不规划或提交补丁。独立的 `AutomaticMonitor` 使用已有补丁记录中的最新扫描；它不会自行扩大扫描范围。要持续获得证据，按[定期漏洞观察说明](VULNERABILITY_WATCH.md)明确启用对应目标，也可人工发起既有登记目标的扫描。

1. 后台核对模式、远端策略摘要、grant、窗口、剩余配额和目标暂停状态；有待核实的任务时先跟进原任务。
2. 只使用采集时间不超过 900 秒、目标与策略匹配的扫描。需要具体 finding 同时确认受影响、供应商证据新鲜、逐条证据完整及候选可修复；Pro 模糊待评估项不触发安装。
3. 按目标、作用域、finding、当前与候选版本形成稳定候选身份，保存后再向 root 准备不可变计划。
4. 再核对扫描、模式修订号、当前策略、grant 摘要、时效、完整单包事务、风险及重启影响。状态改变则等待新证据重新规划。
5. 在控制端持久保存提交意图、固定任务 ID 并占用配额，然后最多发起一次远端提交。root 使用自身策略和 UTC 时钟独立决定是否接受。
6. 持久 systemd worker 复验权限；进入 dpkg 前，APT 内钩子再次核验模式、授权、窗口、精确状态、完整协议 3 事务及软件包 SHA256。窗口关闭或授权到期可在安装前拒绝动作；已经进入 dpkg 的事务不会因窗口结束或模式切换被强杀。
7. 沿同一任务查询安装、同 finding 复扫、运行映射、dpkg、登记服务、HTTP 与新的 SSH 管理连接。`verified` 仅表示本任务覆盖项通过验证，不代表整机或所有业务均已安全。

控制端调度检查间隔为 5 秒，原任务状态读取间隔为 15 秒；本页可见时的 UI 状态读取为 30 秒。这些间隔不替代定期扫描间隔，也不是服务恢复时限承诺。修改任务串行执行；推荐以一个控制端进程、`--workers 1` 运行，跨进程租约只用于防止重复编排。

## 控制端配置

沿用 `OPSARK_INVENTORY`、`OPSARK_PATCH_INVENTORY` 和 `OPSARK_AUTOMATION_POLICY`。本版没有新增自动启用环境变量：应用构造自动监视器，但缺少明确启用的 `ControlPolicy.automatic` 时不会提交自动动作。模型凭据不是此流程的前提。

以下为**默认禁用的结构样例**，时间和摘要均为占位值，不能直接启用。为避免把样例变成实际授权，部署时必须用独立随机 grant ID、实际 UTC 维护时间以及审核安装后的远端策略摘要重新生成配置。

```json
{
  "enabled": false,
  "host_ids": ["opsark-brotli-lab"],
  "allowed_actions": ["os_security_upgrade"],
  "allowed_packages": ["libbrotli1"],
  "max_packages_per_job": 1,
  "allow_reboot": false,
  "allow_service_restart": true,
  "automatic": {
    "schema_version": 1,
    "enabled": false,
    "grant_id": "00000000000000000000000000000000",
    "issued_at": "2026-10-28T00:00:00Z",
    "expires_at": "2026-10-28T01:00:00Z",
    "host_ids": ["opsark-brotli-lab"],
    "allowed_packages": ["libbrotli1"],
    "allowed_advisories": ["USN-8956-1"],
    "target_policy_digests": {
      "opsark-brotli-lab": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "maintenance_windows": [
      {"weekdays": [2], "start_minute": 0, "end_minute": 60}
    ],
    "max_jobs_per_day": 1,
    "max_total_jobs": 1,
    "allowed_risk_levels": ["low", "medium"],
    "allow_service_restart": true
  }
}
```

控制端自动目标与包范围必须是现有授权范围的子集。每个目标必须对应一份当前远端 `policy_digest`。`grant_digest` 可在输入时省略，由 `AutomaticGrant` 校验后计算；若显式提供，必须与完整内容一致。修改 helper 源码、root 策略或目标能力会改变摘要，旧授权和旧计划不能沿用。

| 字段 | 校验含义 |
| --- | --- |
| `grant_id` | 32 位小写十六进制，标识此次明确授权；不能借换 ID 绕过每日次数或暂停 |
| `issued_at`、`expires_at` | 带时区时间，按 UTC 比较；开始含、结束不含，最长有效期 24 小时 |
| `host_ids`、`target_policy_digests` | 控制端绑定既有目标及各自的 root 策略摘要，不接收临时主机 |
| `allowed_packages`、`allowed_advisories` | 精确的原生包名和 USN 允许名单；当前每个计划只允许一个包变化 |
| `maintenance_windows` | 1–7 个 UTC 窗口，`weekdays` 为 0=周一至 6=周日；分钟表示当天时刻 |
| `max_jobs_per_day`、`max_total_jobs` | 1–5；首次实验均为 1。控制端每日用量按目标跨 grant 累计，总量按 grant 累计 |
| `allowed_risk_levels` | 仅允许显式的 `low` / `medium`；`high`、`unknown` 均不能自动执行 |
| `allow_service_restart` | 可能发生服务重启时必须额外明确允许；同时仍受上层策略限制 |

窗口开始含、结束不含。`0 → 1440` 明确表示全天；`1380 → 60` 表示 23:00 至次日 01:00，按开始日的星期授权。空窗口与重复星期拒绝。不能用本机时区或浏览器时钟代替 root 的 UTC 判断。

## 远端 root 独立授权

先按[修复入口部署说明](../deploy/vulnerability/README.md)审核安装更新后的 root helper。原策略的 `automatic` 字段需由管理员单独登记；控制端不能通过 API 写入这份文件。物理宿主应省略该字段，或保持其 `enabled:false`。

以下也是**禁用的配置片段**，合并到既有 root 策略 `/etc/opsark/patch-policy.json`，不能替代完整策略：

```json
{
  "automatic": {
    "schema_version": 1,
    "enabled": false,
    "grant_id": "00000000000000000000000000000000",
    "issued_at": "2026-10-28T00:00:00Z",
    "expires_at": "2026-10-28T01:00:00Z",
    "allowed_packages": ["libbrotli1"],
    "allowed_advisories": ["USN-8956-1"],
    "maintenance_windows": [
      {"weekdays": [2], "start_minute": 0, "end_minute": 60}
    ],
    "max_jobs_per_day": 1,
    "max_total_jobs": 1,
    "allowed_risk_levels": ["low", "medium"],
    "allow_service_restart": true
  }
}
```

两端 JSON 形状不同。root 已绑定所在机器，不接收控制端的 `host_ids`、`target_policy_digests` 或 `grant_digest` 字段。**root grant 必须由同一份经过校验的控制端模型投影生成，不能分别手拼。** 在具备 OpsArk 控制端依赖的暂存环境中，以 `policy` 为已经校验的 `ControlPolicy` 对象，生成以下值再合并到对应 root 策略：

```python
root_grant = policy.automatic.model_dump(
    mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
)
```

投影会统一 UTC 时间的 `Z` 表示，以及已校验的允许名单与星期顺序。root 保留收到的 grant 内容，并对规范化 JSON 计算摘要；控制端严格校验该投影的完整摘要。手写 `+00:00` 或调整数组顺序，即使时间或集合含义相同，也会得到不同摘要而拒绝计划。字典键的顺序由摘要算法处理；不能手工改写投影字段或复用旧摘要。

控制端 `grant_digest`、root grant 摘要及完整 root `policy_digest` 各有用途，不能互换。先生成投影、审核安装 root 配置并取得新策略摘要，再更新控制端目标登记与 `target_policy_digests`；后者属于控制端字段，不改变已生成的 root grant 投影。重新校验控制端模型、读取并同步模式后才具备执行前提。远端系统 Python 不需要安装控制端依赖，投影在暂存环境完成。

root 的 `automatic_policy.py` 独立限制有效期、UTC 窗口、包/USN、风险、服务重启、每日/总配额与持续暂停。准备计划、接收提交、worker 开始及 APT 内安装前核验都不能由调用者声明的“已验证”标志替代。任何一层拒绝都不能通过放宽 APT 信任配置、改写风险级别或重复发新任务 ID 绕过。

## 持久化、未知结果与暂停

控制端 `OPSARK_DATA_DIR/automatic.sqlite3` 保存候选身份、提交意图、任务 ID、配额和目标暂停；原扫描和远端任务缓存仍在补丁存储中。当前控制端备份白名单为十个数据库，包含 `automatic.sqlite3` 和 `vulnerability-ai.sqlite3`，完整列表见[常驻部署与迁移](../deploy/observer/README.md#迁移与停止)。远端 `/var/lib/opsark-patch/jobs/` 保存实际工作记录，`automatic-state.json` 保存 root 持续暂停。备份和恢复须保留这些记录以及已有模式、补丁和观察数据库；不能通过删除数据库、换授权或重建容器清空用量。

后台每 30 秒对明确的 grant 目标读取一次 root 自动状态，缓存绑定目标作用域、策略摘要和 root grant 摘要。新自动提交仅接受 60 秒内、范围一致、权限/窗口/暂停及用量均已核实的缓存；缺失、读取失败、过期或摘要不符均停止新提交。用量按控制端与 root 所见的较大值核对，未知不得按零放行。root 曾记录暂停时，将原原因、任务和时间持久保留到控制端，后续读到未暂停或任务成功也不自动清除本地暂停。`GET /api/automatic/status` 只读这些缓存，不发起 SSH；UI 刷新不触发远端调用。

提交意图占用次数后，即使 SSH 超时、回执丢失、结果未知或安装失败，也不退回配额。不确定时固定原任务身份，只读查询；无法证明请求未送达时不会重发安装。每日用量以 UTC 日期计算，换 grant 不能清除当日用量。

`unknown`、`failed`、`rejected`、`verification_failed`、`reboot_pending`、`installed_restart_pending` 等结果会持续暂停目标；远端还保留超时状态的拒绝约束。切换模式、新扫描、更新 grant、控制端重启，或原任务后来查询为成功，均不自动清除既存暂停。已从当前目标清单移除的暂停仍显示在状态中。

0.9 不提供解除暂停的入口；0.10 新增经明确人工批准的恢复预检与回执，不提供无条件清状态按钮。管理员先核对原任务、真实 APT/dpkg 状态及业务，再批准当前有效预检；不能把删除状态文件作为恢复方法。模式切回手动只停止新的自动提交，已经进入安装的任务继续完成并保留结果。

### 0.10 原任务对账与人工恢复

恢复只适用于原自动任务已经明确 `verified`，但丢回执或既往超时使控制端、Root 仍保持暂停的情形。真正 `failed`、`rejected`、`unknown`、重启待办、其它未结算事务或缺少原始文件清单时，继续阻断；不会把原失败任务改成成功。

界面在当前手动模式、同步完成且目标仍获部署策略许可时，开放“核对恢复条件”。预检绑定目标/源码/策略、模式修订、原任务修订与摘要、具体暂停及控制端上下文，最多五分钟有效。Root 读取新的包版本、可信 APT 状态、同 finding 供应商证据、安装前与当前文件的运行映射、dpkg、登记服务和 HTTP，并确认无重启待办；不满足时只显示阻断原因。

人工勾选并确认这份预检后，才提交固定恢复 ID。Root 还要求验证后的新 SSH 连接，在所有慢检查后复读包与源摘要、任务、账本、策略和暂停，并用同一次最终决策时间检查期限及生成完成回执。版本、状态或授权变化、回执过期及新增暂停均不能放行。Root 执行器的九文件 pin、安装前文件清单及底层 RPC 见[修复入口](../deploy/vulnerability/README.md#人工对账与恢复暂停)。

恢复批准不会切换模式、创建授权、返还配额或重新安装。不可变 Root 回执覆盖精确的旧任务修订及摘要，保留原 bad history、暂停和计数；控制端核对回执以及新的 Root 状态后才将该次本地暂停标为已对账。迟到的同一旧暂停不能重新激活已解决记录，新坏任务或新的不安全修订仍会重新暂停。

恢复确认本身结果未知时，也只查询原恢复 ID，不重发确认、不换 ID 重试；`recovery_prepared` 仅表示预检存在，不等于恢复完成。控制台记录恢复历史，并分别显示 Root 结果与本地对账是否完成。相关接口为受保护的 `POST /api/automatic/recovery-plans`、`POST /api/automatic/recoveries` 及同一恢复 ID 的 GET 查询；状态读取不会自行批准恢复。

## 状态接口与控制台

`GET /api/automatic/status` 要求控制台 Bearer 认证。返回 `enabled/running/mode/mode_revision/mode_sync_complete`、非秘密 grant、每目标状态、窗口、到期、配额、原任务与持续暂停，以及最近自动任务。`capabilities.automatic_repair=true` 表示实例提供该接口，不能作为某目标已获授权的证明。

| 状态 | 需要如何理解 |
| --- | --- |
| `disabled`、`manual` | 无有效自动授权，或当前模式不提交自动任务 |
| `mode_unsynced` | 停止新提交，等待远端模式同步 |
| `outside_window`、`expired`、`quota_exhausted` | 分别为窗口外、授权到期、次数耗尽；不因此放宽权限 |
| `waiting_scan` | 尚无满足时效和逐条证据门槛的扫描，不表示安全 |
| `planning`、`tracking`、`idle` | 正在规划、跟进原任务、等待后台检查；均不表示修复成功 |
| `latched`、`error` | 持续暂停待核实，或后台读取未完成；保留原因和证据缺口 |

配额未知以 `null` 返回并显示“未知”，不得按零使用放行。普通刷新只通过 GET 读取状态，不提交自动安装或批准恢复；0.10 的恢复按钮需在手动模式下核验并明确批准，人工补丁安装仍走 assisted 通道。接口失败时标明历史快照，退出后清除页面内存中的 grant、任务和未批准恢复引用。当前通知仅为控制台记录，没有邮件、短信或其他外部推送。

## 本轮实机结果与待验收项

2026 年 10 月 28 日，第二台 VPS 的常驻控制端通过预授权自动流程完成以下任务；这是独立于 0.7 半自动任务的新安装记录。

| 项目 | 已观察结果 |
| --- | --- |
| 目标 | 第二台宿主内部的 `opsark-brotli-lab`；`evidence_origin=controlled_lab`，无公开实验端口 |
| 修复范围 | `libbrotli1`，`USN-8956-1` / `CVE-2026-111497`；`1.1.0-2build2 → 1.1.0-2ubuntu0.1` |
| 预授权 | `2026-10-28 15:26:13Z` 至 `16:26:13Z`；每日及总提交各一次；明确允许 `medium` 风险及可能的服务重启，不允许主机重启 |
| 模式与任务 | `automatic` 修订 12；任务 `1d59f9744db18c37dc35d00f69b5249b`，最终 `verified`、修订 7 |
| 安装与完成 | 安装退出码 0；`15:29:29 UTC` 完成最终验证，hook 的预期事务 SHA 匹配，实际 dpkg 升级记录为一次 |
| 修复后验证 | 精确版本通过、同 finding 供应商复扫通过、运行时检查完整且无旧映射；dpkg、SSH/Nginx 服务、HTTP 200 及验证后新 SSH 均通过；无新增主机重启待办 |
| 通知与配额 | 一条控制台完成通知；控制端和 root 均报告每日及总用量 `1/1`，后续状态为 `quota_exhausted` |
| 控制端重建 | 相同镜像重建后容器 ID 改变，guest 未重启；仍为原任务 `verified`、修订 7，通知、自动意图、root 自动任务及本任务 dpkg 升级均各一条，双侧用量仍 `1/1` |
| 重建隔离与证据 | loopback 发布、只读根文件系统及 guest 私网保留；原任务历史和已核验主机记录 SHA 不变 |
| 收尾模式 | `15:34:40 UTC` 保存 `manual` 修订 13，HTTP 200、`mode_sync_complete=true`，三个登记目标均确认同步 |
| 物理宿主 | 两台物理宿主的 automatic 均保持禁用 |

供应商复扫只证明本次目标 finding 已不受影响；整体覆盖仍为 `partial`，存在 Pro 数据不可用及 USN 时间窗限制，不能据此声称 guest 或宿主没有其他漏洞。安全汇总留在本轮交接目录的 `automatic-20261028/status.safe.json`、`proof-before-restart.safe.json`、`proof-after-restart.safe.json` 和 `manual.safe.json`；原任务、此前两条历史任务和 root 安装审计均保留。此次验证的是控制端容器重建，未重启 guest 或物理宿主。

本轮部署重建时依次加载 `compose.yaml`、`compose.lab.yaml` 和部署端 `compose.release.yaml`；第三份固定已审查的构建镜像，第二份保留 guest 私网。后续重建沿用这三份文件，完整命令见[常驻部署说明](../deploy/observer/README.md#可选漏洞观察与补丁入口)。

### 本地验证

已完成 Chromium、Firefox、WebKit 各 8 组合成界面契约，覆盖授权/无授权、跨日 UTC 窗口、未知配额、到期/窗口外/同步/耗尽状态、模式切换保留暂停、历史目标暂停、状态失败、只读轮询、会话迟到响应及文本注入；新增 root 缓存/历史快照、未知用量、30/60 秒条件和 root 暂停覆盖错误 idle 显示。宽度为 1440、1024、768、390、320 像素。合成测试不联系服务器、不调用模型、不提交真实安装。

### 实机 Root 授权与持久化负向对照

2026 年 10 月 28 日 `16:03 UTC`，在第二台授权 VPS 的独立 root 私有目录运行了以下对照。被测程序使用已安装的八份 Root 源码副本，复制前后核对 SHA256；只在测试进程中把 `STATE/LIB/POLICY` 指向该目录。时间来自真实系统 UTC，没有修改系统时间或替换时钟；文件权限、原子写入和 Linux `flock` 使用实际实现。

**这是使用合成授权、计划及任务状态的实机 Root 函数、文件与锁对照，不是 SSH/APT 端到端实验。** 构造的“受影响”“可修复”和任务状态只用于检查授权分支，不是新的供应商漏洞证据，也不表示真的发生了安装失败或超时。

| 对照 | 已观察结果 | 验证边界 |
| --- | --- | --- |
| 有效授权自然到期 | `16:03:09.137209 UTC` 仅授权函数检查通过；grant 在 `16:03:12.118792 UTC` 到期，`16:03:12.273019 UTC` 的提交函数链以 `Root automatic grant is not currently valid` 拒绝 | 计划仍在有效期内；没有提前提交安装，没有新建 job，计划文件不变 |
| 有效授权但窗口外 | grant 仍有效，窗口明确设为次日；`16:03:12.288146 UTC` 以 `Outside the preauthorized UTC maintenance window` 拒绝 | 验证已关闭配置的拒绝，不等同于真实安装过程中跨过窗口边界 |
| unknown 后转 verified | fixture 任务先写入 `unknown`，持久保存暂停，再转成 `verified`；新提交仍以持续暂停拒绝 | 状态为人工构造，未中断真实任务；暂停文件内容与 SHA 保留 |
| overdue 后转 verified | fixture 任务经过 `running_overdue → verifying → verified`；新提交仍以持续暂停拒绝 | 未制造真实 APT 超时，也没有终止任何安装进程 |
| 跨进程、模式和新授权 | 初始进程 PID `280040` 退出后，PID `280127` 在 `16:03:32 UTC` 重新读取；fixture 切到 manual 时拒绝旧方案，换新 grant 并重新选择 automatic 后仍因原暂停拒绝 | 两个暂停文件 SHA 不变，当日用量保留；没有清账本。新 grant 的累计用量独立计算，不能表述为旧累计计数迁移 |
| 实际 Linux 锁争用 | 四份 fixture `rpc.lock` 均为 root 所有、模式 `0600`；第二个独立文件描述符不能同时获得排他锁 | 检查的是隔离目录中的真实内核锁，不占用现有修复任务的锁 |

每个 runner 都先安装执行屏障，禁止外部命令、网络连接及向隔离目录外写入；无害命令探针确实在启动前被拦截，各负例没有额外命令请求，**屏障内实际启动的外部命令为 0**。原生 SSH 引导各启动一次系统 Python runner，属于测试引导，不计为 APT 或运维动作；这个计数不表示没有启动 Python。

该物理宿主现有的策略、模式、任务、计划、八份执行器源码和 dpkg 状态指纹在前后及两个进程间一致。既有 guest、一次性配额及常驻 `manual` 修订 13 未改动，没有新建 guest、执行 APT 或调用 systemctl。证据保留在私有交接目录的 `receipt-20261028/negative-gates-initial.safe.json`、`negative-gates-resume.safe.json` 和 `negative-gates-complete.safe.json`；远端隔离目录保留，未删除测试账本或暂停记录。

### 0.10 真实故障注入与人工恢复

以下对照在第二台授权 VPS 内新建的三份独立、无公开端口的 guest 上执行；使用真实 SSH、APT、systemd 与真实旧 Brotli 包。原先已消耗一次配额的 guest 没有重新种漏洞或清账本。故障工具只在这些新作用域中使用，说明见[实验环境](../deploy/vulnerability_lab/README.md#010-受控故障注入)。

| 层级与场景 | 已观察证据 | 结论边界 |
| --- | --- | --- |
| 实机 SSH/APT：安装提交回执丢失 | 任务 `057af3020efd8a480653b3255a7c013a` 已被 Root 接受后，包装器保存实际回执但不发送；控制端记录未知并暂停，随后只查询原任务 | 不是在提交前切断握手，也没有伪造成功；原始回执与请求记录单独留存 |
| 实际安装超过 300 秒 | 仅一次 unpack 延迟 310 秒；`17:48:29 UTC` 进入真实 `running_overdue`，随后继续完成安装及验证至 `verified`、修订 8。安装期间控制端重建，未重发安装 | 证实不会因超时或控制端重建强杀安装；任务成功后 Root 的 overdue 暂停和本地 unknown 暂停均仍保留 |
| 真实 UI 人工恢复 | 切到该实验控制端的 manual 修订 2，具体预检无阻断，人工勾选后批准恢复 `a116333f2bb0ffa96617b8fa1f97fb43`；Root 回执完成于 `17:56:35 UTC`，在五分钟预检期限内 | 当前版本、同 finding、运行时、dpkg、登记服务/HTTP、无重启待办及新的 SSH 均重新核验；不重写原任务结果或重置用量 |
| 恢复提交回执再次丢失 | Root 已写入恢复回执后故意不发送，界面先保持 `unknown` 和本地暂停；随后 GET 同一恢复 ID 得到 Root `verified` 回执及新状态，本地对账完成 | 界面只发出一次确认请求，回执未知期间不再确认、不换 ID。真实后端界面无脚本错误，已检查 1440/390 像素宽度 |
| 实机 APT 钩子：授权到期 | `5290d19d904cbf7d48c30a182ed67b7b` 在 grant 有效期内提交并进入 `applying`；grant 于 `17:50:00 UTC` 到期，原 `pre_install.py` 实际在 `17:50:02 UTC` 执行后拒绝，APT 退出 100，任务 `failed`、修订 5 | 被测包仍为 `1.1.0-2build2`，`dpkg --audit` 无输出；失败和已用配额保留，不声称修复成功 |
| 实机 APT 钩子：窗口关闭 | `efca8203fd118637c183891f2eb8ba91` 在窗口内提交并进入 `applying`；窗口在 `17:52:00 UTC` 关闭，原钩子于 `17:52:02 UTC` 执行后拒绝，APT 退出 100，任务 `failed`、修订 5 | grant 本身仍有效，隔离了窗口拒绝条件；包版本仍为旧版。`applying` 不等于 dpkg 已发生写入 |

此处时间为 `2026-10-28 UTC`；扫描总体仍为 `partial`，具体同 finding 修复验证通过不能代替全量漏洞评估。主安装任务的未知通知及最终验证通知分开记录，不因重建或恢复重放。原任务、Root 暂停历史、安装前文件清单、故障回执和恢复回执均作为独立审计证据保留。

私有证据位于本轮交接目录的 `recovery-20261029/`：`api-proof.safe.json`、`api-status.safe.json`、`real-ui-recovery.safe.json`、`ui-real-preview.safe.json`、`ui-real-confirm-unknown.safe.json`、`ui-real-query-verified.safe.json`，以及 `expiry/`、`window/` 下的授权与钩子记录。清理、停止状态、正式常驻发布和 CI 应以最终汇总分别确认，不能由以上局部记录推定。

### 仍需独立验收的范围

- 真正失败、一直未知或带重启待办的任务如何由管理员修复并形成新的处置证据；本版不无条件解除这些暂停。
- guest 或物理宿主重启、服务器故障和更长时间负载运行；已完成的控制端重建不能替代这些对照。
- 其他包、发行版和工作负载、更多业务验收、资源测量，以及模型和外部告警实际联调。

应用依赖、容器镜像、内核、数据库迁移、Nginx 配置修复、自动封禁及完整回滚仍需各自的适配与验收。单包升级也可能触发维护脚本和服务变化，本版不承诺降级能恢复所有配置或数据。
