# 控制台、真实 SSH 和真实模型联合验收

2026-11-06 在两台授权 VPS 的全新隔离环境完成。控制端源码为 `e97e8083fd5979c4af4542fcfd96a5903bbcc115`；远端九文件 LF 闭包来自 `e236e3bc322a7bc2676e8b8781111b863313a6c2`，压缩包 SHA256 为 `7e321f91933830aa645a9c5536d7d3ce2898e5a5505cb88b67cc4ad8e6cbdd5e`。五个 Root 模块保持[原请求协议实验](../defense_requests_lab/README.md)的源码身份。

## 实际流程

每台分别创建新 target、候选、管理和对照容器，以及独立角色密钥、Root scope、观察/执行许可和本地十库。常驻十库和服务器配置未复制；模型复用已授权的兼容接口，实验输出预算为 512 tokens，原 provider 文件未修改。真实 Chromium 访问 loopback Uvicorn，使用正式配置加载器、认证、API、事务库、AI 出站门禁和生产 `DefenseClient`，没有 FakeRoot、响应 mock、替换生产 invoker 或拦截浏览器 API。

1. 明确切换半自动模式并完成真实 Root 同步。
2. 从界面确认一次 120 秒观察，由候选生成五次不同源端口的真实认证失败，查询原 cursor。
3. 预览白名单并确认一次真实 OpenAI 兼容模型调用。模型实际返回合法处置建议，独立费用使用一次。
4. 通过真实角色 SSH 准备一份清单，从界面核对 SHA256 和模式版本后批准一次执行。
5. Root 完成实际 nft 动作并持久化后，测试 wrapper 仅截断 apply 的原 SSH socket。准备回执正常返回；原请求 hash 与 native socket marker、action/cursor/manifest 绑定逐项相同。
6. 首个 Uvicorn 生命周期真实停止，在**同一个 Python 进程**内用同一配置和十库创建第二个应用实例。重新登录，选择已有原任务，经新的只读 SSH 查询确认 active，再单独确认撤销。
7. 重新打开旧历史，保留 apply 未确认、新 query active、revoke 和原 AI 费用。unknown latch 保留，未开放后续新动作。

两侧各只有一个 cursor、一个 action、一次模型 HTTP、一个 Root intent 和一次 Root 使用量。模型发送前观察器验证完整白名单并委托原始 `AsyncClient.send`；只记录次数、HTTP 状态和摘要 hash。两台发送文档的规范化 hash 相同，正文仅含临时候选/证据别名、分类、计数、固定 60 秒 TTL 和省略数，没有各自的地址、Root 引用、原始日志、配置或凭据。

## 证据

| 目标 | 浏览器安全记录 SHA256 | 原生生命周期记录 SHA256 |
| --- | --- | --- |
| 第一台 `试验机 B` | `31e34657419b1c929f22d502a6c0c3c45fe35444baa40cfc45b38958f7ff4fc7` | `6090cefd9b96c0b165e2b0d6c5b2feb3e2886d94d66bcb2f92a8eb2f60ecc4b3` |
| 第二台 `试验机 A` | `9e25e094182fc8fdadb6652e4ebc493eb41346d0432f4ae6d2fb7e3f2305b410` | `7fd5838cfe15f8ac58439663aa32de812af44d4aa95c11fa7fefe484b137ff72` |

规范化模型请求文档 SHA256：`cb3f0b84e6e8e441ca09e71f0e5aeac30677f6aab0a37b7d97e9d7128b2a17a6`。每侧都记录 HTTP 200、完整合法的 AI 结果和原费用 consumed；headers 到达耗时单列，不当作完整生成耗时。

汇总 `acceptance.safe.json` SHA256 为 `2512ef3e910dc31fdf138e8ff135c4396080e4b89dad62577a124df9f61c8c45`，保存在忽略的本地验收目录。汇总将浏览器、operator、native、原请求绑定和清理记录逐项连结，包含两份原有容器状态完全一致的核验。早期三个失败阶段也单独保留，不合并成通过：模型调用和 Root 动作均为零。

## 验收驱动与隔离

- `tests/ssh_defense_controller_lab.py`：管理员启动固定 `serve --root <新私有目录> --image sha256:<缓存镜像> --proof <新文件> --confirm-isolated`；发布 Root-private ready 信息和不透明的新测试 key 路径。`status/stimulate/snapshot/health/stop` 只接受固定操作和原命令 ID。刺激在整个 fixture 中只允许一次，重复查询读取原结果。
- `tests/defense_native_relay.py`：`RelayScope` 绑定完整容器/网络/image ID。固定本地 `127.0.0.1:22423` 经管理员持有的外层 SSH channel，执行固定管理容器代理连接 `.4→.2:22423`。每连接先重新核对真实 Docker 身份、网络、挂载、capability 和资源。生产内层 SSH 仍独立核对角色和公钥 pin；不公开远端宿主端口、不挂 Docker socket，不自动重连。
- `tests/browser_defense_native_smoke.py`：`run_native_browser(settings, stimulate_after_arm=..., snapshot=..., health=..., proof_path=...)` 使用正式登记和三个固定的原生回调。provider 文件只由受控程序不透明加载，API key 保持独立文件引用。凭据内容不进入终端、proof 或模型正文。

四个容器均为每个 `0.5 CPU/192 MiB RAM/192 MiB RAM+swap/96 PID`，唯一 internal 网络为 `198.18.241.0/28`。target 的九项 capability 与旧实验相同，客户端 cap-drop ALL、只读和 no-new-privileges；无 host network/PID/设备或宿主端口。新驱动固定工作预算 480 秒、清理预算 120 秒，容器硬限 600 秒；Root grants 仍按创建后 300 秒，cursor 120 秒、动作 TTL 60 秒。旧驱动的 180 秒没有改变。

relay 本地每连接 30 秒、最多四个并发/32 个总连接；远端 inspector、proxy 与外层 timeout 各有独立硬限。它不承诺所有远端子进程都在本地 30 秒时立即退出。每个实际联合用例只使用 12 个内层连接，结束时 active=0、线程和外层 channel 关闭。

## 实机发现及修复

第一轮暴露了生产客户端提前释放 Paramiko stdin wrapper 的问题：析构会先发送 EOF，Root 尚未收到 JSON 即退出。真实 Paramiko 文件对象回归先复现失败，客户端改为持有三个流直至发包、读完和最终清理。旧假流测试未覆盖此行为。

后续原生证据触发跨时钟校验失败：Root 截止时间减控制端观测时间约 129.404 秒，本地不可变窗口实际尚余 105.618 秒；两份截止时间差约 23.786 秒，包含主机时钟与 SSH/arm 延迟。新实现由可信原账本派生不透明时间边界，只在同一本地时钟上核对 created/observed/now/deadline 的 120 秒硬限，并使用固定 30 秒 deadline displacement 一致性预算。Root 原始时间、回复 hash、Source 字节和费用/proof 身份不变；Root 自身 monotonic 窗口和 UTC 审批也不改。该预算不表示精确时钟偏移，超出即拒绝；Root 落后的半自动审批仍可能保守拒绝。

跨应用测试另修复了本地 unknown 历史详情错误返回 503 的问题。读取持久历史保持 200，并保留 query_required；实际远端操作未确认仍返回 503。421 项时间及关联回归、17 项浏览器驱动假数据回归与独立边界复核通过，各自的范围单独留证。

## 保留边界

管理 SSH、对照 SSH 和同源 HTTP 在执行前和撤销后现场探测通过。这些是管理员验收回调；产品的独立业务复验入口和客户交接摘要尚需接入此防护任务类型。此轮没有在 active 阶段另测候选 SSH 超时，相关固定 Root 动作的阻断/TTL 证据仍引用此前独立原生实验。

本轮重建了应用实例，Python 和宿主进程均未重启；不覆盖断电、路由失联或 intent 中途崩溃。持续工作器保持关闭，自动观察许可轮换、自动跟进和人工恢复尚需后续交付。当前仍为固定私有隔离 profile，不能宣传为公网全面防御、WAF 或 DDoS 清洗。

两台运行资源及本轮全部五个服务器私有阶段目录已清理，公用工具镜像保留作后续实验。本地隔离历史保留，常驻版本、配置、历史、模式和权限未改变。
