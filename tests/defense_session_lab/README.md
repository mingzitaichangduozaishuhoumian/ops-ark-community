# 单次自动会话的独立实机实验入口

`ssh_defense_session_lab.py` 在原 business SSH 实验之上只增加两个固定配置：

| 配置 | 授权 | 回执行为 |
| --- | --- | --- |
| `auto-ack` | 全新 auto / wire revision 2 / max uses 1 | 原生 Root control，直接接收回执 |
| `auto-apply-loss` | 同样的全新单次授权 | 原身份绑定的精确 SSH socket 中断 |

两者均在任何容器或 Root 请求 ledger 初始化前封存配置，不迁移、重置或重放已有授权。旧 14 文件逐字节固定，只新增本入口为第 15 文件；ready 与生命周期 proof 同时绑定配置和源码摘要。原五个 Root 文件、四个只读节点、三处目标挂载、四容器资源限制和 mailbox 预算保持原范围。

生命周期 proof 的 `completed` 仅证明实验服务退出并清理资源。是否真正自动执行成功，必须由浏览器和原 ledger 独立核验：

- 浏览器只进行 mode、arm 和单次会话 start；prepare/apply 来自正式后台 worker。
- 正常配置需要原 prepare/apply 的直接 accepted 回执；丢失回执配置保持 reconciliation_only，后续只读 query 不能把它改成 completed。
- 实际两个控制端 Python 进程使用同一原任务和历史；新 owner 不接管发送、不重付 AI 费用。
- 规则配置模型调用为零；真实模型配置另外核对发送层次数、白名单输入摘要和原 permit/proof，不把 fake 模型结果当成实机调用。
- 未独立业务复验时摘要始终待验收，不包含原始日志、凭据或数据库内容。

2026-11-06，两台授权测试机均完成以下三个独立场景：

| 场景 | 每台实际模型调用 | 会话最终状态 | 重启后的操作 |
| --- | --- | --- | --- |
| 规则 + 正常 ACK | 0 | completed | 仅查询原 RID |
| 真实兼容 API + 正常 ACK | 1 | completed | 仅查询原 RID，不再调用模型 |
| 规则 + 真实 socket 丢 ACK | 0 | reconciliation_only | 仅查询原 RID，保持原会话状态 |

六份成功验收各使用两个真实 Python 进程；浏览器仅 mode/arm/start，正式 worker 每份 prepare/apply 一次，Root usage/intent 各一。模型总调用两次，发送层白名单摘要与原 input/permit/proof/consumed fee 独立闭合。全部没有业务复验或人工撤销，摘要继续待验收。

Controller 分别固定于 `400262dfd3c998d08a67c557335cb813e3ecac94` 和 `32b6724068e48b2d523252317c51783d5ea03945`。两者生产源码、网页和其余驱动文件一致，后者只修正验收驱动的原生 `fault_layer` 字段及其回归，逐场景记录真实提交，没有合称同一次构建。15 文件归档 SHA256 为 `89f698284cda12eec00524387f4d389c01b09b539c58d570c7f597f6dc3a8d69`，新增入口 SHA256 为 `4e167b3e528b8be2b3e2eadc332574d32b67510d2ac456c7cb3999db7b53e6a1`；旧 14 文件和五个 Root 节点不改。

另保留 `试验机 A` 首轮丢 ACK 的失败报告：实际动作已执行一次，驱动因读取错误字段而停止验收，没有启动第二进程或重跑原任务。修正后另建全新 `rule-second-r2-loss` 场景验证，原失败不会被成功结果覆盖。

七轮实验各自监督 PID 均已终止；实验容器、网络、私有阶段目录全部清理，原有容器状态与基线一致，缓存工具镜像保留。源配置、role key 和数据库未上传仓库或模型；原生安全证据仅归档固定 JSON 白名单，不复制原始日志或密钥。合成控制端的私有本地历史及凭据引用保留，常驻实例配置、历史和权限未改。

汇总 `acceptance.safe.json` SHA256：`6489095c816bc2e8b02dea2bd2509a2e5f1ae9b91dae747252424f2a03aa0771`。记录位于本地忽略目录 `data/defense-session-native-20261106`，包含六份通过、一份保留失败和逐场景的证据哈希；不把生命周期 completed 当成业务通过。本地固定版本联合回归 368 项及后续驱动回归 33 项分别通过；最新 GitHub jobs 因账户账单/额度未启动，未记作跨平台 CI 通过。

本轮不覆盖真实 AI + 丢 ACK 的组合、业务复验、Root 传输/容器/宿主重启、长期授权或公网防御。常驻实例不因这些测试而升级或扩大权限。
