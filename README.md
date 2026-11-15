# OpsArk

OpsArk 是面向个人站长和小团队的自部署 VPS 运维工具。它可以只读调查故障、持续观察已登记的主机与站点，也可以在授权范围内执行变更并验证业务恢复。调查报告保留采集时间、证据、候选原因和待核实项，客户交接摘要按实际证据标记验收状态。

一次完整的处理流程是 **接入预检 → 收集证据 → 预览并批准处置 → 核对原任务 → 只读复验 → 导出摘要**。可以从只读调查开始，按实际需要启用后续功能。

## 开始试用

**先跑本地合成样本。** 网站 502、磁盘异常和容器反复重启都可以在本机回放。Windows 和 Ubuntu WSL2 已完成首次安装、样本回放和重启读回。试用只需 uv、浏览器和下载依赖的网络，无需 VPS、SSH、Docker 或模型密钥。

从发行页下载试用公告标明的源码 ZIP 附件，核对 SHA-256，再解压到新目录。安装 uv，在含 `pyproject.toml` 和 `uv.lock` 的源码根目录打开一个没有 OpsArk 部署变量的新终端。首次同步会下载锁定依赖，也可能下载 Python 3.13。 [试用发行页](https://github.com/mingzitaichangduozaishuhoumian/ops-ark-community/releases) · [uv 安装说明](https://docs.astral.sh/uv/getting-started/installation/)

```console
uv sync --locked --no-dev --python 3.13
uv run --locked --no-dev python -m uvicorn opsark.main:app --app-dir src --host 127.0.0.1 --port 18190 --workers 1
```

打开本地控制台，用首次启动生成的 `data/access-token` 解锁。选择「本地样本回放」中的网站 502，点击「运行只读调查」，再下载 `opsark-handoff.md`。样本摘要会显示「待验收」。重启控制台后，可以从「最近报告」重新打开原报告并下载摘要。 [本地控制台](http://127.0.0.1:18190/) · [首次运行与故障排查](docs/COMMUNITY_TRIAL.md)

## 调查与接入

接入真实服务器时，先核对 SSH 主机指纹，使用独立的专用账号和受限只读入口，登记站点或容器后运行预检。预检逐项显示系统、工具、服务和权限缺口。 [SSH 登记与预检](docs/RUNNING.md#登记-ssh-主机) · [服务端只读入口](deploy/readonly/README.md)

| 场景 | 报告与证据 |
| --- | --- |
| 网站 502 | 关联 Nginx、登记上游、监听端口和容器状态。启用站点日志窗口后可查看上游拒绝连接和超时计数，采集缺口会随报告显示。[Nginx 日志窗口](deploy/readonly/README.md#nginx-错误日志窗口) |
| 磁盘异常 | 查看可用空间和 inode，比较同一登记范围的增长。根据文件类别和占用证据给出条件回收估计，包括已经删除但仍被进程持有的文件。[磁盘证据](docs/DISK_RECLAIM_EVIDENCE.md) |
| 容器反复重启 | 关联退出码、OOM 标记、重启次数和状态。具备同范围历史基线时，比较容器、镜像和 Compose 配置变化。[容器调查与复验](docs/RUNNING.md#容器调查业务复验) |
| 应用依赖 | 在已授权的 Compose 项目中查找服务和端口候选，由操作者确认后再登记。将 Nginx 磁盘配置里的站点和上游与已登记服务关联，并标记共享关系或未知项。[Compose 发现](docs/COMPOSE_DISCOVERY.md) · [Nginx 依赖](docs/NGINX_DEPENDENCIES.md) |

## 持续观察与 AI 分析

- **SSH 与 Web 观察**  在登记范围内定期采集。控制台呈现 SSH 异常、Web 探测特征、错误集中和慢请求告警，保留覆盖缺口和历史证据，并对重复采集去重。[SSH 观察](docs/SECURITY_OBSERVATION.md) · [Web 观察](docs/WEB_SECURITY_OBSERVATION.md)
- **漏洞公告观察**  在支持的 Ubuntu 环境中将已安装包与供应商公告和修复版本匹配。符合条件的漏洞告警可配置签名 HTTPS Webhook。[漏洞观察与通知](docs/VULNERABILITY_WATCH.md#可选签名-webhook)
- **可选 AI 分析**  可请求模型解释调查结果、分析告警或提供漏洞处置候选建议。支持 OpenAI 兼容接口和 Anthropic 接口。发送前校验结构化白名单，发现敏感内容或无法分类的数据就阻断整次外发。受限执行端独立生成并校验实际修复方案，执行权限由各动作的授权规则决定。[模型设置](docs/RUNNING.md#可选模型解释) · [AI 外发边界](docs/AI_EGRESS_RELEASE_CHECK.md)

## 受控处置与业务复验

首次启动是手动模式，SSH 清单为空。部署者可按所需的处置方式配置权限。

| 模式 | 系统行为 |
| --- | --- |
| 手动 | 收集证据，提供候选原因与处置建议。 |
| 半自动 | 预览目标、动作和影响，人工确认后执行受支持的动作。 |
| 全自动 | 对受支持的 Ubuntu 24.04 单包安全修复，按预先登记的目标、软件包、时间窗和限额自动执行。暂停后可停止新的自动派发。[预授权自动修复](docs/AUTOMATIC_REPAIR.md) |

已实现的受控动作包括 Ubuntu 单包安全更新、已登记服务激活、已登记的 Nginx 上游变更及回退，以及已登记容器重启。每类动作分别登记目标、配置执行入口和授权。[补丁修复](docs/VULNERABILITY_REMEDIATION.md) · [服务激活](docs/SERVICE_ACTIVATION.md) · [Nginx 变更](deploy/nginx/README.md) · [容器重启](deploy/container/README.md)

回执丢失时按原任务身份查回状态。业务复验依据已登记的只读检查。出现明确失败时标记「复验未通过」，超时或证据不足时保留「待验收」，登记项全部通过后标记「复验通过」。旧记录和对应交接摘要可以再次打开。[原任务恢复](docs/RECOVERY.md) · [客户交接验收](docs/HANDOFF_LAB.md)

## 交接、备份与恢复

- **客户交接摘要**  导出 Markdown，汇总调查结论、审批与执行状态、原任务回执和业务复验。公开反馈使用合成样本，真实日志、凭据和业务数据留在本地。
- **控制端加密备份**  使用 age 离线封装控制端十库，并按支持的交接清单纳入配置。接收方先校验密文并完成认证，再恢复到新的私有目录。独立凭据分开保管，恢复配置保持未启用。[备份与恢复指南](docs/SEALED_BACKUP.md)

## 平台与部署范围

控制台、本地浏览器、被管理服务器和写入动作分别验收。社区首试以 Windows 和 Ubuntu WSL2 的本地回放为主，Debian 13 容器也已验证控制台调查和重启读回。优先在 Ubuntu 24.04 x86-64、宿主 Nginx 和同机 rootful Docker Compose 的隔离环境试用真实接入。托管检查包含 Ubuntu/Debian 的受限 SSH 与 Nginx 场景。备份工具、服务激活和写入动作的具体版本及验收范围以各自文档为准。[平台矩阵](docs/PLATFORM_SUPPORT.md) · [运行与接入](docs/RUNNING.md) · [隔离 VPS 试用](docs/COMMUNITY_TRIAL.md#再试一台隔离-vps)

## 反馈与贡献

- 安装卡住或走完试用，都可以用「试用反馈」记录版本、系统和完成到哪一步。[反馈入口](https://github.com/mingzitaichangduozaishuhoumian/ops-ark-community/issues/new/choose) · [反馈填写说明](CONTRIBUTING.md#提交试用反馈)
- 可稳定复现的问题可用 **Issues → New issue → 缺陷反馈**，说明预期与实际结果。 [贡献说明](CONTRIBUTING.md)
- 涉及 OpsArk 自身的安全问题，请通过私密入口报告。 [安全报告流程](SECURITY.md)
- 验收用例、隔离环境和发布核对见[发布检查](docs/RELEASE_CHECK.md)。权限与敏感数据处理见[安全说明](docs/SECURITY_MODEL.md)。

OpsArk 核心以 [Apache-2.0](LICENSE) 开源。部署和维护支持可单独提供。
