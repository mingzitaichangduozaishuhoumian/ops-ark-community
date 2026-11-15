# OpsArk

OpsArk 帮小团队排查 VPS 上的网站 502、磁盘空间异常和 Docker 容器反复重启。调查报告保留采集时间、证据、候选原因和待核实项。完成业务复验后，可以导出给客户的交接摘要。

## 开始试用

**先跑本地合成样本。** 已在 Windows 和 Ubuntu WSL2 验证首次安装、样本回放及重启读回。仅需本机、uv 和浏览器，无需 VPS、SSH、Docker 或模型密钥。

从仓库的 **Releases** 下载试用公告标明版本的源码 ZIP 附件。解压前核对文件的 SHA-256 与发行页公布的值一致，并记下该版本，便于反馈。安装 uv，在解压后的源码根目录打开一个没有 OpsArk 部署变量的新终端。第一次同步需要联网，uv 会下载锁定依赖及本机缺少的 Python 3.13。 [uv 安装说明](https://docs.astral.sh/uv/getting-started/installation/)

```console
uv sync --locked --no-dev --python 3.13
uv run --locked --no-dev python -m uvicorn opsark.main:app --app-dir src --host 127.0.0.1 --port 18190 --workers 1
```

打开本地控制台，用首次启动生成的 `data/access-token` 解锁。选择「本地样本回放」中的网站 502 样本，点击「运行只读调查」。报告应显示「需要关注」和「样本回放」。点击「下载客户交接摘要」，确认得到 `opsark-handoff.md`，其中验收状态为「待验收」。 [本地控制台](http://127.0.0.1:18190/) · [首次运行与故障排查](docs/COMMUNITY_TRIAL.md)

安装卡住或顺利完成后，可在 **Issues → New issue → 试用反馈** 简述版本、系统和完成到哪一步。 [反馈填写说明](CONTRIBUTING.md#提交试用反馈)

## 现在能测试什么

| 场景 | 可查看的结果 |
| --- | --- |
| 网站 502 | Nginx、登记上游、监听端口和容器状态，以及缺失的检查 |
| 磁盘异常 | 可用空间、inode、登记范围的增长和条件回收估计 |
| 容器反复重启 | 退出码、OOM 标记、重启计数，以及有同范围基线时的容器、镜像和 Compose 配置变化 |
| 安全观察 | 已登记范围的 SSH/Web 异常、定期漏洞观察和可选签名通知 |
| 交接和恢复 | 脱敏摘要、原任务查回、已登记业务检查及控制端十库加密备份 |

首次启动使用手动模式与空 SSH 清单。目标机通过管理员核对的 SSH 指纹和受限账号接入。模型可选，外发经过白名单门禁。受控补丁、服务激活和其他变更使用独立入口及授权。平台与写入动作的已验收范围各自记录。 [安全与执行边界](docs/SECURITY_MODEL.md) · [平台支持](docs/PLATFORM_SUPPORT.md)

**可选的隔离 VPS 试用。** 已核验的 0.19.0 私有试用候选为 `4a00bd5`。试用目标采用 Ubuntu 24.04 x86_64、宿主 Nginx 和同机 rootful Docker Compose。包内提供镜像校验、空清单启动与只读接入说明。 [私有 VPS 试用验收](docs/COMMUNITY_TRIAL.md#私有-vps-试用验收)

## 反馈与贡献

- 可稳定复现的问题可用 **Issues → New issue → 缺陷反馈**，说明预期与实际结果。 [贡献说明](CONTRIBUTING.md)
- 涉及 OpsArk 自身的安全问题，请通过私密入口报告。 [安全报告流程](SECURITY.md)
- [运行与接入](docs/RUNNING.md)说明部署、SSH、观测和资源范围。
- [离线加密交接](docs/SEALED_BACKUP.md)说明备份、身份保管与恢复边界。
- [发布检查](docs/RELEASE_CHECK.md)记录测试范围。完整源码仓库另附验收用例与产品计划。

核心免费。部署和维护支持可单独提供。
