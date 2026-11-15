# 实际 Docker 工作负载实验

仅用于授权的一次性 Linux runner：需要本地 rootful Docker Engine、Python 项目依赖和镜像下载能力。不要在生产宿主机运行。CI 调用：

```sh
OPSARK_DISPOSABLE_DOCKER_LAB=1 bash tests/docker_lab/run.sh
```

脚本创建四个随机命名、带本次唯一标签的临时容器。容器使用 `network=none`、只读根文件系统、空 capabilities 和禁止提权配置，不挂载文件或数据卷。每个容器限制为 64 MiB 内存、内存加 swap 总计 64 MiB、0.25 CPU 和 32 个进程。正常进程持续运行；失败进程每次运行 11 秒后退出 42，由 `on-failure:2` 产生实际重启计数；信号对照由实验控制器发送 SIGKILL，获得 `ExitCode=137` 且 `OOMKilled=false` 的实际状态。重启策略及成功启动条件依据 [Docker 官方说明](https://docs.docker.com/engine/containers/start-containers-automatically/)。

OOM 对照的 Python PID 1 先安装信号处理器并等待。实验控制器读取该容器实际 cgroup v2 的 `memory.max` 和 `memory.swap.max`，确认分别为 `67108864` 和 `0` 后才发送 USR1。工作负载最多保留 128 个 1 MiB 内存块，逐页写入，要求 30 秒内由内核终止，Docker 状态必须同时为 `OOMKilled=true` 和退出码 137。普通 `MemoryError` 或达到分配上限自行退出均判为实验失败。cgroup v2 或实际限制无法确认时停止本项验收。

控制器只负责制造和撤销这些实验故障。OpsArk 仍通过登记主机、认证 API、真实 SSH 协议和生产采集器读取 Docker inspect/logs，规则必须保留 stdout/stderr、退出码、重启计数及 137 的不确定性。真实 OOM 的候选原因须直接引用 `E-CONTAINER-STATE`。各报告继续保留业务恢复未验收。

临时 Paramiko SSH 服务仅绑定 `127.0.0.1`，使用现场生成的密钥和可信主机记录。它只接受采集器针对上述容器生成的精确命令，每个已允许的命令用 argv 执行；不提供任意 shell、PTY、SFTP 或端口转发。实验还实际检查任意命令和 SFTP 被拒绝。宿主机内核 journal 明确留作未覆盖项，SSH 夹具对该条命令返回固定的不可用结果，避免读取无关主机日志。Docker CLI 使用本轮新建的空配置目录。Docker socket 不挂载进容器，不使用特权 DinD，也不修改系统 SSH 配置或账号。

默认 CI 镜像为 `python:3.13-slim`。已有本机镜像时可直接运行下列命令，`OPSARK_DOCKER_LAB_IMAGE` 只接受默认名称或完整小写 SHA-256 镜像 ID。工作负载使用 `--pull never`，镜像声明数据卷时拒绝运行。

```console
PYTHONPATH=src OPSARK_DISPOSABLE_DOCKER_LAB=1 OPSARK_DOCKER_LAB_IMAGE=sha256:<本机固定镜像> uv run python tests/docker_lab_smoke.py
```

退出时只清理本次随机名称、标签和容器 ID 一致的对象，不执行 prune，不删除镜像和无关容器。SSH 密钥、报告与令牌保存在临时目录；主服务凭据和模型环境不会传入实验实例。

通过后的 JSON 输出包含 Docker 版本、实际镜像 ID、退出码、重启计数、实际 cgroup 限制与边界标记。结果覆盖一次性 runner 上的实际 Docker 工作负载、memcg OOM 和应用采集链路。生产 OpenSSH 账号隔离、Docker Compose 项目发现、宿主机内存耗尽及完整业务恢复继续分别验收。

2026 年 11 月 5 日在授权测试机的独立临时 Python 环境运行完整实验。Docker Engine `29.7.2` 确认实际内存上限为 `67108864` 字节、`memory.swap.max=0`。OOM 容器的原始及 SSH 采集状态均为 `137 / OOMKilled=true`，内存候选只引用容器状态。普通 SIGKILL 对照仍为 `137 / OOMKilled=false` 并保留不确定性。正常容器、退出 42 的两次重启、真实 stdout/stderr、任意命令及 SFTP 拒绝也通过，业务恢复仍未结案。原容器和网络在实验前后核对一致。

## 应用配置无效的三阶段对照

`run.sh` 还会运行独立的 `tests/docker_config_lab.py`。它固定镜像和应用脚本，仅改变一个有界的合成 JSON 环境配置，依次运行有效、无效、修正后三阶段。每次重建同一登记容器名，记录三个不同的真实容器 ID，保持同一 SSH 信任、调查范围和原始观测基线。应用只输出固定的字段校验结果，配置正文不进入日志。

无效阶段的应用实际校验失败，向 stderr 输出 `listen_port` 应为整数的提示，然后退出 78。容器不自动重启，`OOMKilled=false`。正常生产采集器通过真实 SSH 协议执行 Docker inspect/logs，正常 API 生成三份报告；API 传输使用本机 ASGI 测试客户端，没有模拟采集结果。报告保留真实退出码和错误片段，状态差异由原基线的 `running` 变为 `exited`。修正后的新容器实际运行，原报告及原基线的摘要保持一致。

实验容器仍为 64 MiB、零额外 swap、0.25 CPU、32 进程、只读根文件系统、无 capabilities、无主机挂载、无网络，镜像健康检查禁用。删除时重新核对原容器 ID、唯一标签、名称和资源约束。私有账本仅保存合成输入摘要、字段类型、容器 ID、报告和基线摘要及清理结果；标准输出只给出安全验收摘要。

```console
PYTHONPATH=src OPSARK_DISPOSABLE_DOCKER_LAB=1 OPSARK_DOCKER_LAB_IMAGE=sha256:<本机固定镜像> uv run python tests/docker_config_lab.py --evidence-dir <新的私有绝对目录>
```

2026 年 11 月 5 日，授权测试机使用已核验的 `a1ad75f` 源包完成本项实机验收。运行前后核对 74 个产品运行文件，内容保持一致。独立复核账本确认三次容器、三份同一范围报告、无效阶段退出 78 且非 OOM、有效与修正输入摘要一致、无效输入不同。全部实验容器和临时 Python 环境已删除，既有容器与网络清单一致。

本项不把环境配置读入产品，也不能证明是谁或何时改了配置。应用配置差异与变更因果继续保留为缺口，运行状态不能代替业务恢复。原生 OpenSSH 账户隔离、配置自动修复和真实业务验收分别验证；此前退出 42 的重启实验仍按原记录保留。
