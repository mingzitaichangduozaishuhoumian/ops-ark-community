# 自有 VPS 故障实验

这是管理员通道使用的固定实验 helper，不属于模型工具或 SSH 只读采集账户。仅部署到用户明确授权改造的测试主机；脚本不接收 IP、容器名、端口或路径参数，不连接其他服务器。

依赖 Ubuntu/Debian 的 Python 3 标准库、运行中的本地 Linux Docker Engine 和 Nginx。管理员安装为 root 所有且不可由采集账号写入，例如 `/usr/local/libexec/opsark-vps-fixture.py`，权限 `0700`。不要把此脚本加进只读账户的 sudo 白名单。

```console
/usr/bin/python3 /usr/local/libexec/opsark-vps-fixture.py init
/usr/bin/python3 /usr/local/libexec/opsark-vps-fixture.py status
```

实验边界固定：

- 容器名 `opsark-lab-api`，两个所有权标签分别为 `io.opsark.fixture=v1` 和 `io.opsark.fixture.id=opsark-lab-api`。
- Nginx 文件仅 `/etc/nginx/conf.d/opsark-vps-lab.conf`，root 所有的固定 marker 证明其实验归属；拒绝符号链接、非普通文件或组/其他用户可写文件。已有无关配置不覆盖。
- Nginx 仅监听 `127.0.0.1:18880`，域名 `opsark-lab.invalid`，代理到 `127.0.0.1:18881`。
- Docker 仅发布 `127.0.0.1:18881:8081`，使用固定 `python:3.13-slim` 镜像，缺失时才拉取。`/healthz` 返回 HTTP 200 和 `OPSARK_LAB_OK` 换行。
- 容器使用 bridge 网络、64 MiB 内存、0.25 CPU、32 PID、非 root 用户、只读根文件系统、drop all capabilities、no-new-privileges、每份 1 MiB/最多两份日志。无数据卷、无宿主 Docker socket、无 privileged。

| 动作 | 行为 |
| --- | --- |
| `init` | 核对工具、归属和新建时的端口冲突，创建专属配置；`nginx -t` 成功后创建 healthy 容器并重载 Nginx |
| `healthy` | 只替换具有两个准确标签和准确名称的自有容器，使用正常 HTTP 服务；不存在时创建 |
| `start` / `stop` | 按已核验的自有容器不可变 ID 启停，不接受其他目标 |
| `fail42` | 将自有容器替换为每次睡眠 11 秒后退出 42 的进程，`on-failure:2`；stdout/stderr 带固定实验标记；立即返回，不等待三次运行结束 |
| `status` | 输出干净 JSON，含自有容器 State、RestartCount、MemoryLimit、Image 和两个 loopback 检查；缺失/未配置单独记录，不把命令成功当作健康 |
| `cleanup` | 先验证容器及配置归属，只移除实验配置并通过语法检查后重载；再删除已核验 ID 的自有容器；配置语法检测失败时恢复实验文件且不重载 |

所有 subprocess 使用 argv 和 `shell=False`，固定可信 PATH/环境，Docker 固定到 `unix:///var/run/docker.sock`，使用临时私有空配置目录，不继承 Docker context/TLS、代理或 root 用户配置。错误输出仅含明确代码，不回显 daemon stderr、环境变量或命令文本。状态没有 Config.Env、挂载内容、私钥或业务日志；`fixture_healthy` 需要容器运行且两个实际探针均符合，`ok` 单独不代表服务健康。

普通使用流程：`init → status → stop → status → start → status → fail42 → 由调用者轮询 status → healthy → status → cleanup`。停止上游时 Nginx 应出现真实 502；fail42 应在约 33 秒加调度开销后退出，实际重启数和退出码必须从采集结果验证，不能根据计划推测。每次 `healthy`/`fail42` 会删除并替换自身实验容器，它不承诺保留旧实验进程。

若 Nginx 重载失败，helper 报告错误且不宣称恢复。cleanup 会恢复其配置文件但不会重复重载；管理员需检查实际生效状态。helper 不删除旧业务容器、数据卷、镜像、其他 Nginx 配置或实验错误日志，不进行备份恢复、业务发布或服务器重装。

本机没有运行 Linux Docker Engine；仓库单元测试覆盖命令参数和归属拒绝，不能代替两台 VPS 上的实际部署、故障及管理通道验收。实际部署与结果由管理员流程单独记录。
