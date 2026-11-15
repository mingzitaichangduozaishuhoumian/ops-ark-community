# SSH 与 Nginx 隔离故障实验

在 Linux Docker Engine 和 uv 可用的环境执行：

```console
bash tests/lab/run.sh
```

默认目标为 `ubuntu:24.04`；同一实验还接受以下固定镜像，可用于 CI 矩阵：

```console
OPSARK_LAB_BASE_IMAGE=debian:12 bash tests/lab/run.sh
OPSARK_LAB_BASE_IMAGE=debian:13 bash tests/lab/run.sh
```

脚本与 Python 验收程序都拒绝白名单外的镜像标识；Compose 构建参数由脚本传递。不要绕过脚本给构建参数注入其他镜像后将结果算入此验收矩阵。每次实验根据实际 SSH 证据核对发行版、版本和架构；输出带证据引用的实测平台信息，不以所选镜像名替代实际探测结果。

实验固定使用本机 `/var/run/docker.sock`，专用 Compose 项目为 `opsark-lab`，SSH 仅发布到宿主机 `127.0.0.1:22220`。脚本拒绝复用已存在的同名实验容器，生成临时客户端密钥，只将公钥挂载到目标；从受控容器复制公开主机密钥建立可信记录，退出时清理本实验的容器、网络和临时目录。

Ubuntu 24.04 / Debian 12 / Debian 13 目标包含真实 OpenSSH、Nginx 与无业务写入的 Python 健康接口。测试通过实际 FastAPI 接口和 Paramiko 连接调查，先核对系统、架构和所需工具，再覆盖：

1. 初始站点状态与观测基线保存。
2. 停止实验上游后实际产生的 502 和 Nginx 拒绝连接日志。
3. 恢复实验上游后的当前站点检查，保留未完成的恢复验收。
4. 修改磁盘配置但不重载 Nginx，验证摘要变化与实际加载状态分别呈现。

目标容器没有 systemd 或 Docker daemon，不伪造它们的结果；相应采集缺口必须保留。该实验验证 `D-502-01` 与 `G-NGX-01` 的部分链路，不代表普通 VPS、Docker Compose 故障、完整业务恢复或自动防御已经通过验收。实验根账号仅通过本机 Docker 管理固定故障控制，不允许 SSH root 或密码登录。
