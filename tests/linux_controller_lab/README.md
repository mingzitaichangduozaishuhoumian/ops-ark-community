# Linux 控制端的断网验证

2026-11-06，在授权 `试验机 A` 上的新隔离容器验证固定提交 `3e7f84816cc3f0e9f78fe2ca0e026f3643722d0a`。`试验机 B` 留给另一任务的独立源码编译，本轮没有访问该任务的业务主机或数据。常驻实例、配置、历史和权限未改。

## 固定输入与隔离

使用 Git 对象生成独立测试包，不读取 dirty/untracked 文件或工作区数据目录；454 个 regular 文件、7,220,659 字节。正式候选仍通过原 `release_bundle` 合同生成，没有扩大其归档范围、修改 Compose 或交接 v2 模板。

| 输入 | SHA256 |
| --- | --- |
| 完整测试源码包 | `c2bc39fa297ad4b7266f9995d093b9444acd280fd6d2a6d233bb9b871fb60126` |
| 正式候选包 | `188590c044fa8c5ca840eddcd78ea2c0c52115a14eb3d28a9144244843e7416e` |
| Git 源码 identity | `f9d13ba507a140a1f9377cb89c0a784c3706e07365c040dda457bb8683bfa370` |

测试包的秘密标记例外仅适用于 14 个已审核合成测试的精确 path＋完整 SHA；变更即拒，完整私钥块始终拒绝。归档还检查 Git blob、mode、重复、路径逃逸、symlink/gitlink 及尾随数据。源码内容和正式 runtime 在执行前后分别核对：454 文件源码树摘要 `4495d266aed079b540f1f84996a8423306cc895c19d77c5119a1d80436dc1edf`；94 个 runtime 文件摘要 `cbf5579bca10e3dd3ec2db4a5e0e29c92820c044353be0e8855956c6d9b928d7`，前后完全相等。

公开依赖准备与测试分开。准备容器限 1 CPU/2 GiB、无额外 swap，使用固定 Python 基础镜像、核验过的 uv 0.9.17、`uv sync --locked` 和锁定的 Playwright 浏览器；仅该阶段有独立网络。系统依赖以实际镜像身份记录，没有把滚动 apt 包冒称固定版本。准备阶段没有运行测试、模型或原应用配置。

测试容器使用独立镜像，`network=none`、只读根文件系统、cap-drop ALL、NoNewPrivileges、UID/GID 10001、1 CPU/2 GiB 且无额外 swap、512 PID、768 MiB `/tmp`。只挂载本轮 Git 输入和验证器只读目录以及新建的可写 `/out`，无端口、Docker socket、宿主 namespace 或客户数据挂载。代理变量清空，外层 GNU timeout 覆盖全部 runner，900 秒 TERM＋10 秒强制终止余量。

## 真实结果

| 项目 | 实测 |
| --- | --- |
| 系统 | Debian 13 容器、Linux x86_64 |
| Python / SQLite | 3.13.18 / 3.46.1 |
| Playwright / pytest | 1.64.1 / 9.1.1 |
| Chromium | 156.0.8078.4 |
| UID / CapEff / NNP | 10001 / 0 / true |
| 网络设备 | 仅 lo |
| 217 项 | 全通过，零失败、错误及跳过 |
| 验证耗时 | 177.029 秒 |
| cgroup 内存峰值 | 599,048,192 字节，约 571.30 MiB |
| 内存上限 | 2,147,483,648 字节 |
| OOM / oom_kill | 0 / 0 |

先强制启动真实 Chromium，访问容器内真实 Uvicorn loopback 页面，核对 HTTP 200 和 DOM；浏览器缺失不能被 skip 掩盖。测试集是此前 209 项文件集、六项后台驱动测试及两个明确 Linux/POSIX 节点：凭据改成 0644 后必须在连接前拒绝，GNU `df` 的容量/inode 输出必须实际可解释。JUnit 单独核对两节点都通过。

`real_http_egress_attempts=0` 仅对应 pytest 主进程包装的 actual HTTP transports；MockTransport/ASGI 不被误当网络请求，也不声称全部子进程零尝试。所有进程的无外网连通由外层 Docker network none 与仅 lo 独立保证。测试仅合成凭据和临时数据，未调用实际模型或使用真实服务器修复权限。

## 原件与清理

| 证据 | SHA256 |
| --- | --- |
| runner proof | `81486d1b547747003b22590a4dc387c7445d4fb212f9668c1b9a1cabaf0e1c81` |
| JUnit | `fc7a2624093ce8a54f385044671bb98bf7dbd1c79cef6f918fea8b709ede47e8` |
| cgroup resource proof | `a1709cdef55d9ce94af4f9fa73f5308370e85e4dc34742407ee9b47ffd9ebcdb` |
| 汇总 acceptance | `c11bdf08189bdabec9cb3e1cb9374f766b7e099271ee9cd309aedc96fe5f25f5` |

白名单 JSON/JUnit 在本地忽略目录保留，原始安装和 pytest 日志未进入仓库或模型。第一次非 root 启动因输入子目录不可遍历，退出码 2、尚未运行测试；修正子目录 0755、阶段根仍 0700 后，复用同一已停止容器执行，上述 217 项属于后续成功尝试。失败的固定原因及日志 SHA 独立保留，未计为通过。

全部本轮容器、新依赖镜像、独立网络和 root-private 阶段目录已按精确 ID、名称、RUN 标签清理。原有容器和网络基线一致，原缓存基础及常驻镜像保留。约 571 MiB 是包含浏览器和测试的整组峰值，不能作为常驻服务内存数字。

此范围不等于最新完整 pytest、三平台 CI、全部浏览器引擎、真实 PID1/systemd、Docker/KVM 客体或公网防御验收。GitHub 账单/额度导致未启动的矩阵仍未完成。相关工具为 `tests/linux_controller_package.py` 和 `tests/linux_controller_validation.py`；Windows 上另有 17 项纯临时数据打包/门禁回归通过，静态检查通过。
