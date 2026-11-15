# 平台适配与验证矩阵

更新日期：2026 年 11 月 6 日

控制台运行的系统、浏览器和被管理服务器分别验证。控制台可以在 Windows 上连接 Linux；控制台在 macOS 上通过测试，不代表已经能诊断 macOS 服务器。以[验证记录](IMPLEMENTATION_NOTES.md)及相应 CI 的实际结果为准。

早期矩阵已通过实现提交 87a87a1 的 CI。该次控制台实际架构为 Linux x86_64、Windows AMD64、macOS arm64；三个 SSH/Nginx 容器均为 x86_64。下表中的边界仍然适用，当前版本结果另列，不把历史输出当作新硬件实测。

0.4 的后续 CI继续通过上述矩阵，并增加两台 Ubuntu 24.04 x86_64 VPS 的实际服务器端权限和故障验证。后者使用发行版 Python 3 标准库运行远端 helper，不要求远端安装控制台的 Python 3.13 依赖，见[实机记录](VPS_LAB.md)。

0.5 的当时代码 CI继续覆盖三种控制台系统和三个浏览器内核，新增安全观察与嵌套进程预算回归。持续 journal 采集与独立 SSH 演练实测于上述两台 Ubuntu 24.04 x86_64；0.5 当时控制端常驻第一台，后续已迁至第二台。Windows/macOS 控制台测试不能代替远端 journal/服务管理验收。

0.10 的6206c19 CI八项全部通过，继续覆盖三种控制台系统、三浏览器和 Ubuntu/Debian 的既有实际服务实验。新增恢复 UI 在本机三浏览器各通过 9 组合成契约，覆盖 320–1440 宽度；独立实验控制端的真实 UI 另在 1440/390 验证，没有把合成浏览器测试计为服务器安装。

## 0.18 手工 Linux 全量回归

2026 年 11 月 5 日，在授权测试机的独立 Ubuntu 24.04 容器中，使用提交 `96d6cad0b5f0ca80b42e74dbdad6b4897ea54790` 的完整冻结源码、Python 3.13.11 和锁定开发依赖执行 pytest。发行版 Python 为 3.12.3。结果为 **3,910 项通过、15 项跳过、零失败和错误，行覆盖率 91%**，达到既有 80% 门槛。运行前后 74 个产品运行文件及完整测试源码摘要保持一致。

15 项跳过分别为缺少 Git 的 10 项发布工具测试、缺少 curl 的 4 项原生 HTTP 协议测试，以及没有 Docker socket 的 1 项可选工作负载测试。对应实际工作负载和已执行的发布核验继续按各自记录验收；本轮没有把缺失工具伪装成可用。

执行容器断网、只读根文件系统，源码与依赖只读挂载。临时数据位于本轮私有目录，CPU 上限 1 核、内存及 swap 总量同为 1 GiB，移除所有 capabilities 后仅增加临时文件属主测试需要的 `CHOWN`。测试耗时约 7 分 14 秒，进程组内存峰值约 527 MiB，专属 cgroup 的 OOM kill 增量为零，没有超时或资源预算停止。该峰值包含全量测试、覆盖率和子进程，产品规格仍以[容量实测](CAPACITY_ACCEPTANCE.md)为准。

原始测试日志和 JUnit 留在私有取证目录，对外记录计数及文件摘要。未实际启动测试的首轮初始化单独保留为未执行记录，修正运行器后才取得上述完整回执。完成核对后，专用容器及远端临时环境已删除，既有容器和网络记录保持一致。

这是手工 Linux pytest 结果。三系统 GitHub 控制台矩阵、浏览器引擎矩阵及真实 PID1/服务实验仍按各自证据判定；本轮候选的 GitHub 作业因账户账单或额度限制没有启动测试步骤，不能记为 CI 通过。[发布核验](RELEASE_CHECK.md)

## 0.19 两平台与离线加密工具

冻结候选 `8b9698e` 在 Windows 11 / CPython 3.13.11 完整 pytest 为 3,826 通过、183 跳过、覆盖率 91.33%；授权测试机 Ubuntu 24.04 独立容器 / CPython 3.13.11 为 3,987 通过、22 跳过、覆盖率 91%。两边均收集 4,009 项、零失败和错误。原生 age 1.3.2 的十库加密、密文核对、恢复及负例各 44 项通过；文件边界各通过本平台 7 项、跳过另一平台 7 项。具体跳过、冻结文件与清理记录见[发布检查](RELEASE_CHECK.md#019-离线加密交接候选)和[加密交接](SEALED_BACKUP.md#验证状态)。

离线加密 CLI 目前仅支持经过验证的 Linux 与 Windows 本地文件系统，不声明支持 macOS、网络共享盘或其他 CPU 架构。控制台历史 macOS 结果不能代替该工具验收。本候选的十项 GitHub 作业均未启动测试步骤，账户账单或支出限制仍是矩阵执行阻碍，不能将两平台手工回归写成最新 CI 全绿。当次矩阵

## 本轮适配范围

开发分支 `3e7f848` 的新 SSH 防护事务、原任务只读跟进、进程恢复和业务摘要，另有[Linux 控制端专项验证](../tests/linux_controller_lab/README.md)：Debian 13 x86_64 容器、Python 3.13.18、Chromium 156.0.8078.4、非 root UID 10001、cap0/NNP/断网，217 项全通过且零跳过。454 文件源码与正式候选 94 个 runtime 前后匹配。它是对应 Windows 209 项联合及六项驱动回归的 Linux 补验，加两个关键 POSIX/Linux 节点，不替代上节旧完整 pytest，也不证明新 macOS、Firefox/WebKit 或被管理 Debian 补丁支持。

| 层次 | 本轮自动验证目标 | 验证内容与边界 |
| --- | --- | --- |
| 控制台服务 | Ubuntu 24.04、Windows Server 2025、macOS 15 的 GitHub runner | 固定 Python 3.13，认证 API、SQLite、回放、脱敏、SSH 协议；记录实际架构与 Python 版本。不是安装包、系统服务或公网部署验收 |
| 浏览器 | Chromium、Firefox、WebKit | 合成报告兼容、字段安全、证据跳转、320–1440 宽度，以及实际后端的基本调查流程。WebKit 引擎测试不代表所有 Safari/iOS 设备已测试 |
| SSH/Nginx 目标 | Ubuntu 24.04、Debian 12、Debian 13 容器 | 真实 OpenSSH/Nginx、502、恢复上游、站点检查、磁盘配置摘要变化。不是完整 systemd VPS |
| 受控服务激活实验 | Debian 12、Debian 13 x86_64 systemd guest | 本机各 31 项原生检查，另有三浏览器真实 Web 闭环六组各 18 项通过。合成父补丁/vendor finding，真实批准、重启、SSH、下载及控制端重启；不是 Debian 补丁执行验收。[入口与隔离边界](../tests/activation_lab/README.md) |
| 激活后独立复扫与导出 | Debian 12、Debian 13 × 三浏览器 | 六组各25项通过，另各7项清理后离线对照。真实独立包/运行时/健康读取、队列及证据关联；原父补丁合成，官方供应商判定 not_evaluated、覆盖 partial，不是 Debian 官方 CVE/补丁验收 |
| Docker 工作负载 | Ubuntu runner 与授权测试机的本地 rootful Docker | 实际 SSH/API 采集正常状态、两次重启/退出 42、非 OOM 的 137 与真实 memcg OOM 对照。后者先核对实际 64 MiB/零额外 swap，再触发内核终止。宿主内存耗尽、生产 OpenSSH 和业务恢复分别验收。[实验记录](../tests/docker_lab/README.md) |
| 磁盘与 inode 实验 | 授权测试机内的独立 tmpfs 最小根 | GNU 工具和实际 SSH/API 验证目录分类、删除后仍持有、字节充足时的 inode ENOSPC 及复原测量。使用固定大小和 inode 数，完整 VPS 与真实业务恢复分别验收。[实验记录](../tests/filesystem_lab/README.md) |
| CPU 架构 | 适配器允许 Linux `x86_64`、`aarch64` | 允许选择适配器与该架构的实机验收分别记录。ARM64 远端故障实验仍待补齐 |

GitHub runner 的系统是控制台测试环境；Linux 容器内的发行版是采集目标。两者不能混为同一个操作系统测试。具体补丁版本、镜像 ID 和架构取实际实验输出，不根据镜像标签猜测。

0.9 新增的自动状态界面已在本机 Windows 环境通过 Chromium、Firefox、WebKit 各 8 组合成契约，覆盖 320–1440 像素宽度；对应脚本已加入 Ubuntu 浏览器 CI。另在 Ubuntu 24.04 x86_64 隔离 guest 上完成一次真实预授权自动单包升级及修复后验证，其他实机故障/恢复对照分别记录。控制端浏览器通过不扩大 root 修复 driver 的范围：当前只对 Ubuntu 24.04 原生架构的单包事务适配，不能据此声称 Debian、远端 ARM64 或其他系统自动修复已通过。详见[自动修复说明](AUTOMATIC_REPAIR.md)。

0.10 的真实丢回执、慢安装、恢复确认及 APT 内到期/关窗对照，也只在第二台 Ubuntu VPS 内的独立 Ubuntu 24.04 x86_64 guest 完成。升级验收保留了既有登记，并取得新策略下的部分扫描；它不把实验目标、实验授权或故障注入工具加入普通管理范围。被管理端的 Debian 自动补丁、远端 ARM64 恢复、Windows/macOS 服务器及更多包仍无该验收结论，见[恢复实验](RECOVERY_LAB.md)。

0.14 的 CI 八项继续通过，含三控制端系统与三浏览器。两台新的 Ubuntu 24.04 x86_64 guest 分别测试 SQLite、Expat，模型文本规则和输出预算导致分析失败，补丁任务与修复安装均为零；新增失败诊断与原件核验通过，不扩大已经正向修复的包或发行版范围。结果见[实机记录](AI_PATCH_EXECUTION.md)。

0.15 的新 Ubuntu 24.04 x86_64 隔离实验中，SQLite 完成单包自动修复闭环；Expat 完成安装但产品因旧进程保留重启待办，管理员激活仅作独立对照。这些结果没有扩大到 Debian 补丁、ARM64 实机或 Windows Server，被管理端与控制端平台仍分别验收。见[实际结果](AI_PATCH_EXECUTION.md)。

0.16 在上述两台 VPS 内的新 Ubuntu 24.04 x86_64 systemd guest 完成产品服务激活、官方复扫及新 SSH 验证，关键 D-Bus 例外仅适用于该明确登记的实验范围。原生 OFD 锁与 PID1 私有属性读取在 Linux 实际系统 Python 上另行证明；Windows 测试替身不充当 Linux 原生锁证明。普通 128 MiB 控制台容器通过基础回放，但不等于完整 512 MiB VPS 容量验收，见[资源边界](RUNNING.md#资源占用与小型-vps)与[激活记录](SERVICE_ACTIVATION.md)。

## SSH 预检

每次 SSH 调查先读取有界的 `/etc/os-release`。只接受明确的 `ID=ubuntu` 或 `ID=debian`；`ID_LIKE` 不自动扩大适配范围。关键字段重复、非法格式、截断或权限错误均不选择适配器，不把文件内容交给 Shell 执行。格式参考 [os-release 官方定义](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)；重复关键字段选择停止是本工具的保守策略。

随后运行固定的架构与工具存在性探针，只返回架构和每项工具的布尔标记，不安装工具、不使用 sudo。探针协议不完整或架构不在范围时停止场景采集。工具缺失时只跳过依赖该工具的检查，其他检查继续。每次仍受原有 SSH 时间和输出预算限制。

`Report.compatibility` 保存系统、版本、架构、适配器、工具缺口和证据引用：

- `compatible`：本次探针允许选择命令适配器；工具权限、服务工作状态及发行版验收另行判断。
- `unsupported`：已经识别到范围外的系统或架构，不继续专属检查。
- `unknown`：证据缺失、失败或无法识别；SSH 调查停止专属检查。没有新探针的旧报告保留为未知；旧合成回放仍可验证规则，明确不代表实机适配。

`command -v` 成功不能证明能读日志、能访问 Docker socket 或 systemd 正在运行。后续失败继续作为证据缺口。系统身份是目标报告的元数据，不提供远程完整性或可信启动证明。

## 部署与权限差异

Python 原生启动命令在三个控制台系统保持一致，仍需单 worker。Windows PowerShell 设置路径可使用 `$env:OPSARK_INVENTORY = 'D:\private\opsark.local.toml'`；Linux/macOS Shell 使用 `export OPSARK_INVENTORY=/private/opsark.local.toml`。路径必须存在于控制台进程可访问的文件系统。

Python 3.13 在 Windows 新建 `mode=0700` 目录时会限制访问；既有目录不会因此自动修复 ACL，`chmod(0600)` 也不等同于 Windows ACL 设置。外部数据目录、凭据和备份仍由部署者核验权限。见 [Python mkdir](https://docs.python.org/3.13/library/os.html#os.mkdir) 与 [chmod](https://docs.python.org/3.13/library/os.html#os.chmod)。

Linux Compose 镜像的构建、非 root 启动和持久化另有 Ubuntu CI。Windows/macOS Docker Desktop、Windows 容器、多架构镜像发布、系统服务安装及桌面安装包尚无交付承诺。

## 扩展顺序

1. 补 Linux ARM64 真实故障实验与正式 VPS 接入试用，记录版本、权限和耗时。
2. 在最小权限采集通道稳定后，分别适配 Rootless Docker 和容器内 Nginx；使用独立配置与案例，不自动套用 rootful/宿主机假设。
3. 根据试用需求增加 RHEL 系或其他发行版，重新验证服务名、日志源、包路径和工具行为。
4. Windows Server 被管理端需要单独的 PowerShell/事件日志/服务适配器与权限模型；macOS 被管理端同样独立评估。它们尚未实现，不能直接复用 Linux 命令。

浏览器作为统一入口，先做好桌面和手机宽度的 Web 控制台；原生手机 App、桌面壳与一键安装器在接入需求确认后再排期。
