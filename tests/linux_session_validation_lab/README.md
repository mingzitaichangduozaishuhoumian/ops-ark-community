# 当前 SSH 防护与 AI 隐私 Linux 矩阵

2026-11-06，先在授权 `试验机 B` 的新隔离环境运行固定提交 `cfcd0449816126202a94ab98b8cc3c67d38bcb1e`，保留其失败原件；修正验收定位后，在 `试验机 A` 的独立环境以 `8b21c8c15562ed5357b525705033033b3ab5883c` 完成同范围 1,667 项。两轮均为明确的 69 文件、70 个入口矩阵，涵盖 SSH 防护、会话、AI 隐私与兼容；其他产品通道和精确平台排除另列于回执及[后续分组计划](../../docs/LINUX_VALIDATION_PLAN.md)，不能称全产品或三平台通过。

## 首轮未通过，原结论保留

| 结果 | 实测 |
| --- | --- |
| 通过 / 失败 / 错误 / 跳过 | 1665 / 2 / 0 / 0 |
| 8 个关键节点 | 全部通过：POSIX 凭据拒绝、真实 GNU df/inode、6 个合成 loopback SSH 协议案例 |
| 耗时 | 1011.313 秒，原任务自然退出 1 |
| cgroup 峰值 / 上限 | 805158912 / 2147483648 字节，约 767.86 MiB / 2 GiB |
| OOM / oom_kill | 0 / 0 |
| 父 pytest 审计 | loopback SSH 6，其余 HTTP/SSH 非 loopback、loopback HTTP、实际 Docker 尝试均为 0 |
| 源码与正式 runtime | 前后完全相同 |

失败节点为 `test_defense_browser_application::test_browser_actual_application_ai_and_original_transaction_reconciliation` 和 `test_browser_defense_native_smoke::test_real_application_restart_workflow_with_shared_fake_root_and_mock_provider[proposal]`。第一项直接报出 `[data-defense="detail"] summary` 同时匹配“历史回执”和“早期工程复验记录”。两份验收源码都有相同宽泛定位器；第二项仅保留泛化 Error，不能从历史保留标志推断全部后续 UI 已通过，也不能唯一确定原抛错行。修复应限定原任务历史的语义结构，保留全部节点和原状态、回执、次数及费用断言，再以新输入独立重跑，不能把本轮失败改绿。

## 冻结输入与隔离

公开 Git 源码包有 492 个普通文件，SHA256 为 `1896fbd181e376486c0b546f168010aac7bd648266827802999adcef63eccdf3`；正式候选包为 `ae6bcd79d38cce12f5d66bee94de51726c8ac97fa71dae3523c972e11c4e2b3b`。外侧 runner `7c352b3b20cb0a8f89830753fe6e937ee1bf1ac822a1087a357a18373e716db2` 和 package helper `dd1e20d7a53810e3d346d002ee6c6b86f392756c850d89815a7416bfb28ce592` 与包内同文件逐字节匹配。测试不读取工作树脏文件、本地凭据或客户数据。

`试验机 A` 首轮在当时可用内存约 1.9 GiB 时被 2 GiB 任务预检拒绝，未启动该回归环境；之后实际内存恢复，不能将该瞬时占用写成固定规格不足。完整矩阵改在已协调的 `试验机 B` 运行。公开依赖准备使用独立网络、锁文件及核验过的 uv 二进制，94.194 秒正常退出，源码/锁不变且没有运行测试或模型。第一次 Docker commit 执行超时原件保留；在确认旧 CLI 终止、tag/本 RUN 镜像及完成回执均无后，仅封存同一已停止容器，未重装。第二次封存成功后才启动测试。

测试镜像以 UID/GID 10001、cap-drop ALL、NoNewPrivileges、只读根文件系统、network none/仅 lo、1 CPU/2 GiB、无额外 swap、512 PID、768 MiB `/tmp` 运行。只挂本轮公开输入、同源验证器及新输出目录，无宿主端口、Docker socket、host namespace 或客户数据挂载；总期限预先固定 1800 秒加 10 秒终止余量。真实 Chromium/本地 Uvicorn 预检强制执行，不用 skip 掩盖缺失浏览器。本轮显式允许容器 lo 上的真实合成 HTTP/SSH；不回填旧 217 例的审计含义。父进程审计范围与所有进程的 Docker 无外网边界分开记录，没有真实模型调用。

## 原件与清理

JUnit SHA256：`8ef2fadb3d5be4fff9848f47ee453899f83e01b913c2230ac9af053d3ab42aa2`；runner proof：`8b11942c4382c7a05281816f8d2286272d9904e1fd41f4d9b77fb5a887c3e021`；资源证明：`7a8dfa702ee91d85171eba61c7c4d11041daa92e98489659a53aa3656d7d9b3a`。独立失败收口 `failed-run.safe.json` SHA256 为 `cbd4e4e621ec0cf38f39c420b1d46cf3b45e7ebe16d2ff428dc2f340a67a10c5`，明确 accepted=false，没有生成通过证明。

本 RUN 的准备/测试两个容器、封存镜像、独立网络和私有阶段目录均已精确清理，额外按 RUN 标签核对迟到镜像为零；原有容器和网络基线一致，缓存基础及常驻镜像保留。只归档固定安全 JSON/JUnit，私有安装/pytest 日志不进入仓库或模型。证据位于本地忽略目录 `data/linux-session-validation-20261106`，失败轮次保持原件，后续新版本结果须另外记录。常驻实例、配置、历史和权限未改。

首轮约 768 MiB 包含 Chromium、测试和多个实际子进程，不能当作常驻服务内存或最低主机规格。未覆盖项不会因为这 1665 项通过而获得支持声明；首轮结案时仍需修复后的同范围完整验收。

## 后续验收定位修正候选

后续仅将原任务历史定位为现有 `.ssh-defense-history-detail` 的直属 summary，并检查唯一性和“历史回执”标签；另一个早期复验面板保留。重复打开不会反向折叠。真实应用回归明确检查两个 summary 同时存在，原 proposal 节点内还核对旧面板在前/后两种 DOM 顺序，因此没有增删原收集节点。

两项原失败节点及三个相关整文件共 30 项本地回归通过，打包器 8 项回归通过，独立整源审核确认没有删减原交易、ACK、历史、次数或费用门禁。生产 Python、网页和冻结 Root 17 文件不改。验收 driver 新 SHA256 为 `af6891ff962d77d5ad5d54c455a2fe0d69b7bc993ef4d278e41ee09659939306`，对应的公开源码合成标记例外仅更新该精确路径和 SHA，完整私钥块仍无条件拒绝。这些本地结果不替代下一份同范围 Linux 完整验收，原 cfcd 的失败结论保持。

## 第二轮：同范围完整通过

在 `试验机 A` 新建的 RUN `510f3f20fb109d` 中，仅启动一次依赖准备和一次测试。公开依赖准备 47.683 秒退出 0，源码和锁文件未变；首次封存成功，随后启动完整矩阵，没有重放安装或缩减节点。测试控制端环境为 Debian 13、Python 3.13.18、Chromium 156.0.8078.4；它不证明完整 Ubuntu 被管理端环境已经验收。

| 结果 | 实测 |
| --- | --- |
| 通过 / 失败 / 错误 / 跳过 | **1667 / 0 / 0 / 0** |
| 8 个关键节点 | 全部通过，保留原 POSIX、GNU df/inode 与 6 个真实合成 loopback SSH 节点 |
| 耗时 / 退出结果 | 496.492 秒，自然退出 0；预算仍为 1800 秒 |
| cgroup 峰值 / 上限 | 793333760 / 2147483648 字节，约 756.58 MiB / 2 GiB |
| cgroup OOM 相关计数 / Docker OOMKilled | 全为 0 / false |
| 父 pytest 审计 | loopback SSH 6，其他四项均为 0 |
| 源码与正式 runtime | 前后完全相同；包内外 runner/helper 匹配 |

公开源包固定为 497 个文件，SHA256 `964dc3ae60bfe74206dc22995ba430248ab120a9b24b6cfff8d1ea813af3b33b`；正式候选为 `d539e5cb7568d568805bc7d35fa1f6fb96661c8f8118caf32a584eb97de7b667`。runtime 实际为 99 个文件，摘要 `da76b9262fc2094c34f8b5bdb79f6ea4de2112a5e8d033d298f6cb447bf4a7a4`，不沿用更早 217 项范围的 94 文件计数。外侧 runner 仍为 `7c352b3b20cb0a8f89830753fe6e937ee1bf1ac822a1087a357a18373e716db2`，helper 为 `c0929934bfc94fe881dfd1c110bfd5f6c46dd8d2dc8c9c6e4fe08f365e0885e4`。

隔离限制与首轮相同：UID 10001、capabilities 0、只读根、NoNewPrivileges、network none/仅 lo、1 CPU/2 GiB、无额外 swap。唯一精确排除仍为 Windows DACL 节点，Linux POSIX 节点实际运行。审计只覆盖 pytest 父进程；所有子进程同时受无外网容器边界约束，没有真实模型调用。全部产品测试未包含在此矩阵，未覆盖文件清单随同源回执保留。

证据收集后，精确移除准备/测试容器、封存镜像、专属网络及私有目录，RUN 标签镜像剩余为 0；原有容器和网络基线一致，缓存基础和常驻镜像保留。随后独立离线验证器核对完整 JUnit、critical 8、来源、runtime、审计、资源、准备与清理回执，才生成本轮通过记录。

| 本地安全原件 | SHA256 |
| --- | --- |
| 独立汇总 `acceptance.safe.json` | `a35e78d31d7b56a1364df26559c5851870dea4842656bf1e14e6e174d34f006b` |
| `junit.xml` | `229629c7cce648c5e6573226a8cd2e2f5b1084045e1020f4eb3be3cbf065337b` |
| runner `proof.json` | `631fe19c8457ce178c4022e15716d9e9d4f989640d8c6ce148bd7f8c4618fc8a` |
| `resources.safe.json` | `7992e684cd051a1c7d1752086bace60079786c68cf4793384bd735ece290a2c6` |
| 独立离线验证器 | `aedc26f191b6e424952ccdfd8901c61ca108188099d24a6e05a74bc3648a10f8` |

原件保留在本地忽略目录 `data/linux-session-validation-r2-20261106`，只收集固定安全 JSON/JUnit，不携带安装、pytest 原始日志或凭据。结论只绑定 `8b21c8c` 的公开输入；后续工作树修改须另行验证。两台常驻实例的配置、历史和权限保持原状。
