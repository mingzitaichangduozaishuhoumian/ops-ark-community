# Linux 验收补齐计划

2026-11-06。目标是补齐整个产品的 Linux 验收；本轮 SSH 矩阵通过不代表该目标完成。本文只安排独立测试范围，不新增服务器权限、持续执行许可或自动修复授权。

## 本轮固定范围

[验证器](../tests/linux_controller_validation.py)声明 `ssh-defense-session-ai-privacy-linux/v2`：69 个完整测试文件，加 `test_linux_commands.py` 的真实容量与 inode 节点；收集 1668 项，精确排除 1 个 Windows DACL 节点后，Linux 必须实际通过 1667 项，零失败、错误及跳过。总测试预算为 1800 秒；公开依赖准备是独立阶段，不占用此预算。旧 217 项属于旧源码和旧范围，不能并入本轮计数。

本轮必须逐项通过 POSIX 凭据权限、真实 `df` 容量/inode，以及 `test_ssh_transport.py` 六个合成 SSH 协议节点。允许专属 `network=none` 容器内的真实 loopback 浏览器、HTTP stub 和合成 SSH；只放行 IP 字面量 `127.0.0.1`、`::1`，不放行 `localhost` 或其他 DNS 名称。SSH 凭据与服务端响应由临时测试生成，不能读取宿主凭据、业务数据或调用真实模型服务。

运行环境保持 UID 10001、capabilities 0、NoNewPrivs、只读根文件系统、仅 lo、1 CPU、2 GiB 内存及零额外 swap。真实 Chromium loopback 预检、源码包与运行候选的独立 SHA、包内/包外验证器逐字节一致、执行前后源码及 runtime 一致、JUnit 关键节点与零跳过门禁均须保留。

审计记录区分 loopback 次数与拒绝次数：`nonloopback_http_attempts=0`、`nonloopback_ssh_attempts=0`、`real_docker_attempts=0`；`loopback_ssh_attempts>=6`，HTTP loopback 次数如实保留。该计数覆盖 pytest 父进程的 HTTPX/Paramiko/Popen；容器无外网、仅 lo 是所有子进程的独立边界，不能把父进程计数说成所有进程的完整流量记录。

实际证明必须来自同一已提交源码构建的公开包与运行候选。不得用旧包搭配未提交的新 runner，也不得在测试中改源码后仍声明原提交通过。每次尝试独立保留失败、超时及最终结果，不覆盖或删去失败记录。

## 剩余范围的计算方式

以下清单以公开提交 `d72aacacd754ce83de7d69a2f5bb53e3b9feec95` 的 201 个顶层测试文件为基线：69 个完整文件已在本轮矩阵，1 个文件只选关键节点，仍有 131 个完整文件未纳入。验证器的 `proof.scope.uncovered_test_files` 会对实际同提交源码包重新计算完整差集；它是本次运行范围的准据，不能长期沿用本文数字。

后续新增的 `test_defense_binding_loss_driver.py`、`test_defense_binding_loss_lab.py` 属于另一份源码与独立范围，须在后续构建中显式纳入，不能静默加入本轮 1667 项或回填旧结果。`test_linux_commands.py` 的 Docker CLI 节点也尚未包含在本轮关键节点里。

2026-11-07 后续：固定 `cb928f4d6dbc1476043c74994050c2c3e40cd2c5` 及其独立准入镜像，18 文件 general **549 项**、9 文件 observation **290 项**、Root 单节点 **1 项**分别实跑通过，各组零失败、错误与跳过。冻结/有序 JUnit、源/runtime 和清理核对通过，见[当前实跑与旧失败](../tests/linux_product_validation_lab/README.md#增加依赖与观察组后的隔离导入修复)。旧 `04798c8` general 收集失败、一次未建立任务的运输异常均保留。已收口的三个 profile 仍不是完整产品范围，不能将不同版本与重叠组的数字相加当作全套通过。

## 八组后续矩阵

下一组的[独立验证器](../tests/linux_product_validation.py)已实现两个固定 profile：`general-controller-nonroot` 覆盖本节通用组和 Compose 组件/API，共 15 个文件；`readonly-policy-root` 只运行 `test_readonly_guard.py::test_actual_policy_symlink_permissions_and_parent_trust`。Linux flock 节点没有 root 要求，保留在非 root 范围实际执行，不因 Windows 上曾跳过而排除。Native curl 是必要前置，不能用缺少工具的 skip 取得通过。

两 profile 均固定 1 CPU、1 GiB、无额外 swap、PID256、只读根、仅 lo、capabilities 全零；所需 UID 分别为 10001 和 0。总预算 900 秒包括来源、测试与最终源码/runtime 复核。验证器只接受既定 profile，不接受任意测试选择；先在同一 Linux 环境 collection 并封存有序节点清单/摘要，再用独立子进程重收集核对，JUnit 必须逐节点精确匹配且零 skip。外置验证器须与同提交源包内文件一致，沿用源码、候选和运行文件前后核对、父进程传输审计及无网容器边界。

新增 43 项纯 Fake/合成 pytest 回执与旧验证器 28 项共 71 项本地回归通过；它们只验证验证器边界。尚未产生这两组的真实 Linux collection/execution，节点数也未从 Windows 计数推断。须先提交并重建含新验证器的准确源包，再由明确的 Linux 实验产生通过证明。旧 1667 范围和 `8b21` 原件不变，新范围不会并入旧结果。

2026-11-07 后续[首次实跑](../tests/linux_product_validation_lab/README.md)：固定 `af7a078` 源和实际准入 `1ebb` 镜像，Root 唯一节点 **1 项通过、零跳过**；非 Root 通用组在收集阶段失败，尚未执行测试。另起两次明确不执行测试的形状诊断，确认 479 个唯一节点、15 文件、精确排除项及必测节点齐全，但最长 nodeid 为 5,094 字符，超过旧 1,024 字符限制。原失败及清理回执保留；修复提高单项上限并保留最终 2 MiB 清单门，73 项本地验证器回归通过，仍待新提交制品的真实通用组验证。只收集诊断不计为通过，Root 结果也不替代通用组。

随后固定修复提交 `b6cdbb97e4f3774feb0c9cb0eb33d9c78b0f7f95`，新源码/候选包与独立准入 `9dc7d70c` 镜像的两组[实跑结果](../tests/linux_product_validation_lab/README.md#修复后新候选实跑)为：通用组 **479 全过**、Root 单节点 **1 项通过**，各自零失败、错误和跳过；完整冻结 nodeid 与执行/JUnit 有序匹配、源码/runtime 不变，清理及旧基线检查通过。旧收集失败仍保留；其余分组和完整产品验收继续未完成，不合并旧版本数字冒称全套通过。

每组先在目标 Linux 环境收集精确节点、固定数量和预算，再实跑。每组都需要独立的零跳过、前后源码/runtime 校验和原始 JUnit；组之间不得靠合计数字掩盖缺失节点。下列分组没有永久豁免，权限或依赖不适合当前容器的节点须移到明确的匹配矩阵，而不是当作通过。

### 下一版固定 profile（本地实现，待新制品 Linux 实跑）

通用 `general-controller-nonroot` 范围升级为 `general-controller-onboard-platform-privacy-linux/v2`，在原 15 文件上增加 `test_nginx_dependencies.py`、`test_nginx_dependencies_api.py`、`test_nginx_dependency_scope.py`，共 18 文件。浏览器和 SourceGate/Git 测试未混入本组。flock、四个原生 curl 节点和 Compose 的真实 loopback SSH 节点均为不可删的必测项；执行审计仍要求真实 SSH/curl 调用，第四个 curl 过大响应对照也不能省略。Root profile 仍只选择原来一个精确节点。

新增 `security-observation-nonroot`（范围 ID `security-observation-web-events-linux/v1`）只选择下文安全观察/Web 事件的固定 9 文件，不排除任何节点。它固定 UID/GID 10001、1 CPU/1 GiB/零额外 swap/PID256/只读根/仅 lo/cap0/NoNewPrivs/900 秒；selector、真实管道、进程组、GNU timeout、flock 继承、proc fd 元数据和符号链接节点均必须实际执行，JUnit 中任何 skip 都不算通过。当前这 9 文件没有需额外 root 权限的实际节点；模拟管理员安装的测试仍只证明其合成边界。

观察组不虚构 SSH 或 native curl 的 wire 要求；这两类计数可为零，外网、真实 Docker 和未授权 native 客户端仍必须为零。其原生 reader 对照需要**准确的 `/usr/bin/timeout` GNU 工具**：先运行固定 `--version` 并记录二进制 SHA，缺少或非 GNU 就拒绝，不安装、不跳过。仅该 profile 的父进程 guard 额外允许 `/usr/bin/timeout -k 1s {0.1s,3s} <同一 sys.executable> -I -c <固定测试中的 Python 代码>`，不允许 Shell、其他程序、解释器、时长或执行文件覆盖；单列 `local_timeout_attempts`，执行阶段至少一次。子进程的独立安全边界仍是无网、无宿主挂载/套接字的专属容器，计数不扩大成所有进程的完整流量证明。

三 profile 均保留 16,384 字符单 nodeid、最终 2 MiB 清单上限、同一 Linux 环境先收集/封存后独立执行、有序节点重收集/JUnit、零跳过及测试前后源码/runtime 见证。本次本地边界回归不产生新的 Linux 节点计数或通过结论；需要新提交源码包、候选和独立 runtime 准入后再实跑，旧 479/1 结果按原版本保留。

| 组 | 文件数 | 首选环境与需要分出的原生边界 |
| --- | ---: | --- |
| 通用控制端、接入、平台与脱敏 | 12 | 非 root/无网；Root-only 只读策略元数据另跑 root 临时命名空间。 |
| 安全观察与 Web 事件 | 9 | 非 root/仅 lo；Linux selector、flock、进程组和真实管道节点必须运行。 |
| 漏洞扫描、AI 分析、证据与通知 | 29 | 普通部分非 root/无网；Ubuntu 原生 APT 清单单独匹配发行版与系统 python3-apt。 |
| 补丁、自动处置与恢复 | 30 | 控制端/假执行器先跑；原生 APT parser、POSIX dirfd/umask/子进程预算保留实际检查。 |
| 服务激活与激活后恢复 | 18 | 控制端与假服务传输无网；Linux OFD/POSIX 锁交互必须实际运行，不能以模拟替代。 |
| 业务复验、交接、备份与存储 | 11 | 非 root/仅 lo；age 工具、文件系统和 Windows/需要 CAP_CHOWN 的节点分开。 |
| Nginx 变更与原生文件事务 | 13 | 假 runtime/控制逻辑与 root-owned 临时配置/journal 分开；不借用真实站点目录。 |
| 发布打包与纯假实验室边界 | 9 | 非 root/无网，准备 Git 与硬链接；假 Docker/Root helper 不得变成宿主 Docker 操作。 |

完整文件名单如下，均位于 `tests/`。

### 通用控制端、接入、平台与脱敏

- `test_ai.py`
- `test_api.py`
- `test_baselines.py`
- `test_collector.py`
- `test_collector_exec_deadline.py`（实际 Paramiko Channel 的内存 ACK 超时与锁释放回归）
- `test_diagnostics.py`
- `test_health.py`
- `test_host_onboarding.py`
- `test_host_preflight.py`
- `test_platforms.py`
- `test_readonly_guard.py`
- `test_redaction.py`
- `test_replay.py`

### 安全观察与 Web 事件

- `test_observation_api.py`
- `test_security_ai.py`
- `test_security_events.py`
- `test_security_monitor.py`
- `test_security_probe.py`
- `test_security_store.py`
- `test_web_integration.py`
- `test_web_security_events.py`
- `test_web_security_store.py`

### 漏洞扫描、AI 分析、证据与通知

- `test_vulnerability_ai.py`
- `test_vulnerability_ai_boundaries.py`
- `test_vulnerability_ai_failure_codes.py`
- `test_vulnerability_ai_focus.py`
- `test_vulnerability_ai_focus_integrity.py`
- `test_vulnerability_ai_focus_service.py`
- `test_vulnerability_ai_prompt.py`
- `test_vulnerability_ai_service.py`
- `test_vulnerability_ai_store.py`
- `test_vulnerability_ai_text_boundaries.py`
- `test_vulnerability_ai_text_categories.py`
- `test_vulnerability_evidence.py`
- `test_vulnerability_evidence_api.py`
- `test_vulnerability_evidence_cli.py`
- `test_vulnerability_evidence_export.py`
- `test_vulnerability_evidence_export_v2.py`
- `test_vulnerability_evidence_failed_projection.py`
- `test_vulnerability_evidence_golden.py`
- `test_vulnerability_evidence_store.py`
- `test_vulnerability_evidence_store_v2.py`
- `test_vulnerability_evidence_v2.py`
- `test_vulnerability_monitor.py`
- `test_vulnerability_rescan_queue.py`
- `test_vulnerability_scan.py`
- `test_vulnerability_scan_resources.py`
- `test_vulnerability_store.py`
- `test_vulnerability_watch_api.py`
- `test_vulnerability_webhook.py`
- `test_vulnerability_webhook_integration.py`

### 补丁、自动处置与恢复

- `test_automatic_ai.py`
- `test_automatic_ai_api.py`
- `test_automatic_ai_dispatch.py`
- `test_automatic_ai_integration.py`
- `test_automatic_ai_policy.py`
- `test_automatic_ai_store.py`
- `test_automatic_api.py`
- `test_automatic_monitor.py`
- `test_automatic_policy.py`
- `test_automatic_service.py`
- `test_automatic_store.py`
- `test_automatic_store_sidecars.py`
- `test_patch_agent.py`
- `test_patch_api.py`
- `test_patch_archive.py`
- `test_patch_client.py`
- `test_patch_client_eof.py`
- `test_patch_core.py`
- `test_patch_handoff_audit.py`
- `test_patch_install.py`
- `test_patch_install_safety.py`
- `test_patch_monitor.py`
- `test_patch_store.py`
- `test_patch_transaction.py`
- `test_patch_worker.py`
- `test_recovery_api.py`
- `test_recovery_boundaries.py`
- `test_recovery_client.py`
- `test_root_automatic.py`
- `test_root_recovery.py`

### 服务激活与激活后恢复

- `test_activation_client_boundaries.py`
- `test_activation_controller.py`
- `test_activation_guest_harness.py`
- `test_activation_historical_parent.py`
- `test_activation_observation.py`
- `test_activation_package_locks.py`
- `test_activation_private_manager.py`
- `test_activation_recovery_controller.py`
- `test_activation_recovery_main_wiring.py`
- `test_activation_recovery_root.py`
- `test_activation_recovery_store.py`
- `test_activation_recovery_transport.py`
- `test_activation_root_wiring.py`
- `test_activation_store_and_evidence.py`
- `test_activation_transfer.py`
- `test_activation_web_harness.py`
- `test_root_activation.py`
- `test_service_activation_policy.py`

### 业务复验、交接、备份与存储

- `test_business_probe.py`
- `test_business_readiness.py`
- `test_business_receipt_deadline.py`
- `test_handoff_timeline.py`
- `test_receipt_history_merge.py`
- `test_sealed_backup.py`
- `test_sealed_defense.py`
- `test_sealed_defense_native.py`
- `test_sealed_paths.py`
- `test_storage.py`
- `test_store_transfer.py`

### Nginx 变更与原生文件事务

- `test_nginx_action_journal.py`
- `test_nginx_config_plan.py`
- `test_nginx_config_snapshot.py`
- `test_nginx_fixture_action.py`
- `test_nginx_fixture_context.py`
- `test_nginx_fixture_context_syntax.py`
- `test_nginx_fixture_renewal.py`
- `test_nginx_fixture_restore.py`
- `test_nginx_fixture_runtime.py`
- `test_nginx_fixture_tls_runtime.py`
- `test_nginx_plan_approval.py`
- `test_nginx_plan_context.py`
- `test_nginx_plan_validation.py`

### 发布打包与纯假实验室边界

- `test_capacity_guest_probe.py`
- `test_docker_lab_harness.py`
- `test_linux_controller_package.py`
- `test_linux_controller_validation.py`
- `test_release_bundle.py`
- `test_ssh_fixture_evidence.py`
- `test_ssh_fixture_executor.py`
- `test_ssh_fixture_nft.py`
- `test_vps_fixture.py`

## 精确的平台排除与必须另跑的节点

Linux 只排除确实依赖 Windows 内核/DACL 的节点；它们仍是 Windows 验收的必需范围。本轮唯一排除：

- `tests/test_defense_client.py::test_windows_everyone_read_access_is_rejected`

后续完整文件矩阵再明确排除以下 7 个 Windows 节点，不按整文件排除 `test_sealed_paths.py`：

- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[delete-child]`
- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[write-data]`
- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[write-attributes]`
- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[write-dacl]`
- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[write-owner]`
- `tests/test_sealed_paths.py::test_windows_untrusted_ancestor_cannot_admit_native_execution[generic-all]`
- `tests/test_sealed_paths.py::test_windows_peer_creation_is_allowed_but_held_ancestor_cannot_be_renamed`

下列属于 Linux 功能或环境要求，不能以平台排除代替：

- `tests/test_sealed_paths.py::test_linux_other_uid_is_rejected_before_admission[ancestor]` 与 `[candidate]`：在独立临时命名空间使用实际 UID 0 和最小 CAP_CHOWN，目标只限新建的测试目录，事后恢复所有权。普通非 root 矩阵不因该权限缺失而给这两例记通过。
- `tests/test_readonly_guard.py::test_actual_policy_symlink_permissions_and_parent_trust`：需要实际 root-owned 策略元数据；与不需要 root 的 flock/杀父进程锁继承检查分开。
- `tests/test_nginx_fixture_renewal.py::test_pending_receipt_round_trips_through_the_private_journal`，以及 Nginx action/journal/snapshot/plan 中要求可信 Linux owner 的测试：使用独立 root 临时文件树。保留权限断言，不修改 getuid 或测试标记来冒充真实文件系统验收。
- `tests/test_patch_core.py::test_distribution_tagsection_parses_normalized_commented_deb822_sources` 与 `tests/test_vulnerability_scan.py::test_actual_distribution_version_comparison_keeps_epoch_and_tilde`：准备系统 Python 和发行版提供的 python3-apt，再无网执行。
- `tests/test_vulnerability_scan.py::test_native_repeated_inventory_has_stable_fingerprint_after_library_reinitialization`：单独 Ubuntu 24.04 环境，固定准备后的 APT 索引、可读权限与系统 python3-apt。Debian 上的跳过不能替代 Ubuntu 验收；索引外部变化也不能伪装为通过。
- `tests/test_linux_commands.py::test_actual_docker_cli_prefix_ignores_remote_context_and_tls_environment`：另列受控 Docker 能力矩阵，明确 daemon、实验目标与允许操作；普通非 root 控制端容器继续不挂宿主 Docker socket。

`test_sealed_backup.py` 的 `native_tools` 需要独立校验过的原生 age v1.3.2 工具；`test_release_bundle.py` 与打包组需要 Git。真实 curl、硬链接、符号链接、Linux selector/管道与可信临时目录必须按测试要求准备。依赖缺失导致的 `pytest.skip` 是尚未验收，不能计入通过数。给测试账户提供容器内专属可写 home/tmp；不能挂载宿主 home、密钥或业务目录。

## 执行和退出条件

先完成本轮固定 SSH 矩阵的实际结果，再沿上述分组补齐。每轮记录：源码提交与包 SHA、runner/helper SHA、完整节点、精确排除、依赖版本、UID/caps/挂载/网络、预算、JUnit 全量计数、关键节点、loopback 与拒绝审计、源码/runtime 前后核验、资源退出与清理证据。

准备依赖允许访问公开软件源，必须与无网测试阶段分离；不能借准备阶段导入旧应用镜像内的数据、真实服务器凭据或用户备份。失败后修复原因，重新构建同提交的新包并保留新旧尝试。只有各通道所需矩阵都完成，才报告对应平台范围完成；当前单一子矩阵绿色不代表全产品、多发行版、Windows、macOS 或不同 CPU 架构全部完成。

2026-11-07 新增[磁盘原生实验](../tests/disk_native_lab/README.md)：固定 `01176af` 源码在授权 `试验机 A` 的单个无网 Linux 容器中通过 21 项真实文件系统/FD/mmap 与产品 replay 报告链检查，记录 8 次 statvfs。容器和三项操作进程均已退出，原清单及十一份安全记录未变。该记录与旧 general/observation/Root 矩阵分列，不能作为最新全量节点、Ubuntu root 安装或专用 SSH 的通过证据。
