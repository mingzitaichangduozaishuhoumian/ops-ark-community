# 私有发布候选与控制端恢复演练

发布候选从一个确定的 Git 提交打包。工作区修改、本机配置、数据库和密钥不进入候选。归档只附部署和验收所需的操作文档，旧实验记录留在私有仓库。使用当前仓库中的工具构建到一个新的本地文件，再用独立取得的提交与文件摘要核对接收件。

```console
python tools/release_bundle.py build --commit <full-commit> --output opsark-candidate.tar.gz
python tools/release_bundle.py verify opsark-candidate.tar.gz --expected-commit <full-commit> --expected-sha256 <archive-sha256>
```

工具检查固定文件范围、运行时与依赖锁文件里的版本，以及归档内每个文件的 SHA-256。核验无需解包、安装依赖或联网。提交、版本和归档摘要可用于记录候选身份。将摘要与归档分开，通过可信渠道提供。核验通过说明文件与预期摘要一致。

构建候选镜像后，从该镜像复制 `/app` 中的 `src`、`web`、`pyproject.toml` 和 `uv.lock` 到一个新的核验目录。执行 `verify-runtime`，逐文件与归档核对。核验应在只读取镜像文件的临时容器副本上完成。可复现归档中的文件时间固定，遇到构建缓存与实际源码不一致时，为临时构建目录更新时间戳并禁用缓存重新构建，随后再次核验镜像内容。

```console
python tools/release_bundle.py verify-runtime opsark-candidate.tar.gz /private/image-runtime --expected-commit <full-commit> --expected-sha256 <archive-sha256>
```

只读容器 CI 使用同一核验命令，逐文件比较已构建容器和该次检出的提交。

仓库为 Python、TOML、JavaScript、HTML、CSS、JSON 和 `uv.lock` 固定 LF 换行。本轮 Windows 常规 Git 归档曾把测试源码转换为 CRLF，被运行文件核验拒绝；补齐属性后，在 CRLF 配置下重新导出，74 个运行文件与候选一致。正式候选继续从 Git 原始对象打包。另行导出完整测试源码时可使用 `git -c core.autocrlf=false archive`，执行前仍须核对运行文件，依赖安装成功不能替代源码核验。

## 0.19 离线加密交接候选

开发分支 `3e7f848` 新增的 SSH 原任务跟进、查询 fence、进程恢复及业务摘要，已在 `试验机 A` 的[独立 Linux 控制端断网验证](../tests/linux_controller_lab/README.md)通过 217 项、零跳过，包括真实 Chromium/loopback 与两个关键 POSIX/Linux 节点。454 文件 Git 源码和正式候选内 94 个 runtime 执行前后相等；UID 10001、cap0、NNP、仅 lo，1 CPU/2 GiB 下峰值约 571 MiB，无 OOM。本轮资源清理、原容器/网络基线一致；它没有替代下述旧完整 pytest 或 GitHub 最新跨平台矩阵。

冻结提交 `8b9698ecb77f0eda8c2b9cd2f0637f05dd7d8a67` 的归档含 147 个文件，SHA-256 为 `eb539e7a02b3789df689798e68c29412bf136e5a2097f11ace54e3a05a51f08e`；75 个运行文件摘要为 `e43f8468040d1d33d452598f375915824c36733bb6da08d025428d81e87398ea`。离线加密工具和操作说明随归档提供，原生 age 二进制由管理员另行独立核验。

该冻结源码在 Windows 11 / Python 3.13.11 完整 pytest 为 3,826 通过、183 跳过、覆盖率 91.33%；授权测试机 Ubuntu 24.04 隔离容器 / Python 3.13.11 为 3,987 通过、22 跳过、覆盖率 91%。两边均为零失败及错误、4,009 项收集，真实加密交接 44 项均全部通过，具体平台跳过及首轮 Windows 记录器失败见[加密交接验收](SEALED_BACKUP.md#验证状态)。

Linux 无网络/端口、1 CPU/1 GiB 且无额外 swap，496 秒完成；测试进程组峰值约 580 MiB，无 OOM、超时或预算停止。结束后专用容器与私有目录已删除，既有容器和网络基线一致。Windows 临时工具和假身份已清理；测试前后源码摘要一致。测试输入仅用合成凭据；远端编排通过既定 SSH 通道，传输凭据不作为测试或模型输入。未调用实际模型或修改常驻实例。

这里只验证假十库、原配置保真封装和惰性恢复。实际客户交付仍须独立核对可信收件人和密文哈希、另备凭据及可信镜像，并按下节验证恢复副本和业务；加密工具不会自动执行这些部署动作。GitHub 的十项检查均因账户账单或支出限制在启动前被拒绝，不能以手工结果宣称跨平台矩阵已过。候选 CI

## 十库恢复演练

异机交付原始快照前，使用[离线加密交接](SEALED_BACKUP.md)在本机封装，只传密文。需要同时保存配置和镜像时按固定交接档案登记；镜像身份本身不等于镜像字节备份。恢复后仍执行本节的断网副本验收。

管理员停止本次快照涉及的全部写入者后，用 `snapshot --confirm-quiescent` 读取控制端数据目录。该选项要求源文件在整个操作期间保持稳定。对于没有非空 WAL 的库，使用 SQLite 3.22.0 及以上的不可变读取，避免源端创建辅助文件。不可变连接会跳过 SQLite 文件锁和变更检测。对于存在非空 WAL 的库，工具将主库和 WAL 暂存到私有输出目录，再让 SQLite 在暂存副本上读取已提交记录。保留原有 WAL，并为单库及其 WAL 的临时副本预留空间。发现任何回滚日志时命令会拒绝发布，须先用正常的 SQLite 恢复流程处理源库。未加此选项时，`snapshot` 沿用带锁的 SQLite Backup API，源目录可能出现 SQLite 辅助文件。跨数据库没有全局事务，正式迁移的最终快照必须在停止写入后生成。源目录、快照目录和演练目录需要彼此独立。以下命令中的输出目录须不存在或为空，演练数据与生产数据分开存放。[SQLite 只读 WAL 文档](https://sqlite.org/wal.html#read_only_databases) · [不可变读取参数](https://sqlite.org/uri.html#uriimmutable)

```console
python deploy/observer/store_transfer.py snapshot /private/opsark-source /private/opsark-snapshot --confirm-quiescent
python deploy/observer/store_transfer.py verify /private/opsark-snapshot
python deploy/observer/store_transfer.py rehearse /private/opsark-snapshot /private/opsark-rehearsal
python deploy/observer/store_transfer.py verify /private/opsark-rehearsal
```

`verify` 要求十个登记的 SQLite 文件和完成状态的 manifest。它重新计算文件与表记录摘要，检查 SQLite 完整性和外键，遇到缺库、摘要不一致或意外文件会停止。`rehearse` 在核验后创建独立副本，再比对副本的表结构和记录。它不会清空任务、通知或租约。旧版本缺库的目录仍可用原有迁移工具处理，核验时应如实记录为不完整。快照内含运维历史，应按私有数据加密保存，身份凭据按原部署流程单独保管。

新版 `reports.sqlite3` 包含独立的业务复验回执表。十库快照会一并保存并核验这张表。历史合并命令可接受带或不带回执表的报告库，对已有回执逐条核对。同一回执 ID 内容不一致时停止发布合并结果。单独合并报告与基线时，补丁账本仍使用目标环境自己的原任务和审批记录。没有匹配账本的回执无法作为该环境的业务验收。

离线核验通过后，使用待验收镜像启动另一个无网络、无端口映射的临时容器，只挂载演练副本。先把演练 manifest 移到私有审计目录，为该副本准备容器用户可读写的权限。通过容器内的回环接口核对认证、手动模式、已保存报告和导出内容，再重启确认历史可重复读取。验收记录应注明镜像版本、十库核验结果、哪些历史记录和接口实际通过，以及当前环境的覆盖范围。

2026 年 11 月 5 日，测试机验证了提交 `ecfaec2` 的 `0.17.0` 私有候选。归档包含 116 个文件，SHA-256 为 `7a4422515fa3806296a3286212732fda425a5df18d56c695febe49cae567bef7`。测试机独立核对归档，执行 Compose 配置校验并按候选 Dockerfile 构建。在无外部网络和端口映射的独立容器中生成一份回放报告，完整核对十库后启动恢复副本。副本生成独立登录令牌，原报告与客户摘要逐字节一致，重启后可重复读取，原快照摘要保持一致。本次覆盖的是控制端历史与启动验收，使用合成回放数据。

同日完成从 `0.17.0` 到 `0.18.0` 的断网恢复。首次镜像混入旧版本源码，被版本核对拒绝。为临时构建目录更新时间戳并禁用缓存后重新构建，核对镜像中 72 个运行文件，与已验证归档完全一致。同一核验命令拒绝了旧镜像。新容器通过十库恢复、报告与客户摘要逐字节对照、重启复验和独立令牌检查，原快照文件摘要一致。

新版控制端还在断网副本中读回了此前真实补丁验收的原任务和四份报告。失败、待验收和通过三份客户摘要与浏览器首次下载逐字节一致，重启后再次核对通过。此项单独验证了两库离线归档中的真实历史读取，原归档摘要一致。

### 含业务复验回执的十库冷恢复

2026 年 11 月 5 日，测试机从 `06cc09a` 的私有归档重新构建候选镜像。归档 SHA-256 为 `999cfc1cc40b9575cd49659b69b3bb29b4074c44effdff5b696af70bbdc7afc7`，镜像内 73 个运行文件逐一与归档核对。源控制端直接使用镜像内的应用和页面，在真实 SSH 与 Nginx 上生成失败、失败、待验收、通过四条回执。审批和原任务对账是隔离夹具的合成记录。

停止源控制端后生成并核验十库冷快照。断网副本只挂载恢复出的数据库，首次启动生成独立令牌。原报告、原任务对账和四条回执可查，四份摘要的 SHA-256 与冷备份前一致，重启后重新核对也一致。新复验请求被拒绝，回执无法从调查报告或 AI 入口读取。验收前后源快照的文件摘要一致。

从源码仓库复验时，使用已核验的候选镜像 ID 和本机固定的 SSH/Nginx 实验镜像 ID。两个命令都要求管理员控制的私有实验根目录位于 `/var/lib/opsark-release-lab` 下。冷快照及同目录的预期摘要文件只保留在实验目录内。

```console
sudo python3 -I tests/business_readiness_lab.py --root <private-lab> --ssh-image sha256:<fixture-image> --nginx-image sha256:<fixture-image> --controller-image sha256:<candidate-image> --confirm-isolated --handoff --cold-snapshot <private-lab>/cold
sudo python3 -I tests/business_handoff_restore_lab.py --root <private-lab> --snapshot <private-lab>/cold --expected <private-lab>/cold.expected.json --image sha256:<candidate-image> --confirm-isolated
```

该候选的十项 GitHub Actions 作业都因账户账单或支出限制在启动前被拒绝，未执行测试步骤。GitHub Actions 记录

### 含 SSH 防护观察的断网恢复

测试机从私有候选 `1876359` 归档重新构建镜像。归档 SHA-256 为 `4767eb6b09634a51df9dd462f249924677822094f14fd1042cf63433b8df3554`，镜像内 74 个运行文件与归档一致。源控制台使用镜像内置应用，在真实 TCP 丢回执后经受限 SSH 查回原动作。只读 SSH 监听器停机时，停止控制台并保存十库冷快照，其中保留了上次确认的 `active` 观察和原采集时间。

恢复演练只复制经核验的数据库，并用原公开主机指纹和新生成的测试凭据重新登记同一隔离范围。副本以非 root 用户在断网容器运行，首次启动生成独立控制台令牌。历史观察、原时间及作用域均可读回。重新查询返回 `unavailable`，缓存行保持一致，重启后再次核对通过。源冷快照文件的摘要保持一致。

源私钥和控制台令牌未进入十库备份。实验公钥及预期摘要文件留在私有实验目录，真实部署凭据仍由部署者独立保管。

```console
sudo python3 -I tests/ssh_defense_private_lab.py --root <private-lab> --image sha256:<target-fixture-image> --controller-image sha256:<candidate-image> --cold-snapshot <private-lab>/cold --confirm-isolated
sudo python3 -I tests/ssh_defense_restore_lab.py --root <private-lab> --snapshot <private-lab>/cold --expected <private-lab>/cold.expected.json --image sha256:<candidate-image> --confirm-isolated
```

## 从空清单完成首次接入

测试机使用 `d7f7b615384c2d870db1d4eed7135cb2c605e9e4` 的私有候选，从空清单和新数据目录完成实际浏览器接入。归档 SHA-256 为 `e89291a1b89fcf584d595a84db5c119ec6e5e798f3f8f61fea3419e4518d567a`，控制台镜像内 74 个运行文件与归档逐一一致。浏览器没有拦截或模拟接口，SSH 使用原生 OpenSSH 和正式只读安装器。

错误指纹被拒绝，核对后的公开主机密钥生成登记材料。部署者按实际输出安装专用账户、公钥和受限策略。固定采集命令执行成功，任意命令和写文件命令被拒绝。接入预检明确保留 Docker、systemd 缺口，首次调查取得真实 Nginx 上游拒绝连接证据，交接摘要标记待验收。控制台重启后，从界面查回原报告并重新下载摘要，内容保持一致。

本轮没有配置模型或业务检查，不计为 AI 调用、业务恢复或完整系统管理验收。摘要核对了具体测试元数据、令牌与凭据引用的排除，没有注入隐私 canary。重启等待和浏览器历史选择的测试驱动已修正，产品运行文件保持不变。复验需要完整源码仓库，阶段命令与准确边界见 [首次接入验收](../tests/onboarding_lab/README.md)。
