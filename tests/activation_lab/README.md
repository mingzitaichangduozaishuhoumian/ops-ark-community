# Debian 原生服务激活验收

在授权的本地 Linux Docker Engine 上，从仓库根目录执行（Windows Docker Desktop 的 Linux Engine 也可）：

```sh
OPSARK_DISPOSABLE_ACTIVATION_LAB=1 uv run python tests/activation_guest_acceptance.py --image debian:12
OPSARK_DISPOSABLE_ACTIVATION_LAB=1 uv run python tests/activation_guest_acceptance.py --image debian:13
```

PowerShell 先设置 `$env:OPSARK_DISPOSABLE_ACTIVATION_LAB='1'`，再分别运行两个 `uv run` 命令。只接受这两个镜像；固定连接本机 Docker，忽略 `DOCKER_*` 重定向。构建上下文只复制实验文件和受审 Root 源码，不包含 `data/`、密钥或控制端配置。不使用现有 VPS 或常驻实例。

每次随机命名并标记独立镜像和 systemd guest，运行期 `network=none`、无端口发布、host bind、卷或 Docker socket。SSH 与 HTTP 只走 guest loopback。资源为 1 CPU、1 GiB、256 PIDs，`restart=no`、private cgroup namespace，沿用漏洞实验的 `SYS_ADMIN`、`SYS_PTRACE` 和 AppArmor unconfined。guest 共享宿主内核，不承载漏洞利用或其它不可信代码。

服务通过 ctypes 加载 guest 私有的 zlib 副本，再原子替换该文件，产生真实的 deleted 映射。没有包升级、降级或漏洞植入。历史 pending 补丁、自动暂停与 vendor finding 是明确标注的合成前置件；Debian 清单适配器读取实际 dpkg/APT 状态。只替换测试进程内的 `core.load_policy`、`core.inventory`、`core.scan_packages`，不改生产文件、发行版门禁或 Python/原生工具。生产 Ubuntu-only 清单继续拒绝 Debian。

真实执行范围包括：Root 激活计划/批准/单次 systemd worker、PID1 属性、配置与管理器环境绑定、四个 APT/dpkg 内核锁、进程身份/映射、登记 HTTP、dpkg audit 和受限 SSH 新连接。专用 Ed25519 key 只用于此 guest，禁 root/密码登录、转发与任意命令，sudo 只允许固定实验入口。默认入口允许三个 activation RPC、模式同步 `set_mode` 和只读 `automatic_status`；独立复扫模式另明确允许固定的只读 `scan`，任何模式都不能安装补丁。worker 只改为调用同一测试适配器；执行的仍是生产 `activation.run`。

负向覆盖手动提交、模式修订、摘要/上下文、过期、unit/管理器环境/父任务漂移、worker/APT/dpkg 锁、SSH 关键单元及任意 SSH 命令。另用 Root 私有的有界 worker gate，让已批准任务在实际执行前遇到环境漂移，确认拒绝且无重启意图；不修改生产 worker。两次独立批准分别产生一次拒绝和一次成功，另有一次显式重复提交对照。过期用重封装的已过期实验计划验证，不伪称等待五分钟；丢回执由客户端丢弃实际收到的回复验证，不冒称真实网络断线。成功后只查原 ID，真实旧 SSH 连接仍不可完成验收，必须建立真实新 SSH；再做一次重复 submit/worker 对照，确认只有一个持久重启意图和同一新 PID。原父任务、计划、manifest、暂停逐字保留，dpkg/APT 状态不变，最后转 manual2。

原件默认保存到 Git 忽略的 `data/activation-guest-acceptance/<发行版>-<run>/`，含实际 OS/架构/Python/systemd/OpenSSH、十文件 SHA、镜像/容器身份、逐项结果、Root 计划与回执、journal 和清理记录；不导出私钥。退出先导出，再核对完整容器 ID/唯一标签，停止删除本次 guest 与镜像；不 prune 或删除基础镜像。验收失败同样留证，不删除旧结果或重置已有 guest 以制造成功。

上面的原生 CLI 路径不覆盖 Web 批准。真实 Web 路径见下文；两条路径都不代表 Debian 官方漏洞评估、APT 安装或完整业务恢复验收。实测结果及发现的兼容性边界记录在[实现记录](../../docs/IMPLEMENTATION_NOTES.md)。

## 真实 Web 批准闭环

每次必须使用新的 guest；例如先设置同一显式 opt-in，再执行：

```sh
uv run python tests/activation_guest_acceptance.py --image debian:12 --web-browser chromium
uv run python tests/activation_guest_acceptance.py --image debian:13 --web-browser chromium
```

`--web-browser` 同时接受 `firefox`、`webkit`。CI 在每个 Debian 版本依次运行三个浏览器，每个组合独立创建/清理 guest，不复用已经完成激活的环境。运行前用 `uv run playwright install --with-deps chromium firefox webkit` 安装对应浏览器及 Linux 依赖；Windows 无需 `--with-deps`。

guest 仍为 `network=none`、无发布端口/host bind/卷。宿主只监听两个临时 `127.0.0.1` 端口：正式 Uvicorn 控制台，以及透明 SSH 字节转发。转发通过一条常驻、非 root `docker exec` 标准输入/输出通道，每次请求重新连接 guest 自己的 `127.0.0.1:22`，不读取/修改 RPC、不预建或复用 SSH 会话；正式 Paramiko 客户端继续验证专用 key 和从本次 guest 复制的 host key。产品 SSH 超时不变，原生新连接证明仍由 guest sshd 祖先和内核启动 tick 决定。宿主 Docker socket 不进入 guest 或 Web 控制台。

临时控制台直接运行正式 `opsark.main:app`、全部正式 API/monitor/SQLite 与当前 Web 资源。清除继承的 `OPSARK_*`，仅登记本次 guest 和临时数据目录；不继承真实模型、采集、自动 grant 或部署凭据。修复 key 仅在临时私有目录复制，另生成一个未启用的只读登记 key 以满足库存结构；此实验不验收只读采集角色。父任务/计划从本次合成前置件原样导入，暂停由真实只读安全 RPC 导入产品缓存，快照后不再改写。

浏览器无 route mock、假 API 或 invoker 替换。实际验证登录鉴权、手动模式预览不能批准、未勾选和取消不提交、错误确认/摘要/模式拒绝、1440/390 页面、一次勾选并批准、后台新 SSH 验证、真实证据下载、真实控制端进程替换后重新登录、原 ID/通知不重复及 Web 切回 manual。Root 原任务/计划/manifest/暂停逐字比较，控制端原父任务/计划/暂停 SQL 行单独比较；只允许新增激活记录、模式及正常 monitor 元数据变化。

Windows 强制结束控制端进程后会保留未到期的 monitor 租约，验收等待其自然到期，不清表、改租约或重放提交。控制端对不超过一秒的未来计划可以先有界等待实际 UTC 追上，再执行原时效校验；未来/到期或时钟未前进仍拒绝，不改 Root TTL 或扩大授权。

额外证据包括 `web-before.json`、`web-after.json`、请求/响应记录（不含令牌头）、四张截图、真实下载证据包、最终回执、浏览器版本、控制端 PID、Root 十文件/控制端源码/Web 资源 SHA，以及冻结后的十库备份。临时 key/令牌不导出。未开启下述复扫开关时，漏洞观察关闭，证据包仍为 incomplete。失败试验保留原件，不计作完整 Web 验收通过。

## 激活后的独立原生复扫与导出

```sh
uv run python tests/activation_guest_acceptance.py --image debian:12 --web-browser chromium --activation-rescan
uv run python tests/activation_guest_acceptance.py --image debian:13 --web-browser chromium --activation-rescan
```

仍需同一 disposable opt-in；该开关必须与真实 Web 路径一起使用。CI 的两个 Debian job 对三浏览器均开启此模式，原生 CLI 验收仍单独保留。

开启后只给当前 guest 写 Root 私有的实验标记，允许受限 `scan`。正式 `VulnerabilityMonitor` 通过真实 SSH 发起读取，获得新 scan ID 和真实包版本、APT 状态摘要、进程、运行时映射及 HTTP/服务状态；数据写入 Root `lab-scans/<scan_id>.json`。没有调用 Ubuntu-only 扫描器冒充 Debian 官方判定，也不输出虚构 CVE/官方来源：`findings=[]`、`source_receipts=[]`、coverage=partial、assessment_kind=not_evaluated。原父任务的 provenance 明确为 synthetic_fixture。

正式激活 monitor 以本次 activation ID 排独立 `service_activation` 请求，保留 `job_id=null` 和 `original_job_id`。Root 私有、有界的只读复扫 hold 仅用于观察 pending/claimed 时的真实下载，不改回执或调度状态；释放后由真实 monitor 完成复扫。完成必须绑定唯一扫描 ID、观察 ID、作用域和时间，随后额外发起一份真实“最新扫描”，确认下载仍引用原复扫；控制端重启也不能改关联或重放扫描。源队列未完成或缺观察时保持 incomplete，不从 latest 回填。

`collection_evidence` 只保留至多 16 KiB 的声明采集事实及 facts_digest；原生采集和未执行供应商判定分列。`evidence_status=internally_consistent` 仅表示记录和关联一致，不代表 Debian CVE 已评估、漏洞已消除或原安装已 verified。真实原生复扫不得生成虚构的漏洞确认/解除事件；原任务与两侧暂停保持。

清理 guest/控制端后，自动调用新的离线入口核对真实下载、pending 下载及五种重封装修改副本，原下载不改写：

```sh
uv run python tools/verify_activation_evidence.py /private/downloaded-activation.json
```

工具只读取指定本地 JSON，不读取当前凭据、不访问 SQLite、SSH 或模型；输出结构/关联核验和明确 provenance。完整内部一致包退出 0；缺件/pending 为 incomplete、修改矛盾为 invalid，均退出 2。`integrity_valid` 不等于证据齐全，SHA 也不是来源签名，`origin_authenticity` 始终 not_authenticated。旧 `tools/verify_evidence.py` 继续只处理原漏洞证据类型。
