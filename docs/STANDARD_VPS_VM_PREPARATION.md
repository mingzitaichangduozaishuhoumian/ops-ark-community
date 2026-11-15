# 标准 VPS 隔离 VM 的准备证据

2026-11-07 更新。完整 Ubuntu 24.04 + systemd/Nginx/rootful Compose 首次接入仍未验收；本文记录已实际完成的公共工具准备、独立工具镜像接纳、暂停式 KVM 检查、官方 Ubuntu 镜像下载和签名核验，以及只读 qcow2 格式检查。不改变常驻实例、权限或支持承诺。

## 公共工具与独立镜像接纳

在授权测试机尾号 `试验机 A` 的独立容器中，仅执行一次七包公共准备，QEMU 为 `10.0.13`，自然退出 0，无 OOM；峰值内存 `445427712` 字节。它没有生成认证材料、启动 guest 或调用模型。官方 APT 验签保持启用，宿主没有安装这些包。

首轮旧任务因公开 Debian trixie 的 archive `.pgp` 普通文件与 `.gpg` 别名格式不符而在 APT 前终止。其清理又因两次 Docker inspect 的 `Mounts` 数组顺序不同而误拒；现场捕获证实内容与所有其他字段不变。独立、固定原 CID/netID 的补偿器只规范化该数组排序，完成清理；原管理器随后移除旧阶段目录，基线和缓存保留，失败原件不改。

新准备任务的封存调用产生镜像，但保留了原 Python entrypoint，不满足旧“空 entrypoint”契约，故旧 SEAL 仍记失败、没有补写旧完成回执。只读 Docker commit 事件明确关联原容器、当前 imageID 和目标 tag。随后用无网、无挂载、无设备、非 root、只读根、cap0 的一次性容器，显式指定 Python 入口，实际核对七包版本及 QEMU；自然退出后探针移除，原十一份安全记录和基线未变。

该结果形成独立工具镜像接纳合同：禁止默认入口和隐式 CMD；消费者必须使用固定显式入口及冻结源码。它没有把旧封存失败改绿，也不证明软件无漏洞。

| 证据 | SHA256 |
| --- | --- |
| 七包实际终态回执 | `9cd5e48ff89f7ff5e72bd27015ddcb3077ec9e2b4d6b1285a92268bf73ffdb37` |
| 独立接纳 `admission.safe.json` | `bdfa0dd9db4a99d37a5d0e1809b2467f93f7285b38f9bd762ba1ea7c81013a26` |
| 消费者合同 | `26723f9f181a1edbb8e863a00c6cdc9d0478dbc3bdad151fb15e9b9b77254bb4` |
| 旧失败任务清理收口，accepted=false | `50dc42618a59b6bffabc52f3434ff8147d4811cfdd979aa21db67277f5ca739d` |

## 实际暂停式 KVM

首次检查在创建态 `AppArmorProfile` 为空时安全停止，容器未启动，QEMU 未运行。只读诊断确认宿主 AppArmor 为启用、Docker 支持 AppArmor/seccomp，原对象 PID0/未启动且其他配置匹配；随后按原完整 CID 移除，其他容器和网络不变。

新独立任务只区分已实证的创建态 ABI：从未启动的对象允许空 AppArmor 字段，运行态双 inspect 及送源门仍要求真实 `docker-default`。没有预填字段或关闭防护；inside 源码和完整生命周期 BODY 保持不变。

实际 r2 的容器限制为 UID/GID10001、KVM 附加组994、cap0、NoNewPrivileges、默认 seccomp/AppArmor、只读根、network none、1 CPU、384 MiB 且无额外 swap、PID64、私有 `/tmp` 128 MiB。仅传 `/dev/kvm:rw`，没有磁盘、宿主目录、Docker socket、端口、host namespace、认证或模型输入。

冻结脚本启动唯一固定 QEMU，强制 KVM、1 vCPU、256 MiB、`-S`，只允许四条固定 QMP 命令。实际观察到 `prelaunch/running=false`、KVM present/enabled，以及同一已核身份进程的一个 VM fd 和一个 vCPU fd；没有恢复 CPU 执行。QEMU/原 attach CLI 自然退出 0，没有 TERM/KILL，原容器已删除，基线及原十一份工具记录保持。

| 证据 | SHA256 |
| --- | --- |
| 暂停式 KVM 实际结果 | `36e901197e8f9ba92b959f5e7355699decec3021648d49cd3aa832cfe852b509` |
| 实际发送源码 | `2e76a06cbe0cc10624393b1dd9ede4cf98ff1ec2871ab1ed5fade764a488cd7f` |
| inside 冻结脚本 | `794ac29b8a9783581b46a65c34072615e089327f93a773fae4a7f650282db0fb` |
| 创建态区分后的 outer profile | `d1873a21d7294f0da447d2b968045a1de17abf5ba6f31a7a97fdd0806af8f23e` |

独立只读复核已核实际发送源码与冻结输入逐字一致、一次派发、严格结果 schema 和全部通过标志。首次失败及其诊断/清理记录仍保留。宿主的小型安全审计目录有意留存，不称这些目录已删除。原日志、完整 inspect、密钥及业务数据未带入模型或仓库。

## 官方 Ubuntu 镜像的实际签名核验

在 `试验机 A` 新建的隔离下载容器中，固定获取 Ubuntu 24.04 amd64 `release-20260725` 的镜像、checksum、detached signature，以及 Ubuntu 公钥服务的公开材料。HTTPS 核证、完整主指纹、密钥有效期和撤销状态、GPG 机器签名结果、checksum 唯一文件条目和实际文件 SHA256 均通过。公钥服务只运输材料；信任依据为预先固定的完整 Ubuntu cloud-image 主指纹，未从下载响应自动接纳其他密钥。

实际镜像为 `624105472` 字节，SHA256 为 `d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac`。实际主密钥和 signer 指纹均为 `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`；获取到的材料中两者未过期、未撤销，签名 hash algorithm 为 10。此检查不证明公钥服务包含全部最新撤销材料，也不承诺镜像内容没有漏洞。

前两次失败保留：首次报告 `download_rejected`；随后用实际 stdlib HTTPResponse 的内存回归复现了正常 EOF 被误拒的缺陷，但未读取原失败的私有诊断来判定其具体响应。独立 EOF 修复后，第二次在获取公钥时报告 `http_headers_rejected`；只读公开文件元数据及固定公钥 GET 的头部分类确认该服务使用标准分块传输。新候选仅兼容无 Content-Length、无歧义单一 chunked，保持 decoded 字节界限及全部签名/摘要检查；重复 CL/TE/CE、冲突分帧、编码链和非 identity 内容编码仍拒绝。58 项本地检查不是实机验签的替代物；实机成功由独立第三个新任务取得，旧失败未改绿。

实际消费者为 UID10001、cap0、只读根、默认 AppArmor/seccomp、无设备或宿主控制 socket、1 CPU/512 MiB、PID128，仅见本轮新建输出目录。临时自有 bridge 无对外发布端口；TLS 连接使用已核公共地址及固定域名。成功后原下载容器及临时网络已删除，attach CLI 终结、其他资源基线和原十一份安全记录不变。已核验公开镜像留作下一阶段输入，不读取或导出私有诊断日志。

| 证据 | SHA256 |
| --- | --- |
| r3 实际签名核验与清理结果 | `58f1e3b3c82f1128a607f4ac73f7c5b310ec1bddb8a231ed65a40d70f898d167` |
| 发布的公开 manifest | `a4c156e6b37149610590891a94d998cf8a6e8ac08171d094243db8003a0ffe3a` |
| r3 实际发送源码 | `16644558a567a0cec81546b6e179d6147dbe0ab62e120e61151591d20e7eacf2` |
| 分帧兼容 verifier | `8b35e889e770cd7f9c64780f60da59806c0c42950d9ba85f5da55563bf53255b` |
| 58 项本地回归源码 | `4b2ce1c0b964e4b9a9cd775af120f56a84518fd52a70d5ba294101fc50ae7925` |
| 首次失败，unconfirmed | `f1401c5d44065b9e8fa8b5d80dd8cb207b055799dce5b760775bc2c3f50c61ed` |
| 第二次失败，unconfirmed | `af3f9ba6b8b977c5c7de5c432143fbff2756c8aa1fff2f220b42ce200ffedef9` |

## 实际只读 qcow2 格式检查

另一个无网、无设备、UID10001/cap0、只读根的消费者仅挂载已验签公开目录，采用独立 profile，执行固定 `qemu-img info`，通过继承的只读 FD 访问镜像。先重核 manifest 和完整文件摘要、原生 qcow2 头及引用字段，再解析 QEMU JSON，结束后再核文件身份和摘要；不创建 overlay、seed 或 guest。

实际格式为 qcow2，虚拟容量 `3758096384` 字节（3.5 GiB），文件大小仍为 `624105472` 字节。检查拒绝 backing/external data file、加密、snapshot、脏状态及未知特性或元数据。该固定镜像的 112 字节 v3 头中，新增八字节均为零；实际 file child 的 dirty 为 false、children 为空、format-specific 为 `type=file/data={}`。这些是已分类的 QEMU 元数据，不是忽略任意未知字段。

此前两个格式任务分别在旧 104 字节假定和旧四字段 child 假定处安全拒绝；两个过窄的结构诊断也保留为失败。随后按 QEMU 官方格式/QMP 定义和固定公开输入的独立类型投影核对，仅接纳已观测的可选字段。结构投影成功只记 `diagnostic_only`；独立新格式任务才取得 `format_checked`。不读取或带出原日志、完整 QEMU JSON 或私有诊断。

实际格式任务结束后，精确容器已删除，CLI 终结、基线及原十一份安全记录保持，公开输入继续只读保留。该结果确认这份 base 可进入下一阶段；不代表 guest 已启动或业务服务已经验收。

| 证据 | SHA256 |
| --- | --- |
| 实际格式检查及清理结果 | `31699a8bd4345ccf6bff6821c274ae4b41ec1d8afa4f929094b91f869376dabe` |
| 实际发送源码 | `8f7004580452a5f07ee877fc94b2804c421a8972be0153053708276b11f9262d` |
| 冻结格式 helper | `01d58e4bfc104fb36d801999cf0bb3306c1277877b11ee727b2025fb6214de0d` |
| 独立消费者 profile | `9e47e8f7247d6517a95e63dd84c016b54e14b1606e9affa7cd295f41bc86dd79` |
| 独立类型诊断，diagnostic_only | `5c3544b116aaf71ecf8648eac93d17279a9d0fd0cb47ec0dd4980b51213e0672` |

## 实际 guest 启动与未完成的 APT 准备

另一次独立任务实际生成本轮 NoCloud seed 和 qcow2 overlay，启动一次强制 KVM 的 QEMU。代理与 VM 容器共享经 PID/出生身份核对的私有 NetNS，没有主机公开端口、宿主目录共享或 Docker socket。guest 程序已通过 Ubuntu 24.04、x86_64 和 PID1=systemd 检查，随后在 `apt` 阶段发出闭合的 `unconfirmed` 失败回执。

该任务约 121 秒后结束。内层监督器拒绝把失败回执当作成功，QEMU 经固定 quit 终结，未使用 TERM/KILL；这不是干净 guest shutdown 或 `prepared_stopped`。外层按精确 ID 清理代理、VM 容器和网络，基线与原十一份安全记录保持。只提取已知前缀、精确字段的安全回执，未带出串口原文、私钥、公钥 packet 或数据内容。

旧 guest 程序把 setup、索引更新、安装、版本查询和 InRelease 核验都归入 `apt`，并丢弃具体异常码，因此当前证据不足以确定失败子步骤或唯一原因。该失败保持原结论；后续采用不执行 APT 的诊断环境，独立输出主机指纹和固定网络检查结果，不重复旧准备任务。

## 实际控制台依赖运行环境

固定 `af7a0786b741eb625bbbbfc767c0b07c7f07301f` 的公开源码闭包与锁，在独立 root/cap0、1 CPU/1 GiB 容器中只安装一次。UV 同步约 5.4 秒，内存峰值 `593420288` 字节，无 OOM，509 份源码和锁前后相同；未安装浏览器、未调用模型。一次封存后，另以 network none、只读根、UID10001/cap0 容器核对完整源码树、Python 3.13.18、十个锁定依赖版本和导入，才接纳运行镜像。

接纳镜像为 `sha256:1ebb97bd5b904e33e3150c1f59958d925cd7c6fa779cf2be16bff9eb8d081c87`。准备容器、提取 UV 的容器、接纳探针和临时网络均已删除；镜像与本轮公开输入/审计有意保留，其他基线不变。这证明依赖运行环境可用，不代表 Linux pytest 分组、控制台首次接入或业务复验已经通过。

## 传输生命周期的独立实测

无 guest、无磁盘、无 KVM、network none 的小型探针确认：当前 TCP character-device 转发在没有 guest 请求时已连接后端一次；主动关闭后端后，三秒窗口内没有新连接，QEMU 仍存活。探针随后终结唯一 held 子进程并移除自身容器，基线保持。

这与 [QEMU 文档](https://www.qemu.org/docs/master/system/invocation.html)所述的 character-device 生命周期一致，提示它与当前代理单请求后关闭的协议不匹配；短窗口测试不能证明永久不重连，也不能单独解释旧 APT 失败。后续固定目标逐连接中继需独立复核并在诊断 guest 中实测，不开放可由模型指定的命令、参数或目标。

| 新增实机证据 | SHA256 |
| --- | --- |
| guest 失败终态与清理 | `5e83e9ea873346fce3cb8c2054f607d8ce2b490bfb6a0e464ce7262c7c4ea2dd` |
| 已分类的 guest 失败回执 | `71ab2935a5d461d42cf21160381c96d1e63363116e5b65ae9483129fb0cf4f33` |
| 实际控制台依赖准备 | `35cc8080d4bd703117abe06ba0c3d07b87b5882304e55a765b5510625e94d349` |
| 独立无网、非 root 准入 | `ac3fa8bffe594ca5385b4e6bc79964f5b803341ef7305c153685f3283d1a1101` |
| 运行环境准备资源清理 | `824bb2e75046c27692ec02e7273273f080c3a5fbd51f721d8fbc752be4d47839` |
| guestfwd 生命周期观测 | `7cebcc0b95894fa97663af31148a1d64c773e8b1595db0e82406aa77b77187dc` |

## 后续实际服务子步失败

2026-11-07 的[新隔离 r7 任务](../tests/standard_guest_lab/README.md)已用精确十一字段的失败 v2 回执定位到 `services / sshd_syntax`，`sshd -t` 返回 255、未超时。新任务仅启动一次，沿用官方基盘、受限软件源代理和资源/权限边界；此前旧 APT、传输和回执失败仍保留，不能倒填它们缺失的退出码或子步骤。

本次约 95 秒后正常关机，取得 shutdown event、QEMU 退出 0；没有 quit/TERM/KILL。专属容器/网络已清理，原清单和十一份安全记录不变，原 worker 的 PID/birth 已查为 missing。Root 对已闭合的结果再次核验；没有读取或带出原日志、配置、密钥或磁盘正文。255 只证明该命令失败，不能直接认定配置错误或猜测唯一原因；后续先核查运行前置元数据。

## 标准实验环境准备已通过

同日后续[实机 r8/r9 记录](../tests/standard_guest_lab/README.md)先验证固定 SSH 运行目录条件修复，再修正 user-data 中不被 cloud-config schema 接纳的 `datasource_list`。原成功校验未放宽：r9 约 109.55 秒后取得 `prepared_stopped`，12 包、rootful Docker/Compose v2、Nginx 和三个初始探针通过，cloud done/exit 0/四标志全 true；正常关机和精确清理、原基线及十一安全记录保持均已复验，原 worker 已 missing。

r8 的 exit 2 和警告仍保留为失败，没有倒填唯一原因或改成成功；其安全回执和同原任务的只读恢复记录分列。r9 仍明确 guard_installed=false、product_enrolled=false、business_acceptance=pending，准备通过不是产品首次接入、故障闭环或正式业务验收通过。

## 尚未完成

官方镜像下载、签名、只读 qcow2 检查、guest 基础身份、控制台依赖及标准 Docker/Nginx/Compose 实验栈准备已有实机证据。产品专用账户/guard、真实 SSH 首次接入、完整故障与业务复验、备份和交接仍须在同一标准环境分别实跑。下一阶段工具的合成测试不充当这些结果，环境准备通过也不等于完整标准 VPS 交付。

安全原件保留在本地忽略目录 `data/standard-vps-tools-*`、`data/standard-vps-kvm-*`、`data/standard-vps-image-*`；它们不随公开源码包发布。完整交付要求继续见 [MVP 核对](MVP_DELIVERY_CHECK.md)，已验证的接入部分见 [Compose 候选发现](COMPOSE_DISCOVERY.md)。
