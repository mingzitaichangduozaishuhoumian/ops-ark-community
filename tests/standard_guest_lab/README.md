# 标准 Ubuntu guest 的分步准备证据

2026-11-07，授权 `试验机 A` 的全新隔离任务 `3dde40ed37a7fac5` 仅启动一次。
固定官方 Ubuntu 24.04 镜像与此前签名、SHA256、qcow2 结构证据一致；
只读公开基盘、新 overlay/seed、受限公开软件源代理和 VM 沿用原权限及资源边界。
没有改变常驻配置、权限或历史，没有重跑旧 r6。

本轮 r7 给所有失败阶段保留闭合原因，并把 services 拆为八个固定子步；
失败 schema/v2 精确十一字段，不含命令输出、异常文本、配置、公私钥内容或日志。
核心八组、宿主三十九项内存检查先由独立作者及 Root 分别通过，真实结果再单列。

[r7-failure.safe.json](r7-failure.safe.json) 是实际安全回执的本地核验摘要：

- 任务约 **95.009 秒**结束，失败点为 `services / sshd_syntax`，
  原固定 `/usr/sbin/sshd -t` 返回 **255**，没有超时。
- 由固定程序的阶段顺序可知已走过包安装、版本及来源检查；prepared/cloud-success 回执均不存在。
- 请求了正常关机，取得 guest shutdown event，QEMU 退出 0；没有 quit、TERM 或 KILL。
- 代理、VM 和网络按完整身份清理，原清单及十一份安全记录未变；
  [原 worker 终态查询](r7-worker-terminal.safe.json)确认原 PID/birth 已 missing。
- Root 以相同源码的闭合消费者和公开 source/profile 上下文再次验证内层结果。
  摘要中的 canonical SHA 标识语义规范化结果；不能冒充远端原始文件字节 SHA。

这些证据只确定失败命令，**不证明 SSH 配置有错，也未证明唯一原因**。
`sshd -t` 还涉及运行前置条件；下一步核查固定运行目录与 unit 的选定元数据，
不读取旧日志、配置、磁盘正文或密钥来猜测。未准备成功、未连接产品专用 SSH，
标准 Nginx/Compose 首次接入及整体业务验收继续保持待验。

核查方向来自 [Ubuntu 的 sshd 手册](https://manpages.ubuntu.com/manpages/noble/man8/sshd.8.html)
对测试模式和运行目录的要求，以及 [systemd 255 的 RuntimeDirectory 文档](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#RuntimeDirectory=)
对启动时创建、停止/重启时生命周期的说明。这些公开规则不证明本次 guest 的实际目录状态；
必须采到对应元数据，才能决定是否适用修复。

回执中的 `private_key_read=false` 指验收器没有提取或带出私钥；
不声称 OpenSSH 自身的密钥检查不使用该隔离 guest 生成的主机密钥。

## r8：固定运行目录修复成功，整体仍拒绝

同日新任务 `d653247f0b805727` 实际核到 `/run/sshd` 缺失、父目录可信、
effective unit 声明 `sshd/0755`，原测试返回 255。仅满足这些条件时，
目标 guest 相对 held 父目录创建一次固定目录，核验 root:root 0755 后复查返回 0；
没有替换或 chmod/chown 既有节点，也没有重跑 APT。
[r8 回执摘要](r8-prerequisite-and-cloud-failure.safe.json)保留了这一成功子步骤。

整体仍为 `unconfirmed / cloud_not_done`。固定前缀、安全字段选择器随后只取回
[八字段 cloud 状态](r8-cloud-recovered.safe.json)：exit 2、no_errors=true，
no_recoverable_errors=false、datasource_nocloud=true、modules_final_finished=false。
最后一个标志是“结束时间、错误、可恢复错误”的复合判据，不能推断 final 从未结束。
严格 cloud 成功门未放宽，任务不是干净 guest shutdown；专属资源仍已清理。

原结果中 prepared=null 也不是未执行的证明：异常跳过了已验证 slot 的复制。
同原任务的[固定 PREP 选择器](r8-prep-recovered.safe.json)按原严格校验器验证后，
仅返回计数、flags 和 canonical digest：12 包、rootful Docker、3 项初始检查均成立。
它不返回版本、镜像标识、指纹或完整对象。两次选择只读同一原任务，状态文件
SHA 前后均为 `5cef2d856b905b2bfe91e90e1c10b9ce20137504ef4f4fbb3766e83255cdf741`，
没有更改回执或重启动作。

这些筛选程序在目标端丢弃其他串口字节，只输出预定义、安全校验通过的闭合回执；
没有原始日志行、原始 status JSON、配置、密钥或磁盘正文外带。
最初 r8 摘要的 `raw_logs_read=false` 描述取回安全回执前的捕获时点，
不表示后来筛选程序无需在目标端处理该字节流。

## r9：标准实验环境准备通过

官方 [24.1](https://github.com/canonical/cloud-init/blob/24.1/cloudinit/config/schemas/schema-cloud-config-v1.json)
与 [26.1](https://github.com/canonical/cloud-init/blob/26.1/cloudinit/config/schemas/schema-cloud-config-v1.json)
cloud-config schema 不接纳 user-data 顶层 `datasource_list`。
新模板只移除这个不兼容项，保留原 system config 和 NoCloud seed/ISO 机制；
新监督器同时保留已验证的准备/云回执，typed negative 正常关机并继续标未确认。
原 `prepared/completed` 成功校验逐 AST 不变，消费者不能把失败云状态提升为成功。
这修正了已证实的模板缺口和观测缺口，不倒填 r8 原始警告的唯一原因。

新 RUN `62ec64cbfa9c5b89` 仅启动一次，约 **109.55 秒**后取得
**prepared_stopped**，见 [r9 实机摘要](r9-prepared.safe.json)：

- 12 个包、rootful Docker、Compose v2、Nginx 和 3 个初始探针通过原严格验证。
- cloud 回执为 done、exit 0，四项条件全 true；没有把 exit 2 或警告当作成功。
- SSH 固定前置修复再次完成 255 → 一次创建 → 复查 0，未知条件仍停止。
- 受控正常关机、shutdown event、QEMU 退出 0；没有 quit/TERM/KILL。
- 专属容器/网络已清理，原清单与十一份安全记录不变；
  [原 worker 终态](r9-worker-terminal.safe.json)确认原 PID/birth 已 missing。

源码与回执经独立审查、Root 本地模拟及同源码消费者再次验证。
observer 只向模型输出计数、状态和固定 flags，完整的闭合对象留在本地；
不输出版本、host 指纹或完整 PREP。模型调用为 0。

**此结果只完成标准实验环境准备。** guard_installed=false、product_enrolled=false，
business_acceptance=pending。产品专用账户/只读 guard 安装、真实 SSH 登记与调查、
三故障及客户交接的标准环境验收仍需后续完成，不能把实验探针当成这些功能已交付。

JSON 副本按仓库要求规范化 LF；私有原件保留。准备结果的 canonical digest 与原始
外层 observation 摘要字段分别标注，不把语义规范化副本称为远端原始字节。

## r11：真实 SSH 预检通过，后续调查未确认

2026 年 11 月 12 日，使用产品提交 `874bea8e3bdfa300719cd18535c833c871a70f73`
启动一轮新的隔离环境。该提交让预检识别 Ubuntu 打包的 Compose v2 数字后缀。
同一份旧实验准备记录中的版本，原解析器返回 `invalid_output`，修复版通过。

本次 RUN `3f96604748433965` 安装了专用只读入口。产品经真实 SSH 返回 `ready`，
用时 13.757 秒，8 项检查均为 `ok`：系统、工具、Nginx、容器、磁盘字节、
磁盘 inode、Compose v2 和 rootful Docker。模型调用为 0。

后续调查和读回尚未确认，整体终态为 `unconfirmed / container_changed`。
原 worker 已退出，专属容器已清理，原清单和十一份安全记录一致。
关机事件及收尾回执未获确认。本地闭合摘要 SHA256 为
`87d5742bce40e1c29b9d25493a7f8442125474326a4487aec294da632491af5e`。

独立 Docker 对照中，固定 exec 运行时只有 `ExecIDs` 发生变化，退出后恢复，容器 PID
始终一致。对照支持修正 SSH 窗口内的容器比较，r11 原始差异字段仍未知。

## r12：只读接入、磁盘调查和重启读回通过

新 RUN `2c1ff5e63b344b01` 仍用产品 `874bea8e3bdfa300719cd18535c833c871a70f73`。
验收工具只在 proxy 的活动 SSH 窗口排除已验证格式的顶层 `ExecIDs`，容器其余字段、
权限与进程身份仍按原规则校验。

- 错误指纹被拒绝，正确指纹完成登记。真实 SSH 预检 8 项均通过，用时 11.508 秒。
- 7 项受限入口检查通过，包含允许的固定命令、敏感文件命令与 shell 分隔符拒绝，
  以及 TCP 转发、PTY、SFTP 拒绝。
- 真实磁盘调查报告为 `no_issue_detected`。新控制端进程读回同一份报告，
  诊断、导出和交接摘要保持一致。业务复验状态为待验收。
- 收尾回执与本地结果摘要匹配。虚拟机正常关机，QEMU 退出 0，
  原 worker 已退出，专属资源清理完成。模型调用为 0。

本地闭合执行摘要 SHA256 为 `aeb04efa69ecd69f44ce19ef29d95853837fdb9620f3668276d633e227be49d4`。

同一隔离控制端的十库以 `stores-v1` 加密并完成认证恢复。两个独立恢复进程读回原报告，
报告、导出及交接摘要的 SHA256 均与原记录相符。备份范围为十库和清单。
快照工具在源目录产生四对 WAL/SHM 伴随文件，四个 WAL 均为空。这次恢复通过，
源目录无副作用的验收仍未通过。隔离恢复凭证 SHA256 为
`4aebb3f172e9c85ef8389e5eb870fee2858943ada5661c793befe7ec63f714bd`。

## r14：登记业务就绪检查通过

前一次 r13 在启动虚拟机之前被资源门槛拒绝，原 worker 已退出。
随后只读复查资源达标。新 RUN `aea1ea4f1b026d4e` 使用相同产品及验收代码。

通过认证的 `/business-readiness` 经受限 SSH 检查三个登记项，分别覆盖主站上游 A、
共享站上游 A 和共享站上游 B。三项均返回 200，完整响应匹配。
报告列表前后字节相同，回执只包含登记标识、HTTP 状态和匹配标志。

同一 RUN 还通过八项 SSH 预检、七项受限入口检查、真实磁盘报告、
新控制端进程读回、导出及交接摘要一致性。关机事件、QEMU 退出 0、
原 worker 退出和资源清理均已确认。处置后的业务复验保持待验收状态。

本地闭合执行摘要 SHA256 为 `ec60bbaa5bd0f13f18215393e24872ca2dc95e9fd781e1f753e450888afb093f`。
