# Nginx 本机依赖只读发现

本功能自动把**磁盘配置中可解析的本机 TCP 上游**与**管理员授权的一个 Compose 项目的发布端口**关联起来，多个站点引用相同上游或服务时自动列出共享关系。无需先人工确认某个容器属于该站点，候选关联也不会写入登记。

这是一份有时间、配置摘要和来源行号的观察记录。`loaded_generation=unknown`：磁盘文件、Nginx active 状态和配置语法检测均不能证明当前 worker 已经加载这些文件。本功能不执行 reload，不运行完整 Nginx 语法检查，也不宣告业务恢复；`actions_enabled=false`，不调用 AI。卷、数据库、网络与跨机的完整共享依赖仍未交付。

## 管理员登记范围

服务器端 helper 固定安装为 `/usr/local/libexec/opsark-nginx-dependencies`，只读取 root 拥有且其他用户不可写的 `/etc/opsark/nginx-dependency-scope.json`。SSH/API/模型不能传入路径、项目或命令。范围示例（请按实际部署收紧）：

```json
{
  "schema_version": 1,
  "entry": "/etc/nginx/nginx.conf",
  "include_files": ["/etc/nginx/mime.types"],
  "include_roots": ["/etc/nginx/conf.d", "/etc/nginx/sites-enabled", "/etc/nginx/modules-enabled"],
  "symlink_roots": ["/etc/nginx/sites-available"],
  "compose_project": "demo"
}
```

配置扫描最多 32 文件、128 KiB、8 层 include，输出不超过 14,000 字节，内部 4 秒、外层固定 timeout 5 秒。入口和精确 include 文件接受 `.conf` 及明确的 `mime.types`；允许根内扫描 `.conf` 和标准 `default` 站点文件。`sites-enabled` 的叶链接只能指向管理员登记的 `symlink_roots`，每级父目录和目标文件必须可信。越界、循环、重复 include、未知路径、链接逃逸、文件/目录成员或范围漂移、超时、截断一律不给部分结果。引用 `/usr/share` 等范围外动态模块配置的环境暂不适配，不应扩大根目录来绕过拒绝。

在管理员本地核对该 JSON 后计算**原始字节 SHA256**，填入控制台现有主机登记（不从页面上传范围内容）：

```toml
compose_project = "demo"
container_binding_confirmed = false
nginx_dependency_scope_digest = "<服务器端范围文件原始字节的64位SHA256>"
```

保留现有的独立 SSH 凭据、可信主机记录和权限。用原 `deploy/readonly/export_policy.py` 为该主机重新导出精确策略，再由管理员按原安装流程应用策略。新策略只增加这一条无参数命令：

```text
LC_ALL=C timeout -k 1s 5s /usr/local/libexec/opsark-nginx-dependencies
```

最后由管理员在目标机使用审核过、root 拥有的源码目录执行：

```text
python3 -I /absolute/reviewed/deploy/readonly/install_nginx_dependencies.py --scope /absolute/reviewed/scope.json --expected-sha256 <独立核对的SHA256>
```

安装器只复制该 helper、其 scope 及专属完整性标记；要求已安装策略包含精确命令。它不创建账号、不加 Docker 组、不修改 sudo/SSH 配置、不重启服务；拒绝接管无标记或已漂移文件。升级中断后只接受标记中的旧/新摘要。它不能替代管理员对新读取范围的授权。

## 支持与证据

支持 literal `server_name`、TCP `listen`、literal `location` 中的 `proxy_pass http(s)://127.0.0.0/8:port` 或 `[::1]:port`，以及只含 literal 本机 TCP `server` 成员的命名 upstream。关联同时比较地址族、绑定地址、TCP 和宿主发布端口；IPv4 `0.0.0.0` 和 IPv6 `::` 仅匹配各自地址族。两个可匹配容器不会自动选一个；仅 EXPOSE、UDP、不同端口均不匹配。

变量、regex location、重写/条件路由、外部域名/地址、Unix socket、不完整 server 或重复虚拟主机保持不可确认。helper 是保守配置词法/结构投影，不是完整 Nginx 语法验证器；即使得到唯一候选，也只证明这些磁盘指令和当时 Docker 发布元数据可关联，不证明站点生效或应用依赖完整。Compose 在同一固定 SSH 会话中于配置观察前后各采一次，元数据变化则丢弃本次关系。

原始配置只在目标机内存内读取，不经 SSH 返回，不写日志，不传给模型；不读取证书/私钥、认证文件、环境变量、Compose 文件、日志、业务数据库或卷内容。只返回白名单域名、监听/本机上游、受限文件路径与 SHA/行号、服务/容器候选引用及状态。敏感凭据或数据库信号（包括注释中的测试 canary）整次拒绝；控制端再次执行既有敏感内容门禁和严格 DTO 检查，未知字段不被忽略。错误信息仅固定类别。

在主机卡片点击“观察 Nginx 依赖”即可看到自动关系、共享站点和配置摘要列表。已鉴权主机元数据只公开 scope SHA 和包含项目/目标/可信身份的不可逆绑定摘要，不公开配置或凭据。UI 同时绑定请求时的两个摘要，回执到达后再读取一次主机元数据；即使主机地址没变，范围或项目已变的旧结果也不显示。新观察立即清除旧关系；登出或切换目标后，旧请求结果不会附到新卡片。这里没有批准、登记、重启、重载或修复按钮。

## 容器重启前检查站点关联

已有受控容器重启预览且仍待批准时，可点「检查站点影响（只读）」。主机需同时登记已确认归属的 Compose 容器和 Nginx 依赖范围。检查使用现有只读 SSH 会话和指纹，比较配置观察前后的 Compose 快照，按预览里的完整容器 ID 关联可唯一核实的本机发布端口。结果只显示站点、配置来源行号和观察时间。容器已替换、观察中证据变化、关联有歧义或采集失败时，本次检查显示无法核实。

空结果表示本次在支持范围内未找到可核实的关联。当前生效的 Nginx 配置仍显示未知。此检查无需批准或启动重启，重启仍须独立批准。处置后的实际业务状态请在原任务内复验。

## 登记路径响应

同时登记 Nginx 依赖范围和至少一项已确认只读的业务检查后，依赖面板可单独运行「检查登记路径响应」。它使用已有业务检查策略，在目标机回环地址访问登记路径。响应只包含控制端观察时间、检查编号、HTTP 状态和登记条件的匹配结果。磁盘观察与路径检查分别点按，各自记录时间。

相同的 HTTP 200 仍可能返回不同正文。只有状态和正文都满足登记条件，该项才通过。明确不匹配显示失败，超时或回执不完整显示证据不足。此结果只描述本次访问。已加载配置代次仍显示未知，处置后的业务验收请查看对应原任务。

使用现有只读账号、指纹和固定业务检查命令。已有这些业务检查权限时可直接使用。网页和 API 无法提交临时路径、主机地址或命令。探测正文留在目标机，预期摘要只用于固定探测参数。模型、调查和历史库均不接收此次结果。

## 同机 Compose 命名卷观察

命名卷观察独立于 Nginx 磁盘关系。控制台显示单个授权项目内有 Compose 项目标记、由 Docker 内置 `local` 驱动登记且范围为 `local` 的命名卷，以及本次观察中挂载同一卷的服务数和容器数。别名仅在本次观察内有效。第三方驱动、全局范围卷、未标记的外部卷、绑定挂载、跨项目连接及读写模式均未覆盖。卷名可能短暂出现在目标机 Docker 子进程参数中，回执只含随机别名和计数。辅助程序不读取卷内容、数据库、容器环境、挂载路径或配置正文。

辅助程序在卷列表命令中使用 `driver=local`，并再次校验每行的驱动和范围。已安装过此功能的主机需用下方安装器更新辅助程序。控制台只接受覆盖值为 `compose_labeled_local_named_volumes` 的成功回执。Docker 守护进程可能在应用列表过滤前发现其他卷驱动。`local` 驱动允许通过挂载选项连接 NFS 等存储，因此该观察无法判断底层存储位置。[Docker 卷过滤](https://docs.docker.com/reference/cli/docker/volume/ls/) · [Moby 驱动发现与列表](https://github.com/moby/moby/blob/v27.5.1/volume/service/store.go) · [Docker 卷驱动选项](https://docs.docker.com/engine/storage/volumes/#use-a-volume-driver)

部署者准备一份 UTF-8 文件，内容为单行 `{"compose_project":"demo","schema_version":1}`，末尾加一个 LF。项目名必须与已有主机登记中的 `compose_project` 相同。独立核对这份文件的 SHA-256，将其填入同一主机的 `compose_volume_scope_digest`。使用现有只读策略导出和安装流程添加固定命令，保留专用 `opsark-readonly` 账号及其现有权限。将已审核的安装器与 `compose_volume_metadata.py`、`guard.py`、`install_nginx_dependencies.py` 放在同一目录。目录和各级父目录须由 root 拥有且其他用户不可写。

```text
python3 -I /absolute/reviewed/deploy/readonly/install_compose_volume_metadata.py --scope /absolute/reviewed/volume-scope.json --expected-sha256 <独立核对的SHA256>
```

登记后，主机卡片提供「观察命名卷共享」。辅助程序比较两次 Docker 元数据，发生变化或采集超时时停止并丢弃本次关系。先在隔离项目核对范围、权限与结果。该功能不发送模型请求，不改变卷、容器或 Nginx 已加载代次，也不提供恢复或执行入口。

2026-11-13 在授权测试机用 `791b3fd` 的辅助程序和独立测试范围观察实际 Docker Compose。两个服务挂载同一个命名卷，各一个容器。另一个测试项目挂载同一卷和自己的独立卷，结果没有计入该项目。测试没有发布端口、读取卷内容或拉取镜像。隔离容器、网络和卷已清理，宿主基线一致。实机回执为 `5694efc89f6e146b862993353d94ea034eb0040410569d991d5b7540f74ecefa`。这份回执记录的是增加 `driver=local` 和新版覆盖值之前的行为。收紧后的采集器与同一实机的安装、受限 SSH、控制台 API 和 Chromium 链路仍需联合验收。

## 验收范围

本分支先做本地合成验证：直接/命名上游、共享服务、IP/端口/协议不符、歧义、未知语法、include 边界、配置与 Compose 漂移、canary/未知 DTO、错误指纹、只读 API 认证/锁与 UI 拒绝部分结果。它不替代标准 Ubuntu guest 上从部署 scope/专用 SSH/真实配置到界面的实机验收。

2026-11-12 用 `330258b` 在 Ubuntu 24.04 隔离来宾机完成实际 helper 安装、专用 SSH 指纹核验和产品 API 观察。登记容器归属待确认时，产品从实际 Nginx 磁盘配置及 Compose 发布元数据找到三条唯一关联、两条共享依赖、一条未发布端口和一条无法确认的正则路由。报告历史前后相同，回执保持已加载代次未知、动作关闭和零模型调用。实机闭合摘要 SHA256 为 `6cd30ec12a725d6c902038a11445ebcbe78dbead33eac94b61cdba2da62977e8`。

同一份实机回执通过拦截请求的真实 Chromium 在 320 和 1440 像素视口验证。浏览器环节重放该回执，产品 API 的实时 SSH 证据来自前一环节。

另一次实机对照在原配置加载及三项初始探针通过后，将测试来宾机 `/other/` 的磁盘配置改到未发布的 18088，仅运行语法检查。产品把该磁盘关系标为未匹配，同一控制端的业务探针仍取得原上游的预期 200 响应，已加载代次继续显示未知。磁盘摘要与准备回执相同，浏览器重放通过。第一次对照在 SSH 预检连接错误处结束并清理，成功回执来自新任务。对照闭合摘要 SHA256 为 `29cfbbacaa2618fde7bdf5c2ad64347a9335f9b19de21a7a5ee234416c2ff408`。

后续实机覆盖包括启用链接、容器替换与恢复、扫描中漂移及超时，以及更多配置组合。相关范围见 [MVP 交付核对](MVP_DELIVERY_CHECK.md)。
