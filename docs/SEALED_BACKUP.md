# 离线加密备份与交接

`tools/sealed_backup.py` 在本机把已核验的十库快照直接流式加密，异机只需保存密文。它不连接 AI、SSH、对象存储或控制端，也不自动停服务、启动恢复实例、重放任务或改变权限。此工具属于免费的核心交付。

## 档案范围

| 档案 | 包含 | 不包含 |
| --- | --- | --- |
| `stores-v1` | 十个登记数据库及快照 manifest，保留审批、任务、配额、暂停、租约和历史 | 部署配置、镜像、独立凭据和远端 Root 状态 |
| `observer-handover-v1` | 上述十库、登记的原始配置字节、配置顺序和镜像身份；可附带固定镜像归档 | 配置引用的私钥文件、控制台令牌、age 私钥、远端 Root 账本及其他未登记文件 |
| `observer-handover-v2` | 同一十库及旧配置保真合同，另可登记成对的 SSH 防护清单、策略、三个公用 pin 文件和固定防护 Compose overlay | 独立凭据文件、远端 Root 状态；不激活配置、不重新签发许可或更新有效期 |

配置可能原本就内嵌密码或模型密钥。交接档案会把这些原始字节放进加密流，恢复后按原字节保留，因此恢复目录本身也是敏感材料；它们不会成为 CLI 输出或模型输入。独立凭据文件不自动跟随配置引用读取。不要把恢复目录、源快照或原配置交给聊天模型，也不要将其作为异机传输包。

启用 Compose 容器与镜像变化观察时，十库中的 `reports.sqlite3` 会保留每份原调查的私有比对记录。恢复和离线合并保留该记录，清单仅包含数据库与表的核验摘要。目标机比对密钥由目标机管理员单独保管。已有对照可在离线恢复后读取。目标密钥或 Docker 守护进程身份变化时，新旧观测无法比较。

2026-11-12 在独立目录实际封装并认证恢复了 `330258b` 的 `observer-handover-v2`。18 个成员包括十库及快照清单、六份合成配置和实建的 Linux amd64 镜像归档。镜像从同一候选包构建，103 个运行文件逐项匹配并通过无网启动。恢复库与原快照的核验结果一致，六份配置逐字节相同，镜像归档 SHA256 匹配。归档的镜像身份由 OCI manifest、配置和层引用逐级核对。此次配置登记未启用 SSH 防护角色。闭合恢复凭证 SHA256 为 `44fe147646eb3886b0c89c7783b4af85aaad05f0d6c57c318bb1029669a0054a`。

两个独立的离线控制端进程使用空清单及恢复十库的受保护副本，读回同一份原报告、导出和交接摘要。API 读回凭证 SHA256 为 `ce3abfab5fd8d601dd28857f328f1fae56af8aeb10e42874cac453090195bdc9`。

随后为授权 Linux 测试机上的独立接收身份流式重加密同一归档。接收方认证整份密文后恢复十库、配置和镜像，再用恢复的 Compose 和环境生成隔离副本。副本加载了恢复归档中的确切镜像，容器无网络、无宿主端口并以非 root 只读运行。新令牌权限符合要求，未认证报告请求返回 401，同一容器重启前后读回的报告、导出和交接摘要均匹配。模型、持续观察和执行入口保持关闭。原恢复树在验收前后校验一致，临时接收身份与恢复副本随后清理。该结果绑定 `330258b` 镜像，闭合凭证 SHA256 为 `d3f6500a1ecb9e6fe3b388e9367aabc91dacc5aee0c43881050a22681e1ed24b`。

2026-11-13 使用 `3947ba3` 的实建镜像重新完成本地认证封装和惰性恢复。镜像中的 106 个运行文件已独立核对，镜像归档回传 SHA-256 为 `8b8d5ac06661a92f385eeb055fafa584e7174543b0bdb6ea7ef6cbe5346477be`。本次交接恢复十库、六份合成配置与同一镜像归档。两个独立 API 进程使用准确候选运行文件和恢复库的私有副本，读回原报告、导出和交接摘要，默认 Nginx 处置保持关闭。原恢复库摘要在读回前后一致，副本已清理。交接回执 SHA-256 为 `1da8cbec1d0b8a37503c03e6c899b3d3616b432bcdd4e65b0ea09badc76423c2`，读回回执为 `e86b305f5640c7185305090d2968fd47d1adfb885df620b90ef17b59c6a2b2da`。从本次恢复归档启动 Linux 镜像仍单独验收。

`handover.json` 的完整性声明由管理员确认。工具核对固定文件集合、文件哈希和镜像归档哈希，不解析任意 Compose 包含关系、插值或外部 Shell 环境。使用自定义 Compose、其他 env 文件、额外 include 或未登记覆盖时，不能用这一档宣称完整交接。

## 准备材料

先停止此次快照涉及的所有写入者，再按[十库恢复步骤](RELEASE_CHECK.md#十库恢复演练)用 `snapshot --confirm-quiescent` 生成独立快照。管理员需要确保从快照开始到完成，源数据库和辅助文件都保持稳定。封装命令的 `--confirm-quiescent` 记录该前提，十个数据库之间没有全局快照事务。

本版只接受固定版本 `age` / `age-keygen` **v1.3.2** 的本地可执行文件、单个原生 X25519 收件人和原生身份。不支持插件、SSH 密钥、口令模式、多收件人、ASCII armor 或其他 identity 类型。二进制由管理员从[官方发布](https://github.com/FiloSottile/age/releases/tag/v1.3.2)取得并独立核验，本工具不自动下载。不要只对来源未知的下载现场计算一个哈希，就把它当作可信预期值。

本次验证过官方资产的 SHA-256 和 Sigsum 证明，解包后固定二进制哈希如下；升级版本或更换平台需重新核验。

| 平台 | 程序 | SHA-256 |
| --- | --- | --- |
| Linux amd64 | age | `eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c` |
| Linux amd64 | age-keygen | `0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899` |
| Windows amd64 | age.exe | `2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0` |
| Windows amd64 | age-keygen.exe | `1549c7049be32695594bedd09bbd352a94b6013a9d5c43364f3c6cd7a09ab61c` |

公钥文件只放一行 `age1…`；预期公钥文件哈希通过独立可信渠道核对，避免把备份加密给错误的收件人。私钥在接收方单独保管，只由本地原生 age 工具读取，不放进备份或命令参数内容。恢复需要这份私钥，密文和 SHA-256 不能替代它。

Linux 使用管理员控制的私有目录，目录 `0700`、敏感文件 `0600`。Windows 要求本地 NTFS/ReFS 上真实受限的 owner/DACL；`chmod` 或文件名本身不能代替 ACL。链接、junction、重解析点、硬链接及无法验证的路径会被拒绝。工具不会替现有目录改权限。

原生可执行文件还要核验全部上级目录，防止其他本地账户替换执行路径。Linux 不接受 `/tmp` 等其他账户可写的祖先；Windows 默认的临时目录或共享 D 盘目录也可能被拒绝，应将已核验工具放在当前用户下新建的受保护专用目录。不能为了通过检查而给既有共享目录批量改 ACL。Linux 从已持有的文件描述符执行，Windows 在调用期间保持文件和祖先句柄，保护边界不覆盖已控制当前账户或系统管理员的攻击者。

工具安装目录与备份、恢复输出目录应分开。Windows 输出的直接父目录不能是正在保护的工具目录或其祖先，避免文件发布与程序路径保护互相冲突；使用另一个专用私有工作目录。该工具目前仅验收 Linux 与 Windows，未声明支持 macOS 或网络共享文件系统。

## 三个离线命令

以下示例是路径占位，先准备可信二进制、公钥和私有工作目录。输出位置必须不存在，不能覆盖旧备份。完整命令和 stdout 都只在受控本地终端使用。

```console
python -I tools/sealed_backup.py seal --snapshot /srv/opsark-private/snapshot --recipient-file /srv/opsark-private/recipient.txt --expected-recipient-sha256 <trusted-public-file-sha256> --age-bin /opt/opsark-tools/age --expected-age-sha256 <trusted-age-sha256> --output /srv/opsark-private/archive.age --confirm-quiescent
python -I tools/sealed_backup.py check-ciphertext --input /srv/opsark-private/archive.age --expected-sha256 <independently-trusted-cipher-sha256>
python -I tools/sealed_backup.py restore --input /srv/opsark-private/archive.age --expected-sha256 <independently-trusted-cipher-sha256> --identity-file /srv/opsark-private/identity.txt --age-bin /opt/opsark-tools/age --expected-age-sha256 <trusted-age-sha256> --age-keygen-bin /opt/opsark-tools/age-keygen --expected-age-keygen-sha256 <trusted-keygen-sha256> --output /srv/opsark-private/restored
```

`seal` 不落地明文 tar，生成成功后才以不覆盖方式发布 `.age` 文件。对外回执只给密文哈希、大小、数量和固定状态，不打印数据库值、配置、身份、源路径、原生 stderr 或内部各文件摘要。

`check-ciphertext` 只比较可信预期哈希和支持的密文头，明确返回 `content_authenticated=false`，不声称可以解密。加密本身不证明发送者身份：如果攻击者能一起替换密文与同目录的哈希文件，单独比较它们不够。接收方应从独立可信渠道取得预期密文哈希。

`restore` 先完整解密到丢弃流，要求原生 age 成功退出；然后对同一份固定密文进行第二次解密，在私有隔离目录提取并核对完整归档、十库及全部文件哈希，再发布新的恢复目录。身份错误、截断、篡改、异常归档和核验失败都不能发布部分恢复内容。

归档仅接受固定普通 USTAR 文件，拒绝重复成员、链接、路径穿越、PAX/GNU 扩展和非零尾部。单库最多 256 MiB，十库合计最多 512 MiB，可选镜像归档最多 1 GiB；超出限制要另行设计和验收，不能静默省略文件。

恢复会在私有工作目录保留一份固定密文副本和恢复结果。操作前为两者之和预留空间，并保留主机业务余量；流式处理不表示无需额外磁盘空间，也不提供文件系统配额或断电恢复承诺。

## 配置与镜像交接

使用交接档案时，在独立私有 `--config-root` 放以下固定材料，再添加 `--profile observer-handover-v1 --config-root <private-config-root>`。

- 必需：`compose.yaml`、`compose.release.yaml`、`secrets/inventory.toml`、`secrets/known_hosts` 和 `handover.json`。
- 实际使用时登记：`compose.lab.yaml`、`.env`、`observer.env`、`secrets/patch-targets.json`、`secrets/automation-policy.json`。固定材料存在却没登记也会拒绝，不能把缺失等同于未使用。
- 可选镜像材料只能是 `artifacts/controller-image.tar`，它的可信 SHA-256 必须记录在交接声明里。

`handover.json` 的示例结构如下。列表顺序必须与实际部署一致，镜像身份与运行文件哈希也必须填真实核验值。

```json
{
  "schema_version": 1,
  "compose_files": ["compose.yaml", "compose.release.yaml"],
  "env_files": [],
  "configuration_files": ["secrets/inventory.toml", "secrets/known_hosts"],
  "unregistered_configuration_sources": false,
  "external_environment_overrides": false,
  "operator_confirmed_configuration_complete": true,
  "credential_files_included": false,
  "remote_root_state_included": false,
  "image": {
    "image_id": "sha256:<64-lowercase-hex>",
    "runtime_sha256": "<64-lowercase-hex>",
    "material": "identity_only",
    "archive_sha256": null
  }
}
```

`identity_only` 只保存镜像身份，**没有备份镜像字节**。接收方还需要独立可信的镜像来源；没有镜像时不能承诺离线恢复。要连镜像归档一起保存，改为 `embedded_archive` 并填 `archive_sha256`，同时放入上述固定归档。工具只保真保存和核对归档，不检查镜像内部，也不执行 `docker load`。

## 恢复后的验收

恢复结果包含 `stores/`，交接档案另有 `config-original/` 和可选 `artifacts/`。原配置保持原字节，处于未激活状态。不要直接启动它：先单独准备新凭据、可信镜像、隔离覆盖配置和容器用户权限，再按[发布检查](RELEASE_CHECK.md)在断网、无宿主端口的副本中核对历史、原任务、摘要和重启读取。

恢复不会清理租约、重置已用配额、解除暂停、切到自动模式、扩大授权或重装补丁。历史中存在结果未知的原任务，应继续查原任务和远端原始账本；控制端备份不能代替目标机 Root 账本。业务复验尚未完成时仍是待验收。

恢复目录和身份由管理员按本地保留策略处置。工具只清理本次拥有的临时目录；它不承诺磁盘安全擦除，也不扫描或删除其他备份。

## v2 防护配置交接

开发候选新增 `--profile observer-handover-v2`。它使用外层 manifest 和 `handover.json` 的 `schema_version:2`；原 v1 格式、profile 和原有配置保真语义不变。旧工具不支持 v2，验证 manifest 时会拒绝，不能将版本号改成 1 绕过。v2 工具仍仅使用 Python 标准库和已核验的 age，不导入应用、调用模型或连接服务器。

所有交接档案都会检查上述旧固定配置及六个新增防护路径是否存在。v1 的配置目录只要存在任一新增防护文件，就明确拒绝并要求改用 v2，不能忽略文件后仍宣称配置完整；不含新增防护配置的 v1 保持兼容，v1 的归档成员名单也不扩大。

在前述交接声明中把版本改为 2，并增加 `ssh_defense`。未登记防护时必须显式填 `null`，且不能夹带防护文件；登记时只接受以下结构：

```json
"ssh_defense": {
  "inventory_file": "secrets/defense-targets.json",
  "policy_file": "secrets/defense-policy.json",
  "role_known_hosts_files": {
    "readonly": "secrets/defense-readonly-known_hosts",
    "observe": "secrets/defense-observe-known_hosts",
    "control": "secrets/defense-control-known_hosts"
  },
  "compose_file": "compose.defense.yaml"
}
```

这五个 `secrets/` 文件必须同时列入 `configuration_files`，overlay 必须列入实际顺序的 `compose_files`。两份防护 JSON 各最多 16 KiB，三个新增 pin 文件各最多 64 KiB；成员缺失、只登记一半、存在却未登记、重复或未知字段、任意新路径都会拒绝。v2 仍完整保留 `secrets/patch-targets.json`、`secrets/automation-policy.json` 及原有 `.env`、`observer.env` 的原始字节，不删除、改写或脱敏既有 APT、AI 或其他配置。

新增防护清单只能引用既有主机 ID，角色用户名固定为 `opsark-defense-readonly`、`opsark-defense-observe`、`opsark-defense-control`；私钥引用固定为 `/run/opsark/defense-<role>.key`，可信主机文件引用对应上列 `/run/opsark/defense-<role>-known_hosts`。工具核对策略与清单的 Root scope、固定策略、boot、listener binding，以及 pin 原始字节的 SHA-256。新增 pin 只接受精确登记地址、22423 端口和结构正确的 Ed25519 公钥，不接受哈希主机名、通配符、其他地址、注释或证书；三个角色必须固定同一服务器身份。私钥引用只作原配置字节保存，绝不跟随读取或验证私钥内容。恢复后仍须独立准备并核验凭据。

v2 的 Compose 范围也明确收窄：`compose.yaml` 必须匹配本工具登记的 observer 基础模板，可选 `compose.lab.yaml` 必须匹配对应模板；验证时允许 CRLF/LF 差异，归档仍保留原字节。`compose.release.yaml` 只接受以下 JSON 子集，`image` 必须等于交接声明中的镜像 ID。JSON 也是 Compose 可读的 YAML 子集；工具不运行 Compose。

```json
{"services":{"observer":{"image":"sha256:<与交接声明相同的64位摘要>"}}}
```

`compose.defense.yaml` 只接受下列固定 JSON 对象，可以调整空白和字段顺序，不能增加命令、权限、挂载或其他环境变量：

```json
{"services":{"observer":{"environment":{
  "OPSARK_DEFENSE_INVENTORY":"/run/opsark/defense-targets.json",
  "OPSARK_DEFENSE_POLICY":"/run/opsark/defense-policy.json",
  "OPSARK_DEFENSE_WORKER_ENABLED":"false"
}}}}
```

这些是 v2 可核对的部署合同，不是给现有部署静默生成或替换配置。自定义基础 Compose、其他 override、非标准防护路径或 pin 算法需要独立扩展并验收；工具会拒绝，不能据此宣称完整交接。旧环境文件仍按 v1 保真保存，**不执行、不展开变量、不判断它们是否足以启动服务**；管理员仍须确认实际环境来源和 Compose 顺序完整。

“不包含独立凭据文件”不等于“配置原文没有秘密”。原有 env、APT 策略或其他原始配置里可能有内嵌秘密，两种交接档案都明确返回 `inline_config_secrets_may_be_present:true`。受控本地程序把它们封装进整包 age 密文，向模型发送这些原文仍被禁止；异机只接收密文。恢复先完整认证密文，再提取到新私有目录，不启动服务，不改变任何授权时间、模式、用量、暂停、unknown 或租约。配置改变后的重新接入须另行核验，不能通过恢复清除未知结果或续期许可。

2026-11-06 在 Windows/CPython 3.13.11 上补测了 v2 的三项真实 age v1.3.2 用例：新生成身份完成防护配置、十库、原 unknown 和 AI 费用记录的加密恢复往返；错误身份和密文认证篡改均在提取前拒绝、目标目录不产生。配置和十库逐字节比较通过，恢复未激活配置、清租约或加载镜像。只使用合成数据与新测试身份，没有操作客户数据或调用模型。独立执行器先核验公用二进制 SHA，并置于新建、受保护的用户目录；较早一次放在不符合可执行文件祖先权限要求的目录被拒绝，保留为环境拒绝记录，未计入三项通过。此轮不代替 v2 的 Linux、实际客户迁移和激活验收。

新防护表仍在 `security.sqlite3` 内，没有增加第十一库。假十库的 snapshot、归档提取、恢复演练及重新打开已核对所有新增表、审批、执行/模型费用、unknown latch、模式回执、复验和租约保真；相同登记下不会重置模式。新 profile 的真实 age 往返和客户部署演练仍须单独验收，不能沿用下列 v1 历史结果宣称已完成。

## 验证状态

2026 年 11 月 5 日，在 Windows 11、CPython 3.13.11 上，使用独立核验的 age/age-keygen v1.3.2、新建私有目录、假十库、假内嵌配置和临时身份完成 **44 项通过、零失败、零跳过**。覆盖三条真实 CLI、错误身份、密文篡改与截断、认证先于提取、恶意归档、无覆盖竞态、原始配置保真、独立凭据引用不跟随，以及旧任务、审批、配额、暂停、租约和复验历史保持。最终执行前后源码 SHA 一致，临时材料清理完成，未调用模型或远程服务器。

随后对冻结候选 `8b9698ecb77f0eda8c2b9cd2f0637f05dd7d8a67` 完成两平台完整 pytest。Windows 为 **3,826 项通过、183 项跳过、零失败和错误，覆盖率 91.33%**；Ubuntu 24.04 隔离容器为 **3,987 项通过、22 项跳过、零失败和错误，覆盖率 91%**。两边均收集 4,009 项，真实加密交接 44 项各自全部通过；文件边界测试各通过本平台的 7 项，另 7 项按平台跳过。

Linux 的其余跳过为缺少 Git 的 10 项、缺少 curl 的 4 项、没有 Docker socket 的 1 项；Windows 主要跳过 Linux/POSIX 专属检查及本地链接权限要求。源码前后摘要一致。Linux 容器限制 1 CPU、1 GiB、无额外 swap、无网络或宿主端口，496 秒完成，无 OOM、超时或预算终止；专属容器和私有目录已清理，原容器和网络基线一致。测试进程组的资源峰值不能当作产品最低配置。

Windows 全量的首轮被同进程进度记录器干扰，终止于 pytest 内部错误。它单独保留为失败记录，没有算作通过；移除测试内记录钩子后，以独立父进程观察同一冻结候选，才取得完整成功回执。临时工具和全部假身份目录均已清理。

CI 为 Linux/Windows 准备固定哈希的原生工具，避免完整用例因未配置依赖而全部跳过；但本候选十项 GitHub 作业仍因账户账单或支出限制在启动前被拒绝，零测试步骤，不能算矩阵通过。当次 GitHub Actions

这些是隔离假数据与固定原生工具验收，不能宣称常驻实例已完成加密异机备份，也不代替客户镜像、实际生产迁移、恢复副本启动或业务验收。原始日志和取证材料继续私有保存。
