# 隐私化 Web 观察采集

这些资产由管理员审核部署，不向采集账号开放安装、探测或任意 Shell。当前安装器只修改已有的 OpsArk loopback 实验 vhost，不改旧 API/status vhost、主 SSH、Cloudflare 或 DNS。

## 安装

首次安装前确认 `/etc/opsark`、`/usr/local/libexec` 及其上级都是由 root 所有的真实目录，组和其他用户不可写。目标机的[只读入口安装器](../readonly/README.md#安装接口)会准备这两个目录。空白隔离来宾做本地日志演练时，由管理员仅创建缺失目录，保留已存在目录的权限和属主。

将本目录的 `install.py`、`read_journal.py`、`nginx-format.conf` 放到 root 所有且不能由其他用户写入的部署目录。先通过管理通道读取 `/etc/nginx/conf.d/opsark-vps-lab.conf` 的实际 SHA256，再执行：

```console
python3 -I install.py install --expected-vhost-sha256 <实际摘要>
python3 -I install.py status
```

安装器只接受带实验所有权标记、单个 `127.0.0.1:18880` / `opsark-lab.invalid` server 和单个 access_log 的 vhost。当前摘要不同会停止；目录、符号链接、非 root 文件、无关既有部署文件和外部修改也会被拒绝。它先备份、写入新格式和 vhost，`nginx -t` 通过后才重载；语法失败恢复原文件而不重载。如果失败时发现已写入文件被其他操作改变，则停止自动回退并要求管理员依据备份复核，不覆盖并发外部修改。

安装命令返回成功后，先确认 `nginx.service` 的新配置已生效，再发普通回环验收请求，并通过读取器核对请求已进入原生 journal。在隔离来宾的验收中，可以等待旧 worker 退出并核对新 worker 接管。上面的 `status` 用于核对落盘文件摘要。

成功结果包含 `profile_digest`，即 root profile 文件原始字节的 SHA256。把它登记到控制端该主机的 `web_profile_digest`，再审核精确策略增加唯一命令：

```text
LC_ALL=C timeout -k 1s 5s /usr/bin/python3 -I /usr/local/libexec/opsark-web-read
```

reader 为 root:root 0755；profile `/etc/opsark/web-observation.json` 为 root:root 0600。profile 摘要变化后，旧登记不能继续计数，必须复核并重新加载控制端清单。安装器另维护 root 所有的归属与文件摘要标记。它不会修改精确采集策略或控制端清单，管理员应分别审核这些步骤。

## 日志与来源

Nginx 在本机 Unix syslog `/dev/log` 输出 `escape=json` 的固定投影，tag 为 `opsark_web`。URI、查询参数、User-Agent 只在内部 map 中分类，**log_format 不输出原始路径、查询、Cookie、认证头、referrer、User-Agent 或请求体**。导出的路径仅为固定类别，客户端仅为声明的 crawler/browser/probe/other，crawler 声明不构成信任或豁免。

本机 Unix syslog 使用 `nohostname`，避免 hostname 被本机 journal 当成 MESSAGE 前缀，导致 tag 无法解析。参数依据 [Nginx 官方 syslog 文档](https://nginx.org/en/docs/syslog.html)。旧版精确 ACCESS 行只能在归属标记中的当前 vhost 摘要匹配、显式 CAS 和备份/语法检测保护下迁移；不会通过允许空 identifier 或从任意前缀剥出 JSON 来放宽来源校验。

reader 同时核对 journal 的 `nginx.service`、`/usr/sbin/nginx`、`nginx` 进程名及 tag，不单独相信可伪造的 tag。只读最近十五分钟、最多二百条记录，原始字节最多 256 KiB，reader 四秒/独立 timeout 三秒预算。继承的全局采集锁继续传给 timeout，reader 结束后存活的日志进程仍受独立期限和并发限制。输出最多八十条事件、12 KiB；达到限制和不支持的数据均产生覆盖缺口。

实际 TCP peer 使用 `$realip_remote_addr`，所以安装前检查 RealIP 模块。转发头仅保留经过 IP 形状正则筛选的单地址候选和是否存在；无匹配时为空，不记录原头文本。reader 还用 `ipaddress` 做真实地址验证：只有明确 root profile 的可信代理 CIDR 才能提供客户端身份。禁止全网信任；多地址链、缺失或非法候选标记为来源未解决，不把代理当攻击者。不可信 peer 的伪造转发头被忽略，按 TCP peer 归因。

初始 profile 只有 `lab`，origin 为 `controlled_web_probe`、可信代理列表为空。生产站点必须通过独立的 root 配置和日志来源验收后使用 `system_web`，不能把实验数据改称真实攻击。

## 有界演练

`probe.py` 是管理员工具，只访问 `127.0.0.1:18880`，一次最多三十个请求，间隔 0.2 秒：

```console
python3 -I probe.py normal
python3 -I probe.py spoofed_forwarding
python3 -I probe.py errors
python3 -I probe.py scan
python3 -I probe.py crawler_scan
```

依次为普通浏览器/正常 crawler/同出口回调、伪造来源头、十二个固定错误响应、六个敏感端点探测、同样探测但声明为 crawler。它不发送攻击洪峰，不访问公网或第三方站点，不执行漏洞利用，不绕过既有防护。

启用 Web 观察后，不再用旧 fixture 的 `init/cleanup` 重写带日志配置的 vhost；可以用其 `healthy` 操作只替换归属正确的容器。重置或撤销 Nginx 日志应依据安装备份和当前文件摘要由管理员处理。日志采集是有限观察，不是全量取证或 DDoS 清洗能力。
