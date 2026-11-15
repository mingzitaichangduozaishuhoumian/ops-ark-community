# 只读检查与观测基线接口

本轮扩展仍保持只读。HTTP 检查结果只代表当前登记站点的瞬时状态，不自动结案；观测基线不保存可恢复配置，不是回退点。

## 数据约定

`HostPublic.health_checks` 最多三项，字段见 `models.HealthCheck`。检查始终经登记目标 SSH 访问该目标的 `127.0.0.1:port`，Host 头为登记的 domain，仅接受明确 `read_only_confirmed=true` 的静态路径 GET；不接受 API 临时地址、请求头、凭据或跟随跳转。

检查名为 `http_<id>`。stdout 为响应正文加最后的 `\nOPSARK_HTTP_STATUS:<三位状态码>\n`；必须以该尾部元数据结束，缺失、截断、采集错误均不能通过。状态和正文按登记条件联合比较。检查证据仍经统一脱敏并保存。

条件比对在内存中的原始受限响应上先完成，之后只持久化脱敏证据，以及 `Verification.http_status/status_matches/body_matches` 安全元数据。脱敏插入的替换文字不能成为成功依据；基线使用绑定到证据的这些已验证值，不从脱敏正文重新计算。缺少元数据的旧记录标记缺口。

可选 `HostPublic.nginx_config_path` 只允许部署者配置 `/etc/nginx/sites-available/` 或 `/etc/nginx/conf.d/` 下的单个普通路径；固定 `sha256sum` 检查名 `nginx_config_hash`，不读取完整配置正文。磁盘文件摘要不等于 Nginx 已加载配置。

`Report.scope_hash` 根据登记主机的安全公开配置稳定计算，避免同名目标重新登记后沿用旧确认。旧报告缺少 scope 时不能建立基线。`Report.comparison` 记录与同 source、host_id、scenario 的已保存观测基线相比的差异、缺口和引用。

## 新增 API

`POST /api/reports/{id}/baseline`，正文 `{confirm_observation_only:true}`。保存该报告中已成功、完整取得且可解释的观测字段快照。返回 `BaselineInfo`。不接受用户提交 features、scope 或 evidence；无法提取有效字段时返回 409。

保存基线仅影响后续调查的对照，不改写历史事实或恢复状态；旧报告保持原比较结果。同 source、host_id、scenario 使用最新的观测基线，scope 不同则记录 scope_changed 并停止比较。原始日志、不完整或失败字段不得作为已知旧值。

`GET /api/baselines` 返回最近观测基线的摘要列表。与其他接口一样需要 Bearer 认证。调查生成时自动运行登记的 HTTP 检查，比较最新基线后持久化报告，无另一个执行接口。
