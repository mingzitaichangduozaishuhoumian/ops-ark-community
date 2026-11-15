# 授权 Compose 项目的只读候选发现

此能力读取一台已登记 SSH 主机上、管理员明确授权的一个 Compose 项目，展示服务标签、容器状态和已发布端口，生成登记预览。它不调用模型、不读取 Compose 文件或环境变量，也不保存清单或执行部署。另行核对 [Nginx 到服务的依赖关系](NGINX_DEPENDENCIES.md)。

## 从未知容器开始接入

先用[接入向导](RUNNING.md#登记-ssh-主机)核对独立取得的 SSH 主机指纹。已知容器名时保留原登记方式；不知道容器名时，可以只填一个授权 Compose 项目，省略容器名。服务器地址、专用账号、公钥和指纹要求不变。

向导返回的 TOML 是可审核材料，不会写入部署配置。项目限定使用小写字母、数字、下划线或连字符，首字符为字母或数字，最长 63 字符；不接受列表、通配符、路径或 Docker 参数。例如，在已生成凭据引用的主机段中：

```toml
[[hosts]]
id = "site-a"
address = "192.0.2.10"
username = "opsark-readonly"
site_domain = "www.example.test"
credential = "readonly-site-a"
compose_project = "website"
container_binding_confirmed = false
```

`container_binding_confirmed = false` 表示容器待确认。此时不会生成或执行占位容器的 inspect、logs 命令；接入预检保留八项结果，其中容器检查为 `unavailable / registration_unconfirmed`，不能显示整体通过。旧清单未设置此字段时默认沿用原有已明确登记的容器。

管理员按原部署流程审核并应用清单，重新导出并安装精确[只读策略](../deploy/readonly/README.md)。新策略只增加这个项目的固定元数据命令；网页不会为自己扩权，旧策略缺少命令时保留缺口。

## 发现、选择、再次核对

已登记主机卡中点击“发现授权 Compose 项目”，才发起一次 SSH 采集。平台、工具、Compose major 2 与固定本地 rootful Docker 引擎检查通过后，才列举授权项目的标签候选。前置失败时不继续枚举。

每个候选包含服务、容器、状态、同服务实例数及发布端口。用户明确选择已观察到的 TCP 主机发布端口，然后核对登记预览。服务端使用原登记和授权项目重新连接采集，比较当前快照与原候选；主机登记、信任记录、容器身份、状态或端口变化会使旧选择失效。客户端不能提交自己的当前快照、地址、项目名、配置路径或 Shell。

预览仅生成四行可复制片段：

```toml
compose_project = "website"
container_name = "website-api-1"
container_binding_confirmed = true
expected_upstream_port = 8081
```

用户采纳片段后，仍须由管理员更新部署清单并重新审核精确策略。生成预览不改变“容器待确认”状态，不写数据库或服务器配置。只有 UDP 或未发布容器端口的候选，不能填成已确认的 TCP 上游端口。

标签与 Docker 发布映射只是采集事实。它们不证明端口正在监听、Nginx 正在使用该上游、网站健康或服务已经恢复；业务复验仍走独立流程。多实例也不会被自动合并成一个可执行目标。

## 数据与容量边界

固定 Docker 格式只投影 ID、名称、状态、两项 Compose 保留标签及端口。不会请求 Env、Command、Mounts、全部 Labels、镜像凭据、容器日志、Compose 原文或数据库正文。结果仅用于本地控制台，不进入 AI 请求或客户交接摘要。

每次采集的原输出上限为 16 KiB、64 个容器；每容器最多 128 个发布端口，全项目最多 256 个，序列化成功响应不超过 64 KiB。未知字段、错误项目、重复身份、畸形端口、截断、失败或非空 stderr 会拒绝整份库存，不把已读取的前半部分当作完整发现；失败结果不带候选或快照摘要。完整的空列表另标为无候选，也不代表业务健康。

HTTP 接口均需控制台认证，并复用只读检查并发锁：

- `POST /api/hosts/{id}/compose-discovery` 只接受空对象。
- `POST /api/hosts/{id}/compose-discovery/preview` 只接受候选 ID、快照摘要和整数 TCP 发布端口。

未登记返回 404，未授权项目或旧选择返回 409，额外请求字段返回 422；后台错误不回显原始异常。

## 验证范围

新增组件和实际 API 的本地合成测试覆盖了严格解析、总量限制、未确认容器的权限与检查缺口、清单导出不读取私钥正文、候选变化、无配置/数据库写入，以及真实 loopback SSH 的指纹拒绝和固定命令。前端另有四视口真 Chromium 契约验证。

这些结果不等于真实 Docker/systemd 或完整 Ubuntu VPS 首次接入已经通过。真正的本地应用联调、标准虚拟机验收、最终发行提交与源包核验须分别留存结果；未完成项继续保留，不把合成 Docker 元数据写成原生服务证明。

2026-11-06 的本地证据分别保留：

| 检查 | 实际结果与范围 | 证据 SHA256 |
| --- | --- | --- |
| 后端、登记、权限和 AI 门禁合并回归 | 420 通过、2 个 Windows 上的 Linux 专属节点跳过；真实 HTTP/非 loopback SSH/socket 尝试均为 0，17 次允许的 loopback SSH。源码前后相同 | JUnit `66c3fa6a482d6a43153e9166739e9bffed8f8d7152b5e6f3c861dfc24966b1be` |
| 前端契约 | 26 通过；真 Chromium 1440/768/390/320，接口为 Mock，源前后相同 | 汇总 `01bef3d80f2a21f5e70b5cc1531f5745386b57431fccc5ae335d23912d33e3cb` |
| 实际本地应用联调 | 3 个真实 main 进程、真 Chromium 1440/320、多连接 Paramiko loopback；64 条精确 SSH 命令、10 次库存采集，未知命令为 0 | 汇总 `112e983ca1baf271ddcf93554043ab4a1c4a2fd5bd24586391b1279b17c86847` |
| 同轮模型入口计量自测 | 第 4 个 testcase 直接触发假调用，证明共同 dispatch sink 的拒绝计数有效；实际三个进程都核对钩子在位、dispatch 尝试为 0 | 该轮 4 项 JUnit `d1de750dfd6e403e8510197c6f14be0746eb06541cb3cb6380a0342e1195d3c9` |

两个跳过节点为 `test_child_keeps_execution_lock_after_guard_process_is_killed` 和 `test_actual_policy_symlink_permissions_and_parent_trust`，仍须在对应 Linux 权限环境实际运行。合并回归不是完整产品测试，也不把旧 Linux 子矩阵的源码版本扩大到本次工作树。

联调中每次预览都有新 SSH 库存；端口改变后旧选择返回真实 409 并清空，用户重新发现新 ID 后才能生成四行片段。待确认状态没有被预览自动改写，inspect/logs 命令为零；独立错误 pin 案例在鉴权执行前拒绝，exec 为零。登记与可信记录、全部 SQLite 逻辑历史前后一致，进程与 SSH 线程/监听均已停止。源码、配置与浏览器都使用全新合成目录，没有连接常驻实例或实际 Docker。

两组联调原件私下保存。前三次联调编排失败分别是 Windows venv 启动器身份、脚本复用旧候选 ID、脚本把 SSH 私有状态用于 replay 条目，原件保留。第 4 轮的模型计数只是初始化值，不能称实测；第 5 轮虽测试通过但存在测试 hook 的类型检查问题。最终第 6 轮才以同一冻结 helper、真实 sink 计量和完整静态检查收口，不倒改旧轮次。

显式本地复现使用新空输出目录，安装项目依赖及 Chromium 后运行：

```console
python -m pytest tests/test_compose_discovery.py tests/test_compose_discovery_api.py
python -m pytest tests/test_browser_compose_discovery_smoke.py
python -m pytest tests/compose_discovery_live_lab.py --junitxml=<新的JUnit路径> --basetemp=<新的临时目录>
```

命令与标签依据为 Docker 官方[容器列表格式](https://docs.docker.com/reference/cli/docker/container/ls/)和 [Compose 服务标签](https://docs.docker.com/reference/compose-file/services/#labels)。
