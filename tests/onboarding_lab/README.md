# 首次接入的真实浏览器验收

2026 年 11 月 5 日，在授权测试机的独立 Docker 内部桥接网络中，使用真实 Chromium、实际控制台 API、原生 OpenSSH 和 Nginx 验证首次接入。浏览器经本机 SSH 隧道访问控制台，全程使用实际响应。

控制台使用 `d7f7b615384c2d870db1d4eed7135cb2c605e9e4` 的 `0.18.0` 候选镜像。归档 SHA-256 为 `e89291a1b89fcf584d595a84db5c119ec6e5e798f3f8f61fea3419e4518d567a`，镜像内 74 个运行文件与归档核对通过，运行文件摘要为 `b5d4e7eaf1cbdce548037d51888c973dd4b4f1bc8a63593859b12c6bf438db20`。[候选核验方法](../../docs/RELEASE_CHECK.md)

## 已核对的结果

- 空登记控制台中，错误指纹实际返回 422，正确的独立公开主机指纹生成材料。页面中的 TOML、`known_hosts` 和两个文件引用与 API 回执逐字一致。
- 部署端为此目标生成独立采集密钥，私钥保留在控制台秘密目录，仅把公钥交给目标安装器。部署脚本严格核对浏览器生成的全部清单字段、公钥记录及换行摘要后，应用原材料并安装正式只读 guard。
- 专用账号通过真实 SSH 执行已登记的 OS 命令；`id` 和 `touch` 均由 guard 以 126 拒绝，禁止写入的测试标记始终不存在。
- 浏览器点击接入预检，实际 SSH 连接和 Ubuntu 适配通过。缺少 Docker、systemd 能力的项目显示缺口，整体为 `needs_attention`。
- 管理员只停止已记录的实验上游，先确认目标返回 502、共享站点返回 200，并取得真实连接拒绝日志。随后从页面运行 `web_502` 调查，报告来源为 SSH，事实引用原生 Nginx 的上游 8081 连接拒绝证据，执行权限为关闭，缺失项保留。
- 向导材料没有登记业务健康检查，客户摘要显示待验收。实际下载中核对了主机标识、地址、域名、公钥、凭据文件引用及控制台令牌均未出现。本轮没有注入隐私 canary，相关注入验收仍引用各自记录。
- 控制台重启后，从历史列表重开同一报告，作用域和报告摘要一致，重新下载的客户 Markdown 字节摘要一致。读回阶段没有写请求，也没有生成新调查。模型未配置，本轮模型调用为零。

最终一次完整浏览器 `verify` 通过。此前两次脚本因本地输出使用相对路径而终止，产品均已生成只读报告，本次共保留三份报告。脚本现会在启动浏览器前核对绝对路径、输出不存在及文件别名。另修正了登录后自动选中历史报告的等待，以及启动探针的 30 秒单调时钟预算。读回阶段执行两次控制台重启，首次启动探针失败保留，后续就绪与实际读回通过。这些修正属于实验编排，产品运行文件保持上述候选内容。

## SSH 失联与独立网站对照

首次浏览器读回通过后，`tests/onboarding_access_lab.py` 复用同一隔离范围，用原生 SSH 和 Nginx 补充失联验收。独立控制台容器先核对两个站点均为 200；仅停止精确识别的实验 SSH 监听进程后，网站仍正常。再停止实验 Nginx，两个站点均拒绝连接。两次正常调查 API 都产生新的 SSH 来源、证据不足报告，仅保留当次连接错误，没有套用旧的 502 或健康事实。两份不完整报告申请保存观测基线均返回 409，已有基线没有变化。

恢复同一目标后，正式只读 guard 和新 SSH 调查再次通过。原三份报告、原客户摘要、登记清单、可信主机记录和实验状态文件保持一致。这一额外流程实测 38.51 秒，新增两份失联报告及一份恢复后的采集报告，全部保留。没有新增模型调用或补丁执行。

此项是 D-ACCESS-01 的部分覆盖：独立网站结果来自实验检查，没有登记为产品业务检查，也没有被产品用来断言网站健康。公网监测、登记业务检查的失联联动和完整事件结案仍需单独验收。

## 分阶段复现

使用完整源码仓库、已核验的控制台候选镜像和包含 OpenSSH、Nginx、sudo 的固定目标镜像。实验根目录须已存在、归管理员所有、权限 0700，位于 `/var/lib/opsark-release-lab/` 下。目标和控制台仅连接固定内部网段，不发布宿主端口；控制台以非 root 用户运行，数据和私有登记分别挂载。

在测试机执行准备阶段，每轮使用新目录。

```console
lab_root=/var/lib/opsark-release-lab/onboarding-example
target_image='sha256:<固定目标镜像>'
controller_image='sha256:<已核验候选镜像>'
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated prepare
```

准备阶段在私有根目录生成 `browser.private.json`。通过管理通道将它保存到本地私有目录，为其增加指向本机 SSH 隧道的 `url`，例如 `http://127.0.0.1:<端口>/`。令牌保留在这个私有描述文件中，浏览器脚本仅输出布尔验收结果。

在安装了 Chromium 的本地项目环境执行。所有描述文件、材料、记录和证明路径使用绝对路径，每个证明文件使用新名称。

```console
uv run python tests/onboarding_browser_lab.py --descriptor <绝对私有描述文件> --phase prepare --materials <绝对私有材料文件> --proof <新的绝对准备证明文件>
```

将浏览器生成的材料 JSON 原样私下传到测试机的 `$lab_root/materials.json`，设为 root 所有、0600。然后应用材料、验证 guard 并构造上游故障。

```console
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated activate
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated guard-check
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated fault
```

本地浏览器运行实际预检、调查和下载。`--record` 保存报告编号、作用域及摘要，供下一阶段核对。

```console
uv run python tests/onboarding_browser_lab.py --descriptor <绝对私有描述文件> --phase verify --materials <绝对私有材料文件> --record <新的绝对私有读回记录> --proof <新的绝对调查证明文件>
```

重启同一控制台，保持私有描述文件中的隧道可用，再通过页面读回原报告并下载摘要。

```console
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated restart
```

```console
uv run python tests/onboarding_browser_lab.py --descriptor <绝对私有描述文件> --phase readback --materials <绝对私有材料文件> --record <原绝对私有读回记录> --proof <新的绝对重启证明文件>
```

如需追加失联对照，在清理前将首次浏览器 `--record` 与成功的读回证明经管理通道分别保存为实验根目录的直接子文件，设为 root 所有、0600，然后运行：

```console
sudo python3 -I tests/onboarding_access_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --first-use-record "$lab_root/first-use-record.json" --readback-proof "$lab_root/readback-proof.json" --confirm-isolated
```

完成核对后，在测试机停止并移除本轮归属一致的容器和网络。

```console
sudo python3 -I tests/onboarding_lab.py --root "$lab_root" --image "$target_image" --controller-image "$controller_image" --confirm-isolated cleanup
```

`cleanup` 的范围为本轮 Docker 容器和网络。操作者还需核对实验前后的资源清单，保存经过筛选的证明，再处理自己创建的私有目录，包括合成采集私钥、临时令牌和描述文件。

本轮追加对照后，再从浏览器选择原报告并下载摘要，内容仍与首次验收一致。随后关闭本机隧道，删除临时容器、内部网络、专用控制台镜像和远端私有实验目录。本机合成令牌描述文件、材料及读回编号文件也已删除，仅保留不含凭据的布尔证明和镜像运行文件见证。实验前后的既有容器与网络清单一致。报告保留结论指清理前的同一实例和历史读取，临时报告库随实验目录收尾移除；既有项目历史和常驻实例未改动。
