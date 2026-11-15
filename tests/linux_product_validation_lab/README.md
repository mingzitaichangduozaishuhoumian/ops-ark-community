# Linux 通用组与 Root 策略首次实跑

2026-11-07，授权 `试验机 A` 的独立无网容器，固定源码
`af7a0786b741eb625bbbbfc767c0b07c7f07301f`，实际准入镜像
`sha256:1ebb97bd5b904e33e3150c1f59958d925cd7c6fa779cf2be16bff9eb8d081c87`。
两组均为只读根、capabilities 0、NoNewPrivs、1 CPU、1 GiB、无额外 swap、
PID256、仅 lo；只挂公开输入和专属输出，没有常驻配置、凭据或数据库。

仓库中的 JSON 是回执文本副本，换行按 `.gitattributes` 统一为 LF；原始回执
在私有验收目录保留，其字节 SHA256 如下，不能拿规范化副本冒充原件字节：

| 回执 | 原始 SHA256 |
| --- | --- |
| 通用组失败 | `2cf7ce3864e32709b834cd501a354814eecd99fe1ee3dcc14d6d27c917841591` |
| Root 通过 | `f6e3c5e8b670d8b7f6ffbf5e2c44f12670e8164e0acc21895ccbfc1bbbd6df51` |
| 首轮清理 | `af6a24c6b3d6f7cade57d6e0c3cdc079b7a6e0ba1988e8097438979f15681c2f` |
| 形状诊断 | `e06e11ae810e7611143da95779bcac7938fcb6ab8b0868d4d06c2cf5416ddc22` |
| 形状诊断清理 | `ee7d82e4f679df0967a4efab306c286558b409c7f8e42284fffce5caf6f3a0a4` |

## 实际结果

同一 RUN `144896cee76c03eb` 中，通用组在收集阶段失败，没有执行测试；
原始外层回执为 [general-first-failure.safe.json](general-first-failure.safe.json)。
只读投影确认 `collection_failed`、没有 JUnit、源码/runtime 见证未变，
收集阶段七项 HTTP/SSH/native/Docker 审计计数均为零。没有读取原始测试日志。

独立 Root profile 的唯一节点
`tests/test_readonly_guard.py::test_actual_policy_symlink_permissions_and_parent_trust`
实际 **1 passed、0 failed/errors/skipped**，见
[root-first-pass.safe.json](root-first-pass.safe.json)。它只证明这个节点，
不代表非 Root 通用组或完整 Linux 产品通过。
[清理回执](first-run-cleanup.safe.json)确认专属容器移除，原有资源基线和
十一份安全记录不变；公开镜像、输入和报告保留，常驻实例未改。

## 不读取日志的原因定位

另起只收集的诊断 RUN `2e021c007f9497ac`，固定相同 15 文件，实际收集
479 项、没有收集异常。它不运行测试，不计作产品通过。为了区分验证器门禁，
后续 RUN `8dd10cec10994b09` 仅增加收集形状和原 `freeze_collection` 原因枚举：

- 479 项均唯一，15 文件齐全，精确排除 Root 节点一项；
- flock 与四项 native curl 必测节点均存在，没有额外文件；
- 最长 nodeid **5,094 字符**，原验证器的 1,024 字符上限返回
  `collected_nodes_invalid`。

[形状诊断回执](collection-shape.safe.json)只含固定文件计数、长度、必测布尔和
固定原因，不输出完整参数化 nodeid、异常消息或测试日志；七项传输审计计数为零。
[诊断清理](collection-shape-cleanup.safe.json)确认资源和旧记录不变。

修复将单个 nodeid 上限设为 16,384 字符，保留完整名称、精确作用域、排除项、
执行/JUnit 身份核对，并对包含 hash 的最终 canonical manifest 保持 2 MiB 上限。
5,094 字符身份的 JSON/JUnit 保真、篡改拒绝、单项及总量超限负例已加入回归。
后续固定新提交和制品的实跑结果另列如下，不倒改以上失败为通过。

## 修复后新候选实跑

固定提交 `b6cdbb97e4f3774feb0c9cb0eb33d9c78b0f7f95`，完整源码包 SHA256
`db0954adb7de07beac5b03fe524f7908d1b17b26418e9e632042d38f6d7c22d0`，
运行候选包 `37ff7e839e5978e0626150a09332c9677c95490dcd068b0c60ab7716be619266`，
identity 文件 `c4f220799cb09c1c730080e11c71a32e2945e276f6dbf85bf150b864b2723cea`。
新容器仅准备公开源码和锁定依赖，独立无网非 Root 准入逐文件核对 515 个源文件及
十个依赖版本，见 [runtime 准入](b6c-runtime-admission.safe.json)。实际镜像为
`sha256:9dc7d70c7b4f06ee294b55deb0bb63c626648d4e386949d24de0260c090fef12`。

新 RUN `1db61e3aefc36a17` 分别执行两组：

- [非 Root 通用组](b6c-general-pass.safe.json)：**479 passed，零失败、错误或跳过**；
- [Root 唯一策略节点](b6c-root-pass.safe.json)：**1 passed，零失败、错误或跳过**。

完整 nodeid 经同 Linux 环境收集冻结后，独立执行进程重新核对，并以 JUnit 有序身份
逐项匹配；包含原 5,094 字符名称，没有截短、删测试或增加排除项。
通用组含真实 loopback SSH、四项 native curl 和 Linux flock 节点。
源码/runtime 前后见证一致，两组各自专属容器已移除，
[最终清理](b6c-cleanup.safe.json)确认基线与十一份既有安全记录不变。
镜像、公开输入和原始报告保留，未读取或导出原始日志，未变更常驻配置、权限或历史。

| 新候选回执 | 原始字节 SHA256（仓库副本统一 LF） |
| --- | --- |
| Runtime 准入 | `4a8276d17ac9c1fe084c29905ab0c1f844590eb4778e41574689bf763f2b0242` |
| 通用组通过 | `2522addcc0c93fe924db13af1f7ddc1636031eba38537009c8ad7513365f1850` |
| Root 通过 | `664fd5802de033a61ab045e628d386d7fe8d45547bbbc0bbbc3932f1060781c9` |
| 清理 | `d1be5e42339cacfcc701e42443e4cfe33ba3e33d17dd895db127671fc5857920` |

这收口两个指定 profile，不代表完整产品、其余 Linux 分组或标准 VPS 业务链通过。

## 增加依赖与观察组后的隔离导入修复

`04798c8` 将 general 扩为 18 文件，并加入固定 9 文件的
`security-observation-nonroot`。该版实际观察组 290 项、Root 1 项通过，但
[general 在收集阶段失败](04798-general-collection-failure.safe.json)，尚未运行测试。
独立 `python -I -B` 最小对照证实：原 child 只加 `src`/`tests`，无法导入新测试用的
`deploy` namespace；本地 harness 预先加入 repo 根掩盖了这个差异。修复只追加已验证的
source 根，并保持 src/tests 优先，不采用 ambient cwd 或 `PYTHONPATH`。
四项真实隔离子进程回归及 105 项本地验证器检查通过，没有读取原始失败日志。

新提交固定为 `cb928f4d6dbc1476043c74994050c2c3e40cd2c5`：
源码包 `99ae297cfe6413b6a7a5382ee6158c0594f2b865ff31c92400a283ddd7185208`，
运行候选包 `5de1a3f4f0658f5c1c00110bb98f77745057c92907af18558f62621a5314a038`，
identity `70b06a7086486c0f10d2d92b7438346a49104019fc08cfe1e91678c1c9f3fd83`。
[独立准入回执](cb-runtime-admission.safe.json)核对 529 源文件、十个依赖版本及
Python 3.13.18，实际镜像为
`sha256:fc5ad733e1ffe4f95d6083b8625b66ba90a192d74c51a0dc156d82b2b748f8e2`。

第一次调度 RUN `49ea2b5c5c5368bb` 的 general 运输包装器报错；只读检查确认没有
general claim、CID 或 proof，惰性源加载与原 stage/input 核验通过，最终清理通过。
未读取私有错误日志，也未确定具体运输失败原因。该尝试没有重发或记作通过。
另起带固定启动异常类型回执的新 RUN `473011255e947889`：

| 固定组 | 实际结果 | 回执 |
| --- | --- | --- |
| General 18 文件 | 549 passed、零失败/错误/跳过 | [回执](cb-general-pass.safe.json) |
| Observation 9 文件 | 290 passed、零失败/错误/跳过 | [回执](cb-observation-pass.safe.json) |
| Root 精确单节点 | 1 passed、零失败/错误/跳过 | [回执](cb-root-pass.safe.json) |

三组均核对冻结节点与有序 JUnit、实际源/runtime 前后不变；general 必测包含真实
loopback SSH、四项 curl 和 flock，观察组包含真实管道/selector/进程/锁及 GNU timeout。
观察组不虚构 SSH 或 curl 流量要求。[清理回执](cb-cleanup.safe.json)确认专属容器均
移除，既有资源基线与十一份安全记录保持。此版新组结果不与旧版本数字相加宣称完整产品通过。

仓库 JSON 继续按 LF 保存；对应原始字节 SHA256：

| 回执 | 原始 SHA256 |
| --- | --- |
| Runtime 准入 | `76dcfcb9c9022ea6b60da5bde505ffa7ff61f727dddc8101be1d53cb8bd051d8` |
| General | `4b7627aa5444a4e1bc25a0dacadffa267da69846f1a3c36160a3b96b585a2898` |
| Observation | `644ec7edef9a8b710dd5fe68d89db48dede52b02c60a88056898a7c4fd0c8e60` |
| Root | `c61bdece5e577967b739aeb3eb8dcf5e5c836d9d0cad0efac3355bf83183e521` |
| 清理 | `e632add479cc3e3be59542d004bdeff930eaf3ff2226ae62153843e3bbc685f0` |
