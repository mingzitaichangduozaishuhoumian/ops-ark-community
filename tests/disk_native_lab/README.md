# 磁盘元数据的 Linux 原生验证

2026-11-07，在授权 `试验机 A` 的独立无网容器中，固定产品源码
`01176af92147ec511081aa21f54810485abbf823`、543 文件公开源码包及已准入的
Python 3.13.18 镜像上完成 RUN `29999ece68d41859`。本次没有安装 helper、
连接产品专用 SSH 或修改常驻实例；产品诊断链使用明确的 replay 信封，
操作系统元数据、FD、独立子进程、ctypes mmap/munmap 和 statvfs 为真实 Linux 调用。
不能把信封中声明的 Ubuntu 24.04 当成目标 Ubuntu 实机验收。

固定容器为 UID 0、capabilities 0、NoNewPrivs、network none、1 CPU、1 GiB
内存且无额外 swap、PID64。只挂两个公开只读源码/程序目录和新输出目录；
没有主机根、Docker socket、设备、凭据或常驻数据挂载。可写根仅创建本次假文件。
完整 created/running profile 和 held Docker CLI 身份核验后才通过 stdin 释放固定脚本。

## 结果及可证明的范围

[native-result.safe.json](native-result.safe.json) 记录 **21 项检查通过**、
8 次 statvfs 观察、源码见证和零模型调用：

- 64 MiB 稀疏文件的已分配块小于逻辑大小；跨目录硬链接、重复 FD 按 inode 去重。
- 日志已删除仍被 FD 持有、已链接且打开、业务数据排除，以及同一 scope 的日志/业务增长。
- 三个已删除对象在子进程关闭 FD 后从扫描消失；容量观察增加 **12 MiB**、空闲 inode 增加 3。
- mmap 文件关闭 FD 后仍由映射持有，FD 扫描无法看到该引用；unlink 时可用容量未增加，
  子进程 munmap 后增加 **3 MiB**、空闲 inode 增加 1。关闭已见 FD 或删除路径不能据此普遍承诺释放。
- 实际产品诊断、报告/基线保存读回、增长对照、导出和 AI 分类投影以本次假状态运行；
  未分类指标整份拒绝，无原路径/文件名进入输出，零模型请求。

statvfs 为共享底层文件系统的分时观察，仍可能受并发写入影响；上述数字只描述本次实验。
产品继续保留 `physical_reclaim_verified=false`，不将文件分配块、条件上界或占用下降
等同于任意环境中的物理释放或业务恢复。

[cleanup.safe.json](cleanup.safe.json) 证明原 Docker 清单及既有十一份安全记录未变；
[terminal.safe.json](terminal.safe.json) 独立查询确认容器 missing，prepare/fixture/cleanup
三份原进程 PID/birth 均已不存在，安全结果再次验证通过。每项操作仅派发一次；镜像、
公开输入和安全审计记录保留，没有重跑旧任务。

## 固定夹具与字节绑定

实际执行的夹具原件保留在提交 `801fc1c173ba372336f86dc58421e7d0e09ae4e2`
的 `tests/disk_native_lab/native_disk_fixture.py`，原始 SHA256：
`9cdd0d78e4217b24aa3088313f130fe37062523024875712bbddf8a453516cec`。
当前 [native_disk_fixture.py](native_disk_fixture.py) 仅增加三处针对固定测试目录/子进程的
lint 注释并拆分一个长 f-string，SHA256 为
`cbf2389abe2722f36592664d8be261fb62a3c1a7f43f1430f3a9ea8173eadc04`；
两版 AST 已逐节点核对完全相同，见 [source-equivalence.safe.json](source-equivalence.safe.json)。
当前文件字节不能冒充实际执行原件；格式与完整 Ruff 检查均通过。
[source-manifest.json](source-manifest.json) 原始 SHA256：
`4300767cc42aafaf706a3faa842b2f6e494ac2794a75b0d8a540509670f05db9`。
133 项 manifest 绑定上述产品提交的原始 Git blob，不包含本次新增验收目录。
夹具默认读取 `/opt/opsark-reviewed` 和相邻 manifest，`--self-test` 为纯 Fake，
`--native` 才执行固定 Linux 假文件实验；不得直接在常驻或业务环境运行。

主机工具在派发前经独立源审及 Root 复跑：6 项 profile/字节绑定、23 项内存生命周期/结果、
16 项派发/观察检查均通过。它们与这里的原生结果分列，不混计测试数量。

仓库回执副本按 `.gitattributes` 规范化为 LF；私有原始回执保留，其字节摘要如下。
这些原始摘要不能拿来宣称规范化副本字节相同：

| 回执 | 原始 SHA256 |
| --- | --- |
| 原生结果 | `81b305d283d9ff3e2234696f44fdb5512233339ffa9b9d5f279d376043581ea2` |
| 清理 | `b3c49322cc78e8f31195b0e6cb6daebcefb7e783e328ce136aff6026efa0fc51` |
| 独立终态查询 | `45c428b5aadabdd585aed78a40110b2c56f8e75c77dd9f7cd16c5eb91ff43467` |

## 仍待验收

Ubuntu 24.04 标准栈中的 root 安装、专用只读 SSH/精确策略、正常/异常/恢复/证据不足
四组产品调查，以及同环境的首次接入、Nginx/Compose 依赖和业务闭环仍需单独证据。
本记录不将整体 MVP、磁盘场景或最新完整 Linux 矩阵改为全部通过。
