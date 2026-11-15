"""Evidence-based, read-only interpretation of a bounded collection.

These rules describe observations and candidate causes. They never execute a
command, infer a historical change from a single snapshot, or certify recovery.
"""

import json
import re
from collections import Counter
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

from opsark.disk_reclaim import parse_disk_reclaim, safe_disk_check
from opsark.models import (
    CheckResult,
    Collection,
    Evidence,
    Finding,
    HostPublic,
    Report,
    Scenario,
    Verification,
)
from opsark.nginx_error_window import metadata_line
from opsark.platforms import assess, os_identity

_MAX_OUTPUT_BYTES = 16_384
_SCENARIOS: tuple[Scenario, ...] = ("web_502", "disk", "container_restart", "ssh_security")
_TITLES = {
    "web_502": "网站代理与上游调查",
    "disk": "根分区容量与 inode 调查",
    "container_restart": "容器退出与重启调查",
    "ssh_security": "SSH 认证安全观察",
}
_REQUIRED = {
    "web_502": ("nginx_status", "nginx_errors", "container_state", "listeners"),
    "disk": ("disk_bytes", "disk_inodes", "disk_directories"),
    "container_restart": ("container_state", "container_logs", "memory_events"),
    "ssh_security": ("ssh_auth",),
}
_LABELS = {
    "os_release": "系统版本",
    "platform_tools": "架构与工具预检",
    "nginx_status": "Nginx 服务状态",
    "nginx_errors": "Nginx 错误日志",
    "listeners": "监听端口",
    "container_state": "指定容器状态",
    "container_logs": "应用日志",
    "memory_events": "系统内存事件",
    "disk_bytes": "根分区容量",
    "disk_inodes": "根分区 inode",
    "disk_directories": "目录占用",
    "disk_reclaim": "磁盘 inode 与开放文件元数据",
    "ssh_auth": "SSH 认证记录",
}


def _bound(check: CheckResult) -> CheckResult:
    """Keep displayed evidence and the data interpreted by rules identical."""
    stdout = check.stdout.encode("utf-8")
    stderr = check.stderr.encode("utf-8")
    clipped = len(stdout) + len(stderr) > _MAX_OUTPUT_BYTES
    stdout = stdout[:_MAX_OUTPUT_BYTES]
    stderr = stderr[: max(0, _MAX_OUTPUT_BYTES - len(stdout))]
    return check.model_copy(
        update={
            "stdout": stdout.decode("utf-8", errors="ignore"),
            "stderr": stderr.decode("utf-8", errors="ignore"),
            "truncated": check.truncated or clipped,
        }
    )


class _Investigation:
    def __init__(self, host: HostPublic, collection: Collection) -> None:
        self.host = host
        self.collection = collection
        self.checks: dict[str, CheckResult] = {}
        self.references: dict[str, str] = {}
        self.evidence: list[Evidence] = []
        self.facts: list[Finding] = []
        self.candidates: list[Finding] = []
        self.missing: list[str] = []
        self.next_steps: list[str] = []
        self.attention = False
        self.healthy_observation = False
        self.parse_incomplete = False
        self.egress_blocked = False
        for check in collection.checks:
            if check.name in self.checks:
                raise ValueError("duplicate check identifiers are not allowed")
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", check.name):
                raise ValueError("invalid check identifier")
            if check.name == "disk_reclaim":
                check, rejected = safe_disk_check(check, host.disk_reclaim_scope_digest)
                self.egress_blocked = self.egress_blocked or rejected
            if check.name == "nginx_errors" and collection.nginx_error_window is not None:
                check = check.model_copy(update={"stdout": "", "stderr": ""})
            normalized = _bound(check)
            evidence_id = "E-" + check.name.replace("_", "-").upper()
            self.checks[check.name] = normalized
            self.references[check.name] = evidence_id
            output = normalized.stdout
            if normalized.stderr:
                output += ("\n" if output else "") + "[stderr]\n" + normalized.stderr
            if check.name == "nginx_errors" and collection.nginx_error_window is not None:
                output = metadata_line(collection.nginx_error_window)
            self.evidence.append(
                Evidence(
                    id=evidence_id,
                    check_id=check.name,
                    target=host.id,
                    source=collection.source,
                    collected_at=collection.started_at,
                    status=normalized.status,
                    output=output or "（未取得输出；请结合检查状态判断）",
                    exit_code=normalized.exit_code,
                    truncated=normalized.truncated,
                )
            )

    def gap(self, text: str) -> None:
        if text not in self.missing:
            self.missing.append(text)

    def finding(self, text: str, *names: str, candidate: bool = False) -> None:
        finding = Finding(
            text=text,
            evidence_ids=[self.references[name] for name in names if name in self.references],
        )
        (self.candidates if candidate else self.facts).append(finding)

    def read(self, name: str, *, partial: bool = False) -> str | None:
        check = self.checks.get(name)
        if check is None:
            self.gap(f"未采集{_LABELS.get(name, name)}。")
            return None
        if check.status != "ok" or check.exit_code != 0:
            self.gap(
                f"{_LABELS.get(name, name)}检查未完成（{check.status}，退出结果 "
                f"{check.exit_code if check.exit_code is not None else '未知'}）"
                "，不能作为正常依据。"
            )
            return None
        if not check.stdout.strip():
            self.gap(f"{_LABELS.get(name, name)}没有可解释的输出，不能据此排除异常。")
            return None
        if check.truncated:
            self.gap(f"{_LABELS.get(name, name)}结果已截断，仅覆盖展示片段。")
            if not partial:
                return None
        return check.stdout

    def system_supported(self) -> bool:
        raw = self.read("os_release")
        if raw is None:
            return False
        system_id, _ = os_identity(self.checks.get("os_release"))
        if system_id is None:
            self.gap("系统标识无法识别，环境专属结论受限。")
            return False
        self.finding(f"读取的系统标识为 {system_id}。", "os_release")
        if system_id not in {"ubuntu", "debian"}:
            self.gap("该系统不在当前 Ubuntu / Debian 验证范围内，停止环境专属判断。")
            return False
        return True

    def container(self) -> dict[str, Any] | None:
        raw = self.read("container_state")
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            self.gap("容器状态不是完整的 JSON 对象，不能据此判断健康或退出原因。")
            return None
        if not isinstance(data, dict) or not isinstance(data.get("State"), dict):
            self.gap("容器状态缺少可识别的 State 对象。")
            return None
        if str(data.get("Name", "")).lstrip("/") != self.host.container_name:
            self.gap("采集到的容器标识与登记目标不一致，不能将其状态用于本次结论。")
            return None
        state = data["State"]
        if state.get("Status") not in {
            "created",
            "running",
            "paused",
            "restarting",
            "removing",
            "exited",
            "dead",
        }:
            self.gap("容器运行状态字段缺失或不可识别。")
            return None
        return data


def _nginx_status(inv: _Investigation) -> str | None:
    check = inv.checks.get("nginx_status")
    # systemctl is-active uses exit status 3 for known inactive states.
    if (
        check is not None
        and check.status in {"ok", "error"}
        and check.exit_code in {0, 3}
        and not check.truncated
        and check.stdout.strip() in {"active", "inactive", "failed", "activating", "deactivating"}
    ):
        state = check.stdout.strip()
        inv.finding(f"Nginx 服务状态返回 {state}；该项不代表网站业务检查。", "nginx_status")
        return state
    inv.read("nginx_status")
    return None


def _published_ports(container: dict[str, Any]) -> set[int] | None:
    ports = container.get("Ports")
    if not isinstance(ports, dict):
        return None
    result: set[int] = set()
    for bindings in ports.values():
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            return None
        for binding in bindings:
            if not isinstance(binding, dict):
                return None
            port = binding.get("HostPort")
            if not isinstance(port, (str, int)) or isinstance(port, bool):
                return None
            try:
                number = int(port)
            except ValueError:
                return None
            if not 1 <= number <= 65535:
                return None
            result.add(number)
    return result


def _web(inv: _Investigation) -> None:
    state = _nginx_status(inv)
    window = inv.collection.nginx_error_window
    errors = inv.read("nginx_errors", partial=True) if window is None else None
    if window is not None:
        if window.status == "observed":
            if window.matching_refused:
                inv.attention = True
                inv.finding("目标站点的日志窗口记录了已识别的上游连接拒绝。", "nginx_errors")
            if window.matching_timeout:
                inv.attention = True
                inv.finding("目标站点的日志窗口记录了已识别的上游超时。", "nginx_errors")
        else:
            inv.gap(metadata_line(window))
    listeners = inv.read("listeners")
    container = inv.container()
    if state in {"inactive", "failed"}:
        inv.attention = True
        inv.finding(
            "Nginx 服务当前未处于 active 状态，代理层不可用是候选原因。",
            "nginx_status",
            candidate=True,
        )
    refused_ports: set[int] = set()
    if errors:
        for line in errors.splitlines():
            if "connect() failed" not in line or "Connection refused" not in line:
                continue
            server_match = re.search(r"\bserver:\s*([^,\s]+)", line)
            upstream_match = re.search(
                r"\bupstream:\s*[\"']?https?://127\.0\.0\.1:(\d+)(?:/|[\"',\s])", line
            )
            if (
                server_match
                and server_match.group(1).lower().rstrip(".")
                == inv.host.site_domain.lower().rstrip(".")
                and upstream_match
            ):
                port = int(upstream_match.group(1))
                if 1 <= port <= 65535:
                    refused_ports.add(port)
        if refused_ports:
            inv.attention = True
            inv.finding(
                "目标站点的错误片段包含本机上游连接被拒绝，涉及端口 "
                f"{', '.join(map(str, sorted(refused_ports)))}。",
                "nginx_errors",
            )
        elif any(
            "upstream timed out" in line
            and (server := re.search(r"\bserver:\s*([^,\s]+)", line))
            and server.group(1).lower().rstrip(".") == inv.host.site_domain.lower().rstrip(".")
            for line in errors.splitlines()
        ):
            inv.attention = True
            inv.finding(
                "目标站点日志片段包含上游超时；尚不能确定是应用、依赖还是资源原因。", "nginx_errors"
            )
    if container:
        container_state = container["State"]["Status"]
        inv.finding(
            f"登记容器 {inv.host.container_name} 的当前状态为 {container_state}。",
            "container_state",
        )
        if container_state in {"exited", "dead", "restarting", "paused", "created"}:
            inv.attention = True
            inv.finding(
                "登记的上游容器当前不在正常运行状态；需要结合监听和错误日志核对站点依赖。",
                "container_state",
                "nginx_errors",
                candidate=True,
            )
        published = _published_ports(container)
        if published is None:
            inv.gap("容器发布端口字段不完整，无法可靠比较代理上游。")
        elif published:
            inv.finding(
                f"容器当前发布的宿主端口为 {', '.join(map(str, sorted(published)))}。",
                "container_state",
            )
            for port in sorted(refused_ports - published):
                inv.finding(
                    f"日志请求端口 {port} 不在目标容器当前发布端口中，"
                    "上游端口不一致是候选原因；尚需核实预期部署设计。",
                    "nginx_errors",
                    "container_state",
                    candidate=True,
                )
        else:
            inv.gap(
                "容器未显示宿主端口发布；可能使用容器网络或其他代理形态，超出当前端口比较范围。"
            )
    if listeners:
        inv.finding("已取得监听端口快照；监听存在本身不能证明 HTTP 或业务可用。", "listeners")
    inv.gap("未取得可靠的历史部署记录或上次已验收配置，不能断言近期变更或建立可靠回退点。")
    inv.gap("站点即时检查与完整业务验收分开记录；本次不能宣告网站恢复或所有相关站点健康。")
    inv.next_steps.extend(
        [
            "核实域名、Nginx 上游和容器发布端口是否属于同一条已确认依赖。",
            "补齐预期配置、配置归属和可靠回退版本，再单独评审任何重载或修改。",
            "登记无业务写入的检查与共享站点，后续按观察窗口验收。",
        ]
    )


def _df(raw: str | None, *, inode: bool = False) -> tuple[int, int, int, int] | None:
    if not raw:
        return None
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) != 2:
        return None
    if inode:
        if "Inodes" not in lines[0] or "IUse%" not in lines[0]:
            return None
    elif "1024-blocks" not in lines[0] and "1K-blocks" not in lines[0]:
        return None
    parts = lines[1].split()
    if len(parts) != 6 or parts[-1] != "/" or not re.fullmatch(r"\d+%", parts[-2]):
        return None
    try:
        total, used, available = (int(value) for value in parts[1:4])
        percent = int(parts[4][:-1])
    except ValueError:
        return None
    if total <= 0 or min(used, available, percent) < 0 or percent > 1000:
        return None
    return total, used, available, percent


def _disk(inv: _Investigation) -> None:
    capacity = _df(inv.read("disk_bytes"))
    inode = _df(inv.read("disk_inodes"), inode=True)
    scoped = "disk_reclaim" in inv.checks or inv.host.disk_reclaim_scope_digest is not None
    directories = None if scoped else inv.read("disk_directories", partial=True)
    if capacity:
        _, _, available_kib, used_percent = capacity
        available_gib = available_kib / (1024 * 1024)
        inv.finding(
            f"根分区容量快照已用 {used_percent}%，可用约 {available_gib:.2f} GiB。", "disk_bytes"
        )
        if used_percent >= 90 or available_gib < 1:
            inv.attention = True
            inv.finding(
                "根分区空间已达到本版关注阈值（使用率至少 90% 或可用低于 1 GiB），"
                "写入风险需要排查。",
                "disk_bytes",
                candidate=True,
            )
    else:
        inv.gap("根分区容量输出缺失或格式不符合登记的 df -Pk 检查，不能判断容量是否正常。")
    if inode:
        _, _, available_inodes, inode_percent = inode
        inv.finding(
            f"根分区 inode 已用 {inode_percent}%，可用数量 {available_inodes}。", "disk_inodes"
        )
        if inode_percent >= 90 or available_inodes == 0:
            inv.attention = True
            inv.finding(
                "inode 使用率偏高或已无可用 inode，即使仍有字节空间也可能无法创建文件。",
                "disk_inodes",
                candidate=True,
            )
    else:
        inv.gap("根分区 inode 输出缺失或不可解释，不能仅凭字节容量排除磁盘问题。")
    if directories:
        parsed: list[tuple[int, str]] = []
        for line in directories.splitlines():
            match = re.fullmatch(r"\s*(\d+)\s+(/[^\r\n]+)\s*", line)
            if match:
                parsed.append((int(match.group(1)), match.group(2).strip()))
        if parsed:
            for kib, path in sorted(parsed, reverse=True)[:4]:
                if path == "/var/log" or path.startswith("/var/log/"):
                    category = "日志目录，需核对保留要求"
                elif path.startswith(
                    ("/srv", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/docker/volumes")
                ):
                    category = "可能的业务或持久化数据，不视为可删除对象"
                elif path.startswith("/var/lib/docker"):
                    category = "Docker 数据，可能含业务与容器数据，不能直接清理"
                else:
                    category = "性质待维护者确认"
                inv.finding(
                    f"目录样本 {path} 占用约 {kib / (1024 * 1024):.2f} GiB；{category}。",
                    "disk_directories",
                )
        else:
            inv.gap("目录占用结果没有可解释的大小与路径，分类尚未完成。")
            inv.parse_incomplete = True
    inv.healthy_observation = bool(capacity and inode and not inv.attention)
    inv.gap("当前快照不提供连续增长历史；单次采集不能确定增长来源或速度，观测基线差异另行展示。")
    if scoped:
        _disk_reclaim(inv)
    else:
        inv.gap(
            "日志保留、开放文件引用、存储快照和实际可回收空间未核实；目录逻辑大小不等于释放量。"
        )
    inv.next_steps.extend(
        [
            "按采集覆盖范围核实日志和业务数据的保留、备份与归属，不自动删除持久化数据。",
            "补充历史容量样本，并核对精确登记范围之外的持有者，区分当前占用和增长来源。",
            "任何人工处置后重新测量文件系统与 inode，并独立检查业务状态。",
        ]
    )


def _disk_reclaim(inv: _Investigation) -> None:
    if inv.read("disk_reclaim") is None:
        inv.parse_incomplete = True
        inv.gap("未取得通过范围、一致性与完整白名单核验的磁盘元数据；不提供回收容量估算。")
        return
    result = parse_disk_reclaim(inv.checks["disk_reclaim"], inv.host.disk_reclaim_scope_digest)
    labels = {
        "deleted_held": "已删除仍持有",
        "linked_open": "仍链接且已见持有者",
        "linked_no_registered_holder": "仍链接且登记进程中未见持有者",
    }
    conditions = {
        "business_excluded": "业务数据排除清理",
        "all_holders_close": "须全部持有者及映射释放后再复测",
        "retention_all_links_all_holders": "须审批保留要求、移除全部链接并关闭全部持有者",
        "unscoped_links_unknown": "存在范围外硬链接，排除容量估算",
    }
    for obj in result.objects:
        category = "日志" if obj.category == "log" else "业务数据"
        directories = ",".join(obj.directory_refs)
        inv.finding(
            f"磁盘对象 {obj.object_ref}（{directories}，{category}）："
            f"逻辑 {obj.logical_bytes} 字节，已分配 {obj.allocated_bytes} 字节；"
            f"{labels[obj.state]}，范围内硬链接 {obj.scoped_link_count}/{obj.link_count}；"
            f"{conditions[obj.release_condition]}。",
            "disk_reclaim",
        )
        if obj.state == "deleted_held" and obj.allocated_bytes:
            inv.attention = True
    inv.finding(
        f"日志分配块的条件回收区间为 0 至 {result.conditional_log_upper_bytes} 字节；"
        "立即可回收量未知，未验证物理释放。",
        "disk_reclaim",
    )
    inv.gap(
        "仅覆盖登记目录和登记 PID 的 FD；未见持有者不证明全机无人持有，PID 或文件变化后须重新采集。"
    )
    inv.gap(
        "未扫描内存映射与其他内核引用；已删除对象仍须全部引用释放后复测，"
        "不能保证关闭已见 FD 即释放。"
    )
    inv.gap("日志与业务分类来自部署者登记，未读取内容验证；业务数据始终排除清理。")
    inv.gap(
        "这是根文件系统上按 inode 去重的非原子元数据快照；硬链接不重复相加，范围外链接排除估算。"
    )
    inv.gap(
        "条件上界采用 st_blocks×512，稀疏文件逻辑大小不参与相加；"
        "共享块、快照、压缩与处置后的并发写入未验证，实际物理释放可能为零。"
    )
    inv.next_steps.append(
        "由维护者核对日志对象引用、保留审批、所有硬链接与全部持有者；"
        "OpsArk 不删除、截断或重启，业务数据始终排除清理。"
    )


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _container(inv: _Investigation) -> None:
    data = inv.container()
    logs = inv.read("container_logs", partial=True)
    memory_events = inv.read("memory_events", partial=True)
    if data:
        state = data["State"]
        status = state["Status"]
        count = _integer(data.get("RestartCount"))
        exit_code = _integer(state.get("ExitCode"))
        memory_limit = _integer(data.get("MemoryLimit"))
        oom = state.get("OOMKilled")
        inv.finding(f"容器 {inv.host.container_name} 当前状态为 {status}。", "container_state")
        if count is not None:
            inv.finding(
                f"当前快照累计重启计数为 {count}；单次计数不能确定近期重启频率。", "container_state"
            )
        else:
            inv.gap("重启计数字段缺失或类型不正确，无法判断重启历史。")
        if exit_code is not None:
            inv.finding(
                f"容器状态中最近退出码为 {exit_code}；退出码本身不证明根因。", "container_state"
            )
        else:
            inv.gap("最近退出结果缺失或不可解释。")
        if memory_limit is not None:
            limit_text = (
                f"{memory_limit / (1024 * 1024):.0f} MiB" if memory_limit else "未设置显式内存上限"
            )
            inv.finding(f"容器内存限制记录为 {limit_text}。", "container_state")
        if status in {"restarting", "exited", "dead"} or (count is not None and count > 0):
            inv.attention = True
        if oom is True:
            inv.attention = True
            inv.finding(
                "运行时状态明确记录 OOMKilled=true，为内存终止提供直接状态证据。", "container_state"
            )
            supporting = (
                ("container_state", "memory_events")
                if memory_events
                and re.search(
                    r"out of memory|oom-kill|killed process", memory_events, re.IGNORECASE
                )
                else ("container_state",)
            )
            inv.finding(
                "内存终止是有状态证据支持的候选原因；仍需核对对应时间、容器及资源历史。",
                *supporting,
                candidate=True,
            )
        elif oom is not False:
            inv.gap("运行时 OOM 标记缺失或类型不明确。")
        if exit_code == 137 and oom is not True:
            inv.finding(
                "退出码 137 尚不能区分内存终止、外部终止或其他信号来源，需要补证。",
                "container_state",
                candidate=True,
            )
            inv.gap("没有直接 OOM 状态证据；不得仅凭 137 或配置了内存上限就认定 OOM。")
        if logs and re.search(
            r"connection.*(?:timeout|timed out)|database.*timeout", logs, re.IGNORECASE
        ):
            inv.finding("应用日志片段出现连接超时；其与退出的因果关系尚未证实。", "container_logs")
            inv.gap("需要核实应用依赖状态、完整日志和退出时间，不能将日志共现直接当作根因。")
        inv.healthy_observation = (
            status == "running" and count == 0 and exit_code == 0 and oom is False
        )
    inv.gap("缺少已核实的配置变更、人工操作与连续资源历史，不能断言近期变更或退出信号来源。")
    inv.gap("容器运行或重启计数不增加，不能替代业务恢复与持续观察。")
    inv.next_steps.extend(
        [
            "先保留退出上下文和应用日志，补充对应时间的内存事件、资源与依赖证据。",
            "区分临时恢复、资源调整和应用修复；任何重启、重建或资源变更都需单独评审。",
            "后续按登记窗口比较重启事件与业务检查，不以运行状态直接结案。",
        ]
    )


_FAILED = re.compile(
    r"\bsshd(?:-session)?\[\d+\]: Failed (?:password|publickey) for "
    r"(?:invalid user )?([A-Za-z0-9._@-]{1,64}) from ([^\s]+) port \d+"
)
_ACCEPTED = re.compile(
    r"\bsshd(?:-session)?\[\d+\]: Accepted (?:password|publickey|keyboard-interactive) for "
    r"([A-Za-z0-9._@-]{1,64}) from ([^\s]+) port \d+"
)


def _ssh(inv: _Investigation) -> None:
    raw = inv.read("ssh_auth", partial=True)
    if raw:
        failures: Counter[str] = Counter()
        successes: Counter[str] = Counter()
        for line in raw.splitlines():
            for pattern, counter in ((_FAILED, failures), (_ACCEPTED, successes)):
                match = pattern.search(line)
                if match:
                    try:
                        source = str(ip_address(match.group(2)))
                    except ValueError:
                        continue
                    counter[source] += 1
        total = sum(failures.values())
        if total:
            inv.finding(
                f"展示片段中匹配到 {total} 条认证失败事件；这是日志事件数量，不代表唯一请求总量。",
                "ssh_auth",
            )
        if successes:
            inv.finding(
                f"展示片段中匹配到 {sum(successes.values())} 条认证成功事件，"
                "需独立核对来源与授权。",
                "ssh_auth",
            )
        for source, count in failures.most_common(5):
            inv.finding(f"来源 {source} 在展示片段内有 {count} 条认证失败事件。", "ssh_auth")
            if count >= 5:
                inv.attention = True
                inv.finding(
                    f"来源 {source} 的重复认证失败达到本版观察阈值（片段内至少 5 条）；"
                    "可能是自动化尝试或错误配置的合法任务，需核对。",
                    "ssh_auth",
                    candidate=True,
                )
            if source in successes:
                inv.attention = True
                inv.finding(
                    f"同一来源 {source} 还出现认证成功事件，需要核实账号与授权；"
                    "不能据此直接认定攻击者入侵。",
                    "ssh_auth",
                    candidate=True,
                )
        if not total and not successes:
            inv.gap("日志片段没有可识别的认证失败或成功格式，不能将其解释为没有攻击或登录。")
    inv.gap("日志时间窗、轮转和采集权限未证明完整覆盖；未见成功记录不能排除成功登录。")
    inv.gap("账号、密钥、计划任务及完整管理员会话尚未核实，入侵状态未确定。")
    inv.next_steps.extend(
        [
            "核实认证来源、账号、完整时间窗与已知自动任务，分别记录攻击尝试和入侵证据。",
            "当前仅安全观察，OpsArk 不新增或扩大封禁；已有防护动作按其实际执行归属记录。",
            "如需后续短时阻断，另行验证授权范围、管理通道、真实生效路径和到期撤销。",
        ]
    )


def diagnose(scenario: Scenario, host: HostPublic, collection: Collection) -> Report:
    """Build a conservative report; no side effects occur in the domain layer."""
    if scenario not in _SCENARIOS:
        raise ValueError("unsupported scenario")
    if host.id != collection.host_id or host.source != collection.source:
        raise ValueError("collection target/source does not match the registered host")
    if collection.started_at.tzinfo is None:
        raise ValueError("collection timestamp must include its timezone")
    inv = _Investigation(host, collection)
    compatibility = assess(list(inv.checks.values()))
    supported = inv.system_supported()
    preflight_required = collection.source == "ssh" or "platform_tools" in inv.checks
    if preflight_required and compatibility.status != "compatible":
        inv.gap(compatibility.detail)
        supported = False
    if supported:
        {"web_502": _web, "disk": _disk, "container_restart": _container, "ssh_security": _ssh}[
            scenario
        ](inv)
    else:
        inv.next_steps.append("补齐系统标识与支持范围后重新调查，当前只保留采集证据。")
    required = _REQUIRED[scenario]
    if scenario == "disk" and host.disk_reclaim_scope_digest is not None:
        required = ("disk_bytes", "disk_inodes", "disk_reclaim")
    core_complete = all(
        name in inv.checks
        and inv.checks[name].status == "ok"
        and inv.checks[name].exit_code == 0
        and bool(inv.checks[name].stdout.strip())
        and not inv.checks[name].truncated
        for name in required
    )
    if inv.attention:
        status = "needs_attention"
        summary = "发现需要关注的采集事实或候选原因；仍有证据缺口，未实施修复、防御或恢复验收。"
    elif inv.healthy_observation and core_complete and not inv.parse_incomplete:
        status = "no_issue_detected"
        summary = "已完成的本次检查未显示该类异常；覆盖范围有限，不代表整机安全或业务恢复。"
    else:
        status = "inconclusive"
        summary = "当前证据不足以可靠确认或排除该类问题；请查看缺失信息和下一步检查。"
    return Report(
        id=str(uuid4()),
        host_id=host.id,
        host_name=host.name,
        scenario=scenario,
        source=collection.source,
        created_at=datetime.now(UTC),
        status=status,
        title=_TITLES[scenario],
        summary=summary,
        facts=inv.facts,
        candidates=inv.candidates,
        missing=inv.missing,
        evidence=inv.evidence,
        next_steps=inv.next_steps,
        verification=[
            Verification(
                name="业务状态与正常访问",
                detail="未执行实际处置后的业务验收；需要单独登记并确认无副作用的检查。",
            ),
            Verification(
                name="持续观察与未覆盖业务",
                status="uncovered",
                detail="本次为快照调查，不覆盖登录、下单、支付、完整安全调查或持续恢复观察。",
            ),
        ],
        duration_ms=collection.duration_ms,
        target=host,
        compatibility=compatibility,
        nginx_error_window=collection.nginx_error_window if scenario == "web_502" else None,
        ai_egress_block_reason="unclassified_payload" if inv.egress_blocked else None,
    )
