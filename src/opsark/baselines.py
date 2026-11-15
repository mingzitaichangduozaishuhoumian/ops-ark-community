"""Immutable, reduced observation snapshots; never configuration restore points."""

import hashlib
import ipaddress
import json
import re
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from opsark.disk_reclaim import (
    DiskAllocationRejected,
    allocation_features,
    allocation_group,
    parse_disk_reclaim,
    validate_allocation_features,
    validate_disk_comparison,
)
from opsark.models import (
    BaselineChange,
    BaselineComparison,
    BaselineInfo,
    CheckResult,
    Evidence,
    HostPublic,
    Report,
    Scenario,
    Source,
    Verification,
)
from opsark.redaction import redact

_MAX_OUTPUT = 16_384
_MAX_VALUE = 4096
_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_HTTP_CHECK = re.compile(r"http_[a-z][a-z0-9_]{0,39}\Z")
_CONTAINER_NAME = re.compile(r"/?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,440}(?:@sha256:[a-f0-9]{64})?\Z")
_CONTAINER_STATUSES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
_SUPPORTED_CHECKS = {
    "os_release",
    "container_state",
    "disk_bytes",
    "disk_inodes",
    "nginx_status",
    "nginx_config_hash",
    "disk_reclaim",
}


def _scope_for(host: HostPublic, *, include_disk: bool) -> str:
    values = host.model_dump(mode="json", exclude={"name", "web_profile_digest"})
    if not include_disk or host.disk_reclaim_scope_digest is None:
        values.pop("disk_reclaim_scope_digest", None)
    try:
        values["address"] = str(ipaddress.ip_address(host.address))
    except ValueError:
        values["address"] = host.address.lower().rstrip(".")
    values["site_domain"] = host.site_domain.lower().rstrip(".")
    values["health_checks"] = sorted(
        [
            {**check, "domain": check["domain"].lower().rstrip(".")}
            for check in values["health_checks"]
        ],
        key=lambda check: check["id"],
    )
    serialized = json.dumps(values, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def scope_for(host: HostPublic) -> str:
    """Bind transport, remediation and security observations to the registered host."""
    return _scope_for(host, include_disk=False)


def diagnostic_scope_for(host: HostPublic) -> str:
    """Bind reports and baselines to the host and its registered disk metadata scope."""
    return _scope_for(host, include_disk=True)


def matches_host_scope(host: HostPublic, expected: str) -> bool:
    """Recognize the durable scope or the historical hash of this exact registration."""
    return expected == scope_for(host) or expected == diagnostic_scope_for(host)


def report_target_matches_host_scope(
    target: HostPublic | None, host_id: str, report_scope: str, host_scope: str
) -> bool:
    if target is None:
        return report_scope == host_scope
    return (
        target.source == "ssh"
        and target.id == host_id
        and diagnostic_scope_for(target) == report_scope
        and matches_host_scope(target, host_scope)
    )


def _number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1:
        return value
    return None


def _os_fields(output: str) -> tuple[dict[str, str], list[str]]:
    values = {}
    for key, pattern in (
        ("ID", r"[a-z0-9_-]{1,32}"),
        ("VERSION_ID", r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}"),
    ):
        matches = re.findall(rf"^{key}=([^\r\n]+)\r?$", output, re.MULTILINE)
        if len(matches) != 1:
            continue
        value = matches[0].strip()
        if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        if re.fullmatch(pattern, value):
            values["os." + key.lower()] = value
    missing = [
        f"系统字段 {key} 未取得完整、可解释的值。"
        for key in ("ID", "VERSION_ID")
        if "os." + key.lower() not in values
    ]
    return values, missing


def _ports(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, list[str]] = {}
    for container_port, bindings in value.items():
        if not isinstance(container_port, str):
            return None
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", container_port)
        if match is None or not 1 <= int(match[1]) <= 65535:
            return None
        if bindings is None:
            result[container_port] = []
            continue
        if not isinstance(bindings, list) or len(bindings) > 64:
            return None
        addresses = []
        for binding in bindings:
            if not isinstance(binding, dict):
                return None
            address = binding.get("HostIp")
            raw_port = binding.get("HostPort")
            if not isinstance(address, str) or not isinstance(raw_port, (str, int)):
                return None
            if isinstance(raw_port, bool) or not re.fullmatch(r"[0-9]{1,5}", str(raw_port)):
                return None
            if not 1 <= int(raw_port) <= 65535:
                return None
            try:
                if address:
                    address = str(ipaddress.ip_address(address))
            except ValueError:
                return None
            addresses.append(f"[{address}]:{int(raw_port)}")
        result[container_port] = sorted(addresses)
    normalized = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return normalized if len(normalized) <= _MAX_VALUE else None


def _container_fields(output: str, target: HostPublic) -> tuple[dict[str, str], list[str]]:
    try:
        document = json.loads(output)
    except (ValueError, TypeError):
        return {}, ["容器快照不是完整的 JSON 对象。"]
    if not isinstance(document, dict):
        return {}, ["容器快照不是对象结构。"]
    state = document.get("State")
    if not isinstance(state, dict):
        return {}, ["容器快照缺少可解释的运行状态。"]
    values: dict[str, str] = {}
    missing = []
    name = document.get("Name")
    if isinstance(name, str) and _CONTAINER_NAME.fullmatch(name) and redact(name) == name:
        if name.lstrip("/") != target.container_name:
            return {}, ["容器标识与登记目标不一致，未提取该容器的基线字段。"]
        values["container.name"] = name.lstrip("/")
    else:
        return {}, ["容器名称缺失或不能安全识别。"]
    status = state.get("Status")
    if isinstance(status, str) and status in _CONTAINER_STATUSES:
        values["container.status"] = status
    else:
        missing.append("容器状态字段缺失或不可解释。")
    for field, key in (("RestartCount", "restart_count"), ("MemoryLimit", "memory_limit_bytes")):
        number = _number(document.get(field))
        if number is None:
            missing.append(f"容器字段 {field} 缺失或类型不正确。")
        else:
            values["container." + key] = str(number)
    oom = state.get("OOMKilled")
    if isinstance(oom, bool):
        values["container.oom_killed"] = "true" if oom else "false"
    else:
        missing.append("容器 OOM 状态字段缺失或类型不正确。")
    image = document.get("Image")
    if isinstance(image, str) and _IMAGE_ID.fullmatch(image):
        values["container.image_id"] = image
    else:
        missing.append("容器镜像摘要缺失或格式不正确。")
    reference = document.get("ImageReference")
    if (
        isinstance(reference, str)
        and _IMAGE_REFERENCE.fullmatch(reference)
        and "://" not in reference
        and ".." not in reference
        and redact(reference) == reference
    ):
        values["container.image_reference"] = reference
    else:
        missing.append("容器镜像引用缺失或不能安全识别。")
    ports = _ports(document.get("Ports"))
    if ports is None:
        missing.append("容器发布端口缺失或不可完整解释。")
    else:
        values["container.published_ports"] = ports
    return values, missing


def _df_fields(output: str, *, inode: bool = False) -> tuple[dict[str, str], list[str]]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 2:
        return {}, ["文件系统快照行数不符合已登记的根分区检查。"]
    if inode:
        valid_header = "Inodes" in lines[0] and "IUse%" in lines[0]
        prefix = "inode."
        keys = ("total", "used", "available", "used_percent")
    else:
        valid_header = "1024-blocks" in lines[0] or "1K-blocks" in lines[0]
        prefix = "disk."
        keys = ("total_kib", "used_kib", "available_kib", "used_percent")
    fields = lines[1].split()
    if not valid_header or len(fields) != 6 or fields[-1] != "/":
        return {}, ["文件系统快照不是当前根分区的预期格式。"]
    if not re.fullmatch(r"[0-9]{1,4}%", fields[4]):
        return {}, ["文件系统使用率字段不能解释。"]
    raw_values = [*fields[1:4], fields[4][:-1]]
    if any(not re.fullmatch(r"[0-9]{1,19}", value) for value in raw_values):
        return {}, ["文件系统数值字段不能解释。"]
    numbers = [int(value) for value in raw_values]
    if numbers[0] <= 0 or any(_number(value) is None for value in numbers) or numbers[3] > 1000:
        return {}, ["文件系统数值超出可解释范围。"]
    return {prefix + key: str(number) for key, number in zip(keys, numbers, strict=True)}, []


def _extract(
    evidence: Evidence, target: HostPublic, verification: list[Verification]
) -> tuple[dict[str, str], list[str]]:
    check = evidence.check_id
    if check == "os_release":
        return _os_fields(evidence.output)
    if check == "container_state":
        return _container_fields(evidence.output, target)
    if check in {"disk_bytes", "disk_inodes"}:
        return _df_fields(evidence.output, inode=check == "disk_inodes")
    if check == "disk_reclaim":
        try:
            result = parse_disk_reclaim(
                CheckResult(
                    name=check,
                    status=evidence.status,
                    stdout=evidence.output,
                    exit_code=evidence.exit_code,
                    truncated=evidence.truncated,
                ),
                target.disk_reclaim_scope_digest,
            )
            return allocation_features(result), []
        except ValueError:
            raise DiskAllocationRejected("Disk allocation source rejected") from None
    if check == "nginx_status":
        if evidence.output.strip() == "active":
            return {"nginx.status": "active"}, []
        return {}, ["Nginx 状态不是成功取得的 active 观测，不能保存为正常旧值。"]
    if check == "nginx_config_hash":
        match = re.fullmatch(r"([a-fA-F0-9]{64})(?:[ \t]+([^\r\n]+))?\n?", evidence.output)
        if not target.nginx_config_path:
            return {}, ["未登记 Nginx 配置文件范围，未提取文件摘要。"]
        if match and (match[2] is None or match[2].lstrip(" *") == target.nginx_config_path):
            return {"nginx.config_sha256": match[1].lower()}, []
        return {}, ["Nginx 摘要格式或文件范围不符；它不是已生效配置或回退点。"]
    registered = {"http_" + item.id: item for item in target.health_checks}
    if check not in registered or not registered[check].read_only_confirmed:
        return {}, [f"HTTP 检查 {check} 未登记或未确认只读，未提取快照字段。"]
    matches = [result for result in verification if evidence.id in result.evidence_ids]
    if len(matches) != 1 or matches[0].evidence_ids != [evidence.id]:
        return {}, [f"HTTP 检查 {check} 缺少唯一、明确绑定当前证据的原始判断。"]
    result = matches[0]
    config = registered[check]
    if (
        type(result.http_status) is not int
        or not 100 <= result.http_status <= 599
        or type(result.status_matches) is not bool
        or type(result.body_matches) is not bool
        or result.status_matches != (result.http_status == config.expected_status)
        or result.status not in {"passed", "failed"}
        or (result.status == "passed") != (result.status_matches and result.body_matches)
        or (config.expected_body == "" and result.body_matches is not True)
    ):
        return {}, [f"HTTP 检查 {check} 的原始判断元数据缺失或互相矛盾，未提取字段。"]
    prefix = "http." + check.removeprefix("http_")
    return {
        prefix + ".status": str(result.http_status),
        prefix + ".body_matches": "true" if result.body_matches else "false",
        prefix + ".expected_status_matches": "true" if result.status_matches else "false",
    }, []


def snapshot(report: Report) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
    """Extract only typed, bounded metadata from complete successful evidence."""
    features: dict[str, str] = {}
    references: dict[str, list[str]] = {}
    missing: list[str] = []
    target = report.target
    if target is None:
        return {}, {}, ["报告没有登记目标元数据，不能建立可核对的观测基线。"]
    if (target.id, target.source) != (report.host_id, report.source):
        raise ValueError("Registered target scope does not match the report")
    if (
        not _SHA256.fullmatch(report.scope_hash)
        or diagnostic_scope_for(target) != report.scope_hash
    ):
        raise ValueError("Report scope hash does not match its registered target")
    if target.source == "ssh" and not target.trusted_hosts_digest:
        return {}, {}, ["SSH 目标缺少已核验主机记录摘要，不能建立身份绑定的观测基线。"]
    if len({item.id for item in target.health_checks}) != len(target.health_checks):
        raise ValueError("Duplicate registered health check identifiers")
    seen_checks: set[str] = set()
    seen_ids: set[str] = set()
    for evidence in report.evidence:
        if evidence.target != report.host_id or evidence.source != report.source:
            raise ValueError("Evidence scope does not match the report")
        if evidence.check_id in seen_checks or evidence.id in seen_ids:
            raise ValueError("Duplicate evidence identifiers cannot define a baseline")
        seen_checks.add(evidence.check_id)
        seen_ids.add(evidence.id)
        if evidence.check_id not in _SUPPORTED_CHECKS and not _HTTP_CHECK.fullmatch(
            evidence.check_id
        ):
            continue
        if evidence.status != "ok" or evidence.exit_code != 0 or evidence.truncated:
            missing.append(f"检查 {evidence.check_id} 未成功完整取得，未将其保存为已知旧值。")
            continue
        if len(evidence.output.encode("utf-8")) > _MAX_OUTPUT:
            missing.append(f"检查 {evidence.check_id} 超过快照输出预算，未提取字段。")
            continue
        extracted, gaps = _extract(evidence, target, report.verification)
        features.update(extracted)
        references.update({field: [evidence.id] for field in extracted})
        missing.extend(gaps)
    if not features:
        missing.append("没有可提取的完整观测字段；原始日志不会作为基线保存。")
    if target.disk_reclaim_scope_digest is not None and "disk_reclaim" not in seen_checks:
        missing.append("未采集已登记范围的磁盘元数据，不能以零占用替代。")
    return features, references, list(dict.fromkeys(missing))


def compare(report: Report, baseline: BaselineInfo | None) -> BaselineComparison:
    """Compare observations without asserting causality, recovery or restore ability."""
    if baseline is None:
        return BaselineComparison(missing=["尚未为该来源、目标与场景保存观测基线。"])
    if (report.source, report.host_id, report.scenario) != (
        baseline.source,
        baseline.host_id,
        baseline.scenario,
    ):
        raise ValueError("A baseline cannot cross source, host or scenario boundaries")
    if baseline.schema_version != _SCHEMA_VERSION:
        return BaselineComparison(
            baseline_id=baseline.id,
            baseline_report_id=baseline.report_id,
            baseline_created_at=baseline.created_at,
            status="incomplete",
            missing=["该观测基线缺少当前字段算法版本，停止比较；请从新调查保存基线。"],
        )
    if not report.scope_hash or not _SHA256.fullmatch(report.scope_hash):
        return BaselineComparison(
            baseline_id=baseline.id,
            baseline_report_id=baseline.report_id,
            baseline_created_at=baseline.created_at,
            status="incomplete",
            missing=["当前报告缺少有效的目标范围摘要，停止比较。"],
        )
    if report.scope_hash != baseline.scope_hash:
        return BaselineComparison(
            baseline_id=baseline.id,
            baseline_report_id=baseline.report_id,
            baseline_created_at=baseline.created_at,
            status="scope_changed",
            missing=["登记目标或检查范围已经变化，不能沿用旧观测范围进行比较。"],
        )
    try:
        features, references, missing = snapshot(report)
        current_disk = validate_allocation_features(features)
        baseline_disk = validate_allocation_features(baseline.features)
    except DiskAllocationRejected:
        report.ai_egress_block_reason = "unclassified_payload"
        return BaselineComparison(
            baseline_id=baseline.id,
            baseline_report_id=baseline.report_id,
            baseline_created_at=baseline.created_at,
            status="incomplete",
            missing=["磁盘聚合指标或证据未通过完整白名单与一致性核验，整份对照已拒绝。"],
        )
    prior = dict(baseline.features)
    if current_disk and baseline_disk:
        groups = {key for key in {*features, *prior} if allocation_group(key) is not None}
        disk_refs = references["disk_scope.total.allocated_bytes"]
        for key in groups:
            # Zero is justified only by two complete same-scope scans, never missing evidence.
            features.setdefault(key, "0")
            prior.setdefault(key, "0")
            references.setdefault(key, disk_refs)
    missing.extend(baseline.missing)
    for key in sorted(set(prior) - set(features)):
        missing.append(f"当前未完整取得字段 {key}，不能以空值或零代替。")
    for key in sorted(set(features) - set(prior)):
        missing.append(f"基线未保存字段 {key}，无法建立该字段的前后对照。")
    changes = [
        BaselineChange(
            field=key,
            before=prior[key],
            after=features[key],
            evidence_ids=references[key],
        )
        for key in sorted(set(features) & set(prior))
        if features[key] != prior[key]
    ]
    incomplete = bool(missing)
    if current_disk or baseline_disk:
        missing.append(
            "磁盘分配块差异仅覆盖同一登记范围的非原子快照，按类别和目录引用组合聚合；"
            "全局、类别和组合是同一占用的不同汇总层次，不能再相加。"
            "对象引用随 ctime 变化，不连续追踪单文件，不证明增长因果或可清理量；业务数据排除清理。"
        )
    if report.source == "replay":
        missing.append("回放仅展示合成样本之间的差异，不代表真实服务器变化或增长。")
    return BaselineComparison(
        baseline_id=baseline.id,
        baseline_report_id=baseline.report_id,
        baseline_created_at=baseline.created_at,
        status="incomplete" if incomplete else "compared",
        changes=changes,
        missing=list(dict.fromkeys(missing)),
    )


compare_report = compare


class BaselineStore:
    """Keep each selected metadata snapshot immutable in its own SQLite database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS baselines (
                    id TEXT PRIMARY KEY, report_id TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL, host_id TEXT NOT NULL, scenario TEXT NOT NULL,
                    created_at TEXT NOT NULL, payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS baselines_scope_time "
                "ON baselines(source, host_id, scenario, created_at DESC)"
            )
        path.chmod(0o600)

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, report: Report) -> BaselineInfo:
        validate_disk_comparison(report)
        if not _SHA256.fullmatch(report.scope_hash):
            raise ValueError("A report without a scope hash cannot define a baseline")
        features, references, missing = snapshot(report)
        if not features:
            raise ValueError("The report has no complete interpretable observation metadata")
        result = BaselineInfo(
            id=str(uuid4()),
            report_id=report.id,
            host_id=report.host_id,
            source=report.source,
            scenario=report.scenario,
            created_at=datetime.now(UTC),
            scope_hash=report.scope_hash,
            features=features,
            references=references,
            missing=missing,
            schema_version=_SCHEMA_VERSION,
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT payload FROM baselines WHERE report_id = ?", (report.id,)
            ).fetchone()
            if prior is not None:
                existing = BaselineInfo.model_validate_json(prior["payload"])
                immutable = (
                    "report_id",
                    "host_id",
                    "source",
                    "scenario",
                    "scope_hash",
                    "features",
                    "references",
                    "missing",
                    "schema_version",
                )
                if any(getattr(existing, field) != getattr(result, field) for field in immutable):
                    raise ValueError("An existing report baseline cannot be replaced")
                return existing
            connection.execute(
                "INSERT INTO baselines "
                "(id, report_id, source, host_id, scenario, created_at, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    result.id,
                    result.report_id,
                    result.source,
                    result.host_id,
                    result.scenario,
                    result.created_at.isoformat(),
                    result.model_dump_json(),
                ),
            )
        return result

    def latest(self, source: Source, host_id: str, scenario: Scenario) -> BaselineInfo | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM baselines WHERE source = ? AND host_id = ? AND scenario = ? "
                "ORDER BY created_at DESC, id DESC LIMIT 1",
                (source, host_id, scenario),
            ).fetchone()
        return None if row is None else BaselineInfo.model_validate_json(row["payload"])

    def for_report(self, report_id: str) -> BaselineInfo | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM baselines WHERE report_id = ?", (report_id,)
            ).fetchone()
        return None if row is None else BaselineInfo.model_validate_json(row["payload"])

    def list(self) -> list[dict[str, object]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM baselines ORDER BY created_at DESC, id DESC LIMIT 100"
            ).fetchall()
        fields = {
            "id",
            "report_id",
            "host_id",
            "source",
            "scenario",
            "created_at",
            "scope_hash",
            "purpose",
            "restore_capable",
            "schema_version",
        }
        return [
            BaselineInfo.model_validate_json(row["payload"]).model_dump(mode="json", include=fields)
            for row in rows
        ]
