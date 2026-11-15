"""Read only one authorized project's explicit Docker metadata.

Labels identify candidates, not a verified Nginx dependency. Environment, command,
mount, log and Compose file contents are never requested. No model is called.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Literal, TypedDict

import paramiko
from pydantic import ConfigDict, Field

from opsark.collector import (
    COLLECTION_TIMEOUT,
    COMMAND_TIMEOUT,
    _connect_registered,
    commands_for_preflight,
    run_check,
)
from opsark.config import COMPOSE_PROJECT, IDENTIFIER, HostConfig
from opsark.host_preflight import _capability
from opsark.models import CheckResult, StrictModel
from opsark.platforms import assess, os_identity, required_tools

MAX_CONTAINERS = 64
MAX_PORTS = 128
MAX_TOTAL_PORTS = 256
MAX_BYTES = 16_384
MAX_RESPONSE_BYTES = 65_536
PROJECT = COMPOSE_PROJECT
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}\Z")
STATES = frozenset({"created", "running", "paused", "restarting", "removing", "exited", "dead"})
FORMAT = (
    '{"id":{{json .ID}},"name":{{json .Names}},"state":{{json .State}},'
    '"project":{{json (.Label "com.docker.compose.project")}},'
    '"service":{{json (.Label "com.docker.compose.service")}},"ports":{{json .Ports}}}'
)

type DiscoveryReason = Literal[
    "connection_failed",
    "platform_unavailable",
    "compose_unavailable",
    "engine_unavailable",
    "inventory_unavailable",
    "inventory_truncated",
    "inventory_invalid",
    "inventory_limit",
    "no_label_candidates",
]


class DiscoveryRefused(ValueError):
    """Fixed reason only; submitted metadata never enters exception text."""


class _Common(TypedDict):
    host_id: str
    project: str
    collected_at: datetime
    duration_ms: int


class _Output(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PublishedPort(_Output):
    host_ip: str
    host_port: int = Field(ge=1, le=65535)
    container_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp", "sctp"]


class ComposeCandidate(_Output):
    candidate_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_name: str
    service_name: str
    state: Literal["created", "running", "paused", "restarting", "removing", "exited", "dead"]
    published_ports: list[PublishedPort] = Field(max_length=MAX_PORTS)
    service_instances: int = Field(ge=1, le=MAX_CONTAINERS)
    registration_supported: bool


class ComposeDiscovery(_Output):
    host_id: str
    project: str
    status: Literal["candidates", "empty", "unavailable"]
    reason: DiscoveryReason | None = None
    candidates: list[ComposeCandidate] = Field(default_factory=list, max_length=MAX_CONTAINERS)
    snapshot_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    collected_at: datetime
    duration_ms: int = Field(ge=0)
    scope: Literal["one_authorized_compose_project"] = "one_authorized_compose_project"
    evidence_kind: Literal["observed_compose_labels_and_published_ports"] = (
        "observed_compose_labels_and_published_ports"
    )
    nginx_dependency: Literal["unverified"] = "unverified"
    actions_enabled: Literal[False] = False


class ComposeSelection(_Output):
    candidate_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    host_port: int = Field(ge=1, le=65535)


class ComposeRegistrationPreview(_Output):
    host_id: str
    candidate_id: str
    snapshot_digest: str
    inventory_fragment: str
    nginx_dependency: Literal["unverified"] = "unverified"
    actions_enabled: Literal[False] = False


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _project(value: str) -> str:
    if type(value) is not str or PROJECT.fullmatch(value) is None:
        raise DiscoveryRefused("The authorized Compose project is invalid.")
    return value


def commands_for_compose_discovery(host: HostConfig, project: str) -> dict[str, str]:
    """Project is deployment-owned; an API caller cannot supply Docker arguments."""
    project = _project(project)
    probes = commands_for_preflight(host)
    # Reuse the exact registered local socket and cleared Docker transport flags.
    docker = probes["compose_version"].removesuffix(" compose version --short")
    return {
        key: probes[key]
        for key in ("os_release", "platform_tools", "compose_version", "docker_rootful")
    } | {
        "compose_inventory": (
            docker
            + " container ls --all --no-trunc --filter "
            + shlex.quote("label=com.docker.compose.project=" + project)
            + " --format "
            + shlex.quote(FORMAT)
        )
    }


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values = dict(pairs)
    if len(values) != len(pairs):
        raise DiscoveryRefused("inventory_invalid")
    return values


def _constant(_value: str) -> None:
    raise DiscoveryRefused("inventory_invalid")


def _range(value: str) -> range:
    if re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", value) is None:
        raise DiscoveryRefused("inventory_invalid")
    parts = value.split("-")
    first, last = int(parts[0]), int(parts[-1])
    if not 1 <= first <= last <= 65535 or last - first >= MAX_PORTS:
        raise DiscoveryRefused("inventory_invalid")
    return range(first, last + 1)


def _ports(raw: str) -> list[PublishedPort]:
    if not raw:
        return []
    if len(raw) > 8192:
        raise DiscoveryRefused("inventory_limit")
    values: dict[tuple[str, int, int, str], PublishedPort] = {}
    for item in raw.split(", "):
        mapping, separator, protocol = item.rpartition("/")
        if not separator or protocol not in {"tcp", "udp", "sctp"}:
            raise DiscoveryRefused("inventory_invalid")
        if "->" not in mapping:
            _range(mapping)  # Exposed container ports are not host-published mappings.
            continue
        if mapping.count("->") != 1:
            raise DiscoveryRefused("inventory_invalid")
        left, right = mapping.split("->")
        address, separator, host_ports = left.rpartition(":")
        if not separator or not address or "%" in address:
            raise DiscoveryRefused("inventory_invalid")
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise DiscoveryRefused("inventory_invalid") from None
        published, private = _range(host_ports), _range(right)
        if len(published) != len(private):
            raise DiscoveryRefused("inventory_invalid")
        for host_port, container_port in zip(published, private, strict=True):
            key = (address, host_port, container_port, protocol)
            if key in values or len(values) >= MAX_PORTS:
                raise DiscoveryRefused("inventory_invalid")
            values[key] = PublishedPort(
                host_ip=address,
                host_port=host_port,
                container_port=container_port,
                protocol=protocol,
            )
    return [values[key] for key in sorted(values)]


def _inventory(raw: str, project: str) -> list[dict]:
    if len(raw.encode("utf-8")) > MAX_BYTES or "\ufffd" in raw:
        raise DiscoveryRefused("inventory_limit")
    lines = raw.splitlines()
    if len(lines) > MAX_CONTAINERS:
        raise DiscoveryRefused("inventory_limit")
    rows, identities, names = [], set(), set()
    port_count = 0
    for line in lines:
        try:
            value = json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
        except (ValueError, RecursionError):
            raise DiscoveryRefused("inventory_invalid") from None
        if type(value) is not dict or set(value) != {
            "id",
            "name",
            "state",
            "project",
            "service",
            "ports",
        }:
            raise DiscoveryRefused("inventory_invalid")
        if not all(type(item) is str for item in value.values()):
            raise DiscoveryRefused("inventory_invalid")
        if (
            re.fullmatch(r"[0-9a-f]{64}", value["id"]) is None
            or NAME.fullmatch(value["name"]) is None
            or IDENTIFIER.fullmatch(value["service"]) is None
            or value["project"] != project
            or value["state"] not in STATES
            or value["id"] in identities
            or value["name"] in names
        ):
            raise DiscoveryRefused("inventory_invalid")
        identities.add(value["id"])
        names.add(value["name"])
        ports = _ports(value["ports"])
        port_count += len(ports)
        if port_count > MAX_TOTAL_PORTS:
            raise DiscoveryRefused("inventory_limit")
        rows.append(value | {"ports": ports})
    return sorted(rows, key=lambda row: (row["service"], row["name"], row["id"]))


def project_compose_discovery(
    host: HostConfig,
    project: str,
    check: CheckResult,
    *,
    collected_at: datetime,
    duration_ms: int,
) -> ComposeDiscovery:
    project = _project(project)
    common: _Common = {
        "host_id": host.public.id,
        "project": project,
        "collected_at": collected_at,
        "duration_ms": duration_ms,
    }
    reason: DiscoveryReason | None = None
    if (
        check.name != "compose_inventory"
        or check.status != "ok"
        or check.exit_code != 0
        or check.stderr.strip()
    ):
        reason = "inventory_unavailable"
    elif check.truncated:
        reason = "inventory_truncated"
    if reason:
        return ComposeDiscovery(**common, status="unavailable", reason=reason)
    try:
        rows = _inventory(check.stdout, project)
    except DiscoveryRefused as error:
        reason = "inventory_limit" if str(error) == "inventory_limit" else "inventory_invalid"
        return ComposeDiscovery(**common, status="unavailable", reason=reason)
    instances = Counter(row["service"] for row in rows)
    candidates, snapshots = [], []
    for row in rows:
        snapshot = row | {"ports": [item.model_dump() for item in row["ports"]]}
        snapshots.append(snapshot)
        candidates.append(
            ComposeCandidate(
                candidate_id=_digest({"project": project, **snapshot}),
                container_name=row["name"],
                service_name=row["service"],
                state=row["state"],
                published_ports=row["ports"],
                service_instances=instances[row["service"]],
                registration_supported=(
                    IDENTIFIER.fullmatch(row["name"]) is not None
                    and any(port.protocol == "tcp" for port in row["ports"])
                ),
            )
        )
    binding = {
        "host": host.public.id,
        "address": host.public.address,
        "port": host.public.port,
        "username": host.public.username,
        "trust": host.public.trusted_hosts_digest,
        "project": project,
        "container_binding_confirmed": host.container_binding_confirmed,
        "registered_container": host.public.container_name
        if host.container_binding_confirmed
        else None,
        "registered_port": host.public.expected_upstream_port
        if host.container_binding_confirmed
        else None,
        "containers": snapshots,
    }
    result = ComposeDiscovery(
        **common,
        status="candidates" if rows else "empty",
        reason=None if rows else "no_label_candidates",
        candidates=candidates,
        snapshot_digest=_digest(binding),
    )
    if len(result.model_dump_json().encode("utf-8")) > MAX_RESPONSE_BYTES:
        return ComposeDiscovery(**common, status="unavailable", reason="inventory_limit")
    return result


def preview_compose_registration(
    current: ComposeDiscovery,
    selection: ComposeSelection,
) -> ComposeRegistrationPreview:
    """Call only with a freshly collected result; never persist or execute a choice."""
    if (
        current.status != "candidates"
        or current.snapshot_digest != selection.snapshot_digest
        or not current.snapshot_digest
    ):
        raise DiscoveryRefused("The selection no longer matches current discovery evidence.")
    selected = [item for item in current.candidates if item.candidate_id == selection.candidate_id]
    if len(selected) != 1 or not selected[0].registration_supported:
        raise DiscoveryRefused("The selected candidate is not available for registration.")
    candidate = selected[0]
    if selection.host_port not in {
        port.host_port for port in candidate.published_ports if port.protocol == "tcp"
    }:
        raise DiscoveryRefused("The selected TCP port is not in current discovery evidence.")
    fragment = (
        "compose_project = "
        + json.dumps(current.project)
        + "\n"
        + "container_name = "
        + json.dumps(candidate.container_name)
        + "\n"
        + "container_binding_confirmed = true\n"
        + "expected_upstream_port = "
        + str(selection.host_port)
        + "\n"
    )
    return ComposeRegistrationPreview(
        host_id=current.host_id,
        candidate_id=candidate.candidate_id,
        snapshot_digest=current.snapshot_digest,
        inventory_fragment=fragment,
    )


def run_compose_discovery(host: HostConfig, project: str) -> ComposeDiscovery:
    """One pinned connection; do not enumerate after a failed platform/capability probe."""
    commands = commands_for_compose_discovery(host, project)
    started_at, started = datetime.now(UTC), time.monotonic()
    client = paramiko.SSHClient()
    checks: list[CheckResult] = []
    reason: DiscoveryReason | None = None
    inventory = None
    try:
        if host.public.source != "ssh":
            raise DiscoveryRefused("connection_failed")
        _connect_registered(client, host)
        for name, command in commands.items():
            if name not in {"os_release", "platform_tools"}:
                tools = set(required_tools(name)) | {"env", "docker"}
                if not tools <= set(assess(checks).available_tools):
                    reason = "platform_unavailable"
                    break
            remaining = COLLECTION_TIMEOUT - (time.monotonic() - started)
            if remaining <= 0:
                reason = "inventory_unavailable"
                break
            result = run_check(client, name, command, min(COMMAND_TIMEOUT, remaining))
            checks.append(result)
            if (
                name in {"os_release", "platform_tools"}
                and (result.stderr.strip() or "\ufffd" in result.stdout)
                or name == "os_release"
                and os_identity(result)[0] not in {"ubuntu", "debian"}
                or name == "platform_tools"
                and assess(checks).status != "compatible"
            ):
                reason = "platform_unavailable"
            elif name in {"compose_version", "docker_rootful"} and _capability(result)[0] != "ok":
                reason = (
                    "compose_unavailable" if name == "compose_version" else "engine_unavailable"
                )
            elif name == "compose_inventory":
                inventory = result
            if reason:
                break
    except (OSError, ValueError, paramiko.SSHException):
        reason = "connection_failed"
    finally:
        client.close()
    duration = round((time.monotonic() - started) * 1000)
    if reason or inventory is None:
        return ComposeDiscovery(
            host_id=host.public.id,
            project=project,
            status="unavailable",
            reason=reason or "inventory_unavailable",
            collected_at=started_at,
            duration_ms=duration,
        )
    return project_compose_discovery(
        host,
        project,
        inventory,
        collected_at=started_at,
        duration_ms=duration,
    )
