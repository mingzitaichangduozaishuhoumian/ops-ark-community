"""Read-only disk dependency evidence; no raw configuration or model transport."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Literal

import paramiko
from pydantic import AwareDatetime, ConfigDict, Field, ValidationError, model_validator

from opsark.ai_egress import AIEgressBlocked, guard_source
from opsark.business_readiness import BusinessReadiness, business_profile_digest
from opsark.collector import (
    COLLECTION_TIMEOUT,
    COMMAND_TIMEOUT,
    _connect_registered,
    nginx_dependencies_command,
    run_check,
)
from opsark.compose_discovery import (
    PublishedPort,
    _inventory,
    _pairs,
    commands_for_compose_discovery,
    project_compose_discovery,
)
from opsark.config import HostConfig, Settings
from opsark.host_preflight import _capability
from opsark.models import CheckResult, StrictModel
from opsark.platforms import assess, os_identity, required_tools

HASH = r"^[0-9a-f]{64}$"
FILE = r"^/etc/nginx/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$"
DOMAIN = r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
REASONS = frozenset(
    {
        "scope_invalid",
        "scope_unavailable",
        "path_untrusted",
        "configuration_unavailable",
        "configuration_limit",
        "configuration_invalid",
        "configuration_unsupported",
        "configuration_ambiguous",
        "configuration_changed",
        "include_unavailable",
        "include_ambiguous",
        "content_blocked",
        "collection_timeout",
    }
)
SERVER_REASONS = Literal[
    "domain_unsupported",
    "listen_unsupported",
    "routing_unsupported",
    "server_incomplete",
    "duplicate_virtual_host",
]


class Closed(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvidenceFile(Closed):
    path: str = Field(pattern=FILE, max_length=256)
    sha256: str = Field(pattern=HASH)


class Endpoint(Closed):
    ip: str = Field(max_length=45)
    port: int = Field(ge=1, le=65535)


class DiskRoute(Closed):
    file: str = Field(pattern=FILE, max_length=256)
    line: int = Field(ge=1, le=131072)
    endpoints: list[Endpoint] = Field(max_length=64)
    reason: Literal["routing_unsupported"] | None


class DiskServer(Closed):
    server_id: str = Field(pattern=HASH)
    file: str = Field(pattern=FILE, max_length=256)
    line: int = Field(ge=1, le=131072)
    domains: list[str] = Field(max_length=32)
    listens: list[Endpoint] = Field(max_length=16)
    routes: list[DiskRoute] = Field(max_length=32)
    reasons: list[SERVER_REASONS] = Field(max_length=5)


class DiskProjection(Closed):
    schema_: Literal["opsark-nginx-disk-dependencies/v1"] = Field(alias="schema")
    scope_digest: str = Field(pattern=HASH)
    project: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    disk_configuration: Literal["observed"]
    loaded_generation: Literal["unknown"]
    files: list[EvidenceFile] = Field(max_length=32)
    servers: list[DiskServer] = Field(max_length=32)
    actions_enabled: Literal[False]
    snapshot_digest: str = Field(pattern=HASH)


class Relationship(Closed):
    server_id: str
    domains: list[str]
    file: str
    line: int
    endpoint: Endpoint | None
    binding: Literal["unique", "unmatched", "ambiguous", "unsupported"]
    candidate_id: str | None = None
    service_name: str | None = None
    container_name: str | None = None
    container_state: str | None = None


class SharedDependency(Closed):
    kind: Literal["upstream", "compose_service"]
    resource_ref: str
    server_ids: list[str]
    domains: list[str]


class NginxDependencies(Closed):
    host_id: str
    status: Literal["observed", "unavailable"]
    reason: Literal["collection_unavailable", "evidence_changed"] | None = None
    scope_digest: str | None = None
    binding_digest: str | None = None
    snapshot_digest: str | None = None
    compose_snapshot_digest: str | None = None
    collected_at: datetime
    duration_ms: int
    files: list[EvidenceFile] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    shared_dependencies: list[SharedDependency] = Field(default_factory=list)
    disk_configuration: Literal["observed", "unavailable"] = "unavailable"
    loaded_generation: Literal["unknown"] = "unknown"
    actions_enabled: Literal[False] = False
    model_calls: Literal[0] = 0


class NginxPathObservation(BusinessReadiness):
    binding_digest: str = Field(pattern=HASH)
    observed_at: datetime


type ImpactReason = Literal[
    "collection_unavailable", "evidence_changed", "container_not_observed", "ambiguous_binding"
]


class ContainerImpactSite(Closed):
    domain: str = Field(pattern=DOMAIN)
    file: str = Field(pattern=FILE, max_length=256)
    line: int = Field(ge=1, le=131072)


class ContainerRestartImpact(Closed):
    status: Literal["observed", "unavailable"]
    reason: ImpactReason | None = None
    observed_at: AwareDatetime | None = None
    loaded_generation: Literal["unknown"] = "unknown"
    sites: list[ContainerImpactSite] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def check_evidence(self) -> ContainerRestartImpact:
        if self.status == "observed":
            if self.reason is not None or self.observed_at is None:
                raise ValueError("Observation requires a timestamp and no refusal reason")
        elif self.reason is None or self.observed_at is not None or self.sites:
            raise ValueError("Unavailable observation cannot include evidence")
        return self


class _DependencyEvidenceChanged(ValueError):
    pass


_COLLECTION_ERRORS = (ValueError, OSError, paramiko.SSHException, EOFError)


def _digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    ).hexdigest()


def _refused():
    raise ValueError("Dependency projection rejected")


def dependency_binding_digest(host: HostConfig) -> str | None:
    """Public opaque identity for registered scope/project/SSH target; no secret material."""
    if host.nginx_scope_digest is None or host.compose_project is None:
        return None
    return _digest(
        {
            "scope": host.nginx_scope_digest,
            "project": host.compose_project,
            "host": host.public.id,
            "address": host.public.address,
            "port": host.public.port,
            "username": host.public.username,
            "trust": host.public.trusted_hosts_digest,
        }
    )


def path_observation_binding_digest(host: HostConfig) -> str | None:
    scope = dependency_binding_digest(host)
    if (
        scope is None
        or host.public.trusted_hosts_digest is None
        or not any(check.read_only_confirmed for check in host.business_checks)
    ):
        return None
    return _digest({"nginx_path_observation": scope, "business": business_profile_digest(host)})


def parse_projection(check: CheckResult, host: HostConfig, settings: Settings) -> DiskProjection:
    if (
        check.name != "nginx_dependencies"
        or check.status != "ok"
        or check.exit_code != 0
        or check.truncated
        or check.stderr.strip()
        or not 0 < len(check.stdout.encode("utf-8")) <= 14000
    ):
        _refused()
    try:
        value = json.loads(
            check.stdout, object_pairs_hook=_pairs, parse_constant=lambda _: _refused()
        )
        guard_source(value, settings)
        if type(value) is not dict or value.get("actions_enabled") is not False:
            _refused()
        result = DiskProjection.model_validate(value)
    except (ValueError, ValidationError, AIEgressBlocked, RecursionError):
        raise ValueError("Dependency projection rejected") from None
    payload = dict(value)
    payload.pop("snapshot_digest")
    if (
        result.scope_digest != host.nginx_scope_digest
        or result.project != host.compose_project
        or result.snapshot_digest != _digest(payload)
        or not result.files
    ):
        _refused()
    files = {item.path for item in result.files}
    if len(files) != len(result.files) or any(".." in item.split("/") for item in files):
        _refused()
    ids = set()
    for server in result.servers:
        if (
            server.server_id in ids
            or server.server_id != _digest([server.file, server.line])
            or server.file not in files
            or len(set(server.domains)) != len(server.domains)
            or len(set(server.reasons)) != len(server.reasons)
        ):
            _refused()
        ids.add(server.server_id)
        for domain in server.domains:
            if re.fullmatch(DOMAIN, domain) is None or ".." in domain:
                _refused()
        for listen in server.listens:
            ipaddress.ip_address(listen.ip)
        for route in server.routes:
            if route.file not in files or (server.reasons and route.reason is None):
                _refused()
            for point in route.endpoints:
                if not ipaddress.ip_address(point.ip).is_loopback:
                    _refused()
    return result


def _matches(ports: list[PublishedPort], point: Endpoint):
    family = ipaddress.ip_address(point.ip).version
    return any(
        port.protocol == "tcp"
        and port.host_port == point.port
        and (port.host_ip == point.ip or port.host_ip == ("0.0.0.0" if family == 4 else "::"))  # noqa: S104 -- compare only.
        for port in ports
    )


def project_dependencies(
    host: HostConfig, disk: DiskProjection, compose, *, collected_at: datetime, duration_ms: int
) -> NginxDependencies:
    if (
        compose.host_id != host.public.id
        or compose.project != host.compose_project
        or compose.status not in {"candidates", "empty"}
        or not compose.snapshot_digest
    ):
        _refused()
    edges = []
    resources = defaultdict(dict)
    for server in disk.servers:
        for route in server.routes:
            if route.reason is not None or server.reasons or not route.endpoints:
                edges.append(
                    Relationship(
                        server_id=server.server_id,
                        domains=server.domains,
                        file=route.file,
                        line=route.line,
                        endpoint=None,
                        binding="unsupported",
                    )
                )
                continue
            for point in route.endpoints:
                matches = [
                    item for item in compose.candidates if _matches(item.published_ports, point)
                ]
                candidate = matches[0] if len(matches) == 1 else None
                edges.append(
                    Relationship(
                        server_id=server.server_id,
                        domains=server.domains,
                        file=route.file,
                        line=route.line,
                        endpoint=point,
                        binding="unique" if candidate else "ambiguous" if matches else "unmatched",
                        candidate_id=candidate.candidate_id if candidate else None,
                        service_name=candidate.service_name if candidate else None,
                        container_name=candidate.container_name if candidate else None,
                        container_state=candidate.state if candidate else None,
                    )
                )
                resources[("upstream", _digest(point.model_dump()))][server.server_id] = (
                    server.domains
                )
                if candidate:
                    resources[
                        ("compose_service", _digest([compose.project, candidate.service_name]))
                    ][server.server_id] = server.domains
    shared = [
        SharedDependency(
            kind=kind,
            resource_ref=ref,
            server_ids=sorted(servers),
            domains=sorted({domain for domains in servers.values() for domain in domains}),
        )
        for (kind, ref), servers in sorted(resources.items())
        if len(servers) > 1
    ]
    result = NginxDependencies(
        host_id=host.public.id,
        status="observed",
        scope_digest=disk.scope_digest,
        binding_digest=dependency_binding_digest(host),
        snapshot_digest=_digest(
            {
                "disk": disk.snapshot_digest,
                "compose": compose.snapshot_digest,
                "host": host.public.id,
                "address": host.public.address,
                "port": host.public.port,
                "trust": host.public.trusted_hosts_digest,
            }
        ),
        compose_snapshot_digest=compose.snapshot_digest,
        collected_at=collected_at,
        duration_ms=duration_ms,
        files=disk.files,
        relationships=edges,
        shared_dependencies=shared,
        disk_configuration="observed",
    )
    if len(result.model_dump_json().encode()) > 65536:
        _refused()
    return result


def _collect_dependencies(host: HostConfig, settings: Settings, project: str, started, when):
    commands = commands_for_compose_discovery(host, project)
    client = paramiko.SSHClient()
    try:
        _connect_registered(client, host)
        checks = []

        def check(name, command):
            left = COLLECTION_TIMEOUT - (time.monotonic() - started)
            if left <= 0:
                _refused()
            return run_check(client, name, command, min(COMMAND_TIMEOUT, left), require_eof=True)

        for key, command in commands.items():
            if key not in {"os_release", "platform_tools"} and not (
                set(required_tools(key)) | {"env", "docker"}
            ) <= set(assess(checks).available_tools):
                _refused()
            result = check(key, command)
            checks.append(result)
            if (
                key == "os_release"
                and os_identity(result)[0] not in {"ubuntu", "debian"}
                or key == "platform_tools"
                and assess(checks).status != "compatible"
                or key in {"compose_version", "docker_rootful"}
                and _capability(result)[0] != "ok"
            ):
                _refused()
        first = project_compose_discovery(
            host, project, checks[-1], collected_at=when, duration_ms=0
        )
        disk = parse_projection(
            check("nginx_dependencies", nginx_dependencies_command(host)), host, settings
        )
        last_check = check("compose_inventory", commands["compose_inventory"])
        last = project_compose_discovery(
            host, project, last_check, collected_at=when, duration_ms=0
        )
        if first.snapshot_digest != last.snapshot_digest or first.status != last.status:
            raise _DependencyEvidenceChanged
        return disk, last, last_check
    finally:
        try:
            client.close()
        except _COLLECTION_ERRORS:
            _refused()


def run_nginx_dependencies(host: HostConfig, settings: Settings) -> NginxDependencies:
    started, when = time.monotonic(), datetime.now(UTC)
    project = host.compose_project
    if host.public.source != "ssh" or host.nginx_scope_digest is None or project is None:
        raise ValueError("Dependency scope is not registered")
    try:
        disk, last, _ = _collect_dependencies(host, settings, project, started, when)
        value = project_dependencies(
            host,
            disk,
            last,
            collected_at=when,
            duration_ms=round((time.monotonic() - started) * 1000),
        )
        guard_source(value.model_dump(mode="json"), settings)
        return value
    except _COLLECTION_ERRORS as error:
        return NginxDependencies(
            host_id=host.public.id,
            status="unavailable",
            reason="evidence_changed"
            if isinstance(error, _DependencyEvidenceChanged)
            else "collection_unavailable",
            collected_at=when,
            duration_ms=round((time.monotonic() - started) * 1000),
        )


def run_container_restart_impact(
    host: HostConfig, settings: Settings, container_id: str
) -> ContainerRestartImpact:
    """Find supported disk routes for the original full container ID in one stable window."""
    project = host.compose_project
    if (
        type(container_id) is not str
        or re.fullmatch(HASH, container_id) is None
        or host.public.source != "ssh"
        or host.public.trusted_hosts_digest is None
        or host.nginx_scope_digest is None
        or project is None
        or not host.container_binding_confirmed
    ):
        return ContainerRestartImpact(status="unavailable", reason="collection_unavailable")
    started, when = time.monotonic(), datetime.now(UTC)
    try:
        disk, last, last_check = _collect_dependencies(host, settings, project, started, when)
        if last.snapshot_digest is None:
            _refused()
        # The stock snapshot digest covers exact IDs and all normalized rows. Parsing the
        # checked last response here keeps those identities out of the public DTO.
        rows = _inventory(last_check.stdout, project)
        target = next((row for row in rows if row["id"] == container_id), None)
        if (
            target is None
            or target["name"] != host.public.container_name
            or target["state"] != "running"
        ):
            return ContainerRestartImpact(status="unavailable", reason="container_not_observed")

        locations = set()
        for server in disk.servers:
            for route in server.routes:
                if server.reasons or route.reason is not None:
                    continue
                for point in route.endpoints:
                    if not _matches(target["ports"], point):
                        continue
                    if any(row is not target and _matches(row["ports"], point) for row in rows):
                        return ContainerRestartImpact(
                            status="unavailable", reason="ambiguous_binding"
                        )
                    locations.update((domain, route.file, route.line) for domain in server.domains)
                    if len(locations) > 128:
                        _refused()
        result = ContainerRestartImpact(
            status="observed",
            observed_at=when,
            sites=[
                ContainerImpactSite(domain=domain, file=file, line=line)
                for domain, file, line in sorted(locations)
            ],
        )
        guard_source(result.model_dump(mode="json"), settings)
        return result
    except _DependencyEvidenceChanged:
        return ContainerRestartImpact(status="unavailable", reason="evidence_changed")
    except _COLLECTION_ERRORS:
        return ContainerRestartImpact(status="unavailable", reason="collection_unavailable")
