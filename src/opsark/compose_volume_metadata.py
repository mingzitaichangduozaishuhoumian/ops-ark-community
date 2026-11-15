"""Collect one registered Compose project's named-volume attachment metadata."""

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Literal, Never, Self

from pydantic import ConfigDict, Field, model_validator

from opsark.ai_egress import guard_source
from opsark.collector import collect_registered_receipts
from opsark.config import HostConfig, Settings, compose_volume_scope_sha256
from opsark.models import CheckResult, StrictModel

CHECK = "compose_volume_metadata"
COMMAND = "timeout -k 1s 5s /usr/local/libexec/opsark-compose-volume-metadata"
MAX_OUTPUT = 14_000
HASH = r"^[0-9a-f]{64}$"
ALIAS = r"^[0-9a-f]{32}$"

type Reason = Literal[
    "scope_invalid",
    "scope_unavailable",
    "collection_unavailable",
    "collection_timeout",
    "metadata_invalid",
    "metadata_limit",
    "evidence_changed",
]


class Closed(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ServiceAttachment(Closed):
    service_ref: str = Field(pattern=ALIAS)
    container_count: int = Field(ge=1, le=32)


class VolumeAttachment(Closed):
    volume_ref: str = Field(pattern=ALIAS)
    sharing: Literal["shared_across_services", "one_service"]
    services: list[ServiceAttachment] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_services(self) -> Self:
        refs = [row.service_ref for row in self.services]
        if refs != sorted(set(refs)) or (self.sharing == "shared_across_services") != (
            len(refs) > 1
        ):
            raise ValueError("Volume service observation rejected")
        return self


class VolumeProjection(Closed):
    schema_version: Literal["opsark-compose-volume-metadata/v1"] = Field(alias="schema")
    status: Literal["observed", "unavailable"]
    reason: Reason | None
    scope_digest: str | None = Field(pattern=HASH)
    snapshot_digest: str | None = Field(pattern=HASH)
    observed_containers: int = Field(ge=0, le=32)
    coverage: Literal["compose_labeled_local_named_volumes", "unavailable"]
    mount_mode: Literal["unknown"]
    volumes: list[VolumeAttachment] = Field(max_length=16)
    actions_enabled: Literal[False]
    model_calls: Literal[0]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.status == "unavailable":
            if (
                self.reason is None
                or self.scope_digest is not None
                or self.snapshot_digest is not None
                or self.observed_containers
                or self.volumes
                or self.coverage != "unavailable"
            ):
                raise ValueError("Partial volume observation rejected")
            return self
        if (
            self.reason is not None
            or self.scope_digest is None
            or self.snapshot_digest is None
            or self.coverage != "compose_labeled_local_named_volumes"
        ):
            raise ValueError("Volume observation identity rejected")
        refs = [row.volume_ref for row in self.volumes]
        service_counts: dict[str, int] = {}
        for volume in self.volumes:
            for service in volume.services:
                service_counts[service.service_ref] = max(
                    service_counts.get(service.service_ref, 0), service.container_count
                )
        if (
            refs != sorted(set(refs))
            or set(service_counts).intersection(refs)
            or sum(service_counts.values()) > self.observed_containers
        ):
            raise ValueError("Volume observation coverage rejected")
        return self


class ComposeVolumeObservation(VolumeProjection):
    host_id: str
    binding_digest: str | None = Field(pattern=HASH)
    collected_at: datetime
    duration_ms: int = Field(ge=0)


def _digest(value):
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256((payload + "\n").encode("ascii")).hexdigest()


def binding_digest(host: HostConfig) -> str | None:
    if (
        host.public.source != "ssh"
        or host.public.username != "opsark-readonly"
        or host.public.trusted_hosts_digest is None
        or host.compose_volume_scope_digest is None
        or host.compose_project is None
        or host.compose_volume_scope_digest != compose_volume_scope_sha256(host.compose_project)
    ):
        return None
    return _digest(
        {
            "scope": host.compose_volume_scope_digest,
            "project": host.compose_project,
            "host": host.public.id,
            "address": host.public.address,
            "port": host.public.port,
            "trust": host.public.trusted_hosts_digest,
        }
    )


def collection_command(host: HostConfig) -> str:
    if binding_digest(host) is None:
        raise ValueError("Compose volume scope is not registered")
    return COMMAND


def _reject(_=None) -> Never:
    raise ValueError("Compose volume projection rejected")


def _unique(rows):
    value = dict(rows)
    if len(value) != len(rows):
        _reject()
    return value


def parse_projection(check: CheckResult, host: HostConfig, settings: Settings) -> VolumeProjection:
    if (
        binding_digest(host) is None
        or check.name != CHECK
        or check.status != "ok"
        or check.exit_code != 0
        or check.truncated
        or check.stderr
        or not 0 < len(check.stdout.encode("utf-8")) <= MAX_OUTPUT
    ):
        _reject()
    value = json.loads(check.stdout, object_pairs_hook=_unique, parse_constant=_reject)
    guard_source(value, settings)
    if (
        type(value) is not dict
        or value.get("actions_enabled") is not False
        or type(value.get("model_calls")) is not int
        or value["model_calls"] != 0
    ):
        _reject()
    result = VolumeProjection.model_validate(value)
    if result.status == "observed":
        content = {key: item for key, item in value.items() if key != "snapshot_digest"}
        if (
            result.scope_digest != host.compose_volume_scope_digest
            or result.snapshot_digest != _digest(content)
        ):
            _reject()
    return result


def run_compose_volume_metadata(host: HostConfig, settings: Settings) -> ComposeVolumeObservation:
    started, when = time.monotonic(), datetime.now(UTC)
    command = collection_command(host)
    try:
        # The extra byte lets the transport observe EOF after an exactly full valid receipt.
        checks = collect_registered_receipts(host, {CHECK: command}, output_limit=MAX_OUTPUT + 1)
        check = checks.get(CHECK)
        if check is None:
            _reject()
        result = parse_projection(check, host, settings)
    except (ValueError, OSError, RecursionError):
        result = VolumeProjection(
            schema="opsark-compose-volume-metadata/v1",
            status="unavailable",
            reason="collection_unavailable",
            scope_digest=None,
            snapshot_digest=None,
            observed_containers=0,
            coverage="unavailable",
            mount_mode="unknown",
            volumes=[],
            actions_enabled=False,
            model_calls=0,
        )
    return ComposeVolumeObservation.model_validate(
        {
            **result.model_dump(by_alias=True),
            "host_id": host.public.id,
            "binding_digest": binding_digest(host) if result.status == "observed" else None,
            "collected_at": when,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    )
