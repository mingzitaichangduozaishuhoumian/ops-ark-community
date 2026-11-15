"""Compare private equality markers from an explicitly enrolled Compose target."""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Annotated, Literal, Never

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

from opsark.baselines import diagnostic_scope_for
from opsark.collector import collect_registered_receipts
from opsark.config import COMPOSE_PROJECT, IDENTIFIER, HostConfig, compose_generation_scope_sha256
from opsark.models import CheckResult

CHECK = "compose_generation"
COMMAND = "timeout -k 1s 5s /usr/local/libexec/opsark-compose-generation"
MAX_OUTPUT = 1024
_Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Change = Literal["unchanged", "changed", "unavailable"]


class GenerationUnavailable(ValueError):
    """Neither transport output nor a Docker label belongs in this exception."""


class _Closed(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", hide_input_in_errors=True)


class _Witness(_Closed):
    """Internal-only identity and equality markers. Keep them out of reports and APIs."""

    binding: _Digest = Field(exclude=True, repr=False)
    key_epoch: _Digest = Field(exclude=True, repr=False)
    container: _Digest = Field(exclude=True, repr=False)
    image: _Digest = Field(exclude=True, repr=False)
    configuration: _Digest | None = Field(exclude=True, repr=False)
    compose_version: _Digest | None = Field(exclude=True, repr=False)
    observed_at: AwareDatetime


class _Receipt(_Closed):
    schema_version: Literal["opsark-compose-generation/v1"] = Field(alias="schema")
    status: Literal["observed"]
    reason: None
    scope_digest: _Digest
    binding: _Digest
    container: _Digest
    image: _Digest
    configuration: _Digest | None
    compose_version: _Digest | None


class GenerationComparison(_Closed):
    """Only observed differences. The label does not establish when or who changed it."""

    status: Literal["observed", "unavailable"] = "unavailable"
    container: Change = "unavailable"
    image: Change = "unavailable"
    compose_configuration: Change = "unavailable"
    source: Literal["docker_engine_metadata_and_compose_labels"] = (
        "docker_engine_metadata_and_compose_labels"
    )
    deployment_source: Literal["unknown"] = "unknown"
    changed_at: Literal["unknown"] = "unknown"
    actor: Literal["unknown"] = "unknown"


def _reject(*_) -> Never:
    raise GenerationUnavailable("Compose generation observation unavailable")


def binding_digest(host: HostConfig) -> str | None:
    project = host.compose_project
    service = host.compose_generation_service
    scope = host.compose_generation_scope_digest
    if (
        host.public.source != "ssh"
        or host.public.username != "opsark-readonly"
        or not host.public.trusted_hosts_digest
        or not host.container_binding_confirmed
        or project is None
        or COMPOSE_PROJECT.fullmatch(project) is None
        or IDENTIFIER.fullmatch(host.public.container_name) is None
        or type(service) is not str
        or IDENTIFIER.fullmatch(service) is None
        or scope != compose_generation_scope_sha256(project, host.public.container_name, service)
    ):
        return None
    bound = f"{diagnostic_scope_for(host.public)}:{scope}".encode("ascii")
    return hashlib.sha256(b"opsark-compose-generation-controller/v1\0" + bound).hexdigest()


def collection_command(host: HostConfig) -> str:
    if binding_digest(host) is None:
        _reject()
    return COMMAND


def _unique(rows):
    result = dict(rows)
    if len(result) != len(rows):
        _reject()
    return result


def private_observation(check: CheckResult, host: HostConfig, *, observed_at: datetime) -> _Witness:
    """Validate a complete typed receipt. The target retains the HMAC key and raw metadata."""
    binding = binding_digest(host)
    if (
        binding is None
        or check.name != CHECK
        or check.status != "ok"
        or type(check.exit_code) is not int
        or check.exit_code != 0
        or check.truncated
        or check.stderr
        or not check.stdout.isascii()
        or "\x00" in check.stdout
        or "\r" in check.stdout
        or not 0 < len(check.stdout) <= MAX_OUTPUT
        or check.stdout.count("\n") != 1
        or not check.stdout.endswith("\n")
        or observed_at.utcoffset() is None
    ):
        _reject()
    try:
        receipt = _Receipt.model_validate(
            json.loads(check.stdout, object_pairs_hook=_unique, parse_constant=_reject)
        )
    except (ValueError, RecursionError):
        raise GenerationUnavailable("Compose generation observation unavailable") from None
    if receipt.scope_digest != host.compose_generation_scope_digest or (
        receipt.configuration is None
    ) != (receipt.compose_version is None):
        _reject()
    return _Witness(
        binding=binding,
        key_epoch=receipt.binding,
        container=receipt.container,
        image=receipt.image,
        configuration=receipt.configuration,
        compose_version=receipt.compose_version,
        observed_at=observed_at.astimezone(UTC),
    )


def collect_generation(host: HostConfig) -> _Witness | None:
    command = collection_command(host)
    observed_at = datetime.now(UTC)
    results = collect_registered_receipts(host, {CHECK: command}, output_limit=MAX_OUTPUT + 1)
    check = results.get(CHECK)
    if check is None:
        return None
    try:
        return private_observation(check, host, observed_at=observed_at)
    except GenerationUnavailable:
        return None


def stable_observation(before: _Witness | None, after: _Witness | None) -> _Witness | None:
    """Keep the later sample only when both ends of an investigation agree."""
    if before is None or after is None or before.observed_at >= after.observed_at:
        return None
    fields = ("binding", "key_epoch", "container", "image", "configuration", "compose_version")
    stable = all(getattr(before, field) == getattr(after, field) for field in fields)
    return after if stable else None


def _change(before: str, after: str) -> Change:
    return "unchanged" if hmac.compare_digest(before, after) else "changed"


def compare_generation(before: _Witness | None, after: _Witness | None) -> GenerationComparison:
    """Compare two distinct-time observations from the same registered service scope."""
    if (
        before is None
        or after is None
        or before.binding != after.binding
        or before.key_epoch != after.key_epoch
        or before.observed_at >= after.observed_at
    ):
        return GenerationComparison()
    container = _change(before.container, after.container)
    image = _change(before.image, after.image)
    config: Change = "unavailable"
    if (
        before.compose_version == after.compose_version
        and before.configuration is not None
        and after.configuration is not None
    ):
        config = _change(before.configuration, after.configuration)
    if container == "unchanged" and (image == "changed" or config == "changed"):
        return GenerationComparison()  # Those Docker fields are fixed for one container.
    return GenerationComparison(
        status="observed", container=container, image=image, compose_configuration=config
    )
