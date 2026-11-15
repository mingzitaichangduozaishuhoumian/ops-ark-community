"""Independent deployment authorization for the fixed private defense profile."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from opsark.defense_client import _read_file
from opsark.defense_models import DefenseModel, Digest, Identifier, Revision, Timestamp, utc

HostId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
Alias = Literal["fixture-a", "fixture-b"]


class DefenseWindow(DefenseModel):
    weekdays: tuple[Annotated[int, Field(ge=0, le=6)], ...] = Field(min_length=1, max_length=7)
    start_minute: int = Field(ge=0, le=1439)
    end_minute: int = Field(ge=1, le=1440)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len(set(self.weekdays)) != len(self.weekdays) or self.start_minute >= self.end_minute:
            raise ValueError("Invalid defense UTC window")
        return self

    def contains(self, instant: datetime) -> bool:
        minute = instant.hour * 60 + instant.minute
        return instant.weekday() in self.weekdays and self.start_minute <= minute < self.end_minute


class ObservationGrant(DefenseModel):
    v: int = Field(default=1, ge=1, le=1)
    enabled: bool = False
    grant_ref: Identifier
    issued_at: Timestamp
    expires_at: Timestamp
    host_ids: tuple[HostId, ...] = Field(min_length=1, max_length=10)
    target_scope_sha256: dict[HostId, Digest] = Field(min_length=1, max_length=10)
    target_policy_sha256: dict[HostId, Digest] = Field(min_length=1, max_length=10)
    windows: tuple[DefenseWindow, ...] = Field(min_length=1, max_length=7)

    @model_validator(mode="after")
    def bound(self) -> Self:
        if (
            len(set(self.host_ids)) != len(self.host_ids)
            or set(self.host_ids) != set(self.target_scope_sha256)
            or set(self.host_ids) != set(self.target_policy_sha256)
            or not timedelta(0) < utc(self.expires_at) - utc(self.issued_at) <= timedelta(hours=24)
        ):
            raise ValueError("Invalid defense observation grant")
        return self

    def open(self, instant: datetime) -> bool:
        return (
            self.enabled
            and utc(self.issued_at) <= instant < utc(self.expires_at)
            and any(window.contains(instant) for window in self.windows)
        )


class DefenseGrant(ObservationGrant):
    """Controller permission binds administrator-deployed Root grant references."""

    root_grant_refs: dict[HostId, Identifier] = Field(min_length=1, max_length=10)
    boot_refs: dict[HostId, Digest] = Field(min_length=1, max_length=10)
    binding_refs: dict[HostId, Digest] = Field(min_length=1, max_length=10)
    wire_revisions: tuple[Revision, ...] = Field(min_length=1, max_length=8)
    source_aliases: tuple[Alias, ...] = Field(min_length=1, max_length=2)
    max_actions_per_day: int = Field(ge=1, le=8)
    max_total_actions: int = Field(ge=1, le=8)

    @model_validator(mode="after")
    def execution_bound(self) -> Self:
        if (
            any(
                set(values) != set(self.host_ids)
                for values in (self.root_grant_refs, self.boot_refs, self.binding_refs)
            )
            or len(set(self.wire_revisions)) != len(self.wire_revisions)
            or len(set(self.source_aliases)) != len(self.source_aliases)
            or self.max_actions_per_day > self.max_total_actions
        ):
            raise ValueError("Invalid defense execution grant")
        return self


class DefenseAIConsent(DefenseModel):
    """Reserved independent consent; this slice does not run a model provider."""

    enabled: bool = False
    provider_fingerprint: Digest | None = None
    max_analyses_per_day: int = Field(default=1, ge=1, le=8)
    max_total_analyses: int = Field(default=1, ge=1, le=8)
    requires_ai: bool = False

    @model_validator(mode="after")
    def provider_bound(self) -> Self:
        if self.enabled and self.provider_fingerprint is None:
            raise ValueError("Invalid defense AI consent")
        return self


class DefensePolicy(DefenseModel):
    v: int = Field(default=1, ge=1, le=1)
    enabled: bool = False
    profile: Literal["private-198.18.241.0/28"] = "private-198.18.241.0/28"
    action: Literal["block-single-source"] = "block-single-source"
    ttl_ms: int = Field(default=60000, ge=60000, le=60000)
    source_aliases: tuple[Alias, ...] = ("fixture-a", "fixture-b")
    observation: ObservationGrant | None = None
    execution: DefenseGrant | None = None
    ai: DefenseAIConsent = DefenseAIConsent()

    @model_validator(mode="after")
    def fixed_aliases(self) -> Self:
        if self.source_aliases != ("fixture-a", "fixture-b"):
            raise ValueError("Invalid defense profile aliases")
        return self


def load_policy(path: Path | None) -> DefensePolicy:
    """None is disabled and never consults a default deployment file."""
    if path is None:
        return DefensePolicy()
    try:
        raw, seal = _read_file(path, 16384, private=True)

        def unique(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("Duplicate defense policy field")
                result[name] = value
            return result

        def nonfinite(_value):
            raise ValueError("Invalid defense policy number")

        value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
        policy = DefensePolicy.model_validate_json(json.dumps(value, allow_nan=False))
        _, current = _read_file(path, 16384, private=True)
        if current != seal:
            raise ValueError("Defense policy changed while loading")
        return policy
    except Exception:
        raise ValueError("Defense deployment policy could not be verified") from None


def now_utc() -> datetime:
    return datetime.now(UTC)
