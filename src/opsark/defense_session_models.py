"""Local single-session declarations, never Root or provider authority by themselves."""

from dataclasses import dataclass, field
from typing import Literal, Self

from pydantic import Field, model_validator

from opsark.defense_models import DefenseModel, Digest, Identifier, Timestamp, canonical, utc
from opsark.defense_store import DefenseContext, DefenseSource, Owner
from opsark.mode_coordinator import ModeSnapshot

type SessionPhase = Literal[
    "declared",
    "observing",
    "analyzing",
    "analysis_ready",
    "preparing",
    "prepared",
    "applying",
    "confirmed",
    "completed",
    "stopped",
    "expired",
    "reconciliation_only",
]
type SessionStopReason = Literal[
    "requested",
    "mode_changed",
    "registration_changed",
    "lease_lost",
    "owner_changed",
    "deadline_elapsed",
    "result_unknown",
    "ai_unavailable",
    "proof_changed",
    "budget_insufficient",
]


class SessionModeSnapshot(DefenseModel):
    scope: Digest
    mode: Literal["manual", "assisted", "automatic"]
    revision: int = Field(ge=0, le=2**31 - 2)
    sync_generation: int = Field(ge=0, le=2**63 - 1)

    @classmethod
    def capture(cls, snapshot: ModeSnapshot):
        if type(snapshot) is not ModeSnapshot:
            raise ValueError("A session needs the complete current mode snapshot")
        return cls.model_validate_json(
            canonical(
                {
                    "scope": snapshot.scope,
                    "mode": snapshot.mode,
                    "revision": snapshot.revision,
                    "sync_generation": snapshot.sync_generation,
                }
            )
        )


class SessionRuntime(DefenseModel):
    """Trusted controller callback result; never accepted from an HTTP request."""

    context: DefenseContext
    mode: SessionModeSnapshot
    host_scope: Digest
    enabled: bool
    stopping: bool
    mode_sync_complete: bool
    execution_authorized: bool
    observation_grant_ref: Identifier
    controller_grant_ref: Identifier
    root_grant_ref: Identifier
    allowed_source_aliases: tuple[Literal["fixture-a", "fixture-b"], ...] = Field(
        min_length=1, max_length=2
    )
    requires_ai: bool
    provider_fingerprint: Digest | None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (
            self.context.mode
            != {"manual": "manual", "assisted": "semi", "automatic": "auto"}[self.mode.mode]
            or self.context.global_revision != self.mode.revision
            or self.context.epoch != self.mode.sync_generation
            or len(set(self.allowed_source_aliases)) != len(self.allowed_source_aliases)
            or (self.requires_ai and self.provider_fingerprint is None)
        ):
            raise ValueError("Session runtime context is not closed")
        return self


class SessionDeclaration(DefenseModel):
    v: Literal[1] = 1
    session_ref: Identifier
    cursor_rid: Identifier
    boot_owner: Owner
    worker_epoch: int = Field(ge=0, le=2**63 - 1)
    runtime: SessionRuntime
    source: DefenseSource
    arm_request_sha256: Digest
    controller_created_at: Timestamp
    controller_deadline_at: Timestamp
    max_ai_intents: Literal[1] = 1
    max_actions: Literal[1] = 1

    @model_validator(mode="after")
    def local_window(self) -> Self:
        created, deadline = utc(self.controller_created_at), utc(self.controller_deadline_at)
        if (
            not 0 < (deadline - created).total_seconds() <= 120
            or self.cursor_rid != self.source.cursor_rid
            or not created <= utc(self.source.observed_at) < deadline
            or self.source.host_scope != self.runtime.host_scope
            or self.source.defense_scope != self.runtime.context.defense_scope
        ):
            raise ValueError("Session declaration does not retain its original local window")
        return self


class SessionSelection(DefenseModel):
    session_ref: Identifier
    source: DefenseSource
    source_ref: Identifier
    evidence_sha256: Digest
    observed_sequence: int = Field(ge=1)
    selected_at: Timestamp


class SessionAIIntent(DefenseModel):
    session_ref: Identifier
    analysis_id: Identifier
    intent_key: Digest
    input_digest: Digest
    provider_fingerprint: Digest
    selection_sha256: Digest


class SessionAction(DefenseModel):
    session_ref: Identifier
    rid: Identifier
    cursor_rid: Identifier
    context_sha256: Digest
    owner: Owner
    deadline_at: Timestamp


class SessionRequestBinding(DefenseModel):
    session_ref: Identifier
    rid: Identifier
    op: Literal["prepare", "apply"]
    request_sha256: Digest
    owner: Owner
    worker_epoch: int = Field(ge=0, le=2**63 - 1)


class SessionRecord(DefenseModel):
    declaration: SessionDeclaration
    declaration_sha256: Digest
    owner: Owner
    worker_epoch: int = Field(ge=0, le=2**63 - 1)
    phase: SessionPhase
    revision: int = Field(ge=0, le=2**63 - 1)
    created_at: Timestamp
    updated_at: Timestamp
    stop_reason: SessionStopReason | None = None
    selection: SessionSelection | None = None
    ai_intent: SessionAIIntent | None = None
    action: SessionAction | None = None
    effective_phase: SessionPhase
    business_verdict: Literal["pending"] = "pending"


@dataclass(frozen=True, init=False)
class SessionAdmission:
    """Process-local capability issued by one store, not a serialized authorization."""

    _store: object = field(repr=False)
    _token: object = field(repr=False)
    session_ref: str
    declaration_sha256: str
    owner: str
    worker_epoch: int
    phase: str
    revision: int
