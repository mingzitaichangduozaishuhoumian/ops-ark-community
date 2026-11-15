"""Bounded evidence for independent defense business rechecks, without execution authority."""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from opsark.defense_models import (
    DefenseModel,
    DefenseReply,
    Digest,
    Identifier,
    State,
    Timestamp,
    canonical,
    digest,
    utc,
)
from opsark.defense_store import Host, ObservationMetadata, Owner

CheckID = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")]
type BusinessStatus = Literal["passed", "failed", "inconclusive", "uncovered"]
type RootState = State | Literal["unavailable"]
type RecheckReason = Literal[
    "ok",
    "authority_proven",
    "authority_unproven",
    "approval_missing",
    "approval_unused",
    "approval_invalid",
    "apply_not_sent",
    "preauthorization_invalid",
    "usage_missing",
    "root_unproven",
    "root_changed",
    "root_unavailable",
    "ttl_elapsed",
    "scope_changed",
    "profile_missing",
    "profile_changed",
    "profile_uncovered",
    "business_failed",
    "business_inconclusive",
    "business_uncovered",
    "business_passed",
    "receipt_unavailable",
    "status_mismatch",
    "body_mismatch",
    "not_confirmed",
    "clock_regressed",
    "time_unverified",
    "run_unfinished",
    "evidence_missing",
    "evidence_changed",
    "unavailable",
]
Reasons = Annotated[tuple[RecheckReason, ...], Field(min_length=1, max_length=16)]


class ActionBusinessProfile(DefenseModel):
    v: int = Field(default=1, ge=1, le=1)
    rid: Identifier
    context_sha256: Digest
    prepare_request_sha256: Digest
    host_scope: Digest
    business_profile_sha256: Digest
    check_ids: tuple[CheckID, ...] = Field(max_length=16)
    sealed_at: Timestamp

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len(set(self.check_ids)) != len(self.check_ids):
            raise ValueError("Defense action business check identifiers must be unique")
        return self


class DefenseRecheckDeclaration(DefenseModel):
    v: int = Field(default=2, ge=2, le=2)
    run_ref: Identifier
    host_id: Host
    rid: Identifier
    expected_manifest_sha256: Digest
    expected_profile_sha256: Digest

    @property
    def sha256(self) -> str:
        return digest(self)


class RecheckRootEvidence(DefenseModel):
    sequence: int = Field(ge=1, le=2**63 - 1)
    observation: ObservationMetadata
    reply: DefenseReply | None

    @model_validator(mode="after")
    def exact_query(self) -> Self:
        import hashlib

        observation, reply = self.observation, self.reply
        if observation.op != "query":
            raise ValueError("Defense rechecks require an exact query observation")
        if reply is None:
            if (
                observation.state != "unavailable"
                or observation.accepted
                or observation.receipt_sha256 is not None
            ):
                raise ValueError("Defense missing reply cannot establish a Root observation")
        elif (
            reply.op != "query"
            or reply.request_id != observation.rid
            or reply.state != observation.state
            or hashlib.sha256(canonical(reply) + b"\n").hexdigest() != observation.receipt_sha256
        ):
            raise ValueError("Defense recheck Root observation does not close")
        return self


class RecheckAuthority(DefenseModel):
    kind: Literal["human_approval", "preauthorization", "unproven"]
    proof_sha256: Digest | None
    reason_codes: Reasons

    @model_validator(mode="after")
    def proof(self) -> Self:
        if (self.kind != "unproven") != (self.proof_sha256 is not None):
            raise ValueError("Defense recheck authority requires an exact proof")
        return self


class RecheckBusinessCheck(DefenseModel):
    id: CheckID
    status: BusinessStatus
    reason_code: RecheckReason

    @model_validator(mode="after")
    def reason(self) -> Self:
        allowed = {
            "passed": {"ok", "business_passed"},
            "failed": {"status_mismatch", "body_mismatch", "business_failed"},
            "inconclusive": {
                "receipt_unavailable",
                "business_inconclusive",
                "scope_changed",
                "profile_changed",
                "clock_regressed",
                "time_unverified",
                "unavailable",
                "evidence_missing",
            },
            "uncovered": {
                "not_confirmed",
                "profile_missing",
                "profile_uncovered",
                "business_uncovered",
                "unavailable",
                "evidence_missing",
            },
        }
        if self.reason_code not in allowed[self.status]:
            raise ValueError("Defense business row status and reason disagree")
        return self


def business_status(checks: tuple[RecheckBusinessCheck, ...]) -> BusinessStatus:
    states = {check.status for check in checks}
    return next(
        (state for state in ("failed", "inconclusive", "uncovered", "passed") if state in states),
        "uncovered",
    )


class RecheckBusinessEvidence(DefenseModel):
    checks: tuple[RecheckBusinessCheck, ...] = Field(max_length=16)
    status: BusinessStatus

    @model_validator(mode="after")
    def aggregate(self) -> Self:
        if len({check.id for check in self.checks}) != len(
            self.checks
        ) or self.status != business_status(self.checks):
            raise ValueError("Defense business result does not close")
        return self


def root_state(root: RecheckRootEvidence | None) -> RootState:
    if root is None or not root.observation.accepted or root.reply is None:
        return "unavailable"
    return root.reply.state


def root_transition(
    before: RecheckRootEvidence | None, after: RecheckRootEvidence | None
) -> Literal["unknown", "unchanged", "ttl_elapsed", "changed"]:
    first, second = root_state(before), root_state(after)
    if "unavailable" in (first, second) or "unknown" in (first, second):
        return "unknown"
    if first == second:
        if (
            first == "active"
            and before is not None
            and after is not None
            and before.reply is not None
            and after.reply is not None
            and before.reply.remaining_ms is not None
            and after.reply.remaining_ms is not None
            and after.reply.remaining_ms > before.reply.remaining_ms
        ):
            return "changed"
        return "unchanged"
    if (first, second) == ("active", "expired"):
        return "ttl_elapsed"
    return "changed"


class DefenseRecheckResult(DefenseModel):
    v: int = Field(default=2, ge=2, le=2)
    run_ref: Identifier
    host_id: Host
    rid: Identifier
    manifest_sha256: Digest
    defense_scope: Digest
    host_scope: Digest
    business_profile_sha256: Digest
    authority: RecheckAuthority
    business: RecheckBusinessEvidence
    root_before: RecheckRootEvidence | None
    root_after: RecheckRootEvidence | None
    expected_root_state: RootState
    current_root_state: RootState
    transition: Literal["unchanged", "ttl_elapsed", "changed", "unknown"]
    started_at: Timestamp
    finished_at: Timestamp
    verdict: Literal["pending", "failed", "passed"]
    reason_codes: Reasons

    @model_validator(mode="after")
    def evidence(self) -> Self:
        if (
            self.expected_root_state != root_state(self.root_before)
            or self.current_root_state != root_state(self.root_after)
            or self.transition != root_transition(self.root_before, self.root_after)
        ):
            raise ValueError("Defense recheck Root summary does not close")
        for root in (self.root_before, self.root_after):
            if root is not None and root.observation.rid != self.rid:
                raise ValueError("Defense recheck Root action changed")
        if utc(self.finished_at) < utc(self.started_at) and (
            self.verdict != "pending"
            or not {"clock_regressed", "time_unverified"}.intersection(self.reason_codes)
        ):
            raise ValueError("Defense recheck clock regression cannot establish a verdict")
        if self.verdict == "passed" and (
            self.authority.kind == "unproven"
            or self.business.status != "passed"
            or not self.business.checks
            or self.transition not in {"unchanged", "ttl_elapsed"}
            or self.expected_root_state not in {"active", "expired", "revoked"}
            or self.current_root_state not in {"active", "expired", "revoked"}
            or self.root_before is None
            or self.root_after is None
            or self.root_after.sequence <= self.root_before.sequence
            or not utc(self.started_at)
            <= utc(self.root_before.observation.observed_at)
            <= utc(self.root_after.observation.observed_at)
            <= utc(self.finished_at)
        ):
            raise ValueError("Defense recheck passing verdict lacks complete evidence")
        return self


class RecheckClaim(DefenseModel):
    run_ref: Identifier
    sequence: int = Field(ge=1, le=2**63 - 1)
    owner: Owner
    claim_ref: Identifier
    claimed_at: Timestamp
    declaration_sha256: Digest
    observation_sequence: int = Field(ge=0, le=2**63 - 1)


class RecheckInterruption(DefenseModel):
    interrupted_at: Timestamp
    hard_deadline_at: Timestamp
    reason_code: Literal["collection_deadline_elapsed"]
    claim_ref: Identifier
    declaration_sha256: Digest


class DefenseRecheckRun(DefenseModel):
    sequence: int = Field(ge=1, le=2**63 - 1)
    declaration: DefenseRecheckDeclaration
    declaration_sha256: Digest
    status: Literal["pending", "claimed", "completed", "interrupted"]
    created_at: Timestamp
    claimed_at: Timestamp | None
    owner: Owner | None
    claim: RecheckClaim | None
    result_sha256: Digest | None
    result: DefenseRecheckResult | None
    interruption: RecheckInterruption | None = None

    @model_validator(mode="after")
    def closed(self) -> Self:
        if self.declaration_sha256 != self.declaration.sha256:
            raise ValueError("Defense recheck declaration digest changed")
        if self.status == "pending":
            if any(
                value is not None
                for value in (
                    self.claimed_at,
                    self.owner,
                    self.claim,
                    self.result_sha256,
                    self.result,
                )
            ):
                raise ValueError("Defense pending recheck contains execution evidence")
        elif (
            self.claim is None
            or self.claimed_at != self.claim.claimed_at
            or self.owner != self.claim.owner
            or self.claim.run_ref != self.declaration.run_ref
            or self.claim.sequence != self.sequence
            or self.claim.declaration_sha256 != self.declaration_sha256
        ):
            raise ValueError("Defense recheck claim does not close")
        if (self.status == "completed") != (
            self.result is not None and self.result_sha256 is not None
        ):
            raise ValueError("Defense recheck completion is not sealed")
        if self.result is not None and (
            self.result_sha256 != digest(self.result)
            or self.result.run_ref != self.declaration.run_ref
        ):
            raise ValueError("Defense recheck result digest changed")
        if (self.status == "interrupted") != (self.interruption is not None):
            raise ValueError("Defense recheck interruption does not close")
        if self.interruption is not None and (
            self.claim is None
            or self.interruption.claim_ref != self.claim.claim_ref
            or self.interruption.declaration_sha256 != self.declaration_sha256
            or self.result is not None
            or self.result_sha256 is not None
        ):
            raise ValueError("Defense recheck interruption cannot replace a result")
        return self
