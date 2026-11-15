"""Strict private-profile defense wire DTOs; no transport or execution authority."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_WIRE_BYTES = 4096
POLICY_SHA256 = hashlib.sha256(
    b"opsark-defense-requests/v1;private;198.18.241.0/28;target=.2:22422;"
    b"sources=.3,.5;management=.4;arm=120s;ttl=60000ms;ports=5;"
    b"success=deny;capacity=8;single-element;no-retry-after-intent"
).hexdigest()
type DefenseRole = Literal["readonly", "observe", "control"]
type WireMode = Literal["manual", "semi", "auto"]
type Operation = Literal["arm", "prepare", "apply", "query", "revoke", "mode_sync"]
type QueryKind = Literal["cursor", "action", "mode"]
type Reason = Literal[
    "ok",
    "not_found",
    "request_conflict",
    "mode_unsynced",
    "authorization_denied",
    "quota_exhausted",
    "cursor_expired",
    "evidence_gap",
    "success_seen",
    "binding_changed",
    "policy_changed",
    "capacity_full",
    "result_unknown",
]
type State = Literal[
    "armed",
    "attached",
    "consumed",
    "expired",
    "invalid",
    "ready",
    "ready_expired",
    "active",
    "revoked",
    "unknown",
    "synced",
    "rejected",
    "not_found",
]
Identifier = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", min_length=32, max_length=32)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
Revision = Annotated[int, Field(ge=1, le=2**31 - 1)]


def utc(value: str) -> datetime:
    if (
        type(value) is not str
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is None
    ):
        raise ValueError("Invalid defense timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def _timestamp(value: str) -> str:
    utc(value)
    return value


Timestamp = Annotated[str, AfterValidator(_timestamp)]


def canonical(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate defense field")
        result[key] = value
    return result


def decode(raw: bytes) -> object:
    """Decode exactly one bounded LF-terminated JSON document, without normalization."""
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_WIRE_BYTES
        or not raw.endswith(b"\n")
        or b"\n" in raw[:-1]
        or b"\r" in raw
    ):
        raise ValueError("Invalid defense framing")

    def invalid_constant(_):
        raise ValueError("Invalid defense number")

    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=invalid_constant,
        )
    except (RecursionError, UnicodeError):
        raise ValueError("Invalid defense JSON") from None
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 16:
            raise ValueError("Invalid defense depth")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


class DefenseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class DefenseApproval(DefenseModel):
    approval_id: Identifier
    purpose: Literal["apply", "revoke"]
    request_id: Identifier
    manifest_sha256: Digest
    approved_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if (
            not timedelta(0)
            < utc(self.expires_at) - utc(self.approved_at)
            <= timedelta(seconds=120)
        ):
            raise ValueError("Invalid defense approval lifetime")
        return self


class ArmBody(DefenseModel):
    observation_grant_ref: Identifier
    policy_sha256: Digest


class PrepareBody(DefenseModel):
    cursor_id: Identifier
    source_ref: Identifier
    evidence_sha256: Digest
    policy_sha256: Digest
    mode: Literal["semi", "auto"]
    mode_revision: Revision
    controller_grant_ref: Identifier
    root_grant_ref: Identifier


class ActionBody(DefenseModel):
    manifest_sha256: Digest
    approval: DefenseApproval | None


class QueryBody(DefenseModel):
    kind: QueryKind


class ModeBody(DefenseModel):
    mode: WireMode
    mode_revision: Revision
    policy_sha256: Digest


class DefenseRequest(DefenseModel):
    v: int = Field(ge=1, le=1)
    op: Operation
    request_id: Identifier
    scope_sha256: Digest
    body: ArmBody | PrepareBody | ActionBody | QueryBody | ModeBody

    @model_validator(mode="after")
    def operation_body(self) -> Self:
        expected = {
            "arm": ArmBody,
            "prepare": PrepareBody,
            "apply": ActionBody,
            "revoke": ActionBody,
            "query": QueryBody,
            "mode_sync": ModeBody,
        }[self.op]
        if type(self.body) is not expected:
            raise ValueError("Invalid defense operation body")
        if isinstance(self.body, ActionBody):
            approval = self.body.approval
            if self.op == "revoke" and approval is None:
                raise ValueError("Defense revoke requires a declaration")
            if approval is not None and (
                approval.purpose != self.op
                or approval.request_id != self.request_id
                or approval.manifest_sha256 != self.body.manifest_sha256
            ):
                raise ValueError("Invalid defense approval binding")
        return self

    @classmethod
    def parse(cls, raw: bytes) -> Self:
        return cls.model_validate(decode(raw))

    def wire_bytes(self) -> bytes:
        raw = canonical(self) + b"\n"
        if len(raw) > MAX_WIRE_BYTES:
            raise ValueError("Defense request exceeds budget")
        return raw


class DefenseCandidate(DefenseModel):
    source_ref: Identifier
    source_alias: Literal["fixture-a", "fixture-b"]
    classification: Literal["eligible", "insufficient", "success_seen", "gap"]
    distinct_failure_ports: int = Field(ge=0, le=256)
    evidence_sha256: Digest | None

    @model_validator(mode="after")
    def evidence(self) -> Self:
        if (self.evidence_sha256 is not None) != (self.classification == "eligible"):
            raise ValueError("Invalid defense candidate evidence")
        return self


class DefenseManifest(DefenseModel):
    v: int = Field(ge=1, le=1)
    request_id: Identifier
    action_id: Identifier
    scope_sha256: Digest
    policy_sha256: Digest
    cursor_id: Identifier
    source_ref: Identifier
    evidence_sha256: Digest
    boot_ref: Digest
    binding_ref: Digest
    mode: Literal["semi", "auto"]
    mode_revision: Revision
    controller_grant_ref: Identifier
    root_grant_ref: Identifier
    ttl_ms: int = Field(ge=60000, le=60000)
    deadline_at: Timestamp

    @property
    def sha256(self) -> str:
        return digest(self)


class DefenseReply(DefenseModel):
    v: int = Field(ge=1, le=1)
    op: Operation
    request_id: Identifier
    scope_sha256: Digest
    policy_sha256: Digest
    boot_ref: Digest
    binding_ref: Digest
    mode: WireMode
    mode_revision: Revision
    state: State
    action_id: Identifier | None
    cursor_id: Identifier | None
    manifest_sha256: Digest | None
    deadline_at: Timestamp | None
    remaining_ms: Annotated[int, Field(ge=1, le=60000)] | None
    reason_code: Reason
    candidates: tuple[DefenseCandidate, ...] = Field(max_length=2)

    @field_validator("candidates", mode="before")
    @classmethod
    def immutable_candidates(cls, value):
        if type(value) is list:
            return tuple(value)
        return value

    @model_validator(mode="after")
    def relationships(self) -> Self:
        if (self.remaining_ms is not None) != (self.state == "active"):
            raise ValueError("Invalid defense TTL")
        if len({c.source_ref for c in self.candidates}) != len(self.candidates) or len(
            {c.source_alias for c in self.candidates}
        ) != len(self.candidates):
            raise ValueError("Duplicate defense candidate")
        if self.state == "not_found" and self.reason_code != "not_found":
            raise ValueError("Invalid defense absence")
        if self.state == "rejected" and self.reason_code == "ok":
            raise ValueError("Invalid defense rejection")
        action = (self.action_id, self.cursor_id, self.manifest_sha256, self.deadline_at)
        shape = (
            "empty"
            if all(value is None for value in action)
            else "action"
            if all(value is not None for value in action)
            else "cursor"
            if self.action_id is None
            and self.manifest_sha256 is None
            and self.cursor_id is not None
            and self.deadline_at is not None
            else "invalid"
        )
        if (
            shape == "invalid"
            or (
                self.state in {"ready", "ready_expired", "active", "revoked", "unknown"}
                and shape != "action"
            )
            or (self.state in {"armed", "attached", "consumed", "invalid"} and shape != "cursor")
            or (self.state in {"synced", "not_found"} and shape != "empty")
            or (self.state == "expired" and shape not in {"cursor", "action"})
        ):
            raise ValueError("Invalid defense nullable fields")
        if self.candidates and not (
            self.op == "query"
            and shape == "cursor"
            and self.state in {"armed", "attached", "invalid"}
        ):
            raise ValueError("Invalid defense candidate context")
        if (
            self.state in {"armed", "attached", "consumed", "ready", "active", "revoked", "synced"}
            and self.reason_code != "ok"
        ):
            raise ValueError("Invalid defense success reason")
        if (
            self.state == "ready_expired"
            and self.reason_code != "cursor_expired"
            or self.state == "invalid"
            and self.reason_code != "evidence_gap"
            or self.state == "unknown"
            and self.reason_code not in {"result_unknown", "binding_changed"}
            or self.state == "expired"
            and self.reason_code != ("cursor_expired" if shape == "cursor" else "ok")
        ):
            raise ValueError("Invalid defense state reason")
        return self

    @classmethod
    def parse(cls, raw: bytes) -> Self:
        return cls.model_validate(decode(raw))


@dataclass(frozen=True)
class DefenseCall:
    """Local durable context. Only ``request`` is sent over SSH.

    Action queries recover from the original prepare request, even if its reply was lost.
    A historical action's mode is never evidence for the current global mode.
    """

    request: DefenseRequest
    prepare_request: DefenseRequest | None = None
    expected_manifest: DefenseManifest | None = None
    expected_mode: WireMode | None = None
    expected_mode_revision: int | None = None


def rebuild_manifest(request: DefenseRequest, reply: DefenseReply) -> DefenseManifest:
    if request.op != "prepare" or not isinstance(request.body, PrepareBody):
        raise ValueError("Defense manifest requires original prepare")
    body = request.body
    return DefenseManifest.model_validate(
        {
            "v": 1,
            "request_id": request.request_id,
            "action_id": reply.action_id,
            "scope_sha256": request.scope_sha256,
            "policy_sha256": body.policy_sha256,
            "cursor_id": body.cursor_id,
            "source_ref": body.source_ref,
            "evidence_sha256": body.evidence_sha256,
            "boot_ref": reply.boot_ref,
            "binding_ref": reply.binding_ref,
            "mode": body.mode,
            "mode_revision": body.mode_revision,
            "controller_grant_ref": body.controller_grant_ref,
            "root_grant_ref": body.root_grant_ref,
            "ttl_ms": 60000,
            "deadline_at": reply.deadline_at,
        }
    )
