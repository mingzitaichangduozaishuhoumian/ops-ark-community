"""Durable, single-dispatch defense ledger inside the existing security database.

This ledger is an admission *boundary*, not a mode or Root authority. The service
must recheck current registry, credentials, global mode and Root grants immediately
before dispatch. No network call belongs inside a database transaction.
"""

import hashlib
import re
import secrets
import sqlite3
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, Self

from pydantic import Field, TypeAdapter, model_validator

if TYPE_CHECKING:
    from opsark.defense_session_models import SessionRecord

from opsark.defense_models import (
    ActionBody,
    DefenseApproval,
    DefenseCall,
    DefenseCandidate,
    DefenseManifest,
    DefenseModel,
    DefenseReply,
    DefenseRequest,
    Digest,
    Identifier,
    ModeBody,
    Operation,
    PrepareBody,
    QueryBody,
    State,
    Timestamp,
    WireMode,
    canonical,
    digest,
    rebuild_manifest,
    utc,
)

type Kind = Literal["cursor", "action", "mode"]
type Phase = Literal[
    "created",
    "prepared_intent",
    "prepare_sendable",
    "ready",
    "apply_sendable",
    "active",
    "unknown",
    "rejected",
    "expired",
    "revoked",
    "ready_expired",
    "arm_sendable",
    "armed",
    "attached",
    "consumed",
    "invalid",
    "mode_sendable",
    "synced",
    "revoke_sendable",
    "not_found",
]
type DispatchPhase = Literal["intent", "sendable", "replied", "unknown"]
type ObservationReason = Literal[
    "ok",
    "unavailable",
    "binding_changed",
    "stale",
    "ttl_increased",
    "terminal_regression",
    "unknown",
    "not_found",
    "rejected",
]
Host = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
Owner = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
Epoch = Annotated[int, Field(ge=0, le=2**63 - 1)]
MAX_DEADLINE_DISPLACEMENT_SECONDS = 30


def _now(value: datetime | None = None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if not isinstance(result, datetime) or result.tzinfo is None:
        raise ValueError("Defense time must have a timezone")
    return result.astimezone(UTC)


def _stamp(value: datetime) -> str:
    return _now(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class DefenseConflict(ValueError):
    """The immutable ledger identity or current admission context conflicts."""


class DefenseQuotaExceeded(DefenseConflict):
    pass


class DefenseContext(DefenseModel):
    """Immutable service admission epoch, including its mode-sync generation.

    epoch belongs to the service's registry/mode/stop snapshot. WorkerLease.epoch
    is an independent fencing counter and must never substitute for this value.
    """

    host_id: Host
    defense_scope: Digest
    registry_scope: Digest
    root_scope: Digest
    policy_sha256: Digest
    boot_ref: Digest
    binding_ref: Digest
    mode: WireMode
    global_revision: int = Field(ge=0, le=2**31 - 2)
    wire_revision: int = Field(ge=1, le=2**31 - 1)
    epoch: Epoch

    @model_validator(mode="after")
    def revisions(self) -> Self:
        if self.wire_revision != self.global_revision + 1:
            raise ValueError("Defense wire revision must follow the global revision")
        return self


class DefenseTransaction(DefenseModel):
    rid: Identifier
    kind: Kind
    context: DefenseContext
    owner: Owner
    deadline_at: Timestamp
    cursor_rid: Identifier | None
    phase: Phase
    created_at: Timestamp
    updated_at: Timestamp
    manifest_sha256: Digest | None
    action_id: Identifier | None
    query_required: bool
    last_error_code: (
        Literal[
            "unavailable",
            "binding_changed",
            "stale",
            "ttl_increased",
            "terminal_regression",
            "unknown",
            "not_found",
            "rejected",
        ]
        | None
    )


class RequestMetadata(DefenseModel):
    rid: Identifier
    op: Operation
    request_sha256: Digest
    dispatch_phase: DispatchPhase
    send_owner: Owner | None
    send_started_at: Timestamp | None
    reply_sha256: Digest | None


class SendPermit(DefenseModel):
    rid: Identifier
    op: Operation
    request_sha256: Digest
    owner: Owner
    epoch: Epoch
    committed_at: Timestamp


class UsageClaim(DefenseModel):
    """Stable business identity is supplied by the service, never generated here.

    Changing a grant must not change intent_key. Execution reservation is made
    before prepare and becomes consumed with apply; neither state is refundable.
    """

    intent_key: Digest
    kind: Literal["execution", "ai"]
    grant_ref: Identifier
    max_per_day: int = Field(ge=1, le=100_000)
    max_total: int = Field(ge=1, le=1_000_000)
    provider_fingerprint: Digest | None = None

    @model_validator(mode="after")
    def provider(self) -> Self:
        if (self.kind == "ai") != (self.provider_fingerprint is not None):
            raise ValueError("Defense AI usage requires exactly one provider binding")
        return self


class UsageMetadata(DefenseModel):
    intent_key: Digest
    kind: Literal["execution", "ai"]
    rid: Identifier
    host_id: Host
    defense_scope: Digest
    grant_ref: Identifier
    charged_day: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    provider_fingerprint: Digest | None
    state: Literal["reserved", "consumed", "unknown"]
    created_at: Timestamp


class ApprovalMetadata(DefenseModel):
    approval: DefenseApproval
    global_revision: int = Field(ge=0, le=2**31 - 2)
    wire_revision: int = Field(ge=1, le=2**31 - 1)
    controller_grant_ref: Identifier
    root_grant_ref: Identifier
    statement_sha256: Digest
    # Revoke authorizes this new operation against the immutable old manifest.
    # Apply always remains bound to the original transaction context instead.
    admission_context: DefenseContext | None = None


class AuthorizationRecord(DefenseModel):
    metadata: ApprovalMetadata
    dispatch_state: Literal["recorded", "used"]
    used_at: Timestamp | None

    @model_validator(mode="after")
    def used(self) -> Self:
        if (self.dispatch_state == "used") != (self.used_at is not None):
            raise ValueError("Defense authorization use metadata does not close")
        return self


class ConfirmedMetadata(DefenseModel):
    rid: Identifier
    state: Literal["ready", "active", "expired", "revoked"]
    remaining_ms: int | None = Field(ge=1, le=60000)
    observed_at: Timestamp
    receipt_sha256: Digest


class ObservationMetadata(DefenseModel):
    observation_id: Identifier
    rid: Identifier
    op: Operation
    state: State | Literal["unavailable"]
    observed_at: Timestamp
    receipt_sha256: Digest | None
    accepted: bool
    reason: ObservationReason


class SequencedObservation(DefenseModel):
    sequence: int = Field(ge=1)
    observation: ObservationMetadata
    reply: DefenseReply | None


class ModeAckMetadata(DefenseModel):
    context: DefenseContext
    mode_rid: Identifier
    status: Literal["pending", "unknown", "confirmed"]
    checked_at: Timestamp
    receipt_sha256: Digest | None


class DefenseSource(DefenseModel):
    v: int = Field(ge=1, le=1)
    host_scope: Digest
    defense_scope: Digest
    root_scope: Digest
    policy_sha256: Digest
    boot_ref: Digest
    binding_ref: Digest
    cursor_rid: Identifier
    observed_at: Timestamp
    cursor_deadline_at: Timestamp
    root_reply_sha256: Digest
    candidates: tuple[DefenseCandidate, ...] = Field(max_length=2)

    @model_validator(mode="after")
    def bounds(self) -> Self:
        # observed_at belongs to the Controller; cursor_deadline_at belongs to
        # Root. A structural DTO must not compare these different clock domains.
        if len({c.source_ref for c in self.candidates}) != len(self.candidates):
            raise ValueError("Defense source aliases must be unique")
        if len({c.source_alias for c in self.candidates}) != len(self.candidates):
            raise ValueError("Defense source aliases must be unique")
        return self


class _ControllerTimeData(DefenseModel):
    cursor_rid: Identifier
    source_sha256: Digest
    context_sha256: Digest
    created_at: Timestamp
    deadline_at: Timestamp


@dataclass(frozen=True, init=False)
class ControllerTimeBounds:
    """Opaque local provenance, issued only by a ledger read and rechecked on use.

    No HTTP DTO or model input contains this object. Its process-local token is
    not persisted; after restart the original ledger must issue it again.
    """

    _ledger: "DefenseStore" = field(repr=False)
    _token: object = field(repr=False)
    _data: _ControllerTimeData = field(repr=False)
    root_reply: DefenseReply = field(repr=False)

    def require(
        self,
        source: DefenseSource,
        *,
        context: DefenseContext | None = None,
        now: datetime | None = None,
    ) -> None:
        try:
            if (
                type(self) is not ControllerTimeBounds
                or type(self._ledger) is not DefenseStore
                or self._token is not self._ledger._time_bounds_token
            ):
                raise DefenseConflict("Defense source time provenance is unavailable")
            self._ledger._require_time_bounds(self, source, context=context, now=now)
        except AttributeError:
            raise DefenseConflict("Defense source time provenance is unavailable") from None


class SourceMetadata(DefenseModel):
    source_key: Digest
    source_sha256: Digest
    cursor_rid: Identifier
    defense_scope: Digest
    observed_at: Timestamp
    cursor_deadline_at: Timestamp


class DefenseAlias(DefenseModel):
    candidate_alias: Literal["candidate-1", "candidate-2"]
    evidence_alias: Literal["evidence-1", "evidence-2"]
    source_ref: Identifier
    evidence_sha256: Digest


class AliasMap(DefenseModel):
    aliases: tuple[DefenseAlias, ...] = Field(max_length=2)

    @model_validator(mode="after")
    def closed(self) -> Self:
        for name in ("candidate_alias", "evidence_alias", "source_ref"):
            if len({getattr(alias, name) for alias in self.aliases}) != len(self.aliases):
                raise ValueError("Defense AI aliases must be unique")
        return self


class AIResult(DefenseModel):
    analysis_id: Identifier
    intent_key: Digest
    input_digest: Digest
    provider_fingerprint: Digest
    status: Literal["completed", "refused", "failed", "unknown", "stale"]
    proof_sha256: Digest | None
    decision: Literal["propose_defense", "collect_more", "review_access", "no_action"] | None
    source_ref: Identifier | None
    evidence_sha256: Digest | None
    reason_code: Literal["evidence_sufficient", "evidence_gap", "access_review", "no_match"] | None

    @model_validator(mode="after")
    def proposal(self) -> Self:
        proposed = self.status == "completed" and self.decision == "propose_defense"
        if proposed != (self.source_ref is not None and self.evidence_sha256 is not None):
            raise ValueError("Defense AI proposal needs exact source and evidence references")
        if self.status == "completed" and (self.decision is None or self.reason_code is None):
            raise ValueError("Defense AI completion needs a typed decision")
        return self


class AIAdviceAuthorization(DefenseModel):
    purpose: Literal["explicit_advice"] = "explicit_advice"
    context_sha256: Digest
    consent_sha256: Digest
    provider_fingerprint: Digest
    confirmed_at: Timestamp


class AIUsagePermit(DefenseModel):
    analysis_id: Identifier
    intent_key: Digest
    input_digest: Digest
    source_key: Digest
    rid: Identifier
    provider_fingerprint: Digest
    owner: Owner
    deadline_at: Timestamp
    committed_at: Timestamp
    advice_authorization: AIAdviceAuthorization | None = None


class DefenseRecheck(DefenseModel):
    recheck_id: Identifier
    report_id: Identifier
    rid: Identifier
    manifest_sha256: Digest
    approval_id: Identifier
    defense_scope: Digest
    profile_sha256: Digest
    started_at: Timestamp
    ended_at: Timestamp
    checks: tuple[Literal["ok", "error", "timeout", "unavailable", "scope_changed"], ...] = Field(
        min_length=1,
        max_length=16,
    )

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if utc(self.ended_at) < utc(self.started_at):
            raise ValueError("Defense recheck times are out of order")
        return self


class LegacyRecheckRecord(DefenseModel):
    sequence: int = Field(ge=1, le=2**63 - 1)
    record: DefenseRecheck
    verdict: Literal["pending"] = "pending"


class WorkerLease(DefenseModel):
    owner: Owner
    expires_at: Timestamp
    epoch: Epoch


class SessionGuard(Protocol):
    base: "DefenseStore"

    def get(self, session_ref: str, *, now=None) -> "SessionRecord": ...

    def atomic_assert(self, admission, connection: sqlite3.Connection, *, now=None): ...
    def bind_action(self, admission, rid, *, now=None, connection=None): ...
    def bind_request(self, admission, request, *, now=None, connection=None): ...
    def bind_ai_permit(self, admission, permit, *, now=None, connection=None): ...


class DefenseStore:
    """Own only defense_* tables; all failed commits fail closed for dispatch."""

    def __init__(self, path: Path) -> None:
        self._time_bounds_token = object()
        self._session_guard: SessionGuard | None = None
        self.path = Path(path)
        if self.path.is_symlink() or self.path.exists() and not self.path.is_file():
            raise ValueError("Defense database must be a regular file")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS defense_transactions(
                    rid TEXT PRIMARY KEY, kind TEXT NOT NULL, host_id TEXT NOT NULL,
                    defense_scope TEXT NOT NULL, context_json BLOB NOT NULL,
                    context_sha256 TEXT NOT NULL, owner TEXT NOT NULL, deadline_at TEXT NOT NULL,
                    cursor_rid TEXT, phase TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, manifest_sha256 TEXT, manifest_json BLOB,
                    action_id TEXT, query_required INTEGER NOT NULL DEFAULT 0,
                    last_error_code TEXT,
                    UNIQUE(defense_scope,cursor_rid),
                    FOREIGN KEY(cursor_rid) REFERENCES defense_transactions(rid)
                );
                CREATE TABLE IF NOT EXISTS defense_observation_intents(
                    intent_key TEXT PRIMARY KEY,
                    rid TEXT NOT NULL UNIQUE REFERENCES defense_transactions(rid)
                );
                CREATE TABLE IF NOT EXISTS defense_requests(
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid), op TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL, request_bytes BLOB NOT NULL,
                    dispatch_phase TEXT NOT NULL, send_owner TEXT, send_started_at TEXT,
                    reply_sha256 TEXT, reply_bytes BLOB, PRIMARY KEY(rid,op)
                );
                CREATE TABLE IF NOT EXISTS defense_authorizations(
                    approval_id TEXT PRIMARY KEY, rid TEXT NOT NULL
                    REFERENCES defense_transactions(rid), purpose TEXT NOT NULL,
                    statement_sha256 TEXT NOT NULL, typed_statement BLOB NOT NULL,
                    dispatch_state TEXT NOT NULL DEFAULT 'recorded', used_at TEXT,
                    UNIQUE(rid,purpose)
                );
                CREATE TABLE IF NOT EXISTS defense_op_admissions(
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    op TEXT NOT NULL CHECK(op='revoke'), context_json BLOB NOT NULL,
                    context_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY(rid,op)
                );
                CREATE TABLE IF NOT EXISTS defense_usage(
                    intent_key TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid), host_id TEXT NOT NULL,
                    defense_scope TEXT NOT NULL, grant_ref TEXT NOT NULL, charged_day TEXT NOT NULL,
                    provider_fingerprint TEXT, state TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS defense_usage_quota
                    ON defense_usage(kind,grant_ref,charged_day);
                CREATE TABLE IF NOT EXISTS defense_last_confirmed(
                    host_id TEXT NOT NULL, defense_scope TEXT NOT NULL,
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid), state TEXT NOT NULL,
                    remaining_ms INTEGER, observed_at TEXT NOT NULL, receipt_sha256 TEXT NOT NULL,
                    PRIMARY KEY(host_id,defense_scope,rid)
                );
                CREATE TABLE IF NOT EXISTS defense_observations(
                    observation_id TEXT PRIMARY KEY,
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid), op TEXT NOT NULL,
                    state TEXT NOT NULL, observed_at TEXT NOT NULL, receipt_sha256 TEXT,
                    receipt_bytes BLOB, accepted INTEGER NOT NULL, reason TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS defense_observation_history
                    ON defense_observations(rid,observed_at,observation_id);
                CREATE TABLE IF NOT EXISTS defense_mode_ack(
                    host_id TEXT NOT NULL, registry_scope TEXT NOT NULL,
                    global_revision INTEGER NOT NULL, context_json BLOB NOT NULL,
                    mode_rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    status TEXT NOT NULL, checked_at TEXT NOT NULL, receipt_sha256 TEXT,
                    PRIMARY KEY(host_id,registry_scope,global_revision)
                );
                CREATE TABLE IF NOT EXISTS defense_mode_ack_history(
                    snapshot_sha256 TEXT PRIMARY KEY,
                    mode_rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    typed_snapshot BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_mode_query_bindings(
                    observation_id TEXT PRIMARY KEY
                    REFERENCES defense_observations(observation_id),
                    mode_rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    context_json BLOB NOT NULL, context_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_sources(
                    source_key TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
                    source_sha256 TEXT NOT NULL, typed_source BLOB NOT NULL,
                    alias_sha256 TEXT NOT NULL, alias_map BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_ai_results(
                    analysis_id TEXT PRIMARY KEY, intent_key TEXT NOT NULL UNIQUE
                    REFERENCES defense_usage(intent_key), result_sha256 TEXT NOT NULL,
                    typed_result BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_ai_intents(
                    analysis_id TEXT PRIMARY KEY, intent_key TEXT NOT NULL UNIQUE
                    REFERENCES defense_usage(intent_key), permit_sha256 TEXT NOT NULL,
                    typed_permit BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_rechecks(
                    recheck_id TEXT PRIMARY KEY, rid TEXT NOT NULL
                    REFERENCES defense_transactions(rid), recheck_sha256 TEXT NOT NULL,
                    typed_recheck BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_worker_lease(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    owner TEXT NOT NULL, expires_at TEXT NOT NULL, epoch INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_target_latches(
                    host_id TEXT NOT NULL, defense_scope TEXT NOT NULL,
                    reason TEXT NOT NULL, rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    created_at TEXT NOT NULL, PRIMARY KEY(host_id,defense_scope)
                );
            """)

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            yield connection
        finally:
            connection.close()

    def _commit(self, connection: sqlite3.Connection) -> None:
        """Separate seam for testing a failed durable boundary."""
        connection.commit()

    def register_session_guard(self, guard: SessionGuard) -> None:
        if (
            getattr(guard, "base", None) is not self
            or any(
                not callable(getattr(guard, name, None))
                for name in (
                    "get",
                    "atomic_assert",
                    "bind_action",
                    "bind_request",
                    "bind_ai_permit",
                )
            )
            or self._session_guard is not None
            and self._session_guard is not guard
        ):
            raise DefenseConflict("A session ledger has one immutable local guard")
        self._session_guard = guard

    def require_session_admission(
        self,
        rid: str,
        admission,
        *,
        phase: str | None = None,
        now: datetime | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> SessionGuard | None:
        """Resolve persistent ownership before deciding whether an optional fence is optional."""
        TypeAdapter(Identifier).validate_python(rid, strict=True)
        instant = _now(now)
        if connection is None:
            with self._connection() as db:
                db.execute("BEGIN")
                return self.require_session_admission(
                    rid, admission, phase=phase, now=instant, connection=db
                )
        databases = connection.execute("PRAGMA database_list").fetchall()
        main = next((row for row in databases if row[1] == "main"), None)
        if (
            not connection.in_transaction
            or main is None
            or Path(main[2]).resolve() != self.path.resolve()
        ):
            raise DefenseConflict("Session admission needs its original ledger transaction")
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('defense_sessions_v1','defense_session_actions_v1','defense_session_ai_v1')"
            )
        }
        references = set()
        if "defense_sessions_v1" in tables:
            references.update(
                row[0]
                for row in connection.execute(
                    "SELECT session_ref FROM defense_sessions_v1 "
                    "WHERE cursor_rid=? OR cursor_rid IN "
                    "(SELECT cursor_rid FROM defense_transactions WHERE rid=? AND kind='action')",
                    (rid, rid),
                )
            )
            if "defense_session_actions_v1" in tables:
                references.update(
                    row[0]
                    for row in connection.execute(
                        "SELECT session_ref FROM defense_session_actions_v1 WHERE rid=?", (rid,)
                    )
                )
            if "defense_session_ai_v1" in tables:
                references.update(
                    row[0]
                    for row in connection.execute(
                        "SELECT session_ref FROM defense_session_ai_v1 WHERE analysis_id=?", (rid,)
                    )
                )
            ai = connection.execute(
                "SELECT * FROM defense_ai_intents WHERE analysis_id=?", (rid,)
            ).fetchone()
            if ai is not None:
                if _hash(ai["typed_permit"]) != ai["permit_sha256"]:
                    raise DefenseConflict("Session analysis identity is not verifiable")
                permit = AIUsagePermit.model_validate_json(ai["typed_permit"])
                references.update(
                    row[0]
                    for row in connection.execute(
                        "SELECT session_ref FROM defense_sessions_v1 WHERE cursor_rid=?",
                        (permit.rid,),
                    )
                )
        if not references:
            if admission is not None:
                raise DefenseConflict("A session token cannot authorize unrelated work")
            return None
        if (
            len(references) != 1
            or admission is None
            or self._session_guard is None
            or getattr(admission, "session_ref", None) not in references
            or phase is not None
            and getattr(admission, "phase", None) != phase
        ):
            raise DefenseConflict("Original session admission is required")
        if self._session_guard.atomic_assert(admission, connection, now=instant) is not None:
            raise DefenseConflict("Session admission did not close")
        return self._session_guard

    @contextmanager
    def _write(self) -> Generator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                self._commit(connection)
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _transaction(connection: sqlite3.Connection, rid: str) -> DefenseTransaction:
        row = connection.execute(
            "SELECT * FROM defense_transactions WHERE rid=?", (rid,)
        ).fetchone()
        if row is None:
            raise DefenseConflict("Defense transaction was not found")
        if _hash(row["context_json"]) != row["context_sha256"]:
            raise DefenseConflict("Defense transaction integrity failed")
        context = DefenseContext.model_validate_json(row["context_json"])
        if context.host_id != row["host_id"] or context.defense_scope != row["defense_scope"]:
            raise DefenseConflict("Defense transaction binding failed")
        if row["manifest_json"] is not None:
            manifest = DefenseManifest.model_validate_json(row["manifest_json"])
            if manifest.sha256 != row["manifest_sha256"] or manifest.request_id != rid:
                raise DefenseConflict("Defense manifest integrity failed")
        return DefenseTransaction(
            rid=row["rid"],
            kind=row["kind"],
            context=context,
            owner=row["owner"],
            deadline_at=row["deadline_at"],
            cursor_rid=row["cursor_rid"],
            phase=row["phase"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            manifest_sha256=row["manifest_sha256"],
            action_id=row["action_id"],
            query_required=bool(row["query_required"]),
            last_error_code=row["last_error_code"],
        )

    @staticmethod
    def _request(connection: sqlite3.Connection, rid: str, op: str) -> DefenseRequest:
        row = connection.execute(
            "SELECT request_bytes,request_sha256 FROM defense_requests WHERE rid=? AND op=?",
            (rid, op),
        ).fetchone()
        if row is None or _hash(row["request_bytes"]) != row["request_sha256"]:
            raise DefenseConflict("Defense request integrity failed")
        request = DefenseRequest.parse(row["request_bytes"])
        if (
            request.request_id != rid
            or request.op != op
            or request.wire_bytes() != row["request_bytes"]
        ):
            raise DefenseConflict("Defense request binding failed")
        return request

    def create_transaction(
        self,
        *,
        kind: Kind,
        context: DefenseContext,
        owner: str,
        deadline_at: str,
        cursor_rid: str | None = None,
        observation_key: str | None = None,
        now: datetime | None = None,
        session_admission=None,
    ) -> DefenseTransaction:
        instant = _now(now)
        context = DefenseContext.model_validate_json(canonical(context))
        # Constructing the public DTO validates every caller-controlled scalar.
        new = DefenseTransaction(
            rid=secrets.token_hex(16),
            kind=kind,
            context=context,
            owner=owner,
            deadline_at=deadline_at,
            cursor_rid=cursor_rid,
            phase="created",
            created_at=_stamp(instant),
            updated_at=_stamp(instant),
            manifest_sha256=None,
            action_id=None,
            query_required=False,
            last_error_code=None,
        )
        if not 0 < (utc(deadline_at) - instant).total_seconds() <= 120 or (kind == "action") != (
            cursor_rid is not None
        ):
            raise DefenseConflict("Defense transaction deadline or cursor is invalid")
        if observation_key is not None and (
            kind != "cursor"
            or type(observation_key) is not str
            or len(observation_key) != 64
            or any(c not in "0123456789abcdef" for c in observation_key)
        ):
            raise DefenseConflict("Defense observation intent identity is invalid")
        with self._write() as connection:
            guard = None
            if kind == "action":
                if cursor_rid is None:
                    raise DefenseConflict("A session action requires an original cursor")
                guard = self.require_session_admission(
                    cursor_rid,
                    session_admission,
                    phase="preparing",
                    now=instant,
                    connection=connection,
                )
            elif session_admission is not None:
                raise DefenseConflict("Sessions cannot authorize arm or mode transactions")
            if observation_key is not None:
                existing = connection.execute(
                    "SELECT rid FROM defense_observation_intents WHERE intent_key=?",
                    (observation_key,),
                ).fetchone()
                if existing is not None:
                    original = self._transaction(connection, existing["rid"])
                    if original.context != context:
                        raise DefenseConflict("Defense observation identity changed")
                    return original
            if cursor_rid is not None:
                cursor = self._transaction(connection, cursor_rid)
                if cursor.kind != "cursor" or cursor.context != context:
                    raise DefenseConflict("Defense cursor context changed")
                if utc(deadline_at) > utc(cursor.deadline_at):
                    raise DefenseConflict("Defense action cannot extend its cursor deadline")
                existing = connection.execute(
                    "SELECT rid FROM defense_transactions WHERE defense_scope=? AND cursor_rid=?",
                    (context.defense_scope, cursor_rid),
                ).fetchone()
                if existing is not None:
                    if guard is not None:
                        guard.bind_action(
                            session_admission, existing["rid"], now=instant, connection=connection
                        )
                    return self._transaction(connection, existing["rid"])
            connection.execute(
                "INSERT INTO defense_transactions(rid,kind,host_id,defense_scope,context_json,"
                "context_sha256,owner,deadline_at,cursor_rid,phase,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new.rid,
                    kind,
                    context.host_id,
                    context.defense_scope,
                    canonical(context),
                    digest(context),
                    owner,
                    deadline_at,
                    cursor_rid,
                    "created",
                    new.created_at,
                    new.updated_at,
                ),
            )
            if observation_key is not None:
                connection.execute(
                    "INSERT INTO defense_observation_intents VALUES(?,?)",
                    (observation_key, new.rid),
                )
            if guard is not None:
                guard.bind_action(session_admission, new.rid, now=instant, connection=connection)
        return new

    def transaction(self, rid: str) -> DefenseTransaction:
        with self._connection() as connection:
            return self._transaction(connection, rid)

    def transactions(
        self, host_id: str | None = None, limit: int = 100
    ) -> tuple[DefenseTransaction, ...]:
        """Read bounded metadata; this list never grants dispatch or mode authority."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Defense transaction limit is invalid")
        if host_id is not None and (
            type(host_id) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", host_id) is None
        ):
            raise ValueError("Defense host identity is invalid")
        with self._connection() as connection:
            if host_id is None:
                rows = connection.execute(
                    "SELECT rid FROM defense_transactions "
                    "ORDER BY created_at DESC,rowid DESC LIMIT ?",
                    (limit,),
                )
            else:
                rows = connection.execute(
                    "SELECT rid FROM defense_transactions WHERE host_id=? "
                    "ORDER BY created_at DESC,rowid DESC LIMIT ?",
                    (host_id, limit),
                )
            return tuple(self._transaction(connection, row["rid"]) for row in rows)

    def history_hosts(self, *, after: str | None = None, limit: int = 20) -> tuple[str, ...]:
        """Discover local historical action targets, including retired registrations."""
        if after is not None:
            TypeAdapter(Host).validate_python(after, strict=True)
        if type(limit) is not int or not 1 <= limit <= 101:
            raise ValueError("Defense historical host page bounds are invalid")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT host_id FROM defense_transactions WHERE kind='action' "
                "AND (? IS NULL OR host_id COLLATE BINARY>?) "
                "ORDER BY host_id COLLATE BINARY LIMIT ?",
                (after, after, limit),
            ).fetchall()
            return tuple(
                TypeAdapter(Host).validate_python(row["host_id"], strict=True) for row in rows
            )

    def request(self, rid: str, op: Operation) -> DefenseRequest:
        """Recover an immutable typed intent without exporting stored wire bytes."""
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            request = self._request(connection, rid, op)
            self._bind_request(transaction, request)
            return request

    def latest_reply(self, rid: str) -> DefenseReply | None:
        """Read the latest accepted Root DTO; it never substitutes for a current mode ACK."""
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            row = connection.execute(
                "SELECT * FROM defense_observations WHERE rid=? AND accepted=1 "
                "ORDER BY observed_at DESC,rowid DESC LIMIT 1",
                (rid,),
            ).fetchone()
            if row is None:
                return None
            if row["receipt_bytes"] is None or _hash(row["receipt_bytes"]) != row["receipt_sha256"]:
                raise DefenseConflict("Defense latest receipt integrity failed")
            reply = DefenseReply.parse(row["receipt_bytes"])
            context = transaction.context
            if (
                reply.request_id != rid
                or reply.op != row["op"]
                or reply.state != row["state"]
                or reply.scope_sha256 != context.root_scope
                or reply.policy_sha256 != context.policy_sha256
                or reply.boot_ref != context.boot_ref
                or reply.binding_ref != context.binding_ref
                or reply.mode != context.mode
                or reply.mode_revision != context.wire_revision
            ):
                raise DefenseConflict("Defense latest receipt binding failed")
            if transaction.kind == "action":
                manifest = self._manifest(connection, rid)
                if (
                    reply.manifest_sha256 != manifest.sha256
                    or reply.action_id != manifest.action_id
                    or reply.cursor_id != manifest.cursor_id
                    or reply.deadline_at != manifest.deadline_at
                ):
                    raise DefenseConflict("Defense latest receipt manifest binding failed")
            return reply

    def save_request(
        self,
        rid: str,
        request: DefenseRequest,
        *,
        session_admission=None,
        now: datetime | None = None,
    ) -> RequestMetadata:
        request = DefenseRequest.parse(request.wire_bytes())
        raw = request.wire_bytes()
        with self._write() as connection:
            guard = None
            if request.op in {"prepare", "apply"}:
                guard = self.require_session_admission(
                    rid,
                    session_admission,
                    phase="preparing" if request.op == "prepare" else "applying",
                    now=now,
                    connection=connection,
                )
            elif session_admission is not None:
                raise DefenseConflict("Session tokens cannot authorize this request")
            transaction = self._transaction(connection, rid)
            self._bind_request(transaction, request)
            if request.op == "prepare":
                self._bind_prepare_source(connection, transaction, request)
            previous = connection.execute(
                "SELECT request_bytes FROM defense_requests WHERE rid=? AND op=?",
                (rid, request.op),
            ).fetchone()
            if previous is not None and previous["request_bytes"] != raw:
                raise DefenseConflict("Defense request identity is immutable")
            if previous is None:
                connection.execute(
                    "INSERT INTO defense_requests(rid,op,request_sha256,request_bytes,"
                    "dispatch_phase)"
                    " VALUES(?,?,?,?, 'intent')",
                    (rid, request.op, _hash(raw), raw),
                )
                if request.op == "prepare":
                    connection.execute(
                        "UPDATE defense_transactions SET phase='prepared_intent' WHERE rid=?",
                        (rid,),
                    )
            if guard is not None:
                guard.bind_request(session_admission, request, now=now, connection=connection)
        return self.request_metadata(rid, request.op)

    @staticmethod
    def _bind_prepare_source(
        connection: sqlite3.Connection, transaction: DefenseTransaction, request: DefenseRequest
    ) -> DefenseReply:
        if not isinstance(request.body, PrepareBody) or transaction.cursor_rid is None:
            raise DefenseConflict("Defense prepare needs an original cursor source")
        row = connection.execute(
            "SELECT receipt_bytes,receipt_sha256 FROM defense_observations WHERE rid=? "
            "AND accepted=1 AND state IN ('armed','attached') "
            "ORDER BY observed_at DESC,rowid DESC LIMIT 1",
            (transaction.cursor_rid,),
        ).fetchone()
        if row is None or _hash(row["receipt_bytes"]) != row["receipt_sha256"]:
            raise DefenseConflict("Defense prepare needs a confirmed cursor source")
        cursor = DefenseReply.parse(row["receipt_bytes"])
        body = request.body
        if cursor.cursor_id != body.cursor_id or not any(
            candidate.source_ref == body.source_ref
            and candidate.classification == "eligible"
            and candidate.evidence_sha256 == body.evidence_sha256
            for candidate in cursor.candidates
        ):
            raise DefenseConflict("Defense prepare source or evidence changed")
        return cursor

    @staticmethod
    def _bind_request(transaction: DefenseTransaction, request: DefenseRequest) -> None:
        context, body = transaction.context, request.body
        expected = {
            "cursor": {"arm", "query"},
            "action": {"prepare", "apply", "revoke", "query"},
            "mode": {"mode_sync", "query"},
        }[transaction.kind]
        if (
            request.request_id != transaction.rid
            or request.scope_sha256 != context.root_scope
            or request.op not in expected
        ):
            raise DefenseConflict("Defense request target changed")
        if isinstance(body, (PrepareBody, ModeBody)) and (
            body.policy_sha256 != context.policy_sha256
            or body.mode != context.mode
            or body.mode_revision != context.wire_revision
        ):
            raise DefenseConflict("Defense request mode or policy changed")
        if request.op == "arm" and getattr(body, "policy_sha256", None) != context.policy_sha256:
            raise DefenseConflict("Defense request policy changed")
        if isinstance(body, QueryBody) and body.kind != transaction.kind:
            raise DefenseConflict("Defense query kind changed")
        if isinstance(body, ActionBody) and body.manifest_sha256 != transaction.manifest_sha256:
            raise DefenseConflict("Defense request manifest changed")

    def request_metadata(self, rid: str, op: Operation) -> RequestMetadata:
        with self._connection() as connection:
            self._transaction(connection, rid)
            self._request(connection, rid, op)
            row = connection.execute(
                "SELECT * FROM defense_requests WHERE rid=? AND op=?",
                (rid, op),
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense request was not found")
            if row["reply_bytes"] is not None:
                parsed = DefenseReply.parse(row["reply_bytes"])
                if _hash(row["reply_bytes"]) != row["reply_sha256"] or parsed.request_id != rid:
                    raise DefenseConflict("Defense receipt integrity failed")
            return RequestMetadata(
                rid=rid,
                op=op,
                request_sha256=row["request_sha256"],
                dispatch_phase=row["dispatch_phase"],
                send_owner=row["send_owner"],
                send_started_at=row["send_started_at"],
                reply_sha256=row["reply_sha256"],
            )

    def _fresh_revoke_query(
        self,
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        instant: datetime,
    ) -> bool:
        """A known original active element may be removed while the unknown latch remains."""
        if transaction.kind != "action":
            return False
        row = connection.execute(
            "SELECT * FROM defense_observations WHERE rid=? "
            "ORDER BY observed_at DESC,rowid DESC LIMIT 1",
            (transaction.rid,),
        ).fetchone()
        if row is None or not row["accepted"] or row["op"] != "query" or row["state"] != "active":
            return False
        raw = row["receipt_bytes"]
        if raw is None or _hash(raw) != row["receipt_sha256"]:
            raise DefenseConflict("Defense revoke observation integrity failed")
        reply = DefenseReply.parse(raw)
        age = (instant - utc(row["observed_at"])).total_seconds()
        if (
            reply.state != "active"
            or reply.remaining_ms is None
            or not 0 <= age <= 5
            or age * 1000 >= reply.remaining_ms
        ):
            return False
        manifest = self._manifest(connection, transaction.rid)
        original = self._request(connection, transaction.rid, "prepare")
        return (
            reply.request_id == transaction.rid
            and reply.scope_sha256 == transaction.context.root_scope
            and reply.policy_sha256 == transaction.context.policy_sha256
            and reply.boot_ref == transaction.context.boot_ref
            and reply.binding_ref == transaction.context.binding_ref
            and reply.mode == transaction.context.mode
            and reply.mode_revision == transaction.context.wire_revision
            and rebuild_manifest(original, reply) == manifest
            and reply.manifest_sha256 == manifest.sha256
        )

    @staticmethod
    def _latch(
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        reason: ObservationReason,
        observed_at: str,
    ) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO defense_target_latches VALUES(?,?,?,?,?)",
            (
                transaction.context.host_id,
                transaction.context.defense_scope,
                reason,
                transaction.rid,
                observed_at,
            ),
        )

    def latched(self, host_id: str, defense_scope: str) -> bool:
        """An unresolved old binding also blocks this host's newly computed scope."""
        with self._connection() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM defense_target_latches WHERE host_id=?",
                    (host_id,),
                ).fetchone()
                is not None
            )

    @staticmethod
    def _charge(
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        usage: UsageClaim,
        instant: datetime,
        *,
        consume: bool,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM defense_usage WHERE intent_key=?",
            (usage.intent_key,),
        ).fetchone()
        if row is not None:
            if (
                row["kind"] != usage.kind
                or row["rid"] != transaction.rid
                or row["grant_ref"] != usage.grant_ref
                or row["provider_fingerprint"] != usage.provider_fingerprint
            ):
                raise DefenseConflict("Defense cost intent was already reserved")
            if consume and row["state"] == "reserved":
                connection.execute(
                    "UPDATE defense_usage SET state='consumed' WHERE intent_key=?",
                    (usage.intent_key,),
                )
            return
        day = instant.date().isoformat()
        total, today = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(charged_day=?),0) FROM defense_usage "
            "WHERE kind=? AND grant_ref=?",
            (day, usage.kind, usage.grant_ref),
        ).fetchone()
        if total >= usage.max_total or today >= usage.max_per_day:
            raise DefenseQuotaExceeded("Defense usage quota is exhausted")
        connection.execute(
            "INSERT INTO defense_usage VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                usage.intent_key,
                usage.kind,
                transaction.rid,
                transaction.context.host_id,
                transaction.context.defense_scope,
                usage.grant_ref,
                day,
                usage.provider_fingerprint,
                "consumed" if consume else "reserved",
                _stamp(instant),
            ),
        )

    @staticmethod
    def _require_prepare_window(
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        request: DefenseRequest,
        instant: datetime,
    ) -> None:
        root_cursor = DefenseStore._bind_prepare_source(connection, transaction, request)
        cursor = DefenseStore._transaction(connection, transaction.cursor_rid or "")
        row = connection.execute(
            "SELECT * FROM defense_observations WHERE rid=? "
            "ORDER BY observed_at DESC,rowid DESC LIMIT 1",
            (cursor.rid,),
        ).fetchone()
        if (
            cursor.query_required
            or cursor.phase not in {"armed", "attached"}
            or row is None
            or row["accepted"] != 1
            or row["op"] != "query"
            or row["receipt_sha256"] != _hash(canonical(root_cursor) + b"\n")
            or root_cursor.deadline_at is None
            or root_cursor.scope_sha256 != cursor.context.root_scope
            or root_cursor.policy_sha256 != cursor.context.policy_sha256
            or root_cursor.boot_ref != cursor.context.boot_ref
            or root_cursor.binding_ref != cursor.context.binding_ref
            or root_cursor.mode != cursor.context.mode
            or root_cursor.mode_revision != cursor.context.wire_revision
        ):
            raise DefenseConflict("Defense current cursor evidence is unavailable")
        DefenseStore._require_clock_window(
            created_at=cursor.created_at,
            deadline_at=cursor.deadline_at,
            observed_at=row["observed_at"],
            root_deadline_at=root_cursor.deadline_at,
            now=instant,
        )

    def begin_sendable(
        self,
        rid: str,
        op: Operation,
        *,
        context: DefenseContext,
        owner: str,
        usage: UsageClaim | None = None,
        now: datetime | None = None,
        lease: WorkerLease | None = None,
        session_admission=None,
    ) -> SendPermit | None:
        """Commit a unique send claim; an existing claim never produces a permit.

        The returned permit is usable only for this call's first dispatch. Losing
        it across a crash requires query of the same RID, regardless of outcome.
        """
        instant = _now(now)
        context = DefenseContext.model_validate_json(canonical(context))
        if usage is not None:
            usage = UsageClaim.model_validate_json(canonical(usage))
        if op == "query":
            raise DefenseConflict("Queries do not use mutation send permits")
        permit = None
        with self._write() as connection:
            guard = None
            if op in {"prepare", "apply"}:
                guard = self.require_session_admission(
                    rid,
                    session_admission,
                    phase="preparing" if op == "prepare" else "applying",
                    now=instant,
                    connection=connection,
                )
            elif session_admission is not None:
                raise DefenseConflict("Session tokens cannot authorize this dispatch")
            transaction = self._transaction(connection, rid)
            request = self._request(connection, rid, op)
            self._bind_request(transaction, request)
            if guard is not None:
                guard.bind_request(session_admission, request, now=instant, connection=connection)
            row = connection.execute(
                "SELECT dispatch_phase FROM defense_requests WHERE rid=? AND op=?",
                (rid, op),
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense request was not found")
            if row["dispatch_phase"] != "intent":
                return None
            if (
                transaction.owner != owner
                or (
                    op != "revoke"
                    and (transaction.context != context or instant >= utc(transaction.deadline_at))
                )
                or (op == "revoke" and not self._same_binding(transaction.context, context))
            ):
                raise DefenseConflict("Defense dispatch owner, deadline or epoch changed")
            if lease is not None:
                self.assert_worker(lease, now=instant, connection=connection)
                if lease.owner != owner:
                    raise DefenseConflict("Defense worker lease changed")
            if op in {"prepare", "apply", "revoke"}:
                if context.mode == "manual":
                    raise DefenseConflict("Manual mode cannot dispatch defense actions")
                if (
                    connection.execute(
                        "SELECT 1 FROM defense_target_latches WHERE host_id=?",
                        (context.host_id,),
                    ).fetchone()
                    is not None
                ) and not (
                    op == "revoke" and self._fresh_revoke_query(connection, transaction, instant)
                ):
                    raise DefenseConflict("Defense target requires reconciliation")
                if not self._mode_confirmed(connection, context):
                    raise DefenseConflict("Defense mode acknowledgement is pending")
            if op == "prepare" and (usage is None or usage.kind != "execution"):
                raise DefenseConflict("Defense prepare requires an execution reservation")
            if op == "prepare":
                self._require_prepare_window(connection, transaction, request, instant)
                if (
                    isinstance(request.body, PrepareBody)
                    and usage is not None
                    and (usage.grant_ref != request.body.controller_grant_ref)
                ):
                    raise DefenseConflict("Defense execution grant changed")
            if op == "apply":
                if transaction.phase != "ready" or usage is None or usage.kind != "execution":
                    raise DefenseConflict("Defense apply requires a ready reserved intent")
                if not connection.execute(
                    "SELECT 1 FROM defense_usage WHERE intent_key=? AND rid=? AND state='reserved'",
                    (usage.intent_key, rid),
                ).fetchone():
                    raise DefenseConflict("Defense apply has no original reservation")
                self._require_prepare_window(
                    connection, transaction, self._request(connection, rid, "prepare"), instant
                )
            if isinstance(request.body, ActionBody):
                if request.body.approval is not None:
                    self._require_approval(
                        connection, transaction, request.body.approval, instant, context=context
                    )
                elif context.mode != "auto" or op != "apply":
                    raise DefenseConflict("Defense operation needs exact confirmation")
            if usage is not None:
                if usage.kind != "execution" or op not in {"prepare", "apply"}:
                    raise DefenseConflict("Defense usage cannot authorize this operation")
                self._charge(connection, transaction, usage, instant, consume=op == "apply")
            if op == "revoke":
                # This new admission never changes the old prepare/apply context,
                # deadlines, grants or quota. The exact confirmation supplies its
                # independent lifetime; store admission and sendable atomically.
                connection.execute(
                    "INSERT INTO defense_op_admissions VALUES(?,'revoke',?,?,?)",
                    (rid, canonical(context), digest(context), _stamp(instant)),
                )
            phase = {
                "arm": "arm_sendable",
                "prepare": "prepare_sendable",
                "apply": "apply_sendable",
                "revoke": "revoke_sendable",
                "mode_sync": "mode_sendable",
            }[op]
            stamp = _stamp(instant)
            connection.execute(
                "UPDATE defense_requests SET dispatch_phase='sendable',send_owner=?,"
                "send_started_at=? WHERE rid=? AND op=?",
                (owner, stamp, rid, op),
            )
            connection.execute(
                "UPDATE defense_transactions SET phase=?,updated_at=?,query_required=1 WHERE rid=?",
                (phase, stamp, rid),
            )
            permit = SendPermit(
                rid=rid,
                op=op,
                request_sha256=_hash(request.wire_bytes()),
                owner=owner,
                epoch=context.epoch,
                committed_at=stamp,
            )
        # Deliberately after the context manager's successful COMMIT.
        return permit

    @staticmethod
    def _same_binding(original: DefenseContext, current: DefenseContext) -> bool:
        return all(
            getattr(original, name) == getattr(current, name)
            for name in (
                "host_id",
                "defense_scope",
                "registry_scope",
                "root_scope",
                "policy_sha256",
                "boot_ref",
                "binding_ref",
            )
        )

    @staticmethod
    def _op_admission(connection: sqlite3.Connection, rid: str) -> DefenseContext | None:
        row = connection.execute(
            "SELECT * FROM defense_op_admissions WHERE rid=? AND op='revoke'",
            (rid,),
        ).fetchone()
        if row is None:
            return None
        if _hash(row["context_json"]) != row["context_sha256"]:
            raise DefenseConflict("Defense revoke admission integrity failed")
        return DefenseContext.model_validate_json(row["context_json"])

    def revoke_admission(self, rid: str) -> DefenseContext | None:
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            context = self._op_admission(connection, rid)
            if context is not None and not self._same_binding(transaction.context, context):
                raise DefenseConflict("Defense revoke admission binding changed")
            return context

    @staticmethod
    def _manifest(connection: sqlite3.Connection, rid: str) -> DefenseManifest:
        row = connection.execute(
            "SELECT manifest_json,manifest_sha256 FROM defense_transactions WHERE rid=?",
            (rid,),
        ).fetchone()
        if row is None or row["manifest_json"] is None:
            raise DefenseConflict("Defense manifest was not confirmed")
        manifest = DefenseManifest.model_validate_json(row["manifest_json"])
        if manifest.sha256 != row["manifest_sha256"] or manifest.request_id != rid:
            raise DefenseConflict("Defense manifest integrity failed")
        return manifest

    def manifest(self, rid: str) -> DefenseManifest:
        with self._connection() as connection:
            self._transaction(connection, rid)
            return self._manifest(connection, rid)

    def save_approval(
        self,
        rid: str,
        approval: DefenseApproval,
        *,
        context: DefenseContext,
        controller_grant_ref: str,
        root_grant_ref: str,
        now: datetime | None = None,
    ) -> ApprovalMetadata:
        instant = _now(now)
        approval = DefenseApproval.model_validate_json(canonical(approval))
        context = DefenseContext.model_validate_json(canonical(context))
        metadata = ApprovalMetadata(
            approval=approval,
            global_revision=context.global_revision,
            wire_revision=context.wire_revision,
            controller_grant_ref=controller_grant_ref,
            root_grant_ref=root_grant_ref,
            statement_sha256=digest(approval),
            admission_context=context if approval.purpose == "revoke" else None,
        )
        with self._write() as connection:
            transaction = self._transaction(connection, rid)
            manifest = self._manifest(connection, rid)
            if (
                (approval.purpose == "apply" and transaction.context != context)
                or (
                    approval.purpose == "revoke"
                    and (
                        not self._same_binding(transaction.context, context)
                        or context.mode == "manual"
                    )
                )
                or approval.request_id != rid
                or approval.manifest_sha256 != manifest.sha256
                or controller_grant_ref != manifest.controller_grant_ref
                or root_grant_ref != manifest.root_grant_ref
                or not utc(approval.approved_at) <= instant < utc(approval.expires_at)
                or approval.purpose == "apply"
                and utc(approval.expires_at) > utc(manifest.deadline_at)
            ):
                raise DefenseConflict("Defense confirmation binding or lifetime changed")
            previous = connection.execute(
                "SELECT typed_statement FROM defense_authorizations WHERE rid=? AND purpose=?",
                (rid, approval.purpose),
            ).fetchone()
            raw = canonical(metadata)
            if previous is not None and previous["typed_statement"] != raw:
                raise DefenseConflict("Defense confirmation cannot be replaced")
            if previous is None:
                connection.execute(
                    "INSERT INTO defense_authorizations(approval_id,rid,purpose,"
                    "statement_sha256,typed_statement) VALUES(?,?,?,?,?)",
                    (approval.approval_id, rid, approval.purpose, digest(metadata), raw),
                )
        return metadata

    @staticmethod
    def _require_approval(
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        approval: DefenseApproval,
        instant: datetime,
        *,
        context: DefenseContext,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM defense_authorizations WHERE rid=? AND purpose=?",
            (transaction.rid, approval.purpose),
        ).fetchone()
        if row is None or _hash(row["typed_statement"]) != row["statement_sha256"]:
            raise DefenseConflict("Defense confirmation was not durably recorded")
        metadata = ApprovalMetadata.model_validate_json(row["typed_statement"])
        if (
            metadata.approval != approval
            or metadata.statement_sha256 != digest(approval)
            or metadata.global_revision != context.global_revision
            or metadata.wire_revision != context.wire_revision
            or (
                approval.purpose == "apply"
                and (context != transaction.context or metadata.admission_context is not None)
            )
            or (approval.purpose == "revoke" and metadata.admission_context != context)
            or not utc(approval.approved_at) <= instant < utc(approval.expires_at)
        ):
            raise DefenseConflict("Defense confirmation is stale")
        if row["dispatch_state"] != "recorded":
            raise DefenseConflict("Defense confirmation already belongs to a dispatch")
        # Consume the exact declaration in the same transaction as usage and
        # sendable. A failed COMMIT preserves all three as unclaimed.
        connection.execute(
            "UPDATE defense_authorizations SET dispatch_state='used',used_at=? WHERE approval_id=?",
            (_stamp(instant), approval.approval_id),
        )

    def approval_record(
        self, rid: str, purpose: Literal["apply", "revoke"] = "apply"
    ) -> AuthorizationRecord | None:
        if purpose not in {"apply", "revoke"}:
            raise DefenseConflict("Defense authorization purpose is invalid")
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            row = connection.execute(
                "SELECT * FROM defense_authorizations WHERE rid=? AND purpose=?", (rid, purpose)
            ).fetchone()
            if row is None:
                return None
            if (
                len(row["typed_statement"]) > 4096
                or _hash(row["typed_statement"]) != row["statement_sha256"]
            ):
                raise DefenseConflict("Defense authorization statement integrity failed")
            metadata = ApprovalMetadata.model_validate_json(row["typed_statement"])
            approval, context, manifest = (
                metadata.approval,
                transaction.context,
                self._manifest(connection, rid),
            )
            admission = context if purpose == "apply" else metadata.admission_context
            if (
                admission is None
                or approval.approval_id != row["approval_id"]
                or approval.request_id != rid
                or approval.purpose != purpose
                or metadata.statement_sha256 != digest(approval)
                or approval.manifest_sha256 != manifest.sha256
                or metadata.controller_grant_ref != manifest.controller_grant_ref
                or metadata.root_grant_ref != manifest.root_grant_ref
                or metadata.global_revision != admission.global_revision
                or metadata.wire_revision != admission.wire_revision
                or (purpose == "apply" and metadata.admission_context is not None)
                or not self._same_binding(context, admission)
            ):
                raise DefenseConflict("Defense authorization original binding failed")
            record = AuthorizationRecord(
                metadata=metadata, dispatch_state=row["dispatch_state"], used_at=row["used_at"]
            )
            request_row = connection.execute(
                "SELECT * FROM defense_requests WHERE rid=? AND op=?", (rid, purpose)
            ).fetchone()
            if request_row is None:
                if record.dispatch_state == "used":
                    raise DefenseConflict("Defense used authorization has no original operation")
                return record
            request = self._request(connection, rid, purpose)
            if not isinstance(request.body, ActionBody) or request.body.approval != approval:
                raise DefenseConflict("Defense authorization differs from original operation")
            if record.dispatch_state == "used" and (
                request_row["send_started_at"] != record.used_at
                or request_row["send_owner"] != transaction.owner
                or request_row["dispatch_phase"] not in {"sendable", "replied", "unknown"}
                or record.used_at is None
                or not utc(approval.approved_at) <= utc(record.used_at) < utc(approval.expires_at)
            ):
                raise DefenseConflict("Defense authorization use does not close")
            if record.dispatch_state == "recorded" and request_row["send_started_at"] is not None:
                raise DefenseConflict("Defense dispatched authorization is not marked used")
            return record

    def approval(
        self, rid: str, purpose: Literal["apply", "revoke"] = "apply"
    ) -> AuthorizationRecord | None:
        return self.approval_record(rid, purpose)

    def execution_usage(self, rid: str) -> UsageMetadata | None:
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            if transaction.kind != "action":
                raise DefenseConflict("Defense execution usage requires an original action")
            rows = connection.execute(
                "SELECT * FROM defense_usage WHERE rid=? AND kind='execution' LIMIT 2", (rid,)
            ).fetchall()
            if not rows:
                return None
            if len(rows) != 1:
                raise DefenseConflict("Defense action has ambiguous execution usage")
            usage = UsageMetadata.model_validate(dict(rows[0]))
            request = self._request(connection, rid, "prepare")
            expected = digest(
                {
                    "channel": "ssh-defense-execution/v1",
                    "defense_scope": transaction.context.defense_scope,
                    "cursor_rid": transaction.cursor_rid,
                }
            )
            if (
                not isinstance(request.body, PrepareBody)
                or usage.intent_key != expected
                or usage.host_id != transaction.context.host_id
                or usage.defense_scope != transaction.context.defense_scope
                or usage.grant_ref != request.body.controller_grant_ref
                or usage.provider_fingerprint is not None
                or usage.charged_day != utc(usage.created_at).date().isoformat()
                or utc(usage.created_at) < utc(transaction.created_at)
            ):
                raise DefenseConflict("Defense execution usage identity changed")
            return usage

    def query_call(self, rid: str) -> DefenseCall:
        """Build typed reconciliation context; never export stored wire bytes."""
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            manifest = None
            prepare = None
            if transaction.kind == "action":
                prepare = self._request(connection, rid, "prepare")
                if transaction.manifest_sha256 is not None:
                    manifest = self._manifest(connection, rid)
            request = DefenseRequest(
                v=1,
                op="query",
                request_id=rid,
                scope_sha256=transaction.context.root_scope,
                body=QueryBody(kind=transaction.kind),
            )
            return DefenseCall(
                request,
                prepare_request=prepare,
                expected_manifest=manifest,
                expected_mode=transaction.context.mode if transaction.kind == "mode" else None,
                expected_mode_revision=(
                    transaction.context.wire_revision if transaction.kind == "mode" else None
                ),
            )

    def _observation(
        self,
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        *,
        op: Operation,
        state: State | Literal["unavailable"],
        observed_at: str,
        raw: bytes | None,
        accepted: bool,
        reason: ObservationReason,
    ) -> ObservationMetadata:
        metadata = ObservationMetadata(
            observation_id=secrets.token_hex(16),
            rid=transaction.rid,
            op=op,
            state=state,
            observed_at=observed_at,
            receipt_sha256=None if raw is None else _hash(raw),
            accepted=accepted,
            reason=reason,
        )
        connection.execute(
            "INSERT INTO defense_observations VALUES(?,?,?,?,?,?,?,?,?)",
            (
                metadata.observation_id,
                transaction.rid,
                op,
                state,
                observed_at,
                metadata.receipt_sha256,
                raw,
                int(accepted),
                reason,
            ),
        )
        if reason != "ok" and not (transaction.kind == "mode" and reason == "stale"):
            self._latch(connection, transaction, reason, observed_at)
        return metadata

    def record_unavailable(
        self,
        rid: str,
        op: Operation,
        *,
        now: datetime | None = None,
        context: DefenseContext | None = None,
        commit_guard: Callable[[sqlite3.Connection], None] | None = None,
        session_admission=None,
    ) -> ObservationMetadata:
        if commit_guard is not None and op != "query":
            raise DefenseConflict("An observation fence only applies to read-only queries")
        stamp = _stamp(_now(now))
        with self._write() as connection:
            if op in {"prepare", "apply"}:
                self.require_session_admission(
                    rid,
                    session_admission,
                    phase="preparing" if op == "prepare" else "applying",
                    now=now,
                    connection=connection,
                )
            elif session_admission is not None:
                raise DefenseConflict("Session tokens cannot authorize this observation")
            if commit_guard is not None and commit_guard(connection) is not None:
                raise DefenseConflict("The read-only observation fence did not close")
            transaction = self._transaction(connection, rid)
            reason: ObservationReason = "unavailable"
            if transaction.kind == "mode":
                current = connection.execute(
                    "SELECT context_json FROM defense_mode_ack WHERE mode_rid=?",
                    (rid,),
                ).fetchone()
                expected = transaction.context if context is None else context
                if current is not None and current["context_json"] != canonical(expected):
                    reason = "stale"
            metadata = self._observation(
                connection,
                transaction,
                op=op,
                state="unavailable",
                observed_at=stamp,
                raw=None,
                accepted=False,
                reason=reason,
            )
            connection.execute(
                "UPDATE defense_transactions SET phase='unknown',query_required=1,"
                "last_error_code='unavailable',updated_at=? WHERE rid=?",
                (stamp, rid),
            )
            connection.execute(
                "UPDATE defense_requests SET dispatch_phase='unknown' WHERE rid=? AND op=? "
                "AND dispatch_phase='sendable'",
                (rid, op),
            )
            connection.execute("UPDATE defense_usage SET state='unknown' WHERE rid=?", (rid,))
            if transaction.kind == "mode":
                connection.execute(
                    "UPDATE defense_mode_ack SET status='unknown',checked_at=? WHERE mode_rid=? "
                    "AND context_json=?",
                    (stamp, rid, canonical(transaction.context if context is None else context)),
                )
                self._record_mode_history(connection, rid)
        return metadata

    def record_reply(
        self,
        rid: str,
        op: Operation,
        reply: DefenseReply,
        *,
        context: DefenseContext,
        now: datetime | None = None,
        commit_guard: Callable[[sqlite3.Connection], None] | None = None,
        session_admission=None,
    ) -> ObservationMetadata:
        """Append every validated DTO; reject unsafe transitions without erasing facts.

        Only a mode query can confirm a pending mode ACK. An action reply's mode
        belongs to its historical manifest and never acknowledges current mode.
        """
        if commit_guard is not None and op != "query":
            raise DefenseConflict("An observation fence only applies to read-only queries")
        instant, raw = _now(now), canonical(reply) + b"\n"
        context = DefenseContext.model_validate_json(canonical(context))
        reply = DefenseReply.parse(raw)
        stamp = _stamp(instant)
        with self._write() as connection:
            if op in {"prepare", "apply"}:
                self.require_session_admission(
                    rid,
                    session_admission,
                    phase="preparing" if op == "prepare" else "applying",
                    now=instant,
                    connection=connection,
                )
            elif session_admission is not None:
                raise DefenseConflict("Session tokens cannot authorize this observation")
            if commit_guard is not None and commit_guard(connection) is not None:
                raise DefenseConflict("The read-only observation fence did not close")
            transaction = self._transaction(connection, rid)
            source_op = {"cursor": "arm", "action": "prepare", "mode": "mode_sync"}[
                transaction.kind
            ]
            original = self._request(connection, rid, source_op if op == "query" else op)
            self._bind_request(transaction, original)
            reason = self._reply_reason(connection, transaction, op, reply, context, stamp)
            send_state = connection.execute(
                "SELECT dispatch_phase FROM defense_requests WHERE rid=? AND op=?",
                (rid, source_op if op == "query" else op),
            ).fetchone()
            if (send_state is None or send_state["dispatch_phase"] == "intent") and (
                reply.state not in {"rejected", "not_found"}
            ):
                reason = "binding_changed"
            manifest = None
            if (
                reason == "ok"
                and transaction.kind == "action"
                and reply.state
                not in {
                    "rejected",
                    "not_found",
                    "unknown",
                }
            ):
                manifest = rebuild_manifest(self._request(connection, rid, "prepare"), reply)
                if manifest.sha256 != reply.manifest_sha256 or transaction.manifest_sha256 not in {
                    None,
                    manifest.sha256,
                }:
                    reason = "binding_changed"
            accepted = reason == "ok"
            metadata = self._observation(
                connection,
                transaction,
                op=op,
                state=reply.state,
                observed_at=stamp,
                raw=raw,
                accepted=accepted,
                reason=reason,
            )
            if op != "query":
                # The first original receipt is immutable. Queries go only to history.
                connection.execute(
                    "UPDATE defense_requests SET reply_bytes=?,reply_sha256=?,"
                    "dispatch_phase='replied' "
                    "WHERE rid=? AND op=? AND reply_bytes IS NULL AND dispatch_phase!='intent'",
                    (raw, _hash(raw), rid, op),
                )
            if not accepted:
                phase = "rejected" if reason == "rejected" else "unknown"
                connection.execute(
                    "UPDATE defense_transactions SET phase=?,query_required=1,last_error_code=?,"
                    "updated_at=? WHERE rid=?",
                    (phase, reason, stamp, rid),
                )
                connection.execute("UPDATE defense_usage SET state='unknown' WHERE rid=?", (rid,))
                if transaction.kind == "mode":
                    connection.execute(
                        "UPDATE defense_mode_ack SET status='unknown',checked_at=? "
                        "WHERE mode_rid=? AND context_json=?",
                        (stamp, rid, canonical(context)),
                    )
                    self._record_mode_history(connection, rid)
            else:
                connection.execute(
                    "UPDATE defense_transactions SET phase=?,updated_at=?,query_required=0,"
                    "last_error_code=NULL WHERE rid=?",
                    (reply.state, stamp, rid),
                )
                if manifest is not None and transaction.manifest_sha256 is None:
                    connection.execute(
                        "UPDATE defense_transactions SET manifest_sha256=?,manifest_json=?,"
                        "action_id=? WHERE rid=?",
                        (manifest.sha256, canonical(manifest), manifest.action_id, rid),
                    )
                if (
                    reply.state in {"ready", "active", "expired", "revoked"}
                    and transaction.kind == "action"
                ):
                    connection.execute(
                        "INSERT INTO defense_last_confirmed VALUES(?,?,?,?,?,?,?) "
                        "ON CONFLICT(host_id,defense_scope,rid) DO UPDATE SET state=excluded.state,"
                        "remaining_ms=excluded.remaining_ms,observed_at=excluded.observed_at,"
                        "receipt_sha256=excluded.receipt_sha256",
                        (
                            context.host_id,
                            context.defense_scope,
                            rid,
                            reply.state,
                            reply.remaining_ms,
                            stamp,
                            _hash(raw),
                        ),
                    )
                if transaction.kind == "mode" and op == "query" and reply.state == "synced":
                    connection.execute(
                        "INSERT INTO defense_mode_query_bindings VALUES(?,?,?,?)",
                        (metadata.observation_id, rid, canonical(context), digest(context)),
                    )
                    connection.execute(
                        "UPDATE defense_mode_ack SET status='confirmed',checked_at=?,"
                        "receipt_sha256=? "
                        "WHERE mode_rid=? AND context_json=?",
                        (stamp, _hash(raw), rid, canonical(context)),
                    )
                    self._record_mode_history(connection, rid)
        return metadata

    @staticmethod
    def _reply_reason(
        connection: sqlite3.Connection,
        transaction: DefenseTransaction,
        op: Operation,
        reply: DefenseReply,
        context: DefenseContext,
        stamp: str,
    ) -> ObservationReason:
        original = transaction.context
        historical_action = transaction.kind == "action" and op in {"query", "revoke"}
        if transaction.kind == "mode" and op == "query":
            # A fresh read of one existing Root mode RID can confirm a new local
            # sync generation. A delayed old worker cannot clear its new pending.
            ack = connection.execute(
                "SELECT context_json FROM defense_mode_ack WHERE mode_rid=?",
                (transaction.rid,),
            ).fetchone()
            if (
                not DefenseStore._same_binding(original, context)
                or context.mode != original.mode
                or context.global_revision != original.global_revision
                or context.wire_revision != original.wire_revision
            ):
                return "binding_changed"
            if ack is None or ack["context_json"] != canonical(context):
                return "stale"
        elif historical_action:
            if not DefenseStore._same_binding(original, context):
                return "binding_changed"
            if (
                op == "revoke"
                and DefenseStore._op_admission(connection, transaction.rid) != context
            ):
                return "binding_changed"
        elif context != original:
            return "binding_changed"
        if (
            reply.op != op
            or reply.request_id != transaction.rid
            or reply.scope_sha256 != original.root_scope
            or reply.policy_sha256 != original.policy_sha256
            or reply.boot_ref != original.boot_ref
            or reply.binding_ref != original.binding_ref
            or reply.mode != original.mode
            or reply.mode_revision != original.wire_revision
        ):
            return "binding_changed"
        allowed = {
            "cursor": {"armed", "attached", "consumed", "expired", "invalid"},
            "action": {"ready", "ready_expired", "active", "expired", "revoked", "unknown"},
            "mode": {"synced"},
        }[transaction.kind] | {"rejected", "not_found"}
        if reply.state not in allowed:
            return "binding_changed"
        if transaction.kind == "mode" and any(
            value is not None
            for value in (
                reply.action_id,
                reply.cursor_id,
                reply.manifest_sha256,
                reply.deadline_at,
                reply.remaining_ms,
            )
        ):
            return "binding_changed"
        if (
            transaction.kind == "action"
            and reply.state not in {"rejected", "not_found"}
            and (
                reply.action_id is None
                or reply.cursor_id is None
                or reply.manifest_sha256 is None
                or reply.deadline_at is None
                or reply.candidates
            )
        ):
            return "binding_changed"
        if reply.state in {"unknown", "not_found", "rejected"}:
            return reply.state
        if transaction.kind == "cursor":
            old_cursor = connection.execute(
                "SELECT receipt_bytes,receipt_sha256 FROM defense_observations WHERE rid=? "
                "AND accepted=1 ORDER BY observed_at DESC,rowid DESC LIMIT 1",
                (transaction.rid,),
            ).fetchone()
            if old_cursor is not None:
                if _hash(old_cursor["receipt_bytes"]) != old_cursor["receipt_sha256"]:
                    raise DefenseConflict("Defense cursor receipt integrity failed")
                previous_cursor = DefenseReply.parse(old_cursor["receipt_bytes"])
                if (
                    previous_cursor.cursor_id != reply.cursor_id
                    or previous_cursor.deadline_at != reply.deadline_at
                ):
                    return "binding_changed"
                if previous_cursor.state in {"expired", "consumed", "invalid"} and (
                    reply.state != previous_cursor.state
                ):
                    return "terminal_regression"
        if transaction.kind == "action":
            terminal = connection.execute(
                "SELECT state FROM defense_observations WHERE rid=? AND accepted=1 "
                "AND state='ready_expired' LIMIT 1",
                (transaction.rid,),
            ).fetchone()
            if terminal is not None and reply.state != "ready_expired":
                return "terminal_regression"
        previous = connection.execute(
            "SELECT * FROM defense_last_confirmed WHERE rid=?",
            (transaction.rid,),
        ).fetchone()
        latest = connection.execute(
            "SELECT observed_at FROM defense_observations WHERE rid=? "
            "ORDER BY observed_at DESC LIMIT 1",
            (transaction.rid,),
        ).fetchone()
        if latest is not None and utc(stamp) < utc(latest["observed_at"]):
            return "stale"
        if previous is not None:
            if previous["state"] in {"expired", "revoked"} and reply.state != previous["state"]:
                return "terminal_regression"
            if previous["state"] == "active" and reply.state in {"ready", "ready_expired"}:
                return "terminal_regression"
            if (
                reply.state == "active"
                and previous["state"] == "active"
                and reply.remaining_ms is not None
                and reply.remaining_ms > previous["remaining_ms"]
            ):
                return "ttl_increased"
        return "ok"

    @staticmethod
    def _observation_record(
        connection: sqlite3.Connection, observation_id: str
    ) -> SequencedObservation:
        TypeAdapter(Identifier).validate_python(observation_id, strict=True)
        row = connection.execute(
            "SELECT rowid AS sequence,* FROM defense_observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        if row is None or type(row["accepted"]) is not int or row["accepted"] not in {0, 1}:
            raise DefenseConflict("Defense exact observation was not found or is invalid")
        transaction = DefenseStore._transaction(connection, row["rid"])
        metadata = ObservationMetadata(
            observation_id=row["observation_id"],
            rid=row["rid"],
            op=row["op"],
            state=row["state"],
            observed_at=row["observed_at"],
            receipt_sha256=row["receipt_sha256"],
            accepted=bool(row["accepted"]),
            reason=row["reason"],
        )
        reply = None
        if row["receipt_bytes"] is None:
            if (
                metadata.accepted
                or metadata.receipt_sha256 is not None
                or metadata.state != "unavailable"
            ):
                raise DefenseConflict("Defense missing observation receipt cannot prove a state")
        else:
            if (
                len(row["receipt_bytes"]) > 4096
                or _hash(row["receipt_bytes"]) != metadata.receipt_sha256
            ):
                raise DefenseConflict("Defense exact observation receipt integrity failed")
            reply = DefenseReply.parse(row["receipt_bytes"])
            if (
                reply.request_id != transaction.rid
                or reply.op != metadata.op
                or reply.state != metadata.state
            ):
                raise DefenseConflict("Defense exact observation receipt references changed")
            if metadata.accepted:
                context = transaction.context
                if (
                    reply.scope_sha256 != context.root_scope
                    or reply.policy_sha256 != context.policy_sha256
                    or reply.boot_ref != context.boot_ref
                    or reply.binding_ref != context.binding_ref
                    or reply.mode != context.mode
                    or reply.mode_revision != context.wire_revision
                    or metadata.reason != "ok"
                ):
                    raise DefenseConflict("Defense exact observation context changed")
                if transaction.kind == "action":
                    manifest = DefenseStore._manifest(connection, transaction.rid)
                    if (
                        reply.manifest_sha256 != manifest.sha256
                        or reply.action_id != manifest.action_id
                        or reply.cursor_id != manifest.cursor_id
                        or reply.deadline_at != manifest.deadline_at
                    ):
                        raise DefenseConflict("Defense exact observation manifest changed")
        return SequencedObservation(sequence=row["sequence"], observation=metadata, reply=reply)

    def observation_record(self, observation_id: str) -> SequencedObservation:
        """Read the exact inserted observation; no fallback to an older accepted fact."""
        with self._connection() as connection:
            return self._observation_record(connection, observation_id)

    def latest_observation(self, rid: str) -> SequencedObservation | None:
        with self._connection() as connection:
            self._transaction(connection, rid)
            row = connection.execute(
                "SELECT observation_id FROM defense_observations WHERE rid=? "
                "ORDER BY rowid DESC LIMIT 1",
                (rid,),
            ).fetchone()
            return (
                None if row is None else self._observation_record(connection, row["observation_id"])
            )

    def observations(self, rid: str) -> tuple[ObservationMetadata, ...]:
        with self._connection() as connection:
            self._transaction(connection, rid)
            results = []
            for row in connection.execute(
                "SELECT * FROM defense_observations WHERE rid=? ORDER BY observed_at,rowid",
                (rid,),
            ):
                if row["receipt_bytes"] is not None:
                    reply = DefenseReply.parse(row["receipt_bytes"])
                    if (
                        _hash(row["receipt_bytes"]) != row["receipt_sha256"]
                        or reply.request_id != rid
                        or reply.op != row["op"]
                        or reply.state != row["state"]
                    ):
                        raise DefenseConflict("Defense observation integrity failed")
                results.append(
                    ObservationMetadata(
                        observation_id=row["observation_id"],
                        rid=rid,
                        op=row["op"],
                        state=row["state"],
                        observed_at=row["observed_at"],
                        receipt_sha256=row["receipt_sha256"],
                        accepted=bool(row["accepted"]),
                        reason=row["reason"],
                    )
                )
            return tuple(results)

    def last_confirmed(self, rid: str) -> ConfirmedMetadata | None:
        with self._connection() as connection:
            self._transaction(connection, rid)
            row = connection.execute(
                "SELECT * FROM defense_last_confirmed WHERE rid=?", (rid,)
            ).fetchone()
            if row is not None:
                observation = connection.execute(
                    "SELECT receipt_bytes FROM defense_observations WHERE rid=? AND accepted=1 "
                    "AND receipt_sha256=? AND observed_at=?",
                    (rid, row["receipt_sha256"], row["observed_at"]),
                ).fetchone()
                if (
                    observation is None
                    or _hash(observation["receipt_bytes"]) != row["receipt_sha256"]
                ):
                    raise DefenseConflict("Defense confirmed receipt integrity failed")
                receipt = DefenseReply.parse(observation["receipt_bytes"])
                if (
                    receipt.request_id != rid
                    or receipt.state != row["state"]
                    or receipt.remaining_ms != row["remaining_ms"]
                ):
                    raise DefenseConflict("Defense confirmed receipt binding failed")
            return (
                None
                if row is None
                else ConfirmedMetadata(
                    rid=rid,
                    state=row["state"],
                    remaining_ms=row["remaining_ms"],
                    observed_at=row["observed_at"],
                    receipt_sha256=row["receipt_sha256"],
                )
            )

    def register_mode_pending(
        self, rid: str, *, context: DefenseContext | None = None, now: datetime | None = None
    ) -> ModeAckMetadata:
        stamp = _stamp(_now(now))
        with self._write() as connection:
            transaction = self._transaction(connection, rid)
            if transaction.kind != "mode":
                raise DefenseConflict("Defense mode ACK requires a mode RID")
            original = transaction.context
            context = (
                original
                if context is None
                else DefenseContext.model_validate_json(canonical(context))
            )
            if (
                not self._same_binding(original, context)
                or context.mode != original.mode
                or context.global_revision != original.global_revision
                or context.wire_revision != original.wire_revision
            ):
                raise DefenseConflict("Defense mode intent binding changed")
            previous = connection.execute(
                "SELECT * FROM defense_mode_ack WHERE host_id=? AND registry_scope=? "
                "AND global_revision=?",
                (context.host_id, context.registry_scope, context.global_revision),
            ).fetchone()
            if previous is not None and previous["mode_rid"] != rid:
                raise DefenseConflict("Defense mode intent is immutable")
            if previous is None:
                connection.execute(
                    "INSERT INTO defense_mode_ack VALUES(?,?,?,?,?,?,?,NULL)",
                    (
                        context.host_id,
                        context.registry_scope,
                        context.global_revision,
                        canonical(context),
                        rid,
                        "pending",
                        stamp,
                    ),
                )
            elif previous["context_json"] != canonical(context):
                current = DefenseContext.model_validate_json(previous["context_json"])
                if context.epoch <= current.epoch:
                    raise DefenseConflict("Defense mode sync generation is stale")
                connection.execute(
                    "UPDATE defense_mode_ack SET context_json=?,status='pending',checked_at=?,"
                    "receipt_sha256=NULL WHERE mode_rid=?",
                    (canonical(context), stamp, rid),
                )
            self._record_mode_history(connection, rid)
        result = self.mode_ack(context)
        if result is None:
            raise DefenseConflict("Defense mode intent was not found")
        return result

    @staticmethod
    def _record_mode_history(connection: sqlite3.Connection, rid: str) -> None:
        row = connection.execute(
            "SELECT * FROM defense_mode_ack WHERE mode_rid=?",
            (rid,),
        ).fetchone()
        if row is None:
            return
        snapshot = ModeAckMetadata(
            context=DefenseContext.model_validate_json(row["context_json"]),
            mode_rid=rid,
            status=row["status"],
            checked_at=row["checked_at"],
            receipt_sha256=row["receipt_sha256"],
        )
        connection.execute(
            "INSERT OR IGNORE INTO defense_mode_ack_history VALUES(?,?,?)",
            (digest(snapshot), rid, canonical(snapshot)),
        )

    def mode_ack_history(self, rid: str) -> tuple[ModeAckMetadata, ...]:
        with self._connection() as connection:
            transaction = self._transaction(connection, rid)
            results = []
            for row in connection.execute(
                "SELECT * FROM defense_mode_ack_history WHERE mode_rid=? ORDER BY rowid",
                (rid,),
            ):
                if _hash(row["typed_snapshot"]) != row["snapshot_sha256"]:
                    raise DefenseConflict("Defense mode ACK history integrity failed")
                snapshot = ModeAckMetadata.model_validate_json(row["typed_snapshot"])
                if snapshot.mode_rid != rid or not self._same_binding(
                    transaction.context, snapshot.context
                ):
                    raise DefenseConflict("Defense mode ACK history binding changed")
                results.append(snapshot)
            return tuple(results)

    @staticmethod
    def _mode_confirmed(connection: sqlite3.Connection, context: DefenseContext) -> bool:
        row = connection.execute(
            "SELECT * FROM defense_mode_ack WHERE host_id=? AND registry_scope=? "
            "AND global_revision=?",
            (context.host_id, context.registry_scope, context.global_revision),
        ).fetchone()
        if row is None or row["status"] != "confirmed" or row["context_json"] != canonical(context):
            return False
        observation = connection.execute(
            "SELECT o.receipt_bytes,b.context_json,b.context_sha256 FROM defense_observations o "
            "JOIN defense_mode_query_bindings b ON b.observation_id=o.observation_id "
            "WHERE o.rid=? AND o.op='query' AND o.state='synced' AND o.accepted=1 "
            "AND o.receipt_sha256=? AND o.observed_at=? AND b.context_sha256=?",
            (row["mode_rid"], row["receipt_sha256"], row["checked_at"], digest(context)),
        ).fetchone()
        if (
            observation is None
            or _hash(observation["receipt_bytes"]) != row["receipt_sha256"]
            or _hash(observation["context_json"]) != observation["context_sha256"]
            or observation["context_json"] != canonical(context)
        ):
            raise DefenseConflict("Defense mode acknowledgement integrity failed")
        receipt = DefenseReply.parse(observation["receipt_bytes"])
        if (
            receipt.request_id != row["mode_rid"]
            or receipt.op != "query"
            or receipt.state != "synced"
            or receipt.scope_sha256 != context.root_scope
            or receipt.policy_sha256 != context.policy_sha256
            or receipt.boot_ref != context.boot_ref
            or receipt.binding_ref != context.binding_ref
            or receipt.mode != context.mode
            or receipt.mode_revision != context.wire_revision
        ):
            raise DefenseConflict("Defense mode acknowledgement binding failed")
        return True

    def mode_ack(self, context: DefenseContext) -> ModeAckMetadata | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM defense_mode_ack WHERE host_id=? AND registry_scope=? "
                "AND global_revision=?",
                (context.host_id, context.registry_scope, context.global_revision),
            ).fetchone()
            if row is None:
                return None
            actual = DefenseContext.model_validate_json(row["context_json"])
            if actual != context:
                raise DefenseConflict("Defense mode context changed")
            self._transaction(connection, row["mode_rid"])
            if row["status"] == "confirmed":
                self._mode_confirmed(connection, context)
            return ModeAckMetadata(
                context=actual,
                mode_rid=row["mode_rid"],
                status=row["status"],
                checked_at=row["checked_at"],
                receipt_sha256=row["receipt_sha256"],
            )

    def mode_rid(self, context: DefenseContext) -> Identifier | None:
        """Find an existing same-revision mode intent without treating its ACK as current.

        A new local sync generation reuses this RID, marks it pending with
        register_mode_pending(context=current), and sends only a fresh query.
        """
        context = DefenseContext.model_validate_json(canonical(context))
        with self._connection() as connection:
            row = connection.execute(
                "SELECT mode_rid FROM defense_mode_ack WHERE host_id=? AND registry_scope=? "
                "AND global_revision=?",
                (context.host_id, context.registry_scope, context.global_revision),
            ).fetchone()
            if row is None:
                return None
            original = self._transaction(connection, row["mode_rid"])
            if (
                not self._same_binding(original.context, context)
                or original.context.mode != context.mode
                or original.context.wire_revision != context.wire_revision
            ):
                raise DefenseConflict("Defense mode intent binding changed")
            return original.rid

    @staticmethod
    def _source_time_data(
        connection: sqlite3.Connection, source: DefenseSource
    ) -> tuple[_ControllerTimeData, DefenseReply]:
        transaction = DefenseStore._transaction(connection, source.cursor_rid)
        context = transaction.context
        if transaction.kind != "cursor" or any(
            getattr(source, name) != getattr(context, name)
            for name in ("defense_scope", "root_scope", "policy_sha256", "boot_ref", "binding_ref")
        ):
            raise DefenseConflict("Defense source time context changed")
        original = DefenseStore._request(connection, transaction.rid, "arm")
        DefenseStore._bind_request(transaction, original)
        row = connection.execute(
            "SELECT * FROM defense_observations WHERE rid=? AND accepted=1 AND op='query' "
            "AND receipt_sha256=? AND observed_at=? LIMIT 1",
            (source.cursor_rid, source.root_reply_sha256, _stamp(utc(source.observed_at))),
        ).fetchone()
        if row is None or _hash(row["receipt_bytes"]) != source.root_reply_sha256:
            raise DefenseConflict("Defense source time receipt integrity failed")
        reply = DefenseReply.parse(row["receipt_bytes"])
        if (
            reply.request_id != source.cursor_rid
            or reply.op != "query"
            or reply.state not in {"armed", "attached"}
            or reply.state != row["state"]
            or reply.deadline_at != source.cursor_deadline_at
            or reply.candidates != source.candidates
            or reply.scope_sha256 != context.root_scope
            or reply.policy_sha256 != context.policy_sha256
            or reply.boot_ref != context.boot_ref
            or reply.binding_ref != context.binding_ref
            or reply.mode != context.mode
            or reply.mode_revision != context.wire_revision
        ):
            raise DefenseConflict("Defense source time receipt binding failed")
        data = _ControllerTimeData(
            cursor_rid=transaction.rid,
            source_sha256=digest(source),
            context_sha256=digest(context),
            created_at=transaction.created_at,
            deadline_at=transaction.deadline_at,
        )
        return data, reply

    @staticmethod
    def _require_clock_window(
        *,
        created_at: str,
        deadline_at: str,
        observed_at: str,
        root_deadline_at: str,
        now: datetime | None = None,
    ) -> None:
        created, deadline, observed = utc(created_at), utc(deadline_at), utc(observed_at)
        if (
            not 0 < (deadline - created).total_seconds() <= 120
            or not created <= observed < deadline
            or abs((utc(root_deadline_at) - deadline).total_seconds())
            > MAX_DEADLINE_DISPLACEMENT_SECONDS
            or (now is not None and not observed <= _now(now) < deadline)
        ):
            raise DefenseConflict("Defense source local lifetime or deadline alignment failed")

    @staticmethod
    def _require_time_data(
        data: _ControllerTimeData,
        source: DefenseSource,
        *,
        context: DefenseContext | None = None,
        now: datetime | None = None,
    ) -> None:
        # These three values and now are Controller timestamps. Root's deadline
        # remains an exact wire binding, never a remote remaining-time estimate.
        if (
            data.cursor_rid != source.cursor_rid
            or data.source_sha256 != digest(source)
            or (context is not None and data.context_sha256 != digest(context))
        ):
            raise DefenseConflict("Defense source time identity changed")
        DefenseStore._require_clock_window(
            created_at=data.created_at,
            deadline_at=data.deadline_at,
            observed_at=source.observed_at,
            root_deadline_at=source.cursor_deadline_at,
            now=now,
        )

    def source_time_bounds(self, source: DefenseSource) -> ControllerTimeBounds:
        """Derive original local bounds; query refreshes never restart the clock."""
        source = DefenseSource.model_validate_json(canonical(source))
        with self._connection() as connection:
            data, reply = self._source_time_data(connection, source)
            self._require_time_data(data, source)
        bounds = object.__new__(ControllerTimeBounds)
        for name, value in (
            ("_ledger", self),
            ("_token", self._time_bounds_token),
            ("_data", data),
            ("root_reply", reply),
        ):
            object.__setattr__(bounds, name, value)
        return bounds

    def _require_time_bounds(
        self,
        bounds: ControllerTimeBounds,
        source: DefenseSource,
        *,
        context: DefenseContext | None = None,
        now: datetime | None = None,
    ) -> None:
        source = DefenseSource.model_validate_json(canonical(source))
        with self._connection() as connection:
            data, reply = self._source_time_data(connection, source)
            if data != bounds._data or reply != bounds.root_reply:
                raise DefenseConflict("Defense source time bounds changed")
            self._require_time_data(data, source, context=context, now=now)

    @staticmethod
    def _read_source(
        connection: sqlite3.Connection, source_key: str
    ) -> tuple[DefenseSource, AliasMap]:
        TypeAdapter(Digest).validate_python(source_key, strict=True)
        row = connection.execute(
            "SELECT * FROM defense_sources WHERE source_key=?", (source_key,)
        ).fetchone()
        if (
            row is None
            or row["schema_version"] != 1
            or len(row["typed_source"]) > 16384
            or len(row["alias_map"]) > 4096
            or _hash(row["typed_source"]) != row["source_sha256"]
            or _hash(row["alias_map"]) != row["alias_sha256"]
        ):
            raise DefenseConflict("Defense source integrity failed")
        source = DefenseSource.model_validate_json(row["typed_source"])
        aliases = AliasMap.model_validate_json(row["alias_map"])
        transaction = DefenseStore._transaction(connection, source.cursor_rid)
        context = transaction.context
        if transaction.kind != "cursor" or any(
            getattr(source, name) != getattr(context, name)
            for name in ("defense_scope", "root_scope", "policy_sha256", "boot_ref", "binding_ref")
        ):
            raise DefenseConflict("Defense source context integrity failed")
        receipt = connection.execute(
            "SELECT * FROM defense_observations WHERE rid=? AND accepted=1 "
            "AND receipt_sha256=? AND observed_at=? LIMIT 1",
            (source.cursor_rid, source.root_reply_sha256, _stamp(utc(source.observed_at))),
        ).fetchone()
        if receipt is None or _hash(receipt["receipt_bytes"]) != source.root_reply_sha256:
            raise DefenseConflict("Defense source receipt integrity failed")
        reply = DefenseReply.parse(receipt["receipt_bytes"])
        if (
            reply.op != "query"
            or reply.state not in {"armed", "attached"}
            or reply.request_id != source.cursor_rid
            or reply.deadline_at != source.cursor_deadline_at
            or reply.candidates != source.candidates
            or reply.scope_sha256 != context.root_scope
            or reply.policy_sha256 != context.policy_sha256
            or reply.boot_ref != context.boot_ref
            or reply.binding_ref != context.binding_ref
            or reply.mode != context.mode
            or reply.mode_revision != context.wire_revision
        ):
            raise DefenseConflict("Defense source receipt binding failed")
        if any(
            not any(
                candidate.classification == "eligible"
                and candidate.source_ref == alias.source_ref
                and candidate.evidence_sha256 == alias.evidence_sha256
                for candidate in source.candidates
            )
            for alias in aliases.aliases
        ):
            raise DefenseConflict("Defense source aliases do not close")
        return source, aliases

    def source(self, source_key: str) -> tuple[DefenseSource, AliasMap]:
        """Read one bounded, hash-checked source with its original Root provenance."""
        with self._connection() as connection:
            return self._read_source(connection, source_key)

    def source_reply(self, source_key: str) -> DefenseReply:
        """Return the original complete Root DTO after checking its stored provenance."""
        with self._connection() as connection:
            source, _ = self._read_source(connection, source_key)
            row = connection.execute(
                "SELECT receipt_bytes FROM defense_observations WHERE rid=? AND accepted=1 "
                "AND receipt_sha256=? AND observed_at=? LIMIT 1",
                (source.cursor_rid, source.root_reply_sha256, _stamp(utc(source.observed_at))),
            ).fetchone()
            if row is None or _hash(row["receipt_bytes"]) != source.root_reply_sha256:
                raise DefenseConflict("Defense original source receipt disappeared")
            return DefenseReply.parse(row["receipt_bytes"])

    def cursor_source(self, cursor_rid: str, *, host_scope: str) -> DefenseSource:
        """Build a source only from the latest accepted fresh-query cursor receipt.

        Freshness against wall time remains a caller admission predicate. No Root
        receipt fields are projected away before the strict wire parser runs.
        """
        with self._connection() as connection:
            transaction = self._transaction(connection, cursor_rid)
            if (
                transaction.kind != "cursor"
                or transaction.query_required
                or transaction.phase not in {"armed", "attached"}
            ):
                raise DefenseConflict("Defense cursor is not an admitted source")
            row = connection.execute(
                "SELECT * FROM defense_observations WHERE rid=? "
                "ORDER BY observed_at DESC,rowid DESC LIMIT 1",
                (cursor_rid,),
            ).fetchone()
            if (
                row is None
                or row["accepted"] != 1
                or row["op"] != "query"
                or row["receipt_bytes"] is None
                or _hash(row["receipt_bytes"]) != row["receipt_sha256"]
            ):
                raise DefenseConflict("Defense cursor has no current confirmed query")
            reply = DefenseReply.parse(row["receipt_bytes"])
            context = transaction.context
            if (
                reply.request_id != cursor_rid
                or reply.op != "query"
                or reply.state not in {"armed", "attached"}
                or reply.scope_sha256 != context.root_scope
                or reply.policy_sha256 != context.policy_sha256
                or reply.boot_ref != context.boot_ref
                or reply.binding_ref != context.binding_ref
                or reply.mode != context.mode
                or reply.mode_revision != context.wire_revision
                or reply.deadline_at is None
            ):
                raise DefenseConflict("Defense cursor source binding failed")
            return DefenseSource(
                v=1,
                host_scope=host_scope,
                defense_scope=context.defense_scope,
                root_scope=context.root_scope,
                policy_sha256=context.policy_sha256,
                boot_ref=context.boot_ref,
                binding_ref=context.binding_ref,
                cursor_rid=cursor_rid,
                observed_at=row["observed_at"],
                cursor_deadline_at=reply.deadline_at,
                root_reply_sha256=row["receipt_sha256"],
                candidates=reply.candidates,
            )

    def ai_permit(
        self, *, analysis_id: str | None = None, intent_key: str | None = None
    ) -> AIUsagePermit | None:
        """Recover a single immutable AI cost intent; absence never permits replay."""
        if (analysis_id is None) == (intent_key is None):
            raise DefenseConflict("Defense AI lookup requires one identity")
        TypeAdapter(Identifier if analysis_id is not None else Digest).validate_python(
            analysis_id if analysis_id is not None else intent_key, strict=True
        )
        with self._connection() as connection:
            query, value = (
                ("SELECT * FROM defense_ai_intents WHERE analysis_id=?", analysis_id)
                if analysis_id is not None
                else ("SELECT * FROM defense_ai_intents WHERE intent_key=?", intent_key)
            )
            row = connection.execute(query, (value,)).fetchone()
            if row is None:
                return None
            if (
                len(row["typed_permit"]) > 4096
                or _hash(row["typed_permit"]) != row["permit_sha256"]
            ):
                raise DefenseConflict("Defense AI permit integrity failed")
            permit = AIUsagePermit.model_validate_json(row["typed_permit"])
            transaction = self._transaction(connection, permit.rid)
            usage = connection.execute(
                "SELECT * FROM defense_usage WHERE intent_key=?", (permit.intent_key,)
            ).fetchone()
            source, aliases = self._read_source(connection, permit.source_key)
            source_transaction = self._transaction(connection, source.cursor_rid)
            if usage is not None:
                UsageMetadata.model_validate(dict(usage))
            if (
                permit.analysis_id != row["analysis_id"]
                or permit.intent_key != row["intent_key"]
                or permit.owner != transaction.owner
                or permit.deadline_at != transaction.deadline_at
                or source.cursor_rid != (transaction.cursor_rid or transaction.rid)
                or source_transaction.context != transaction.context
                or not aliases.aliases
                or utc(permit.committed_at) >= utc(permit.deadline_at)
                or usage is None
                or usage["kind"] != "ai"
                or usage["rid"] != permit.rid
                or usage["host_id"] != transaction.context.host_id
                or usage["defense_scope"] != transaction.context.defense_scope
                or usage["provider_fingerprint"] != permit.provider_fingerprint
            ):
                raise DefenseConflict("Defense AI permit binding failed")
            advice = permit.advice_authorization
            if advice is not None and (
                advice.context_sha256 != digest(transaction.context)
                or advice.provider_fingerprint != permit.provider_fingerprint
                or not 0
                <= (utc(permit.committed_at) - utc(advice.confirmed_at)).total_seconds()
                <= 120
            ):
                raise DefenseConflict("Defense AI advice purpose binding failed")
            if transaction.context.mode == "manual" and advice is None:
                raise DefenseConflict("Defense manual AI has no explicit advice authorization")
            return permit

    def ai_result(self, analysis_id: str) -> AIResult | None:
        """Read one typed result and close its permit, provider and source references."""
        permit = self.ai_permit(analysis_id=analysis_id)
        if permit is None:
            return None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM defense_ai_results WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
            if row is None:
                return None
            if (
                len(row["typed_result"]) > 4096
                or _hash(row["typed_result"]) != row["result_sha256"]
            ):
                raise DefenseConflict("Defense AI result integrity failed")
            result = AIResult.model_validate_json(row["typed_result"])
            if (
                result.analysis_id != analysis_id
                or result.intent_key != row["intent_key"]
                or result.intent_key != permit.intent_key
                or result.input_digest != permit.input_digest
                or result.provider_fingerprint != permit.provider_fingerprint
            ):
                raise DefenseConflict("Defense AI result binding failed")
            source, aliases = self._read_source(connection, permit.source_key)
            proposed = result.status == "completed" and result.decision == "propose_defense"
            if proposed:
                if result.proof_sha256 is None or not any(
                    alias.source_ref == result.source_ref
                    and alias.evidence_sha256 == result.evidence_sha256
                    and any(
                        candidate.source_ref == alias.source_ref
                        and candidate.evidence_sha256 == alias.evidence_sha256
                        and candidate.classification == "eligible"
                        for candidate in source.candidates
                    )
                    for alias in aliases.aliases
                ):
                    raise DefenseConflict("Defense AI proposal references do not close")
            elif any(
                value is not None
                for value in (result.proof_sha256, result.source_ref, result.evidence_sha256)
            ):
                raise DefenseConflict("Defense AI nonproposal contains proposal references")
            if result.status != "completed" and any(
                value is not None for value in (result.decision, result.reason_code)
            ):
                raise DefenseConflict("Defense AI failure contains a completion")
            if result.status == "completed" and result.reason_code != {
                "propose_defense": "evidence_sufficient",
                "collect_more": "evidence_gap",
                "review_access": "access_review",
                "no_action": "no_match",
            }.get(result.decision):
                raise DefenseConflict("Defense AI decision reason binding failed")
            return result

    def unfinished_ai(
        self, host_id: str, defense_scope: str, *, except_analysis_id: str | None = None
    ) -> bool:
        """A crashed cost intent fences later evidence until explicitly reconciled."""
        TypeAdapter(Host).validate_python(host_id, strict=True)
        TypeAdapter(Digest).validate_python(defense_scope, strict=True)
        if except_analysis_id is not None:
            TypeAdapter(Identifier).validate_python(except_analysis_id, strict=True)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT a.analysis_id FROM defense_ai_intents a "
                "JOIN defense_usage u ON u.intent_key=a.intent_key "
                "LEFT JOIN defense_ai_results r ON r.analysis_id=a.analysis_id "
                "WHERE u.kind='ai' AND u.host_id=? "
                "AND r.analysis_id IS NULL AND a.analysis_id!=? LIMIT 1",
                (host_id, except_analysis_id or ""),
            ).fetchone()
        if row is None:
            return False
        permit = self.ai_permit(analysis_id=row["analysis_id"])
        if permit is None:
            raise DefenseConflict("Defense unfinished AI permit disappeared")
        return True

    def save_source(
        self, source_key: str, source: DefenseSource, *, alias_map: AliasMap | None = None
    ) -> SourceMetadata:
        source = DefenseSource.model_validate_json(canonical(source))
        aliases = (
            AliasMap(aliases=())
            if alias_map is None
            else AliasMap.model_validate_json(canonical(alias_map))
        )
        for alias in aliases.aliases:
            if not any(
                candidate.classification == "eligible"
                and candidate.source_ref == alias.source_ref
                and candidate.evidence_sha256 == alias.evidence_sha256
                for candidate in source.candidates
            ):
                raise DefenseConflict("Defense source alias references do not close")
        metadata = SourceMetadata(
            source_key=source_key,
            source_sha256=digest(source),
            cursor_rid=source.cursor_rid,
            defense_scope=source.defense_scope,
            observed_at=source.observed_at,
            cursor_deadline_at=source.cursor_deadline_at,
        )
        with self._write() as connection:
            transaction = self._transaction(connection, source.cursor_rid)
            context = transaction.context
            if (
                transaction.kind != "cursor"
                or source.defense_scope != context.defense_scope
                or source.root_scope != context.root_scope
                or source.policy_sha256 != context.policy_sha256
                or source.boot_ref != context.boot_ref
                or source.binding_ref != context.binding_ref
            ):
                raise DefenseConflict("Defense source context changed")
            receipt = connection.execute(
                "SELECT receipt_bytes,observed_at FROM defense_observations WHERE rid=? "
                "AND accepted=1 "
                "AND receipt_sha256=?",
                (source.cursor_rid, source.root_reply_sha256),
            ).fetchone()
            if receipt is None or _hash(receipt["receipt_bytes"]) != source.root_reply_sha256:
                raise DefenseConflict("Defense source has no confirmed Root observation")
            root_reply = DefenseReply.parse(receipt["receipt_bytes"])
            if (
                root_reply.deadline_at != source.cursor_deadline_at
                or root_reply.candidates != source.candidates
                or utc(receipt["observed_at"]) != utc(source.observed_at)
            ):
                raise DefenseConflict("Defense source candidate references changed")
            previous = connection.execute(
                "SELECT source_sha256,alias_sha256 FROM defense_sources WHERE source_key=?",
                (source_key,),
            ).fetchone()
            if previous is not None and (
                previous["source_sha256"] != metadata.source_sha256
                or previous["alias_sha256"] != digest(aliases)
            ):
                raise DefenseConflict("Defense source identity is immutable")
            connection.execute(
                "INSERT OR IGNORE INTO defense_sources VALUES(?,1,?,?,?,?)",
                (
                    source_key,
                    metadata.source_sha256,
                    canonical(source),
                    digest(aliases),
                    canonical(aliases),
                ),
            )
        return metadata

    def begin_ai_usage(
        self,
        rid: str,
        *,
        source_key: str,
        context: DefenseContext,
        owner: str,
        usage: UsageClaim,
        analysis_id: str,
        input_digest: str,
        advice_authorization: AIAdviceAuthorization | None = None,
        now: datetime | None = None,
        session_admission=None,
    ) -> AIUsagePermit:
        instant = _now(now)
        context = DefenseContext.model_validate_json(canonical(context))
        usage = UsageClaim.model_validate_json(canonical(usage))
        if advice_authorization is not None:
            advice_authorization = AIAdviceAuthorization.model_validate_json(
                canonical(advice_authorization)
            )
            if (
                advice_authorization.context_sha256 != digest(context)
                or advice_authorization.provider_fingerprint != usage.provider_fingerprint
                or not 0
                <= (instant - utc(advice_authorization.confirmed_at)).total_seconds()
                <= 120
            ):
                raise DefenseConflict("Defense AI advice authorization changed")
        if usage.kind != "ai":
            raise DefenseConflict("Defense AI usage must use the independent AI budget")
        with self._write() as connection:
            guard = self.require_session_admission(
                rid, session_admission, phase="analyzing", now=instant, connection=connection
            )
            transaction = self._transaction(connection, rid)
            if (
                transaction.context != context
                or transaction.owner != owner
                or utc(transaction.deadline_at) <= instant
            ):
                raise DefenseConflict("Defense AI admission context changed")
            if (context.mode == "manual" and advice_authorization is None) or (
                context.mode != "manual" and not self._mode_confirmed(connection, context)
            ):
                raise DefenseConflict("Defense AI mode acknowledgement is pending")
            if (
                connection.execute(
                    "SELECT 1 FROM defense_target_latches WHERE host_id=?",
                    (context.host_id,),
                ).fetchone()
                is not None
            ):
                raise DefenseConflict("Defense AI target requires reconciliation")
            row = connection.execute(
                "SELECT * FROM defense_sources WHERE source_key=?",
                (source_key,),
            ).fetchone()
            if row is None or _hash(row["typed_source"]) != row["source_sha256"]:
                raise DefenseConflict("Defense AI needs a durable source")
            source = DefenseSource.model_validate_json(row["typed_source"])
            if _hash(row["alias_map"]) != row["alias_sha256"]:
                raise DefenseConflict("Defense AI source alias integrity failed")
            aliases = AliasMap.model_validate_json(row["alias_map"])
            if not aliases.aliases:
                raise DefenseConflict("Defense AI needs a durable alias map")
            cursor_rid = transaction.cursor_rid if transaction.kind == "action" else rid
            if source.defense_scope != context.defense_scope or source.cursor_rid != cursor_rid:
                raise DefenseConflict("Defense AI source changed")
            time_data, _ = self._source_time_data(connection, source)
            self._require_time_data(time_data, source, context=context, now=instant)
            cursor = self._transaction(connection, cursor_rid)
            latest = connection.execute(
                "SELECT op,accepted,receipt_sha256,observed_at FROM defense_observations "
                "WHERE rid=? ORDER BY observed_at DESC,rowid DESC LIMIT 1",
                (cursor_rid,),
            ).fetchone()
            if (
                cursor.phase not in {"armed", "attached"}
                or cursor.query_required
                or latest is None
                or latest["op"] != "query"
                or latest["accepted"] != 1
                or latest["receipt_sha256"] != source.root_reply_sha256
                or utc(latest["observed_at"]) != utc(source.observed_at)
            ):
                raise DefenseConflict("Defense AI current evidence changed before cost commitment")
            if (
                connection.execute(
                    "SELECT 1 FROM defense_usage WHERE intent_key=?",
                    (usage.intent_key,),
                ).fetchone()
                is not None
            ):
                raise DefenseConflict("Defense AI cost intent cannot be resent")
            self._charge(connection, transaction, usage, instant, consume=True)
            if usage.provider_fingerprint is None:
                raise DefenseConflict("Defense AI provider was not bound")
            permit = AIUsagePermit(
                analysis_id=analysis_id,
                intent_key=usage.intent_key,
                input_digest=input_digest,
                source_key=source_key,
                rid=rid,
                provider_fingerprint=usage.provider_fingerprint,
                owner=owner,
                deadline_at=transaction.deadline_at,
                committed_at=_stamp(instant),
                advice_authorization=advice_authorization,
            )
            connection.execute(
                "INSERT INTO defense_ai_intents VALUES(?,?,?,?)",
                (analysis_id, usage.intent_key, digest(permit), canonical(permit)),
            )
            if guard is not None:
                guard.bind_ai_permit(session_admission, permit, now=instant, connection=connection)
        return permit

    def usage(self, intent_key: str) -> UsageMetadata:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM defense_usage WHERE intent_key=?", (intent_key,)
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense usage was not found")
            transaction = self._transaction(connection, row["rid"])
            result = UsageMetadata.model_validate(dict(row))
            if (
                result.host_id != transaction.context.host_id
                or result.defense_scope != transaction.context.defense_scope
            ):
                raise DefenseConflict("Defense usage binding failed")
            return result

    def save_ai_result(
        self, result: AIResult, *, session_admission=None, now: datetime | None = None
    ) -> None:
        result = AIResult.model_validate_json(canonical(result))
        with self._write() as connection:
            self.require_session_admission(
                result.analysis_id,
                session_admission,
                phase="analyzing",
                now=now,
                connection=connection,
            )
            usage = connection.execute(
                "SELECT * FROM defense_usage WHERE intent_key=?",
                (result.intent_key,),
            ).fetchone()
            if (
                usage is None
                or usage["kind"] != "ai"
                or usage["provider_fingerprint"] != result.provider_fingerprint
            ):
                raise DefenseConflict("Defense AI result has no matching cost intent")
            row = connection.execute(
                "SELECT * FROM defense_ai_intents WHERE analysis_id=?",
                (result.analysis_id,),
            ).fetchone()
            if row is None or _hash(row["typed_permit"]) != row["permit_sha256"]:
                raise DefenseConflict("Defense AI result has no original send intent")
            permit = AIUsagePermit.model_validate_json(row["typed_permit"])
            if (
                permit.intent_key != result.intent_key
                or permit.input_digest != result.input_digest
                or permit.provider_fingerprint != result.provider_fingerprint
            ):
                raise DefenseConflict("Defense AI result input binding changed")
            if result.status == "completed" and result.decision == "propose_defense":
                source = connection.execute(
                    "SELECT * FROM defense_sources WHERE source_key=?",
                    (permit.source_key,),
                ).fetchone()
                if source is None or _hash(source["typed_source"]) != source["source_sha256"]:
                    raise DefenseConflict("Defense AI result source integrity failed")
                original = DefenseSource.model_validate_json(source["typed_source"])
                if result.proof_sha256 is None or not any(
                    candidate.classification == "eligible"
                    and candidate.source_ref == result.source_ref
                    and candidate.evidence_sha256 == result.evidence_sha256
                    for candidate in original.candidates
                ):
                    raise DefenseConflict("Defense AI result source binding changed")
            previous = connection.execute(
                "SELECT result_sha256 FROM defense_ai_results WHERE intent_key=?",
                (result.intent_key,),
            ).fetchone()
            if previous is not None and previous["result_sha256"] != digest(result):
                raise DefenseConflict("Defense AI result is immutable")
            connection.execute(
                "INSERT OR IGNORE INTO defense_ai_results VALUES(?,?,?,?)",
                (result.analysis_id, result.intent_key, digest(result), canonical(result)),
            )
            if result.status != "completed":
                transaction = self._transaction(connection, permit.rid)
                self._latch(connection, transaction, "unknown", _stamp(_now(now)))
                connection.execute(
                    "UPDATE defense_usage SET state='unknown' WHERE intent_key=?",
                    (result.intent_key,),
                )

    @staticmethod
    def _legacy_recheck(connection: sqlite3.Connection, row) -> LegacyRecheckRecord:
        if (
            len(row["typed_recheck"]) > 16384
            or _hash(row["typed_recheck"]) != row["recheck_sha256"]
        ):
            raise DefenseConflict("Defense legacy recheck integrity failed")
        record = DefenseRecheck.model_validate_json(row["typed_recheck"])
        transaction = DefenseStore._transaction(connection, record.rid)
        if (
            record.recheck_id != row["recheck_id"]
            or record.rid != row["rid"]
            or transaction.context.defense_scope != record.defense_scope
            or transaction.manifest_sha256 != record.manifest_sha256
        ):
            raise DefenseConflict("Defense legacy recheck original references changed")
        # A legacy confirmation ID or checks=('ok',) is never v2 authority or
        # business evidence. Preserve the old bytes and expose only pending.
        return LegacyRecheckRecord(sequence=row["sequence"], record=record)

    def legacy_recheck(self, recheck_id: str) -> LegacyRecheckRecord | None:
        TypeAdapter(Identifier).validate_python(recheck_id, strict=True)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT rowid AS sequence,* FROM defense_rechecks WHERE recheck_id=?", (recheck_id,)
            ).fetchone()
            return None if row is None else self._legacy_recheck(connection, row)

    def legacy_rechecks(
        self, host_id: str, rid: str | None = None, *, after_sequence: int = 0, limit: int = 20
    ) -> tuple[LegacyRecheckRecord, ...]:
        TypeAdapter(Host).validate_python(host_id, strict=True)
        if rid is not None:
            TypeAdapter(Identifier).validate_python(rid, strict=True)
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence <= 2**63 - 1
            or type(limit) is not int
            or not 1 <= limit <= 101
        ):
            raise ValueError("Defense legacy recheck page bounds are invalid")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT r.rowid AS sequence,r.* FROM defense_rechecks r "
                "JOIN defense_transactions t ON t.rid=r.rid WHERE t.host_id=? "
                "AND (? IS NULL OR r.rid=?) AND r.rowid>? ORDER BY r.rowid LIMIT ?",
                (host_id, rid, rid, after_sequence, limit),
            ).fetchall()
            return tuple(self._legacy_recheck(connection, row) for row in rows)

    def save_recheck(self, recheck: DefenseRecheck) -> None:
        recheck = DefenseRecheck.model_validate_json(canonical(recheck))
        with self._write() as connection:
            transaction = self._transaction(connection, recheck.rid)
            if (
                recheck.manifest_sha256 != transaction.manifest_sha256
                or recheck.defense_scope != transaction.context.defense_scope
            ):
                raise DefenseConflict("Defense recheck binding changed")
            if (
                connection.execute(
                    "SELECT 1 FROM defense_authorizations WHERE approval_id=? AND rid=?",
                    (recheck.approval_id, recheck.rid),
                ).fetchone()
                is None
            ):
                raise DefenseConflict("Defense recheck has no original confirmation")
            previous = connection.execute(
                "SELECT recheck_sha256 FROM defense_rechecks WHERE recheck_id=?",
                (recheck.recheck_id,),
            ).fetchone()
            if previous is not None and previous["recheck_sha256"] != digest(recheck):
                raise DefenseConflict("Defense recheck identity is immutable")
            connection.execute(
                "INSERT OR IGNORE INTO defense_rechecks VALUES(?,?,?,?)",
                (recheck.recheck_id, recheck.rid, digest(recheck), canonical(recheck)),
            )

    def acquire_worker(
        self,
        owner: str,
        *,
        expires_at: str,
        now: datetime | None = None,
    ) -> WorkerLease | None:
        instant = _now(now)
        candidate = WorkerLease(owner=owner, expires_at=expires_at, epoch=0)
        if utc(expires_at) <= instant or (utc(expires_at) - instant).total_seconds() > 300:
            raise DefenseConflict("Defense worker lease lifetime is invalid")
        with self._write() as connection:
            previous = connection.execute("SELECT * FROM defense_worker_lease").fetchone()
            if previous is not None and utc(previous["expires_at"]) > instant:
                return None
            epoch = 0 if previous is None else previous["epoch"] + 1
            candidate = candidate.model_copy(update={"epoch": epoch})
            connection.execute(
                "INSERT INTO defense_worker_lease VALUES(1,?,?,?) ON CONFLICT(singleton) "
                "DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at,"
                "epoch=excluded.epoch",
                (owner, expires_at, epoch),
            )
        return candidate

    def assert_worker(
        self,
        lease: WorkerLease,
        *,
        now: datetime | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """SELECT-only exact fence; a caller's cost/write transaction is reused."""
        instant = _now(now)
        if type(lease) is not WorkerLease:
            raise DefenseConflict("Defense worker lease is not a typed permit")
        lease = WorkerLease.model_validate_json(canonical(lease))
        if connection is None:
            with self._connection() as db:
                db.execute("BEGIN")
                return self.assert_worker(lease, now=instant, connection=db)
        databases = connection.execute("PRAGMA database_list").fetchall()
        database = next((row for row in databases if row[1] == "main"), None)
        if (
            not connection.in_transaction
            or database is None
            or Path(database[2]).resolve() != self.path.resolve()
        ):
            raise DefenseConflict("Defense worker fence requires its original ledger transaction")
        row = connection.execute(
            "SELECT owner,epoch,expires_at FROM defense_worker_lease"
        ).fetchone()
        if row is None:
            raise DefenseConflict("Defense worker lease was not found")
        current = WorkerLease(owner=row[0], epoch=row[1], expires_at=row[2])
        if current != lease or utc(current.expires_at) <= instant:
            raise DefenseConflict("Defense worker lease expired or changed")
        return None

    def renew_worker(
        self,
        lease: WorkerLease,
        *,
        expires_at: str,
        now: datetime | None = None,
        deadline_at: str | None = None,
    ) -> WorkerLease:
        """Extend one still-live lease with exact owner/epoch/old-expiry CAS.

        Renewal retains the fencing epoch. A session caller must additionally
        supply its original Controller deadline, never a Root UTC projection.
        """
        instant = _now(now)
        if type(lease) is not WorkerLease:
            raise DefenseConflict("Defense worker lease is not a typed permit")
        previous = WorkerLease.model_validate_json(canonical(lease))
        candidate = WorkerLease(owner=previous.owner, epoch=previous.epoch, expires_at=expires_at)
        expiry = utc(candidate.expires_at)
        if (
            not 0 < (expiry - instant).total_seconds() <= 300
            or expiry <= utc(previous.expires_at)
            or deadline_at is not None
            and expiry > utc(deadline_at)
        ):
            raise DefenseConflict("Defense worker renewal exceeds its original bounds")
        with self._write() as connection:
            self.assert_worker(previous, now=instant, connection=connection)
            changed = connection.execute(
                "UPDATE defense_worker_lease SET expires_at=? "
                "WHERE singleton=1 AND owner=? AND epoch=? AND expires_at=?",
                (candidate.expires_at, previous.owner, previous.epoch, previous.expires_at),
            ).rowcount
            if changed != 1:
                raise DefenseConflict("Defense worker renewal compare-and-swap failed")
        return candidate

    def release_worker(self, lease: WorkerLease, *, now: datetime | None = None) -> None:
        # A stale copy cannot release a renewal. Retain the epoch after release.
        if type(lease) is not WorkerLease:
            raise DefenseConflict("Defense worker lease is not a typed permit")
        lease = WorkerLease.model_validate_json(canonical(lease))
        instant = _now(now)
        if utc(lease.expires_at) <= instant:
            return
        with self._write() as connection:
            connection.execute(
                "UPDATE defense_worker_lease SET expires_at=? "
                "WHERE singleton=1 AND owner=? AND epoch=? AND expires_at=?",
                (_stamp(instant), lease.owner, lease.epoch, lease.expires_at),
            )
