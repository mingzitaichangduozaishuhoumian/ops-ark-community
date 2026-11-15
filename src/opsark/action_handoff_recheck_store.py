"""Append-only, action-bound business rechecks in the existing report database."""

from __future__ import annotations

import builtins
import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
)

from opsark.baselines import matches_host_scope
from opsark.models import HostPublic
from opsark.storage import ReportStore

type ActionKind = Literal["nginx", "container_restart"]
type CheckState = Literal["passed", "failed", "uncovered"]
type CheckSlots = tuple[CheckState, CheckState, CheckState]
type Verdict = Literal["passed", "failed", "pending"]
type ReportId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
type PlanId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
type HostId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
type Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
type RunId = Annotated[str, StringConstraints(pattern=r"^ar-[0-9a-f]{32}$")]

_RUN_ID = TypeAdapter(RunId)
_ORIGINAL_ACTION = TypeAdapter(tuple[ReportId, ActionKind, PlanId])
_ORIGINAL_IDENTITY = TypeAdapter(tuple[ReportId, ActionKind, PlanId, RunId])
_MISMATCH = "Action recheck evidence is inconsistent"
_COLLECTION_WINDOW = timedelta(seconds=120)
_INTENT_TABLE = "action_handoff_recheck_intents_v1"
_RESULT_TABLE = "action_handoff_recheck_results_v1"
_ORIGINAL_INDEX = "action_handoff_recheck_original_v1"
_ORIGINAL_INDEX_DDL = """
    CREATE INDEX IF NOT EXISTS action_handoff_recheck_original_v1
        ON action_handoff_recheck_intents_v1
        (report_id, kind, plan_id, started_at DESC, sequence DESC)
"""
_SCHEMA = (
    """
    CREATE TABLE action_handoff_recheck_intents_v1 (
        sequence INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        report_id TEXT NOT NULL REFERENCES reports(id),
        kind TEXT NOT NULL CHECK (kind IN ('nginx', 'container_restart')),
        plan_id TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL,
        binding_json TEXT NOT NULL,
        started_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX action_handoff_recheck_binding_v1 ON action_handoff_recheck_intents_v1
        (report_id, kind, plan_id, binding_sha256, started_at DESC, sequence DESC)
    """,
    _ORIGINAL_INDEX_DDL,
    """
    CREATE TABLE action_handoff_recheck_results_v1 (
        id TEXT PRIMARY KEY NOT NULL REFERENCES action_handoff_recheck_intents_v1(id),
        finished_at TEXT NOT NULL,
        result_sha256 TEXT NOT NULL,
        result_json TEXT NOT NULL
    )
    """,
)
_SELECT = """
    SELECT i.id, i.report_id, i.kind, i.plan_id, i.binding_sha256, i.binding_json,
           i.started_at, r.finished_at, r.result_sha256, r.result_json
    FROM action_handoff_recheck_intents_v1 AS i
    LEFT JOIN action_handoff_recheck_results_v1 AS r ON r.id=i.id
    WHERE i.report_id=? AND i.kind=? AND i.plan_id=?
"""
_BOUND = _SELECT + " AND i.binding_sha256=?"
_LATEST_FIRST = " ORDER BY i.started_at DESC, i.sequence DESC"
_ORIGINAL_HISTORY = """
    SELECT i.id, i.report_id, i.kind, i.plan_id, i.binding_sha256, i.binding_json,
           i.started_at, r.finished_at, r.result_sha256, r.result_json
    FROM action_handoff_recheck_intents_v1 AS i INDEXED BY action_handoff_recheck_original_v1
    LEFT JOIN action_handoff_recheck_results_v1 AS r ON r.id=i.id
    WHERE i.report_id=? AND i.kind=? AND i.plan_id=?
    ORDER BY i.started_at DESC, i.sequence DESC LIMIT 20
"""


class _Record(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class ActionRecheckBinding(_Record):
    """Provide the server-verified original action and its captured business profile."""

    report_id: ReportId
    kind: ActionKind
    plan_id: PlanId
    host_id: HostId
    host_scope: Digest
    target_scope: Digest
    approval_digest: Digest
    execution_digest: Digest
    profile_digest: Digest
    configured_checks: int = Field(ge=1, le=3)
    execution_at: AwareDatetime

    @field_validator("execution_at")
    @classmethod
    def utc(cls, instant: datetime) -> datetime:
        return instant.astimezone(UTC)


class ActionRecheckIntent(_Record):
    id: RunId
    binding: ActionRecheckBinding
    started_at: AwareDatetime


class ActionRecheckResult(_Record):
    finished_at: AwareDatetime
    checks: CheckSlots


class ActionRecheckRun(_Record):
    intent: ActionRecheckIntent
    result: ActionRecheckResult | None

    @property
    def verdict(self) -> Verdict:
        if self.result is None:
            return "pending"
        checks = self.result.checks[: self.intent.binding.configured_checks]
        if "failed" in checks:
            return "failed"
        return "passed" if all(check == "passed" for check in checks) else "pending"


def _now() -> datetime:
    return datetime.now(UTC)


def _decode[Record: _Record](model: type[Record], raw: object) -> Record:
    if not isinstance(raw, str) or not 0 < len(raw) <= 4096:
        raise ValueError(_MISMATCH)
    try:
        value = model.model_validate_json(raw)
    except ValueError:
        raise ValueError(_MISMATCH) from None
    if value.model_dump_json() != raw:
        raise ValueError(_MISMATCH)
    return value


def _stamp(instant: datetime) -> str:
    return instant.astimezone(UTC).isoformat(timespec="microseconds")


def _payload_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def _identity(binding: ActionRecheckBinding) -> tuple[str, str, str, str]:
    payload = binding.model_dump_json(warnings=False)
    _decode(ActionRecheckBinding, payload)
    return binding.report_id, binding.kind, binding.plan_id, _payload_hash(payload)


def _run(row: sqlite3.Row, binding: ActionRecheckBinding) -> ActionRecheckRun:
    stored = _decode(ActionRecheckBinding, row["binding_json"])
    if stored != binding or _identity(stored) != (
        row["report_id"],
        row["kind"],
        row["plan_id"],
        row["binding_sha256"],
    ):
        raise ValueError(_MISMATCH)
    start = datetime.fromisoformat(row["started_at"])
    if (
        start.utcoffset() is None
        or _stamp(start) != row["started_at"]
        or start <= stored.execution_at
    ):
        raise ValueError(_MISMATCH)
    intent = ActionRecheckIntent(id=row["id"], binding=stored, started_at=start)
    result = None
    if row["result_json"] is not None:
        result = _decode(ActionRecheckResult, row["result_json"])
        if (
            _payload_hash(row["result_json"]) != row["result_sha256"]
            or _stamp(result.finished_at) != row["finished_at"]
            or not start <= result.finished_at <= start + _COLLECTION_WINDOW
            or any(check != "uncovered" for check in result.checks[stored.configured_checks :])
        ):
            raise ValueError(_MISMATCH)
    return ActionRecheckRun(intent=intent, result=result)


def _check_report(db: sqlite3.Connection, binding: ActionRecheckBinding) -> None:
    row = db.execute(
        "SELECT created_at, json_extract(payload,'$.id') AS payload_id, "
        "json_extract(payload,'$.host_id') AS host_id, json_extract(payload,'$.source') AS source, "
        "json_extract(payload,'$.scope_hash') AS scope, json_extract(payload,'$.target') AS target "
        "FROM reports WHERE id=?",
        (binding.report_id,),
    ).fetchone()
    if row is None or row["payload_id"] != binding.report_id or row["host_id"] != binding.host_id:
        raise ValueError(_MISMATCH)
    created = datetime.fromisoformat(row["created_at"])
    target = HostPublic.model_validate_json(row["target"]) if row["target"] is not None else None
    report_scope = row["scope"]
    # Legacy reports without captured registration can match only their original scope.
    scope_matches = (
        report_scope == binding.host_scope
        if target is None
        else (
            target.source == "ssh"
            and target.id == binding.host_id
            and matches_host_scope(target, report_scope)
            and matches_host_scope(target, binding.host_scope)
        )
    )
    if (
        row["source"] != "ssh"
        or created.utcoffset() is None
        or created >= binding.execution_at
        or not scope_matches
    ):
        raise ValueError(_MISMATCH)


def _has_schema(db: sqlite3.Connection) -> bool:
    rows = db.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name IN (?, ?)",
        (_INTENT_TABLE, _RESULT_TABLE),
    ).fetchall()
    if len(rows) == 1:
        raise ValueError(_MISMATCH)
    return bool(rows)


class ActionHandoffRecheckStore:
    """Record local collection attempts without modifying original actions or reports."""

    def __init__(self, reports: ReportStore) -> None:
        self._reports = reports

    def start(self, binding: ActionRecheckBinding) -> ActionRecheckIntent:
        """Persist a new collection intent before checking the host."""
        key = _identity(binding)
        with self._reports._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            _check_report(db, binding)
            started = _now()
            if started <= binding.execution_at:
                raise ValueError(_MISMATCH)
            if not _has_schema(db):
                for statement in _SCHEMA:
                    db.execute(statement)
            else:
                db.execute(_ORIGINAL_INDEX_DDL)
            intent = ActionRecheckIntent(
                id="ar-" + secrets.token_hex(16), binding=binding, started_at=started
            )
            db.execute(
                "INSERT INTO action_handoff_recheck_intents_v1 "
                "(id, report_id, kind, plan_id, binding_sha256, binding_json, started_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (intent.id, *key, binding.model_dump_json(), _stamp(started)),
            )
        return intent

    def finish(
        self, binding: ActionRecheckBinding, run_id: str, *, checks: CheckSlots
    ) -> ActionRecheckRun:
        """Seal one typed result. Interrupted intents stay pending until a new attempt."""
        key = (*_identity(binding), _RUN_ID.validate_python(run_id))
        with self._reports._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            _check_report(db, binding)
            if not _has_schema(db):
                raise ValueError(_MISMATCH)
            row = db.execute(_BOUND + " AND i.id=?", key).fetchone()
            if row is None:
                raise ValueError(_MISMATCH)
            run = _run(row, binding)
            result = ActionRecheckResult(finished_at=_now(), checks=checks)
            started = run.intent.started_at
            if (
                run.result is not None
                or not started <= result.finished_at <= started + _COLLECTION_WINDOW
                or any(check != "uncovered" for check in checks[binding.configured_checks :])
            ):
                raise ValueError(_MISMATCH)
            payload = result.model_dump_json()
            db.execute(
                "INSERT INTO action_handoff_recheck_results_v1 "
                "(id, finished_at, result_sha256, result_json) VALUES (?,?,?,?)",
                (run_id, _stamp(result.finished_at), _payload_hash(payload), payload),
            )
        return ActionRecheckRun(intent=run.intent, result=result)

    def get(self, binding: ActionRecheckBinding, run_id: str) -> ActionRecheckRun | None:
        key = (*_identity(binding), _RUN_ID.validate_python(run_id))
        with self._reports._connection() as db:
            if not _has_schema(db):
                return None
            row = db.execute(_BOUND + " AND i.id=?", key).fetchone()
            if row is None:
                return None
            _check_report(db, binding)
            return _run(row, binding)

    def get_original(
        self, report_id: str, kind: ActionKind, plan_id: str, run_id: str
    ) -> ActionRecheckRun | None:
        """Read an explicitly selected historical attempt using its captured profile."""
        key = _ORIGINAL_IDENTITY.validate_python((report_id, kind, plan_id, run_id), strict=True)
        with self._reports._connection() as db:
            if not _has_schema(db):
                return None
            row = db.execute(_SELECT + " AND i.id=?", key).fetchone()
            if row is None:
                return None
            binding = _decode(ActionRecheckBinding, row["binding_json"])
            _check_report(db, binding)
            return _run(row, binding)

    def latest(self, binding: ActionRecheckBinding) -> ActionRecheckRun | None:
        key = _identity(binding)
        with self._reports._connection() as db:
            if not _has_schema(db):
                return None
            row = db.execute(_BOUND + _LATEST_FIRST + " LIMIT 1", key).fetchone()
            if row is None:
                return None
            _check_report(db, binding)
            return _run(row, binding)

    def list_original(
        self, report_id: str, kind: ActionKind, plan_id: str
    ) -> builtins.list[ActionRecheckRun]:
        """Return at most twenty recent attempts across the original action's profiles."""
        key = _ORIGINAL_ACTION.validate_python((report_id, kind, plan_id), strict=True)
        with self._reports._connection() as db:
            if (
                not _has_schema(db)
                or db.execute(
                    "SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?", (_ORIGINAL_INDEX,)
                ).fetchone()
                is None
            ):
                return []
            rows = db.execute(_ORIGINAL_HISTORY, key).fetchall()
            history = []
            for row in rows:
                binding = _decode(ActionRecheckBinding, row["binding_json"])
                _check_report(db, binding)
                history.append(_run(row, binding))
            return history

    def list(self, binding: ActionRecheckBinding) -> builtins.list[ActionRecheckRun]:
        """Return at most twenty attempts matching the entire original binding."""
        key = _identity(binding)
        with self._reports._connection() as db:
            if not _has_schema(db):
                return []
            rows = db.execute(_BOUND + _LATEST_FIRST + " LIMIT 20", key).fetchall()
            if rows:
                _check_report(db, binding)
            return [_run(row, binding) for row in rows]
