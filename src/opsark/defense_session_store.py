"""Dormant single-session sidecars in security.sqlite3; no network or fee mutation.

The caller must wire current_runtime as a bounded, read-only, lock-free snapshot
callback. It may run inside an existing BEGIN IMMEDIATE; it must never acquire
mode_lock, start network work or write either ledger. These objects do not enable
an execution path: later cost/send owners must explicitly call atomic_assert.
"""

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import datetime

from opsark.defense_ai import DefenseAIService, intent_key
from opsark.defense_models import (
    ActionBody,
    ArmBody,
    DefenseRequest,
    PrepareBody,
    canonical,
    digest,
    utc,
)
from opsark.defense_session_models import (
    SessionAction,
    SessionAdmission,
    SessionAIIntent,
    SessionDeclaration,
    SessionPhase,
    SessionRecord,
    SessionRequestBinding,
    SessionRuntime,
    SessionSelection,
    SessionStopReason,
)
from opsark.defense_store import (
    AIUsagePermit,
    DefenseConflict,
    DefenseSource,
    DefenseStore,
    Owner,
    WorkerLease,
    _now,
    _stamp,
)

MAX_SESSIONS = 1024
MAX_SOURCE_AGE_SECONDS = 30
TERMINAL = frozenset({"completed", "stopped", "expired", "reconciliation_only"})
NEXT = {
    "declared": {"observing"},
    "observing": {"analyzing", "preparing"},
    "analyzing": {"analysis_ready"},
    "analysis_ready": {"preparing"},
    "preparing": {"prepared"},
    "prepared": {"applying"},
    "applying": {"confirmed"},
    "confirmed": {"completed"},
}


def _typed(model, raw, expected):
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= 32768
        or hashlib.sha256(raw).hexdigest() != expected
    ):
        raise DefenseConflict("Session record integrity failed")
    value = model.model_validate_json(raw)
    if canonical(value) != raw:
        raise DefenseConflict("Session record canonical schema changed")
    return value


class DefenseSessionStore:
    def __init__(
        self,
        base: DefenseStore,
        *,
        owner: str,
        current_runtime: Callable[[str], SessionRuntime],
        stopped: Callable[[], bool],
    ):
        from pydantic import TypeAdapter

        if type(base) is not DefenseStore or not callable(current_runtime) or not callable(stopped):
            raise TypeError("Sessions require the existing ledger and trusted local snapshots")
        TypeAdapter(Owner).validate_python(owner, strict=True)
        self.base, self.path, self.owner = base, base.path, owner
        self.current_runtime, self.stopped, self._token = current_runtime, stopped, object()
        with base._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS defense_sessions_v1(
                    session_ref TEXT PRIMARY KEY, cursor_rid TEXT NOT NULL UNIQUE
                        REFERENCES defense_transactions(rid),
                    owner TEXT NOT NULL, worker_epoch INTEGER NOT NULL,
                    declaration_sha256 TEXT NOT NULL,
                    typed_declaration BLOB NOT NULL, phase TEXT NOT NULL,
                    revision INTEGER NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, stop_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS defense_session_selections_v1(
                    session_ref TEXT PRIMARY KEY REFERENCES defense_sessions_v1(session_ref),
                    sha256 TEXT NOT NULL, typed_record BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_session_ai_v1(
                    session_ref TEXT PRIMARY KEY REFERENCES defense_sessions_v1(session_ref),
                    analysis_id TEXT NOT NULL UNIQUE, intent_key TEXT NOT NULL UNIQUE,
                    sha256 TEXT NOT NULL, typed_record BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_session_actions_v1(
                    session_ref TEXT PRIMARY KEY REFERENCES defense_sessions_v1(session_ref),
                    rid TEXT NOT NULL UNIQUE REFERENCES defense_transactions(rid),
                    sha256 TEXT NOT NULL, typed_record BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_session_requests_v1(
                    rid TEXT NOT NULL REFERENCES defense_transactions(rid), op TEXT NOT NULL,
                    session_ref TEXT NOT NULL REFERENCES defense_sessions_v1(session_ref),
                    sha256 TEXT NOT NULL, typed_record BLOB NOT NULL, PRIMARY KEY(rid,op)
                );
            """)
        base.register_session_guard(self)

    def _read(self, db, session_ref, now):
        row = db.execute(
            "SELECT * FROM defense_sessions_v1 WHERE session_ref=?", (session_ref,)
        ).fetchone()
        if row is None:
            raise DefenseConflict("Session was not found")
        declaration = _typed(
            SessionDeclaration, row["typed_declaration"], row["declaration_sha256"]
        )
        if (
            declaration.session_ref != row["session_ref"]
            or declaration.cursor_rid != row["cursor_rid"]
            or declaration.boot_owner != row["owner"]
            or declaration.worker_epoch != row["worker_epoch"]
        ):
            raise DefenseConflict("Session declaration binding changed")
        cursor = self.base._transaction(db, declaration.cursor_rid)
        if (
            cursor.kind != "cursor"
            or cursor.owner != row["owner"]
            or cursor.context != declaration.runtime.context
            or cursor.created_at != declaration.controller_created_at
            or cursor.deadline_at != declaration.controller_deadline_at
            or not utc(cursor.created_at) <= utc(row["created_at"]) <= utc(row["updated_at"])
            or utc(row["created_at"]) >= utc(cursor.deadline_at)
        ):
            raise DefenseConflict("Session original cursor identity changed")
        extras = {}
        for table, model, key in (
            ("defense_session_selections_v1", SessionSelection, "selection"),
            ("defense_session_ai_v1", SessionAIIntent, "ai_intent"),
            ("defense_session_actions_v1", SessionAction, "action"),
        ):
            entry = db.execute(
                "SELECT * FROM " + table + " WHERE session_ref=?",  # noqa: S608 -- fixed table literals above.
                (session_ref,),
            ).fetchone()
            value = None if entry is None else _typed(model, entry["typed_record"], entry["sha256"])
            extras[key] = value
            if value is not None and value.session_ref != session_ref:
                raise DefenseConflict("Session sidecar reference changed")
            if (
                key == "ai_intent"
                and value is not None
                and (
                    value.analysis_id != entry["analysis_id"]
                    or value.intent_key != entry["intent_key"]
                )
            ):
                raise DefenseConflict("Session AI lookup identity changed")
            if key == "action" and value is not None and value.rid != entry["rid"]:
                raise DefenseConflict("Session action lookup identity changed")
        selection, ai_intent, action = (extras[key] for key in ("selection", "ai_intent", "action"))
        if selection is not None:
            self.base._source_time_data(db, selection.source)
            observation = db.execute(
                "SELECT rid,receipt_sha256 FROM defense_observations WHERE rowid=?",
                (selection.observed_sequence,),
            ).fetchone()
            if (
                selection.source.cursor_rid != declaration.cursor_rid
                or selection.source.host_scope != declaration.runtime.host_scope
                or observation is None
                or observation["rid"] != declaration.cursor_rid
                or observation["receipt_sha256"] != selection.source.root_reply_sha256
                or not utc(selection.source.observed_at)
                <= utc(selection.selected_at)
                < utc(declaration.controller_deadline_at)
            ):
                raise DefenseConflict("Session selected source identity changed")
        if ai_intent is not None and (
            selection is None
            or ai_intent.selection_sha256 != digest(selection)
            or ai_intent.provider_fingerprint != declaration.runtime.provider_fingerprint
        ):
            raise DefenseConflict("Session AI source identity changed")
        if action is not None:
            original = self.base._transaction(db, action.rid)
            if (
                action.cursor_rid != declaration.cursor_rid
                or action.owner != row["owner"]
                or action.context_sha256 != digest(declaration.runtime.context)
                or action.deadline_at != declaration.controller_deadline_at
                or original.kind != "action"
                or original.cursor_rid != action.cursor_rid
                or original.owner != action.owner
                or original.context != declaration.runtime.context
                or original.deadline_at != action.deadline_at
            ):
                raise DefenseConflict("Session original action identity changed")
        effective = row["phase"]
        if effective not in TERMINAL:
            lease = db.execute("SELECT * FROM defense_worker_lease").fetchone()
            if row["owner"] != self.owner:
                effective = "reconciliation_only"
            elif self.stopped() is not False:
                effective = (
                    "reconciliation_only" if extras["ai_intent"] or extras["action"] else "stopped"
                )
            elif now >= utc(declaration.controller_deadline_at):
                effective = (
                    "reconciliation_only" if extras["ai_intent"] or extras["action"] else "expired"
                )
            elif (
                lease is None
                or lease["owner"] != row["owner"]
                or lease["epoch"] != row["worker_epoch"]
                or utc(lease["expires_at"]) <= now
            ):
                effective = "reconciliation_only"
        return SessionRecord(
            declaration=declaration,
            declaration_sha256=row["declaration_sha256"],
            owner=row["owner"],
            worker_epoch=row["worker_epoch"],
            phase=row["phase"],
            revision=row["revision"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            stop_reason=row["stop_reason"],
            effective_phase=effective,
            selection=extras["selection"],
            ai_intent=extras["ai_intent"],
            action=extras["action"],
        )

    def get(self, session_ref: str, *, now: datetime | None = None):
        from pydantic import TypeAdapter

        from opsark.defense_models import Identifier

        TypeAdapter(Identifier).validate_python(session_ref, strict=True)
        with self.base._connection() as db:
            return self._read(db, session_ref, _now(now))

    def _runtime(self, declaration):
        runtime = self.current_runtime(declaration.runtime.context.host_id)
        if type(runtime) is not SessionRuntime:
            raise DefenseConflict("Session runtime callback did not return a typed snapshot")
        runtime = SessionRuntime.model_validate_json(canonical(runtime))
        if (
            runtime != declaration.runtime
            or self.stopped() is not False
            or not runtime.enabled
            or runtime.stopping
            or not runtime.execution_authorized
            or not runtime.mode_sync_complete
            or runtime.mode.mode != "automatic"
            or runtime.context.mode != "auto"
        ):
            raise DefenseConflict("Session runtime mode, scope or authority changed")
        return runtime

    def _source(self, db, declaration, source: DefenseSource, now, *, latest=True, fresh=True):
        source = DefenseSource.model_validate_json(canonical(source))
        data, reply = self.base._source_time_data(db, source)
        self.base._require_time_data(data, source, context=declaration.runtime.context, now=now)
        if (
            source.host_scope != declaration.runtime.host_scope
            or source.cursor_rid != declaration.cursor_rid
            or source.cursor_deadline_at != declaration.source.cursor_deadline_at
            or (
                fresh
                and not 0
                <= (now - utc(source.observed_at)).total_seconds()
                <= MAX_SOURCE_AGE_SECONDS
            )
        ):
            raise DefenseConflict("Session source does not close its original window")
        row = db.execute(
            "SELECT rowid AS sequence,* FROM defense_observations "
            "WHERE rid=? ORDER BY rowid DESC LIMIT 1",
            (source.cursor_rid,),
        ).fetchone()
        if latest and (
            row is None
            or not row["accepted"]
            or row["op"] != "query"
            or row["receipt_sha256"] != source.root_reply_sha256
            or utc(row["observed_at"]) != utc(source.observed_at)
        ):
            raise DefenseConflict("Session source is not the current exact query")
        return row, reply

    def declare(self, declaration: SessionDeclaration, *, now: datetime | None = None):
        declaration = SessionDeclaration.model_validate_json(canonical(declaration))
        instant = _now(now)
        with self.base._write() as db:
            old = db.execute(
                "SELECT session_ref FROM defense_sessions_v1 WHERE session_ref=?",
                (declaration.session_ref,),
            ).fetchone()
            if old is not None:
                original = self._read(db, declaration.session_ref, instant)
                if original.declaration != declaration:
                    raise DefenseConflict("A session declaration cannot be replaced")
                return original
            runtime = self._runtime(declaration)
            lease = db.execute("SELECT * FROM defense_worker_lease").fetchone()
            if (
                lease is None
                or lease["owner"] != self.owner
                or utc(lease["expires_at"]) <= instant
                or declaration.boot_owner != self.owner
                or declaration.worker_epoch != lease["epoch"]
            ):
                raise DefenseConflict("Session declaration needs its original live worker lease")
            cursor = self.base._transaction(db, declaration.cursor_rid)
            arm = self.base._request(db, cursor.rid, "arm")
            metadata = db.execute(
                "SELECT * FROM defense_requests WHERE rid=? AND op='arm'", (cursor.rid,)
            ).fetchone()
            if (
                cursor.kind != "cursor"
                or cursor.owner != self.owner
                or cursor.context != runtime.context
                or cursor.phase != "armed"
                or cursor.query_required
                or cursor.created_at != declaration.controller_created_at
                or cursor.deadline_at != declaration.controller_deadline_at
                or not isinstance(arm.body, ArmBody)
                or arm.body.observation_grant_ref != runtime.observation_grant_ref
                or hashlib.sha256(arm.wire_bytes()).hexdigest() != declaration.arm_request_sha256
                or metadata is None
                or metadata["dispatch_phase"] != "replied"
                or metadata["send_owner"] != self.owner
                or metadata["reply_sha256"] is None
                or not self.base._mode_confirmed(db, cursor.context)
            ):
                raise DefenseConflict(
                    "Session needs its own explicitly armed cursor and current ACK"
                )
            self._source(db, declaration, declaration.source, instant)
            if (
                db.execute(
                    "SELECT 1 FROM defense_transactions WHERE cursor_rid=?", (cursor.rid,)
                ).fetchone()
                or db.execute("SELECT 1 FROM defense_usage WHERE rid=?", (cursor.rid,)).fetchone()
                or db.execute("SELECT count(*) FROM defense_sessions_v1").fetchone()[0]
                >= MAX_SESSIONS
            ):
                raise DefenseConflict("Session cannot adopt existing work or exceed local capacity")
            stamp = _stamp(instant)
            try:
                db.execute(
                    "INSERT INTO defense_sessions_v1 VALUES(?,?,?,?,?,?,'declared',0,?,?,NULL)",
                    (
                        declaration.session_ref,
                        cursor.rid,
                        self.owner,
                        lease["epoch"],
                        digest(declaration),
                        canonical(declaration),
                        stamp,
                        stamp,
                    ),
                )
            except sqlite3.IntegrityError:
                raise DefenseConflict("A cursor belongs to exactly one original session") from None
            return self._read(db, declaration.session_ref, instant)

    def _lease(self, db, lease, now):
        if type(lease) is not WorkerLease:
            raise DefenseConflict("Session needs the current worker lease")
        row = db.execute("SELECT * FROM defense_worker_lease").fetchone()
        if (
            row is None
            or row["owner"] != self.owner
            or lease.owner != self.owner
            or row["epoch"] != lease.epoch
            or row["expires_at"] != lease.expires_at
            or utc(row["expires_at"]) <= now
        ):
            raise DefenseConflict("Session worker lease is no longer current")

    def admit(
        self,
        session_ref: str,
        lease: WorkerLease,
        *,
        expected_phase: SessionPhase,
        now: datetime | None = None,
    ):
        return self._admit(session_ref, lease, expected_phase=expected_phase, now=now, fresh=True)

    def admit_refresh(
        self,
        session_ref: str,
        lease: WorkerLease,
        *,
        expected_phase: SessionPhase,
        now: datetime | None = None,
    ):
        """Issue only a read-only refresh checkpoint, never a mutation exemption."""
        return self._admit(session_ref, lease, expected_phase=expected_phase, now=now, fresh=False)

    def _admit(self, session_ref, lease, *, expected_phase, now, fresh):
        instant = _now(now)
        with self.base._connection() as db:
            record = self._read(db, session_ref, instant)
            self._lease(db, lease, instant)
            if record.phase != expected_phase or record.worker_epoch != lease.epoch:
                raise DefenseConflict("Session phase changed")
            admission = object.__new__(SessionAdmission)
            for key, value in (
                ("_store", self),
                ("_token", self._token),
                ("session_ref", session_ref),
                ("declaration_sha256", record.declaration_sha256),
                ("owner", self.owner),
                ("worker_epoch", lease.epoch),
                ("phase", record.phase),
                ("revision", record.revision),
            ):
                object.__setattr__(admission, key, value)
            db.execute("BEGIN")
            self._atomic_assert(admission, db, now=instant, fresh=fresh)
            return admission

    def atomic_assert(
        self, admission: SessionAdmission, connection: sqlite3.Connection, *, now=None
    ):
        """SELECT-only fence usable inside a caller's existing BEGIN IMMEDIATE."""
        return self._atomic_assert(admission, connection, now=now, fresh=True)

    def _atomic_assert(self, admission, connection, *, now=None, fresh):
        instant = _now(now)
        database = connection.execute("PRAGMA database_list").fetchone()
        from pathlib import Path

        if (
            not connection.in_transaction
            or database is None
            or Path(database["file"]).resolve() != self.path.resolve()
        ):
            raise DefenseConflict("Session fencing requires the original ledger transaction")
        if (
            type(admission) is not SessionAdmission
            or admission._store is not self
            or admission._token is not self._token
        ):
            raise DefenseConflict("Session admission was not issued by this process")
        record = self._read(connection, admission.session_ref, instant)
        if (
            record.owner != self.owner
            or admission.owner != self.owner
            or record.declaration_sha256 != admission.declaration_sha256
            or record.phase != admission.phase
            or record.revision != admission.revision
            or record.worker_epoch != admission.worker_epoch
            or record.effective_phase != record.phase
            or record.phase in TERMINAL
            or instant < utc(record.declaration.controller_created_at)
            or instant < utc(record.created_at)
            or instant < utc(record.updated_at)
        ):
            raise DefenseConflict("Session owner, phase or original declaration changed")
        lease = connection.execute("SELECT * FROM defense_worker_lease").fetchone()
        if (
            lease is None
            or lease["owner"] != self.owner
            or lease["epoch"] != admission.worker_epoch
            or utc(lease["expires_at"]) <= instant
        ):
            raise DefenseConflict("Session lease expired or changed owner")
        self._runtime(record.declaration)
        cursor = self.base._transaction(connection, record.declaration.cursor_rid)
        if (
            cursor.owner != self.owner
            or cursor.context != record.declaration.runtime.context
            or cursor.deadline_at != record.declaration.controller_deadline_at
            or not self.base._mode_confirmed(connection, cursor.context)
            or connection.execute(
                "SELECT 1 FROM defense_target_latches WHERE host_id=?", (cursor.context.host_id,)
            ).fetchone()
            is not None
        ):
            raise DefenseConflict("Session cursor admission is no longer current")
        if record.selection is not None:
            latest = connection.execute(
                "SELECT * FROM defense_observations WHERE rid=? ORDER BY rowid DESC LIMIT 1",
                (cursor.rid,),
            ).fetchone()
            if latest is None or latest["receipt_bytes"] is None:
                raise DefenseConflict("Session latest source disappeared")
            from opsark.defense_models import DefenseReply

            reply = DefenseReply.parse(latest["receipt_bytes"])
            source = record.selection.source.model_copy(
                update={
                    "observed_at": latest["observed_at"],
                    "root_reply_sha256": latest["receipt_sha256"],
                }
            )
            self._source(connection, record.declaration, source, instant, fresh=fresh)
            if reply.candidates != record.selection.source.candidates:
                raise DefenseConflict("Session selected evidence changed")
        if record.declaration.runtime.requires_ai and record.phase in {
            "analysis_ready",
            "preparing",
            "prepared",
            "applying",
            "confirmed",
        }:
            self._require_ai(record)
        return None

    def assert_live(self, admission: SessionAdmission, *, now: datetime | None = None):
        """Fresh local checkpoint; close the read transaction before any network I/O."""
        with self.base._connection() as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            self.atomic_assert(admission, db, now=now)
        return None

    def assert_refresh(self, admission: SessionAdmission, *, now=None, connection=None):
        """Check original authority for an exact cursor query despite an old receipt.

        This performs no writes and cannot satisfy any ordinary mutation fence.
        The caller must obtain a fresh ordinary admission after the query reply.
        """
        if connection is not None:
            return self._atomic_assert(admission, connection, now=now, fresh=False)
        with self.base._connection() as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            return self._atomic_assert(admission, db, now=now, fresh=False)

    def _using(self, admission, connection, now, work):
        if connection is not None:
            self.atomic_assert(admission, connection, now=now)
            return work(connection)
        with self.base._write() as db:
            self.atomic_assert(admission, db, now=now)
            return work(db)

    def _require_ai(self, row):
        if row.ai_intent is None or row.selection is None:
            raise DefenseConflict("Session has no original AI cost binding")
        permit = self.base.ai_permit(analysis_id=row.ai_intent.analysis_id)
        result = self.base.ai_result(row.ai_intent.analysis_id)
        if permit is None:
            raise DefenseConflict("Session AI result is incomplete or stale")
        source, aliases = self.base.source(permit.source_key)
        if (
            permit.intent_key != row.ai_intent.intent_key
            or permit.input_digest != row.ai_intent.input_digest
            or permit.provider_fingerprint != row.ai_intent.provider_fingerprint
            or permit.advice_authorization is not None
            or source != row.selection.source
            or len(aliases.aliases) != 1
            or aliases.aliases[0].source_ref != row.selection.source_ref
            or aliases.aliases[0].evidence_sha256 != row.selection.evidence_sha256
            or self.base.usage(permit.intent_key).state != "consumed"
            or result is None
            or result.status != "completed"
            or result.decision != "propose_defense"
            or result.source_ref != row.selection.source_ref
            or result.evidence_sha256 != row.selection.evidence_sha256
            or result.proof_sha256
            != DefenseAIService._proof(
                result, permit, row.selection.source, row.declaration.runtime.context
            )
        ):
            raise DefenseConflict("Session AI result is incomplete or stale")

    @staticmethod
    def _once(db, table, record, extra_columns="", extra_values=()):
        old = db.execute(
            "SELECT * FROM " + table + " WHERE session_ref=?",  # noqa: S608 -- fixed internal table identifiers only.
            (record.session_ref,),
        ).fetchone()
        if old is not None:
            if old["sha256"] != digest(record) or old["typed_record"] != canonical(record):
                raise DefenseConflict("A session sidecar cannot be replaced")
            return record
        columns = "session_ref,sha256,typed_record" + extra_columns
        values = (record.session_ref, digest(record), canonical(record), *extra_values)
        marks = ",".join("?" for _ in values)
        db.execute("INSERT INTO " + table + "(" + columns + ") VALUES(" + marks + ")", values)  # noqa: S608 -- fixed internal identifiers; values are placeholders.
        return record

    def select_source(self, admission, source, source_ref, evidence_sha256, *, now=None):
        instant = _now(now)

        def work(db):
            row = self._read(db, admission.session_ref, instant)
            if row.phase != "observing":
                raise DefenseConflict("Source selection needs the original observing phase")
            frame, reply = self._source(db, row.declaration, source, instant)
            matches = [
                candidate
                for candidate in reply.candidates
                if candidate.source_ref == source_ref
                and candidate.evidence_sha256 == evidence_sha256
                and candidate.classification == "eligible"
                and candidate.source_alias in row.declaration.runtime.allowed_source_aliases
            ]
            if len(matches) != 1:
                raise DefenseConflict("Session source is not an authorized eligible candidate")
            if row.selection is not None:
                if (
                    row.selection.source != source
                    or row.selection.source_ref != source_ref
                    or row.selection.evidence_sha256 != evidence_sha256
                ):
                    raise DefenseConflict("A selected source cannot be replaced")
                return row.selection
            selection = SessionSelection(
                session_ref=admission.session_ref,
                source=source,
                source_ref=source_ref,
                evidence_sha256=evidence_sha256,
                observed_sequence=frame["sequence"],
                selected_at=_stamp(instant),
            )
            return self._once(db, "defense_session_selections_v1", selection)

        return self._using(admission, None, instant, work)

    def bind_ai(self, admission, intent: SessionAIIntent, *, now=None, connection=None):
        intent = SessionAIIntent.model_validate_json(canonical(intent))
        instant = _now(now)

        def work(db):
            row = self._read(db, admission.session_ref, instant)
            if (
                row.phase != "analyzing"
                or row.selection is None
                or not row.declaration.runtime.requires_ai
            ):
                raise DefenseConflict("Session has no AI admission phase")
            fingerprint = row.declaration.runtime.provider_fingerprint
            if (
                intent.session_ref != admission.session_ref
                or intent.selection_sha256 != digest(row.selection)
                or fingerprint is None
                or intent.provider_fingerprint != fingerprint
                or intent.intent_key
                != intent_key(row.selection.source, row.selection.source_ref, fingerprint)
                or intent.analysis_id != digest({"ssh_defense_analysis": intent.intent_key})[:32]
            ):
                raise DefenseConflict("Session AI cost identity changed")
            return self._once(
                db,
                "defense_session_ai_v1",
                intent,
                ",analysis_id,intent_key",
                (intent.analysis_id, intent.intent_key),
            )

        return self._using(admission, connection, instant, work)

    def bind_ai_permit(self, admission, permit: AIUsagePermit, *, now=None, connection=None):
        """Bind only the real permit inserted in the same cost transaction."""
        permit = AIUsagePermit.model_validate_json(canonical(permit))
        instant = _now(now)

        def work(db):
            record = self._read(db, admission.session_ref, instant)
            raw = db.execute(
                "SELECT * FROM defense_ai_intents WHERE analysis_id=?", (permit.analysis_id,)
            ).fetchone()
            source, _ = self.base._read_source(db, permit.source_key)
            usage = db.execute(
                "SELECT state FROM defense_usage WHERE intent_key=?", (permit.intent_key,)
            ).fetchone()
            if (
                record.selection is None
                or raw is None
                or raw["permit_sha256"] != digest(permit)
                or raw["typed_permit"] != canonical(permit)
                or permit.rid != record.declaration.cursor_rid
                or permit.owner != self.owner
                or permit.advice_authorization is not None
                or permit.deadline_at != record.declaration.controller_deadline_at
                or source != record.selection.source
                or usage is None
                or usage["state"] != "consumed"
                or not utc(record.selection.selected_at)
                <= utc(permit.committed_at)
                < utc(permit.deadline_at)
            ):
                raise DefenseConflict("Session AI permit is not its original committed cost")
            value = SessionAIIntent(
                session_ref=admission.session_ref,
                analysis_id=permit.analysis_id,
                intent_key=permit.intent_key,
                input_digest=permit.input_digest,
                provider_fingerprint=permit.provider_fingerprint,
                selection_sha256=digest(record.selection),
            )
            return self.bind_ai(admission, value, now=instant, connection=db)

        return self._using(admission, connection, instant, work)

    def bind_action(self, admission, rid, *, now=None, connection=None):
        instant = _now(now)

        def work(db):
            row = self._read(db, admission.session_ref, instant)
            action = self.base._transaction(db, rid)
            if row.action is not None:
                if row.action.rid != rid:
                    raise DefenseConflict("A session cannot bind a second action")
                return row.action
            if (
                row.phase != "preparing"
                or row.selection is None
                or action.kind != "action"
                or action.cursor_rid != row.declaration.cursor_rid
                or action.owner != self.owner
                or action.context != row.declaration.runtime.context
                or action.deadline_at != row.declaration.controller_deadline_at
                or action.phase != "created"
            ):
                raise DefenseConflict("Session cannot adopt an action from another sender")
            if action.cursor_rid is None:
                raise DefenseConflict("A session action has no original cursor")
            value = SessionAction(
                session_ref=admission.session_ref,
                rid=rid,
                cursor_rid=action.cursor_rid,
                context_sha256=digest(action.context),
                owner=action.owner,
                deadline_at=action.deadline_at,
            )
            return self._once(db, "defense_session_actions_v1", value, ",rid", (rid,))

        return self._using(admission, connection, instant, work)

    def bind_request(self, admission, request: DefenseRequest, *, now=None, connection=None):
        request = DefenseRequest.parse(request.wire_bytes())
        instant = _now(now)

        def work(db):
            row = self._read(db, admission.session_ref, instant)
            if row.action is None or row.selection is None or request.request_id != row.action.rid:
                raise DefenseConflict("Session request has no original action binding")
            if request.scope_sha256 != row.declaration.runtime.context.root_scope:
                raise DefenseConflict("Session request scope changed")
            if (
                request.op == "prepare"
                and row.phase == "preparing"
                and isinstance(request.body, PrepareBody)
            ):
                body, runtime = request.body, row.declaration.runtime
                _, reply = self.base._source_time_data(db, row.selection.source)
                if (
                    body.cursor_id != reply.cursor_id
                    or body.source_ref != row.selection.source_ref
                    or body.evidence_sha256 != row.selection.evidence_sha256
                    or body.mode != "auto"
                    or body.mode_revision != runtime.context.wire_revision
                    or body.policy_sha256 != runtime.context.policy_sha256
                    or body.controller_grant_ref != runtime.controller_grant_ref
                    or body.root_grant_ref != runtime.root_grant_ref
                ):
                    raise DefenseConflict("Session preparation declaration changed")
            elif (
                request.op == "apply"
                and row.phase == "applying"
                and isinstance(request.body, ActionBody)
            ):
                if (
                    request.body.approval is not None
                    or request.body.manifest_sha256
                    != self.base._manifest(db, request.request_id).sha256
                ):
                    raise DefenseConflict("An automatic session cannot borrow a human approval")
            else:
                raise DefenseConflict("Session cannot bind this mutation or phase")
            binding = SessionRequestBinding(
                session_ref=admission.session_ref,
                rid=request.request_id,
                op=request.op,
                request_sha256=hashlib.sha256(request.wire_bytes()).hexdigest(),
                owner=self.owner,
                worker_epoch=admission.worker_epoch,
            )
            old = db.execute(
                "SELECT * FROM defense_session_requests_v1 WHERE rid=? AND op=?",
                (binding.rid, binding.op),
            ).fetchone()
            if old is not None:
                if old["sha256"] != digest(binding) or old["typed_record"] != canonical(binding):
                    raise DefenseConflict("A session request binding cannot be replaced")
            else:
                db.execute(
                    "INSERT INTO defense_session_requests_v1 VALUES(?,?,?,?,?)",
                    (
                        binding.rid,
                        binding.op,
                        binding.session_ref,
                        digest(binding),
                        canonical(binding),
                    ),
                )
            return binding

        return self._using(admission, connection, instant, work)

    def advance(self, admission, *, next_phase: SessionPhase, now=None):
        instant = _now(now)

        def work(db):
            row = self._read(db, admission.session_ref, instant)
            if next_phase not in NEXT.get(row.phase, set()):
                raise DefenseConflict("Session phase transition is not allowed")
            if next_phase in {"analyzing", "preparing"} and row.selection is None:
                raise DefenseConflict("Session has no selected evidence")
            if next_phase == "analyzing" and not row.declaration.runtime.requires_ai:
                raise DefenseConflict("This session has no model-call authorization")
            if (
                next_phase == "preparing"
                and row.declaration.runtime.requires_ai
                and row.phase != "analysis_ready"
            ):
                raise DefenseConflict("Required AI advice cannot be bypassed")
            if next_phase == "analysis_ready":
                self._require_ai(row)
            if next_phase in {"prepared", "applying", "confirmed", "completed"}:
                if row.action is None:
                    raise DefenseConflict("Session has no original action")
                action = self.base._transaction(db, row.action.rid)
                if next_phase in {"prepared", "applying"} and (
                    action.phase != "ready" or action.query_required
                ):
                    raise DefenseConflict("Session preparation is not confirmed")
                if next_phase in {"confirmed", "completed"} and (
                    action.phase != "active" or action.query_required
                ):
                    raise DefenseConflict("Session execution is not confirmed")
                op = "prepare" if next_phase in {"prepared", "applying"} else "apply"
                bound = db.execute(
                    "SELECT * FROM defense_session_requests_v1 WHERE rid=? AND op=?",
                    (action.rid, op),
                ).fetchone()
                actual = db.execute(
                    "SELECT * FROM defense_requests WHERE rid=? AND op=?", (action.rid, op)
                ).fetchone()
                if (
                    bound is None
                    or actual is None
                    or actual["dispatch_phase"] != "replied"
                    or actual["reply_sha256"] is None
                ):
                    raise DefenseConflict("Session needs its directly recorded operation receipt")
                binding = _typed(SessionRequestBinding, bound["typed_record"], bound["sha256"])
                if (
                    actual["request_sha256"] != binding.request_sha256
                    or binding.session_ref != admission.session_ref
                    or bound["session_ref"] != binding.session_ref
                    or binding.rid != action.rid
                    or binding.op != op
                    or binding.owner != self.owner
                    or binding.worker_epoch != admission.worker_epoch
                    or actual["send_owner"] != self.owner
                ):
                    raise DefenseConflict("Session original request changed")
            db.execute(
                "UPDATE defense_sessions_v1 SET phase=?,revision=revision+1,updated_at=? "
                "WHERE session_ref=? AND phase=? AND revision=?",
                (
                    next_phase,
                    _stamp(instant),
                    admission.session_ref,
                    admission.phase,
                    admission.revision,
                ),
            )
            return self._read(db, admission.session_ref, instant)

        return self._using(admission, None, instant, work)

    def halt(self, session_ref: str, *, reason: SessionStopReason, now=None):
        instant = _now(now)
        with self.base._write() as db:
            row = self._read(db, session_ref, instant)
            if row.owner != self.owner:
                raise DefenseConflict("A new process may only read the original session")
            if row.phase in TERMINAL:
                return row
            # Validate the fixed reason without accepting exception text.
            SessionRecord.model_validate_json(
                canonical(row.model_copy(update={"stop_reason": reason}))
            )
            phase = (
                "reconciliation_only"
                if row.ai_intent or row.action or reason == "result_unknown"
                else "stopped"
            )
            if reason == "deadline_elapsed" and phase == "stopped":
                phase = "expired"
            db.execute(
                "UPDATE defense_sessions_v1 SET phase=?,revision=revision+1,stop_reason=?,"
                "updated_at=? WHERE session_ref=?",
                (phase, reason, _stamp(instant), session_ref),
            )
            return self._read(db, session_ref, instant)
