"""Dormant, explicitly armed one-action sessions; no deployment switch or auto-arm."""

from datetime import timedelta
from threading import Event, Lock

from pydantic import TypeAdapter

from opsark.baselines import scope_for
from opsark.defense_ai import AI_BUDGET_REF, DefenseAIService, ModelInput, intent_key
from opsark.defense_api import PrepareRequest
from opsark.defense_client import MAX_KNOWN_HOSTS_BYTES, _read_file
from opsark.defense_models import Identifier, canonical, digest, utc
from opsark.defense_policy import HostId
from opsark.defense_session_models import (
    SessionDeclaration,
    SessionModeSnapshot,
    SessionRuntime,
)
from opsark.defense_session_store import MAX_SOURCE_AGE_SECONDS, TERMINAL, DefenseSessionStore
from opsark.defense_store import AIResult, AIUsagePermit, DefenseConflict, UsageMetadata, _now

RPC_SECONDS = 10
AI_SECONDS = 20
FINISH_MARGIN_SECONDS = 5
OBSERVATION_INTERVAL_SECONDS = 5


def _receipt_model(model, row, hash_column, body_column):
    if row is None:
        raise DefenseConflict("Original AI receipt is incomplete")
    raw = row[body_column]
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise DefenseConflict("Original AI receipt is invalid")
    value = model.model_validate_json(raw)
    if canonical(value) != raw or digest(value) != row[hash_column]:
        raise DefenseConflict("Original AI receipt integrity changed")
    return value


class DefenseSessionCoordinator:
    """Internal coordinator only. Creating this object never starts network work.

    A fresh process can read old sessions and query their original identities;
    it never reconstructs the in-memory worker lease needed for new mutations.
    """

    def __init__(self, controller, *, ai_service=None, clock=None):
        self.controller = controller
        self.ai_service = ai_service if ai_service is not None else controller.ai_service
        self.clock = clock or controller.clock
        self.stopped = Event()
        self._lock = Lock()
        self._leases = {}
        self._query_after = {}
        self._reconciled = set()
        existing = getattr(controller.store, "_session_guard", None)
        self._mutation_owner = existing is None
        if existing is None:
            self.store = DefenseSessionStore(
                controller.store,
                owner=controller.owner,
                current_runtime=self.runtime,
                stopped=lambda: self.stopped.is_set() or controller.stopped.is_set(),
            )
        elif (
            type(existing) is DefenseSessionStore
            and existing.base is controller.store
            and existing.owner == controller.owner
        ):
            self.store = existing
        else:
            raise DefenseConflict("Session coordinator cannot replace another registered guard")

    def _now(self):
        return _now(self.clock())

    def _pins(self, host_id):
        target = self.controller.targets.get(host_id)
        if target is None or target.host.public.id != host_id:
            raise DefenseConflict("Session target is not currently registered")
        for role in ("readonly", "observe", "control"):
            credential = getattr(target, role)
            _, seal = _read_file(credential.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
            if seal != credential._hosts_seal or seal.sha256 != credential.trusted_hosts_digest:
                raise DefenseConflict("Session public trust changed")
        return target

    def runtime(self, host_id):
        """Pure read callback: no mode lock, network or write transaction."""
        target = self._pins(host_id)
        context = self.controller._context(host_id)
        grant = self.controller._execution(context)
        observed = self.controller._observe(context)
        snapshot = self.controller._snapshot()
        return SessionRuntime(
            context=context,
            mode=SessionModeSnapshot.capture(snapshot),
            host_scope=scope_for(target.host.public),
            enabled=bool(self.controller.policy.enabled and self.controller.targets),
            stopping=self.stopped.is_set() or self.controller.stopped.is_set(),
            mode_sync_complete=self.controller.automation.status()["mode_sync_complete"],
            execution_authorized=True,
            observation_grant_ref=observed,
            controller_grant_ref=grant.grant_ref,
            root_grant_ref=grant.root_grant_refs[host_id],
            allowed_source_aliases=grant.source_aliases,
            requires_ai=self.controller.policy.ai.requires_ai,
            provider_fingerprint=self.controller.policy.ai.provider_fingerprint,
        )

    def get(self, session_ref):
        return self.store.get(session_ref, now=self._now())

    def ai_receipt(self, host_id, session_ref):
        """Local historical facts only; no current provider or execution admission.

        usage_state is the original OpsArk quota ledger, not provider billing.
        Read all bindings in one snapshot and disclose no partial corrupt result.
        """
        try:
            return self._ai_receipt(host_id, session_ref)
        except DefenseConflict:
            raise
        except (ValueError, TypeError, KeyError, OverflowError):
            raise DefenseConflict("Original session AI receipt could not be verified") from None

    def _ai_receipt(self, host_id, session_ref):
        TypeAdapter(HostId).validate_python(host_id, strict=True)
        TypeAdapter(Identifier).validate_python(session_ref, strict=True)
        with self.controller.store._connection() as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            record = self.store._read(db, session_ref, self._now())
            if record.declaration.runtime.context.host_id != host_id:
                raise DefenseConflict("Session belongs to another original host")
            view = {
                "v": 1,
                "session_ref": session_ref,
                "analysis_id": None,
                "status": "not_started"
                if record.declaration.runtime.requires_ai
                else "not_required",
                "decision": None,
                "usage_state": None,
                "input_digest": None,
                "proof_sha256": None,
                "actions_executable": False,
            }
            if record.ai_intent is None:
                orphan = db.execute(
                    "SELECT 1 FROM defense_usage WHERE kind='ai' AND rid=?",
                    (record.declaration.cursor_rid,),
                ).fetchone()
                if record.declaration.runtime.requires_ai:
                    if record.phase in {
                        "analysis_ready",
                        "preparing",
                        "prepared",
                        "applying",
                        "confirmed",
                        "completed",
                        "reconciliation_only",
                    } or (record.phase == "analyzing" and record.selection is None):
                        raise DefenseConflict("Session AI sidecar is missing")
                    if record.selection is not None:
                        fingerprint = record.declaration.runtime.provider_fingerprint
                        if fingerprint is None:
                            raise DefenseConflict("Session original AI identity is missing")
                        key = intent_key(
                            record.selection.source, record.selection.source_ref, fingerprint
                        )
                        analysis_id = digest({"ssh_defense_analysis": key})[:32]
                        orphan = (
                            orphan
                            or db.execute(
                                "SELECT 1 FROM defense_ai_intents WHERE analysis_id=? "
                                "UNION ALL SELECT 1 FROM defense_ai_results "
                                "WHERE analysis_id=? LIMIT 1",
                                (analysis_id, analysis_id),
                            ).fetchone()
                        )
                if orphan:
                    raise DefenseConflict("Session AI sidecar is missing")
                return view
            return view | self._original_ai_receipt(db, record)

    def _original_ai_receipt(self, db, record):
        declaration, sidecar, selection = record.declaration, record.ai_intent, record.selection
        if sidecar is None or selection is None or not declaration.runtime.requires_ai:
            raise DefenseConflict("Session has no original AI binding")
        row = db.execute(
            "SELECT * FROM defense_ai_intents WHERE analysis_id=?", (sidecar.analysis_id,)
        ).fetchone()
        permit = _receipt_model(AIUsagePermit, row, "permit_sha256", "typed_permit")
        source, aliases = self.controller.store._read_source(db, permit.source_key)
        fee_row = db.execute(
            "SELECT * FROM defense_usage WHERE intent_key=?", (sidecar.intent_key,)
        ).fetchone()
        if fee_row is None:
            raise DefenseConflict("Session AI quota record is missing")
        usage = UsageMetadata.model_validate(dict(fee_row))
        context = declaration.runtime.context
        if (
            row["analysis_id"] != sidecar.analysis_id
            or row["intent_key"] != sidecar.intent_key
            or permit.analysis_id != sidecar.analysis_id
            or permit.intent_key != sidecar.intent_key
            or permit.input_digest != sidecar.input_digest
            or permit.provider_fingerprint != sidecar.provider_fingerprint
            or permit.rid != declaration.cursor_rid
            or permit.owner != declaration.boot_owner
            or permit.deadline_at != declaration.controller_deadline_at
            or permit.advice_authorization is not None
            or not utc(selection.selected_at) <= utc(permit.committed_at) < utc(permit.deadline_at)
            or source != selection.source
            or permit.source_key != digest({"source": digest(source), "aliases": digest(aliases)})
            or len(aliases.aliases) != 1
            or aliases.aliases[0].candidate_alias != "candidate-1"
            or aliases.aliases[0].evidence_alias != "evidence-1"
            or aliases.aliases[0].source_ref != selection.source_ref
            or aliases.aliases[0].evidence_sha256 != selection.evidence_sha256
            or usage.intent_key != permit.intent_key
            or usage.kind != "ai"
            or usage.rid != permit.rid
            or usage.host_id != context.host_id
            or usage.defense_scope != context.defense_scope
            or usage.provider_fingerprint != permit.provider_fingerprint
            or usage.grant_ref != AI_BUDGET_REF
            or usage.created_at != permit.committed_at
            or usage.charged_day != utc(permit.committed_at).date().isoformat()
        ):
            raise DefenseConflict("Session original AI identity changed")
        matches = [item for item in source.candidates if item.source_ref == selection.source_ref]
        if len(matches) != 1 or matches[0].classification != "eligible":
            raise DefenseConflict("Session original AI candidate changed")
        summary = ModelInput.model_validate_json(
            canonical(
                {
                    "v": 1,
                    "candidates": [
                        {
                            "candidate_alias": "candidate-1",
                            "evidence_alias": "evidence-1",
                            "classification": "eligible",
                            "distinct_failure_ports": matches[0].distinct_failure_ports,
                            "ttl_seconds": 60,
                        }
                    ],
                    "omitted_candidate_count": len(source.candidates) - 1,
                }
            )
        ).model_dump(mode="json")
        if (
            sidecar.analysis_id != digest({"ssh_defense_analysis": sidecar.intent_key})[:32]
            or sidecar.intent_key
            != intent_key(source, selection.source_ref, sidecar.provider_fingerprint)
            or sidecar.input_digest
            != DefenseAIService._input_digest(
                source, summary, aliases, sidecar.provider_fingerprint
            )
        ):
            raise DefenseConflict("Session original AI input changed")
        result_row = db.execute(
            "SELECT * FROM defense_ai_results WHERE analysis_id=?", (sidecar.analysis_id,)
        ).fetchone()
        result = (
            None
            if result_row is None
            else _receipt_model(AIResult, result_row, "result_sha256", "typed_result")
        )
        if result is not None:
            proposal = result.status == "completed" and result.decision == "propose_defense"
            if (
                result_row["analysis_id"] != sidecar.analysis_id
                or result_row["intent_key"] != sidecar.intent_key
                or result.analysis_id != permit.analysis_id
                or result.intent_key != permit.intent_key
                or result.input_digest != permit.input_digest
                or result.provider_fingerprint != permit.provider_fingerprint
                or (
                    proposal
                    and (
                        result.source_ref != selection.source_ref
                        or result.evidence_sha256 != selection.evidence_sha256
                        or result.proof_sha256
                        != DefenseAIService._proof(result, permit, source, context)
                    )
                )
                or (
                    not proposal
                    and any(
                        value is not None
                        for value in (
                            result.source_ref,
                            result.evidence_sha256,
                            result.proof_sha256,
                        )
                    )
                )
                or (
                    result.status != "completed"
                    and (result.decision is not None or result.reason_code is not None)
                )
                or (
                    result.status == "completed"
                    and result.reason_code
                    != {
                        "propose_defense": "evidence_sufficient",
                        "collect_more": "evidence_gap",
                        "review_access": "access_review",
                        "no_action": "no_match",
                    }.get(result.decision)
                )
            ):
                raise DefenseConflict("Session original AI result changed")
        return {
            "analysis_id": sidecar.analysis_id,
            "status": "unknown" if result is None else result.status,
            "decision": None if result is None else result.decision,
            "usage_state": usage.state,
            "input_digest": sidecar.input_digest,
            "proof_sha256": None if result is None else result.proof_sha256,
        }

    def status(self):
        return {
            "session_only": True,
            "continuous_execution": False,
            "max_actions_per_session": 1,
            "background_started": False,
            "stopping": self.stopped.is_set(),
            "owned_sessions": len(self._leases),
            "mutation_owner": self._mutation_owner,
        }

    def owned_session_refs(self):
        """Only references explicitly started in this process, never restored rows."""
        return tuple(self._leases)

    def list(self, host_id, *, after_sequence=0, limit=20):
        TypeAdapter(HostId).validate_python(host_id, strict=True)
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence < 2**63
            or type(limit) is not int
            or not 1 <= limit <= 20
        ):
            raise DefenseConflict("Session history page is invalid")
        with self.controller.store._connection() as db:
            db.execute("BEGIN")
            rows = db.execute(
                "SELECT s.rowid AS sequence,s.session_ref FROM defense_sessions_v1 s "
                "JOIN defense_transactions t ON t.rid=s.cursor_rid "
                "WHERE t.host_id=? AND s.rowid>? ORDER BY s.rowid LIMIT ?",
                (host_id, after_sequence, limit + 1),
            ).fetchall()
            visible = rows[:limit]
            result = [
                {
                    "sequence": row["sequence"],
                    "record": self.store._read(db, row["session_ref"], self._now()),
                }
                for row in visible
            ]
        return {
            "sessions": result,
            "next_after_sequence": visible[-1]["sequence"] if len(rows) > limit else None,
        }

    def start(self, host_id, cursor_rid, *, expected_mode_revision, session_ref):
        with self._lock:
            with self.controller.store._connection() as db:
                old = db.execute(
                    "SELECT session_ref FROM defense_sessions_v1 WHERE session_ref=?",
                    (session_ref,),
                ).fetchone()
                cursor_session = db.execute(
                    "SELECT session_ref FROM defense_sessions_v1 WHERE cursor_rid=?",
                    (cursor_rid,),
                ).fetchone()
            if old is not None:
                record = self.get(session_ref)
                if (
                    record.declaration.cursor_rid != cursor_rid
                    or record.declaration.runtime.context.host_id != host_id
                    or record.declaration.runtime.mode.revision != expected_mode_revision
                ):
                    raise DefenseConflict("An existing session declaration cannot be replaced")
                return record
            if cursor_session is not None:
                raise DefenseConflict("The original cursor already belongs to another session")
            if not self._mutation_owner:
                raise DefenseConflict("An existing registered coordinator is read-only here")
            if self.stopped.is_set() or self.controller.stopped.is_set():
                raise DefenseConflict("Session coordinator is stopping")
            with self.controller.mode_lock:
                context = self.controller._expected(host_id, expected_mode_revision)
                cursor = self.controller._transaction(host_id, cursor_rid)
                if (
                    context.mode != "auto"
                    or cursor.kind != "cursor"
                    or cursor.owner != self.controller.owner
                    or cursor.context != context
                ):
                    raise DefenseConflict(
                        "A session needs its own explicitly armed automatic cursor"
                    )
                expected = self.runtime(host_id)
            instant = self._now()
            if not instant < utc(cursor.deadline_at):
                raise DefenseConflict("The original Controller observation window elapsed")
            lease = self.controller.store.acquire_worker(
                self.controller.owner, expires_at=cursor.deadline_at, now=instant
            )
            if lease is None:
                raise DefenseConflict("Another worker owns the current session window")
            try:

                def guard():
                    if self.stopped.is_set() or self.controller.stopped.is_set():
                        raise DefenseConflict("Session coordinator is stopping")
                    self.controller.store.assert_worker(lease, now=self._now())
                    if self.runtime(host_id) != expected:
                        raise DefenseConflict("Session runtime changed before initial query")

                def commit_guard(connection):
                    if self.stopped.is_set() or self.controller.stopped.is_set():
                        raise DefenseConflict("Session coordinator is stopping")
                    self.controller.store.assert_worker(
                        lease, now=self._now(), connection=connection
                    )
                    if self.runtime(host_id) != expected:
                        raise DefenseConflict("Session runtime changed before initial receipt")

                self.controller.query_with_observation(
                    host_id,
                    cursor_rid,
                    admit=guard,
                    commit_guard=commit_guard,
                    rpc_timeout=RPC_SECONDS,
                )
                guard()
                source = self.controller.store.cursor_source(
                    cursor_rid, host_scope=expected.host_scope
                )
                record = self.store.declare(
                    SessionDeclaration(
                        session_ref=session_ref,
                        cursor_rid=cursor_rid,
                        boot_owner=self.controller.owner,
                        worker_epoch=lease.epoch,
                        runtime=expected,
                        source=source,
                        arm_request_sha256=self.controller.store.request_metadata(
                            cursor_rid, "arm"
                        ).request_sha256,
                        controller_created_at=cursor.created_at,
                        controller_deadline_at=cursor.deadline_at,
                    ),
                    now=self._now(),
                )
                permit = self.store.admit(
                    session_ref, lease, expected_phase="declared", now=self._now()
                )
                record = self.store.advance(permit, next_phase="observing", now=self._now())
            except Exception:
                self.controller.store.release_worker(lease, now=self._now())
                raise
            self._leases[session_ref] = lease
            self._query_after[session_ref] = self._now() + timedelta(
                seconds=OBSERVATION_INTERVAL_SECONDS
            )
            return record

    def _admission(self, record):
        if self.stopped.is_set() or self.controller.stopped.is_set():
            raise DefenseConflict("Session coordinator is stopping")
        lease = self._leases.get(record.declaration.session_ref)
        if lease is None:
            raise DefenseConflict("This process does not own the original worker lease")
        return self.store.admit(
            record.declaration.session_ref, lease, expected_phase=record.phase, now=self._now()
        )

    def _budget(self, record, seconds):
        now = self._now()
        return (
            utc(record.declaration.controller_created_at) <= now
            and (utc(record.declaration.controller_deadline_at) - now).total_seconds() >= seconds
        )

    def _release(self, session_ref):
        lease = self._leases.pop(session_ref, None)
        self._query_after.pop(session_ref, None)
        if lease is not None:
            self.controller.store.release_worker(lease, now=self._now())

    def _halt(self, record, reason):
        try:
            if record.owner == self.controller.owner:
                return self.store.halt(
                    record.declaration.session_ref, reason=reason, now=self._now()
                )
            return record
        finally:
            self._release(record.declaration.session_ref)

    def _query_cursor(self, record, admission):
        def guard():
            if self.stopped.is_set() or self.controller.stopped.is_set():
                raise DefenseConflict("Session coordinator is stopping")
            self.controller.store.require_session_admission(
                record.declaration.cursor_rid, admission, phase=record.phase, now=self._now()
            )

        def commit_guard(connection):
            if self.stopped.is_set() or self.controller.stopped.is_set():
                raise DefenseConflict("Session coordinator is stopping")
            self.controller.store.require_session_admission(
                record.declaration.cursor_rid,
                admission,
                phase=record.phase,
                now=self._now(),
                connection=connection,
            )

        self.controller.query_with_observation(
            record.declaration.runtime.context.host_id,
            record.declaration.cursor_rid,
            admit=guard,
            commit_guard=commit_guard,
            rpc_timeout=RPC_SECONDS,
        )
        guard()
        return self.controller.store.cursor_source(
            record.declaration.cursor_rid, host_scope=record.declaration.runtime.host_scope
        )

    def _refresh_source(self, record, required):
        """Refresh only the original cursor; keep selection and paid advice immutable."""
        if record.selection is None or record.phase == "analyzing":
            return record
        source = self.controller.store.cursor_source(
            record.declaration.cursor_rid, host_scope=record.declaration.runtime.host_scope
        )
        next_io = {
            "analyzing": AI_SECONDS,
            "analysis_ready": 2 * RPC_SECONDS,
            "preparing": 2 * RPC_SECONDS,
            "prepared": RPC_SECONDS,
            "applying": RPC_SECONDS,
        }.get(record.phase, 0)
        refresh_age = MAX_SOURCE_AGE_SECONDS - next_io - FINISH_MARGIN_SECONDS
        if (self._now() - utc(source.observed_at)).total_seconds() <= refresh_age:
            return record
        if not self._budget(record, RPC_SECONDS + (required or FINISH_MARGIN_SECONDS)):
            return self._halt(record, "budget_insufficient")
        admission = self.store.admit_refresh(
            record.declaration.session_ref,
            self._leases[record.declaration.session_ref],
            expected_phase=record.phase,
            now=self._now(),
        )

        def guard():
            return self.store.assert_refresh(admission, now=self._now())

        def commit_guard(connection):
            return self.store.assert_refresh(admission, now=self._now(), connection=connection)

        self.controller.query_with_observation(
            record.declaration.runtime.context.host_id,
            record.declaration.cursor_rid,
            admit=guard,
            commit_guard=commit_guard,
            rpc_timeout=RPC_SECONDS,
        )
        # The query is no execution authority. Its fresh receipt must close the
        # ordinary <=30s fence and exactly match the original candidate evidence.
        self._admission(record)
        return self.get(record.declaration.session_ref)

    def _reconcile(self, record, *, force=False):
        reference = record.declaration.session_ref
        if force or reference not in self._reconciled:
            rid = record.action.rid if record.action is not None else record.declaration.cursor_rid
            self.controller.query(record.declaration.runtime.context.host_id, rid)
            self._reconciled.add(reference)
        return self.get(reference)

    def tick(self, session_ref):
        if not self._lock.acquire(blocking=False):
            return self.get(session_ref)
        try:
            record = self.get(session_ref)
            if record.phase in TERMINAL or record.effective_phase != record.phase:
                self._release(session_ref)
                return record
            if session_ref not in self._leases:
                return record.model_copy(update={"effective_phase": "reconciliation_only"})
            try:
                return self._tick(record)
            except (ValueError, OSError, RuntimeError, KeyError):
                retained = self.get(session_ref)
                return self._halt(
                    retained,
                    "requested"
                    if self.stopped.is_set() or self.controller.stopped.is_set()
                    else "deadline_elapsed"
                    if not self._budget(retained, 0)
                    else "result_unknown"
                    if retained.action or retained.ai_intent
                    else "proof_changed",
                )
        finally:
            self._lock.release()

    def _tick(self, record):
        required = {
            "analyzing": AI_SECONDS + 3 * RPC_SECONDS + FINISH_MARGIN_SECONDS,
            "analysis_ready": 3 * RPC_SECONDS + FINISH_MARGIN_SECONDS,
            "preparing": 3 * RPC_SECONDS + FINISH_MARGIN_SECONDS,
            "prepared": RPC_SECONDS + FINISH_MARGIN_SECONDS,
            "applying": RPC_SECONDS + FINISH_MARGIN_SECONDS,
        }.get(record.phase)
        if required is not None and not self._budget(record, required):
            return self._halt(record, "budget_insufficient")
        record = self._refresh_source(record, required)
        if record.phase in TERMINAL:
            return record
        admission = self._admission(record)
        reference = record.declaration.session_ref
        host = record.declaration.runtime.context.host_id
        if record.phase == "observing":
            if record.selection is None:
                source = self.controller.store.cursor_source(
                    record.declaration.cursor_rid, host_scope=record.declaration.runtime.host_scope
                )
                eligible = [item for item in source.candidates if item.classification == "eligible"]
                source_age = (self._now() - utc(source.observed_at)).total_seconds()
                if not eligible or source_age > MAX_SOURCE_AGE_SECONDS - RPC_SECONDS:
                    if self._now() < self._query_after.get(reference, self._now()):
                        return record
                    if not self._budget(record, RPC_SECONDS + FINISH_MARGIN_SECONDS):
                        return self._halt(record, "budget_insufficient")
                    source = self._query_cursor(record, admission)
                    self._query_after[reference] = self._now() + timedelta(
                        seconds=OBSERVATION_INTERVAL_SECONDS
                    )
                    eligible = [
                        item for item in source.candidates if item.classification == "eligible"
                    ]
                if not eligible:
                    return self.get(reference)
                if (
                    len(eligible) != 1
                    or eligible[0].source_alias
                    not in record.declaration.runtime.allowed_source_aliases
                ):
                    return self._halt(record, "proof_changed")
                item = eligible[0]
                self.store.select_source(
                    admission, source, item.source_ref, item.evidence_sha256, now=self._now()
                )
                record = self.get(reference)
                admission = self._admission(record)
            phase = "analyzing" if record.declaration.runtime.requires_ai else "preparing"
            return self.store.advance(admission, next_phase=phase, now=self._now())
        if record.phase == "analyzing":
            if record.ai_intent is not None:
                return self._halt(record, "result_unknown")
            if self.ai_service is None:
                return self._halt(record, "ai_unavailable")
            if not self._budget(record, AI_SECONDS + 3 * RPC_SECONDS + FINISH_MARGIN_SECONDS):
                return self._halt(record, "budget_insufficient")
            # Selection is the immutable AI input. Do not refresh or replace it
            # before that one call; cap its total timeout to the remaining fresh
            # interval instead. Completed advice can then use an exact refresh.
            source_age = (self._now() - utc(record.selection.source.observed_at)).total_seconds()
            ai_seconds = min(
                AI_SECONDS, MAX_SOURCE_AGE_SECONDS - source_age - FINISH_MARGIN_SECONDS
            )
            if ai_seconds <= 0:
                return self._halt(record, "proof_changed")
            preview = self.ai_service.preview(
                host, record.declaration.cursor_rid, record.selection.source_ref
            )
            result = self.ai_service.analyze(
                host,
                record.declaration.cursor_rid,
                record.selection.source_ref,
                expected_input_digest=preview["input_digest"],
                expected_mode_revision=record.declaration.runtime.context.global_revision,
                automatic=True,
                confirm_ai=False,
                session_admission=admission,
                timeout_seconds=ai_seconds,
            )
            if (
                result["status"] != "completed"
                or result["decision"] != "propose_defense"
                or not result["proof_sha256"]
            ):
                return self._halt(self.get(reference), "ai_unavailable")
            return self.store.advance(admission, next_phase="analysis_ready", now=self._now())
        if record.phase == "analysis_ready":
            return self.store.advance(admission, next_phase="preparing", now=self._now())
        if record.phase == "preparing":
            if record.action is not None:
                self._reconcile(record)
                return self._halt(self.get(reference), "result_unknown")
            if not self._budget(record, 3 * RPC_SECONDS + FINISH_MARGIN_SECONDS):
                return self._halt(record, "budget_insufficient")
            result = self.controller.prepare(
                host,
                PrepareRequest(
                    cursor_request_id=record.declaration.cursor_rid,
                    source_ref=record.selection.source_ref,
                    expected_evidence_sha256=record.selection.evidence_sha256,
                    expected_mode_revision=record.declaration.runtime.context.global_revision,
                ),
                session_admission=admission,
                worker_lease=self._leases[reference],
                rpc_timeout=RPC_SECONDS,
            )
            if result["phase"] != "ready" or result["query_required"]:
                return self._halt(self.get(reference), "result_unknown")
            return self.store.advance(admission, next_phase="prepared", now=self._now())
        if record.phase == "prepared":
            if not self._budget(record, RPC_SECONDS + FINISH_MARGIN_SECONDS):
                return self._halt(record, "budget_insufficient")
            return self.store.advance(admission, next_phase="applying", now=self._now())
        if record.phase == "applying":
            with self.controller.store._connection() as db:
                old = db.execute(
                    "SELECT 1 FROM defense_requests WHERE rid=? AND op='apply'",
                    (record.action.rid,),
                ).fetchone()
            if old is not None:
                self._reconcile(record)
                return self._halt(self.get(reference), "result_unknown")
            if not self._budget(record, RPC_SECONDS + FINISH_MARGIN_SECONDS):
                return self._halt(record, "budget_insufficient")
            result = self.controller.automatic_apply(
                host,
                record.action.rid,
                expected_mode_revision=record.declaration.runtime.context.global_revision,
                session_admission=admission,
                worker_lease=self._leases[reference],
                rpc_timeout=RPC_SECONDS,
            )
            if result["phase"] != "active" or result["query_required"]:
                return self._halt(self.get(reference), "result_unknown")
            return self.store.advance(admission, next_phase="confirmed", now=self._now())
        if record.phase == "confirmed":
            completed = self.store.advance(admission, next_phase="completed", now=self._now())
            self._release(reference)
            return completed
        raise DefenseConflict("Session has no executable phase")

    def reconcile(self, session_ref):
        with self._lock:
            # Explicit user queries are fresh attempts, including recovery from
            # an unavailable reply or expiry after a previous success. Only the
            # coordinator's automatic recovery path is bounded to one attempt.
            return self._reconcile(self.get(session_ref), force=True)

    def stop(self, session_ref=None):
        if session_ref is not None:
            # A stop must fence the persisted phase immediately, even while a
            # tick is waiting for provider/SSH output outside its DB transaction.
            record = self.get(session_ref)
            if record.owner != self.controller.owner:
                raise DefenseConflict("A new process can only read or reconcile this session")
            return self._halt(record, "requested")
        self.stopped.set()
        # Do not wait on the tick lock: in-flight provider/SSH checkpoints must
        # observe stop immediately, then their receiver fences reject writes.
        for reference in tuple(self._leases):
            self._halt(self.get(reference), "requested")
        return self.status()
