"""Durable defense service with short local admission locks and single sends."""

import secrets
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from threading import Event, Lock, local
from typing import Annotated, Literal, Protocol, TypedDict

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import Field, field_validator

from opsark.automation_store import AutomationStore
from opsark.baselines import scope_for
from opsark.business_readiness import business_profile_digest
from opsark.config import Settings
from opsark.defense_client import (
    DefenseTarget,
    _call_context,
    _credentials,
    _validate_reply,
    invoke,
)
from opsark.defense_config import defense_registry_scope
from opsark.defense_models import (
    ActionBody,
    ArmBody,
    DefenseApproval,
    DefenseCall,
    DefenseModel,
    DefenseReply,
    DefenseRequest,
    Digest,
    Identifier,
    ModeBody,
    PrepareBody,
    WireMode,
    canonical,
    digest,
    utc,
)
from opsark.defense_policy import DefenseGrant, DefensePolicy, HostId, now_utc
from opsark.defense_recheck_models import ActionBusinessProfile
from opsark.defense_session_models import SessionAdmission
from opsark.defense_store import (
    DefenseConflict,
    DefenseContext,
    DefenseStore,
    ObservationMetadata,
    SendPermit,
    UsageClaim,
    WorkerLease,
)
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, ModeSnapshot


class _SessionKeywords(TypedDict, total=False):
    session_admission: SessionAdmission


class _SessionRequestKeywords(_SessionKeywords, total=False):
    now: datetime


class _SessionSendKeywords(_SessionKeywords, total=False):
    lease: WorkerLease | None


class _SessionTransportKeywords(_SessionKeywords, total=False):
    rpc_timeout: float | None


def _session_keywords(admission: SessionAdmission | None) -> _SessionKeywords:
    return {} if admission is None else {"session_admission": admission}


def _session_request_keywords(
    admission: SessionAdmission | None, now: datetime
) -> _SessionRequestKeywords:
    return {} if admission is None else {"session_admission": admission, "now": now}


def _session_send_keywords(
    admission: SessionAdmission | None, lease: WorkerLease | None
) -> _SessionSendKeywords:
    return {} if admission is None else {"session_admission": admission, "lease": lease}


def _session_transport_keywords(
    admission: SessionAdmission | None, timeout: float | None
) -> _SessionTransportKeywords:
    return {} if admission is None else {"session_admission": admission, "rpc_timeout": timeout}


GlobalRevision = Annotated[int, Field(ge=0, le=2**31 - 2)]
MODE: dict[str, WireMode] = {"manual": "manual", "assisted": "semi", "automatic": "auto"}


class BusinessProfileStore(Protocol):
    def action_profile(self, rid: str) -> ActionBusinessProfile | None: ...
    def seal_action_profile(self, profile: ActionBusinessProfile) -> object: ...


class HistoryTargetsQuery(DefenseModel):
    after: HostId | None = None
    limit: int = Field(default=20, ge=1, le=100, strict=False)


class Confirmation(DefenseModel):
    @field_validator("*", mode="before")
    @classmethod
    def true_boolean(cls, value, info):
        if info.field_name.startswith("confirm_") and type(value) is not bool:
            raise ValueError("Invalid defense confirmation")
        return value


class ArmRequest(Confirmation):
    expected_mode_revision: GlobalRevision
    confirm_arm: Literal[True]


class PrepareRequest(DefenseModel):
    cursor_request_id: Identifier
    source_ref: Identifier
    expected_evidence_sha256: Digest
    expected_mode_revision: GlobalRevision


class ApplyRequest(Confirmation):
    expected_manifest_sha256: Digest
    expected_mode_revision: GlobalRevision
    confirm_execute: Literal[True]


class RevokeRequest(Confirmation):
    expected_manifest_sha256: Digest
    expected_mode_revision: GlobalRevision
    confirm_revoke: Literal[True]


class QueryRequest(DefenseModel):
    pass


class DefenseServiceError(DefenseConflict):
    def __init__(self, code: str = "conflict"):
        self.code = code if code in {"disabled", "conflict", "ai_required"} else "conflict"
        super().__init__("Defense request cannot be admitted")


def defense_service_scope(targets: dict[str, DefenseTarget], policy: DefensePolicy) -> str | None:
    registry = defense_registry_scope(targets)
    if registry is None:
        return None
    return digest(
        {
            "channel": "ssh-defense-controller/v1",
            "registry": registry,
            "policy": policy.model_dump(mode="json"),
        }
    )


def _stamp(instant: datetime) -> str:
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


class DefenseService:
    def __init__(
        self,
        settings: Settings,
        targets: dict[str, DefenseTarget],
        store: DefenseStore,
        automation: AutomationStore,
        coordinator: ModeCoordinator | None = None,
        policy: DefensePolicy | None = None,
        *,
        mode_lock=None,
        invoker: Callable = invoke,
        clock: Callable[[], datetime] = now_utc,
        ai_service=None,
        business_profile_store: BusinessProfileStore | None = None,
    ):
        self.settings, self.targets, self.store = settings, dict(targets), store
        self.automation, self.coordinator = automation, coordinator
        self.mode_lock = coordinator.mode_lock if coordinator is not None else mode_lock or Lock()
        if coordinator is not None and coordinator.automation is not automation:
            raise ValueError("Defense coordinator must own the shared automation store")
        self.policy = DefensePolicy.model_validate_json(canonical(policy or DefensePolicy()))
        self.registry_scope = defense_service_scope(self.targets, self.policy)
        self.invoker, self.clock, self.ai_service = invoker, clock, ai_service
        self.business_profile_store = business_profile_store
        self.stopped = Event()
        self._proof_local = local()
        self.owner = "defense-" + secrets.token_hex(16)

    def participant(self) -> ModeParticipant | None:
        if self.registry_scope is None:
            return None
        return ModeParticipant("ssh-defense", self.registry_scope, self.synchronize)

    def _snapshot(self) -> ModeSnapshot:
        status = self.automation.status()
        return ModeSnapshot(
            self.automation.scope, status["mode"], status["revision"], status["sync_generation"]
        )

    def _context(self, host_id: str, snapshot: ModeSnapshot | None = None) -> DefenseContext:
        if (
            host_id not in self.targets
            or self.registry_scope is None
            or defense_service_scope(self.targets, self.policy) != self.registry_scope
        ):
            raise DefenseServiceError()
        snapshot = snapshot or self._snapshot()
        target = self.targets[host_id]
        defense_scope = digest(
            {
                "channel": "ssh-defense-controller/v1",
                "host_scope": scope_for(target.host.public),
                "trusted_host_digest": target.readonly.trusted_hosts_digest,
                "role_key_identities": {
                    name: getattr(target, name).key_identity
                    for name in ("readonly", "observe", "control")
                },
                "root_scope_sha256": target.root_scope_sha256,
                "root_policy_sha256": target.root_policy_sha256,
                "boot_ref": target.boot_ref,
                "binding_ref": target.binding_ref,
            }
        )
        return DefenseContext(
            host_id=host_id,
            defense_scope=defense_scope,
            registry_scope=self.registry_scope,
            root_scope=target.root_scope_sha256,
            policy_sha256=target.root_policy_sha256,
            boot_ref=target.boot_ref,
            binding_ref=target.binding_ref,
            mode=MODE[snapshot.mode],
            global_revision=snapshot.revision,
            wire_revision=snapshot.wire_revision,
            epoch=snapshot.sync_generation,
        )

    def _enabled(self) -> None:
        if not self.policy.enabled or not self.targets or self.stopped.is_set():
            raise DefenseServiceError("disabled")

    def _expected(self, host_id: str, revision: int) -> DefenseContext:
        self._enabled()
        context = self._context(host_id)
        if type(revision) is not int or context.global_revision != revision:
            raise DefenseServiceError()
        return context

    def _observe(self, context: DefenseContext) -> str:
        grant = self.policy.observation
        if (
            grant is None
            or not grant.open(self.clock())
            or context.host_id not in grant.host_ids
            or grant.target_scope_sha256.get(context.host_id) != context.root_scope
            or grant.target_policy_sha256.get(context.host_id) != context.policy_sha256
        ):
            raise DefenseServiceError()
        return grant.grant_ref

    def _execution(self, context: DefenseContext, *, alias: str | None = None) -> DefenseGrant:
        self._enabled()
        grant = self.policy.execution
        ack = self.store.mode_ack(context)
        if (
            context.mode == "manual"
            or not self.automation.status()["mode_sync_complete"]
            or ack is None
            or ack.status != "confirmed"
            or self.store.latched(context.host_id, context.defense_scope)
            or grant is None
            or not grant.open(self.clock())
            or context.host_id not in grant.host_ids
            or grant.target_scope_sha256.get(context.host_id) != context.root_scope
            or grant.target_policy_sha256.get(context.host_id) != context.policy_sha256
            or grant.boot_refs.get(context.host_id) != context.boot_ref
            or grant.binding_refs.get(context.host_id) != context.binding_ref
            or context.wire_revision not in grant.wire_revisions
            or alias is not None
            and alias not in grant.source_aliases
        ):
            raise DefenseServiceError()
        return grant

    def _ai(self, context, cursor_rid, source_ref, evidence):
        if not self.policy.ai.requires_ai:
            return
        # Local proof callbacks reuse our existing lock ownership on this thread.
        self._proof_local.held = True
        try:
            if (
                self.ai_service is None
                or self.ai_service.validate_proposal(
                    context=context,
                    cursor_rid=cursor_rid,
                    source_ref=source_ref,
                    evidence_sha256=evidence,
                )
                is not True
            ):
                raise DefenseServiceError("ai_required")
        finally:
            self._proof_local.held = False

    def _ai_snapshot_locked(self, host_id):
        from opsark.defense_ai import DefenseAISnapshot

        context = self._context(host_id)
        for role in ("readonly", "observe", "control"):
            _credentials(self.targets[host_id], role)
        return DefenseAISnapshot(
            context=context,
            host_scope=scope_for(self.targets[host_id].host.public),
            consent=self.policy.ai,
            enabled=bool(self.policy.enabled and self.targets),
            mode_sync_complete=self.automation.status()["mode_sync_complete"],
            stopping=self.stopped.is_set(),
            sync_generation=context.epoch,
        )

    def ai_snapshot(self, host_id):
        if getattr(self._proof_local, "held", False):
            return self._ai_snapshot_locked(host_id)
        with self.mode_lock:
            return self._ai_snapshot_locked(host_id)

    def _validate_ai_locked(self, admission):
        current = self._ai_snapshot_locked(admission.snapshot.context.host_id)
        if (
            current != admission.snapshot
            or not current.enabled
            or current.stopping
            or not current.consent.enabled
            or current.consent.provider_fingerprint != admission.provider_fingerprint
            or not admission.automatic
            and admission.confirm_ai is not True
        ):
            raise DefenseServiceError()
        cursor = self.store.transaction(admission.cursor_rid)
        if cursor.context != current.context or cursor.kind != "cursor":
            raise DefenseServiceError()
        _, candidate = self._candidate(
            admission.cursor_rid, admission.source_ref, admission.evidence_sha256
        )
        if admission.automatic:
            if current.context.mode != "auto":
                raise DefenseServiceError()
            self._execution(current.context, alias=candidate.source_alias)
        elif current.context.mode != "manual":
            ack = self.store.mode_ack(current.context)
            if not current.mode_sync_complete or ack is None or ack.status != "confirmed":
                raise DefenseServiceError()

    def validate_ai_admission(self, admission):
        if getattr(self._proof_local, "held", False):
            self._validate_ai_locked(admission)
            return
        with self.mode_lock:
            self._validate_ai_locked(admission)

    def _revoke_authority(self, context, rid):
        """New exact withdrawal authority survives the original execution window."""
        self._enabled()
        ack = self.store.mode_ack(context)
        manifest, grant = self.store.manifest(rid), self.policy.execution
        transaction = self.store.transaction(rid)
        reply = self.store.latest_reply(rid)
        observations = self.store.observations(rid)
        latest = observations[-1] if observations else None
        if (
            context.mode == "manual"
            or not self.automation.status()["mode_sync_complete"]
            or ack is None
            or ack.status != "confirmed"
            or grant is None
            or not grant.enabled
            or context.host_id not in grant.host_ids
            or grant.target_scope_sha256.get(context.host_id) != context.root_scope
            or grant.target_policy_sha256.get(context.host_id) != context.policy_sha256
            or grant.boot_refs.get(context.host_id) != context.boot_ref
            or grant.binding_refs.get(context.host_id) != context.binding_ref
            or grant.grant_ref != manifest.controller_grant_ref
            or grant.root_grant_refs.get(context.host_id) != manifest.root_grant_ref
            or transaction.query_required
            and transaction.phase != "revoke_sendable"
            or reply is None
            or reply.state != "active"
            or latest is None
            or latest.op != "query"
            or not latest.accepted
            or latest.state != "active"
            or reply.remaining_ms is None
            or not 0
            <= (self.clock() - utc(latest.observed_at)).total_seconds()
            < min(5, reply.remaining_ms / 1000)
        ):
            raise DefenseServiceError()
        return grant

    def _transaction(self, host_id: str, rid: str):
        transaction = self._local_transaction(host_id, rid)
        self._context(host_id)
        return transaction

    def _local_transaction(self, host_id: str, rid: str):
        """Historical local records do not require live credentials or a current grant."""
        transaction = self.store.transaction(rid)
        if transaction.context.host_id != host_id:
            raise DefenseServiceError()
        return transaction

    def _usage(self, transaction, grant: DefenseGrant) -> UsageClaim:
        return UsageClaim(
            intent_key=digest(
                {
                    "channel": "ssh-defense-execution/v1",
                    "defense_scope": transaction.context.defense_scope,
                    "cursor_rid": transaction.cursor_rid,
                }
            ),
            kind="execution",
            grant_ref=grant.grant_ref,
            max_per_day=grant.max_actions_per_day,
            max_total=grant.max_total_actions,
        )

    def _candidate(self, cursor_rid: str, source_ref: str, evidence: str):
        transaction = self.store.transaction(cursor_rid)
        if transaction.kind != "cursor" or transaction.query_required:
            raise DefenseServiceError()
        target = self.targets.get(transaction.context.host_id)
        if target is None:
            raise DefenseServiceError()
        source = self.store.cursor_source(cursor_rid, host_scope=scope_for(target.host.public))
        bounds = self.store.source_time_bounds(source)
        bounds.require(source, context=transaction.context, now=self.clock())
        reply = bounds.root_reply
        candidate = next(
            (
                candidate
                for candidate in reply.candidates
                if (
                    candidate.source_ref == source_ref
                    and candidate.evidence_sha256 == evidence
                    and candidate.classification == "eligible"
                    and candidate.distinct_failure_ports >= 5
                )
            ),
            None,
        )
        if candidate is None:
            raise DefenseServiceError()
        return reply, candidate

    def transaction(self, host_id: str, rid: str) -> dict:
        transaction = self._local_transaction(host_id, rid)
        reply = self.store.latest_reply(rid)
        manifest = self.store.manifest(rid) if transaction.manifest_sha256 else None
        controller_observation = None
        if transaction.kind == "cursor":
            instant = self.clock()
            remaining = 0
            if utc(transaction.created_at) <= instant:
                delta_ms = int((utc(transaction.deadline_at) - instant).total_seconds() * 1000)
                remaining = max(0, min(120000, delta_ms))
            controller_observation = {
                "owned_by_current_boot": transaction.owner == self.owner,
                "deadline_at": transaction.deadline_at,
                "remaining_ms": remaining,
            }
        source_alias = None
        if manifest is not None and transaction.cursor_rid is not None:
            cursor = self.store.latest_reply(transaction.cursor_rid)
            if cursor is not None:
                source_alias = next(
                    (
                        candidate.source_alias
                        for candidate in cursor.candidates
                        if candidate.source_ref == manifest.source_ref
                    ),
                    None,
                )
        return {
            "host_id": host_id,
            "request_id": rid,
            "kind": transaction.kind,
            "phase": transaction.phase,
            "mode": transaction.context.mode,
            "mode_revision": transaction.context.global_revision,
            "controller_observation": controller_observation,
            "manifest": None
            if manifest is None
            else {
                "sha256": manifest.sha256,
                "ttl_ms": manifest.ttl_ms,
                "source_ref": manifest.source_ref,
                "source_alias": source_alias,
                "deadline_at": manifest.deadline_at,
            },
            "current_result": None
            if reply is None or transaction.query_required
            else (reply.model_dump(mode="json")),
            "last_confirmed": self.store.last_confirmed(rid),
            "query_required": transaction.query_required,
            "reason_code": transaction.last_error_code or "ok",
            "history": self.store.observations(rid),
        }

    def transactions(self, host_id: str) -> dict:
        # A retired target remains readable, while query/execute still require
        # its separately registered current transport and scope.
        transactions = self.store.transactions(host_id)
        if not transactions:
            self._context(host_id)
        return {
            "transactions": [
                self.transaction(host_id, transaction.rid) for transaction in transactions
            ]
        }

    def history_targets(self, *, after: str | None = None, limit: int = 20) -> dict:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise DefenseServiceError()
        page = self.store.history_hosts(after=after, limit=limit + 1)
        visible = page[:limit]
        return {
            "history_targets": [{"host_id": host_id} for host_id in visible],
            "next_after": visible[-1] if len(page) > limit else None,
        }

    def status(self) -> dict:
        with self.mode_lock:
            status = self.automation.status()
            targets = []
            for host_id in sorted(self.targets):
                context = self._context(host_id)
                try:
                    ack = self.store.mode_ack(context)
                except DefenseConflict:
                    ack = None
                observation = execution = False
                try:
                    self._enabled()
                    self._observe(context)
                    observation = True
                except DefenseConflict:
                    pass
                try:
                    self._execution(context)
                    execution = True
                except DefenseConflict:
                    pass
                targets.append(
                    {
                        "host_id": host_id,
                        "mode_ack": ack,
                        "observation_available": observation,
                        "execution_available": execution,
                        "reconciliation_required": self.store.latched(
                            host_id, context.defense_scope
                        ),
                    }
                )
            enabled = bool(self.policy.enabled and self.targets and not self.stopped.is_set())
            history = self.history_targets()
            return {
                "configured": bool(self.targets),
                "enabled": enabled,
                "disabled": not enabled,
                "limited_profile": self.policy.profile,
                "ttl_ms": 60000,
                "mode": status["mode"],
                "revision": status["revision"],
                "sync_generation": status["sync_generation"],
                "mode_sync_complete": status["mode_sync_complete"],
                "targets": targets,
                "history_targets": history["history_targets"],
                "history_targets_next_after": history["next_after"],
                "ai_required": self.policy.ai.requires_ai,
                "reason_code": "ok" if enabled else "disabled",
            }

    def _permit_guard(
        self,
        permit: SendPermit,
        context: DefenseContext,
        request: DefenseRequest,
        session_admission: SessionAdmission | None = None,
    ):
        def admit():
            with self.mode_lock:
                if self.stopped.is_set() or self._context(context.host_id) != context:
                    raise DefenseServiceError()
                metadata = self.store.request_metadata(permit.rid, permit.op)
                if (
                    metadata.dispatch_phase != "sendable"
                    or metadata.request_sha256 != permit.request_sha256
                    or metadata.send_owner != permit.owner
                    or metadata.send_started_at != permit.committed_at
                    or permit.epoch != context.epoch
                ):
                    raise DefenseServiceError()
                transaction = self.store.transaction(permit.rid)
                if transaction.owner != permit.owner:
                    raise DefenseServiceError()
                if request.op in {"prepare", "apply"}:
                    self.store.require_session_admission(
                        permit.rid,
                        session_admission,
                        phase="preparing" if request.op == "prepare" else "applying",
                        now=self.clock(),
                    )
                if request.op != "revoke" and utc(transaction.deadline_at) <= self.clock():
                    raise DefenseServiceError()
                if request.op == "arm":
                    self._enabled()
                    if not isinstance(request.body, ArmBody) or (
                        self._observe(context) != request.body.observation_grant_ref
                    ):
                        raise DefenseServiceError()
                elif request.op in {"prepare", "apply", "revoke"}:
                    body = self.store.request(permit.rid, "prepare").body
                    if not isinstance(body, PrepareBody):
                        raise DefenseServiceError()
                    grant = (
                        self._revoke_authority(context, permit.rid)
                        if (request.op == "revoke")
                        else self._execution(context)
                    )
                    if (
                        grant.grant_ref != body.controller_grant_ref
                        or grant.root_grant_refs[context.host_id] != body.root_grant_ref
                    ):
                        raise DefenseServiceError()
                    if request.op != "revoke":
                        usage = self.store.usage(self._usage(transaction, grant).intent_key)
                        if usage.rid != permit.rid or usage.state != (
                            "reserved" if request.op == "prepare" else "consumed"
                        ):
                            raise DefenseServiceError()
                        _, candidate = self._candidate(
                            transaction.cursor_rid or "", body.source_ref, body.evidence_sha256
                        )
                        if candidate.source_alias not in grant.source_aliases:
                            raise DefenseServiceError()
                        self._ai(
                            context, transaction.cursor_rid, body.source_ref, body.evidence_sha256
                        )
                    if isinstance(request.body, ActionBody):
                        approval = request.body.approval
                        if approval is not None and not (
                            utc(approval.approved_at) <= self.clock() < utc(approval.expires_at)
                        ):
                            raise DefenseServiceError()
            return None

        return admit

    def _network(
        self,
        host_id: str,
        call: DefenseCall,
        context: DefenseContext,
        *,
        permit=None,
        session_admission: SessionAdmission | None = None,
        rpc_timeout: float | None = None,
    ):
        return self._network_result(
            host_id,
            call,
            context,
            permit=permit,
            **_session_transport_keywords(session_admission, rpc_timeout),
        )[1]

    def _network_result(
        self,
        host_id: str,
        call: DefenseCall,
        context: DefenseContext,
        *,
        permit=None,
        query_admit: Callable[[], None] | None = None,
        commit_guard: Callable[[sqlite3.Connection], None] | None = None,
        session_admission: SessionAdmission | None = None,
        rpc_timeout: float | None = None,
    ) -> tuple[ObservationMetadata, DefenseReply | None]:
        target, request = self.targets[host_id], call.request
        if rpc_timeout is not None and (
            (session_admission is None and (query_admit is None or commit_guard is None))
            or type(rpc_timeout) not in {int, float}
            or not 0 < rpc_timeout <= 30
        ):
            raise DefenseConflict("A session RPC budget must be explicit and bounded")
        if session_admission is not None and request.op not in {"prepare", "apply"}:
            raise DefenseConflict("Session mutation admission cannot authorize this operation")
        if (query_admit is not None or commit_guard is not None) and (
            request.op != "query" or permit is not None
        ):
            raise DefenseConflict("A read-only query fence cannot authorize a mutation")
        cancelled = False

        def checkpoint():
            nonlocal cancelled
            if query_admit is not None:
                try:
                    if query_admit() is not None:
                        raise DefenseConflict("Read-only query admission did not close")
                except Exception:
                    cancelled = True
                    raise

        def session_checkpoint():
            if session_admission is not None:
                self.store.require_session_admission(
                    request.request_id,
                    session_admission,
                    phase="preparing" if request.op == "prepare" else "applying",
                    now=self.clock(),
                )

        # No cancelled local work may manufacture an unavailable Root observation.
        checkpoint()
        session_checkpoint()
        mutation_options = _session_keywords(session_admission)
        transport_options = {} if rpc_timeout is None else {"timeout": rpc_timeout}
        try:
            result = self.invoker(
                target,
                call,
                "observe"
                if request.op == "arm"
                else "readonly"
                if request.op == "query"
                else "control",
                admit=checkpoint
                if query_admit is not None
                else None
                if permit is None
                else self._permit_guard(permit, context, request, session_admission),
                **transport_options,
            )
            result = _validate_reply(target, _call_context(target, call), result.reply_bytes)
        except Exception:
            # The SSH client intentionally normalizes exceptions; retain the
            # fact that our own final admission rejected the call nevertheless.
            if cancelled:
                raise DefenseConflict("Read-only query admission expired") from None
            checkpoint()
            session_checkpoint()
            observation = self.store.record_unavailable(
                request.request_id,
                request.op,
                context=context,
                now=self.clock(),
                commit_guard=commit_guard,
                **mutation_options,
            )
            return observation, None
        checkpoint()
        session_checkpoint()
        with self.mode_lock:
            # Captured epochs survive a late callback; never replace with a new one.
            observation = self.store.record_reply(
                request.request_id,
                request.op,
                result.reply,
                context=context,
                now=self.clock(),
                commit_guard=commit_guard,
                **mutation_options,
            )
        return observation, result.reply if observation.accepted else None

    def _dispatch(
        self,
        transaction,
        request,
        context,
        permit,
        *,
        session_admission: SessionAdmission | None = None,
        rpc_timeout: float | None = None,
    ):
        if permit is None:
            return self.query(transaction.context.host_id, transaction.rid)
        call = DefenseCall(request)
        if request.op in {"apply", "revoke"}:
            call = DefenseCall(
                request,
                prepare_request=self.store.request(transaction.rid, "prepare"),
                expected_manifest=self.store.manifest(transaction.rid),
            )
        self._network(
            context.host_id,
            call,
            context,
            permit=permit,
            **_session_transport_keywords(session_admission, rpc_timeout),
        )
        return self.transaction(context.host_id, transaction.rid)

    def synchronize(self, snapshot: ModeSnapshot) -> bool:
        complete = True
        for host_id in sorted(self.targets):
            try:
                with self.mode_lock:
                    if self.stopped.is_set() or self._snapshot() != snapshot:
                        raise DefenseServiceError()
                    context = self._context(host_id, snapshot)
                    rid = self.store.mode_rid(context)
                    if rid is None:
                        transaction = self.store.create_transaction(
                            kind="mode",
                            context=context,
                            owner=self.owner,
                            deadline_at=_stamp(self.clock() + timedelta(seconds=120)),
                            now=self.clock(),
                        )
                        self.store.register_mode_pending(transaction.rid, now=self.clock())
                        request = DefenseRequest(
                            v=1,
                            op="mode_sync",
                            request_id=transaction.rid,
                            scope_sha256=context.root_scope,
                            body=ModeBody(
                                mode=context.mode,
                                mode_revision=context.wire_revision,
                                policy_sha256=context.policy_sha256,
                            ),
                        )
                        self.store.save_request(transaction.rid, request)
                    else:
                        transaction = self.store.transaction(rid)
                        self.store.register_mode_pending(rid, context=context, now=self.clock())
                        request = self.store.request(rid, "mode_sync")
                    # Existing sendable/replied intents never produce another permit.
                    # An unsent old-epoch intent is conservatively refused by store.
                    permit = self.store.begin_sendable(
                        transaction.rid,
                        "mode_sync",
                        context=context,
                        owner=transaction.owner,
                        now=self.clock(),
                    )
                if permit is not None:
                    self._network(host_id, DefenseCall(request), context, permit=permit)
                with self.mode_lock:
                    if self._snapshot() != snapshot:
                        raise DefenseServiceError()
                    call = self.store.query_call(transaction.rid)
                self._network(host_id, call, context)
                with self.mode_lock:
                    ack = self.store.mode_ack(context)
                    complete = bool(
                        complete
                        and self._snapshot() == snapshot
                        and ack
                        and ack.status == "confirmed"
                    )
            except Exception:
                complete = False
        return complete

    def arm(self, host_id: str, body: ArmRequest) -> dict:
        body = ArmRequest.model_validate(body.model_dump())
        with self.mode_lock:
            context = self._expected(host_id, body.expected_mode_revision)
            self._observe(context)
            existing = next(
                (
                    transaction
                    for transaction in self.store.transactions(host_id)
                    if transaction.kind == "cursor"
                    and transaction.context == context
                    and utc(transaction.deadline_at) > self.clock()
                ),
                None,
            )
            if existing is None:
                grant_ref = self._observe(context)
                transaction = self.store.create_transaction(
                    kind="cursor",
                    context=context,
                    owner=self.owner,
                    deadline_at=_stamp(self.clock() + timedelta(seconds=120)),
                    observation_key=digest(
                        {
                            "channel": "explicit-defense-observation/v1",
                            "context": context.model_dump(mode="json"),
                            "grant_ref": grant_ref,
                        }
                    ),
                    now=self.clock(),
                )
                if transaction.owner != self.owner or utc(transaction.deadline_at) <= self.clock():
                    # Another process (or a previous process before a crash) already
                    # claimed this grant/context. Its durable RID is query-only;
                    # never reconstruct its one-shot send permit or renew a cursor.
                    existing = transaction
                else:
                    request = DefenseRequest(
                        v=1,
                        op="arm",
                        request_id=transaction.rid,
                        scope_sha256=context.root_scope,
                        body=ArmBody(
                            observation_grant_ref=grant_ref, policy_sha256=context.policy_sha256
                        ),
                    )
                    self.store.save_request(transaction.rid, request)
                    permit = self.store.begin_sendable(
                        transaction.rid,
                        "arm",
                        context=context,
                        owner=transaction.owner,
                        now=self.clock(),
                    )
        if existing is not None:
            return self.query(host_id, existing.rid)
        return self._dispatch(transaction, request, context, permit)

    def _action(
        self,
        host_id,
        rid,
        revision,
        expected_hash,
        op,
        *,
        automatic=False,
        session_admission: SessionAdmission | None = None,
        worker_lease: WorkerLease | None = None,
        rpc_timeout: float | None = None,
    ):
        self._session_options(session_admission, worker_lease, rpc_timeout)
        if session_admission is not None and (not automatic or op != "apply"):
            raise DefenseConflict("A session cannot borrow a human confirmation")
        with self.mode_lock:
            previous = self._transaction(host_id, rid)
            if previous.kind != "action" or self.store.manifest(rid).sha256 != expected_hash:
                raise DefenseServiceError()
            try:
                existing = self.store.request(rid, op)
            except DefenseConflict:
                existing = None
        if existing is not None:
            return self.query(host_id, rid)
        if op == "revoke":
            # Query freshness is independent of cursor/prepare deadlines and
            # cannot be inferred from an old last_confirmed row.
            self.query(host_id, rid)
        with self.mode_lock:
            context = self._expected(host_id, revision)
            transaction = self._transaction(host_id, rid)
            if transaction.kind != "action":
                raise DefenseServiceError()
            manifest = self.store.manifest(rid)
            if manifest.sha256 != expected_hash:
                raise DefenseServiceError()
            if op == "apply" and (
                context != transaction.context or context.mode != ("auto" if automatic else "semi")
            ):
                raise DefenseServiceError()
            grant = (
                self._revoke_authority(context, rid) if op == "revoke" else self._execution(context)
            )
            if (
                grant.grant_ref != manifest.controller_grant_ref
                or grant.root_grant_refs[host_id] != manifest.root_grant_ref
            ):
                raise DefenseServiceError()
            try:
                request = self.store.request(rid, op)
            except DefenseConflict:
                request = None
            if request is not None:
                # Existing op is reconciliation only, including unsent intents
                # after a crash. A lost permit is never reconstructed.
                permit = None
            else:
                if op == "apply":
                    original = self.store.request(rid, "prepare")
                    if not isinstance(original.body, PrepareBody):
                        raise DefenseServiceError()
                    self._candidate(
                        transaction.cursor_rid,
                        original.body.source_ref,
                        original.body.evidence_sha256,
                    )
                    self._ai(
                        context,
                        transaction.cursor_rid,
                        original.body.source_ref,
                        original.body.evidence_sha256,
                    )
                    if transaction.phase != "ready" or utc(transaction.deadline_at) <= self.clock():
                        raise DefenseServiceError()
                elif self.store.last_confirmed(rid) is None:
                    raise DefenseServiceError()
                approval = None
                if not automatic or op == "revoke":
                    expires = self.clock() + timedelta(seconds=120)
                    if op == "apply":
                        expires = min(expires, utc(manifest.deadline_at))
                    approval = DefenseApproval(
                        approval_id=secrets.token_hex(16),
                        purpose=op,
                        request_id=rid,
                        manifest_sha256=manifest.sha256,
                        approved_at=_stamp(self.clock()),
                        expires_at=_stamp(expires),
                    )
                    self.store.save_approval(
                        rid,
                        approval,
                        context=context,
                        controller_grant_ref=grant.grant_ref,
                        root_grant_ref=grant.root_grant_refs[host_id],
                        now=self.clock(),
                    )
                request = DefenseRequest(
                    v=1,
                    op=op,
                    request_id=rid,
                    scope_sha256=context.root_scope,
                    body=ActionBody(manifest_sha256=manifest.sha256, approval=approval),
                )
                self.store.save_request(
                    rid,
                    request,
                    **_session_request_keywords(session_admission, self.clock()),
                )
                permit = self.store.begin_sendable(
                    rid,
                    op,
                    context=context,
                    owner=transaction.owner,
                    usage=None if op == "revoke" else self._usage(transaction, grant),
                    now=self.clock(),
                    **_session_send_keywords(session_admission, worker_lease),
                )
        return self._dispatch(
            transaction,
            request,
            context,
            permit,
            **_session_transport_keywords(session_admission, rpc_timeout),
        )

    def apply(self, host_id: str, rid: str, body: ApplyRequest) -> dict:
        body = ApplyRequest.model_validate(body.model_dump())
        return self._action(
            host_id, rid, body.expected_mode_revision, body.expected_manifest_sha256, "apply"
        )

    def automatic_apply(
        self,
        host_id: str,
        rid: str,
        *,
        expected_mode_revision: int,
        session_admission: SessionAdmission | None = None,
        worker_lease: WorkerLease | None = None,
        rpc_timeout: float | None = None,
    ) -> dict:
        """Worker authority; never reuses an assisted UI confirmation."""
        return self._action(
            host_id,
            rid,
            expected_mode_revision,
            self.store.manifest(rid).sha256,
            "apply",
            automatic=True,
            session_admission=session_admission,
            worker_lease=worker_lease,
            rpc_timeout=rpc_timeout,
        )

    def revoke(self, host_id: str, rid: str, body: RevokeRequest) -> dict:
        body = RevokeRequest.model_validate(body.model_dump())
        return self._action(
            host_id, rid, body.expected_mode_revision, body.expected_manifest_sha256, "revoke"
        )

    def query(self, host_id: str, rid: str) -> dict:
        self.query_with_observation(host_id, rid)
        return self.transaction(host_id, rid)

    def query_with_observation(
        self,
        host_id: str,
        rid: str,
        *,
        admit: Callable[[], None] | None = None,
        commit_guard: Callable[[sqlite3.Connection], None] | None = None,
        rpc_timeout: float | None = None,
    ) -> tuple[ObservationMetadata, DefenseReply | None]:
        """Return this exact read-only query, never an older last-confirmed receipt."""
        with self.mode_lock:
            transaction = self._transaction(host_id, rid)
            context, call = transaction.context, self.store.query_call(rid)
        return self._network_result(
            host_id,
            call,
            context,
            query_admit=admit,
            commit_guard=commit_guard,
            rpc_timeout=rpc_timeout,
        )

    @staticmethod
    def _session_options(session_admission, worker_lease, rpc_timeout):
        if session_admission is None:
            if worker_lease is not None or rpc_timeout is not None:
                raise DefenseConflict("Session options require an original session admission")
            return
        if (
            type(session_admission) is not SessionAdmission
            or type(worker_lease) is not WorkerLease
            or worker_lease.owner != session_admission.owner
            or worker_lease.epoch != session_admission.worker_epoch
            or (
                rpc_timeout is not None
                and (type(rpc_timeout) not in {int, float} or not 0 < rpc_timeout <= 30)
            )
        ):
            raise DefenseConflict("Session options do not bind the original sender")

    def prepare(
        self,
        host_id: str,
        body: PrepareRequest,
        *,
        session_admission: SessionAdmission | None = None,
        worker_lease: WorkerLease | None = None,
        rpc_timeout: float | None = None,
    ) -> dict:
        self._session_options(session_admission, worker_lease, rpc_timeout)
        body = PrepareRequest.model_validate(body.model_dump())
        with self.mode_lock:
            context = self._expected(host_id, body.expected_mode_revision)
            self._execution(context)
            cursor = self._transaction(host_id, body.cursor_request_id)
            if cursor.context != context or cursor.kind != "cursor":
                raise DefenseServiceError()
            self.store.require_session_admission(
                cursor.rid, session_admission, phase="preparing", now=self.clock()
            )
        if session_admission is None:
            self.query(host_id, cursor.rid)
        else:

            def query_admit():
                self.store.require_session_admission(
                    cursor.rid, session_admission, phase="preparing", now=self.clock()
                )

            def query_commit(connection):
                self.store.require_session_admission(
                    cursor.rid,
                    session_admission,
                    phase="preparing",
                    now=self.clock(),
                    connection=connection,
                )

            self.query_with_observation(
                host_id,
                cursor.rid,
                admit=query_admit,
                commit_guard=query_commit,
                rpc_timeout=rpc_timeout,
            )
        with self.mode_lock:
            if self._context(host_id) != context:
                raise DefenseServiceError()
            reply, candidate = self._candidate(
                cursor.rid, body.source_ref, body.expected_evidence_sha256
            )
            grant = self._execution(context, alias=candidate.source_alias)
            if context.mode == "manual":
                raise DefenseServiceError()
            self._ai(context, cursor.rid, body.source_ref, body.expected_evidence_sha256)
            transaction = self.store.create_transaction(
                kind="action",
                context=context,
                owner=self.owner,
                deadline_at=cursor.deadline_at,
                cursor_rid=cursor.rid,
                now=self.clock(),
                **_session_keywords(session_admission),
            )
            if transaction.phase != "created":
                request = self.store.request(transaction.rid, "prepare")
            else:
                request = DefenseRequest(
                    v=1,
                    op="prepare",
                    request_id=transaction.rid,
                    scope_sha256=context.root_scope,
                    body=PrepareBody(
                        cursor_id=reply.cursor_id,
                        source_ref=body.source_ref,
                        evidence_sha256=body.expected_evidence_sha256,
                        policy_sha256=context.policy_sha256,
                        mode=context.mode,
                        mode_revision=context.wire_revision,
                        controller_grant_ref=grant.grant_ref,
                        root_grant_ref=grant.root_grant_refs[host_id],
                    ),
                )
                self.store.save_request(
                    transaction.rid,
                    request,
                    **_session_request_keywords(session_admission, self.clock()),
                )
            if self.business_profile_store is not None:
                metadata = self.store.request_metadata(transaction.rid, "prepare")
                if (
                    metadata.dispatch_phase == "intent"
                    and metadata.send_started_at is None
                    and self.business_profile_store.action_profile(transaction.rid) is None
                ):
                    host = self.targets[host_id].host
                    self.business_profile_store.seal_action_profile(
                        ActionBusinessProfile(
                            rid=transaction.rid,
                            context_sha256=digest(transaction.context),
                            prepare_request_sha256=metadata.request_sha256,
                            host_scope=scope_for(host.public),
                            business_profile_sha256=business_profile_digest(host),
                            check_ids=tuple(check.id for check in host.business_checks),
                            sealed_at=_stamp(self.clock()),
                        )
                    )
            permit = self.store.begin_sendable(
                transaction.rid,
                "prepare",
                context=context,
                owner=transaction.owner,
                usage=self._usage(transaction, grant),
                now=self.clock(),
                **_session_send_keywords(session_admission, worker_lease),
            )
        return self._dispatch(
            transaction,
            request,
            context,
            permit,
            **_session_transport_keywords(session_admission, rpc_timeout),
        )


def register_defense_routes(app: FastAPI, service: DefenseService, protected: list) -> None:
    class DefenseRoute(APIRoute):
        def get_route_handler(self):
            original = super().get_route_handler()

            async def bounded(request):
                try:
                    return await original(request)
                except RequestValidationError:
                    raise HTTPException(status_code=422, detail="Invalid defense request") from None

            return bounded

    router = APIRouter(prefix="/api", dependencies=protected, route_class=DefenseRoute)

    def guarded(action, *, remote=False):
        try:
            result = action()
            # An unavailable remote receipt is still a valid durable local
            # record. Historical GETs must remain readable after reconnecting.
            if remote and result.get("reason_code") == "unavailable":
                return JSONResponse(status_code=503, content=jsonable_encoder(result))
            return result
        except DefenseServiceError as error:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason_code": error.code,
                    "message": "Defense request cannot be admitted",
                },
            ) from None
        except DefenseConflict:
            raise HTTPException(
                status_code=409, detail="Defense request conflicts with current authority"
            ) from None
        except (sqlite3.Error, ValueError, OSError):
            raise HTTPException(status_code=503, detail="Defense evidence is unavailable") from None

    @router.get("/ssh-defense/status")
    def status():
        return guarded(service.status)

    @router.get("/ssh-defense/history-targets")
    def history_targets(query: Annotated[HistoryTargetsQuery, Query()]):
        return guarded(lambda: service.history_targets(after=query.after, limit=query.limit))

    @router.get("/hosts/{host_id}/ssh-defense/transactions")
    def transactions(host_id: HostId):
        return guarded(lambda: service.transactions(host_id))

    @router.get("/hosts/{host_id}/ssh-defense/transactions/{rid}")
    def transaction(host_id: HostId, rid: Identifier):
        return guarded(lambda: service.transaction(host_id, rid))

    @router.post("/hosts/{host_id}/ssh-defense/arm")
    def arm(host_id: HostId, body: ArmRequest):
        return guarded(lambda: service.arm(host_id, body), remote=True)

    @router.post("/hosts/{host_id}/ssh-defense/prepare")
    def prepare(host_id: HostId, body: PrepareRequest):
        return guarded(lambda: service.prepare(host_id, body), remote=True)

    @router.post("/hosts/{host_id}/ssh-defense/transactions/{rid}/apply")
    def apply(host_id: HostId, rid: Identifier, body: ApplyRequest):
        return guarded(lambda: service.apply(host_id, rid, body), remote=True)

    @router.post("/hosts/{host_id}/ssh-defense/transactions/{rid}/query")
    def query(host_id: HostId, rid: Identifier, body: QueryRequest):
        return guarded(lambda: service.query(host_id, rid), remote=True)

    @router.post("/hosts/{host_id}/ssh-defense/transactions/{rid}/revoke")
    def revoke(host_id: HostId, rid: Identifier, body: RevokeRequest):
        return guarded(lambda: service.revoke(host_id, rid, body), remote=True)

    app.include_router(router)
