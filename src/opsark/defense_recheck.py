"""Independent business rechecks bound to original defense transactions.

The collector is server-owned and accepts only an existing HostConfig. Durable
run references are claimed once; reads and customer exports never open SSH.
"""

from __future__ import annotations

import copy
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol

from opsark.baselines import scope_for
from opsark.business_readiness import (
    BusinessReadiness,
    business_profile_digest,
)
from opsark.config import HostConfig
from opsark.defense_api import DefenseService
from opsark.defense_client import MAX_KNOWN_HOSTS_BYTES, DefenseTarget, _read_file
from opsark.defense_handoff import (
    CheckReason,
    DefenseHandoffProjection,
    HandoffCheck,
    HandoffReason,
    RootState,
    defense_handoff_markdown,
    merge_business,
    merge_verdict,
)
from opsark.defense_models import ActionBody, DefenseReply, canonical, digest, rebuild_manifest, utc
from opsark.defense_recheck_api import DefenseRecheckInterrupt, DefenseRecheckRequest
from opsark.defense_recheck_models import (
    ActionBusinessProfile,
    DefenseRecheckDeclaration,
    DefenseRecheckResult,
    DefenseRecheckRun,
    RecheckAuthority,
    RecheckBusinessCheck,
    RecheckBusinessEvidence,
    RecheckClaim,
    RecheckReason,
    RecheckRootEvidence,
    root_transition,
)
from opsark.defense_store import DefenseConflict

MAX_CURRENT_QUERY_AGE_SECONDS = 30
MAX_CURRENT_BUSINESS_AGE_SECONDS = 30


class RecheckLedger(Protocol):
    def action_profile(self, rid: str) -> ActionBusinessProfile | None: ...
    def authority(self, rid: str, root: RecheckRootEvidence | None = None) -> RecheckAuthority: ...
    def create(
        self, declaration: DefenseRecheckDeclaration, *, now: datetime
    ) -> DefenseRecheckRun: ...
    def claim(self, run_ref: str, *, owner: str, now: datetime) -> RecheckClaim | None: ...
    def finish(self, claim: RecheckClaim, result: DefenseRecheckResult) -> DefenseRecheckRun: ...
    def get(self, run_ref: str) -> DefenseRecheckRun | None: ...
    def interrupt(
        self, run_ref: str, *, expected_declaration_sha256: str, now: datetime
    ) -> DefenseRecheckRun: ...
    def active_run(self, host_id: str) -> DefenseRecheckRun | None: ...
    def list(
        self, host_id: str, rid: str | None = None, *, after_sequence: int = 0, limit: int = 20
    ) -> tuple[DefenseRecheckRun, ...]: ...


def _stamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise DefenseConflict("Recheck time is unavailable")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class DefenseRecheckService:
    def __init__(
        self,
        controller: DefenseService,
        hosts: Mapping[str, HostConfig],
        store: RecheckLedger,
        *,
        collector: Callable[[HostConfig], BusinessReadiness] | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.controller, self.hosts, self.store = controller, hosts, store
        self.collector, self.clock = collector, clock or controller.clock
        self.owner = "defense-recheck-" + secrets.token_hex(16)

    def _task(self, host_id, rid):
        transaction = self.controller.store.transaction(rid)
        if transaction.kind != "action" or transaction.context.host_id != host_id:
            raise DefenseConflict("Recheck task binding changed")
        manifest = self.controller.store.manifest(rid)
        return transaction, manifest

    def _host(self, host_id):
        host = self.hosts.get(host_id)
        if host is None or host.public.id != host_id or host.public.source != "ssh":
            raise DefenseConflict("Recheck host registration is unavailable")
        if len(host.business_checks) > 3 or len({row.id for row in host.business_checks}) != len(
            host.business_checks
        ):
            raise DefenseConflict("Recheck business registration is invalid")
        return host

    def _run(self, host_id, rid, run_ref):
        run = self.store.get(run_ref)
        if run is None or (run.declaration.host_id, run.declaration.rid) != (host_id, rid):
            raise DefenseConflict("Recheck reference is unavailable")
        return run

    @staticmethod
    def _pin(host):
        import hashlib

        if host.public.trusted_hosts_digest is None:
            raise DefenseConflict("Business connection requires its registered public pin")
        try:
            raw, seal = _read_file(host.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
            if hashlib.sha256(raw).hexdigest() != host.public.trusted_hosts_digest:
                raise DefenseConflict("Business public pin changed")
            return seal
        except (ValueError, OSError):
            raise DefenseConflict("Business public pin is unavailable") from None

    def _registered_physical_scope(self, host_id: str) -> str:
        """Read public registration only; mode, grants and key bytes are unrelated here."""
        target = self.controller.targets.get(host_id)
        if type(target) is not DefenseTarget or target.host.public.id != host_id:
            raise DefenseConflict("Current defense physical registration is unavailable")
        for role in ("readonly", "observe", "control"):
            credential = getattr(target, role)
            _, seal = _read_file(credential.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
            if seal != credential._hosts_seal or seal.sha256 != credential.trusted_hosts_digest:
                raise DefenseConflict("Current defense public pin changed")
        return digest(
            {
                "channel": "ssh-defense-controller/v1",
                "host_scope": scope_for(target.host.public),
                "trusted_host_digest": target.readonly.trusted_hosts_digest,
                "role_key_identities": {
                    role: getattr(target, role).key_identity
                    for role in ("readonly", "observe", "control")
                },
                "root_scope_sha256": target.root_scope_sha256,
                "root_policy_sha256": target.root_policy_sha256,
                "boot_ref": target.boot_ref,
                "binding_ref": target.binding_ref,
            }
        )

    def _query(self, host_id, rid, claim):
        try:
            observation, reply = self.controller.query_with_observation(host_id, rid)
            recorded = self.controller.store.observation_record(observation.observation_id)
            evidence = RecheckRootEvidence.model_validate_json(canonical(recorded))
            if (
                evidence.observation != observation
                or ((observation.accepted or reply is not None) and evidence.reply != reply)
                or evidence.sequence <= claim.observation_sequence
            ):
                return None
            return evidence
        except (ValueError, OSError, RuntimeError):
            return None

    @staticmethod
    def _state(frame: RecheckRootEvidence | None) -> RootState:
        if frame is None or not frame.observation.accepted or frame.reply is None:
            return "unavailable"
        state = frame.reply.state
        if state not in {
            "active",
            "expired",
            "revoked",
            "ready",
            "ready_expired",
            "unknown",
            "rejected",
            "not_found",
        }:
            return "unavailable"
        return state

    @staticmethod
    def _valid_root(frame, transaction, manifest, *, after_sequence=0):
        if frame is None or frame.sequence <= after_sequence or frame.reply is None:
            return False
        observation, reply = frame.observation, frame.reply
        return bool(
            observation.accepted
            and observation.op == "query"
            and reply.op == "query"
            and observation.rid == transaction.rid
            and reply.request_id == transaction.rid
            and observation.receipt_sha256 == digest_wire(reply)
            and reply.manifest_sha256 == manifest.sha256
            and reply.action_id == manifest.action_id
            and reply.cursor_id == manifest.cursor_id
            and reply.scope_sha256 == manifest.scope_sha256
            and reply.policy_sha256 == manifest.policy_sha256
            and reply.boot_ref == manifest.boot_ref
            and reply.binding_ref == manifest.binding_ref
            and reply.mode == manifest.mode
            and reply.mode_revision == manifest.mode_revision
            and reply.deadline_at == manifest.deadline_at
            and reply.state in {"active", "expired", "revoked"}
        )

    def _collect(self, host):
        expected = tuple(check.id for check in host.business_checks)
        try:
            if self.collector is None:
                raise ValueError("Registered business collector is unavailable")
            outcome = self.collector(host)
            if type(outcome) is not BusinessReadiness or outcome.host_id != host.public.id:
                raise ValueError("Recheck collector returned an unbound result")
            if tuple(check.id for check in outcome.checks) != expected:
                raise ValueError("Recheck checks do not close")
            rows = []
            for configured, check in zip(host.business_checks, outcome.checks, strict=True):
                status = check.status if configured.read_only_confirmed else "uncovered"
                reason = "not_confirmed"
                if status == "passed":
                    if (
                        check.status_matches is not True
                        or check.body_matches is not True
                        or type(check.http_status) is not int
                        or check.http_status != configured.expected_status
                    ):
                        status, reason = "inconclusive", "receipt_unavailable"
                    else:
                        reason = "business_passed"
                elif status == "failed":
                    if (
                        check.status_matches is False
                        and type(check.http_status) is int
                        and 200 <= check.http_status <= 599
                        and check.http_status != configured.expected_status
                    ):
                        reason = "status_mismatch"
                    elif (
                        check.status_matches is True
                        and check.body_matches is False
                        and type(check.http_status) is int
                        and check.http_status == configured.expected_status
                    ):
                        reason = "body_mismatch"
                    else:
                        status, reason = "inconclusive", "receipt_unavailable"
                elif status == "inconclusive":
                    reason = "business_inconclusive"
                rows.append(
                    RecheckBusinessCheck(id=configured.id, status=status, reason_code=reason)
                )
        except (ValueError, TypeError, AttributeError, KeyError, RuntimeError, OSError):
            rows = [
                RecheckBusinessCheck(
                    id=check.id, status="inconclusive", reason_code="receipt_unavailable"
                )
                for check in host.business_checks
            ]
        states = {check.status for check in rows}
        status = next(
            (
                value
                for value in ("failed", "inconclusive", "uncovered", "passed")
                if value in states
            ),
            "uncovered",
        )
        return RecheckBusinessEvidence(checks=tuple(rows), status=status)

    def start(self, host_id: str, rid: str, body: DefenseRecheckRequest) -> dict:
        body = DefenseRecheckRequest.model_validate_json(canonical(body))
        declaration = DefenseRecheckDeclaration(
            run_ref=body.run_ref,
            host_id=host_id,
            rid=rid,
            expected_manifest_sha256=body.expected_manifest_sha256,
            expected_profile_sha256=body.expected_profile_sha256,
        )
        with self.controller.mode_lock:
            retained = self.store.get(body.run_ref)
            if retained is not None:
                if retained.declaration != declaration:
                    raise DefenseConflict("Recheck declaration cannot be replaced")
                return self._view(retained)
            transaction, manifest = self._task(host_id, rid)
            host = copy.deepcopy(self._host(host_id))
            profile, host_scope = business_profile_digest(host), scope_for(host.public)
            pin = self._pin(host)
            if (
                manifest.sha256 != body.expected_manifest_sha256
                or profile != body.expected_profile_sha256
            ):
                raise DefenseConflict("Recheck preview changed")
            original_profile = self.store.action_profile(rid)
            if original_profile is not None and original_profile.host_scope != host_scope:
                raise DefenseConflict("Original recheck host scope changed")
            run = self.store.create(declaration, now=self.clock())
            claim = self.store.claim(body.run_ref, owner=self.owner, now=self.clock())
            if claim is None:
                return self._view(self._run(host_id, rid, body.run_ref))

        # No mode lock or SQLite transaction spans either transport.
        started = self.clock()
        root_before = self._query(host_id, rid, claim)
        collected_start = self.clock()
        business = self._collect(host)
        collected_end = self.clock()
        root_after = self._query(host_id, rid, claim)
        finished = self.clock()
        reasons: list[RecheckReason] = []
        with self.controller.mode_lock:
            latest_transaction, latest_manifest = self._task(host_id, rid)
            authority = self.store.authority(rid, root_before)
            if authority.kind == "unproven":
                reasons.append("authority_unproven")
            try:
                current = self._host(host_id)
                if scope_for(current.public) != host_scope:
                    reasons.append("scope_changed")
                if business_profile_digest(current) != profile:
                    reasons.append("profile_changed")
                if self._pin(current) != pin:
                    reasons.append("scope_changed")
            except DefenseConflict:
                reasons.append("scope_changed")
            if latest_transaction.context != transaction.context or latest_manifest != manifest:
                reasons.append("evidence_changed")
            if original_profile is None:
                reasons.append("profile_missing")
            elif (
                original_profile.context_sha256 != digest(transaction.context)
                or original_profile.prepare_request_sha256
                != self.controller.store.request_metadata(rid, "prepare").request_sha256
                or original_profile.host_scope != host_scope
                or original_profile.business_profile_sha256 != profile
                or original_profile.check_ids != tuple(check.id for check in host.business_checks)
                or self.store.action_profile(rid) != original_profile
            ):
                reasons.append("profile_changed")
            if not self._valid_root(
                root_before, transaction, manifest, after_sequence=claim.observation_sequence
            ):
                reasons.append("root_unproven")
            if not self._valid_root(
                root_after,
                transaction,
                manifest,
                after_sequence=(
                    root_before.sequence if root_before else claim.observation_sequence
                ),
            ):
                reasons.append("root_unproven")
            transition = root_transition(root_before, root_after)
            if transition not in {"unchanged", "ttl_elapsed"}:
                reasons.append("root_changed")
            times = [utc(run.created_at), utc(claim.claimed_at), started]
            if root_before is not None:
                times.append(utc(root_before.observation.observed_at))
            times.extend((collected_start, collected_end))
            if root_after is not None:
                times.append(utc(root_after.observation.observed_at))
            times.append(finished)
            time_valid = all(left <= right for left, right in zip(times, times[1:], strict=False))
            if not time_valid:
                reasons.extend(("clock_regressed", "time_unverified"))
            safe_checks = _handoff_checks(business)
            verdict = merge_verdict(safe_checks, bindings_complete=not reasons)
            if not time_valid:
                verdict = "pending"
            if business.status != "passed":
                reasons.append(
                    "business_failed" if business.status == "failed" else "business_inconclusive"
                )
            if transition == "ttl_elapsed":
                reasons.append("ttl_elapsed")
            result = DefenseRecheckResult(
                run_ref=body.run_ref,
                host_id=host_id,
                rid=rid,
                manifest_sha256=manifest.sha256,
                defense_scope=transaction.context.defense_scope,
                host_scope=host_scope,
                business_profile_sha256=profile,
                authority=authority,
                business=business,
                root_before=root_before,
                root_after=root_after,
                expected_root_state=self._state(root_before),
                current_root_state=self._state(root_after),
                transition=transition,
                started_at=_stamp(started),
                finished_at=_stamp(finished),
                verdict=verdict,
                reason_codes=tuple(dict.fromkeys(reasons)) or ("ok",),
            )
            completed = self.store.finish(claim, result)
            return self._view(completed)

    def _latest(self, rid):
        try:
            value = self.controller.store.latest_observation(rid)
            return (
                None if value is None else RecheckRootEvidence.model_validate_json(canonical(value))
            )
        except ValueError:
            return None

    def _execution_timeline(self, host_id: str, rid: str) -> dict:
        """Close original local intent and exact Root observations, without transport."""
        values = {
            "original_authority_kind": "unproven",
            "original_authority_at": None,
            "execution_status": "unproven",
            "execution_submitted_at": None,
            "execution_confirmed_at": None,
            "receipt_status": "no_gap",
            "receipt_unconfirmed_at": None,
            "reconciliation_status": "pending",
            "reconciled_at": None,
        }
        try:
            transaction, manifest = self._task(host_id, rid)
            base = self.controller.store
            prepare = base.request(rid, "prepare")
            frames = sorted(
                (base.observation_record(row.observation_id) for row in base.observations(rid)),
                key=lambda row: row.sequence,
            )

            def closed(frame):
                reply, observation = frame.reply, frame.observation
                return bool(
                    observation.accepted
                    and reply is not None
                    and observation.op in {"apply", "query"}
                    and reply.op == observation.op
                    and observation.rid == rid
                    and reply.request_id == rid
                    and observation.receipt_sha256 == digest_wire(reply)
                    and reply.scope_sha256 == transaction.context.root_scope
                    and reply.policy_sha256 == transaction.context.policy_sha256
                    and reply.boot_ref == transaction.context.boot_ref
                    and reply.binding_ref == transaction.context.binding_ref
                    and reply.action_id == manifest.action_id
                    and reply.cursor_id == manifest.cursor_id
                    and reply.mode == manifest.mode
                    and reply.mode_revision == manifest.mode_revision
                    and rebuild_manifest(prepare, reply) == manifest
                    and reply.manifest_sha256 == manifest.sha256
                )

            queries = [
                row
                for row in frames
                if row.observation.op == "query"
                and closed(row)
                and row.reply is not None
                and row.reply.state in {"ready", "ready_expired", "active", "expired", "revoked"}
            ]
            authority_frame = next(
                (
                    row
                    for row in reversed(queries)
                    if row.reply is not None and row.reply.state in {"active", "expired", "revoked"}
                ),
                None,
            )
            authority = self.store.authority(
                rid,
                None
                if authority_frame is None
                else RecheckRootEvidence.model_validate_json(canonical(authority_frame)),
            )
            values["original_authority_kind"] = authority.kind
            if authority.kind == "human_approval":
                record = base.approval_record(rid, "apply")
                if record is not None:
                    values["original_authority_at"] = record.metadata.approval.approved_at
            elif authority.kind == "preauthorization":
                usage = base.execution_usage(rid)
                if usage is not None:
                    values["original_authority_at"] = usage.created_at
            try:
                request, metadata = base.request(rid, "apply"), base.request_metadata(rid, "apply")
            except DefenseConflict:
                request = metadata = None
            submitted = bool(
                request is not None
                and isinstance(request.body, ActionBody)
                and request.request_id == rid
                and request.scope_sha256 == manifest.scope_sha256
                and request.body.manifest_sha256 == manifest.sha256
                and metadata is not None
                and metadata.send_started_at is not None
                and metadata.send_owner == transaction.owner
                and metadata.dispatch_phase in {"sendable", "replied", "unknown"}
            )
            values["execution_status"] = "submitted" if submitted else "not_submitted"
            if submitted and metadata is not None and metadata.send_started_at is not None:
                values["execution_submitted_at"] = metadata.send_started_at
                active = next(
                    (
                        row
                        for row in frames
                        if closed(row)
                        and row.reply is not None
                        and row.reply.state == "active"
                        and utc(row.observation.observed_at) >= utc(metadata.send_started_at)
                    ),
                    None,
                )
                if active is not None:
                    values["execution_status"] = "confirmed"
                    values["execution_confirmed_at"] = active.observation.observed_at
            gaps = [
                row
                for row in frames
                if (
                    row.observation.state in {"unavailable", "unknown"}
                    or (not row.observation.accepted and row.observation.reason != "rejected")
                )
            ]
            if gaps:
                gap = gaps[-1]
                values["receipt_status"] = "unconfirmed"
                values["receipt_unconfirmed_at"] = gap.observation.observed_at
                reconciled = next(
                    (
                        row
                        for row in queries
                        if row.sequence > gap.sequence
                        and utc(row.observation.observed_at) >= utc(gap.observation.observed_at)
                    ),
                    None,
                )
                if reconciled is not None:
                    values["reconciliation_status"] = "reconciled"
                    values["reconciled_at"] = reconciled.observation.observed_at
            elif not submitted or values["execution_status"] == "confirmed":
                values["reconciliation_status"] = "not_needed"
        except (ValueError, TypeError, AttributeError, OSError):
            values["execution_status"] = "unproven"
        return values

    def _projection(self, run: DefenseRecheckRun) -> DefenseHandoffProjection:
        reference = _task_reference(
            run.declaration.host_id, run.declaration.rid, run.declaration.expected_manifest_sha256
        )
        result = run.result
        execution = self._execution_timeline(run.declaration.host_id, run.declaration.rid)
        if result is None:
            reason: HandoffReason = "interrupted" if run.status == "interrupted" else "in_progress"
            return DefenseHandoffProjection(
                task_reference_sha256=reference, reasons=(reason,), **execution
            )
        checks = _handoff_checks(result.business)
        historical = result.verdict
        current = historical
        reasons: list[HandoffReason] = []
        for reason in result.reason_codes:
            mapped = _public_reason(reason)
            if mapped is not None and mapped not in reasons:
                reasons.append(mapped)
        latest = self._latest(run.declaration.rid)
        current_root = self._state(latest)
        observed_at = latest.observation.observed_at if latest is not None else None
        newer = self.store.list(
            run.declaration.host_id, run.declaration.rid, after_sequence=run.sequence, limit=1
        )
        if newer:
            current = "pending"
            reasons.append("newer_recheck")
        if historical == "passed" and (
            execution["execution_status"] != "confirmed"
            or execution["original_authority_kind"] == "unproven"
            or execution["reconciliation_status"] == "pending"
        ):
            current = "pending"
            reasons.append("current_unverified")
        if historical == "passed":
            try:
                transaction, manifest = self._task(run.declaration.host_id, run.declaration.rid)
                host = self._host(run.declaration.host_id)
                self._pin(host)
                physical_scope = self._registered_physical_scope(run.declaration.host_id)
                profile = self.store.action_profile(run.declaration.rid)
                current_authority = self.store.authority(run.declaration.rid, latest)
                now = self.clock()
                age = (now - utc(observed_at)).total_seconds() if observed_at else -1
                finished_age = (now - utc(result.finished_at)).total_seconds()
                # The final Root RPC can take time after business collection.
                # Only this sealed run's exact pre-collection observation may
                # anchor business freshness; later queries cannot renew it.
                business_anchor = (
                    result.root_before.observation.observed_at if result.root_before else None
                )
                business_age = (
                    (now - utc(business_anchor)).total_seconds() if business_anchor else -1
                )
                valid = (
                    not transaction.query_required
                    and not newer
                    and physical_scope == transaction.context.defense_scope
                    and self._valid_root(latest, transaction, manifest)
                    and latest is not None
                    and result.root_after is not None
                    and latest.sequence >= result.root_after.sequence
                    and 0 <= age <= MAX_CURRENT_QUERY_AGE_SECONDS
                    and 0 <= finished_age <= MAX_CURRENT_BUSINESS_AGE_SECONDS
                    and 0 <= business_age <= MAX_CURRENT_BUSINESS_AGE_SECONDS
                    and profile is not None
                    and profile.host_scope == scope_for(host.public) == result.host_scope
                    and profile.business_profile_sha256
                    == business_profile_digest(host)
                    == result.business_profile_sha256
                    and current_authority == result.authority
                )
                if (
                    valid
                    and latest is not None
                    and latest.reply is not None
                    and latest.reply.state == "active"
                ):
                    valid = (
                        latest.reply.remaining_ms is not None
                        and age * 1000 < latest.reply.remaining_ms
                    )
                if not valid:
                    current = "pending"
                    reasons.append(
                        "current_unknown" if transaction.query_required else "current_unverified"
                    )
            except (ValueError, OSError, RuntimeError):
                current = "pending"
                reasons.append("current_unverified")
        return DefenseHandoffProjection(
            **execution,
            task_reference_sha256=reference,
            historical_verdict=historical,
            current_verdict=current,
            business_verdict=merge_business(checks),
            authority_kind=result.authority.kind,
            root_before=self._state(result.root_before),
            root_after=self._state(result.root_after),
            current_root=current_root,
            transition=result.transition,
            started_at=result.started_at,
            finished_at=result.finished_at,
            root_observed_at=result.root_after.observation.observed_at
            if result.root_after
            else None,
            current_root_observed_at=observed_at,
            checks=checks,
            reasons=tuple(dict.fromkeys(reasons)),
        )

    def _view(self, run: DefenseRecheckRun) -> dict:
        projection = self._projection(run)
        now = self.clock()
        interrupt_available = bool(
            run.status == "claimed"
            and run.claimed_at is not None
            and utc(run.created_at) <= utc(run.claimed_at) <= now
            and (now - utc(run.claimed_at)).total_seconds() >= 120
        )
        return {
            "v": 2,
            "run_ref": run.declaration.run_ref,
            "host_id": run.declaration.host_id,
            "request_id": run.declaration.rid,
            "sequence": run.sequence,
            "status": run.status,
            "created_at": run.created_at,
            "claimed_at": run.claimed_at,
            "declaration_sha256": run.declaration_sha256,
            "can_interrupt": interrupt_available,
            "expected_manifest_sha256": run.declaration.expected_manifest_sha256,
            "expected_profile_sha256": run.declaration.expected_profile_sha256,
            "historical_verdict": projection.historical_verdict,
            "current_verdict": projection.current_verdict,
            "projection": projection.model_dump(mode="json"),
        }

    def get(self, host_id: str, rid: str, run_ref: str) -> dict:
        return self._view(self._run(host_id, rid, run_ref))

    def interrupt(
        self, host_id: str, rid: str, run_ref: str, body: DefenseRecheckInterrupt
    ) -> dict:
        body = DefenseRecheckInterrupt.model_validate_json(canonical(body))
        with self.controller.mode_lock:
            self._run(host_id, rid, run_ref)
            result = self.store.interrupt(
                run_ref,
                expected_declaration_sha256=body.expected_declaration_sha256,
                now=self.clock(),
            )
            return self._view(result)

    def list(self, host_id: str, rid: str, *, after_sequence: int = 0, limit: int = 20) -> dict:
        _, manifest = self._task(host_id, rid)
        current_profile = None
        configured = 0
        can_run = False
        try:
            host = self._host(host_id)
            current_profile = business_profile_digest(host)
            configured = len(host.business_checks)
            can_run = bool(
                self.collector is not None
                and host.public.trusted_hosts_digest
                and any(check.read_only_confirmed for check in host.business_checks)
            )
        except DefenseConflict:
            pass
        rows = self.store.list(host_id, rid, after_sequence=after_sequence, limit=limit)
        active = self.store.active_run(host_id)
        if active is not None:
            can_run = False
        return {
            "v": 2,
            "host_id": host_id,
            "request_id": rid,
            "expected_manifest_sha256": manifest.sha256,
            "current_profile_sha256": current_profile,
            "configured_checks": configured,
            "can_run": can_run,
            "active_run_ref": active.declaration.run_ref if active else None,
            "active_request_id": active.declaration.rid if active else None,
            "runs": [self._view(row) for row in rows],
            "next_after_sequence": rows[-1].sequence if rows and len(rows) == limit else None,
        }

    def handoff(self, host_id: str, rid: str, *, run_ref: str | None = None) -> str:
        _, manifest = self._task(host_id, rid)
        projection = (
            DefenseHandoffProjection(
                task_reference_sha256=_task_reference(host_id, rid, manifest.sha256),
                reasons=("not_run",),
                **self._execution_timeline(host_id, rid),
            )
            if run_ref is None
            else (self._projection(self._run(host_id, rid, run_ref)))
        )
        return defense_handoff_markdown(projection)

    def _legacy_view(self, host_id, rid, value):
        transaction, _ = self._task(host_id, rid)
        record = value.record
        if record.rid != rid or record.defense_scope != transaction.context.defense_scope:
            raise DefenseConflict("Legacy recheck reference changed")
        projection = DefenseHandoffProjection(
            task_reference_sha256=_task_reference(host_id, rid, record.manifest_sha256),
            started_at=record.started_at,
            finished_at=record.ended_at,
            reasons=("legacy_incomplete",),
        )
        return {
            "v": 1,
            "legacy_id": record.recheck_id,
            "sequence": value.sequence,
            "host_id": host_id,
            "request_id": rid,
            "started_at": record.started_at,
            "finished_at": record.ended_at,
            "historical_verdict": "pending",
            "current_verdict": "pending",
            "projection": projection.model_dump(mode="json"),
        }

    def legacy_get(self, host_id: str, rid: str, legacy_id: str) -> dict:
        value = self.controller.store.legacy_recheck(legacy_id)
        if value is None:
            raise DefenseConflict("Legacy recheck reference is unavailable")
        return self._legacy_view(host_id, rid, value)

    def legacy_list(
        self, host_id: str, rid: str, *, after_sequence: int = 0, limit: int = 20
    ) -> dict:
        self._task(host_id, rid)
        rows = self.controller.store.legacy_rechecks(
            host_id, rid, after_sequence=after_sequence, limit=limit
        )
        return {
            "v": 1,
            "host_id": host_id,
            "request_id": rid,
            "legacy_rechecks": [self._legacy_view(host_id, rid, value) for value in rows],
            "next_after_sequence": rows[-1].sequence if rows and len(rows) == limit else None,
        }

    def legacy_handoff(self, host_id: str, rid: str, legacy_id: str) -> str:
        view = self.legacy_get(host_id, rid, legacy_id)
        projection = DefenseHandoffProjection.model_validate_json(canonical(view["projection"]))
        return defense_handoff_markdown(projection)


def digest_wire(reply: DefenseReply) -> str:
    import hashlib

    return hashlib.sha256(canonical(reply) + b"\n").hexdigest()


def _task_reference(host_id: str, rid: str, manifest_sha256: str) -> str:
    return digest(
        {
            "channel": "ssh-defense-handoff-reference/v1",
            "host_id": host_id,
            "rid": rid,
            "manifest_sha256": manifest_sha256,
        }
    )


def _handoff_checks(business: RecheckBusinessEvidence) -> tuple[HandoffCheck, ...]:
    rows = []
    for number, check in enumerate(business.checks, 1):
        reasons: dict[str, CheckReason] = {
            "status_mismatch": "status_mismatch",
            "body_mismatch": "body_mismatch",
            "not_confirmed": "uncovered",
            "ok": "matched",
            "business_passed": "matched",
        }
        reason = reasons.get(check.reason_code, "incomplete")
        rows.append(HandoffCheck(number=number, status=check.status, reason_code=reason))
    return tuple(rows)


def _public_reason(reason) -> HandoffReason | None:
    if reason in {"ok", "authority_proven", "business_passed", "ttl_elapsed"}:
        return None
    if reason.startswith("approval_") or reason in {
        "authority_unproven",
        "preauthorization_invalid",
        "usage_missing",
        "apply_not_sent",
    }:
        return "authority_unproven"
    reasons: dict[str, HandoffReason] = {
        "profile_missing": "original_profile_missing",
        "profile_changed": "profile_changed",
        "scope_changed": "scope_changed",
        "root_unproven": "root_unverified",
        "root_unavailable": "root_unverified",
        "root_changed": "evidence_changed",
        "clock_regressed": "time_unverified",
        "time_unverified": "time_unverified",
        "business_failed": "business_failed",
        "run_unfinished": "result_unknown",
        "evidence_changed": "evidence_changed",
    }
    return reasons.get(reason, "incomplete")
