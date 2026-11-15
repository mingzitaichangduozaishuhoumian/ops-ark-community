"""Project local action evidence into the structured customer handoff timeline."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from pydantic import AwareDatetime, ValidationError

from opsark.action_handoff import (
    ActionTimeline,
    BusinessSnapshot,
    OperationStatus,
    ReconciliationStatus,
)
from opsark.action_handoff_recheck_store import (
    ActionHandoffRecheckStore,
    ActionKind,
    ActionRecheckBinding,
    ActionRecheckRun,
    Digest,
    HostId,
    PlanId,
    ReportId,
    RunId,
    Verdict,
)
from opsark.baselines import report_target_matches_host_scope, scope_for
from opsark.business_readiness import business_profile_digest
from opsark.config import HostConfig
from opsark.container_restarts import ContainerRestartService, ReceiptSource
from opsark.models import HostPublic, StrictModel
from opsark.nginx_actions import NginxActionService
from opsark.storage import ReportStore

_MISMATCH = "处置交接记录与原报告或原任务不一致。"
_UNAVAILABLE = "当前登记与处置回执不足以开始业务复验。"


class _Ledger(StrictModel, strict=True, frozen=True):
    report_id: ReportId
    host_id: HostId
    host_scope: Digest
    target_scope: Digest
    plan_id: PlanId
    action_id: Digest
    approval_id: PlanId
    approved_at: AwareDatetime
    receipt_observed_at: AwareDatetime | None
    receipt_source: ReceiptSource | None
    operation_status: OperationStatus
    reconciliation_status: ReconciliationStatus | None
    blocking: bool


class _NginxLedger(_Ledger):
    action: Literal["apply", "restore"]
    original_action_id: Digest | None


class ActionHandoffRecheckSummary(StrictModel, strict=True, frozen=True):
    """Operator selection metadata. Customer Markdown excludes these identifiers."""

    id: RunId
    selection: Literal["current", "historical"]
    verdict: Verdict
    started_at: AwareDatetime
    finished_at: AwareDatetime | None


@dataclass(frozen=True)
class _Evidence:
    ledger: _Ledger
    timeline: ActionTimeline
    rollback_allows_current: bool


def _report_time(reports: ReportStore, ledger: _Ledger) -> datetime:
    with reports._connection() as db:
        row = db.execute(
            "SELECT created_at, json_extract(payload,'$.id') AS payload_id, "
            "json_extract(payload,'$.created_at') AS payload_time, "
            "json_extract(payload,'$.host_id') AS host_id, "
            "json_extract(payload,'$.source') AS source, "
            "json_extract(payload,'$.scope_hash') AS scope, "
            "json_extract(payload,'$.target') AS target "
            "FROM reports WHERE id=?",
            (ledger.report_id,),
        ).fetchone()
    if (
        row is None
        or row["payload_id"] != ledger.report_id
        or row["source"] != "ssh"
        or row["host_id"] != ledger.host_id
        or row["target"] is None
    ):
        raise ValueError(_MISMATCH)
    try:
        target = HostPublic.model_validate_json(row["target"])
        created = datetime.fromisoformat(row["created_at"])
        payload_time = datetime.fromisoformat(row["payload_time"])
    except (TypeError, ValueError):
        raise ValueError(_MISMATCH) from None
    if (
        created.utcoffset() is None
        or payload_time.utcoffset() is None
        or created != payload_time
        or not report_target_matches_host_scope(
            target, ledger.host_id, row["scope"], ledger.host_scope
        )
    ):
        raise ValueError(_MISMATCH)
    return created


def _digest(domain: str, *values: str) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _ledger(model: type[_Ledger], row: dict) -> _Ledger:
    try:
        evidence = model.model_validate_json(json.dumps(row))
    except (TypeError, ValueError):
        raise ValueError(_MISMATCH) from None
    if (evidence.receipt_observed_at is None) != (evidence.receipt_source is None):
        raise ValueError(_MISMATCH)
    if isinstance(evidence, _NginxLedger) and (
        (evidence.action == "restore") != (evidence.original_action_id is not None)
    ):
        raise ValueError(_MISMATCH)
    return evidence


def _timeline(ledger: _Ledger, investigated_at: datetime) -> ActionTimeline:
    kind = "container_restart"
    if isinstance(ledger, _NginxLedger):
        kind = "nginx_apply" if ledger.action == "apply" else "nginx_restore"
    try:
        return ActionTimeline(
            kind=kind,
            investigated_at=investigated_at,
            approved_at=ledger.approved_at,
            receipt_observed_at=ledger.receipt_observed_at,
            operation_status=ledger.operation_status,
            reconciliation_status=ledger.reconciliation_status,
        )
    except ValidationError:
        raise ValueError(_MISMATCH) from None


def _execution_fields(kind: ActionKind, ledger: _Ledger, observed: datetime) -> tuple[str, str]:
    approval = _digest(
        "opsark-action-handoff-approval/v1",
        kind,
        ledger.report_id,
        ledger.host_id,
        ledger.host_scope,
        ledger.target_scope,
        ledger.plan_id,
        ledger.action_id,
        ledger.approval_id,
        ledger.approved_at.astimezone(UTC).isoformat(),
    )
    execution = _digest(
        "opsark-action-handoff-execution/v1",
        approval,
        observed.astimezone(UTC).isoformat(),
        ledger.receipt_source or "",
        ledger.operation_status,
        ledger.reconciliation_status or "",
    )
    return approval, execution


class ActionHandoffProjection:
    """Read local ledgers only. Business collection and execution have separate entry points."""

    def __init__(
        self,
        reports: ReportStore,
        nginx: NginxActionService,
        container: ContainerRestartService,
        rechecks: ActionHandoffRecheckStore,
    ) -> None:
        self._reports = reports
        self._nginx = nginx
        self._container = container
        self._rechecks = rechecks

    def _evidence(self, report_id: str, kind: ActionKind, plan_id: str) -> _Evidence | None:
        rollback_allows_current = True
        related = None
        if kind == "nginx":
            raw, related, indexed = self._nginx.read_handoff_with_restore(plan_id)
            rollback_allows_current = indexed and related is None
            model = _NginxLedger
        elif kind == "container_restart":
            raw = self._container.read_handoff(plan_id)
            model = _Ledger
        else:
            raise ValueError(_MISMATCH)
        if raw is None:
            return None
        ledger = _ledger(model, raw)
        if ledger.report_id != report_id or ledger.plan_id != plan_id:
            raise ValueError(_MISMATCH)
        investigated = _report_time(self._reports, ledger)
        timeline = _timeline(ledger, investigated)
        if related is not None:
            restore = _ledger(_NginxLedger, related)
            if (
                not isinstance(restore, _NginxLedger)
                or restore.action != "restore"
                or restore.original_action_id != ledger.action_id
                or restore.plan_id == ledger.plan_id
                or restore.report_id != ledger.report_id
                or restore.host_id != ledger.host_id
                or restore.host_scope != ledger.host_scope
                or restore.target_scope != ledger.target_scope
                or restore.approved_at < ledger.approved_at
            ):
                raise ValueError(_MISMATCH)
            _timeline(restore, investigated)
        return _Evidence(ledger, timeline, rollback_allows_current)

    def _binding(
        self, kind: ActionKind, evidence: _Evidence, profile: HostConfig | None
    ) -> ActionRecheckBinding | None:
        ledger, timeline = evidence.ledger, evidence.timeline
        observed = timeline.receipt_observed_at
        if (
            profile is None
            or not evidence.rollback_allows_current
            or ledger.blocking
            or not timeline.operation_verified
            or observed is None
            or profile.public.source != "ssh"
            or profile.public.id != ledger.host_id
            or scope_for(profile.public) != ledger.host_scope
            or not 1 <= len(profile.business_checks) <= 3
        ):
            return None
        targets = self._nginx.targets if kind == "nginx" else self._container.targets
        target = targets.get(ledger.host_id)
        if (
            target is None
            or target.target_scope != ledger.target_scope
            or target.host.business_checks != profile.business_checks
        ):
            return None
        approval, execution = _execution_fields(kind, ledger, observed)
        return ActionRecheckBinding(
            report_id=ledger.report_id,
            kind=kind,
            plan_id=ledger.plan_id,
            host_id=ledger.host_id,
            host_scope=ledger.host_scope,
            target_scope=ledger.target_scope,
            approval_digest=approval,
            execution_digest=execution,
            profile_digest=business_profile_digest(profile),
            execution_at=observed,
            configured_checks=len(profile.business_checks),
        )

    def binding(
        self, report_id: str, kind: ActionKind, plan_id: str, profile: HostConfig
    ) -> ActionRecheckBinding:
        """Resolve eligibility from the original action and the current private registration."""
        evidence = self._evidence(report_id, kind, plan_id)
        binding = self._binding(kind, evidence, profile) if evidence is not None else None
        if binding is None:
            raise ValueError(_UNAVAILABLE)
        return binding

    def timeline(
        self,
        report_id: str,
        kind: ActionKind,
        plan_id: str,
        *,
        profile: HostConfig | None = None,
        recheck_id: str | None = None,
    ) -> ActionTimeline | None:
        """Resolve one current or explicitly selected historical result for export."""
        evidence = self._evidence(report_id, kind, plan_id)
        if evidence is None:
            if recheck_id is not None:
                raise ValueError(_MISMATCH)
            return None
        current = self._binding(kind, evidence, profile)
        selected = None
        if recheck_id is not None:
            selected = self._rechecks.get_original(report_id, kind, plan_id, recheck_id)
            if selected is None:
                raise ValueError(_MISMATCH)
        latest = self._rechecks.latest(current) if current is not None else None
        if recheck_id is None:
            selected = latest
        if selected is None:
            return evidence.timeline
        self._validate_selection(kind, evidence, selected)
        if selected.result is None:
            return evidence.timeline

        is_current = latest is not None and latest.intent.id == selected.intent.id
        if is_current:
            # A rollback may have been approved while the separate report database was read.
            refreshed = self._evidence(report_id, kind, plan_id)
            if refreshed is None or self._binding(kind, refreshed, profile) != current:
                if recheck_id is None:
                    return refreshed.timeline if refreshed is not None else None
                if refreshed is None:
                    raise ValueError(_MISMATCH)
                self._validate_selection(kind, refreshed, selected)
                evidence, is_current = refreshed, False

        binding = selected.intent.binding
        business = BusinessSnapshot(
            selection="current" if is_current else "historical",
            started_at=selected.intent.started_at,
            finished_at=selected.result.finished_at,
            configured_checks=binding.configured_checks,
            passed_checks=selected.result.checks.count("passed"),
            failed_checks=selected.result.checks.count("failed"),
        )
        return ActionTimeline.model_validate({**dict(evidence.timeline), "business": business})

    def rechecks(
        self,
        report_id: str,
        kind: ActionKind,
        plan_id: str,
        *,
        profile: HostConfig | None = None,
    ) -> list[ActionHandoffRecheckSummary]:
        """Offer recent local attempts for selection without exposing their private binding."""
        evidence = self._evidence(report_id, kind, plan_id)
        if evidence is None or not evidence.timeline.operation_verified:
            return []
        history = self._rechecks.list_original(report_id, kind, plan_id)
        current = self._binding(kind, evidence, profile)
        for run in history:
            self._validate_selection(kind, evidence, run)
        latest_id = next((run.intent.id for run in history if run.intent.binding == current), None)
        if latest_id is not None:
            refreshed = self._evidence(report_id, kind, plan_id)
            if refreshed is None or self._binding(kind, refreshed, profile) != current:
                latest_id = None
        return [
            ActionHandoffRecheckSummary(
                id=run.intent.id,
                selection="current" if run.intent.id == latest_id else "historical",
                verdict=run.verdict,
                started_at=run.intent.started_at,
                finished_at=run.result.finished_at if run.result is not None else None,
            )
            for run in history
        ]

    @staticmethod
    def _validate_selection(kind: ActionKind, evidence: _Evidence, run: ActionRecheckRun) -> None:
        ledger, timeline = evidence.ledger, evidence.timeline
        observed = timeline.receipt_observed_at
        if not timeline.operation_verified or observed is None:
            raise ValueError(_MISMATCH)
        approval, execution = _execution_fields(kind, ledger, observed)
        binding = run.intent.binding
        if (
            binding.kind != kind
            or binding.report_id != ledger.report_id
            or binding.plan_id != ledger.plan_id
            or binding.host_id != ledger.host_id
            or binding.host_scope != ledger.host_scope
            or binding.target_scope != ledger.target_scope
            or binding.approval_digest != approval
            or binding.execution_digest != execution
            or binding.execution_at != observed
        ):
            raise ValueError(_MISMATCH)
