"""Project one bound patch audit and an optional read-only business recheck."""

import re
from datetime import UTC, datetime
from typing import Literal, Self, cast

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from opsark.activation_api import ActivationService, _raw_job
from opsark.automatic_store import digest
from opsark.baselines import report_target_matches_host_scope
from opsark.business_readiness import ReadinessStatus
from opsark.models import Report, StrictModel
from opsark.patch_client import PatchClientError

_ID = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
_MISMATCH = "调查、审批、任务或复验的绑定无法核实。"
_PHASES = {
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "running_overdue",
    "awaiting_transport_verification",
    "verified",
    "installed_restart_pending",
    "reboot_pending",
    "verification_failed",
    "failed",
    "rejected",
    "unknown",
}


class TimelineEvent(StrictModel):
    kind: Literal[
        "investigation",
        "approval",
        "native_record",
        "unknown",
        "reconciled",
        "activation",
        "recheck",
    ]
    at: AwareDatetime


type TimelinePhase = Literal[
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "running_overdue",
    "awaiting_transport_verification",
    "verified",
    "installed_restart_pending",
    "reboot_pending",
    "verification_failed",
    "failed",
    "rejected",
    "unknown",
]

type RecheckStatus = Literal["pending", "failed", "passed"]


class HandoffRecheckRequest(StrictModel):
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class HandoffRecheckRow(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    at: AwareDatetime
    status: RecheckStatus
    configured_checks: int = Field(ge=0, le=3)
    matched_checks: int = Field(ge=0, le=3)


class HandoffRechecks(StrictModel):
    can_run: bool
    rechecks: list[HandoffRecheckRow] = Field(max_length=20)


class BusinessHandoffRecheck(StrictModel):
    """Local task-bound receipt carrying only typed check outcomes."""

    model_config = ConfigDict(strict=True, frozen=True)

    id: str = Field(pattern=r"^br-[0-9a-f]{32}$")
    report_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    host_scope: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: AwareDatetime
    finished_at: AwareDatetime
    checks: list[ReadinessStatus] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def chronological(self) -> Self:
        _require(_instant(self.started_at) <= _instant(self.finished_at))
        return self


class HandoffTimeline(StrictModel):
    phase: TimelinePhase
    authorization: Literal["assisted", "automatic"] | None = None
    native_accepted: bool
    events: list[TimelineEvent] = Field(max_length=7)
    activation_verified: bool = False
    recheck_after: AwareDatetime | None = Field(default=None, exclude=True)
    recheck_status: RecheckStatus = "pending"
    configured_checks: int = Field(default=0, ge=0, le=3)
    matched_checks: int = Field(default=0, ge=0, le=3)


def _require(condition) -> None:
    if not condition:
        raise ValueError(_MISMATCH)


def _instant(value: object) -> datetime:
    try:
        if isinstance(value, str) and 0 < len(value) <= 64:
            value = datetime.fromisoformat(value)
        if isinstance(value, datetime) and value.utcoffset() is not None:
            return value.astimezone(UTC)
    except (ValueError, OverflowError):
        pass
    raise ValueError(_MISMATCH)


def _matches(value, pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _revision(value, *, minimum=0) -> bool:
    return type(value) is int and minimum <= value <= 2**63 - 1


def handoff_approval_digest(audit: dict) -> str:
    """Bind the approved intent without folding mutable reconciliation into its identity."""
    _require(isinstance(audit, dict))
    _require(
        _matches(audit.get("host_id"), _HOST_ID)
        and all(_matches(audit.get(key), _ID) for key in ("job_id", "plan_id"))
        and all(
            _matches(audit.get(key), _DIGEST)
            for key in ("host_scope", "plan_digest", "policy_digest")
        )
        and _revision(audit.get("mode_revision"))
        and audit.get("authorization") in ("assisted", "automatic")
    )
    return digest(
        {
            "channel": "handoff-approval/v1",
            "host_id": audit["host_id"],
            "host_scope": audit["host_scope"],
            "job_id": audit["job_id"],
            "plan_id": audit["plan_id"],
            "plan_digest": audit["plan_digest"],
            "policy_digest": audit["policy_digest"],
            "mode_revision": audit["mode_revision"],
            "authorization": audit["authorization"],
            "approved_at": _instant(audit.get("approved_at")).isoformat(),
        }
    )


def _business_recheck_time(
    recheck: BusinessHandoffRecheck, report: Report, audit: dict, approved: datetime
) -> tuple[datetime, datetime]:
    started, finished = _instant(recheck.started_at), _instant(recheck.finished_at)
    _require(
        recheck.id != report.id
        and recheck.report_id == report.id
        and recheck.job_id == audit["job_id"]
        and recheck.host_id == audit["host_id"]
        and recheck.host_scope == audit["host_scope"]
        and recheck.approval_digest == handoff_approval_digest(audit)
        and approved < started <= finished <= datetime.now(UTC)
    )
    return started, finished


def report_matches_handoff_scope(report: Report, host_id: str, scope: str) -> bool:
    return (
        report.source == "ssh"
        and report.host_id == host_id
        and report_target_matches_host_scope(report.target, host_id, report.scope_hash, scope)
    )


def _report_time(report: Report, host_id: str, scope: str) -> datetime:
    _require(report_matches_handoff_scope(report, host_id, scope))
    return _instant(report.created_at)


def _verified_http(recheck, check, after, before):
    check_id = f"http_{check.id}"
    evidence_id = "E-" + check_id.replace("_", "-").upper()
    evidence = [
        item for item in recheck.evidence if item.id == evidence_id or item.check_id == check_id
    ]
    name = f"站点即时检查：{check.id}（{check.domain}）"
    results = [
        item
        for item in recheck.verification
        if item.name == name or evidence_id in item.evidence_ids
    ]
    if not check.read_only_confirmed or len(evidence) != 1 or len(results) != 1:
        return None
    item, result = evidence[0], results[0]
    if (
        item.id != evidence_id
        or item.check_id != check_id
        or item.target != recheck.host_id
        or item.source != "ssh"
        or item.status != "ok"
        or item.truncated
        or type(item.exit_code) is not int
        or item.exit_code != 0
        or result.name != name
        or result.evidence_ids != [evidence_id]
        or result.http_status is None
        or result.status_matches is not (result.http_status == check.expected_status)
        or result.body_matches is None
    ):
        return None
    try:
        if not after < _instant(item.collected_at) <= before:
            return None
    except ValueError:
        return None
    matches = result.status_matches and result.body_matches
    if result.status == ("passed" if matches else "failed"):
        return matches
    return None


def _activation_time(activations, job, audit, after):
    candidates = [
        record
        for record in activations
        if isinstance(record, dict)
        and record.get("host_id") == audit["host_id"]
        and record.get("job_id") == audit["job_id"]
    ]
    if len(candidates) != 1:
        return None
    record = candidates[0]
    raw = _raw_job(job)
    scope = digest(
        {
            "channel": "automatic-patch/v1",
            "host_scope": audit["host_scope"],
            "policy_digest": audit["policy_digest"],
        }
    )
    if (
        record.get("status") != "verified"
        or record.get("scope_hash") != scope
        or record.get("policy_digest") != audit["policy_digest"]
        or record.get("original_job") != raw
        or record.get("job_digest") != digest(raw)
        or not _revision(record.get("job_revision"), minimum=1)
        or record["job_revision"] != job["revision"]
    ):
        return None
    try:
        ActivationService.validate_cached(record)
        result = record["result"]
        completed, updated = _instant(result["completed_at"]), _instant(record["updated_at"])
        if result["status"] == "verified" and after <= completed <= updated:
            return updated
    except (PatchClientError, ValueError, KeyError, TypeError, AttributeError):
        pass
    return None


def build_handoff_timeline(
    report: Report,
    job: dict,
    audit: dict,
    recheck: Report | BusinessHandoffRecheck | None = None,
    *,
    activations=(),
) -> HandoffTimeline:
    """Use only server-owned bound records; do not derive approval from a task alone.

    A validated activation can establish a later recheck boundary. Pause
    release has a distinct approval and is outside this projection.
    """
    _require(isinstance(job, dict) and isinstance(audit, dict))
    host_id, scope = audit.get("host_id"), audit.get("host_scope")
    if (
        not isinstance(host_id, str)
        or not host_id
        or not isinstance(scope, str)
        or not _matches(scope, _DIGEST)
    ):
        raise ValueError(_MISMATCH)
    _require(
        _matches(audit.get("job_id"), _ID)
        and _matches(audit.get("plan_id"), _ID)
        and _matches(audit.get("plan_digest"), _DIGEST)
        and _revision(audit.get("mode_revision"))
    )
    _require(
        all(
            job.get(key) == audit[key]
            for key in ("host_id", "job_id", "plan_id", "plan_digest", "mode_revision")
        )
        and _revision(job.get("mode_revision"))
    )
    _require("host_scope" not in job or job["host_scope"] == scope)
    created = _report_time(report, host_id, scope)
    approved = _instant(audit.get("approved_at"))
    _require(created <= approved)
    phase, authorization = job.get("status"), audit.get("authorization")
    _require(
        isinstance(phase, str)
        and phase in _PHASES
        and authorization in (None, "assisted", "automatic")
    )
    policy = audit.get("policy_digest")
    _require(policy is None or _matches(policy, _DIGEST))
    transport_unknown = phase == "unknown" and job.get("transport_unknown") is True
    local_rejection = phase == "rejected" and job.get("remote_job_created") is False
    _require(job.get("transport_unknown") is not True or transport_unknown)
    _require(job.get("remote_job_created") is not False or local_rejection)
    unknown_value = audit.get("unknown_at")
    unknown_at = _instant(unknown_value) if unknown_value is not None else None
    _require(unknown_at is None or unknown_at >= approved)
    reconciled_value = audit.get("reconciled_at")
    reconciled_revision = audit.get("reconciled_revision")
    reconciled_at = None
    if reconciled_value is not None or reconciled_revision is not None:
        reconciled_at = _instant(reconciled_value)
        _require(
            unknown_at is not None
            and reconciled_at >= unknown_at
            and _revision(reconciled_revision, minimum=1)
        )
    pending = transport_unknown or (unknown_at is not None and reconciled_at is None)
    if pending:
        phase = "unknown"
    native_accepted = not (pending or local_rejection)
    native_policy = job.get("execution_policy_digest", job.get("policy_digest"))
    native_authorization = job.get("authorization")
    _require(native_policy is None or native_policy == policy)
    _require(native_authorization is None or native_authorization == authorization)
    events: list[TimelineEvent] = [
        TimelineEvent(kind="investigation", at=created),
        TimelineEvent(kind="approval", at=approved),
    ]
    recorded_at = None
    if native_accepted:
        _require(
            type(job.get("schema_version")) is int
            and job["schema_version"] == 1
            and policy is not None
            and native_policy == policy
            and authorization is not None
            and native_authorization == authorization
            and _revision(job.get("revision"), minimum=1)
        )
        accepted_at = _instant(job.get("created_at"))
        recorded_at = _instant(job.get("updated_at"))
        _require(approved <= accepted_at <= recorded_at)
        events.append(TimelineEvent(kind="native_record", at=recorded_at))

    if unknown_at is not None:
        events.append(TimelineEvent(kind="unknown", at=unknown_at))
    if reconciled_at is not None and phase != "unknown":
        _require(native_accepted and reconciled_revision <= job["revision"])
        if reconciled_revision == job["revision"]:
            _require(recorded_at is not None and reconciled_at >= recorded_at)
        events.append(TimelineEvent(kind="reconciled", at=reconciled_at))

    terminal = None
    activated_at = None
    install_succeeded = type(job.get("install_exit_code")) is int and job["install_exit_code"] == 0
    if recorded_at is not None and install_succeeded:
        if phase == "verified":
            terminal = recorded_at
        elif phase == "installed_restart_pending":
            activated_at = _activation_time(activations, job, audit, recorded_at)
            if activated_at is not None:
                terminal = activated_at
                events.append(TimelineEvent(kind="activation", at=activated_at))
    if terminal is not None and reconciled_at is not None:
        terminal = max(terminal, reconciled_at)
    recheck_status, configured, matched = "pending", 0, 0
    if isinstance(recheck, BusinessHandoffRecheck):
        started, finished = _business_recheck_time(recheck, report, audit, approved)
        configured = len(recheck.checks)
        if terminal is not None and started > terminal:
            events.append(TimelineEvent(kind="recheck", at=finished))
            matched = recheck.checks.count("passed")
            if "failed" in recheck.checks:
                recheck_status = "failed"
            elif configured and matched == configured:
                recheck_status = "passed"
    elif recheck is not None:
        observed = _report_time(recheck, host_id, scope)
        _require(
            recheck.id != report.id and recheck.scenario == report.scenario and observed > approved
        )
        if terminal is not None:
            _require(observed > terminal)
            events.append(TimelineEvent(kind="recheck", at=observed))
            checks = recheck.target.health_checks if recheck.target is not None else []
            results = [_verified_http(recheck, check, terminal, observed) for check in checks]
            configured = len(results)
            matched = sum(value is True for value in results)
            if results and matched == configured:
                recheck_status = "passed"
            elif any(value is False for value in results):
                recheck_status = "failed"

    events.sort(key=lambda event: event.at)
    return HandoffTimeline(
        phase=cast(TimelinePhase, phase),
        authorization=authorization,
        native_accepted=native_accepted,
        activation_verified=activated_at is not None,
        recheck_after=terminal,
        events=events,
        recheck_status=recheck_status,
        configured_checks=configured,
        matched_checks=matched,
    )
