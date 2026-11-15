"""Authenticated, explicitly approved repair requests over deployment-owned SSH targets."""

import hashlib
import json
import logging
import re
import sqlite3
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import TYPE_CHECKING

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator

from opsark.automatic_store import AutomaticStore
from opsark.automation_store import AutomationStore, ModeChange
from opsark.baselines import scope_for
from opsark.control_modes import (
    ControlPolicy,
    PatchPlan,
    automatic_window_open,
    evaluate_automatic_plan,
)
from opsark.models import StrictModel
from opsark.patch_client import PatchClientError, PatchTarget, UnknownPatchResult, invoke
from opsark.patch_store import PatchStore

if TYPE_CHECKING:
    from opsark.mode_coordinator import ModeCoordinator

logger = logging.getLogger(__name__)
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")


class HostRequest(StrictModel):
    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$", strict=True)


class PrepareRequest(HostRequest):
    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)


class SubmitRequest(HostRequest):
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    expected_plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)
    confirm_execute: bool = Field(strict=True)
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)

    @field_validator("confirm_execute")
    @classmethod
    def confirmed(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("必须明确批准当前具体方案。")
        return value


class ModeSynchronizationError(RuntimeError):
    pass


def targets_scope(targets: dict[str, PatchTarget]) -> str | None:
    if not targets:
        return None
    context = {
        host_id: {
            "host_scope": scope_for(target.host.public),
            "policy_digest": target.policy_digest,
        }
        for host_id, target in sorted(targets.items())
    }
    return hashlib.sha256(
        json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class PatchService:
    def __init__(
        self, targets: dict[str, PatchTarget], store: PatchStore, automation: AutomationStore
    ):
        self.targets = dict(targets)
        self.store = store
        self.automation = automation
        self.mode_lock = Lock()
        self.mode_coordinator: ModeCoordinator | None = None
        self.invoker = invoke
        self.automatic_store: AutomaticStore | None = None
        self.automatic_ai_gate = None
        self.now = lambda: datetime.now(UTC)
        if targets:
            self.automation.mark_sync_pending(self.automation.status()["revision"])

    def target(self, host_id: str) -> PatchTarget:
        if host_id not in self.targets:
            raise HTTPException(status_code=404, detail="修复目标未登记。")
        return self.targets[host_id]

    @property
    def admission_lock(self):
        """Expose the mode admission lock for nonblocking dispatch checks."""
        if self.mode_coordinator is None:
            return self.mode_lock
        if self.mode_coordinator.mode_lock is self.mode_lock:
            raise ValueError("共享模式协调不得使用旧 RPC 执行锁。")
        return self.mode_coordinator.mode_lock

    def local_admission(self):
        """Serialize local authorization and intent commits with shared mode changes."""
        return nullcontext() if self.mode_coordinator is None else self.admission_lock

    def rpc(self, target: PatchTarget, op: str, *, timeout: float = 75, **fields) -> dict:
        result = self.invoker(
            target,
            {
                "schema_version": 1,
                "op": op,
                "policy_digest": target.policy_digest,
                **fields,
            },
            timeout=timeout,
        )
        if not isinstance(result, dict):
            raise PatchClientError("修复入口未返回可信对象。")
        if result.get("status") == "busy" or result.get("error") == "busy":
            raise HTTPException(status_code=409, detail="服务器正在处理其他操作，请稍后读取状态。")
        if result.get("ok") is False or result.get("error") and "job_id" not in result:
            raise HTTPException(
                status_code=409, detail="服务器拒绝了当前请求，请重新读取状态和方案。"
            )
        return result

    def synchronize_mode_targets(self, status: dict) -> None:
        """Confirm only this channel; the caller owns the global pending/ACK commit."""
        if not self.targets:
            return
        revision = status["revision"]
        grant = self.automation.policy.automatic
        preferred = list(grant.host_ids) if grant is not None else []
        automatic_hosts = preferred if grant is not None and grant.enabled else []
        selected = (
            automatic_hosts
            if status["mode"] == "automatic"
            else [*preferred, *(host for host in self.targets if host not in preferred)]
        )
        errors = []
        for host_id in selected:
            try:
                target = self.target(host_id)
                result = self.rpc(
                    target, "set_mode", timeout=15, mode=status["mode"], revision=revision
                )
                if (
                    result.get("mode") != status["mode"]
                    or type(result.get("revision")) is not int
                    or result["revision"] != revision
                ):
                    raise PatchClientError("服务器未确认当前模式版本。")
            except (PatchClientError, HTTPException, OSError, ValueError) as error:
                # Revocation must try every reachable target even when an earlier
                # physical host is offline. The local mode already stopped admission.
                errors.append(error)
        if errors:
            raise ModeSynchronizationError("模式同步未完成，已停止新修复任务。") from errors[0]

    def _sync_locked(self) -> dict:
        status = self.automation.status()
        if not self.targets:
            return status
        revision = status["revision"]
        self.automation.mark_sync_pending(revision)
        try:
            self.synchronize_mode_targets(status)
        except ModeSynchronizationError:
            self.automation.finish_sync(
                revision, "至少一台所需服务器未确认当前模式；停止提交新任务。"
            )
            raise
        self.automation.finish_sync(revision)
        return self.automation.status()

    def sync_mode(self) -> dict:
        if self.mode_coordinator is not None:
            if self.mode_coordinator.mode_lock is self.mode_lock:
                raise ValueError("共享模式协调不得使用旧 RPC 执行锁。")
            return self.mode_coordinator.sync_mode()
        with self.mode_lock:
            return self._sync_locked()

    def change_mode(self, body: ModeChange) -> dict:
        if self.mode_coordinator is not None:
            if self.mode_coordinator.mode_lock is self.mode_lock:
                raise ValueError("共享模式协调不得使用旧 RPC 执行锁。")
            return self.mode_coordinator.change_mode(body)
        with self.mode_lock:
            self.automation.change_mode(body)
            return self._sync_locked()

    def status(self) -> dict:
        mode = self.automation.status()
        supported = list(mode["supported_execution_modes"])
        grant = self.automation.policy.automatic
        auto_configured = bool(
            self.automatic_store is not None
            and grant
            and all(
                host in self.targets and self.targets[host].policy_digest == expected
                for host, expected in grant.target_policy_digests.items()
            )
        )
        if not auto_configured and "automatic" in supported:
            supported.remove("automatic")
        return {
            "configured": bool(self.targets),
            "hosts": [
                {
                    "host_id": host_id,
                    "name": target.host.public.name,
                    "scan": self.store.latest_scan(host_id),
                }
                for host_id, target in self.targets.items()
            ],
            "jobs": self.store.list_jobs(),
            "execution_available": mode["execution_available"]
            and (mode["mode"] != "automatic" or auto_configured),
            "supported_execution_modes": supported if self.targets else [],
            "detail": mode["detail"],
            "mode_sync_complete": mode["mode_sync_complete"],
        }

    def scan(self, body: HostRequest) -> dict:
        target = self.target(body.host_id)
        result = self.rpc(target, "scan")
        self.store.save_scan(body.host_id, result)
        return self.store.latest_scan(body.host_id) or result

    def _plan(self, host_id: str, plan: dict, mode: dict) -> None:
        target = self.target(host_id)
        if (
            type(plan.get("schema_version")) is not int
            or plan["schema_version"] != 1
            or plan.get("host_id") != host_id
            or plan.get("policy_digest") != target.policy_digest
            or type(plan.get("mode_revision")) is not int
            or plan.get("mode_revision") != mode["revision"]
            or plan.get("action") != "os_security_upgrade"
            or not isinstance(plan.get("plan_id"), str)
            or not _ID.fullmatch(plan["plan_id"])
            or not isinstance(plan.get("plan_digest"), str)
            or not _HEX.fullmatch(plan["plan_digest"])
        ):
            raise HTTPException(
                status_code=409, detail="远端方案与当前目标、策略或模式版本不一致。"
            )
        try:
            expiry = datetime.fromisoformat(plan["expires_at"])
            if expiry.tzinfo is None or expiry <= self.now():
                raise ValueError("Expired patch plan")
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(status_code=409, detail="方案已失效，请重新规划。") from error
        changes = plan.get("package_changes")
        if (
            not isinstance(changes, list)
            or len(changes) != 1
            or any(
                not isinstance(change, dict) or not isinstance(change.get("name"), str)
                for change in changes
            )
        ):
            raise HTTPException(
                status_code=409, detail="首批执行只支持经过核实的单个已安装包升级。"
            )

    def prepare(self, body: PrepareRequest) -> dict:
        target = self.target(body.host_id)
        mode = self.sync_mode()
        if mode["mode"] == "automatic":
            raise HTTPException(
                status_code=409, detail="自动模式由受控编排独立规划，请切换模式后手动预览。"
            )
        result = self.rpc(
            target, "prepare", finding_id=body.finding_id, mode_revision=mode["revision"]
        )
        current = self.automation.status()
        if current["revision"] != mode["revision"] or current["mode"] != mode["mode"]:
            raise HTTPException(status_code=409, detail="规划期间模式已变化，请重新规划。")
        self._plan(body.host_id, result, current)
        self.store.save_plan(body.host_id, result)
        return self.store.get_plan(body.host_id, result["plan_id"]) or result

    def _automatic_context(self, host_id, mode_revision, grant_digest, *, check_quota=True):
        target = self.target(host_id)
        mode = self.automation.status()
        policy = ControlPolicy.model_validate(self.automation.policy.model_dump())
        grant, at = policy.automatic, self.now()
        if (
            type(mode_revision) is not int
            or mode_revision < 0
            or mode["mode"] != "automatic"
            or mode["revision"] != mode_revision
            or mode.get("mode_sync_complete") is not True
        ):
            raise HTTPException(409, "自动模式、版本或同步状态已变化。")
        if (
            not policy.enabled
            or host_id not in policy.host_ids
            or "os_security_upgrade" not in policy.allowed_actions
            or grant is None
            or not grant.enabled
            or host_id not in grant.host_ids
            or not isinstance(grant_digest, str)
            or not _HEX.fullmatch(grant_digest)
            or grant.grant_digest != grant_digest
            or grant.target_policy_digests.get(host_id) != target.policy_digest
        ):
            raise HTTPException(403, "当前目标、动作或策略摘要没有匹配的明确自动预授权。")
        if not automatic_window_open(grant, at):
            raise HTTPException(409, "自动预授权已失效或不在 UTC 维护窗口。")
        if self.automatic_store is None:
            raise HTTPException(503, "自动提交的持久安全状态尚未配置。")
        if self.automatic_store.latch(host_id):
            raise HTTPException(409, "自动通道已持久暂停，必须先核实原任务与远端状态。")
        remote = self.automatic_store.remote_admission(
            host_id,
            self._automatic_scope(target),
            target.policy_digest,
            self._root_grant_digest(grant),
            now=at,
        )
        if remote is None:
            raise HTTPException(
                409, "远端自动授权、暂停或已用配额的缓存未能核实，请等待后台只读检查。"
            )
        usage = self.automatic_store.quotas(host_id, grant.grant_id, now=at)
        if not all(type(value) is int and value >= 0 for value in usage.values()):
            raise HTTPException(409, "自动任务已用配额尚未核实。")
        if check_quota and (
            max(usage["daily_used"], remote["usage"]["daily_used"]) >= grant.max_jobs_per_day
            or max(usage["total_used"], remote["usage"]["total_used"]) >= grant.max_total_jobs
        ):
            raise HTTPException(409, "自动任务配额已耗尽。")
        usage.update(
            root_daily_used=remote["usage"]["daily_used"],
            root_total_used=remote["usage"]["total_used"],
        )
        return target, mode, policy, grant, usage

    @staticmethod
    def _automatic_scope(target, *, execution_policy=None):
        return hashlib.sha256(
            json.dumps(
                {
                    "channel": "automatic-patch/v1",
                    "host_scope": scope_for(target.host.public),
                    "policy_digest": target.policy_digest
                    if execution_policy is None
                    else execution_policy,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def refresh_automatic_status(self, host_id):
        """Called by the background monitor only; HTTP GETs read this cached result."""
        target = self.target(host_id)
        grant = self.automation.policy.automatic
        if grant is None or host_id not in grant.host_ids or self.automatic_store is None:
            raise HTTPException(403, "远端自动状态检查只能使用明确登记的自动预授权目标。")
        scope = self._automatic_scope(target)
        try:
            result = self.rpc(target, "automatic_status", timeout=15)
            return self.automatic_store.record_remote_safety(
                host_id,
                scope,
                target.policy_digest,
                result,
                now=self.now(),
            )
        except (PatchClientError, HTTPException, OSError, TypeError, ValueError):
            return self.automatic_store.mark_remote_unavailable(
                host_id,
                scope,
                target.policy_digest,
                now=self.now(),
            )

    @staticmethod
    def _root_grant_digest(grant):
        # Remote grants omit controller-only host bindings. Exact JSON timestamps
        # and field values must match; a domain or local grant digest is different.
        projection = grant.model_dump(
            mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
        )
        return hashlib.sha256(
            json.dumps(
                projection, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()

    def _automatic_scan(self, host_id, finding_id, grant):
        scan = self.store.latest_scan(host_id)
        if not isinstance(scan, dict):
            raise HTTPException(409, "缺少新鲜且完整的扫描证据。")
        try:
            collected = datetime.fromisoformat(scan["collected_at"])
            fresh = collected.tzinfo is not None and (
                0 <= (self.now() - collected).total_seconds() <= 900
            )
        except (KeyError, TypeError, ValueError):
            fresh = False
        if (
            not fresh
            or type(scan.get("schema_version")) is not int
            or scan["schema_version"] != 1
            or scan.get("host_id") != host_id
            or scan.get("policy_digest") != self.target(host_id).policy_digest
            or not isinstance(scan.get("scan_id"), str)
            or not _ID.fullmatch(scan["scan_id"])
            or not isinstance(scan.get("apt_state_digest"), str)
            or not _HEX.fullmatch(scan["apt_state_digest"])
            or scan.get("apt_configuration_safe") is not True
            or not isinstance(scan.get("coverage"), dict)
            or scan["coverage"].get("status") not in {"complete", "partial"}
            or not isinstance(scan.get("findings"), list)
            or not isinstance(scan.get("packages"), list)
        ):
            raise HTTPException(409, "扫描范围、时效、目标或 APT 状态未核实。")
        findings = [
            item
            for item in scan["findings"]
            if isinstance(item, dict) and item.get("finding_id") == finding_id
        ]
        if len(findings) != 1:
            raise HTTPException(409, "漏洞证据缺失或身份不唯一。")
        finding = findings[0]
        if (
            finding.get("package") not in grant.allowed_packages
            or finding.get("advisory") not in grant.allowed_advisories
            or not all(
                finding.get(key) is True
                for key in (
                    "affected",
                    "candidate_fixable",
                    "vendor_evidence_fresh",
                    "finding_evidence_complete",
                )
            )
            or not isinstance(finding.get("vendor_record_digest"), str)
            or not _HEX.fullmatch(finding["vendor_record_digest"])
            or not isinstance(finding.get("evidence_urls"), list)
            or "https://ubuntu.com/security/notices/" + finding["advisory"]
            not in finding["evidence_urls"]
        ):
            raise HTTPException(403, "缺少允许范围内的明确供应商受影响及可修复证据。")
        packages = [
            item
            for item in scan["packages"]
            if isinstance(item, dict)
            and item.get("name") == finding["package"]
            and item.get("architecture") == finding.get("architecture")
        ]
        if len(packages) != 1 or packages[0].get("installed_version") != finding.get(
            "current_version"
        ):
            raise HTTPException(409, "扫描中的已安装包身份与漏洞证据不一致。")
        return scan, finding, packages[0]

    def _automatic_plan(self, host_id, plan, context, *, finding_id, scan_id, usage=None):
        target, mode, policy, grant, counters = context
        if not isinstance(plan, dict):
            raise HTTPException(409, "自动方案不是可信的远端对象。")
        self._plan(host_id, plan, mode)
        scan, finding, package = self._automatic_scan(host_id, finding_id, grant)
        try:
            created, expiry = (
                datetime.fromisoformat(plan[key]) for key in ("created_at", "expires_at")
            )
            full_content = {
                key: value
                for key, value in plan.items()
                if key not in {"plan_digest", "received_at"}
            }
            full_digest = hashlib.sha256(
                json.dumps(
                    full_content,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            if (
                created.tzinfo is None
                or expiry.tzinfo is None
                or not 0 <= (self.now() - created).total_seconds() <= 900
                or not timedelta(0) < expiry - created <= timedelta(minutes=30)
                or full_digest != plan["plan_digest"]
                or plan.get("prepared_mode") != "automatic"
                or plan.get("automatic_grant_id") != grant.grant_id
                or plan.get("automatic_grant_digest") != self._root_grant_digest(grant)
                or scan["scan_id"] != scan_id
                or plan.get("state_digest") != scan["apt_state_digest"]
                or not isinstance(plan.get("finding"), dict)
                or any(
                    plan["finding"].get(key) != finding.get(key)
                    for key in (
                        "finding_id",
                        "advisory",
                        "cve",
                        "package",
                        "architecture",
                        "current_version",
                        "fixed_binary_version",
                        "vendor_record_digest",
                        "affected",
                        "candidate_fixable",
                        "vendor_evidence_fresh",
                        "finding_evidence_complete",
                    )
                )
                or not isinstance(plan.get("health_before"), dict)
                or plan["health_before"].get("passed") is not True
                or plan.get("restart_assessment") not in {"none", "possible", "required"}
                or plan.get("requires_reboot") is not False
                or type(plan.get("requires_service_restart")) is not bool
                or not all(
                    plan.get(key) is True
                    for key in (
                        "evidence_complete",
                        "transaction_complete_verified",
                        "restart_impact_verified",
                    )
                )
            ):
                raise ValueError("Automatic full-plan bindings changed")
            change = plan["package_changes"][0]
            if (
                change.get("name") != finding["package"]
                or change.get("architecture") != finding.get("architecture")
                or change.get("current_version") != finding.get("current_version")
                or change.get("candidate_version") != package.get("candidate_version")
                or change.get("fixed_version") != finding.get("fixed_binary_version")
                or not isinstance(change.get("sha256"), str)
                or not _HEX.fullmatch(change["sha256"])
                or policy.automatic_ai is not None
                and policy.automatic_ai.enabled
                and change["sha256"] != package.get("candidate_sha256")
            ):
                raise ValueError("Automatic package identity changed")
            projected = PatchPlan.model_validate(
                {
                    "host_id": host_id,
                    "action": plan["action"],
                    "package_changes": [
                        {
                            key: change[key]
                            for key in (
                                "name",
                                "current_version",
                                "candidate_version",
                                "fixed_version",
                                "vendor_security_origin_verified",
                                "candidate_contains_fixed_verified",
                                "candidate_is_upgrade_verified",
                                "current_is_affected_verified",
                            )
                            if key in change
                        }
                    ],
                    **{
                        key: plan[key]
                        for key in (
                            "state_digest",
                            "expires_at",
                            "requires_reboot",
                            "requires_service_restart",
                            "evidence_complete",
                            "transaction_complete_verified",
                            "restart_impact_verified",
                            "risk_level",
                        )
                        if key in plan
                    },
                }
            )
            used = usage if usage is not None else counters
            decision = evaluate_automatic_plan(
                policy,
                projected,
                advisory_id=finding["advisory"],
                current_policy_digest=target.policy_digest,
                jobs_today=max(used["daily_used"], counters["root_daily_used"]),
                total_jobs=max(used["total_used"], counters["root_total_used"]),
                latch_paused=False,
                now=self.now(),
            )
            if not decision.executable:
                raise ValueError("Automatic policy decision is blocked")
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(409, "自动方案、完整证据、预授权或剩余配额校验未通过。") from error

    def _automatic_ai_admission(self, host_id, finding_id, scan, context, candidate=None):
        """AI-required deployments cannot reach native actions via a legacy caller."""
        policy = context[2]
        if policy.automatic_ai is None or not policy.automatic_ai.enabled:
            return
        if self.automatic_store is None or self.automatic_ai_gate is None:
            raise HTTPException(503, "自动 AI 证据入口不可用，停止新的修复。")
        if candidate is None:
            from opsark.automatic_store import candidate_identity

            finding = next(f for f in scan["findings"] if f["finding_id"] == finding_id)
            package = next(
                p
                for p in scan["packages"]
                if p["name"] == finding["package"] and p["architecture"] == finding["architecture"]
            )
            candidate = self.automatic_store.get(
                candidate_identity(
                    host_id,
                    self._automatic_scope(context[0]),
                    finding_id,
                    finding["current_version"],
                    package["candidate_version"],
                )
            )
        if (
            not isinstance(candidate, dict)
            or candidate.get("state") not in {"planning", "submission_intent"}
            or candidate.get("host_id") != host_id
            or candidate.get("finding_id") != finding_id
            or candidate.get("scan_id") != scan["scan_id"]
            or not self.automatic_ai_gate.validate_proof(
                candidate, scan, policy, context[1], candidate.get("ai_proof")
            )
        ):
            raise HTTPException(409, "缺少当前候选已持久核验的 AI 提案，停止新的修复。")

    def auto_prepare(self, host_id, finding_id, expected_mode_revision, grant_digest):
        body = PrepareRequest(host_id=host_id, finding_id=finding_id)
        with self.mode_lock, self.local_admission():
            context = self._automatic_context(host_id, expected_mode_revision, grant_digest)
            scan, _finding, _package = self._automatic_scan(host_id, finding_id, context[3])
            self._automatic_ai_admission(host_id, finding_id, scan, context)
        # Planning cannot install. Releasing the mode lock lets a manual stop take
        # effect immediately; the immutable result is rechecked after the RPC.
        result = self.rpc(
            context[0], "prepare", finding_id=body.finding_id, mode_revision=expected_mode_revision
        )
        with self.mode_lock, self.local_admission():
            current = self._automatic_context(host_id, expected_mode_revision, grant_digest)
            current_scan, _, _ = self._automatic_scan(host_id, finding_id, current[3])
            self._automatic_ai_admission(host_id, finding_id, current_scan, current)
            self._automatic_plan(
                host_id, result, current, finding_id=finding_id, scan_id=scan["scan_id"]
            )
            self.store.save_plan(host_id, result)
        return self.store.get_plan(host_id, result["plan_id"]) or result

    def _auto_outcome(self, candidate_id, result):
        if self.automatic_store is None:
            raise ValueError("Automatic ledger disappeared")
        self.automatic_store.record_result(candidate_id, result, now=self.now())
        self.notify(result)
        return result

    def _read_automatic_original(self, host_id, job_id, plan_id):
        try:
            return self.job_status(host_id, job_id)
        except (PatchClientError, HTTPException, OSError, ValueError):
            # A readback failure says nothing about the original submit
            # transport. Keep its existing unknown placeholder if present.
            existing = self.store.get_job(host_id, job_id)
            if (
                existing is not None
                and existing.get("plan_id") == plan_id
                and existing["status"] == "unknown"
            ):
                return existing
            raise

    def auto_submit(self, host_id, plan_id, plan_digest, mode_revision, grant_digest, job_id):
        HostRequest(host_id=host_id)
        for value, pattern in ((plan_id, _ID), (plan_digest, _HEX), (job_id, _ID)):
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise HTTPException(409, "自动任务标识或方案摘要无效。")
        target = self.target(host_id)
        with self.mode_lock:
            existing = self.store.get_job(host_id, job_id)
            if existing is not None:
                if existing.get("plan_id") != plan_id or existing.get("plan_digest") != plan_digest:
                    raise HTTPException(409, "原任务 ID 已绑定其他方案。")
                # This branch is read-only, including after manual mode revoked
                # execution. It never registers or resends a submission.
                return self._read_automatic_original(host_id, job_id, plan_id)
            with self.local_admission():
                context = self._automatic_context(
                    host_id, mode_revision, grant_digest, check_quota=False
                )
                if self.automatic_store is None:
                    raise HTTPException(503, "自动安全状态尚未配置。")
                try:
                    authority = self.automatic_store.authorize_intent(
                        host_id,
                        job_id,
                        plan_id,
                        plan_digest,
                        mode_revision,
                        context[3].grant_id,
                        grant_digest,
                        now=self.now(),
                    )
                except ValueError as error:
                    raise HTTPException(409, "缺少绑定当前任务的持久自动提交意图。") from error
                candidate = authority["candidate"]
                current_scan, _, _ = self._automatic_scan(
                    host_id, candidate["finding_id"], context[3]
                )
                self._automatic_ai_admission(
                    host_id, candidate["finding_id"], current_scan, context, candidate
                )
                scope = self._automatic_scope(target)
                plan = self.store.get_plan(host_id, plan_id)
                if (
                    plan is None
                    or plan.get("plan_digest") != plan_digest
                    or candidate["scope_hash"] != scope
                ):
                    raise HTTPException(409, "自动任务与当前目标范围或方案不一致。")
                self._automatic_plan(
                    host_id,
                    plan,
                    context,
                    finding_id=candidate["finding_id"],
                    scan_id=candidate["scan_id"],
                    usage={
                        "daily_used": authority["daily_used_before"],
                        "total_used": authority["total_used_before"],
                    },
                )
                change = plan["package_changes"][0]
                if any(
                    candidate[key] != change[field]
                    for key, field in (
                        ("package", "name"),
                        ("current_version", "current_version"),
                        ("candidate_version", "candidate_version"),
                    )
                ):
                    raise HTTPException(409, "持久自动意图中的软件包变化已改变。")
                first = self.store.register_submission(
                    host_id,
                    job_id,
                    plan_id,
                    plan_digest,
                    mode_revision,
                    host_scope=scope_for(target.host.public),
                    policy_digest=target.policy_digest,
                    authorization="automatic",
                )
            if not first:
                return self._read_automatic_original(host_id, job_id, plan_id)

            host_scope = scope_for(target.host.public)

            def unconfirmed_submit():
                return self.store.mark_unknown(
                    host_id,
                    job_id,
                    plan_id,
                    automatic_status_binding=(
                        host_scope,
                        target.policy_digest,
                        context[3].grant_id,
                        self._root_grant_digest(context[3]),
                    ),
                )

            def checked_outcome(saved):
                # The ledger can return a cached higher revision in preference
                # to the incoming acknowledgment. Validate that selected row.
                local_unknown = (
                    saved["status"] == "unknown" and saved.get("transport_unknown") is True
                )
                local_rejection = (
                    saved["status"] == "rejected" and saved.get("remote_job_created") is False
                )
                if not (local_unknown or local_rejection):
                    self._check_automatic_status(target, host_scope, candidate, saved)
                return self._auto_outcome(candidate["id"], saved)

            try:
                result = self.rpc(
                    target,
                    "submit",
                    timeout=15,
                    job_id=job_id,
                    plan_id=plan_id,
                    plan_digest=plan_digest,
                    mode_revision=mode_revision,
                )
            except HTTPException:
                rejected = self.store.save_job(
                    host_id,
                    {
                        "job_id": job_id,
                        "plan_id": plan_id,
                        "plan_digest": plan_digest,
                        "mode_revision": mode_revision,
                        "status": "rejected",
                        "authorization": "automatic",
                        "remote_job_created": False,
                        "detail": "远端明确拒绝提交；停止新的自动动作。",
                    },
                )
                return checked_outcome(rejected)
            except (PatchClientError, OSError, ValueError):
                return checked_outcome(unconfirmed_submit())
            expected = {
                "host_id": host_id,
                "job_id": job_id,
                "plan_id": plan_id,
                "plan_digest": plan_digest,
                "policy_digest": target.policy_digest,
                "mode_revision": mode_revision,
                "authorization": "automatic",
                "automatic_grant_id": context[3].grant_id,
                "automatic_grant_digest": self._root_grant_digest(context[3]),
            }
            if (
                type(result.get("schema_version")) is not int
                or result["schema_version"] != 1
                or type(result.get("mode_revision")) is not int
                or any(result.get(key) != value for key, value in expected.items())
                or result.get("execution_policy_digest", target.policy_digest)
                != target.policy_digest
            ):
                return checked_outcome(unconfirmed_submit())
            try:
                saved = self.store.save_job(host_id, result)
            except ValueError:
                saved = unconfirmed_submit()
            return checked_outcome(saved)

    def _authorized_plan(self, body: SubmitRequest, mode: dict) -> dict:
        if mode["mode"] != "assisted":
            raise HTTPException(
                status_code=409, detail="本轮只开放半自动批准执行；当前模式不能提交修复。"
            )
        if mode["revision"] != body.expected_mode_revision or not mode["mode_sync_complete"]:
            raise HTTPException(status_code=409, detail="模式或同步状态已变化，请重新读取并批准。")
        policy = ControlPolicy.model_validate(self.automation.policy.model_dump())
        if (
            not policy.enabled
            or body.host_id not in policy.host_ids
            or "os_security_upgrade" not in policy.allowed_actions
        ):
            raise HTTPException(status_code=403, detail="当前部署策略未授权该目标或动作。")
        plan = self.store.get_plan(body.host_id, body.plan_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="修复方案不存在，请先生成方案。")
        self._plan(body.host_id, plan, mode)
        if plan["plan_digest"] != body.expected_plan_digest:
            raise HTTPException(status_code=409, detail="批准摘要与当前方案不一致。")
        changes = plan["package_changes"]
        if len(changes) > policy.max_packages_per_job or any(
            change["name"] not in policy.allowed_packages for change in changes
        ):
            raise HTTPException(status_code=403, detail="完整软件包变化集合超出部署授权。")
        if (
            type(plan.get("requires_reboot")) is not bool
            or type(plan.get("requires_service_restart")) is not bool
            or plan.get("restart_assessment") not in {"none", "possible", "required"}
            or plan["requires_reboot"]
            and not policy.allow_reboot
            or plan["requires_service_restart"]
            and not policy.allow_service_restart
        ):
            raise HTTPException(status_code=403, detail="重启影响未核实或超出部署授权。")
        return plan

    def submit(self, body: SubmitRequest) -> dict | JSONResponse:
        target = self.target(body.host_id)
        with self.mode_lock:
            with self.local_admission():
                mode = self.automation.status()
                self._authorized_plan(body, mode)
                first = self.store.register_submission(
                    body.host_id,
                    body.job_id,
                    body.plan_id,
                    body.expected_plan_digest,
                    body.expected_mode_revision,
                    host_scope=scope_for(target.host.public),
                    policy_digest=target.policy_digest,
                    authorization="assisted",
                )
            if not first:
                return JSONResponse(self.store.get_job(body.host_id, body.job_id), status_code=202)
            try:
                result = self.rpc(
                    target,
                    "submit",
                    timeout=15,
                    job_id=body.job_id,
                    plan_id=body.plan_id,
                    plan_digest=body.expected_plan_digest,
                    mode_revision=body.expected_mode_revision,
                )
            except UnknownPatchResult:
                unknown = self.store.mark_unknown(body.host_id, body.job_id, body.plan_id)
                self.notify(unknown)
                return JSONResponse(unknown, status_code=202)
            except HTTPException as error:
                rejected = self.store.save_job(
                    body.host_id,
                    {
                        "job_id": body.job_id,
                        "plan_id": body.plan_id,
                        "plan_digest": body.expected_plan_digest,
                        "mode_revision": body.expected_mode_revision,
                        "status": "rejected",
                        "source": "remote_rpc_rejection",
                        "remote_job_created": False,
                        "detail": "远端明确拒绝了提交或正忙；未确认创建安装任务，请重新读取状态。",
                    },
                )
                self.notify(rejected)
                return JSONResponse(rejected, status_code=error.status_code)
            if result.get("job_id") != body.job_id or result.get("plan_id") != body.plan_id:
                unknown = self.store.mark_unknown(body.host_id, body.job_id, body.plan_id)
                self.notify(unknown)
                return JSONResponse(unknown, status_code=202)
            saved = self.store.save_job(body.host_id, result)
            self.notify(saved)
            return saved

    def job_status(self, host_id: str, job_id: str) -> dict:
        target = self.target(host_id)
        if not _ID.fullmatch(job_id):
            raise HTTPException(status_code=404, detail="任务标识无效。")
        result = self.rpc(target, "status", timeout=15, job_id=job_id)
        if result.get("job_id") != job_id:
            raise PatchClientError("任务响应与请求不一致。")
        candidate = (
            self.automatic_store.get_by_job(host_id, job_id)
            if self.automatic_store is not None
            else None
        )
        host_scope = scope_for(target.host.public)
        if candidate is not None and candidate.get("submitted_day") is not None:
            self._check_automatic_status(target, host_scope, candidate, result)
            if result.get("policy_digest") != target.policy_digest:
                raise PatchClientError("原自动任务的当前策略未能核实。")
        saved = self.store.save_job(
            host_id,
            result,
            from_status=True,
            current_host_scope=host_scope,
            current_policy_digest=target.policy_digest,
        )
        if (
            self.automatic_store is not None
            and candidate is not None
            and candidate.get("submitted_day") is not None
        ):
            self._check_automatic_status(target, host_scope, candidate, saved)
            try:
                self.automatic_store.record_result(
                    candidate["id"], saved, now=self.now(), from_status=True
                )
            except ValueError as error:
                self.automatic_store.mark_unknown(candidate["id"], now=self.now(), from_status=True)
                raise PatchClientError("原自动任务的响应绑定未能核实。") from error
        self.notify(saved)
        return saved

    def _check_automatic_status(self, target, host_scope, candidate, result):
        audit = self.store.get_handoff_audit(candidate["host_id"], candidate["job_id"])
        execution_policy = result.get("execution_policy_digest", result.get("policy_digest"))
        original_grant_digest = candidate.get("root_grant_digest")
        if original_grant_digest is None:
            plan = self.store.get_plan(candidate["host_id"], candidate["plan_id"])
            if plan is not None and all(
                plan.get(key) == candidate[key]
                for key in ("host_id", "plan_id", "plan_digest", "mode_revision")
            ):
                original_grant_digest = plan.get("automatic_grant_digest")
        if (
            result.get("host_id") != candidate["host_id"]
            or result.get("job_id") != candidate["job_id"]
            or any(result.get(key) != candidate[key] for key in ("plan_id", "plan_digest"))
            or type(result.get("mode_revision")) is not int
            or result["mode_revision"] != candidate["mode_revision"]
            or result.get("authorization") != "automatic"
            or not isinstance(result.get("policy_digest"), str)
            or not _HEX.fullmatch(result["policy_digest"])
            or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or type(result.get("revision")) is not int
            or result["revision"] < 1
            or result.get("automatic_grant_id") != candidate["grant_id"]
            or not isinstance(original_grant_digest, str)
            or not _HEX.fullmatch(original_grant_digest)
            or result.get("automatic_grant_digest") != original_grant_digest
            or not isinstance(execution_policy, str)
            or not _HEX.fullmatch(execution_policy)
            or candidate["scope_hash"]
            != self._automatic_scope(target, execution_policy=execution_policy)
            or (
                audit is not None
                and (
                    (host_scope, execution_policy) != (audit["host_scope"], audit["policy_digest"])
                    or audit["authorization"] != "automatic"
                    or any(
                        audit[key] != candidate[key]
                        for key in ("plan_id", "plan_digest", "mode_revision")
                    )
                )
            )
        ):
            raise PatchClientError("原自动任务的响应绑定未能核实。")

    def checked_cached_automatic_job(self, candidate):
        host_id, job_id = candidate["host_id"], candidate["job_id"]
        cached = self.store.get_job(host_id, job_id)
        if cached is None or cached.get("status") == "unknown":
            return None
        target = self.target(host_id)
        try:
            self._check_automatic_status(target, scope_for(target.host.public), candidate, cached)
        except PatchClientError:
            # A row from an older controller can remain visible in history. It
            # must pass current binding before influencing automatic recovery.
            return None
        return cached

    @staticmethod
    def notify(job: dict) -> None:
        if job.get("notification_due"):
            logger.warning(
                "Patch job state changed: host=%s job=%s status=%s",
                job["host_id"],
                job["job_id"],
                job["status"],
            )


def register_patch_routes(application: FastAPI, service: PatchService, protected: list) -> None:
    router = APIRouter(prefix="/api/remediation", dependencies=protected)

    def guarded(action):
        try:
            return action()
        except ModeSynchronizationError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except PatchClientError as error:
            raise HTTPException(
                status_code=503, detail="未取得可信远端结果，请查询原任务或稍后读取。"
            ) from error
        except (sqlite3.Error, ValueError, OSError) as error:
            raise HTTPException(status_code=503, detail="修复证据存储或校验暂时不可用。") from error

    @router.get("")
    def status():
        return guarded(service.status)

    @router.post("/scans")
    def scan(body: HostRequest):
        return guarded(lambda: service.scan(body))

    @router.post("/plans")
    def prepare(body: PrepareRequest):
        return guarded(lambda: service.prepare(body))

    @router.post("/jobs")
    def submit(body: SubmitRequest):
        return guarded(lambda: service.submit(body))

    @router.get("/jobs/{host_id}/{job_id}")
    def job(host_id: str, job_id: str):
        return guarded(lambda: service.job_status(host_id, job_id))

    application.include_router(router)
