"""Explicit pause reconciliation backed by a separate verified service activation."""

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import replace
from datetime import timedelta

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import Field, field_validator

from opsark.activation_api import ActivationService
from opsark.activation_recovery_store import ActivationRecoveryStore, verified_facts
from opsark.automatic_store import digest, instant
from opsark.control_modes import ControlPolicy
from opsark.models import StrictModel
from opsark.patch_api import PatchService
from opsark.patch_client import PatchClientError
from opsark.recovery_api import _checks, _hex, _safety, _time

HOST = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"
ID = re.compile(r"[0-9a-f]{32}\Z")
CACHE = {"received_at", "notification_due", "notification_count", "last_notified_at"}
ANCHORS = frozenset(
    {
        "activation_id",
        "activation_revision",
        "activation_digest",
        "activation_record_digest",
        "activation_raw_sha256",
        "original_job_sha256",
        "original_plan_sha256",
        "runtime_manifest_sha256",
        "activation_plan_sha256",
        "restart_intent_sha256",
        "root_safety_raw_sha256",
        "ledger_digest",
    }
)
IDENTITY = frozenset(
    {
        "schema_version",
        "kind",
        "host_id",
        "policy_digest",
        "driver_source_digest",
        "recovery_id",
        "job_id",
        "job_revision",
        "job_digest",
        "mode_revision",
        "context_digest",
        "created_at",
        "expires_at",
    }
)
PLAN_FIELDS = (
    IDENTITY
    | ANCHORS
    | {
        "status",
        "recovery_digest",
        "eligible",
        "checks",
        "blockers",
        "verification",
        "state_digest",
        "root_safety_before",
        "root_safety_digest",
        "root_safety_before_raw",
        "root_usage_before",
        "transport_challenge",
    }
)
RECEIPT_FIELDS = (
    IDENTITY
    | ANCHORS
    | {
        "status",
        "recovery_digest",
        "receipt_digest",
        "completed_at",
        "plan",
        "checks",
        "blockers",
        "verification",
        "resolved_job",
        "verified_activation",
        "resolved_safety_digest",
        "safety_before",
        "safety_after",
        "safety_after_digest",
        "root_usage_before",
        "root_usage_after",
    }
)
REQUIRED_CHECKS = frozenset(
    {
        "original_automatic_pending",
        "original_plan_intact",
        "verified_activation",
        "exact_root_pause",
        "ledger_settled",
        "exact_package_version",
        "apt_configuration_safe",
        "registered_health",
        "no_reboot_pending",
        "runtime_complete",
        "activation_process_current",
        "vendor_rescan",
        "final_package_state",
    }
)
FINAL_CHECKS = frozenset(
    {
        "prepared_eligible",
        "plan_valid",
        "job_unchanged",
        "activation_unchanged",
        "state_unchanged",
        "final_package_state",
        "final_ledger_settled",
        "policy_unchanged",
        "pause_unchanged",
        "usage_unchanged",
        "fresh_ssh",
    }
)


class ActivationRecoveryPrepareRequest(StrictModel):
    host_id: str = Field(pattern=HOST, strict=True)
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    activation_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)


class ActivationRecoverySubmitRequest(StrictModel):
    host_id: str = Field(pattern=HOST, strict=True)
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    expected_recovery_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)
    confirm_recover: bool = Field(strict=True)

    @field_validator("confirm_recover")
    @classmethod
    def confirmed(cls, value):
        if value is not True:
            raise ValueError("必须明确批准本次独立恢复；不能沿用激活批准。")
        return value


class RootActivationRecoveryRejected(ValueError):
    """Definite native refusal; never a permission to retry an uncertain submit."""


def _raw_job(job):
    return {key: value for key, value in job.items() if key not in CACHE}


def _usage(remote):
    if remote.get("grant") is None:
        return None
    return {
        "grant_id": remote["grant"]["grant_id"],
        "grant_digest": remote["grant_digest"],
        "usage": remote["usage"],
    }


def _raw_safety(raw):
    if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= 8192:
        raise ValueError("Original root pause raw bytes are unavailable")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate root pause field")
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    _safety(value)
    return value, hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ActivationRecoveryService:
    def __init__(
        self,
        service: PatchService,
        activation_service: ActivationService,
        store: ActivationRecoveryStore | None = None,
    ):
        self.service, self.activation_service = service, activation_service
        if service.automatic_store is None:
            raise ValueError("Activation recovery requires existing automatic safety storage")
        self.automatic = service.automatic_store
        self.store = store or ActivationRecoveryStore(self.automatic.path, automatic=self.automatic)
        if self.store.path != self.automatic.path:
            raise ValueError("Activation recovery must share the automatic database")

    def _context(self, host_id, revision=None):
        target = self.service.target(host_id)
        mode = self.service.automation.status()
        policy = ControlPolicy.model_validate(self.service.automation.policy.model_dump())
        configured = policy.service_activation
        if (
            mode.get("mode") != "manual"
            or mode.get("mode_sync_complete") is not True
            or type(mode.get("revision")) is not int
            or revision is not None
            and mode["revision"] != revision
        ):
            raise HTTPException(409, "独立恢复要求已同步的当前手动模式及修订。")
        if (
            not policy.enabled
            or "os_security_upgrade" not in policy.allowed_actions
            or host_id not in policy.host_ids
            or configured is None
            or not configured.enabled
            or host_id not in configured.host_ids
        ):
            raise HTTPException(403, "当前目标没有明确登记的激活后恢复范围。")
        return (
            target,
            mode,
            self.service._automatic_scope(target),
            digest(policy.model_dump(mode="json")),
            configured,
        )

    def _root(self, target, operation, **fields):
        result = self.service.invoker(
            target,
            {"schema_version": 1, "op": operation, "policy_digest": target.policy_digest, **fields},
            timeout=75,
        )
        if not isinstance(result, dict):
            raise PatchClientError("独立恢复入口未返回可信对象。")
        if result.get("error") == "rejected":
            raise RootActivationRecoveryRejected("远端明确拒绝本次恢复。")
        if result.get("ok") is False or result.get("error") or result.get("status") == "busy":
            raise PatchClientError("独立恢复入口尚未给出可核实结果。")
        if (
            type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or result.get("host_id") != target.host.public.id
            or result.get("policy_digest") != target.policy_digest
        ):
            raise PatchClientError("恢复回执与当前目标或策略不符。")
        return result

    def _originals(self, target, job_id, activation_id, configured):
        # Cached immutable install/activation evidence is read without refreshing
        # an old terminal native job after helper-source upgrades.
        job = self.service.store.get_job(target.host.public.id, job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_id") != job_id
            or job.get("host_id") != target.host.public.id
            or job.get("authorization") != "automatic"
            or job.get("status") != "installed_restart_pending"
            or type(job.get("revision")) is not int
            or job["revision"] < 1
            or type(job.get("install_exit_code")) is not int
            or job["install_exit_code"] != 0
            or job.get("verification", {}).get("fresh_ssh", {}).get("passed") is not True
        ):
            raise HTTPException(409, "只允许核对原自动安装后待激活任务；不能改写其状态。")
        activation = self.activation_service.store.get(target.host.public.id, activation_id)
        if activation is None:
            raise HTTPException(409, "原服务激活回执缺失，不能建立恢复批准。")
        self.activation_service.validate_cached(activation)
        historical_target = replace(target, policy_digest=activation["policy_digest"])
        raw = _raw_job(job)
        result = activation.get("result")
        if (
            activation["status"] != "verified"
            or not isinstance(result, dict)
            or result.get("status") != "verified"
            or activation["job_id"] != job_id
            or activation["job_revision"] != job["revision"]
            or activation["job_digest"] != digest(raw)
            or activation["original_job"] != raw
            or activation["scope_hash"] != self.service._automatic_scope(historical_target)
            or activation["plan"]["package"] not in configured.allowed_packages
            or activation["plan"]["unit"] not in configured.allowed_units
            or activation["plan"]["unit"] == "dbus.service"
            and "dbus.service" not in configured.allow_critical_units
        ):
            raise HTTPException(409, "原安装与激活的目标、摘要或当前明确范围不一致。")
        return raw, activation

    def _no_pending(self, host_id, *, except_recovery=None):
        if any(job["host_id"] == host_id for job in self.service.store.pollable_jobs()):
            raise HTTPException(409, "该目标仍有活动或未知安装任务，不能恢复。")
        if self.activation_service.store.pending(host_id):
            raise HTTPException(409, "该目标仍有激活结果待核实，不能恢复。")
        legacy = self.automatic.pending_recovery(host_id)
        if legacy is not None:
            raise HTTPException(409, "已有原恢复结果待核实，请先查询该原 ID。")
        pending = self.store.pending(host_id)
        if pending is not None and pending["recovery_id"] != except_recovery:
            raise HTTPException(409, "已有激活后恢复结果待核实，只能查询原 ID。")

    def _latch(self, host_id, job_id):
        latch = self.automatic.latch(host_id)
        if latch is None or latch.get("job_id") != job_id:
            raise HTTPException(409, "只允许恢复当前实际暂停所绑定的原任务。")
        return latch

    @staticmethod
    def _expected_anchors(job, activation):
        result = activation["result"]
        plan = activation["plan"]
        return {
            "activation_id": activation["activation_id"],
            "activation_revision": result["revision"],
            "activation_digest": activation["activation_digest"],
            "activation_record_digest": result["record_digest"],
            "activation_raw_sha256": digest(result),
            "original_job_sha256": plan["original_job_sha256"],
            "original_plan_sha256": plan["original_plan_sha256"],
            "runtime_manifest_sha256": plan["runtime_manifest_sha256"],
            "activation_plan_sha256": digest(plan),
            "restart_intent_sha256": digest(result["restart_evidence"]["intent"]),
            "root_safety_raw_sha256": plan["original_safety_digest"],
        }

    def _plan(self, plan, target, mode, context, job, activation, latch, remote_before=None):
        try:
            now = instant(self.service.now())
            created = _time(plan["created_at"])
            expiry = _time(plan["expires_at"])
            blockers = _checks(plan["checks"])
            safety, raw_hash = _raw_safety(plan["root_safety_before_raw"])
            expected = self._expected_anchors(job, activation)
            if (
                set(plan) != PLAN_FIELDS
                or type(plan.get("schema_version")) is not int
                or plan["schema_version"] != 1
                or plan["kind"] != "activation_recovery"
                or plan["status"] != "activation_recovery_prepared"
                or not _hex(plan["recovery_id"], ID)
                or plan["recovery_digest"]
                != digest({k: v for k, v in plan.items() if k != "recovery_digest"})
                or plan["host_id"] != target.host.public.id
                or plan["policy_digest"] != target.policy_digest
                or not _hex(plan["driver_source_digest"])
                or plan["context_digest"] != context
                or plan["job_id"] != job["job_id"]
                or type(plan["job_revision"]) is not int
                or plan["job_revision"] != job["revision"]
                or plan["job_digest"] != digest(job)
                or type(plan["mode_revision"]) is not int
                or plan["mode_revision"] != mode["revision"]
                or any(plan[key] != value for key, value in expected.items())
                or type(plan["activation_revision"]) is not int
                or not _hex(plan["ledger_digest"])
                or plan["root_safety_before"] != safety
                or raw_hash != plan["root_safety_raw_sha256"]
                or safety.get("paused") is not True
                or safety.get("job_id") != job["job_id"]
                or safety.get("reason") != "automatic_job_installed_restart_pending"
                or plan["root_safety_digest"] != _safety(safety)
                or latch.get("remote_safety") != safety
                or type(plan["eligible"]) is not bool
                or plan["eligible"] != (not blockers)
                or plan["blockers"] != blockers
                or {check["id"] for check in plan["checks"]} != REQUIRED_CHECKS
                or not timedelta(0) < expiry - created <= timedelta(minutes=5)
                or not isinstance(plan["verification"], dict)
                or plan["state_digest"] is not None
                and not _hex(plan["state_digest"])
                or plan["eligible"]
                and not _hex(plan["state_digest"])
                or type(plan["transport_challenge"].get("uptime_ticks")) is not int
                or plan["transport_challenge"]["uptime_ticks"] <= 0
                or set(plan["transport_challenge"]) != {"boot_id", "uptime_ticks"}
                or not isinstance(plan["transport_challenge"].get("boot_id"), str)
                or not plan["transport_challenge"]["boot_id"]
                or remote_before is not None
                and plan["root_usage_before"] != _usage(remote_before)
            ):
                raise ValueError("Activation recovery preview binding changed")
            ahead = (created - now).total_seconds()
            if 0 < ahead <= 1:
                time.sleep(ahead)
                now = instant(self.service.now())
            if not timedelta(0) <= now - created <= timedelta(minutes=5) or expiry <= now:
                raise ValueError("Activation recovery preview is future or expired")
            if plan["eligible"]:
                verified_facts(activation, plan["verification"], plan["state_digest"])
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            raise HTTPException(
                409, "独立恢复预览的原任务、激活、暂停或时效未能完整核实。"
            ) from None

    def prepare(self, body: ActivationRecoveryPrepareRequest):
        with self.service.mode_lock, self.service.local_admission():
            target, mode, scope, controller_digest, configured = self._context(
                body.host_id, body.expected_mode_revision
            )
            self._no_pending(body.host_id)
            self._latch(body.host_id, body.job_id)
            job, activation = self._originals(target, body.job_id, body.activation_id, configured)
        remote = self._root(target, "automatic_status")
        safety = remote.get("safety", {})
        if (
            safety.get("paused") is not True
            or safety.get("job_id") != body.job_id
            or safety.get("reason") != "automatic_job_installed_restart_pending"
        ):
            raise HTTPException(409, "远端不存在与该自动安装任务一致的实际待激活暂停。")
        self.automatic.record_remote_safety(
            body.host_id, scope, target.policy_digest, remote, now=self.service.now()
        )
        latch = self._latch(body.host_id, body.job_id)
        context = digest(latch)
        plan = self._root(
            target,
            "activation_recovery_prepare",
            job_id=body.job_id,
            activation_id=body.activation_id,
            mode_revision=mode["revision"],
            context_digest=context,
        )
        with self.service.mode_lock, self.service.local_admission():
            current_target, current_mode, current_scope, current_digest, current_configured = (
                self._context(body.host_id, mode["revision"])
            )
            if current_scope != scope or current_digest != controller_digest:
                raise HTTPException(409, "读取恢复预览期间目标或当前策略变化。")
            self._no_pending(body.host_id)
            current_latch = self._latch(body.host_id, body.job_id)
            current_job, current_activation = self._originals(
                current_target, body.job_id, body.activation_id, current_configured
            )
            if (
                digest(current_latch) != context
                or current_job != job
                or current_activation != activation
            ):
                raise HTTPException(409, "读取恢复预览期间原证据或暂停变化。")
            self._plan(plan, current_target, current_mode, context, job, activation, latch, remote)
            saved = self.store.save_plan(
                body.host_id,
                plan,
                scope_hash=scope,
                controller_policy_digest=controller_digest,
                original_job=job,
                original_activation=activation,
                latch=latch,
                now=self.service.now(),
            )
            return saved["plan"]

    def _changed(self, record, target):
        if (
            target.policy_digest != record["policy_digest"]
            or self.service._automatic_scope(target) != record["scope_hash"]
        ):
            return "目标或 Root 策略已变化，旧批准不能解除当前暂停。"
        policy = ControlPolicy.model_validate(self.service.automation.policy.model_dump())
        if digest(policy.model_dump(mode="json")) != record["controller_policy_digest"]:
            return "控制端明确权限已变化，旧恢复仅保留历史事实。"
        latch = self.automatic.latch(record["host_id"])
        if latch is None or digest(latch) != record["context_digest"]:
            return "当前暂停原因已变化；不能用旧回执解除新的暂停。"
        try:
            configured = policy.service_activation
            if configured is None:
                return "当前缺少明确服务激活范围。"
            job, activation = self._originals(
                target, record["job_id"], record["activation_id"], configured
            )
            if job != record["original_job"] or activation != record["original_activation"]:
                return "原安装或激活证据已经变化。"
        except (HTTPException, PatchClientError, ValueError, KeyError):
            return "当前原安装或激活证据不可核实。"
        return None

    def _receipt(self, record, receipt):
        try:
            plan = record["plan"]
            blockers = _checks(receipt["checks"])
            if (
                set(receipt) != RECEIPT_FIELDS
                or receipt["kind"] != "activation_recovery"
                or type(receipt["schema_version"]) is not int
                or receipt["schema_version"] != 1
                or receipt["status"] not in {"verified", "rejected"}
                or any(receipt[key] != plan[key] for key in IDENTITY | ANCHORS)
                or receipt["recovery_digest"] != plan["recovery_digest"]
                or receipt["plan"] != plan
                or receipt["receipt_digest"]
                != digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
                or receipt["blockers"] != blockers
                or receipt["resolved_safety_digest"] != plan["root_safety_digest"]
                or receipt["safety_before"] != plan["root_safety_before"]
                or _safety(receipt["safety_before"]) != plan["root_safety_digest"]
                or _safety(receipt["safety_after"]) != receipt["safety_after_digest"]
                or receipt["root_usage_before"] != plan["root_usage_before"]
                or _time(receipt["completed_at"]) < _time(record["confirmed_at"])
                or _time(receipt["completed_at"]) > instant(self.service.now())
            ):
                raise ValueError("Recovery receipt source or approval changed")
            if receipt["status"] == "verified":
                verification = receipt["verification"]
                if (
                    blockers
                    or not {check["id"] for check in receipt["checks"]}
                    >= REQUIRED_CHECKS | FINAL_CHECKS
                    or not _time(plan["created_at"])
                    <= _time(receipt["completed_at"])
                    < _time(plan["expires_at"])
                    or receipt["resolved_job"]
                    != {
                        "job_id": record["job_id"],
                        "revision": record["job_revision"],
                        "job_digest": record["job_digest"],
                        "status": "installed_restart_pending",
                    }
                    or receipt["verified_activation"]
                    != {
                        "activation_id": plan["activation_id"],
                        "revision": plan["activation_revision"],
                        "activation_digest": plan["activation_digest"],
                        "record_digest": plan["activation_record_digest"],
                        "status": "verified",
                    }
                    or receipt["safety_after"]["paused"] is not False
                    or receipt["root_usage_after"] != plan["root_usage_before"]
                    or not isinstance(verification, dict)
                    or any(
                        verification.get(key, {}).get("passed") is not True
                        for key in (
                            "exact_package_version",
                            "health",
                            "vendor_rescan",
                            "final_package_state",
                            "fresh_ssh",
                        )
                    )
                    or verification.get("runtime", {}).get("status") != "complete"
                    or verification["runtime"].get("outdated_process_count") != 0
                    or verification["health"].get("reboot_required") is not False
                    or verification["fresh_ssh"].get("mechanism")
                    != "sshd_connection_started_after_activation_recovery_preview"
                    or _time(verification["fresh_ssh"]["checked_at"]) < _time(plan["created_at"])
                    or _time(verification["fresh_ssh"]["checked_at"])
                    > _time(receipt["completed_at"])
                ):
                    raise ValueError("Recovery receipt lacks complete current evidence")
            self.store._bound_receipt(record, receipt)
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            raise PatchClientError("独立恢复原回执的身份、批准或验证证据不完整。") from None

    def _retire(self, record, detail, receipt=None):
        return self.store.outcome(
            record["host_id"],
            record["recovery_id"],
            "superseded",
            receipt=receipt,
            detail=detail,
            now=self.service.now(),
        )

    def _finish(self, record, result):
        self._receipt(record, result)
        if result["status"] == "rejected":
            return self.store.outcome(
                record["host_id"],
                record["recovery_id"],
                "rejected",
                receipt=result,
                detail="远端拒绝本次独立恢复；原暂停和所有执行身份保持。",
                now=self.service.now(),
            )
        self.store.outcome(
            record["host_id"],
            record["recovery_id"],
            "unknown",
            receipt=result,
            detail="已保留原 Root 回执，仍待当前安全快照核对；不重发恢复。",
            now=self.service.now(),
        )
        target = self.service.target(record["host_id"])
        changed = self._changed(record, target)
        if changed:
            return self._retire(record, changed, result)
        target, _mode, scope, _controller, _configured = self._context(record["host_id"])
        try:
            self._no_pending(record["host_id"], except_recovery=record["recovery_id"])
        except HTTPException:
            return self._retire(record, "有新的未决任务，旧批准不能解除当前原因。", result)
        root = self._root(target, "automatic_status")
        with self.service.local_admission():
            # A status RPC can overlap a mode change. Releasing the local
            # pause requires a fresh synchronized manual context at commit.
            current_target, _mode, current_scope, _controller, _configured = self._context(
                record["host_id"]
            )
            if current_scope != scope or current_target.policy_digest != target.policy_digest:
                return self._retire(record, "读取安全状态期间目标范围变化，原暂停保留。", result)
            changed = self._changed(record, current_target)
            if changed:
                return self._retire(record, changed, result)
            try:
                self._no_pending(record["host_id"], except_recovery=record["recovery_id"])
            except HTTPException:
                return self._retire(record, "有新的未决任务，旧批准不能解除当前原因。", result)
            fresh = self.automatic.record_remote_safety(
                record["host_id"], scope, target.policy_digest, root, now=self.service.now()
            )
            if root.get("safety", {}).get("paused") is not False:
                return self._retire(record, "远端已出现新的暂停，原恢复结果仅作历史保留。", result)
            if _usage(root) != result["root_usage_after"]:
                return self._retire(
                    record, "已用配额或授权身份变化，不能沿用旧批准解除暂停。", result
                )
            changed = self._changed(record, current_target)
            if changed:
                return self._retire(record, changed, result)
            return self.store.complete(
                record["host_id"], record["recovery_id"], result, fresh, now=self.service.now()
            )

    def submit(self, body: ActivationRecoverySubmitRequest):
        with self.service.mode_lock:
            record = self.store.get(body.host_id, body.recovery_id)
            if record is None:
                raise HTTPException(404, "原恢复预览不存在。")
            if record["recovery_digest"] != body.expected_recovery_digest:
                raise HTTPException(409, "批准摘要与原恢复计划不一致。")
            if record["status"] != "prepared":
                return self.status(body.host_id, body.recovery_id, locked=True)
            with self.service.local_admission():
                target, mode, _scope, _digest, _configured = self._context(
                    body.host_id, body.expected_mode_revision
                )
                changed = self._changed(record, target)
                if changed:
                    raise HTTPException(409, changed)
                self._no_pending(body.host_id, except_recovery=body.recovery_id)
                self._plan(
                    record["plan"],
                    target,
                    mode,
                    record["context_digest"],
                    record["original_job"],
                    record["original_activation"],
                    record["latch_before"],
                )
                first, record = self.store.begin_submission(
                    body.host_id,
                    body.recovery_id,
                    body.expected_recovery_digest,
                    body.expected_mode_revision,
                    now=self.service.now(),
                )
            if not first:
                return self.status(body.host_id, body.recovery_id, locked=True)
            try:
                result = self._root(
                    target,
                    "activation_recovery_submit",
                    recovery_id=body.recovery_id,
                    recovery_digest=body.expected_recovery_digest,
                    mode_revision=body.expected_mode_revision,
                    context_digest=record["context_digest"],
                )
                return self._finish(record, result)
            except RootActivationRecoveryRejected:
                return self.store.outcome(
                    body.host_id,
                    body.recovery_id,
                    "rejected",
                    detail="远端明确拒绝批准，暂停保持。",
                    now=self.service.now(),
                )
            except (PatchClientError, HTTPException, ValueError, OSError, sqlite3.Error):
                return self.store.outcome(
                    body.host_id,
                    body.recovery_id,
                    "unknown",
                    detail="独立恢复结果尚未完整核实，仅查询原 ID。",
                    now=self.service.now(),
                )

    def _validated_view(self, record):
        if record["receipt"] is not None:
            self._receipt(record, record["receipt"])
        if record["status"] == "verified" and (
            not record["local_released"] or record["receipt"] is None
        ):
            raise PatchClientError("恢复缓存没有完整的本地对账回执。")
        return record

    def status(self, host_id, recovery_id, *, locked=False):
        if (
            not isinstance(host_id, str)
            or re.fullmatch(HOST, host_id) is None
            or not _hex(recovery_id, ID)
        ):
            raise HTTPException(404, "恢复 ID 无效。")
        record = self.store.get(host_id, recovery_id)
        if record is None:
            raise HTTPException(404, "原独立恢复记录不存在。")
        if record["status"] in {"prepared", "verified", "rejected", "superseded"}:
            return self._validated_view(record)
        if not locked:
            with self.service.mode_lock:
                return self.status(host_id, recovery_id, locked=True)
        try:
            target = self.service.target(host_id)
            if (
                target.policy_digest != record["policy_digest"]
                or self.service._automatic_scope(target) != record["scope_hash"]
            ):
                return self._retire(record, "目标或策略变化，原结果保留未知，不再发送恢复。")
            result = self._root(target, "activation_recovery_status", recovery_id=recovery_id)
            if result.get("status") in {"unknown", "activation_recovery_prepared"}:
                raise PatchClientError("原恢复结果未确定，不重复批准。")
            return self._finish(record, result)
        except (
            PatchClientError,
            RootActivationRecoveryRejected,
            HTTPException,
            ValueError,
            OSError,
            sqlite3.Error,
        ):
            return self.store.outcome(
                host_id,
                recovery_id,
                "unknown",
                detail="原 ID 尚待可信回执和新安全快照；暂停保留。",
                now=self.service.now(),
            )

    def list(self):
        policy = ControlPolicy.model_validate(self.service.automation.policy.model_dump())
        return {
            "enabled": bool(
                policy.enabled and policy.service_activation and policy.service_activation.enabled
            ),
            "supported_modes": ["manual"],
            "records": [self._validated_view(value) for value in self.store.list()],
            "original_jobs_modified": False,
            "mode_or_grants_modified": False,
        }


def register_activation_recovery_routes(
    application: FastAPI, service: ActivationRecoveryService, protected
):
    router = APIRouter(prefix="/api/activation-recoveries", dependencies=protected)

    def guarded(action):
        try:
            return action()
        except RootActivationRecoveryRejected:
            raise HTTPException(409, "远端拒绝独立恢复，原暂停保持。") from None
        except (PatchClientError, ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, "独立恢复证据或审计尚未完整核实。") from None

    @router.get("")
    def listed():
        return guarded(service.list)

    @router.post("/plans")
    def prepare(body: ActivationRecoveryPrepareRequest):
        return guarded(lambda: service.prepare(body))

    @router.post("")
    def submit(body: ActivationRecoverySubmitRequest):
        return guarded(lambda: service.submit(body))

    @router.get("/{host_id}/{recovery_id}")
    def status(host_id: str, recovery_id: str):
        return guarded(lambda: service.status(host_id, recovery_id))

    application.include_router(router)
    return router
