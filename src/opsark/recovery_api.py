"""Explicit human reconciliation of one pause; never installs or grants an action."""

import re
import sqlite3
from datetime import timedelta

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import Field, field_validator

from opsark.automatic_store import digest, instant, safety_digest
from opsark.control_modes import ControlPolicy
from opsark.models import StrictModel
from opsark.patch_api import PatchService
from opsark.patch_client import PatchClientError

HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
CHECK = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
HOST = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"
CACHE_FIELDS = {"received_at", "notification_due", "notification_count", "last_notified_at"}
REQUIRED_CHECKS = {
    "original_job_verified",
    "ledger_settled",
    "original_plan_intact",
    "exact_package_version",
    "apt_configuration_safe",
    "registered_health",
    "no_reboot_pending",
    "runtime_complete",
    "vendor_rescan",
    "final_package_state",
}


class RecoveryPrepareRequest(StrictModel):
    host_id: str = Field(pattern=HOST, strict=True)
    job_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)


class RecoverySubmitRequest(StrictModel):
    host_id: str = Field(pattern=HOST, strict=True)
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$", strict=True)
    expected_recovery_digest: str = Field(pattern=r"^[0-9a-f]{64}$", strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)
    confirm_recover: bool = Field(strict=True)

    @field_validator("confirm_recover")
    @classmethod
    def confirmed(cls, value):
        if value is not True:
            raise ValueError("必须明确批准当前恢复预览。")
        return value


class RootRecoveryRejected(ValueError):
    """An explicit root refusal, distinct from an uncertain response."""


def _hex(value, expression=HEX):
    return isinstance(value, str) and expression.fullmatch(value) is not None


def _time(value):
    from datetime import datetime

    if not isinstance(value, str):
        raise ValueError("Missing recovery time")
    return instant(datetime.fromisoformat(value))


def _safety(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "paused", "reason", "job_id", "updated_at"}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or type(value.get("paused")) is not bool
    ):
        raise ValueError("Recovery safety snapshot is invalid")
    _time(value["updated_at"])
    if value["paused"]:
        if not _hex(value.get("job_id"), ID) or not isinstance(value.get("reason"), str):
            raise ValueError("Recovery pause identity is unavailable")
    elif value["reason"] is not None or value["job_id"] is not None:
        raise ValueError("Conflicting unpaused root snapshot")
    return safety_digest(value)


def _checks(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError("Recovery checks are absent or exceeded their budget")
    seen = set()
    for check in value:
        if (
            not isinstance(check, dict)
            or set(check) != {"id", "status", "detail"}
            or not isinstance(check["id"], str)
            or not CHECK.fullmatch(check["id"])
            or check["id"] in seen
            or check["status"] not in {"passed", "failed", "unavailable"}
            or not isinstance(check["detail"], str)
            or len(check["detail"]) > 2000
        ):
            raise ValueError("Recovery checks cannot be established")
        seen.add(check["id"])
    return [check["id"] for check in value if check["status"] != "passed"]


class RecoveryService:
    def __init__(self, service: PatchService):
        self.service = service

    @property
    def store(self):
        if self.service.automatic_store is None:
            raise HTTPException(503, "恢复审计存储未配置。")
        return self.service.automatic_store

    def _context(self, host_id, revision=None):
        target = self.service.target(host_id)
        mode = self.service.automation.status()
        policy = ControlPolicy.model_validate(self.service.automation.policy.model_dump())
        if (
            mode["mode"] != "manual"
            or mode.get("mode_sync_complete") is not True
            or revision is not None
            and mode["revision"] != revision
            or type(mode.get("revision")) is not int
        ):
            raise HTTPException(409, "人工恢复要求已同步的当前手动模式；模式或修订已变化。")
        if (
            not policy.enabled
            or "os_security_upgrade" not in policy.allowed_actions
            or host_id not in policy.host_ids
        ):
            raise HTTPException(403, "当前部署没有登记该目标的恢复范围。")
        return target, mode, self.service._automatic_scope(target)

    def _root(self, target, operation, **fields):
        value = self.service.invoker(
            target,
            {
                "schema_version": 1,
                "op": operation,
                "policy_digest": target.policy_digest,
                **fields,
            },
            timeout=75 if operation in {"recovery_prepare", "recovery_submit"} else 15,
        )
        if not isinstance(value, dict):
            raise PatchClientError("恢复入口没有返回可信对象。")
        if value.get("status") == "busy" or value.get("error") == "busy":
            raise PatchClientError("恢复入口正忙，不能确定原恢复结果。")
        if value.get("ok") is False or value.get("error"):
            if value.get("error") == "rejected":
                raise RootRecoveryRejected("远端明确拒绝了当前恢复请求。")
            raise PatchClientError("恢复入口结果未能核实。")
        if (
            type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("host_id") != target.host.public.id
            or value.get("policy_digest") != target.policy_digest
        ):
            raise PatchClientError("恢复结果与当前目标或部署策略不一致。")
        return value

    def _job(self, host_id, job_id):
        job = self.service.job_status(host_id, job_id)
        if (
            job.get("job_id") != job_id
            or job.get("host_id") != host_id
            or job.get("authorization") != "automatic"
            or type(job.get("revision")) is not int
            or job["revision"] < 1
        ):
            raise HTTPException(409, "原任务不是可核实的自动任务。")
        return job

    def _no_pending(self, host_id):
        if any(job["host_id"] == host_id for job in self.service.store.pollable_jobs()):
            raise HTTPException(409, "该目标仍有活动或未知任务，必须先对账原任务。")

    def _changed_context(self, record, target):
        if (
            target.policy_digest != record["policy_digest"]
            or self.service._automatic_scope(target) != record["scope_hash"]
        ):
            return "目标或部署策略已变化；旧恢复不能作为当前权限证明，原远端结果仍保留原事实。"
        latch = self.store.latch(record["host_id"])
        if latch is None or digest(latch) != record["context_digest"]:
            return "当前暂停已变化；旧批准不能解除新的暂停，需要核对当前原因后重新预览。"
        return None

    def _superseded(self, record, detail, receipt=None):
        return self.store.supersede_recovery(
            record["host_id"],
            record["recovery_id"],
            receipt=receipt,
            detail=detail,
            now=self.service.now(),
        )

    def _plan(self, value, target, mode, context, job):
        at = instant(self.service.now())
        try:
            created, expiry = _time(value["created_at"]), _time(value["expires_at"])
            blockers = _checks(value["checks"])
            required = {check["id"] for check in value["checks"]} >= REQUIRED_CHECKS
            raw_job = {key: item for key, item in job.items() if key not in CACHE_FIELDS}
            if (
                value.get("status") != "recovery_prepared"
                or not _hex(value.get("recovery_id"), ID)
                or not _hex(value.get("recovery_digest"))
                or value["recovery_digest"]
                != digest({k: v for k, v in value.items() if k != "recovery_digest"})
                or not _hex(value.get("driver_source_digest"))
                or value.get("context_digest") != context
                or value.get("job_id") != job["job_id"]
                or type(value.get("job_revision")) is not int
                or value["job_revision"] != job["revision"]
                or value.get("job_digest") != digest(raw_job)
                or type(value.get("mode_revision")) is not int
                or value["mode_revision"] != mode["revision"]
                or value.get("host_id") != target.host.public.id
                or value.get("policy_digest") != target.policy_digest
                or type(value.get("eligible")) is not bool
                or value.get("eligible") != (not blockers)
                or value.get("eligible") is True
                and not required
                or value.get("blockers") != blockers
                or not timedelta(0) < expiry - created <= timedelta(minutes=5)
                or not timedelta(0) <= at - created <= timedelta(minutes=5)
                or expiry <= at
                or value.get("eligible") is True
                and not _hex(value.get("state_digest"))
                or value.get("state_digest") is not None
                and not _hex(value["state_digest"])
                or value.get("root_safety_digest") != _safety(value["root_safety_before"])
                or not isinstance(value.get("verification"), dict)
                or not isinstance(value.get("transport_challenge"), dict)
                or type(value["transport_challenge"].get("uptime_ticks")) is not int
                or value["transport_challenge"]["uptime_ticks"] < 0
                or not isinstance(value["transport_challenge"].get("boot_id"), str)
                or not value["transport_challenge"]["boot_id"]
            ):
                raise ValueError("Recovery preview bindings changed")
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(409, "恢复预览的原任务、证据、时效或完整摘要未能核实。") from error

    def prepare(self, body: RecoveryPrepareRequest):
        with self.service.mode_lock, self.service.local_admission():
            target, mode, scope = self._context(body.host_id, body.expected_mode_revision)
            latch = self.store.latch(body.host_id)
            if latch is None or latch.get("job_id") != body.job_id:
                raise HTTPException(409, "只允许核对此目标暂停记录中的原任务。")
            pending = self.store.pending_recovery(body.host_id)
            if pending is not None:
                changed = self._changed_context(pending, target)
                if changed:
                    self._superseded(pending, changed)
                else:
                    raise HTTPException(409, "已有恢复结果待核实，只能查询原恢复 ID。")
            context = digest(latch)
        # Reading first reconciles transport/archival state before the root binds
        # its immutable job hash. Recovery never interferes with an installing worker.
        job = self._job(body.host_id, body.job_id)
        if job.get("status") in {
            "queued",
            "preflight",
            "downloading",
            "applying",
            "verifying",
            "awaiting_transport_verification",
            "running_overdue",
        }:
            raise HTTPException(409, "原任务仍在执行或等待验收，先查询原任务，不生成恢复批准。")
        value = self._root(
            target,
            "recovery_prepare",
            job_id=body.job_id,
            mode_revision=mode["revision"],
            context_digest=context,
        )
        job = self._job(body.host_id, body.job_id)
        with self.service.mode_lock, self.service.local_admission():
            self._context(body.host_id, mode["revision"])
            self._plan(value, target, mode, context, job)
            saved = self.store.save_recovery_plan(
                body.host_id, scope, target.policy_digest, value, latch, now=self.service.now()
            )
            return saved["plan"]

    def _receipt(self, record, receipt):
        try:
            plan = record["plan"]
            if (
                receipt.get("status") not in {"verified", "rejected"}
                or type(receipt.get("job_revision")) is not int
                or type(receipt.get("mode_revision")) is not int
                or any(
                    receipt.get(key) != record[key]
                    for key in (
                        "host_id",
                        "policy_digest",
                        "recovery_id",
                        "recovery_digest",
                        "job_id",
                        "job_revision",
                        "job_digest",
                        "mode_revision",
                        "context_digest",
                    )
                )
                or receipt.get("driver_source_digest") != plan["driver_source_digest"]
                or receipt.get("receipt_digest")
                != digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
                or receipt.get("created_at") != plan["created_at"]
                or receipt.get("expires_at") != plan["expires_at"]
                or receipt.get("resolved_safety_digest") != plan["root_safety_digest"]
                or _safety(receipt["safety_before"]) != plan["root_safety_digest"]
                or _safety(receipt["safety_after"]) != receipt.get("safety_after_digest")
                or _time(receipt["completed_at"]) < _time(record["confirmed_at"])
                or _time(receipt["completed_at"]) > instant(self.service.now())
            ):
                raise ValueError("Recovery receipt binding changed")
            blockers = _checks(receipt["checks"])
            if receipt.get("blockers") != blockers:
                raise ValueError("Recovery blockers conflict")
            if receipt["status"] == "verified" and (
                blockers
                or not _time(plan["created_at"])
                <= _time(receipt["completed_at"])
                < _time(plan["expires_at"])
                or receipt["safety_after"].get("paused") is not False
                or not REQUIRED_CHECKS
                | {
                    "prepared_eligible",
                    "plan_valid",
                    "job_unchanged",
                    "state_unchanged",
                    "pause_unchanged",
                    "fresh_ssh",
                    "final_ledger_settled",
                    "policy_unchanged",
                }
                <= {check["id"] for check in receipt["checks"]}
                or receipt.get("verified_job")
                != {
                    "job_id": record["job_id"],
                    "revision": record["job_revision"],
                    "job_digest": record["job_digest"],
                    "status": "verified",
                }
                or not isinstance(receipt.get("verification"), dict)
                or not isinstance(receipt["verification"].get("fresh_ssh"), dict)
                or receipt.get("verification", {}).get("fresh_ssh", {}).get("passed") is not True
            ):
                raise ValueError("Verified recovery lacks complete proof")
        except (KeyError, TypeError, ValueError) as error:
            raise PatchClientError("原恢复回执的完整绑定或验证证据不一致。") from error

    def _finish(self, record, result):
        self._receipt(record, result)
        host_id, recovery_id = record["host_id"], record["recovery_id"]
        if result["status"] == "rejected":
            return self.store.set_recovery_outcome(
                host_id,
                recovery_id,
                "rejected",
                receipt=result,
                detail="远端核验拒绝了本次恢复；原暂停、任务与配额均保留。",
                now=self.service.now(),
            )
        # The exact root result is already known even if a later local check or
        # read fails. Persist it without releasing the pause or resending the RPC.
        self.store.set_recovery_outcome(
            host_id,
            recovery_id,
            "unknown",
            receipt=result,
            detail="远端核验回执已保存，仍待当前安全状态及本地对账；暂停保持。",
            now=self.service.now(),
        )
        target = self.service.target(host_id)
        changed = self._changed_context(record, target)
        if changed:
            return self._superseded(record, changed, result)
        # This is completion of the original exact approval, not a new root
        # action. A later manual revision may reconcile its already durable receipt.
        target, _mode, scope = self._context(host_id)
        if scope != record["scope_hash"] or target.policy_digest != record["policy_digest"]:
            raise PatchClientError("部署范围已变化，旧恢复结果不能作为新的权限证明。")
        job = self._job(host_id, record["job_id"])
        if (
            job.get("status") != "verified"
            or job["revision"] != record["job_revision"]
            or digest({key: value for key, value in job.items() if key not in CACHE_FIELDS})
            != record["job_digest"]
        ):
            return self._superseded(
                record, "原恢复已在远端完成，但原任务现在的证据已变化；保留暂停，重新预览。", result
            )
        try:
            self._no_pending(host_id)
        except HTTPException:
            return self._superseded(
                record, "原恢复已在远端完成，但该目标出现待核实任务；保留暂停，先对账。", result
            )
        root = self._root(target, "automatic_status")
        fresh = self.store.record_remote_safety(
            host_id, scope, target.policy_digest, root, now=self.service.now()
        )
        if root.get("safety", {}).get("paused") is not False:
            return self._superseded(
                record, "远端出现当前暂停；旧恢复已留审计，不能解除当前原因。", result
            )
        # The remote reads cannot retain the shared mode lock. Recheck every
        # local condition with mode changes excluded before releasing the pause.
        with self.service.local_admission():
            target, _mode, current_scope = self._context(host_id)
            if (
                current_scope != scope
                or current_scope != record["scope_hash"]
                or target.policy_digest != record["policy_digest"]
            ):
                raise PatchClientError("部署范围已变化，旧恢复结果不能作为新的权限证明。")
            changed = self._changed_context(record, target)
            if changed:
                return self._superseded(record, changed, result)
            try:
                self._no_pending(host_id)
            except HTTPException:
                return self._superseded(
                    record, "原恢复已在远端完成，但该目标出现待核实任务；保留暂停，先对账。", result
                )
            return self.store.complete_recovery(
                host_id, recovery_id, result, fresh, now=self.service.now()
            )

    def submit(self, body: RecoverySubmitRequest):
        with self.service.mode_lock:
            target, _mode, scope = self._context(body.host_id, body.expected_mode_revision)
            record = self.store.get_recovery(body.host_id, body.recovery_id)
            if record is None:
                raise HTTPException(404, "恢复预览不存在。")
            if record["recovery_digest"] != body.expected_recovery_digest:
                raise HTTPException(409, "人工批准的恢复摘要不一致。")
            if record["status"] != "prepared":
                return self.status(body.host_id, body.recovery_id, locked=True)
            job = self._job(body.host_id, record["job_id"])
            with self.service.local_admission():
                target, mode, scope = self._context(body.host_id, body.expected_mode_revision)
                record = self.store.get_recovery(body.host_id, body.recovery_id)
                if record is None:
                    raise HTTPException(404, "恢复预览不存在。")
                if record["recovery_digest"] != body.expected_recovery_digest:
                    raise HTTPException(409, "人工批准的恢复摘要不一致。")
                if record["status"] != "prepared":
                    first = False
                else:
                    if (
                        record["scope_hash"] != scope
                        or record["policy_digest"] != target.policy_digest
                    ):
                        raise HTTPException(409, "恢复预览的目标或策略范围已变化。")
                    self._plan(record["plan"], target, mode, record["context_digest"], job)
                    self._no_pending(body.host_id)
                    first, record = self.store.register_recovery_submission(
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
                    "recovery_submit",
                    recovery_id=body.recovery_id,
                    recovery_digest=body.expected_recovery_digest,
                    mode_revision=body.expected_mode_revision,
                    context_digest=record["context_digest"],
                )
                return self._finish(record, result)
            except RootRecoveryRejected:
                return self.store.set_recovery_outcome(
                    body.host_id,
                    body.recovery_id,
                    "rejected",
                    detail="远端明确拒绝恢复；保留暂停，请重新核对预览。",
                    now=self.service.now(),
                )
            except (PatchClientError, HTTPException, ValueError, OSError):
                return self.store.set_recovery_outcome(
                    body.host_id,
                    body.recovery_id,
                    "unknown",
                    detail="恢复回执或本地对账尚未完成；保留暂停，只查询原恢复 ID。",
                    now=self.service.now(),
                )

    def status(self, host_id, recovery_id, *, locked=False):
        if (
            not isinstance(host_id, str)
            or re.fullmatch(HOST, host_id) is None
            or not _hex(recovery_id, ID)
        ):
            raise HTTPException(404, "恢复 ID 无效。")
        record = self.store.get_recovery(host_id, recovery_id)
        if record is None:
            raise HTTPException(404, "恢复记录不存在。")
        if record["status"] in {"prepared", "verified", "rejected", "superseded"}:
            return record
        if not locked:
            with self.service.mode_lock:
                return self.status(host_id, recovery_id, locked=True)
        try:
            target = self.service.target(host_id)
            if (
                target.policy_digest != record["policy_digest"]
                or self.service._automatic_scope(target) != record["scope_hash"]
            ):
                return self._superseded(
                    record, "当前目标策略或作用域已变化；旧远端结果仍未知，不沿用旧批准解除暂停。"
                )
            result = self._root(target, "recovery_status", recovery_id=recovery_id)
            # An approved ID whose root plan still exists without a receipt is
            # still uncertain. It must not cause a second submit or a new ID.
            if result.get("status") == "recovery_prepared":
                raise PatchClientError("原恢复结果仍未核实。")
            return self._finish(record, result)
        except (RootRecoveryRejected, PatchClientError, HTTPException, ValueError, OSError):
            return self.store.set_recovery_outcome(
                host_id,
                recovery_id,
                "unknown",
                detail="原恢复尚未取得完整可信回执；暂停保留，不会重新提交恢复。",
                now=self.service.now(),
            )


def register_recovery_routes(application: FastAPI, service: RecoveryService, protected):
    router = APIRouter(prefix="/api/automatic", dependencies=protected)

    def guarded(action):
        try:
            return action()
        except RootRecoveryRejected as error:
            raise HTTPException(409, "远端拒绝恢复预览，原暂停仍保留。") from error
        except PatchClientError as error:
            raise HTTPException(503, "恢复证据读取未能核实，原暂停仍保留。") from error
        except (sqlite3.Error, ValueError, OSError) as error:
            raise HTTPException(503, "恢复审计存储或证据校验暂时不可用。") from error

    @router.post("/recovery-plans")
    def prepare(body: RecoveryPrepareRequest):
        return guarded(lambda: service.prepare(body))

    @router.post("/recoveries")
    def submit(body: RecoverySubmitRequest):
        return guarded(lambda: service.submit(body))

    @router.get("/recoveries")
    def listed():
        return guarded(service.store.list_recoveries)

    @router.get("/recoveries/{host_id}/{recovery_id}")
    def status(host_id: str, recovery_id: str):
        return guarded(lambda: service.status(host_id, recovery_id))

    application.include_router(router)
