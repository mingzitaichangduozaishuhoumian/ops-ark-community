"""Explicitly approved service activation over one original pending patch transaction."""

import re
import sqlite3
import time
from datetime import timedelta

from fastapi import APIRouter, FastAPI, HTTPException, Response
from pydantic import Field, field_validator

from opsark.activation_store import REMOTE_ACTIVE, ActivationStore, identity, instant_from
from opsark.automatic_store import canonical, digest, instant
from opsark.control_modes import ControlPolicy
from opsark.models import StrictModel
from opsark.patch_api import PatchService
from opsark.patch_client import PatchClientError

HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"
ID_PATTERN = r"^[0-9a-f]{32}$"
DIGEST_PATTERN = r"^[0-9a-f]{64}$"
ID = re.compile(ID_PATTERN)
HEX = re.compile(DIGEST_PATTERN)
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.service\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,79}\Z")
VERSION = re.compile(r"[0-9][0-9A-Za-z.+:~_-]{0,159}\Z")
CHECK = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
CACHE = {"received_at", "notification_due", "notification_count", "last_notified_at"}
PLAN_FIELDS = {
    "schema_version",
    "status",
    "activation_id",
    "activation_digest",
    "host_id",
    "evidence_origin",
    "action",
    "policy_digest",
    "driver_source_digest",
    "mode_revision",
    "prepared_mode",
    "context_digest",
    "job_id",
    "job_revision",
    "job_digest",
    "original_job_status",
    "original_job_sha256",
    "original_plan_id",
    "original_plan_digest",
    "original_plan_sha256",
    "runtime_manifest_sha256",
    "original_safety_digest",
    "original_safety_present",
    "package",
    "architecture",
    "candidate_version",
    "unit",
    "unit_evidence",
    "processes",
    "state_digest",
    "boot_id",
    "created_at",
    "expires_at",
    "eligible",
    "checks",
    "blockers",
    "requires_reboot",
    "original_job_will_not_be_modified",
    "effective_result",
}
REQUIRED_CHECKS = {
    "original_patch_pending",
    "original_ledgers_bound",
    "exact_package_version",
    "runtime_service_identity",
    "unit_configuration_bound",
    "registered_health",
    "no_reboot_pending",
}
RECORD_FIELDS = {
    "schema_version",
    "activation_id",
    "activation_digest",
    "host_id",
    "policy_digest",
    "driver_source_digest",
    "job_id",
    "job_revision",
    "job_digest",
    "original_job_status",
    "original_job_sha256",
    "original_safety_digest",
    "mode_revision",
    "context_digest",
    "state_digest",
    "unit",
    "package",
    "architecture",
    "candidate_version",
    "status",
    "revision",
    "created_at",
    "updated_at",
    "approved_at",
    "expires_at",
    "completed_at",
    "approval_digest",
    "plan",
    "restart_evidence",
    "verification",
    "effective_result",
    "local_result",
    "locally_verified_at",
    "locally_verified_uptime_ticks",
    "boot_id",
    "detail",
    "record_digest",
    "original_job_unchanged",
    "original_safety_unchanged",
}


class ActivationPrepareRequest(StrictModel):
    host_id: str = Field(pattern=HOST_PATTERN, strict=True)
    job_id: str = Field(pattern=ID_PATTERN, strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)


class ActivationSubmitRequest(StrictModel):
    host_id: str = Field(pattern=HOST_PATTERN, strict=True)
    activation_id: str = Field(pattern=ID_PATTERN, strict=True)
    expected_activation_digest: str = Field(pattern=DIGEST_PATTERN, strict=True)
    expected_mode_revision: int = Field(ge=0, strict=True)
    confirm_activate: bool = Field(strict=True)

    @field_validator("confirm_activate")
    @classmethod
    def confirmed(cls, value):
        if value is not True:
            raise ValueError("必须明确批准当前服务激活方案。")
        return value


class RootActivationRejected(ValueError):
    """A definite rejection does not authorize replaying an uncertain request."""


def _hex(value, pattern=HEX):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _raw_job(value):
    return {k: v for k, v in value.items() if k not in CACHE}


def _checks(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        raise ValueError("Activation checks are unavailable")
    identifiers, blocked = set(), []
    for value in values:
        if (
            not isinstance(value, dict)
            or not {"id", "status"} <= set(value) <= {"id", "status", "detail"}
            or not isinstance(value["id"], str)
            or CHECK.fullmatch(value["id"]) is None
            or value["id"] in identifiers
            or value["status"] not in {"passed", "failed", "unavailable"}
            or "detail" in value
            and (not isinstance(value["detail"], str) or len(value["detail"]) > 2000)
        ):
            raise ValueError("Activation checks are invalid")
        identifiers.add(value["id"])
        if value["status"] != "passed":
            blocked.append(value["id"])
    return identifiers, blocked


class ActivationService:
    def __init__(self, service: PatchService, store: ActivationStore):
        self.service, self.store = service, store
        self.evidence_observation_store = None

    def _policy(self):
        policy = ControlPolicy.model_validate(self.service.automation.policy.model_dump())
        configured = getattr(policy, "service_activation", None)
        if configured is None:
            return policy, None
        value = configured.model_dump(mode="json")
        return policy, value

    def _context(self, host_id, revision, *, submitting=False):
        target = self.service.target(host_id)
        policy, configured = self._policy()
        mode = self.service.automation.status()
        if (
            type(mode.get("revision")) is not int
            or mode["revision"] != revision
            or mode.get("mode_sync_complete") is not True
            or mode.get("mode") not in ({"assisted"} if submitting else {"manual", "assisted"})
        ):
            raise HTTPException(409, "服务激活要求当前已同步模式；执行仅允许半自动明确批准。")
        if (
            not policy.enabled
            or host_id not in policy.host_ids
            or configured is None
            or configured.get("enabled") is not True
            or host_id not in configured["host_ids"]
            or configured["max_services_per_activation"] != 1
        ):
            raise HTTPException(403, "当前部署未明确授权此目标的服务激活。")
        return target, mode, configured, digest(policy.model_dump(mode="json"))

    @staticmethod
    def _context_digest(target, controller_digest, job):
        return digest(
            {
                "channel": "service-activation/v1",
                "scope_hash": PatchService._automatic_scope(target),
                "controller_policy_digest": controller_digest,
                "job_id": job["job_id"],
                "job_revision": job["revision"],
                "job_digest": digest(_raw_job(job)),
            }
        )

    def _root(self, target, operation, **fields):
        result = self.service.invoker(
            target,
            {
                "schema_version": 1,
                "op": operation,
                "policy_digest": target.policy_digest,
                **fields,
            },
            timeout=75,
        )
        if not isinstance(result, dict):
            raise PatchClientError("服务激活入口没有返回可信对象。")
        if result.get("status") == "busy" or result.get("error") == "busy":
            raise PatchClientError("服务激活入口正忙，原结果仍需查询。")
        if result.get("ok") is False or result.get("error"):
            if result.get("error") == "rejected":
                raise RootActivationRejected("远端明确拒绝了当前服务激活。")
            raise PatchClientError("服务激活结果未能核实。")
        if (
            type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or result.get("host_id") != target.host.public.id
            or result.get("policy_digest") != target.policy_digest
        ):
            raise PatchClientError("激活结果与原目标或部署策略不一致。")
        return result

    def _original_job(self, host_id, job_id, *, refresh):
        job = (
            self.service.job_status(host_id, job_id)
            if refresh
            else self.service.store.get_job(host_id, job_id)
        )
        if (
            not isinstance(job, dict)
            or job.get("job_id") != job_id
            or job.get("host_id") != host_id
            or job.get("status") != "installed_restart_pending"
            or type(job.get("install_exit_code")) is not int
            or job["install_exit_code"] != 0
            or type(job.get("revision")) is not int
            or job["revision"] < 1
            or not _hex(job.get("plan_id"), ID)
            or not _hex(job.get("plan_digest"))
            or not isinstance(job.get("verification"), dict)
            or not isinstance(job["verification"].get("fresh_ssh"), dict)
            or job["verification"].get("fresh_ssh", {}).get("passed") is not True
        ):
            raise HTTPException(409, "仅允许对已安装且等待服务激活的原补丁任务生成方案。")
        return job

    def _no_pending(self, host_id, *, except_id=None):
        if any(record["activation_id"] != except_id for record in self.store.pending(host_id)):
            raise HTTPException(409, "已有激活结果待核实，请查询原激活 ID。")
        if any(job["host_id"] == host_id for job in self.service.store.pollable_jobs()):
            raise HTTPException(409, "目标还有活动或未知补丁事务，先核对原任务。")

    def _plan(self, plan, target, mode, configured, context, job):
        at = instant(self.service.now())
        try:
            checks, blockers = _checks(plan["checks"])
            created, expires = instant_from(plan["created_at"]), instant_from(plan["expires_at"])
            if (
                set(plan) != PLAN_FIELDS
                or plan["status"] != "activation_prepared"
                or not _hex(plan["activation_id"], ID)
                or not _hex(plan["activation_digest"])
                or plan["activation_digest"]
                != digest({k: v for k, v in plan.items() if k != "activation_digest"})
                or plan["host_id"] != target.host.public.id
                or plan["policy_digest"] != target.policy_digest
                or not _hex(plan["driver_source_digest"])
                or plan["action"] != "service_activation"
                or plan["evidence_origin"] not in {"host", "controlled_lab"}
                or plan["job_id"] != job["job_id"]
                or type(plan["job_revision"]) is not int
                or plan["job_revision"] != job["revision"]
                or plan["job_digest"] != digest(_raw_job(job))
                or plan["original_job_status"] != "installed_restart_pending"
                or plan["original_plan_id"] != job["plan_id"]
                or plan["original_plan_digest"] != job["plan_digest"]
                or not all(
                    _hex(plan[key])
                    for key in (
                        "original_job_sha256",
                        "original_plan_sha256",
                        "runtime_manifest_sha256",
                        "original_safety_digest",
                        "state_digest",
                    )
                )
                or type(plan["original_safety_present"]) is not bool
                or plan["context_digest"] != context
                or type(plan["mode_revision"]) is not int
                or plan["mode_revision"] != mode["revision"]
                or plan["prepared_mode"] != mode["mode"]
                or plan["requires_reboot"] is not False
                or plan["original_job_will_not_be_modified"] is not True
                or plan["effective_result"] != "pending_approval"
                or type(plan["eligible"]) is not bool
                or plan["eligible"] != (not blockers)
                or plan["blockers"] != blockers
                or plan["eligible"]
                and not checks >= REQUIRED_CHECKS
                or not timedelta(0) < expires - created <= timedelta(minutes=5)
                or at - created > timedelta(minutes=5)
                or expires <= at
                or not isinstance(plan["boot_id"], str)
                or not plan["boot_id"]
                or len(plan["boot_id"]) > 80
                or not isinstance(plan["unit_evidence"], dict)
                or not isinstance(plan["processes"], list)
                or len(plan["processes"]) > 64
            ):
                raise ValueError("Activation preview binding changed")
            if plan["eligible"] and (
                not isinstance(plan["unit"], str)
                or UNIT.fullmatch(plan["unit"]) is None
                or plan["unit"] not in configured["allowed_units"]
                or plan["unit"] == "dbus.service"
                and plan["unit"] not in configured["allow_critical_units"]
                or not isinstance(plan["package"], str)
                or PACKAGE.fullmatch(plan["package"]) is None
                or plan["package"] not in configured["allowed_packages"]
                or plan["architecture"] not in {"amd64", "arm64"}
                or not isinstance(plan["candidate_version"], str)
                or VERSION.fullmatch(plan["candidate_version"]) is None
                or not plan["processes"]
            ):
                raise ValueError("Activation exceeds the service or package permission")
            if len(canonical(plan).encode()) > 262_144:
                raise ValueError("Activation preview exceeded its budget")
            # Root and controller UTC can differ by a fraction of a second.
            # Wait once, at most one second, without accepting a future plan or
            # extending its immutable expiry. Frozen/backward clocks still fail.
            ahead = (created - at).total_seconds()
            if 0 < ahead <= 1:
                time.sleep(ahead)
                at = instant(self.service.now())
            if not timedelta(0) <= at - created <= timedelta(minutes=5) or expires <= at:
                raise ValueError("Activation preview time could not be established")
        except (ValueError, TypeError, KeyError, RecursionError):
            raise HTTPException(
                409, "激活预览的原任务、服务范围、时效或完整摘要未能核实。"
            ) from None

    def prepare(self, body: ActivationPrepareRequest):
        with self.service.mode_lock, self.service.local_admission():
            target, mode, configured, controller_digest = self._context(
                body.host_id, body.expected_mode_revision
            )
            self._no_pending(body.host_id)
        # The native activation preview reads and binds the original immutable
        # ledger itself. A legacy patch status refresh can rewrite its terminal
        # receipt metadata after a helper upgrade, so admission uses only the
        # already retained receipt and rejects a missing or different snapshot.
        job = self._original_job(body.host_id, body.job_id, refresh=False)
        context = self._context_digest(target, controller_digest, job)
        plan = self._root(
            target,
            "activation_prepare",
            job_id=body.job_id,
            mode_revision=body.expected_mode_revision,
            context_digest=context,
        )
        with self.service.mode_lock, self.service.local_admission():
            current_target, current_mode, current_configured, current_digest = self._context(
                body.host_id, body.expected_mode_revision
            )
            if (
                PatchService._automatic_scope(current_target)
                != PatchService._automatic_scope(target)
                or current_digest != controller_digest
            ):
                raise HTTPException(409, "读取激活预览期间部署范围已变化。")
            self._no_pending(body.host_id)
            self._plan(plan, current_target, current_mode, current_configured, context, job)
            record = self.store.save_plan(
                body.host_id,
                plan,
                scope_hash=PatchService._automatic_scope(target),
                controller_policy_digest=controller_digest,
                original_job=_raw_job(job),
                now=self.service.now(),
            )
        return self._view(record)

    def submit(self, body: ActivationSubmitRequest):
        with self.service.mode_lock:
            with self.service.local_admission():
                record = self.store.get(body.host_id, body.activation_id)
                if record is None:
                    raise HTTPException(404, "服务激活预览不存在。")
                if record["activation_digest"] != body.expected_activation_digest:
                    raise HTTPException(409, "批准的激活摘要与原方案不一致。")
                # Duplicate submit is a cached read even after permission or mode revocation.
                if record["status"] != "prepared":
                    return self._view(record)
                target, mode, configured, controller_digest = self._context(
                    body.host_id, body.expected_mode_revision, submitting=True
                )
                if (
                    record["scope_hash"] != PatchService._automatic_scope(target)
                    or record["controller_policy_digest"] != controller_digest
                ):
                    raise HTTPException(409, "原激活预览的目标或权限范围已变化。")
                self._no_pending(body.host_id, except_id=body.activation_id)
                job = self._original_job(body.host_id, record["job_id"], refresh=False)
                context = self._context_digest(target, controller_digest, job)
                self._plan(record["plan"], target, mode, configured, context, job)
                if record["plan"]["eligible"] is not True:
                    raise HTTPException(409, "服务激活仍有未通过检查，不能批准执行。")
                first, record = self.store.begin_submission(
                    body.host_id,
                    body.activation_id,
                    body.expected_activation_digest,
                    body.expected_mode_revision,
                    now=self.service.now(),
                )
                if not first:
                    return self._view(record)
            # The durable intent precedes any concurrent mode change; network
            # work must leave the shared local admission boundary available.
            try:
                result = self._root(
                    target,
                    "activation_submit",
                    activation_id=body.activation_id,
                    activation_digest=body.expected_activation_digest,
                    mode_revision=body.expected_mode_revision,
                    context_digest=context,
                )
                return self._view(self._save_result(record, result))
            except RootActivationRejected:
                saved = self.store.outcome(
                    body.host_id,
                    body.activation_id,
                    status="rejected",
                    detail="远端明确拒绝本次服务激活；原补丁与暂停保持。",
                    now=self.service.now(),
                )
            except (PatchClientError, HTTPException, ValueError, OSError, sqlite3.Error):
                saved = self.store.outcome(
                    body.host_id,
                    body.activation_id,
                    status="unknown",
                    detail="原激活提交结果未核实；只查询原 ID，不重新提交。",
                    now=self.service.now(),
                )
            return self._view(saved)

    @staticmethod
    def validate_result(record, result):
        try:
            if (
                set(result) != RECORD_FIELDS
                or type(result.get("schema_version")) is not int
                or result["schema_version"] != 1
                or result.get("status")
                not in REMOTE_ACTIVE | {"verified", "verification_failed", "unknown", "rejected"}
                or result.get("activation_id") != record["activation_id"]
                or result.get("activation_digest") != record["activation_digest"]
                or result.get("host_id") != record["host_id"]
                or result.get("policy_digest") != record["policy_digest"]
                or result.get("context_digest") != record["plan"]["context_digest"]
                or result.get("job_id") != record["job_id"]
                or result.get("job_digest") != record["job_digest"]
                or result.get("job_revision") != record["job_revision"]
                or type(result.get("job_revision")) is not int
                or result.get("driver_source_digest") != record["plan"]["driver_source_digest"]
                or result.get("mode_revision") != record["plan"]["mode_revision"]
                or type(result.get("mode_revision")) is not int
                or any(
                    result.get(key) != record["plan"][key]
                    for key in (
                        "original_job_status",
                        "original_job_sha256",
                        "original_safety_digest",
                        "state_digest",
                        "unit",
                        "package",
                        "architecture",
                        "candidate_version",
                    )
                )
                or canonical(result.get("plan")) != canonical(record["plan"])
                or not _hex(result.get("record_digest"))
                or result["record_digest"]
                != digest({k: v for k, v in result.items() if k != "record_digest"})
                or type(result.get("revision")) is not int
                or result["revision"] < 1
                or result.get("approval_digest")
                != digest(
                    {
                        key: result[key]
                        for key in (
                            "activation_id",
                            "activation_digest",
                            "context_digest",
                            "mode_revision",
                            "approved_at",
                            "expires_at",
                        )
                    }
                )
                or not instant_from(record["plan"]["created_at"])
                <= instant_from(result["approved_at"])
                <= instant_from(record["plan"]["expires_at"])
                or instant_from(result["updated_at"]) < instant_from(result["approved_at"])
            ):
                raise ValueError("Original activation receipt binding changed")
            if result["status"] == "verified":
                verification = result["verification"]
                restart = result["restart_evidence"]
                intent = restart["intent"]
                restart_result = restart["result"]
                if (
                    not isinstance(verification, dict)
                    or any(
                        verification.get(key, {}).get("passed") is not True
                        for key in (
                            "new_process",
                            "exact_package_version",
                            "vendor_rescan",
                            "health",
                            "fresh_ssh",
                        )
                    )
                    or verification.get("runtime", {}).get("status") != "complete"
                    or verification["runtime"].get("outdated_process_count") != 0
                    or result.get("effective_result") != "activation_verified"
                    or result.get("original_job_unchanged") is not True
                    or result.get("original_safety_unchanged") is not True
                    or result.get("local_result") != "verified"
                    or type(result.get("locally_verified_uptime_ticks")) is not int
                    or result["locally_verified_uptime_ticks"] < 0
                    or result.get("boot_id") != record["plan"]["boot_id"]
                    or verification["health"].get("reboot_required") is not False
                    or verification["fresh_ssh"].get("mechanism")
                    != "sshd_connection_started_after_activation_verification"
                    or instant_from(verification["fresh_ssh"]["checked_at"])
                    < instant_from(result["locally_verified_at"])
                    or restart.get("intent_digest") != digest(intent)
                    or restart_result.get("intent_digest") != digest(intent)
                    or intent.get("activation_id") != record["activation_id"]
                    or intent.get("activation_digest") != record["activation_digest"]
                    or intent.get("unit") != record["plan"]["unit"]
                    or intent.get("argv")
                    != ["/usr/bin/systemctl", "restart", record["plan"]["unit"]]
                    or intent.get("boot_id") != record["plan"]["boot_id"]
                    or type(restart_result["result"].get("exit_code")) is not int
                    or restart_result["result"]["exit_code"] != 0
                    or restart_result["result"].get("result_unknown") is not False
                    or not isinstance(result.get("completed_at"), str)
                    or instant_from(result["completed_at"]) < instant_from(result["approved_at"])
                    or instant_from(result["completed_at"])
                    < instant_from(verification["fresh_ssh"]["checked_at"])
                ):
                    raise ValueError("Activation verification is incomplete")
        except (KeyError, IndexError, AttributeError, TypeError, ValueError, RecursionError):
            raise PatchClientError("原激活回执、服务或新的管理连接未能完整核实。") from None

    def _save_result(self, record, result):
        self.validate_result(record, result)
        return self.store.outcome(
            record["host_id"],
            record["activation_id"],
            result=result,
            detail="服务激活及本次验证通过；原安装任务和暂停记录保持。"
            if result["status"] == "verified"
            else "原服务激活状态已更新；未改写补丁任务或解除暂停。",
            now=self.service.now(),
        )

    @staticmethod
    def validate_cached(record):
        result = record.get("result")
        if result is None:
            if record["status"] not in {"prepared", "submission_intent", "unknown", "rejected"}:
                raise PatchClientError("激活缓存缺少原生结果，不能确认验证状态。")
            return
        ActivationService.validate_result(record, result)
        if (
            record.get("root_revision") != result["revision"]
            or record["status"] != result["status"]
            and record["status"] != "unknown"
            or result["status"] in {"verified", "verification_failed", "rejected"}
            and record["status"] != result["status"]
        ):
            raise PatchClientError("激活缓存与原生回执的状态或修订不一致。")

    def poll(self, host_id, activation_id):
        record = self.store.get(host_id, activation_id)
        if record is None or record["status"] in {
            "prepared",
            "verified",
            "verification_failed",
            "rejected",
        }:
            return record
        # A current submit holds this lock while Root performs its bounded
        # admission checks. Polling that in-flight intent would only create an
        # avoidable busy/unknown snapshot; after a process restart no lock is held.
        if self.service.mode_lock.locked():
            return record
        try:
            target = self.service.target(host_id)
            if (
                target.policy_digest != record["policy_digest"]
                or PatchService._automatic_scope(target) != record["scope_hash"]
            ):
                return record
            result = self._root(target, "activation_status", activation_id=activation_id)
            if result.get("status") == "activation_prepared":
                raise PatchClientError("原提交的接收结果仍未能核实。")
            return self._save_result(record, result)
        except (RootActivationRejected, PatchClientError, HTTPException, ValueError, OSError):
            return self.store.outcome(
                host_id,
                activation_id,
                status="unknown",
                detail="原激活回执尚未核实；继续保留原 ID，未重发执行。",
                now=self.service.now(),
            )

    def _view(self, record):
        self.validate_cached(record)
        result = json_copy(record)
        stale = True
        try:
            target = self.service.targets.get(record["host_id"])
            policy, _configured = self._policy()
            stale = (
                target is None
                or target.policy_digest != record["policy_digest"]
                or PatchService._automatic_scope(target) != record["scope_hash"]
                or digest(policy.model_dump(mode="json")) != record["controller_policy_digest"]
            )
        except (ValueError, OSError):
            pass
        result.update(
            original_job_id=record["job_id"],
            original_patch_status="installed_restart_pending",
            stale=stale,
            effective_status="historical"
            if stale
            else "activation_verified"
            if record["status"] == "verified"
            else record["status"],
        )
        return result

    def get(self, host_id, activation_id):
        try:
            identity(host_id, activation_id)
        except ValueError:
            raise HTTPException(404, "服务激活 ID 无效。") from None
        record = self.store.get(host_id, activation_id)
        if record is None:
            raise HTTPException(404, "服务激活记录不存在。")
        return self._view(record)

    def list(self):
        policy, configured = self._policy()
        return {
            "enabled": bool(policy.enabled and configured and configured.get("enabled")),
            "supported_execution_modes": ["assisted"],
            "notification_channel": "console",
            "records": [self._view(record) for record in self.store.list()],
            "original_patch_jobs_modified": False,
        }


def json_copy(value):
    import json

    return json.loads(canonical(value))


def register_activation_routes(application: FastAPI, service: ActivationService, protected):
    router = APIRouter(prefix="/api/service-activations", dependencies=protected)

    def guarded(action):
        try:
            return action()
        except RootActivationRejected:
            raise HTTPException(409, "远端拒绝当前激活预览，原补丁和暂停仍保留。") from None
        except PatchClientError:
            raise HTTPException(503, "服务激活入口或证据暂时未能核实。") from None
        except (ValueError, OSError, sqlite3.Error):
            raise HTTPException(503, "服务激活审计或证据暂时不可用。") from None

    @router.post("/plans")
    def prepare(body: ActivationPrepareRequest):
        return guarded(lambda: service.prepare(body))

    @router.post("")
    def submit(body: ActivationSubmitRequest):
        return guarded(lambda: service.submit(body))

    @router.get("")
    def listed():
        return guarded(service.list)

    @router.get("/{host_id}/{activation_id}")
    def status(host_id: str, activation_id: str):
        return guarded(lambda: service.get(host_id, activation_id))

    @router.post("/{host_id}/{activation_id}/acknowledge")
    def acknowledge(host_id: str, activation_id: str):
        record = guarded(
            lambda: service.store.acknowledge(host_id, activation_id, now=service.service.now())
        )
        if record is None:
            raise HTTPException(404, "服务激活记录不存在。")
        return service._view(record)

    @router.get("/{host_id}/{activation_id}/evidence")
    def evidence(host_id: str, activation_id: str):
        from opsark.activation_evidence import ActivationEvidenceNotFound, build_evidence

        try:
            body = build_evidence(service, host_id, activation_id)
        except ActivationEvidenceNotFound:
            raise HTTPException(404, "服务激活原件不存在。") from None
        except (ValueError, TypeError, KeyError, RecursionError, OSError, sqlite3.Error):
            raise HTTPException(409, "服务激活原件或读取稳定性未能核实。") from None
        return Response(
            canonical(body).encode(),
            media_type="application/json",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="opsark-activation-{activation_id}.json"'
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    application.include_router(router)
