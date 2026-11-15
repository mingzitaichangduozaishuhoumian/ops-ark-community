"""Serial, preauthorized repair orchestration over fresh deterministic evidence."""

import logging
import secrets
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread

from fastapi import HTTPException

from opsark.automatic_store import (
    HEX,
    ID,
    PACKAGE,
    VERSION,
    AutomaticStore,
    digest,
    instant,
)
from opsark.baselines import scope_for
from opsark.control_modes import ControlPolicy, automatic_window_open
from opsark.patch_api import PatchService

logger = logging.getLogger(__name__)


def scope_for_automatic(target):
    return digest(
        {
            "channel": "automatic-patch/v1",
            "host_scope": scope_for(target.host.public),
            "policy_digest": target.policy_digest,
        }
    )


def _time(value):
    if not isinstance(value, str):
        raise ValueError("Missing automatic evidence time")
    return instant(datetime.fromisoformat(value))


def _matches(value, expression):
    return isinstance(value, str) and expression.fullmatch(value) is not None


def _at_limit(used, limit):
    if type(used) is not int or type(limit) is not int or used < 0 or limit < 1:
        raise ValueError("Automatic quota is unknown")
    return used >= limit


def _observed_usage(local, remote):
    if type(local) is not int or type(remote) is not int or min(local, remote) < 0:
        raise ValueError("Automatic quota is unknown")
    return max(local, remote)


class AutomaticMonitor:
    """Never scans or invents actions; only the root SDK can install one exact patch."""

    def __init__(self, service: PatchService, store: AutomaticStore, *, now=None, ai_gate=None):
        self.service = service
        self.store = store
        self.now = now or (lambda: datetime.now(UTC))
        self.owner = secrets.token_hex(16)
        self.interval_seconds = 5
        self.status_interval_seconds = 15
        self.remote_status_interval_seconds = 30
        self.stop_event = Event()
        self.poll_lock = Lock()
        self.thread: Thread | None = None
        self.last_error: str | None = None
        self.status_due = {}
        self.ai_gate = ai_gate
        if self.ai_gate is not None:
            self.ai_gate.is_stopping = self.stop_event.is_set
        self.vulnerability_monitor = None

    def start(self):
        if not self.service.targets or self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = Thread(target=self._run, name="opsark-automatic-repair", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.thread is None or not self.thread.is_alive():
            self.store.release_monitor(self.owner)

    def _policy(self):
        # Revalidation detects mutations and never treats an unreadable grant as empty usage.
        return ControlPolicy.model_validate(self.service.automation.policy.model_dump())

    def _mode(self):
        mode = self.service.automation.status()
        if type(mode.get("revision")) is not int or mode["revision"] < 0:
            raise ValueError("Missing automatic mode revision")
        return mode

    def _gate(self, host_id, policy, mode, at):
        target = self.service.targets[host_id]
        grant = policy.automatic
        quota: dict = {
            "daily_limit": None,
            "daily_used": None,
            "total_limit": None,
            "total_used": None,
        }
        window, remote = None, None
        if grant is not None:
            quota.update(
                daily_limit=grant.max_jobs_per_day,
                total_limit=grant.max_total_jobs,
                **self.store.quotas(host_id, grant.grant_id, now=at),
            )
            window = automatic_window_open(grant, at)
            remote = self.store.remote_admission(
                host_id,
                scope_for_automatic(target),
                target.policy_digest,
                PatchService._root_grant_digest(grant),
                now=at,
            )
            if remote is not None:
                quota["daily_used"] = _observed_usage(
                    quota["daily_used"], remote["usage"]["daily_used"]
                )
                quota["total_used"] = _observed_usage(
                    quota["total_used"], remote["usage"]["total_used"]
                )
        state = {
            "host_id": host_id,
            "name": target.host.public.name,
            "scope_hash": scope_for_automatic(target),
            "last_checked": at.isoformat(),
            "next_check": (at + timedelta(seconds=self.interval_seconds)).isoformat(),
            "maintenance_open": window,
            "grant_expires_at": grant.expires_at.isoformat() if grant else None,
            "grant_digest": grant.grant_digest if grant else None,
            "quota": quota,
            "current_job_id": None,
            "latch": self.store.latch(host_id),
            "remote_status": self.store.remote_state(host_id),
        }
        if state["latch"]:
            status, detail = "latched", "自动通道已持久暂停，等待管理员核实原任务及远端状态。"
        elif (
            not policy.enabled
            or grant is None
            or not grant.enabled
            or host_id not in grant.host_ids
        ):
            status, detail = "disabled", "此目标没有启用明确的自动预授权。"
        elif mode["mode"] != "automatic":
            status, detail = "manual", "当前模式不提交自动任务；已有任务仍按原 ID 跟进。"
        elif mode.get("mode_sync_complete") is not True:
            status, detail = "mode_unsynced", "模式尚未同步，停止新的自动提交。"
        elif grant.target_policy_digests.get(host_id) != target.policy_digest:
            status, detail = "disabled", "远端策略摘要已改变，需要新的明确预授权。"
        elif at >= grant.expires_at:
            status, detail = "expired", "自动预授权已过期。"
        elif not window:
            status, detail = "outside_window", "当前不在已授权的 UTC 维护窗口内。"
        elif _at_limit(quota["daily_used"], quota["daily_limit"]) or _at_limit(
            quota["total_used"], quota["total_limit"]
        ):
            status, detail = "quota_exhausted", "当日或本次预授权的总提交配额已耗尽。"
        elif remote is None:
            status, detail = "error", "远端授权、暂停或配额状态未核实，等待后台只读检查。"
        else:
            status, detail = "idle", "等待新鲜、完整且符合预授权范围的漏洞证据。"
        state.update(state=status, detail=detail)
        return state

    def _save(self, state, *, state_name=None, detail=None, job_id=None):
        previous = self.store.host_state(state["host_id"]) or {}
        if state_name:
            state["state"] = state_name
        if detail:
            state["detail"] = detail
        state["current_job_id"] = job_id
        state["latch"] = self.store.latch(state["host_id"])
        if state["latch"]:
            state["state"] = "latched"
        self.store.set_host_state(state["host_id"], state)
        if previous.get("state") != state["state"] and state["state"] in {"planning", "latched"}:
            logger.info(
                "Automatic repair console state: host=%s state=%s job=%s",
                state["host_id"],
                state["state"],
                job_id or "none",
            )

    def _candidates(self, host_id, scan, grant, at):
        target = self.service.targets[host_id]
        if (
            not isinstance(scan, dict)
            or scan.get("schema_version") != 1
            or type(scan.get("schema_version")) is not int
            or scan.get("host_id") != host_id
            or scan.get("policy_digest") != target.policy_digest
            or not _matches(scan.get("scan_id"), ID)
            or not _matches(scan.get("apt_state_digest"), HEX)
            or scan.get("apt_configuration_safe") is not True
            or not isinstance(scan.get("coverage"), dict)
            or scan["coverage"].get("status") not in {"partial", "complete"}
            or not isinstance(scan.get("findings"), list)
            or not isinstance(scan.get("packages"), list)
        ):
            return []
        try:
            if not 0 <= (at - _time(scan.get("collected_at"))).total_seconds() <= 900:
                return []
        except ValueError:
            return []
        candidates = []
        for finding in scan["findings"]:
            if (
                not isinstance(finding, dict)
                or not _matches(finding.get("finding_id"), HEX)
                or finding.get("package") not in grant.allowed_packages
                or not _matches(finding.get("package"), PACKAGE)
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
                or not _matches(finding.get("vendor_record_digest"), HEX)
                or not _matches(finding.get("current_version"), VERSION)
                or not _matches(finding.get("fixed_binary_version"), VERSION)
                or not isinstance(finding.get("evidence_urls"), list)
                or "https://ubuntu.com/security/notices/" + finding["advisory"]
                not in finding["evidence_urls"]
            ):
                continue
            # The scanner keeps candidate versions in inventory, not in a finding.
            packages = [
                item
                for item in scan["packages"]
                if isinstance(item, dict)
                and item.get("name") == finding["package"]
                and item.get("architecture") == finding.get("architecture")
            ]
            if len(packages) != 1:
                continue
            package = packages[0]
            if (
                package.get("installed_version") != finding["current_version"]
                or not _matches(package.get("candidate_version"), VERSION)
                or package["candidate_version"] == finding["current_version"]
            ):
                continue
            candidates.append((finding, package))
        counts = {}
        for finding, _package in candidates:
            counts[finding["finding_id"]] = counts.get(finding["finding_id"], 0) + 1
        return [item for item in candidates if counts[item[0]["finding_id"]] == 1]

    def _plan_valid(self, plan, candidate, scan, grant, revision, at):
        if not isinstance(plan, dict):
            return False
        try:
            created, expiry = _time(plan.get("created_at")), _time(plan.get("expires_at"))
            if not (
                0 <= (at - created).total_seconds() <= 900
                and 0 <= (at - _time(scan.get("collected_at"))).total_seconds() <= 900
                and expiry > at
                and 0 < (expiry - created).total_seconds() <= 1800
            ):
                return False
        except ValueError:
            return False
        changes, finding = plan.get("package_changes"), plan.get("finding")
        if not isinstance(changes, list) or len(changes) != 1 or not isinstance(finding, dict):
            return False
        change = changes[0]
        if not isinstance(change, dict):
            return False
        originals = [
            item
            for item in scan["findings"]
            if isinstance(item, dict) and item.get("finding_id") == candidate["finding_id"]
        ]
        if len(originals) != 1 or any(
            finding.get(key) != originals[0].get(key)
            for key in (
                "advisory",
                "cve",
                "package",
                "architecture",
                "current_version",
                "fixed_binary_version",
                "vendor_record_digest",
            )
        ):
            return False
        return (
            plan.get("schema_version") == 1
            and type(plan.get("schema_version")) is int
            and plan.get("host_id") == candidate["host_id"]
            and plan.get("policy_digest")
            == self.service.targets[candidate["host_id"]].policy_digest
            and _matches(plan.get("plan_id"), ID)
            and _matches(plan.get("plan_digest"), HEX)
            and type(plan.get("mode_revision")) is int
            and plan["mode_revision"] == revision
            and plan.get("prepared_mode") == "automatic"
            and plan.get("automatic_grant_id") == grant.grant_id
            and _matches(plan.get("automatic_grant_digest"), HEX)
            and plan.get("action") == "os_security_upgrade"
            and plan.get("state_digest") == scan["apt_state_digest"]
            and plan.get("risk_level") in grant.allowed_risk_levels
            and plan.get("requires_reboot") is False
            and type(plan.get("requires_service_restart")) is bool
            and (not plan["requires_service_restart"] or grant.allow_service_restart)
            and isinstance(plan.get("health_before"), dict)
            and plan["health_before"].get("passed") is True
            and all(
                plan.get(key) is True
                for key in (
                    "evidence_complete",
                    "transaction_complete_verified",
                    "restart_impact_verified",
                )
            )
            and finding.get("finding_id") == candidate["finding_id"]
            and finding.get("package") == candidate["package"]
            and finding.get("advisory") in grant.allowed_advisories
            and finding.get("current_version") == candidate["current_version"]
            and all(
                finding.get(key) is True
                for key in (
                    "affected",
                    "candidate_fixable",
                    "vendor_evidence_fresh",
                    "finding_evidence_complete",
                )
            )
            and change.get("name") == candidate["package"]
            and change.get("architecture") == finding.get("architecture")
            and change.get("current_version") == candidate["current_version"]
            and change.get("candidate_version") == candidate["candidate_version"]
            and change.get("fixed_version") == finding.get("fixed_binary_version")
            and _matches(change.get("sha256"), HEX)
            and all(
                change.get(key) is True
                for key in (
                    "vendor_security_origin_verified",
                    "candidate_contains_fixed_verified",
                    "candidate_is_upgrade_verified",
                    "current_is_affected_verified",
                )
            )
        )

    def _follow(self, candidate, at):
        host, job = candidate["host_id"], candidate["job_id"]
        # A different reader may already have cached a later receipt. The
        # recovery owner still has to reconcile the original submission.
        if candidate["state"] == "submission_intent" and not self.store.reconcile_submission_intent(
            candidate["id"], self.owner, now=instant(self.now())
        ):
            return
        if host not in self.service.targets:
            self.store.mark_unknown(candidate["id"], now=at)
            return
        cached = self.service.checked_cached_automatic_job(candidate)
        if cached is not None:
            try:
                self.store.record_result(candidate["id"], cached, now=at)
                if cached.get("status") != "unknown":
                    return
            except (KeyError, TypeError, ValueError):
                self.store.mark_unknown(candidate["id"], now=at)
        if self.status_due.get(job, at) > at:
            return
        self.status_due[job] = at + timedelta(seconds=self.status_interval_seconds)
        before_read = self.store.get(candidate["id"])
        if before_read is None or before_read["state"] not in {"tracking", "unknown"}:
            return
        try:
            result = self.service.job_status(host, job)
            self.store.record_result(candidate["id"], result, now=instant(self.now()))
        except Exception:
            current = self.store.mark_unknown(
                candidate["id"], now=instant(self.now()), expected=before_read
            )
            if current["status"] == "unknown":
                self.last_error = "原自动任务状态未能核实；已持久暂停，不会重新提交安装。"

    def poll_once(self):
        if self.stop_event.is_set() or not self.poll_lock.acquire(blocking=False):
            return
        try:
            self._poll_one()
        finally:
            self.poll_lock.release()

    def _poll_one(self):
        at = instant(self.now())
        if not self.store.claim_monitor(self.owner, now=at):
            return
        self.store.recover_interrupted_plans(self.owner, now=at)
        self._ai_outcomes()
        policy = self._policy()
        grant = policy.automatic
        if grant is not None:
            for host_id in grant.host_ids:
                if host_id not in self.service.targets:
                    continue
                target = self.service.targets[host_id]
                scope = scope_for_automatic(target)
                cached = self.store.remote_state(host_id)
                try:
                    due = cached is None or (
                        cached.get("scope_hash") != scope
                        or cached.get("policy_digest") != target.policy_digest
                        or not 0
                        <= (instant(self.now()) - _time(cached["checked_at"])).total_seconds()
                        < self.remote_status_interval_seconds
                    )
                except (KeyError, TypeError, ValueError):
                    due = True
                if not due:
                    continue
                if self.stop_event.is_set() or not self.store.claim_monitor(
                    self.owner, now=instant(self.now())
                ):
                    return
                try:
                    refresh = getattr(self.service, "refresh_automatic_status", None)
                    if not callable(refresh):
                        raise ValueError("No deterministic root safety reader")
                    refresh(host_id)
                except Exception:
                    self.store.mark_remote_unavailable(
                        host_id, scope, target.policy_digest, now=instant(self.now())
                    )
        active = self.store.active_attempts()
        for candidate in active:
            if self.stop_event.is_set() or not self.store.claim_monitor(
                self.owner, now=instant(self.now())
            ):
                return
            self._follow(candidate, at)
        policy, mode = self._policy(), self._mode()
        pending = self.service.store.pollable_jobs()
        for host_id in self.service.targets:
            state = self._gate(host_id, policy, mode, instant(self.now()))
            self._save(state)
            if state["state"] != "idle":
                continue
            if active or pending:
                self._save(
                    state, state_name="tracking", detail="已有任务待核实，保持一次一个自动任务。"
                )
                continue
            scan = self.service.store.latest_scan(host_id)
            if not isinstance(scan, dict):
                self._save(
                    state, state_name="waiting_scan", detail="尚无可信扫描，等待只读扫描提供证据。"
                )
                continue
            candidates = self._candidates(host_id, scan, policy.automatic, instant(self.now()))
            if not candidates:
                self._save(
                    state,
                    state_name="waiting_scan",
                    detail="等待新鲜且完整的适用漏洞证据；不把缺失结果当作安全。",
                )
                continue
            for finding, package in candidates:
                candidate = self.store.claim_candidate(
                    host_id=host_id,
                    scope_hash=state["scope_hash"],
                    finding_id=finding["finding_id"],
                    package=finding["package"],
                    current_version=finding["current_version"],
                    candidate_version=package["candidate_version"],
                    grant_id=policy.automatic.grant_id,
                    grant_digest=policy.automatic.grant_digest,
                    scan_id=scan["scan_id"],
                    owner=self.owner,
                    now=instant(self.now()),
                )
                if candidate is not None:
                    try:
                        self._execute(candidate, scan, policy, mode, state)
                    except Exception:
                        self.store.mark_unknown(candidate["id"], now=instant(self.now()))
                        self.last_error = "自动编排未完成核实；已持久暂停，保留原任务身份。"
                    return

    def _execute(self, candidate, scan, policy, mode, state):
        cid, host_id, grant = candidate["id"], candidate["host_id"], policy.automatic
        if self.stop_event.is_set() or not self.store.claim_monitor(
            self.owner, now=instant(self.now())
        ):
            self.store.defer(
                cid, "停止或失去编排租约，没有请求模型或准备修复。", now=instant(self.now())
            )
            return
        proof = None
        if policy.automatic_ai is not None and policy.automatic_ai.enabled:
            self._save(
                state, state_name="ai_analyzing", detail="正在核对自动 AI 许可和单次分析结果。"
            )
            if self.ai_gate is not None:
                proof = self.ai_gate.require_proposal(candidate, scan, policy, mode)
            if (
                proof is None
                or self.store.bind_ai_result(cid, self.owner, proof, now=instant(self.now()))
                is None
            ):
                self.store.defer(
                    cid, "AI 提案未能核实，保留原分析，不自动重发。", now=instant(self.now())
                )
                self.store.emit_ai_alert(
                    host_id,
                    cid,
                    "blocked",
                    "AI 提案未通过当前授权和证据核验，没有提交安装。",
                    candidate_id=cid,
                    now=instant(self.now()),
                )
                self._save(
                    state,
                    state_name="ai_blocked",
                    detail="自动 AI 分析被阻断，查看告警及原分析记录。",
                )
                return
        self._save(state, state_name="planning", detail="正在准备绑定当前证据的单包修复方案。")
        if self.stop_event.is_set() or not self.store.claim_monitor(
            self.owner, now=instant(self.now())
        ):
            self.store.defer(cid, "规划前停止，等待新扫描。", now=instant(self.now()))
            return
        try:
            plan = self.service.auto_prepare(
                host_id, candidate["finding_id"], mode["revision"], grant.grant_digest
            )
        except HTTPException as error:
            if 400 <= error.status_code < 500:
                self.store.defer(
                    cid, "远端明确拒绝旧状态方案；等待新扫描重新规划。", now=instant(self.now())
                )
            else:
                self.store.mark_unknown(cid, now=instant(self.now()))
            return
        except Exception:
            self.store.mark_unknown(cid, now=instant(self.now()))
            return
        at = instant(self.now())
        current_policy, current_mode = self._policy(), self._mode()
        current = self._gate(host_id, current_policy, current_mode, at)
        current_scan = self.service.store.latest_scan(host_id)
        if (
            self.stop_event.is_set()
            or current["state"] != "idle"
            or current_mode["revision"] != mode["revision"]
            or current_policy.automatic is None
            or current_policy.automatic.grant_digest != grant.grant_digest
            or current["scope_hash"] != candidate["scope_hash"]
            or not isinstance(current_scan, dict)
            or current_scan.get("scan_id") != scan["scan_id"]
            or not self._plan_valid(plan, candidate, scan, grant, mode["revision"], at)
            or proof is not None
            and (
                self.ai_gate is None
                or not self.ai_gate.validate_proof(
                    candidate, current_scan, current_policy, current_mode, proof
                )
            )
            or not self.store.claim_monitor(self.owner, now=at)
        ):
            self.store.defer(cid, "状态、授权、方案证据或时效已变化；等待新扫描重新规划。", now=at)
            return
        if proof is not None:
            self.store.emit_ai_alert(
                host_id,
                cid,
                "plan_ready",
                "AI 提案与原生单包事务均已核验，准备受限自动提交。",
                candidate_id=cid,
                request_key=proof["request_key"],
                now=at,
            )
        reserved = self.store.reserve_submission(
            cid,
            plan,
            mode["revision"],
            daily_limit=grant.max_jobs_per_day,
            total_limit=grant.max_total_jobs,
            now=at,
        )
        if reserved is None:
            return
        if self.stop_event.is_set() or not self.store.claim_monitor(
            self.owner, now=instant(self.now())
        ):
            self.store.mark_unknown(cid, now=instant(self.now()))
            return
        try:
            result = self.service.auto_submit(
                host_id,
                plan["plan_id"],
                plan["plan_digest"],
                mode["revision"],
                grant.grant_digest,
                reserved["job_id"],
            )
            self.store.record_result(cid, result, now=instant(self.now()))
            self.last_error = None
        except Exception:
            self.store.mark_unknown(cid, now=instant(self.now()))
            self.last_error = "自动提交结果未知；只查询原任务，已停止新的自动动作。"
        self._save(
            current,
            state_name="tracking",
            detail="自动提交意图和任务已保存，后续只读取原任务状态。",
            job_id=reserved["job_id"],
        )

    def status(self):
        at, policy, mode = instant(self.now()), self._policy(), self._mode()
        hosts = []
        for host_id in self.service.targets:
            state = self._gate(host_id, policy, mode, at)
            saved = self.store.host_state(host_id)
            if (
                saved
                and saved.get("scope_hash") == state["scope_hash"]
                and state["state"] == "idle"
            ):
                for key in ("state", "detail", "last_checked", "next_check", "current_job_id"):
                    if key in saved:
                        state[key] = saved[key]
            hosts.append(state)
        grant = policy.automatic
        return {
            "enabled": bool(policy.enabled and grant and grant.enabled),
            "running": bool(
                self.thread and self.thread.is_alive() and not self.stop_event.is_set()
            ),
            "mode": mode["mode"],
            "mode_revision": mode["revision"],
            "mode_sync_complete": mode.get("mode_sync_complete") is True,
            "interval_seconds": self.interval_seconds,
            "remote_status_interval_seconds": self.remote_status_interval_seconds,
            "read_only": False,
            "notification_channel": "console",
            "last_error": self.last_error,
            "grants": [grant.model_dump(mode="json")] if grant else [],
            "hosts": hosts,
            "latched_hosts": self.store.latched_hosts(),
            "jobs": [
                {key: value for key, value in job.items() if key != "root_grant_digest"}
                for job in self.store.list_attempts()
            ],
            "ai": self.ai_gate.status() if self.ai_gate is not None else None,
        }

    def _ai_outcomes(self):
        """Reconcile persisted outcomes after crashes, including while mode is manual."""
        if self.ai_gate is None:
            return
        for candidate in self.store.ai_outcomes():
            proof = candidate["ai_proof"]
            verified = candidate.get("status") == "verified"
            self.store.emit_ai_alert(
                candidate["host_id"],
                candidate["id"],
                "repair_verified" if verified else "repair_failed",
                "原自动任务已完成所记录的漏洞复扫与服务验证。"
                if verified
                else "原自动任务存在失败、未知或验证待办，已保留任务并停止新的执行。",
                candidate_id=candidate["id"],
                request_key=proof["request_key"],
                job_id=candidate["job_id"],
                now=instant(self.now()),
            )
            if verified and self.vulnerability_monitor is not None:
                self.vulnerability_monitor.request_rescan(
                    candidate["host_id"],
                    candidate["job_id"],
                    expected_scope=candidate["scope_hash"],
                )

    def _run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    self.poll_once()
                except Exception:
                    self.last_error = "自动编排状态未能核实，停止本轮新的提交。"
                    logger.warning("Automatic repair state unavailable; no new action authorized.")
                self.stop_event.wait(self.interval_seconds)
        finally:
            self.store.release_monitor(self.owner)
