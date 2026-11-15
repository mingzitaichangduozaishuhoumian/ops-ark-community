"""Separate, bounded approval identities for resolving an activation-backed pause."""

import hashlib
import json
from datetime import datetime
from pathlib import Path

from opsark.automatic_store import (
    AutomaticStore,
    binding,
    canonical,
    digest,
    instant,
    safety_digest,
)

MAX_RECORDS = 1000
MAX_RECORD_BYTES = 262_144
MAX_TOTAL_BYTES = 64 * 1024 * 1024
STATES = frozenset(
    {"prepared", "submission_intent", "unknown", "verified", "rejected", "superseded"}
)
PENDING = frozenset({"submission_intent", "unknown"})
ANCHORS = (
    "host_id",
    "recovery_id",
    "recovery_digest",
    "job_id",
    "job_revision",
    "job_digest",
    "activation_id",
    "scope_hash",
    "policy_digest",
    "controller_policy_digest",
    "context_digest",
    "mode_revision",
    "plan",
    "original_job",
    "original_activation",
    "latch_before",
    "candidate_binding",
)
REQUIRED_RECEIPT_CHECKS = frozenset(
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
        "prepared_eligible",
        "plan_valid",
        "job_unchanged",
        "activation_unchanged",
        "state_unchanged",
        "final_ledger_settled",
        "policy_unchanged",
        "pause_unchanged",
        "usage_unchanged",
        "fresh_ssh",
    }
)


def _copy(value):
    text = canonical(value)
    if len(text.encode()) > MAX_RECORD_BYTES:
        raise ValueError("Activation recovery evidence exceeded its record budget")
    return json.loads(text)


def _id(value):
    return (
        isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)
    )


def _hex(value):
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _anchor(value):
    return digest({key: value[key] for key in ANCHORS})


def _candidate_binding(value):
    if value is None:
        return None
    return {
        key: value.get(key)
        for key in ("id", "host_id", "scope_hash", "job_id", "plan_id", "submitted_day")
    }


def verified_facts(activation, verification, state_digest):
    """Validate concrete observations as well as the native check summary."""
    version = activation["plan"]["candidate_version"]
    observed_process = activation["result"]["verification"]["new_process"]["after"]
    if (
        not isinstance(verification, dict)
        or not isinstance(observed_process, dict)
        or not observed_process
        or any(
            verification.get(key, {}).get("passed") is not True
            for key in (
                "exact_package_version",
                "health",
                "vendor_rescan",
                "activation_process",
                "final_package_state",
            )
        )
        or verification["exact_package_version"].get("expected") != version
        or verification["exact_package_version"].get("observed") != version
        or verification["final_package_state"].get("expected") != version
        or verification["final_package_state"].get("observed") != version
        or verification["final_package_state"].get("apt_configuration_safe") is not True
        or verification["final_package_state"].get("apt_state_digest") != state_digest
        or verification.get("runtime", {}).get("status") != "complete"
        or type(verification["runtime"].get("outdated_process_count")) is not int
        or verification["runtime"]["outdated_process_count"] != 0
        or verification["health"].get("reboot_required") is not False
        or verification["activation_process"].get("observed") != observed_process
        or not isinstance(verification["vendor_rescan"].get("finding_id"), str)
        or not verification["vendor_rescan"]["finding_id"]
    ):
        raise ValueError("Activation recovery concrete observations are incomplete")


class ActivationRecoveryStore:
    """Uses automatic.sqlite3; never evicts history, grants, attempts, or old pauses."""

    def __init__(self, path: Path, *, automatic=None):
        self.path = path
        self.automatic = automatic or AutomaticStore(path)
        if self.automatic.path != path:
            raise ValueError("Recovery and automatic latches must share the same database")
        with self.automatic._connection() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS activation_recoveries("
                "host_id TEXT NOT NULL,recovery_id TEXT NOT NULL,status TEXT NOT NULL,"
                "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,anchor_digest TEXT NOT NULL,"
                "payload TEXT NOT NULL,PRIMARY KEY(host_id,recovery_id));"
                "CREATE TABLE IF NOT EXISTS activation_recovery_resolved_jobs("
                "host_id TEXT NOT NULL,scope_hash TEXT NOT NULL,job_id TEXT NOT NULL,"
                "job_digest TEXT NOT NULL,recovery_id TEXT NOT NULL,receipt_digest TEXT NOT NULL,"
                "PRIMARY KEY(host_id,scope_hash,job_id,job_digest));"
            )

    @staticmethod
    def _read(row):
        if row is None:
            return None
        value = _copy(json.loads(row["payload"]))
        if (
            type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("kind") != "activation_recovery"
            or value.get("host_id") != row["host_id"]
            or value.get("recovery_id") != row["recovery_id"]
            or value.get("status") != row["status"]
            or value["status"] not in STATES
            or value.get("created_at") != row["created_at"]
            or value.get("updated_at") != row["updated_at"]
            or _anchor(value) != row["anchor_digest"]
            or not _id(value["recovery_id"])
            or not _id(value.get("activation_id"))
            or not _hex(value.get("recovery_digest"))
            or not _hex(value.get("context_digest"))
            or value["context_digest"] != digest(value["latch_before"])
            or digest(value["original_job"]) != value["job_digest"]
            or value["plan"].get("recovery_digest") != value["recovery_digest"]
            or value["plan"]["recovery_digest"]
            != digest(
                {key: item for key, item in value["plan"].items() if key != "recovery_digest"}
            )
            or value["plan"].get("mode_revision") != value["mode_revision"]
            or type(value.get("local_released")) is not bool
            or value["local_released"] is not (value["status"] == "verified")
        ):
            raise ValueError("Activation recovery record binding is inconsistent")
        return value

    @staticmethod
    def _write(connection, value):
        text = canonical(_copy(value))
        used = connection.execute(
            "SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM activation_recoveries "
            "WHERE NOT(host_id=? AND recovery_id=?)",
            (value["host_id"], value["recovery_id"]),
        ).fetchone()[0]
        if used + len(text.encode()) > MAX_TOTAL_BYTES:
            raise ValueError("Activation recovery ledger is full; original history is retained")
        connection.execute(
            "INSERT INTO activation_recoveries VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,recovery_id) DO UPDATE SET status=excluded.status,"
            "updated_at=excluded.updated_at,payload=excluded.payload",
            (
                value["host_id"],
                value["recovery_id"],
                value["status"],
                value["created_at"],
                value["updated_at"],
                _anchor(value),
                text,
            ),
        )

    def get(self, host_id, recovery_id):
        binding(host_id)
        if not _id(recovery_id):
            raise ValueError("Invalid recovery identity")
        with self.automatic._connection() as connection:
            return self._read(
                connection.execute(
                    "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )

    def list(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= MAX_RECORDS:
            raise ValueError("Invalid recovery list budget")
        with self.automatic._connection() as connection:
            return [
                self._read(row)
                for row in connection.execute(
                    "SELECT * FROM activation_recoveries ORDER BY CASE WHEN status IN "
                    "('submission_intent','unknown') THEN 0 ELSE 1 END,"
                    "updated_at DESC,host_id,recovery_id "
                    "LIMIT ?",
                    (limit,),
                )
            ]

    def pending(self, host_id):
        binding(host_id)
        return next(
            (
                item
                for item in self.list(limit=MAX_RECORDS)
                if item["host_id"] == host_id and item["status"] in PENDING
            ),
            None,
        )

    def save_plan(
        self,
        host_id,
        plan,
        *,
        scope_hash,
        controller_policy_digest,
        original_job,
        original_activation,
        latch,
        now=None,
    ):
        binding(host_id, scope_hash)
        if not _hex(controller_policy_digest) or not _id(plan.get("recovery_id")):
            raise ValueError("Recovery source is unavailable")
        at = instant(now).isoformat()
        value = _copy(
            {
                "schema_version": 1,
                "kind": "activation_recovery",
                "host_id": host_id,
                **{
                    key: plan[key]
                    for key in (
                        "recovery_id",
                        "recovery_digest",
                        "job_id",
                        "job_revision",
                        "job_digest",
                        "activation_id",
                        "policy_digest",
                        "context_digest",
                        "mode_revision",
                    )
                },
                "scope_hash": scope_hash,
                "controller_policy_digest": controller_policy_digest,
                "plan": plan,
                "original_job": original_job,
                "original_activation": original_activation,
                "latch_before": latch,
                "candidate_binding": _candidate_binding(
                    self.automatic.get_by_job(host_id, plan["job_id"])
                ),
                "status": "prepared",
                "local_released": False,
                "created_at": at,
                "updated_at": at,
                "confirmed_at": None,
                "completed_at": None,
                "receipt": None,
                "root_outcome": None,
                "detail": "已保存独立恢复预览；原安装任务、激活和暂停保持。",
            }
        )
        if value["context_digest"] != digest(latch) or digest(original_job) != value["job_digest"]:
            raise ValueError("Recovery original snapshots do not match the reviewed anchors")
        with self.automatic._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self.automatic._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1",
                    (host_id,),
                ).fetchone()
            )
            if current is None or digest(current) != value["context_digest"]:
                raise ValueError("Current pause changed during recovery planning")
            old = self._read(
                connection.execute(
                    "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, value["recovery_id"]),
                ).fetchone()
            )
            if old is not None:
                if _anchor(old) != _anchor(value):
                    raise ValueError("Recovery identity already has another immutable source")
                return old
            if (
                connection.execute("SELECT COUNT(*) FROM activation_recoveries").fetchone()[0]
                >= MAX_RECORDS
            ):
                raise ValueError("Activation recovery identity ledger is full")
            pending = connection.execute(
                "SELECT 1 FROM activation_recoveries WHERE host_id=? AND status IN "
                "('submission_intent','unknown') LIMIT 1",
                (host_id,),
            ).fetchone()
            if pending is not None:
                raise ValueError("An original activation recovery is still unresolved")
            self._write(connection, value)
        return value

    def begin_submission(self, host_id, recovery_id, recovery_digest, mode_revision, *, now=None):
        at = instant(now)
        with self.automatic._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._read(
                connection.execute(
                    "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None:
                raise ValueError("Original recovery preview is absent")
            if (
                value["recovery_digest"] != recovery_digest
                or value["plan"]["mode_revision"] != mode_revision
            ):
                raise ValueError("Approval does not match the immutable recovery preview")
            if value["status"] != "prepared":
                return False, value
            other = connection.execute(
                "SELECT 1 FROM activation_recoveries WHERE host_id=? AND recovery_id!=? "
                "AND status IN ('submission_intent','unknown') LIMIT 1",
                (host_id, recovery_id),
            ).fetchone()
            if other is not None:
                raise ValueError("Another original activation recovery remains unresolved")
            plan = value["plan"]
            if not plan["eligible"] or not datetime.fromisoformat(
                plan["created_at"]
            ) <= at < datetime.fromisoformat(plan["expires_at"]):
                raise ValueError("Recovery preview is blocked or expired")
            current = self.automatic._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1",
                    (host_id,),
                ).fetchone()
            )
            if current is None or digest(current) != value["context_digest"]:
                raise ValueError("The approved pause is no longer current")
            value.update(
                status="submission_intent",
                confirmed_at=at.isoformat(),
                updated_at=at.isoformat(),
                detail="独立恢复批准已保存；仅跟进原恢复 ID，不重复提交。",
            )
            self._write(connection, value)
            return True, value

    @staticmethod
    def _bound_receipt(value, receipt):
        from opsark.activation_recovery_api import (
            ANCHORS,
            IDENTITY,
            PLAN_FIELDS,
            RECEIPT_FIELDS,
            REQUIRED_CHECKS,
        )
        from opsark.recovery_api import _checks, _safety

        plan = value["plan"]
        fingerprints = (ANCHORS - {"activation_id", "activation_revision"}) | {
            "policy_digest",
            "driver_source_digest",
            "job_digest",
            "context_digest",
            "recovery_digest",
            "state_digest",
            "root_safety_digest",
        }
        if (
            set(plan) != PLAN_FIELDS
            or type(plan["schema_version"]) is not int
            or plan["schema_version"] != 1
            or plan["kind"] != "activation_recovery"
            or plan["status"] != "activation_recovery_prepared"
            or plan["eligible"] is not True
            or any(not _hex(plan[key]) for key in fingerprints)
            or not _id(plan["recovery_id"])
            or not _id(plan["job_id"])
            or not _id(plan["activation_id"])
            or any(
                type(plan[key]) is not int or plan[key] < 1
                for key in ("job_revision", "activation_revision")
            )
            or type(plan["mode_revision"]) is not int
            or plan["mode_revision"] < 0
            or _checks(plan["checks"]) != plan["blockers"]
            or plan["blockers"]
            or {check["id"] for check in plan["checks"]} != REQUIRED_CHECKS
            or not isinstance(receipt, dict)
            or set(receipt) != RECEIPT_FIELDS
            or _checks(receipt["checks"]) != receipt["blockers"]
        ):
            raise ValueError("Activation recovery plan or receipt schema is incomplete")
        _safety(plan["root_safety_before"])
        _safety(receipt["safety_before"])
        _safety(receipt["safety_after"])
        fixed = IDENTITY | ANCHORS
        if (
            not isinstance(receipt, dict)
            or receipt.get("kind") != "activation_recovery"
            or type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] != 1
            or receipt.get("status") not in {"verified", "rejected"}
            or receipt.get("receipt_digest")
            != digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
            or receipt.get("plan") != plan
            or any(receipt.get(key) != plan[key] for key in fixed | {"recovery_digest"})
            or receipt.get("resolved_safety_digest") != plan["root_safety_digest"]
            or safety_digest(receipt.get("safety_before", {})) != plan["root_safety_digest"]
        ):
            raise ValueError("The native recovery receipt does not match its original plan")
        if receipt["status"] == "rejected" and (
            not receipt["blockers"]
            or receipt["resolved_job"] is not None
            or receipt["verified_activation"] is not None
        ):
            raise ValueError("A rejected receipt cannot claim effective recovery")
        if receipt["status"] == "verified" and (
            receipt.get("blockers")
            or not receipt.get("checks")
            or any(check.get("status") != "passed" for check in receipt["checks"])
            or not {check.get("id") for check in receipt["checks"]} >= REQUIRED_RECEIPT_CHECKS
            or receipt.get("verification", {}).get("fresh_ssh", {}).get("passed") is not True
            or receipt["verification"]["fresh_ssh"].get("mechanism")
            != "sshd_connection_started_after_activation_recovery_preview"
            or any(
                receipt["verification"].get(key, {}).get("passed") is not True
                for key in (
                    "exact_package_version",
                    "health",
                    "vendor_rescan",
                    "final_package_state",
                )
            )
            or receipt["verification"].get("runtime", {}).get("status") != "complete"
            or receipt["verification"]["runtime"].get("outdated_process_count") != 0
            or receipt["verification"]["health"].get("reboot_required") is not False
            or receipt.get("root_usage_before") != plan["root_usage_before"]
            or receipt.get("root_usage_after") != plan["root_usage_before"]
            or receipt.get("resolved_job")
            != {
                "job_id": value["job_id"],
                "revision": value["job_revision"],
                "job_digest": value["job_digest"],
                "status": "installed_restart_pending",
            }
            or receipt.get("verified_activation")
            != {
                "activation_id": plan["activation_id"],
                "revision": plan["activation_revision"],
                "activation_digest": plan["activation_digest"],
                "record_digest": plan["activation_record_digest"],
                "status": "verified",
            }
            or receipt.get("safety_after", {}).get("paused") is not False
            or receipt.get("safety_after_digest") != safety_digest(receipt["safety_after"])
            or receipt["safety_after"].get("reason") is not None
            or receipt["safety_after"].get("job_id") is not None
            or not datetime.fromisoformat(plan["created_at"])
            <= datetime.fromisoformat(receipt["completed_at"])
            < datetime.fromisoformat(plan["expires_at"])
        ):
            raise ValueError("Verified recovery receipt lacks exact complete proof")
        if receipt["status"] == "verified":
            verified_facts(value["original_activation"], plan["verification"], plan["state_digest"])
            verified_facts(
                value["original_activation"], receipt["verification"], plan["state_digest"]
            )
            if (
                receipt["verification"]["vendor_rescan"]["finding_id"]
                != plan["verification"]["vendor_rescan"]["finding_id"]
                or not datetime.fromisoformat(plan["created_at"])
                <= datetime.fromisoformat(receipt["verification"]["fresh_ssh"]["checked_at"])
                <= datetime.fromisoformat(receipt["completed_at"])
                or value["confirmed_at"] is None
                or datetime.fromisoformat(receipt["completed_at"])
                < datetime.fromisoformat(value["confirmed_at"])
            ):
                raise ValueError("Recovery observation or fresh transport binding changed")

    @classmethod
    def _remember(cls, connection, value, receipt):
        cls._bound_receipt(value, receipt)
        if receipt["status"] == "verified":
            connection.execute(
                "INSERT OR IGNORE INTO automatic_resolved_causes VALUES(?,?,?,?,?)",
                (
                    value["host_id"],
                    value["policy_digest"],
                    receipt["resolved_safety_digest"],
                    value["recovery_id"],
                    receipt["receipt_digest"],
                ),
            )

    def outcome(self, host_id, recovery_id, status, *, receipt=None, detail, now=None):
        if status not in {"unknown", "rejected", "superseded"}:
            raise ValueError("Invalid recovery tracking status")
        with self.automatic._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._read(
                connection.execute(
                    "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None or value["status"] == "prepared":
                raise ValueError("No original approved recovery exists")
            if value["status"] in {"verified", "rejected", "superseded"}:
                return value
            value.update(
                status=status, updated_at=instant(now).isoformat(), detail=str(detail)[:500]
            )
            if receipt is not None:
                self._remember(connection, value, receipt)
                value.update(receipt=receipt, root_outcome=receipt["status"])
            self._write(connection, value)
            return value

    def complete(self, host_id, recovery_id, receipt, remote_state, *, now=None):
        at = instant(now)
        with self.automatic._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._read(
                connection.execute(
                    "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None or value["status"] == "prepared":
                raise ValueError("Original recovery approval is missing")
            if value["status"] == "verified":
                return value
            if value["status"] in {"rejected", "superseded"}:
                raise ValueError("A retired recovery cannot release a current pause")
            self._bound_receipt(value, receipt)
            current = self.automatic._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1",
                    (host_id,),
                ).fetchone()
            )
            current_remote = self.automatic._record(
                connection.execute(
                    "SELECT payload FROM automatic_remote_states WHERE host_id=?",
                    (host_id,),
                ).fetchone()
            )
            checked = datetime.fromisoformat(remote_state["checked_at"])
            if (
                receipt["status"] != "verified"
                or current_remote != remote_state
                or current is None
                or digest(current) != value["context_digest"]
                or not 0 <= (at - checked).total_seconds() <= 60
                or checked < datetime.fromisoformat(receipt["completed_at"])
                or remote_state.get("status") != "available"
                or remote_state.get("host_id") != host_id
                or remote_state.get("scope_hash") != value["scope_hash"]
                or remote_state.get("policy_digest") != value["policy_digest"]
                or remote_state.get("remote", {}).get("safety", {}).get("paused") is not False
                or safety_digest(remote_state["remote"]["safety"]) != receipt["safety_after_digest"]
            ):
                raise ValueError(
                    "Current exact pause and fresh post-receipt Root state do not match"
                )
            self._remember(connection, value, receipt)
            connection.execute(
                "INSERT OR IGNORE INTO automatic_latch_history VALUES(?,?,?)",
                (value["context_digest"], host_id, canonical(current)),
            )
            resolved = {
                **current,
                "resolution": {
                    "kind": "activation_recovery",
                    "recovery_id": recovery_id,
                    "receipt_digest": receipt["receipt_digest"],
                    "resolved_at": at.isoformat(),
                    "policy_digest": value["policy_digest"],
                    "resolved_safety_digest": receipt["resolved_safety_digest"],
                },
            }
            connection.execute(
                "UPDATE automatic_latches SET payload=?,active=0 WHERE host_id=?",
                (canonical(resolved), host_id),
            )
            candidate = self.automatic._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE host_id=? AND job_id=?",
                    (host_id, value["job_id"]),
                ).fetchone()
            )
            if (
                candidate is not None
                and candidate.get("submitted_day") is not None
                and (candidate.get("plan_id") == value["original_job"]["plan_id"])
                and _candidate_binding(candidate) == value["candidate_binding"]
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO activation_recovery_resolved_jobs VALUES(?,?,?,?,?,?)",
                    (
                        host_id,
                        candidate["scope_hash"],
                        value["job_id"],
                        value["job_digest"],
                        recovery_id,
                        receipt["receipt_digest"],
                    ),
                )
            value.update(
                status="verified",
                local_released=True,
                receipt=receipt,
                root_outcome="verified",
                completed_at=at.isoformat(),
                updated_at=at.isoformat(),
                detail="仅本次原暂停已明确对账；原安装和激活记录、模式、授权及配额均保持。",
            )
            self._write(connection, value)
            return value


def verified_source(value):
    """Recheck immutable parent/activation facts when consuming a saved resolution."""
    plan, activation, job = value["plan"], value["original_activation"], value["original_job"]
    raw = plan["root_safety_before_raw"].encode("utf-8")
    if (
        job.get("authorization") != "automatic"
        or job.get("status") != "installed_restart_pending"
        or job.get("host_id") != value["host_id"]
        or job.get("job_id") != value["job_id"]
        or type(job.get("revision")) is not int
        or job["revision"] != value["job_revision"]
        or type(job.get("install_exit_code")) is not int
        or job["install_exit_code"] != 0
        or job.get("verification", {}).get("fresh_ssh", {}).get("passed") is not True
        or any(
            plan[key] != value[key]
            for key in ("host_id", "job_id", "job_revision", "job_digest", "activation_id")
        )
        or activation["status"] != "verified"
        or activation["result"]["status"] != "verified"
        or activation["original_job"] != job
        or activation["job_id"] != value["job_id"]
        or activation["job_revision"] != value["job_revision"]
        or activation["job_digest"] != value["job_digest"]
        or activation["activation_id"] != value["activation_id"]
        or activation["activation_digest"] != plan["activation_digest"]
        or activation["result"]["revision"] != plan["activation_revision"]
        or activation["result"]["record_digest"] != plan["activation_record_digest"]
        or digest(activation["result"]) != plan["activation_raw_sha256"]
        or digest(activation["plan"]) != plan["activation_plan_sha256"]
        or digest(activation["result"]["restart_evidence"]["intent"])
        != plan["restart_intent_sha256"]
        or any(
            activation["plan"][key] != plan[key]
            for key in ("original_job_sha256", "original_plan_sha256", "runtime_manifest_sha256")
        )
        or not 1 <= len(raw) <= 8192
        or hashlib.sha256(raw).hexdigest() != plan["root_safety_raw_sha256"]
        or activation["plan"]["original_safety_digest"] != plan["root_safety_raw_sha256"]
        or json.loads(raw) != plan["root_safety_before"]
    ):
        raise ValueError("Activation recovery original source binding changed")
    from opsark.activation_api import ActivationService

    ActivationService.validate_cached(activation)


def resolved_pending_job(connection, candidate, job):
    """A late identical pending receipt cannot re-latch its already reviewed cause."""
    if job.get("status") != "installed_restart_pending":
        return False
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='activation_recovery_resolved_jobs'"
    ).fetchone()
    if exists is None:
        return False
    raw = {
        key: value
        for key, value in job.items()
        if key not in {"received_at", "notification_due", "notification_count", "last_notified_at"}
    }
    row = connection.execute(
        "SELECT r.*,j.receipt_digest AS resolved_receipt_digest,"
        "j.scope_hash AS resolved_scope,j.job_digest AS resolved_job_digest "
        "FROM activation_recoveries r JOIN activation_recovery_resolved_jobs j "
        "ON r.host_id=j.host_id AND r.recovery_id=j.recovery_id "
        "WHERE j.host_id=? AND j.scope_hash=? "
        "AND j.job_id=? AND j.job_digest=? AND r.status='verified'",
        (candidate["host_id"], candidate["scope_hash"], job.get("job_id"), digest(raw)),
    ).fetchone()
    value = ActivationRecoveryStore._read(row)
    if value is None or not value["local_released"]:
        return False
    if (
        row["resolved_receipt_digest"] != value["receipt"]["receipt_digest"]
        or row["resolved_job_digest"] != value["job_digest"]
        or value["candidate_binding"] != _candidate_binding(candidate)
        or row["resolved_scope"] != candidate["scope_hash"]
    ):
        raise ValueError("Activation recovery late-result resolution binding changed")
    ActivationRecoveryStore._bound_receipt(value, value["receipt"])
    verified_source(value)
    return True


def resolved_root_cause(
    connection, host_id, policy_digest, cause_digest, recovery_id, receipt_digest
):
    """Only an intact saved native result can suppress its exact late Root pause."""
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='activation_recoveries'"
    ).fetchone()
    if exists is None:
        return False
    value = ActivationRecoveryStore._read(
        connection.execute(
            "SELECT * FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
            (host_id, recovery_id),
        ).fetchone()
    )
    if value is None:
        return False
    receipt, plan = value["receipt"], value["plan"]
    if (
        value["status"] not in {"unknown", "verified", "superseded"}
        or value["policy_digest"] != policy_digest
        or receipt is None
        or receipt["status"] != "verified"
        or receipt["receipt_digest"] != receipt_digest
        or receipt["resolved_safety_digest"] != cause_digest
        or plan["root_safety_digest"] != cause_digest
        or plan["eligible"] is not True
        or plan["root_safety_before"]["paused"] is not True
        or plan["root_safety_before"]["job_id"] != value["job_id"]
        or plan["root_safety_before"]["reason"] != "automatic_job_installed_restart_pending"
    ):
        raise ValueError("Activation recovery Root cause has no exact verified source")
    ActivationRecoveryStore._bound_receipt(value, receipt)
    verified_source(value)
    return True
