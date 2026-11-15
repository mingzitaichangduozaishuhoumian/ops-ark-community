"""Durable automatic attempt identities, quotas and non-clearing safety latches."""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from opsark.redaction import redact

HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,79}\Z")
VERSION = re.compile(r"[0-9][0-9A-Za-z.+:~_-]{0,159}\Z")
ACTIVE = {"planning", "ready", "submission_intent", "tracking", "unknown"}
REMOTE_ACTIVE = {
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "awaiting_transport_verification",
    "running_overdue",
}
FAILURES = {
    "unknown",
    "failed",
    "verification_failed",
    "reboot_pending",
    "installed_restart_pending",
    "rejected",
    "running_overdue",
}
MAX_ATTEMPTS = 5000
MAX_RECOVERIES = 1000
MAX_RECOVERY_BYTES = 262_144
MAX_AI_REQUESTS = 5000
MAX_AI_ALERTS = 10_000
AI_TERMINAL = {"completed", "failed", "unknown", "refused", "stale"}
AI_ALERT_KINDS = {
    "analysis_started",
    "analysis_completed",
    "analysis_failed",
    "egress_blocked",
    "no_proposal",
    "plan_ready",
    "repair_verified",
    "repair_failed",
    "blocked",
    "analysis_unknown",
}
AI_REF_FIELDS = {
    "analysis_id",
    "analysis_digest",
    "proposal_id",
    "candidate_id",
    "input_digest",
    "provider_fingerprint",
}
EVENT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


def instant(value=None):
    result = value or datetime.now(UTC)
    if not isinstance(result, datetime) or result.tzinfo is None:
        raise ValueError("Automatic authorization needs an aware time")
    return result.astimezone(UTC)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def safety_digest(value):
    """An unpaused root has no cause timestamp; its semantic state is stable."""
    return digest(
        value
        if value.get("paused") is True
        else {key: item for key, item in value.items() if key != "updated_at"}
    )


def binding(host_id, scope_hash=None):
    if not isinstance(host_id, str) or not HOST.fullmatch(host_id):
        raise ValueError("Invalid automatic host")
    if scope_hash is not None and (
        not isinstance(scope_hash, str) or not HEX.fullmatch(scope_hash)
    ):
        raise ValueError("Invalid automatic scope")


def _identity(value, pattern):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("Invalid automatic binding")
    return value


def candidate_identity(host_id, scope_hash, finding_id, current_version, candidate_version):
    binding(host_id, scope_hash)
    _identity(finding_id, HEX)
    for version in (current_version, candidate_version):
        _identity(version, VERSION)
    return digest(
        {
            "channel": "automatic-patch/v1",
            "host_id": host_id,
            "scope_hash": scope_hash,
            "finding_id": finding_id,
            "current_version": current_version,
            "candidate_version": candidate_version,
        }
    )


def _ai_detail(value):
    if not isinstance(value, str) or len(value.encode()) > 16_384:
        raise ValueError("AI audit detail must be bounded program-owned text")
    if any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in value):
        raise ValueError("AI audit detail contains hidden control characters")
    return redact(value).strip()[:500]


def _ai_ref(value, request):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - AI_REF_FIELDS:
        raise ValueError("AI result reference cannot carry model output or extra fields")
    if len(canonical(value).encode()) > 2048:
        raise ValueError("AI result reference exceeded its budget")
    for name, item in value.items():
        if name in {"proposal_id", "candidate_id"} and item is None:
            continue
        _identity(item, HOST if name == "candidate_id" else ID if name.endswith("_id") else HEX)
    for name in ("analysis_id", "input_digest", "provider_fingerprint"):
        if name not in value or value[name] != request[name]:
            raise ValueError("AI result reference changed its original request binding")
    return dict(value)


class AutomaticStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._check_paths(allow_missing=True)
        with self._connection(creating=True) as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS automatic_candidates("
                "id TEXT PRIMARY KEY,host_id TEXT NOT NULL,scope_hash TEXT NOT NULL,"
                "state TEXT NOT NULL,grant_id TEXT NOT NULL,job_id TEXT NOT NULL UNIQUE,"
                "submitted_day TEXT,"
                "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,payload TEXT NOT NULL);"
                "CREATE INDEX IF NOT EXISTS automatic_host_state "
                "ON automatic_candidates(host_id,state);"
                "CREATE TABLE IF NOT EXISTS automatic_latches("
                "host_id TEXT PRIMARY KEY,payload TEXT NOT NULL,"
                "active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));"
                "CREATE TABLE IF NOT EXISTS automatic_host_states("
                "host_id TEXT PRIMARY KEY,payload TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS automatic_remote_states("
                "host_id TEXT PRIMARY KEY,payload TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS automatic_monitor_lease("
                "id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires_at REAL NOT NULL);"
                "CREATE TABLE IF NOT EXISTS automatic_latch_history("
                "id TEXT PRIMARY KEY,host_id TEXT NOT NULL,payload TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS automatic_recoveries("
                "host_id TEXT NOT NULL,recovery_id TEXT NOT NULL,status TEXT NOT NULL,"
                "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,payload TEXT NOT NULL,"
                "PRIMARY KEY(host_id,recovery_id));"
                "CREATE TABLE IF NOT EXISTS automatic_resolved_causes("
                "host_id TEXT NOT NULL,policy_digest TEXT NOT NULL,safety_digest TEXT NOT NULL,"
                "recovery_id TEXT NOT NULL,receipt_digest TEXT NOT NULL,"
                "PRIMARY KEY(host_id,policy_digest,safety_digest));"
                "CREATE TABLE IF NOT EXISTS automatic_ai_requests("
                "request_key TEXT PRIMARY KEY,host_id TEXT NOT NULL,"
                "grant_id TEXT NOT NULL,charged_day TEXT NOT NULL,"
                "analysis_id TEXT NOT NULL UNIQUE,owner TEXT NOT NULL,status TEXT NOT NULL,"
                "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,payload TEXT NOT NULL);"
                "CREATE INDEX IF NOT EXISTS automatic_ai_daily "
                "ON automatic_ai_requests(host_id,charged_day);"
                "CREATE INDEX IF NOT EXISTS automatic_ai_grant "
                "ON automatic_ai_requests(host_id,grant_id);"
                "CREATE TABLE IF NOT EXISTS automatic_ai_alerts("
                "id TEXT PRIMARY KEY,host_id TEXT NOT NULL,kind TEXT NOT NULL,"
                "candidate_id TEXT,"
                "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,"
                "acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0,1)),"
                "payload TEXT NOT NULL);"
                "CREATE INDEX IF NOT EXISTS automatic_ai_alert_order "
                "ON automatic_ai_alerts(acknowledged,created_at);"
            )
            connection.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in connection.execute("PRAGMA table_info(automatic_latches)")}
            if "active" not in columns:
                connection.execute(
                    "ALTER TABLE automatic_latches ADD COLUMN active INTEGER NOT NULL "
                    "DEFAULT 1 CHECK(active IN (0,1))"
                )
            ai_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(automatic_ai_alerts)")
            }
            if "candidate_id" not in ai_columns:
                connection.execute("ALTER TABLE automatic_ai_alerts ADD COLUMN candidate_id TEXT")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS automatic_ai_alert_candidate "
                "ON automatic_ai_alerts(candidate_id,kind)"
            )
        path.chmod(0o600)

    def _check_paths(self, *, allow_missing=False):
        if self.path.parent.is_symlink():
            raise ValueError("Automatic stores cannot use symbolic links")
        if os.name == "posix":
            parent = self.path.parent.stat()
            if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
                raise ValueError("Automatic store directory must be private and controller-owned")
        for path in (
            self.path,
            *(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm")),
        ):
            try:
                value = path.lstat()
            except FileNotFoundError:
                # SQLite removes sidecars on commit. Their disappearance is normal;
                # the durable database itself is still required below.
                continue
            if stat.S_ISLNK(value.st_mode):
                raise ValueError("Automatic stores cannot use symbolic links")
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise ValueError("Automatic store must be an ordinary single-link file")
            if os.name == "posix" and (value.st_uid != os.geteuid() or value.st_mode & 0o077):
                raise ValueError("Automatic store permissions are unsafe")
        if not self.path.exists() and not allow_missing:
            raise ValueError("Automatic store disappeared")

    @contextmanager
    def _connection(self, *, creating=False):
        self._check_paths(allow_missing=creating)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            self.path.chmod(0o600)
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _record(row):
        return None if row is None else json.loads(row["payload"])

    def get(self, candidate_id):
        _identity(candidate_id, HEX)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )

    def list_attempts(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Automatic attempt list exceeded its budget")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM automatic_candidates ORDER BY updated_at DESC,id LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def get_by_job(self, host_id, job_id):
        binding(host_id)
        _identity(job_id, ID)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE host_id=? AND job_id=?",
                    (host_id, job_id),
                ).fetchone()
            )

    def active_attempts(self):
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM automatic_candidates WHERE submitted_day IS NOT NULL "
                "AND state IN ('submission_intent','tracking','unknown') ORDER BY updated_at,id"
            ).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _write(connection, value):
        text = canonical(value)
        if len(text.encode()) > 32768:
            raise ValueError("Automatic attempt evidence exceeded its budget")
        connection.execute(
            "INSERT INTO automatic_candidates VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "state=excluded.state,grant_id=excluded.grant_id,submitted_day=excluded.submitted_day,"
            "updated_at=excluded.updated_at,"
            "payload=excluded.payload",
            (
                value["id"],
                value["host_id"],
                value["scope_hash"],
                value["state"],
                value["grant_id"],
                value["job_id"],
                value.get("submitted_day"),
                value["created_at"],
                value["updated_at"],
                text,
            ),
        )

    def latch(self, host_id):
        binding(host_id)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
                ).fetchone()
            )

    def latched_hosts(self):
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM automatic_latches WHERE active=1 ORDER BY host_id"
            ).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _latch(connection, value, reason, at):
        old = connection.execute(
            "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1",
            (value["host_id"],),
        ).fetchone()
        if old is not None:
            return json.loads(old["payload"])
        result = {
            "generation": secrets.token_hex(16),
            "host_id": value["host_id"],
            "reason": reason,
            "job_id": value.get("job_id"),
            "candidate_id": value["id"],
            "scope_hash": value["scope_hash"],
            "latched_at": at,
            "detail": "自动通道已暂停；切换模式、更新授权或任务后来恢复均不会自动解除暂停。",
        }
        connection.execute(
            "INSERT INTO automatic_latches(host_id,payload,active) VALUES(?,?,1) "
            "ON CONFLICT(host_id) DO UPDATE SET payload=excluded.payload,active=1",
            (value["host_id"], canonical(result)),
        )
        return result

    def quotas(self, host_id, grant_id, *, now=None):
        binding(host_id)
        _identity(grant_id, ID)
        day = instant(now).date().isoformat()
        with self._connection() as connection:
            daily = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE host_id=? AND submitted_day=?",
                (host_id, day),
            ).fetchone()[0]
            total = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE grant_id=? "
                "AND submitted_day IS NOT NULL",
                (grant_id,),
            ).fetchone()[0]
        return {"daily_used": daily, "total_used": total}

    def claim_candidate(
        self,
        *,
        host_id,
        scope_hash,
        finding_id,
        package,
        current_version,
        candidate_version,
        grant_id,
        grant_digest,
        scan_id,
        owner,
        now=None,
    ):
        cid = candidate_identity(
            host_id, scope_hash, finding_id, current_version, candidate_version
        )
        _identity(package, PACKAGE)
        _identity(grant_id, ID)
        _identity(grant_digest, HEX)
        _identity(scan_id, ID)
        _identity(owner, ID)
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
            ).fetchone():
                return None
            old = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (cid,)
                ).fetchone()
            )
            # Submission identity remains permanent across new grants and process restarts.
            if old is not None and (
                old.get("submitted_day") is not None
                or old["state"] != "deferred"
                or old["scan_id"] == scan_id
            ):
                return None
            active = connection.execute(
                "SELECT 1 FROM automatic_candidates WHERE host_id=? "
                "AND state IN ('planning','ready','submission_intent','tracking','unknown')",
                (host_id,),
            ).fetchone()
            if active is not None:
                return None
            if (
                old is None
                and connection.execute("SELECT COUNT(*) FROM automatic_candidates").fetchone()[0]
                >= MAX_ATTEMPTS
            ):
                raise ValueError("Automatic deduplication ledger is full; new actions are stopped")
            value = old or {
                "id": cid,
                "host_id": host_id,
                "scope_hash": scope_hash,
                "finding_id": finding_id,
                "package": package,
                "current_version": current_version,
                "candidate_version": candidate_version,
                "grant_id": grant_id,
                "grant_digest": grant_digest,
                "created_at": at,
                "job_id": digest({"automatic_job": cid})[:32],
                "submitted_day": None,
                "plan_id": None,
                "plan_digest": None,
                "status": None,
                "remote_revision": None,
            }
            value.update(
                state="planning",
                grant_id=grant_id,
                grant_digest=grant_digest,
                scan_id=scan_id,
                owner=owner,
                updated_at=at,
                detail="已登记自动候选，正在准备不可变方案；尚未提交安装。",
            )
            self._write(connection, value)
            return value

    def defer(self, candidate_id, detail, *, now=None):
        _identity(candidate_id, HEX)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            if value is None or value.get("submitted_day") is not None:
                return value
            value.update(
                state="deferred", detail=str(detail)[:500], updated_at=instant(now).isoformat()
            )
            self._write(connection, value)
            return value

    def reserve_submission(
        self, candidate_id, plan, mode_revision, *, daily_limit, total_limit, now=None
    ):
        _identity(candidate_id, HEX)
        if type(mode_revision) is not int or mode_revision < 0:
            raise ValueError("Automatic submission requires a mode revision")
        for limit in (daily_limit, total_limit):
            if type(limit) is not int or not 1 <= limit <= 5:
                raise ValueError("Automatic quota must be explicitly bounded")
        if not isinstance(plan, dict):
            raise ValueError("Automatic plan must be a root result")
        _identity(plan.get("plan_id"), ID)
        _identity(plan.get("plan_digest"), HEX)
        root_grant_digest = plan.get("automatic_grant_digest")
        if root_grant_digest is not None:
            _identity(root_grant_digest, HEX)
        at = instant(now)
        day = at.date().isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            if (
                value is None
                or value["state"] != "planning"
                or value.get("submitted_day") is not None
            ):
                return None
            if (
                plan.get("host_id") != value["host_id"]
                or plan.get("mode_revision") != mode_revision
            ):
                raise ValueError("Automatic plan identity differs from its candidate")
            if connection.execute(
                "SELECT 1 FROM automatic_latches WHERE host_id=? AND active=1", (value["host_id"],)
            ).fetchone():
                return None
            daily = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE host_id=? AND submitted_day=?",
                (value["host_id"], day),
            ).fetchone()[0]
            total = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE grant_id=? "
                "AND submitted_day IS NOT NULL",
                (value["grant_id"],),
            ).fetchone()[0]
            if daily >= daily_limit or total >= total_limit:
                value.update(state="deferred", detail="提交配额已耗尽。", updated_at=at.isoformat())
                self._write(connection, value)
                return None
            value.update(
                state="submission_intent",
                plan_id=plan["plan_id"],
                plan_digest=plan["plan_digest"],
                mode_revision=mode_revision,
                submitted_day=day,
                submitted_at=at.isoformat(),
                updated_at=at.isoformat(),
                detail="提交意图与原任务 ID 已持久登记，不会换新 ID 重试。",
            )
            if root_grant_digest is not None:
                value["root_grant_digest"] = root_grant_digest
            self._write(connection, value)
            return value

    def authorize_intent(
        self,
        host_id,
        job_id,
        plan_id,
        plan_digest,
        mode_revision,
        grant_id,
        grant_digest,
        *,
        now=None,
    ):
        """Recheck a persisted intent independently of the monitor before transport."""
        binding(host_id)
        for value, pattern in (
            (job_id, ID),
            (plan_id, ID),
            (plan_digest, HEX),
            (grant_id, ID),
            (grant_digest, HEX),
        ):
            _identity(value, pattern)
        if type(mode_revision) is not int or mode_revision < 0:
            raise ValueError("Invalid automatic authorization revision")
        day = instant(now).date().isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE host_id=? AND job_id=?",
                    (host_id, job_id),
                ).fetchone()
            )
            expected = {
                "host_id": host_id,
                "job_id": job_id,
                "plan_id": plan_id,
                "plan_digest": plan_digest,
                "mode_revision": mode_revision,
                "grant_id": grant_id,
                "grant_digest": grant_digest,
            }
            if (
                value is None
                or value.get("state") != "submission_intent"
                or value.get("submitted_day") is None
                or any(value.get(key) != item for key, item in expected.items())
                or connection.execute(
                    "SELECT 1 FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
                ).fetchone()
            ):
                raise ValueError("Automatic submission has no matching, unpaused intent")
            # Only the original never-dispatched intent can reach this path. A later
            # recovery queries its original ID and cannot authorize a new transport.
            if value["submitted_day"] != day:
                value["submitted_day"] = day
                self._write(connection, value)
            daily = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE host_id=? "
                "AND submitted_day=? AND id!=?",
                (host_id, day, value["id"]),
            ).fetchone()[0]
            total = connection.execute(
                "SELECT COUNT(*) FROM automatic_candidates WHERE grant_id=? "
                "AND submitted_day IS NOT NULL AND id!=?",
                (grant_id, value["id"]),
            ).fetchone()[0]
            return {"candidate": value, "daily_used_before": daily, "total_used_before": total}

    def record_result(self, candidate_id, job, *, now=None, from_status=False):
        _identity(candidate_id, HEX)
        if not isinstance(job, dict) or job.get("status") not in REMOTE_ACTIVE | FAILURES | {
            "verified"
        }:
            raise ValueError("Unrecognized automatic job result")
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            if value is None or value.get("submitted_day") is None:
                raise ValueError("Automatic result has no durable submission intent")
            if (
                job.get("host_id") != value["host_id"]
                or job.get("job_id") != value["job_id"]
                or job.get("plan_id") != value["plan_id"]
            ):
                raise ValueError("Automatic job response binding changed")
            revision = job.get("revision")
            if revision is not None and (type(revision) is not int or revision < 0):
                raise ValueError("Invalid automatic remote revision")
            if from_status and value["state"] == "submission_intent":
                # A status reader can see the job before its submitting owner
                # receives the acknowledgment. Only the original submit or
                # lease-bound recovery may consume that durable intent.
                return value
            prior = value.get("remote_revision")
            if prior is not None and revision is not None and revision < prior:
                return value
            if (
                prior is not None
                and revision == prior
                and value.get("status") not in {None, "unknown"}
                and value["status"] != job["status"]
            ):
                raise ValueError("Conflicting automatic remote revision")
            if prior is not None and revision is None and job["status"] != "unknown":
                return value
            status = job["status"]
            value.update(
                status=status,
                state="tracking" if status in REMOTE_ACTIVE else status,
                updated_at=at,
                detail="自动任务状态已保存；仍以原任务 ID 跟进。",
            )
            if revision is not None:
                value["remote_revision"] = revision
            value["result"] = {
                key: job[key]
                for key in (
                    "status",
                    "revision",
                    "install_exit_code",
                    "completed_at",
                    "evidence_origin",
                    "verification",
                    "detail",
                )
                if key in job
            }
            if len(canonical(value["result"]).encode()) > 16384:
                value["result"] = {"status": status, "evidence_truncated": True}
            self._write(connection, value)
            if status in FAILURES:
                # A separately approved activation recovery resolves only the
                # exact original pending receipt, never a changed/bad/unknown job.
                from opsark.activation_recovery_store import resolved_pending_job

                try:
                    resolved = resolved_pending_job(connection, value, job)
                except (
                    ValueError,
                    KeyError,
                    TypeError,
                    AttributeError,
                    RuntimeError,
                    OSError,
                    sqlite3.Error,
                ):
                    # Damaged/orphaned recovery evidence is not authority to keep
                    # an unsafe result unlatched. Preserve the attempt and pause.
                    resolved = False
                if not resolved:
                    self._latch(connection, value, status, at)
            return value

    def mark_unknown(
        self,
        candidate_id,
        *,
        reason="提交或状态结果未知，停止新的自动动作。",
        now=None,
        from_status=False,
        expected=None,
    ):
        _identity(candidate_id, HEX)
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            if value is None:
                raise ValueError("Unknown automatic candidate")
            if expected is not None and value != expected:
                return value
            if from_status and value["state"] == "submission_intent":
                return value
            value.update(state="unknown", status="unknown", detail=str(reason)[:500], updated_at=at)
            self._write(connection, value)
            self._latch(connection, value, "unknown", at)
            return value

    def reconcile_submission_intent(self, candidate_id, owner, *, now=None):
        """Fence recovery with the actual monitor lease before consuming cached status."""
        _identity(candidate_id, HEX)
        _identity(owner, ID)
        at = instant(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if (
                connection.execute(
                    "SELECT 1 FROM automatic_monitor_lease WHERE id=1 AND owner=? AND expires_at>?",
                    (owner, at.timestamp()),
                ).fetchone()
                is None
            ):
                return False
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            if value is None or value["state"] != "submission_intent":
                return False
            value.update(
                state="unknown",
                status="unknown",
                detail="原提交意图尚未结算；已暂停自动处置，只核对原任务。",
                updated_at=at.isoformat(),
            )
            self._write(connection, value)
            self._latch(connection, value, "unknown", at.isoformat())
            return True

    def recover_interrupted_plans(self, owner, *, now=None):
        _identity(owner, ID)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT payload FROM automatic_candidates WHERE state IN ('planning','ready') "
                "AND submitted_day IS NULL"
            ).fetchall()
            for row in rows:
                value = self._record(row)
                if value.get("owner") == owner:
                    continue
                value.update(
                    state="deferred",
                    detail="控制端在规划期间中断；未提交安装，等待新扫描重新规划。",
                    updated_at=instant(now).isoformat(),
                )
                self._write(connection, value)

    def set_host_state(self, host_id, value):
        binding(host_id)
        if (
            not isinstance(value, dict)
            or value.get("host_id") != host_id
            or len(canonical(value).encode()) > 16384
        ):
            raise ValueError("Invalid automatic host status")
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO automatic_host_states VALUES(?,?) ON CONFLICT(host_id) "
                "DO UPDATE SET payload=excluded.payload",
                (host_id, canonical(value)),
            )

    def host_state(self, host_id):
        binding(host_id)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_host_states WHERE host_id=?", (host_id,)
                ).fetchone()
            )

    def remote_state(self, host_id):
        binding(host_id)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_remote_states WHERE host_id=?", (host_id,)
                ).fetchone()
            )

    def _known_root_resolution(self, connection, host_id, policy_digest, cause_digest, resolution):
        """Preserve genuine v1 receipts; new activation causes need their full source."""
        try:
            recovery_id, receipt_digest = resolution["recovery_id"], resolution["receipt_digest"]
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='activation_recoveries'"
            ).fetchone()
            new = (
                table is not None
                and connection.execute(
                    "SELECT 1 FROM activation_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if new or resolution.get("kind") == "activation_recovery":
                from opsark.activation_recovery_store import resolved_root_cause

                known = resolved_root_cause(
                    connection, host_id, policy_digest, cause_digest, recovery_id, receipt_digest
                )
                if known:
                    # Rebuild only the derived index from an intact original
                    # receipt, so later snapshots cannot replace a newer pause.
                    connection.execute(
                        "INSERT OR IGNORE INTO automatic_resolved_causes VALUES(?,?,?,?,?)",
                        (host_id, policy_digest, cause_digest, recovery_id, receipt_digest),
                    )
                return known
            legacy = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if (
                legacy is None
                or legacy.get("host_id") != host_id
                or legacy.get("policy_digest") != policy_digest
                or legacy.get("recovery_id") != recovery_id
                or legacy.get("receipt", {}).get("receipt_digest") != receipt_digest
                or legacy["receipt"].get("resolved_safety_digest") != cause_digest
                or legacy["receipt"].get("status") != "verified"
            ):
                return False
            # Reuse the old schema 1 contract without imposing activation fields.
            self._remember_root_resolution(connection, legacy, legacy["receipt"])
            return True
        except (
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            RuntimeError,
            OSError,
            sqlite3.Error,
        ):
            return False

    def record_remote_safety(self, host_id, scope_hash, policy_digest, result, *, now=None):
        binding(host_id, scope_hash)
        _identity(policy_digest, HEX)
        at = instant(now).isoformat()
        if (
            not isinstance(result, dict)
            or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or result.get("host_id") != host_id
            or result.get("policy_digest") != policy_digest
            or result.get("status") != "automatic_status"
            or type(result.get("enabled")) is not bool
            or type(result.get("maintenance_open")) is not bool
        ):
            raise ValueError("Remote automatic safety binding changed")
        safety, usage, grant = result.get("safety"), result.get("usage"), result.get("grant")
        if (
            not isinstance(safety, dict)
            or set(safety) != {"schema_version", "paused", "reason", "job_id", "updated_at"}
            or type(safety.get("schema_version")) is not int
            or safety["schema_version"] != 1
            or type(safety.get("paused")) is not bool
            or not isinstance(usage, dict)
            or set(usage) != {"daily_used", "total_used"}
            or any(
                value is not None and (type(value) is not int or value < 0)
                for value in usage.values()
            )
            or grant is not None
            and not isinstance(grant, dict)
        ):
            raise ValueError("Remote automatic safety or usage is unknown")
        instant(datetime.fromisoformat(safety["updated_at"]))
        if safety["paused"]:
            _identity(safety["job_id"], ID)
            if safety["reason"] not in {"automatic_job_" + state for state in FAILURES}:
                raise ValueError("Unknown remote automatic safety reason")
        elif safety["reason"] is not None or safety["job_id"] is not None:
            raise ValueError("Remote automatic safety is conflicting")
        if grant is None:
            if result.get("grant_digest") is not None or result["enabled"]:
                raise ValueError("Remote automatic grant is missing")
        elif result.get("grant_digest") != digest(grant):
            raise ValueError("Remote automatic grant digest changed")
        value = {
            "host_id": host_id,
            "scope_hash": scope_hash,
            "policy_digest": policy_digest,
            "checked_at": at,
            "status": "available",
            "remote": {
                key: result[key]
                for key in (
                    "enabled",
                    "grant",
                    "grant_digest",
                    "maintenance_open",
                    "usage",
                    "safety",
                )
            },
        }
        text = canonical(value)
        if len(text.encode()) > 32768:
            raise ValueError("Remote automatic safety exceeded its budget")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if safety["paused"]:
                resolved = connection.execute(
                    "SELECT * FROM automatic_resolved_causes "
                    "WHERE host_id=? AND policy_digest=? AND safety_digest=?",
                    (host_id, policy_digest, safety_digest(safety)),
                ).fetchone()
                if resolved is not None and self._known_root_resolution(
                    connection, host_id, policy_digest, safety_digest(safety), dict(resolved)
                ):
                    cached = self._record(
                        connection.execute(
                            "SELECT payload FROM automatic_remote_states WHERE host_id=?",
                            (host_id,),
                        ).fetchone()
                    )
                    return cached or {
                        **value,
                        "status": "unavailable",
                        "detail": "已解决原因的迟到快照不能作为当前权限，等待新的远端读取。",
                    }
                old_row = connection.execute(
                    "SELECT payload,active FROM automatic_latches WHERE host_id=?", (host_id,)
                ).fetchone()
                old = self._record(old_row)
                if (
                    old_row is not None
                    and not old_row["active"]
                    and resolved is None
                    and old.get("resolution", {}).get("policy_digest") == policy_digest
                    and old.get("resolution", {}).get("resolved_safety_digest")
                    == safety_digest(safety)
                    and self._known_root_resolution(
                        connection,
                        host_id,
                        policy_digest,
                        safety_digest(safety),
                        old["resolution"],
                    )
                ):
                    # A pre-commit read may arrive after its exact cause was
                    # reviewed. It cannot resurrect that cause or become fresh authority.
                    cached = self._record(
                        connection.execute(
                            "SELECT payload FROM automatic_remote_states WHERE host_id=?",
                            (host_id,),
                        ).fetchone()
                    )
                    return cached or {
                        **value,
                        "status": "unavailable",
                        "detail": "已解决原因的迟到快照不能作为当前权限，等待新的远端读取。",
                    }
                if old_row is not None and not old_row["active"]:
                    old = None
                if old is not None and (
                    old.get("job_id") != safety["job_id"]
                    or old.get("remote_safety") is not None
                    and safety_digest(old["remote_safety"]) != safety_digest(safety)
                ):
                    # Keep the superseded cause immutable while the host remains
                    # paused under the newly observed root cause.
                    connection.execute(
                        "INSERT OR IGNORE INTO automatic_latch_history VALUES(?,?,?)",
                        (digest(old), host_id, canonical(old)),
                    )
                    old = None
                latch = old or {
                    "generation": secrets.token_hex(16),
                    "host_id": host_id,
                    "reason": safety["reason"],
                    "job_id": safety["job_id"],
                    "candidate_id": None,
                    "scope_hash": scope_hash,
                    "latched_at": at,
                    "source": "remote_root",
                    "detail": "远端已持久暂停自动处理；需管理员核实原任务。",
                }
                latch["remote_safety"] = safety
                connection.execute(
                    "INSERT INTO automatic_latches(host_id,payload,active) VALUES(?,?,1) "
                    "ON CONFLICT(host_id) DO UPDATE SET payload=excluded.payload,active=1",
                    (host_id, canonical(latch)),
                )
            connection.execute(
                "INSERT INTO automatic_remote_states VALUES(?,?) ON CONFLICT(host_id) "
                "DO UPDATE SET payload=excluded.payload",
                (host_id, text),
            )
        return value

    def get_recovery(self, host_id, recovery_id):
        binding(host_id)
        _identity(recovery_id, ID)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )

    def list_recoveries(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Recovery list exceeded its budget")
        with self._connection() as connection:
            return [
                self._record(row)
                for row in connection.execute(
                    "SELECT payload FROM automatic_recoveries "
                    "ORDER BY CASE WHEN status IN ('submission_intent','unknown') "
                    "THEN 0 ELSE 1 END,updated_at DESC,host_id,recovery_id LIMIT ?",
                    (limit,),
                ).fetchall()
            ]

    @staticmethod
    def _write_recovery(connection, value):
        text = canonical(value)
        if len(text.encode()) > MAX_RECOVERY_BYTES:
            raise ValueError("Recovery evidence exceeded its budget")
        connection.execute(
            "INSERT INTO automatic_recoveries VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(host_id,recovery_id) DO UPDATE SET status=excluded.status,"
            "updated_at=excluded.updated_at,payload=excluded.payload",
            (
                value["host_id"],
                value["recovery_id"],
                value["status"],
                value["created_at"],
                value["updated_at"],
                text,
            ),
        )

    @staticmethod
    def _remember_root_resolution(connection, value, receipt):
        if receipt.get("status") != "verified":
            return
        if (
            any(
                receipt.get(key) != value[key]
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
            or receipt.get("resolved_safety_digest") != value["plan"]["root_safety_digest"]
            or receipt.get("receipt_digest")
            != digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
            or receipt.get("verification", {}).get("fresh_ssh", {}).get("passed") is not True
        ):
            raise ValueError("An unverified root receipt cannot resolve a historical cause")
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

    def pending_recovery(self, host_id):
        binding(host_id)
        with self._connection() as connection:
            return self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? "
                    "AND status IN ('submission_intent','unknown') "
                    "ORDER BY created_at,recovery_id LIMIT 1",
                    (host_id,),
                ).fetchone()
            )

    def save_recovery_plan(self, host_id, scope_hash, policy_digest, plan, latch, *, now=None):
        binding(host_id, scope_hash)
        _identity(policy_digest, HEX)
        _identity(plan.get("recovery_id"), ID)
        _identity(plan.get("recovery_digest"), HEX)
        context = digest(latch)
        if plan.get("context_digest") != context or latch.get("host_id") != host_id:
            raise ValueError("Recovery plan is not bound to the original local pause")
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
                ).fetchone()
            )
            if current is None or digest(current) != context:
                raise ValueError("Local pause changed during recovery planning")
            if connection.execute(
                "SELECT 1 FROM automatic_recoveries WHERE host_id=? "
                "AND status IN ('submission_intent','unknown')",
                (host_id,),
            ).fetchone():
                raise ValueError("An original recovery outcome requires reconciliation")
            old = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, plan["recovery_id"]),
                ).fetchone()
            )
            if old is not None:
                if old["plan"] != plan or old["context_digest"] != context:
                    raise ValueError("Recovery plans are immutable")
                return old
            if (
                connection.execute("SELECT COUNT(*) FROM automatic_recoveries").fetchone()[0]
                >= MAX_RECOVERIES
            ):
                raise ValueError("Recovery audit retention is full")
            value = {
                "host_id": host_id,
                "scope_hash": scope_hash,
                "policy_digest": policy_digest,
                "recovery_id": plan["recovery_id"],
                "recovery_digest": plan["recovery_digest"],
                "job_id": plan["job_id"],
                "job_revision": plan["job_revision"],
                "job_digest": plan["job_digest"],
                "mode_revision": plan["mode_revision"],
                "context_digest": context,
                "status": "prepared",
                "created_at": at,
                "updated_at": at,
                "detail": "恢复预览已保存；尚未批准，也没有解除暂停。",
                "plan": plan,
                "latch_before": latch,
                "receipt": None,
                "local_released": False,
            }
            self._write_recovery(connection, value)
            return value

    def register_recovery_submission(
        self, host_id, recovery_id, recovery_digest, mode_revision, *, now=None
    ):
        binding(host_id)
        _identity(recovery_id, ID)
        _identity(recovery_digest, HEX)
        at = instant(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None:
                raise ValueError("Recovery preview does not exist")
            if (
                value["recovery_digest"] != recovery_digest
                or value["mode_revision"] != mode_revision
            ):
                raise ValueError("Approval does not match the immutable recovery")
            if value["status"] != "prepared":
                return False, value
            plan = value["plan"]
            if (
                plan.get("eligible") is not True
                or instant(datetime.fromisoformat(plan["expires_at"])) <= at
            ):
                raise ValueError("Recovery preview is ineligible or expired")
            current = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
                ).fetchone()
            )
            if current is None or digest(current) != value["context_digest"]:
                raise ValueError("The approved local pause has changed")
            if connection.execute(
                "SELECT 1 FROM automatic_recoveries WHERE host_id=? AND recovery_id!=? "
                "AND status IN ('submission_intent','unknown')",
                (host_id, recovery_id),
            ).fetchone():
                raise ValueError("Another original recovery outcome requires reconciliation")
            value.update(
                status="submission_intent",
                confirmed_at=at.isoformat(),
                updated_at=at.isoformat(),
                detail="人工批准与固定恢复 ID 已持久保存，随后最多发送一次恢复请求。",
            )
            self._write_recovery(connection, value)
            return True, value

    def set_recovery_outcome(
        self, host_id, recovery_id, status, *, receipt=None, detail=None, now=None
    ):
        if status not in {"unknown", "rejected"}:
            raise ValueError("Unsupported unresolved recovery outcome")
        binding(host_id)
        _identity(recovery_id, ID)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None or value["status"] == "prepared":
                raise ValueError("Recovery outcome has no persistent approval")
            if value["status"] in {"verified", "rejected", "superseded"}:
                return value
            value.update(
                status=status,
                updated_at=instant(now).isoformat(),
                detail=str(detail or "恢复结果尚未核实；保留暂停，只查询原恢复 ID。")[:500],
            )
            if receipt is not None:
                value["receipt"] = receipt
                value["root_outcome"] = receipt.get("status", "unknown")
                self._remember_root_resolution(connection, value, receipt)
            self._write_recovery(connection, value)
            return value

    def supersede_recovery(self, host_id, recovery_id, *, receipt=None, detail, now=None):
        """Retire an old approval without claiming its unknown root action failed."""
        binding(host_id)
        _identity(recovery_id, ID)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None:
                raise ValueError("Original recovery does not exist")
            if value["status"] in {"verified", "rejected", "superseded"}:
                return value
            value.update(
                status="superseded",
                updated_at=instant(now).isoformat(),
                local_released=False,
                detail=str(detail)[:500],
                root_outcome="unknown" if receipt is None else receipt.get("status", "unknown"),
            )
            if receipt is not None:
                value["receipt"] = receipt
                self._remember_root_resolution(connection, value, receipt)
            self._write_recovery(connection, value)
            return value

    def complete_recovery(self, host_id, recovery_id, receipt, remote_state, *, now=None):
        """Mark one exact pause resolved; never remove its evidence or refund quota."""
        binding(host_id)
        _identity(recovery_id, ID)
        checked_now = instant(now)
        at = checked_now.isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_recoveries WHERE host_id=? AND recovery_id=?",
                    (host_id, recovery_id),
                ).fetchone()
            )
            if value is None or value["status"] == "prepared":
                raise ValueError("There is no approved recovery intent")
            if value["status"] == "verified":
                return value
            if value["status"] in {"rejected", "superseded"}:
                raise ValueError("A rejected recovery cannot be reused")
            current = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_latches WHERE host_id=? AND active=1", (host_id,)
                ).fetchone()
            )
            if current is None or digest(current) != value["context_digest"]:
                raise ValueError("The approved pause no longer matches current safety state")
            try:
                root_checked = instant(datetime.fromisoformat(remote_state["checked_at"]))
                root_completed = instant(datetime.fromisoformat(receipt["completed_at"]))
                if (
                    not 0 <= (checked_now - root_checked).total_seconds() <= 60
                    or root_checked < root_completed
                ):
                    raise ValueError("Recovery safety snapshot is stale or predates the receipt")
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    "Recovery requires a fresh post-receipt safety snapshot"
                ) from error
            if (
                type(receipt.get("schema_version")) is not int
                or receipt["schema_version"] != 1
                or receipt.get("host_id") != host_id
                or receipt.get("status") != "verified"
                or receipt.get("context_digest") != value["context_digest"]
                or receipt.get("recovery_id") != recovery_id
                or receipt.get("recovery_digest") != value["recovery_digest"]
                or receipt.get("job_id") != value["job_id"]
                or receipt.get("job_revision") != value["job_revision"]
                or receipt.get("job_digest") != value["job_digest"]
                or receipt.get("policy_digest") != value["policy_digest"]
                or receipt.get("driver_source_digest") != value["plan"]["driver_source_digest"]
                or receipt.get("mode_revision") != value["mode_revision"]
                or receipt.get("resolved_safety_digest") != value["plan"]["root_safety_digest"]
                or receipt.get("receipt_digest")
                != digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
                or remote_state.get("status") != "available"
                or remote_state.get("host_id") != host_id
                or remote_state.get("scope_hash") != value["scope_hash"]
                or remote_state.get("policy_digest") != value["policy_digest"]
                or remote_state.get("remote", {}).get("safety", {}).get("paused") is not False
                or safety_digest(remote_state["remote"]["safety"])
                != receipt.get("safety_after_digest")
            ):
                raise ValueError("Verified root recovery and fresh safety snapshot do not match")
            connection.execute(
                "INSERT OR IGNORE INTO automatic_latch_history VALUES(?,?,?)",
                (value["context_digest"], host_id, canonical(current)),
            )
            self._remember_root_resolution(connection, value, receipt)
            resolved = {
                **current,
                "resolution": {
                    "recovery_id": recovery_id,
                    "receipt_digest": receipt["receipt_digest"],
                    "resolved_at": at,
                    "policy_digest": value["policy_digest"],
                    "resolved_safety_digest": receipt["resolved_safety_digest"],
                },
            }
            connection.execute(
                "UPDATE automatic_latches SET payload=?,active=0 WHERE host_id=?",
                (canonical(resolved), host_id),
            )
            value.update(
                status="verified",
                updated_at=at,
                resolved_at=at,
                receipt=receipt,
                local_released=True,
                detail="原任务及当前服务已核验，原暂停已人工对账；模式、授权和配额均未改变。",
            )
            self._write_recovery(connection, value)
            return value

    def mark_remote_unavailable(self, host_id, scope_hash, policy_digest, *, now=None):
        binding(host_id, scope_hash)
        _identity(policy_digest, HEX)
        previous = self.remote_state(host_id)
        value = {
            "host_id": host_id,
            "scope_hash": scope_hash,
            "policy_digest": policy_digest,
            "checked_at": instant(now).isoformat(),
            "status": "unavailable",
            "detail": "远端自动安全状态未能核实；停止新自动提交，历史结果不代表当前安全。",
            "remote": previous.get("remote") if previous else None,
        }
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO automatic_remote_states VALUES(?,?) ON CONFLICT(host_id) "
                "DO UPDATE SET payload=excluded.payload",
                (host_id, canonical(value)),
            )
        return value

    def remote_admission(self, host_id, scope_hash, policy_digest, grant_digest, *, now=None):
        """A failed, stale or foreign snapshot cannot become zero usage or a safe root."""
        binding(host_id, scope_hash)
        _identity(policy_digest, HEX)
        _identity(grant_digest, HEX)
        value = self.remote_state(host_id)
        try:
            if value is None or (
                value.get("status") != "available"
                or value.get("scope_hash") != scope_hash
                or value.get("policy_digest") != policy_digest
                or not 0
                <= (
                    instant(now) - instant(datetime.fromisoformat(value["checked_at"]))
                ).total_seconds()
                <= 60
            ):
                return None
            remote = value["remote"]
            if (
                remote.get("enabled") is not True
                or remote.get("maintenance_open") is not True
                or remote.get("grant_digest") != grant_digest
                or remote.get("safety", {}).get("paused") is not False
                or not all(
                    type(remote["usage"][key]) is int and remote["usage"][key] >= 0
                    for key in ("daily_used", "total_used")
                )
            ):
                return None
            return remote
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _write_ai_request(connection, value):
        text = canonical(value)
        if len(text.encode()) > 8192:
            raise ValueError("Automatic AI intent exceeded its audit budget")
        connection.execute(
            "UPDATE automatic_ai_requests SET status=?,updated_at=?,payload=? "
            "WHERE request_key=? AND owner=? AND status='submission_intent'",
            (
                value["status"],
                value["updated_at"],
                text,
                value["request_key"],
                value["owner"],
            ),
        )

    def _expire_ai_request(self, connection, value, at):
        if (
            value is not None
            and value["status"] == "submission_intent"
            and datetime.fromisoformat(value["deadline_at"]) <= at
        ):
            value.update(
                status="unknown",
                result_ref=None,
                updated_at=at.isoformat(),
                detail="模型请求结果未能在期限内核实；保留原身份与预算，不自动重发。",
            )
            self._write_ai_request(connection, value)
        return value

    def begin_ai_request(
        self,
        request_key,
        host_id,
        scope_hash,
        candidate_id,
        grant_id,
        provider_fingerprint,
        analysis_id,
        input_digest,
        owner,
        *,
        daily_limit,
        total_limit,
        now=None,
    ):
        """Reserve model cost before transport; an existing key never authorizes replay."""
        binding(host_id, scope_hash)
        for value, pattern in (
            (request_key, HEX),
            (candidate_id, HEX),
            (grant_id, ID),
            (provider_fingerprint, HEX),
            (analysis_id, ID),
            (input_digest, HEX),
            (owner, ID),
        ):
            _identity(value, pattern)
        for limit in (daily_limit, total_limit):
            if type(limit) is not int or not 1 <= limit <= 5:
                raise ValueError("Automatic AI budget must be explicitly bounded")
        at = instant(now)
        day = at.date().isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_requests WHERE request_key=?", (request_key,)
                ).fetchone()
            )
            if old is not None:
                return {**self._expire_ai_request(connection, old, at), "dispatch": False}
            daily = connection.execute(
                "SELECT COUNT(*) FROM automatic_ai_requests WHERE host_id=? AND charged_day=?",
                (host_id, day),
            ).fetchone()[0]
            total = connection.execute(
                "SELECT COUNT(*) FROM automatic_ai_requests WHERE host_id=? AND grant_id=?",
                (host_id, grant_id),
            ).fetchone()[0]
            if (
                daily >= daily_limit
                or total >= total_limit
                or connection.execute("SELECT COUNT(*) FROM automatic_ai_requests").fetchone()[0]
                >= MAX_AI_REQUESTS
            ):
                return None
            value = {
                "request_key": request_key,
                "host_id": host_id,
                "scope_hash": scope_hash,
                "candidate_id": candidate_id,
                "grant_id": grant_id,
                "provider_fingerprint": provider_fingerprint,
                "analysis_id": analysis_id,
                "input_digest": input_digest,
                "owner": owner,
                "status": "submission_intent",
                "created_at": at.isoformat(),
                "updated_at": at.isoformat(),
                "deadline_at": (at + timedelta(seconds=120)).isoformat(),
                "result_ref": None,
                "detail": "模型外发意图及独立预算已登记；不因重启或刷新更换身份重发。",
            }
            connection.execute(
                "INSERT INTO automatic_ai_requests "
                "(request_key,host_id,grant_id,charged_day,analysis_id,owner,status,"
                "created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    request_key,
                    host_id,
                    grant_id,
                    day,
                    analysis_id,
                    owner,
                    value["status"],
                    value["created_at"],
                    value["updated_at"],
                    canonical(value),
                ),
            )
            return {**value, "dispatch": True}

    def get_ai_request(self, request_key, now=None):
        _identity(request_key, HEX)
        at = instant(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_requests WHERE request_key=?", (request_key,)
                ).fetchone()
            )
            return self._expire_ai_request(connection, value, at)

    def finish_ai_request(self, request_key, owner, *, status, result_ref=None, detail, now=None):
        _identity(request_key, HEX)
        _identity(owner, ID)
        if not isinstance(status, str) or status not in AI_TERMINAL:
            raise ValueError("Automatic AI result is not a recognized terminal state")
        detail = _ai_detail(detail)
        at = instant(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_requests WHERE request_key=?", (request_key,)
                ).fetchone()
            )
            if value is None or value["owner"] != owner:
                raise ValueError("Automatic AI result has no matching request owner")
            value = self._expire_ai_request(connection, value, at)
            if value["status"] != "submission_intent":
                return value
            reference = _ai_ref(result_ref, value)
            value.update(
                status=status,
                result_ref=reference,
                detail=detail,
                updated_at=at.isoformat(),
            )
            self._write_ai_request(connection, value)
            return value

    def ai_requests(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Automatic AI request list exceeded its budget")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM automatic_ai_requests ORDER BY "
                "CASE WHEN status IN ('submission_intent','unknown') THEN 0 ELSE 1 END,"
                "updated_at DESC,request_key LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def ai_quotas(self, host_id, grant_id, now=None):
        binding(host_id)
        _identity(grant_id, ID)
        day = instant(now).date().isoformat()
        with self._connection() as connection:
            daily = connection.execute(
                "SELECT COUNT(*) FROM automatic_ai_requests WHERE host_id=? AND charged_day=?",
                (host_id, day),
            ).fetchone()[0]
            total = connection.execute(
                "SELECT COUNT(*) FROM automatic_ai_requests WHERE host_id=? AND grant_id=?",
                (host_id, grant_id),
            ).fetchone()[0]
        return {"daily_used": daily, "total_used": total}

    def bind_ai_result(self, candidate_id, owner, proof, *, now=None):
        """Attach exact completed model provenance to the caller-owned planning candidate."""
        _identity(candidate_id, HEX)
        _identity(owner, ID)
        if not isinstance(proof, dict) or set(proof) != AI_REF_FIELDS | {"request_key"}:
            raise ValueError("Automatic candidate needs a complete bounded AI proof")
        _identity(proof["request_key"], HEX)
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidate = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_candidates WHERE id=?", (candidate_id,)
                ).fetchone()
            )
            request = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_requests WHERE request_key=?",
                    (proof["request_key"],),
                ).fetchone()
            )
            if (
                candidate is None
                or candidate["state"] != "planning"
                or candidate.get("submitted_day") is not None
                or candidate.get("owner") != owner
                or request is None
                or request["status"] != "completed"
                or request["candidate_id"] != candidate_id
                or any(
                    request[key] != candidate[key] for key in ("host_id", "scope_hash", "grant_id")
                )
            ):
                return None
            reference = _ai_ref({k: proof[k] for k in AI_REF_FIELDS}, request)
            _identity(reference["analysis_digest"], HEX)
            _identity(reference["proposal_id"], ID)
            _identity(reference["candidate_id"], HOST)
            if reference != request["result_ref"] or candidate.get("ai_proof") not in (None, proof):
                return None
            candidate.update(ai_proof=dict(proof), updated_at=at)
            self._write(connection, candidate)
            return candidate

    def emit_ai_alert(
        self,
        host_id,
        event_key,
        kind,
        detail,
        *,
        request_key=None,
        candidate_id=None,
        job_id=None,
        now=None,
    ):
        binding(host_id)
        _identity(event_key, EVENT_KEY)
        if not isinstance(kind, str) or kind not in AI_ALERT_KINDS:
            raise ValueError("Unknown automatic AI alert kind")
        if redact(event_key) != event_key:
            raise ValueError("Automatic AI event identity cannot contain credentials")
        for value, pattern in ((request_key, HEX), (candidate_id, HEX), (job_id, ID)):
            if value is not None:
                _identity(value, pattern)
        detail = _ai_detail(detail)
        identifier = digest({"host_id": host_id, "event_key": event_key, "kind": kind})
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_alerts WHERE id=?", (identifier,)
                ).fetchone()
            )
            if old is not None:
                return old
            if connection.execute("SELECT COUNT(*) FROM automatic_ai_alerts").fetchone()[0] >= (
                MAX_AI_ALERTS
            ):
                raise ValueError("Automatic AI alert ledger is full; existing alerts are retained")
            value = {
                "id": identifier,
                "host_id": host_id,
                "event_key": event_key,
                "kind": kind,
                "detail": detail,
                "request_key": request_key,
                "candidate_id": candidate_id,
                "job_id": job_id,
                "acknowledged": False,
                "acknowledged_at": None,
                "created_at": at,
                "updated_at": at,
            }
            connection.execute(
                "INSERT INTO automatic_ai_alerts "
                "(id,host_id,kind,candidate_id,created_at,updated_at,acknowledged,payload) "
                "VALUES(?,?,?,?,?,?,0,?)",
                (identifier, host_id, kind, candidate_id, at, at, canonical(value)),
            )
            return value

    def ai_alerts(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Automatic AI alert list exceeded its budget")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM automatic_ai_alerts "
                "ORDER BY acknowledged,created_at DESC,id LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def ack_ai_alert(self, alert_id, now=None):
        _identity(alert_id, HEX)
        at = instant(now).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            value = self._record(
                connection.execute(
                    "SELECT payload FROM automatic_ai_alerts WHERE id=?", (alert_id,)
                ).fetchone()
            )
            if value is None or value["acknowledged"]:
                return value
            value.update(acknowledged=True, acknowledged_at=at, updated_at=at)
            connection.execute(
                "UPDATE automatic_ai_alerts SET acknowledged=1,updated_at=?,payload=? WHERE id=?",
                (at, canonical(value), alert_id),
            )
            return value

    def ai_outcomes(self, limit=100):
        """Read AI-bound outcomes, prioritizing candidates without a terminal event."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Automatic AI outcome list exceeded its budget")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT c.payload FROM automatic_candidates c "
                "WHERE instr(c.payload,'\"ai_proof\":{')>0 AND "
                "(c.state IN ('verified','failed','verification_failed',"
                "'installed_restart_pending',"
                "'reboot_pending','rejected','unknown','running_overdue') OR "
                "(c.state='tracking' AND instr(c.payload,'\"status\":\"running_overdue\"')>0)) "
                "ORDER BY CASE WHEN EXISTS(SELECT 1 FROM automatic_ai_alerts a "
                "WHERE a.candidate_id=c.id AND a.kind IN ('repair_verified','repair_failed')) "
                "THEN 1 ELSE 0 END,c.updated_at DESC,c.id LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._record(row) for row in rows]

    def claim_monitor(self, owner, *, now=None, ttl_seconds=180):
        _identity(owner, ID)
        if type(ttl_seconds) is not int or not 120 <= ttl_seconds <= 300:
            raise ValueError("Automatic lease exceeds its bounded operation budget")
        at = instant(now).timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT owner,expires_at FROM automatic_monitor_lease WHERE id=1"
            ).fetchone()
            if row is not None and row["owner"] != owner and row["expires_at"] > at:
                return False
            connection.execute(
                "INSERT INTO automatic_monitor_lease VALUES(1,?,?) ON CONFLICT(id) "
                "DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at",
                (owner, at + ttl_seconds),
            )
            return True

    def release_monitor(self, owner):
        _identity(owner, ID)
        with self._connection() as connection:
            connection.execute("DELETE FROM automatic_monitor_lease WHERE owner=?", (owner,))
