"""Bounded controller cache for authoritative remote patch evidence and job notices."""

import json
import os
import re
import sqlite3
import stat
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

MAX_SCAN_BYTES = 1_048_576
MAX_RECORD_BYTES = 262_144
MAX_SCANS = 100
MAX_PLANS = 1000
MAX_JOBS = 1000
TERMINAL_STATES = {
    "verified",
    "installed_restart_pending",
    "reboot_pending",
    "verification_failed",
    "failed",
    "rejected",
    "unknown",
}
ACTIVE_STATES = {
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "running_overdue",
    "awaiting_transport_verification",
}
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NON_NATIVE_JOB_FIELDS = {
    "error",
    "ok",
    "source",
    "remote_job_created",
    "transport_unknown",
    "last_remote_revision",
    "received_at",
    "notification_due",
    "notification_count",
    "last_notified_at",
}


def _host(value: str) -> str:
    if not isinstance(value, str) or not _HOST.fullmatch(value):
        raise ValueError("Invalid registered patch host")
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid remote patch identifier")
    return value


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _document(host_id: str, payload: dict, budget: int) -> tuple[dict, str]:
    _host(host_id)
    if not isinstance(payload, dict) or ("host_id" in payload and payload["host_id"] != host_id):
        raise ValueError("Patch evidence belongs to a different host")
    text = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(text.encode()) > budget:
        raise ValueError("Patch evidence exceeded storage budget")
    # Copy JSON data so subsequent caller mutation cannot alter a cached result.
    return json.loads(text), text


class PatchStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise ValueError("Patch store requires a private ordinary directory")
        path.parent.chmod(0o700)
        if not path.exists() and not path.is_symlink():
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        self._check_paths()
        path.chmod(0o600)
        with self._connection() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS patch_scans (host_id TEXT PRIMARY KEY,"
                "received_at TEXT NOT NULL,payload TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS patch_plans ("
                "host_id TEXT NOT NULL,plan_id TEXT NOT NULL,"
                "received_at TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(host_id,plan_id));"
                "CREATE TABLE IF NOT EXISTS patch_jobs (host_id TEXT NOT NULL,job_id TEXT NOT NULL,"
                "received_at TEXT NOT NULL,status TEXT NOT NULL,revision INTEGER,"
                "payload TEXT NOT NULL,notification_count INTEGER NOT NULL,"
                "last_notified_at TEXT,PRIMARY KEY(host_id,job_id));"
                "CREATE TABLE IF NOT EXISTS patch_monitor_lease ("
                "id INTEGER PRIMARY KEY CHECK(id=1),"
                "owner TEXT NOT NULL,expires_at REAL NOT NULL);"
                "CREATE TABLE IF NOT EXISTS patch_submit_intents (host_id TEXT NOT NULL,"
                "job_id TEXT NOT NULL,received_at TEXT NOT NULL,payload TEXT NOT NULL,"
                "PRIMARY KEY(host_id,job_id));"
                "CREATE TABLE IF NOT EXISTS patch_handoff_audit ("
                "host_id TEXT NOT NULL,job_id TEXT NOT NULL,host_scope TEXT NOT NULL,"
                "policy_digest TEXT NOT NULL,plan_id TEXT NOT NULL,plan_digest TEXT NOT NULL,"
                "mode_revision INTEGER NOT NULL,authorization TEXT NOT NULL "
                "CHECK(authorization IN ('assisted','automatic')),approved_at TEXT NOT NULL,"
                "unknown_at TEXT,reconciled_at TEXT,reconciled_revision INTEGER,"
                "PRIMARY KEY(host_id,job_id));"
            )

    def _check_paths(self):
        for path in (
            self.path,
            *(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm")),
        ):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("Patch store does not follow links")
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Patch store requires ordinary single-link files")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError("Patch store files must belong to the controller")
        if not self.path.exists():
            raise ValueError("Patch store disappeared")

    @contextmanager
    def _connection(self):
        self._check_paths()
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.row_factory = sqlite3.Row
            yield connection

    @staticmethod
    def _record(row: sqlite3.Row | None, *, notice: bool = False) -> dict | None:
        if row is None:
            return None
        result = {
            **json.loads(row["payload"]),
            "host_id": row["host_id"],
            "received_at": row["received_at"],
        }
        if "notification_count" in row.keys():  # noqa: SIM118 -- sqlite Row tests values, not keys.
            result.update(
                notification_due=notice,
                notification_count=row["notification_count"],
                last_notified_at=row["last_notified_at"],
            )
        return result

    def save_scan(self, host_id: str, payload: dict) -> None:
        _, text = _document(host_id, payload, MAX_SCAN_BYTES)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO patch_scans VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET "
                "received_at=excluded.received_at,payload=excluded.payload",
                (host_id, datetime.now(UTC).isoformat(), text),
            )
            connection.execute(
                "DELETE FROM patch_scans WHERE host_id IN (SELECT host_id FROM patch_scans "
                "ORDER BY received_at DESC,host_id LIMIT -1 OFFSET ?)",
                (MAX_SCANS,),
            )

    def latest_scan(self, host_id: str) -> dict | None:
        _host(host_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM patch_scans WHERE host_id=?", (host_id,)
            ).fetchone()
        return self._record(row)

    def save_plan(self, host_id: str, payload: dict) -> None:
        value, text = _document(host_id, payload, MAX_RECORD_BYTES)
        plan_id = _identifier(value.get("plan_id"))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT payload FROM patch_plans WHERE host_id=? AND plan_id=?", (host_id, plan_id)
            ).fetchone()
            if old is not None:
                if json.loads(old["payload"]) != value:
                    raise ValueError("Remote patch plans are immutable")
                return
            connection.execute(
                "INSERT INTO patch_plans VALUES(?,?,?,?)",
                (host_id, plan_id, datetime.now(UTC).isoformat(), text),
            )
            connection.execute(
                "DELETE FROM patch_plans WHERE rowid IN (SELECT rowid FROM patch_plans "
                "ORDER BY received_at DESC,host_id,plan_id LIMIT -1 OFFSET ?)",
                (MAX_PLANS,),
            )

    def get_plan(self, host_id: str, plan_id: str) -> dict | None:
        _host(host_id)
        _identifier(plan_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM patch_plans WHERE host_id=? AND plan_id=?", (host_id, plan_id)
            ).fetchone()
        return self._record(row)

    def save_job(
        self,
        host_id: str,
        payload: dict,
        *,
        from_status: bool = False,
        current_host_scope: str | None = None,
        current_policy_digest: str | None = None,
    ) -> dict:
        status_binding = (current_host_scope, current_policy_digest) if from_status else None
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._save_job(
                connection,
                host_id,
                payload,
                now=datetime.now(UTC).isoformat(),
                status_binding=status_binding,
            )

    @staticmethod
    def _reconcile_handoff(connection, host_id, job_id, value, now, status_binding) -> None:
        row = connection.execute(
            "SELECT * FROM patch_handoff_audit WHERE host_id=? AND job_id=? "
            "AND unknown_at IS NOT NULL AND reconciled_at IS NULL",
            (host_id, job_id),
        ).fetchone()
        if (
            row is None
            or status_binding != (row["host_scope"], row["policy_digest"])
            or not row["approved_at"] <= row["unknown_at"] <= now
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or type(value.get("revision")) is not int
            or value["revision"] < 1
            or type(value.get("mode_revision")) is not int
            or value["status"] == "unknown"
            or _NON_NATIVE_JOB_FIELDS & value.keys()
            or value.get("execution_policy_digest", row["policy_digest"]) != row["policy_digest"]
            or any(
                value.get(field) != row[field]
                for field in (
                    "host_id",
                    "job_id",
                    "plan_id",
                    "plan_digest",
                    "policy_digest",
                    "mode_revision",
                    "authorization",
                )
            )
        ):
            return
        connection.execute(
            "UPDATE patch_handoff_audit SET reconciled_at=?,reconciled_revision=? "
            "WHERE host_id=? AND job_id=?",
            (now, value["revision"], host_id, job_id),
        )

    def _save_job(self, connection, host_id, payload, *, now, status_binding=None) -> dict:
        value, text = _document(host_id, payload, MAX_RECORD_BYTES)
        job_id = _identifier(value.get("job_id"))
        status = value.get("status")
        if not isinstance(status, str) or status not in TERMINAL_STATES | ACTIVE_STATES:
            raise ValueError("Unknown remote patch job state")
        revision = value.get("revision")
        if revision is not None and (type(revision) is not int or not 0 <= revision <= 2**63 - 1):
            raise ValueError("Invalid remote job revision")
        old = connection.execute(
            "SELECT * FROM patch_jobs WHERE host_id=? AND job_id=?", (host_id, job_id)
        ).fetchone()
        if old is not None and old["revision"] is not None:
            old_payload = json.loads(old["payload"])
            transport_unknown = old_payload.get("transport_unknown") is True
            if revision is None or revision < old["revision"]:
                result = self._record(old)
                if result is None:
                    raise ValueError("Missing cached patch job")
                return result
            if revision == old["revision"] and old_payload != value and not transport_unknown:
                raise ValueError("Conflicting remote job revision")
        notice = status in TERMINAL_STATES and (old is None or old["status"] != status)
        count = (old["notification_count"] if old is not None else 0) + int(notice)
        notified_at = now if notice else old["last_notified_at"] if old is not None else None
        if old is None:
            count_rows = connection.execute("SELECT COUNT(*) FROM patch_jobs").fetchone()[0]
            if count_rows >= MAX_JOBS:
                candidates = connection.execute(
                    "SELECT host_id,job_id,status FROM patch_jobs "
                    "ORDER BY received_at,host_id,job_id"
                ).fetchall()
                oldest = next((row for row in candidates if row["status"] in TERMINAL_STATES), None)
                if oldest is None:
                    raise ValueError("Patch job cache is full of active jobs")
                identity = (oldest["host_id"], oldest["job_id"])
                connection.execute("DELETE FROM patch_jobs WHERE host_id=? AND job_id=?", identity)
                connection.execute(
                    "DELETE FROM patch_handoff_audit WHERE host_id=? AND job_id=?", identity
                )
        connection.execute(
            "INSERT INTO patch_jobs VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,job_id) DO UPDATE SET "
            "received_at=excluded.received_at,status=excluded.status,revision=excluded.revision,"
            "payload=excluded.payload,notification_count=excluded.notification_count,"
            "last_notified_at=excluded.last_notified_at",
            (host_id, job_id, now, status, revision, text, count, notified_at),
        )
        connection.execute(
            "DELETE FROM patch_submit_intents WHERE host_id=? AND job_id=?", (host_id, job_id)
        )
        if status_binding is not None:
            self._reconcile_handoff(connection, host_id, job_id, value, now, status_binding)
        row = connection.execute(
            "SELECT * FROM patch_jobs WHERE host_id=? AND job_id=?", (host_id, job_id)
        ).fetchone()
        result = self._record(row, notice=notice)
        if result is None:
            raise ValueError("Missing saved patch job")
        return result

    def mark_unknown(
        self,
        host_id: str,
        job_id: str,
        plan_id: str,
        *,
        automatic_status_binding: tuple[str, str, str, str] | None = None,
    ) -> dict:
        """Record lost submit transport without discarding a known remote revision."""
        _host(host_id)
        _identifier(job_id)
        _identifier(plan_id)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = datetime.now(UTC).isoformat()
            old = connection.execute(
                "SELECT * FROM patch_jobs WHERE host_id=? AND job_id=?", (host_id, job_id)
            ).fetchone()
            if old is not None and automatic_status_binding is not None:
                scope, policy, grant_id, grant_digest = automatic_status_binding
                audit = connection.execute(
                    "SELECT * FROM patch_handoff_audit WHERE host_id=? AND job_id=?",
                    (host_id, job_id),
                ).fetchone()
                payload = json.loads(old["payload"])
                if (
                    audit is not None
                    and (audit["host_scope"], audit["policy_digest"]) == (scope, policy)
                    and audit["authorization"] == "automatic"
                    and audit["plan_id"] == plan_id
                    and old["status"] in TERMINAL_STATES - {"unknown"}
                    and payload.get("status") == old["status"]
                    and type(payload.get("revision")) is int
                    and 0 < payload["revision"] == old["revision"]
                    and type(payload.get("schema_version")) is int
                    and payload["schema_version"] == 1
                    and type(payload.get("mode_revision")) is int
                    and not (_NON_NATIVE_JOB_FIELDS & payload.keys())
                    and all(
                        payload.get(field) == audit[field]
                        for field in (
                            "host_id",
                            "job_id",
                            "plan_id",
                            "plan_digest",
                            "mode_revision",
                            "authorization",
                            "policy_digest",
                        )
                    )
                    and payload.get("execution_policy_digest", policy) == policy
                    and payload.get("automatic_grant_id") == grant_id
                    and payload.get("automatic_grant_digest") == grant_digest
                ):
                    # An exact native terminal receipt already settled the job.
                    # Record the ambiguous acknowledgment and its reconciliation
                    # together, leaving the result and its notification intact.
                    connection.execute(
                        "UPDATE patch_handoff_audit SET unknown_at=COALESCE(unknown_at,?),"
                        "reconciled_at=COALESCE(reconciled_at,?),"
                        "reconciled_revision=COALESCE(reconciled_revision,?) "
                        "WHERE host_id=? AND job_id=?",
                        (now, now, payload["revision"], host_id, job_id),
                    )
                    cached = self._record(old)
                    if cached is None:
                        raise ValueError("Missing cached patch job")
                    return cached
            connection.execute(
                "UPDATE patch_handoff_audit SET unknown_at="
                "CASE WHEN reconciled_at IS NOT NULL THEN ? ELSE COALESCE(unknown_at,?) END, "
                "reconciled_at=NULL,reconciled_revision=NULL "
                "WHERE host_id=? AND job_id=? AND plan_id=?",
                (now, now, host_id, job_id, plan_id),
            )
            if old is None:
                # Use the normal retention and notification transaction for the initial placeholder.
                intent = connection.execute(
                    "SELECT payload FROM patch_submit_intents WHERE host_id=? AND job_id=?",
                    (host_id, job_id),
                ).fetchone()
                initial = json.loads(intent["payload"]) if intent is not None else {}
                if initial.get("plan_id") not in {None, plan_id}:
                    raise ValueError("Unknown transport belongs to another plan")
                return self._save_job(
                    connection,
                    host_id,
                    initial
                    | {
                        "job_id": job_id,
                        "plan_id": plan_id,
                        "status": "unknown",
                        "transport_unknown": True,
                        "detail": "提交连接结果未确认，正在查询原任务；不会自动重新安装。",
                    },
                    now=now,
                )
            else:
                payload = json.loads(old["payload"])
                if payload.get("plan_id") not in {None, plan_id}:
                    raise ValueError("Unknown transport belongs to another plan")
                notice = old["status"] != "unknown"
                if "revision" in payload:
                    payload["last_remote_revision"] = payload.pop("revision")
                payload.update(
                    status="unknown",
                    transport_unknown=True,
                    plan_id=plan_id,
                    detail="提交连接结果未确认，正在查询原任务；不会自动重新安装。",
                )
                connection.execute(
                    "UPDATE patch_jobs SET received_at=?,status='unknown',payload=?,"
                    "notification_count=?,last_notified_at=? WHERE host_id=? AND job_id=?",
                    (
                        now,
                        json.dumps(payload, ensure_ascii=False),
                        old["notification_count"] + int(notice),
                        now if notice else old["last_notified_at"],
                        host_id,
                        job_id,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM patch_jobs WHERE host_id=? AND job_id=?", (host_id, job_id)
                ).fetchone()
                result = self._record(row, notice=notice)
                if result is None:
                    raise ValueError("Missing unknown task")
                return result

    def pollable_jobs(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM patch_jobs WHERE status IN (?,?,?,?,?,?,?,?) "
                "ORDER BY received_at,host_id,job_id LIMIT ?",
                (*sorted(ACTIVE_STATES | {"unknown"}), MAX_JOBS),
            ).fetchall()
            pending = connection.execute(
                "SELECT * FROM patch_submit_intents i WHERE NOT EXISTS (SELECT 1 FROM patch_jobs j "
                "WHERE j.host_id=i.host_id AND j.job_id=i.job_id) ORDER BY received_at LIMIT ?",
                (MAX_JOBS,),
            ).fetchall()
        return [value for row in (*rows, *pending) if (value := self._record(row)) is not None]

    def register_submission(
        self,
        host_id: str,
        job_id: str,
        plan_id: str,
        plan_digest: str,
        mode_revision: int,
        *,
        host_scope: str | None = None,
        policy_digest: str | None = None,
        authorization: str | None = None,
    ) -> bool:
        """Persist identifiers before transport; a duplicate is queried rather than resent."""
        _host(host_id)
        _identifier(job_id)
        _identifier(plan_id)
        if not _digest(plan_digest) or type(mode_revision) is not int or mode_revision < 0:
            raise ValueError("Invalid patch submission binding")
        audited = (host_scope, policy_digest, authorization) != (None, None, None)
        if audited and (
            not _digest(host_scope)
            or not _digest(policy_digest)
            or authorization not in {"assisted", "automatic"}
        ):
            raise ValueError("Invalid patch handoff approval binding")
        payload = {
            "job_id": job_id,
            "plan_id": plan_id,
            "plan_digest": plan_digest,
            "mode_revision": mode_revision,
            "status": "unknown",
            "transport_unknown": True,
            "detail": "已保存提交意图，远端执行结果尚未确认；只查询此任务，不重复安装。",
        }
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload FROM patch_jobs WHERE host_id=? AND job_id=? UNION ALL "
                "SELECT payload FROM patch_submit_intents WHERE host_id=? AND job_id=?",
                (host_id, job_id, host_id, job_id),
            ).fetchone()
            if existing is not None:
                previous = json.loads(existing["payload"])
                if previous.get("plan_id") != plan_id or previous.get("plan_digest") not in {
                    None,
                    plan_digest,
                }:
                    raise ValueError("Task identifier is bound to another plan")
                return False
            count = connection.execute("SELECT COUNT(*) FROM patch_submit_intents").fetchone()[0]
            if count >= MAX_JOBS:
                raise ValueError("Too many unresolved patch submission intents")
            approved_at = datetime.now(UTC).isoformat()
            connection.execute(
                "INSERT INTO patch_submit_intents VALUES(?,?,?,?)",
                (
                    host_id,
                    job_id,
                    approved_at,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            if audited:
                connection.execute(
                    "INSERT INTO patch_handoff_audit (host_id,job_id,host_scope,policy_digest,"
                    "plan_id,plan_digest,mode_revision,authorization,approved_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        host_id,
                        job_id,
                        host_scope,
                        policy_digest,
                        plan_id,
                        plan_digest,
                        mode_revision,
                        authorization,
                        approved_at,
                    ),
                )
        return True

    def get_handoff_audit(self, host_id: str, job_id: str) -> dict | None:
        _host(host_id)
        _identifier(job_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM patch_handoff_audit WHERE host_id=? AND job_id=?", (host_id, job_id)
            ).fetchone()
        return dict(row) if row is not None else None

    def claim_monitor(self, owner: str, *, ttl_seconds: int = 45) -> bool:
        _identifier(owner)
        if type(ttl_seconds) is not int or not 20 <= ttl_seconds <= 120:
            raise ValueError("Invalid patch polling lease")
        now = datetime.now(UTC).timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT owner,expires_at FROM patch_monitor_lease").fetchone()
            if row is not None and row["owner"] != owner and row["expires_at"] > now:
                return False
            connection.execute(
                "INSERT INTO patch_monitor_lease VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET "
                "owner=excluded.owner,expires_at=excluded.expires_at",
                (owner, now + ttl_seconds),
            )
        return True

    def release_monitor(self, owner: str) -> None:
        _identifier(owner)
        with self._connection() as connection:
            connection.execute("DELETE FROM patch_monitor_lease WHERE owner=?", (owner,))

    def get_job(self, host_id: str, job_id: str) -> dict | None:
        _host(host_id)
        _identifier(job_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM patch_jobs WHERE host_id=? AND job_id=?", (host_id, job_id)
            ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT * FROM patch_submit_intents WHERE host_id=? AND job_id=?",
                    (host_id, job_id),
                ).fetchone()
        return self._record(row)

    def list_jobs(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Patch job listing limit must be between 1 and 100")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM patch_jobs ORDER BY received_at DESC,host_id,job_id LIMIT ?",
                (limit,),
            ).fetchall()
            pending = connection.execute(
                "SELECT * FROM patch_submit_intents i WHERE NOT EXISTS (SELECT 1 FROM patch_jobs j "
                "WHERE j.host_id=i.host_id AND j.job_id=i.job_id) "
                "ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = [value for row in (*rows, *pending) if (value := self._record(row)) is not None]
        return sorted(results, key=lambda value: value["received_at"], reverse=True)[:limit]
