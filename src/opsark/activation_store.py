"""Durable, single-submit service activation records inside the existing patch database."""

import json
import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import timedelta
from pathlib import Path

from opsark.automatic_store import canonical, digest, instant
from opsark.patch_store import PatchStore

MAX_RECORDS = 1000
MAX_BYTES = 262_144
MAX_TOTAL_BYTES = 64 * 1024 * 1024
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
REMOTE_ACTIVE = {
    "queued",
    "preflight",
    "restarting",
    "verifying",
    "awaiting_transport_verification",
    "running_overdue",
}
TERMINAL = {"verified", "verification_failed", "rejected"}
STATES = REMOTE_ACTIVE | TERMINAL | {"prepared", "submission_intent", "unknown"}
NOTICE = TERMINAL | {"unknown", "running_overdue"}


def identity(host_id, activation_id):
    if not isinstance(host_id, str) or HOST.fullmatch(host_id) is None:
        raise ValueError("Invalid activation host")
    if not isinstance(activation_id, str) or ID.fullmatch(activation_id) is None:
        raise ValueError("Invalid activation identity")


def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _copy(value):
    text = canonical(value)
    if len(text.encode()) > MAX_BYTES:
        raise ValueError("Activation record exceeded its evidence budget")
    return json.loads(text)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate activation field")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("Invalid activation number")


def _anchor(value):
    return digest(
        {
            k: value[k]
            for k in (
                "host_id",
                "activation_id",
                "activation_digest",
                "job_id",
                "job_revision",
                "job_digest",
                "scope_hash",
                "policy_digest",
                "controller_policy_digest",
                "plan",
                "original_job",
            )
        }
    )


class ActivationStore:
    """Never evicts an intent or deletes a completed activation identity."""

    def __init__(self, path: Path):
        self.path = path
        self._patch = PatchStore(path)
        with self._patch._connection() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS service_activation_records("
                "host_id TEXT NOT NULL,activation_id TEXT NOT NULL,status TEXT NOT NULL,"
                "root_revision INTEGER,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,"
                "anchor_digest TEXT NOT NULL,payload TEXT NOT NULL,"
                "PRIMARY KEY(host_id,activation_id));"
                "CREATE INDEX IF NOT EXISTS service_activation_order ON "
                "service_activation_records(status,updated_at);"
                "CREATE TABLE IF NOT EXISTS service_activation_monitor("
                "id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires_at TEXT NOT NULL);"
            )

    @staticmethod
    def _read(row):
        try:
            return ActivationStore._read_validated(row)
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise ValueError("Activation record is inconsistent") from None

    @staticmethod
    def _read_validated(row):
        if row is None:
            return None
        if not isinstance(row["payload"], str) or len(row["payload"].encode()) > MAX_BYTES:
            raise ValueError("Activation record exceeded its evidence budget")
        value = json.loads(row["payload"], object_pairs_hook=_unique, parse_constant=_constant)
        if canonical(value) != row["payload"]:
            raise ValueError("Activation record is not canonical")
        identity(value["host_id"], value["activation_id"])
        if (
            type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value["host_id"] != row["host_id"]
            or value["activation_id"] != row["activation_id"]
            or value["status"] != row["status"]
            or value["status"] not in STATES
            or value["root_revision"] != row["root_revision"]
            or value["root_revision"] is not None
            and (type(value["root_revision"]) is not int or value["root_revision"] < 1)
            or value["created_at"] != row["created_at"]
            or value["updated_at"] != row["updated_at"]
            or _anchor(value) != row["anchor_digest"]
            or not _hex(value["activation_digest"])
            or not _hex(value["scope_hash"])
            or not _hex(value["policy_digest"])
            or not _hex(value["controller_policy_digest"])
            or type(value["notification_count"]) is not int
            or value["notification_count"] < 0
            or type(value["acknowledged"]) is not bool
        ):
            raise ValueError("Activation record is inconsistent")
        return _copy(value)

    @staticmethod
    def _write(connection, value):
        text = canonical(_copy(value))
        used = connection.execute(
            "SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM service_activation_records "
            "WHERE NOT(host_id=? AND activation_id=?)",
            (value["host_id"], value["activation_id"]),
        ).fetchone()[0]
        if used + len(text.encode()) > MAX_TOTAL_BYTES:
            raise ValueError("Activation evidence ledger is full; history is retained")
        connection.execute(
            "INSERT INTO service_activation_records VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,activation_id) DO UPDATE SET status=excluded.status,"
            "root_revision=excluded.root_revision,updated_at=excluded.updated_at,payload=excluded.payload",
            (
                value["host_id"],
                value["activation_id"],
                value["status"],
                value["root_revision"],
                value["created_at"],
                value["updated_at"],
                _anchor(value),
                text,
            ),
        )

    def save_plan(
        self, host_id, plan, *, scope_hash, controller_policy_digest, original_job, now=None
    ):
        identity(host_id, plan.get("activation_id"))
        if not _hex(scope_hash) or not _hex(controller_policy_digest):
            raise ValueError("Activation scope is unavailable")
        if not isinstance(original_job, dict) or digest(original_job) != plan["job_digest"]:
            raise ValueError("Original patch snapshot does not match activation preview")
        value = _copy(
            {
                "schema_version": 1,
                "host_id": host_id,
                "activation_id": plan["activation_id"],
                "activation_digest": plan["activation_digest"],
                "job_id": plan["job_id"],
                "job_revision": plan["job_revision"],
                "job_digest": plan["job_digest"],
                "scope_hash": scope_hash,
                "policy_digest": plan["policy_digest"],
                "controller_policy_digest": controller_policy_digest,
                "plan": plan,
                "original_job": original_job,
                "status": "prepared",
                "root_revision": None,
                "result": None,
                "created_at": instant(now).isoformat(),
                "updated_at": instant(now).isoformat(),
                "submitted_at": None,
                "completed_at": None,
                "notification_count": 0,
                "last_notified_at": None,
                "acknowledged": False,
                "detail": "已保存服务激活预览；尚未批准或执行。",
                "rescan_reference": None,
            }
        )
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, plan["activation_id"]),
                ).fetchone()
            )
            if old is not None:
                if _anchor(old) != _anchor(value):
                    raise ValueError("Activation identity is already bound")
                return old
            if (
                connection.execute("SELECT COUNT(*) FROM service_activation_records").fetchone()[0]
                >= MAX_RECORDS
            ):
                raise ValueError("Activation identity ledger is full; history is retained")
            self._write(connection, value)
        return value

    def get(self, host_id, activation_id):
        identity(host_id, activation_id)
        with self.readonly() as connection:
            return self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, activation_id),
                ).fetchone()
            )

    def list(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= MAX_RECORDS:
            raise ValueError("Invalid activation list budget")
        with self.readonly() as connection:
            return [
                self._read(row)
                for row in connection.execute(
                    "SELECT * FROM service_activation_records ORDER BY "
                    "CASE WHEN status IN ('submission_intent','unknown') THEN 0 ELSE 1 END,"
                    "updated_at DESC,host_id,activation_id LIMIT ?",
                    (limit,),
                ).fetchall()
            ]

    def pending(self, host_id=None):
        values = self.list(limit=MAX_RECORDS)
        return [
            v
            for v in values
            if (host_id is None or v["host_id"] == host_id)
            and v["status"] not in {"prepared", "verified", "rejected"}
        ]

    def pollable(self):
        return [
            v
            for v in self.list(limit=MAX_RECORDS)
            if v["status"] in REMOTE_ACTIVE | {"submission_intent", "unknown"}
        ]

    @contextmanager
    def readonly(self):
        self._patch._check_paths()
        path = self.path.absolute()
        before = path.stat()
        with closing(
            sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
        ) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            yield connection
            connection.rollback()
        self._patch._check_paths()
        after = path.stat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("Activation database identity changed while reading")

    def attach_rescan(self, host_id, activation_id, reference):
        identity(host_id, activation_id)
        fields = {
            "activation_id",
            "original_job_id",
            "host_id",
            "rescan_request_id",
            "event_key",
            "scope_hash",
        }
        if (
            not isinstance(reference, dict)
            or set(reference) != fields
            or reference["activation_id"] != activation_id
            or reference["host_id"] != host_id
            or not isinstance(reference["original_job_id"], str)
            or ID.fullmatch(reference["original_job_id"]) is None
            or not isinstance(reference["event_key"], str)
            or ID.fullmatch(reference["event_key"]) is None
            or reference["event_key"] != activation_id
            or not isinstance(reference["rescan_request_id"], str)
            or ID.fullmatch(reference["rescan_request_id"]) is None
            or not _hex(reference["scope_hash"])
        ):
            raise ValueError("Activation observation reference is invalid")
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, activation_id),
                ).fetchone()
            )
            if (
                record is None
                or record["status"] != "verified"
                or record["job_id"] != reference["original_job_id"]
            ):
                raise ValueError("Only the original verified activation may link observation")
            if record["rescan_reference"] is not None and record["rescan_reference"] != reference:
                raise ValueError("Activation observation reference is immutable")
            record["rescan_reference"] = _copy(reference)
            self._write(connection, record)
            return record

    def begin_submission(
        self, host_id, activation_id, activation_digest, mode_revision, *, now=None
    ):
        identity(host_id, activation_id)
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, activation_id),
                ).fetchone()
            )
            if record is None:
                raise ValueError("Original activation preview is missing")
            if record["activation_digest"] != activation_digest:
                raise ValueError("Activation approval digest changed")
            if record["status"] != "prepared":
                return False, record
            if record["plan"]["mode_revision"] != mode_revision:
                raise ValueError("Activation mode revision changed")
            blocked = connection.execute(
                "SELECT activation_id FROM service_activation_records WHERE host_id=? "
                "AND activation_id!=? AND status NOT IN ('prepared','verified','rejected') LIMIT 1",
                (host_id, activation_id),
            ).fetchone()
            if blocked is not None:
                raise ValueError("Another activation remains unresolved")
            record.update(
                status="submission_intent",
                submitted_at=instant(now).isoformat(),
                updated_at=instant(now).isoformat(),
                detail="原激活 ID 的提交意图已保存；结果未知时只查询，不重发。",
            )
            self._write(connection, record)
            return True, record

    def outcome(self, host_id, activation_id, *, result=None, status=None, detail, now=None):
        identity(host_id, activation_id)
        at = instant(now).isoformat()
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, activation_id),
                ).fetchone()
            )
            if record is None or record["submitted_at"] is None:
                raise ValueError("An original submission intent is required")
            next_state = result["status"] if result is not None else status
            if result is None and next_state not in {"unknown", "rejected"}:
                raise ValueError("An authoritative activation result is required")
            if next_state not in STATES - {"prepared", "submission_intent"}:
                raise ValueError("Unknown activation outcome")
            if record["status"] in TERMINAL:
                if result is None or record["result"] == result:
                    return record
                raise ValueError("A final activation receipt is immutable")
            if result is not None:
                revision = result.get("revision")
                if type(revision) is not int or revision < 1:
                    raise ValueError("Activation revision is unavailable")
                if record["root_revision"] is not None:
                    if revision < record["root_revision"]:
                        return record
                    if revision == record["root_revision"] and record["result"] != result:
                        raise ValueError("Conflicting activation revision")
                record.update(result=_copy(result), root_revision=revision)
            notice = next_state in NOTICE and record["status"] != next_state
            record.update(status=next_state, updated_at=at, detail=detail)
            if notice:
                record.update(
                    notification_count=record["notification_count"] + 1,
                    last_notified_at=at,
                    acknowledged=False,
                )
            if next_state in TERMINAL:
                record["completed_at"] = at
            self._write(connection, record)
            return record

    def acknowledge(self, host_id, activation_id, *, now=None):
        identity(host_id, activation_id)
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = self._read(
                connection.execute(
                    "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
                    (host_id, activation_id),
                ).fetchone()
            )
            if record is None:
                return None
            record.update(acknowledged=True, updated_at=instant(now).isoformat())
            self._write(connection, record)
            return record

    def claim_monitor(self, owner, *, now=None):
        if not isinstance(owner, str) or ID.fullmatch(owner) is None:
            raise ValueError("Invalid activation monitor identity")
        at = instant(now)
        with self._patch._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute(
                "SELECT * FROM service_activation_monitor WHERE id=1"
            ).fetchone()
            if old is not None and old["owner"] != owner and instant_from(old["expires_at"]) > at:
                return False
            connection.execute(
                "INSERT INTO service_activation_monitor VALUES(1,?,?) ON CONFLICT(id) DO UPDATE "
                "SET owner=excluded.owner,expires_at=excluded.expires_at",
                (owner, (at + timedelta(seconds=120)).isoformat()),
            )
            return True

    def release_monitor(self, owner):
        with self._patch._connection() as connection:
            connection.execute(
                "DELETE FROM service_activation_monitor WHERE id=1 AND owner=?", (owner,)
            )


def instant_from(value):
    from datetime import datetime

    if not isinstance(value, str):
        raise ValueError("Missing activation time")
    return instant(datetime.fromisoformat(value))
