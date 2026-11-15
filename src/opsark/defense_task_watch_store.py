"""CAS-fenced read-only follow-up scheduling in the existing security database.

This store never changes Root requests, approvals, modes, usage or latches. Claims
only permit a new query of an existing RID; they cannot authorize any mutation.
"""

import secrets
from datetime import datetime, timedelta

from pydantic import TypeAdapter

from opsark.defense_models import ActionBody, Identifier, digest, utc
from opsark.defense_store import DefenseConflict, DefenseStore, Host, _now, _stamp
from opsark.defense_task_watch_models import (
    TaskWatchClaim,
    TaskWatchEvent,
    TaskWatchLease,
    WatchState,
)

MAX_TASKS = 2048
MAX_EVENTS = 4096
MAX_ATTEMPTS = 24
MAX_DAILY_ATTEMPTS = 8
DISCOVERY_PAGE = 32
LEASE_SECONDS = 120
CLAIM_SECONDS = 90
TERMINAL = frozenset(
    {
        "expired",
        "revoked",
        "not_found",
        "rejected",
        "registration_changed",
        "attempt_limit",
        "capacity_limit",
    }
)


def _hosts(host_ids):
    if type(host_ids) not in (tuple, list) or any(type(host) is not str for host in host_ids):
        raise DefenseConflict("Task watch target allowlist is invalid")
    result = tuple(sorted(host_ids))
    if not result or len(result) > 10 or len(set(result)) != len(result):
        raise DefenseConflict("Task watch target allowlist is invalid")
    for host in result:
        try:
            if type(host) is not str:
                raise ValueError
            TypeAdapter(Host).validate_python(host)
        except ValueError:
            raise DefenseConflict("Task watch target allowlist is invalid") from None
    return result


class DefenseTaskWatchStore:
    def __init__(self, base: DefenseStore):
        if type(base) is not DefenseStore:
            raise TypeError("Task following requires the existing defense ledger")
        self.base, self.path = base, base.path
        with base._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS defense_task_watch_lease_v1(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), owner TEXT NOT NULL,
                    epoch INTEGER NOT NULL, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_task_watch_discovery_v1(
                    scope_sha256 TEXT PRIMARY KEY, after_sequence INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS defense_task_watch_apply_cursor_v1
                    ON defense_requests(op);
                CREATE TABLE IF NOT EXISTS defense_task_watches_v1(
                    rid TEXT PRIMARY KEY REFERENCES defense_transactions(rid),
                    host_id TEXT NOT NULL, defense_scope TEXT NOT NULL,
                    task_reference_sha256 TEXT NOT NULL,
                    due_at TEXT NOT NULL, terminal INTEGER NOT NULL DEFAULT 0,
                    last_state TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                    charged_day TEXT NOT NULL, daily_attempts INTEGER NOT NULL DEFAULT 0,
                    failures INTEGER NOT NULL DEFAULT 0, claim_ref TEXT,
                    claim_until TEXT, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS defense_task_watch_due_v1
                    ON defense_task_watches_v1(terminal,due_at,host_id);
                CREATE TABLE IF NOT EXISTS defense_task_watch_attempts_v1(
                    claim_ref TEXT PRIMARY KEY, rid TEXT NOT NULL
                    REFERENCES defense_task_watches_v1(rid), owner TEXT NOT NULL,
                    epoch INTEGER NOT NULL, claimed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL, attempt INTEGER NOT NULL,
                    finished_at TEXT, state TEXT
                );
                CREATE TABLE IF NOT EXISTS defense_task_watch_events_v1(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_ref TEXT NOT NULL UNIQUE, rid TEXT NOT NULL
                    REFERENCES defense_task_watches_v1(rid), host_id TEXT NOT NULL,
                    task_reference_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                    observed_at TEXT NOT NULL, acknowledged_at TEXT
                );
            """)

    @staticmethod
    def _lease(db, lease, now):
        if type(lease) is not TaskWatchLease:
            raise DefenseConflict("Task watch lease is not a permit")
        row = db.execute("SELECT * FROM defense_task_watch_lease_v1").fetchone()
        if (
            row is None
            or (row["owner"], row["epoch"], row["expires_at"])
            != (lease.owner, lease.epoch, lease.expires_at)
            or utc(lease.expires_at) <= now
        ):
            raise DefenseConflict("Task watch lease is no longer current")

    def acquire(self, owner: str, *, now: datetime | None = None):
        instant = _now(now)
        candidate = TaskWatchLease(
            owner=owner, epoch=0, expires_at=_stamp(instant + timedelta(seconds=LEASE_SECONDS))
        )
        with self.base._write() as db:
            old = db.execute("SELECT * FROM defense_task_watch_lease_v1").fetchone()
            if old is not None and utc(old["expires_at"]) > instant:
                return None
            candidate = TaskWatchLease(
                owner=candidate.owner,
                expires_at=candidate.expires_at,
                epoch=0 if old is None else old["epoch"] + 1,
            )
            db.execute(
                "INSERT INTO defense_task_watch_lease_v1 VALUES(1,?,?,?) "
                "ON CONFLICT(singleton) DO UPDATE SET owner=excluded.owner,"
                "epoch=excluded.epoch,expires_at=excluded.expires_at",
                (candidate.owner, candidate.epoch, candidate.expires_at),
            )
        return candidate

    def renew(self, lease: TaskWatchLease, *, now: datetime | None = None):
        instant = _now(now)
        with self.base._write() as db:
            self._lease(db, lease, instant)
            fresh = lease.model_copy(
                update={"expires_at": _stamp(instant + timedelta(seconds=LEASE_SECONDS))}
            )
            db.execute(
                "UPDATE defense_task_watch_lease_v1 SET expires_at=? WHERE singleton=1",
                (fresh.expires_at,),
            )
        return fresh

    def release(self, lease: TaskWatchLease, *, now: datetime | None = None):
        with self.base._write() as db:
            db.execute(
                "UPDATE defense_task_watch_lease_v1 SET expires_at=? WHERE singleton=1 "
                "AND owner=? AND epoch=? AND expires_at=?",
                (_stamp(_now(now)), lease.owner, lease.epoch, lease.expires_at),
            )

    def discover(self, lease, host_ids, *, now=None):
        hosts, instant = _hosts(host_ids), _now(now)
        scope = digest({"host_ids": hosts, "kind": "original-apply-query/v1"})
        with self.base._write() as db:
            self._lease(db, lease, instant)
            row = db.execute(
                "SELECT after_sequence FROM defense_task_watch_discovery_v1 WHERE scope_sha256=?",
                (scope,),
            ).fetchone()
            cursor = row[0] if row else 0
            rows = db.execute(
                "SELECT r.rowid AS sequence,r.rid,t.host_id,t.kind FROM defense_requests r "
                "JOIN defense_transactions t ON t.rid=r.rid "
                "WHERE r.op='apply' AND r.rowid>? ORDER BY r.rowid LIMIT ?",
                (cursor, DISCOVERY_PAGE),
            ).fetchall()
            count = db.execute("SELECT count(*) FROM defense_task_watches_v1").fetchone()[0]
            for row in rows:
                if row["host_id"] not in hosts or row["kind"] != "action":
                    cursor = row["sequence"]
                    continue
                transaction = self.base._transaction(db, row["rid"])
                request = self.base._request(db, transaction.rid, "apply")
                manifest = self.base._manifest(db, transaction.rid)
                if (
                    not isinstance(request.body, ActionBody)
                    or request.body.manifest_sha256 != manifest.sha256
                ):
                    raise DefenseConflict("Original task follow-up binding changed")
                if transaction.phase in {
                    "revoked",
                    "expired",
                    "rejected",
                    "not_found",
                    "ready_expired",
                    "invalid",
                }:
                    cursor = row["sequence"]
                    continue
                if count >= MAX_TASKS:
                    break  # Retain the discovery cursor; never discard older records.
                reference = digest(
                    {
                        "v": 1,
                        "host_id": transaction.context.host_id,
                        "request_id": transaction.rid,
                        "manifest_sha256": manifest.sha256,
                    }
                )
                inserted = db.execute(
                    "INSERT OR IGNORE INTO defense_task_watches_v1(rid,host_id,defense_scope,"
                    "task_reference_sha256,due_at,charged_day,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        transaction.rid,
                        transaction.context.host_id,
                        transaction.context.defense_scope,
                        reference,
                        _stamp(instant),
                        instant.date().isoformat(),
                        _stamp(instant),
                    ),
                ).rowcount
                count += inserted
                cursor = row["sequence"]
            db.execute(
                "INSERT INTO defense_task_watch_discovery_v1 VALUES(?,?) "
                "ON CONFLICT(scope_sha256) DO UPDATE SET after_sequence=excluded.after_sequence",
                (scope, cursor),
            )
            return len(rows)

    def discovery_incomplete(self, host_ids):
        hosts = _hosts(host_ids)
        scope = digest({"host_ids": hosts, "kind": "original-apply-query/v1"})
        with self.base._connection() as db:
            row = db.execute(
                "SELECT after_sequence FROM defense_task_watch_discovery_v1 WHERE scope_sha256=?",
                (scope,),
            ).fetchone()
            # The op index carries rowid, so this is an indexed endpoint lookup,
            # not a scan of old observations or the entire history at every tick.
            latest = db.execute(
                "SELECT MAX(rowid) FROM defense_requests WHERE op='apply'"
            ).fetchone()[0]
        return (row[0] if row else 0) < (latest or 0)

    @staticmethod
    def _event(db, row, state, instant):
        if state == row["last_state"]:
            return
        count = db.execute("SELECT count(*) FROM defense_task_watch_events_v1").fetchone()[0]
        if count >= MAX_EVENTS:
            raise DefenseConflict("Task watch event capacity is exhausted")
        db.execute(
            "INSERT INTO defense_task_watch_events_v1(event_ref,rid,host_id,"
            "task_reference_sha256,state,observed_at) VALUES(?,?,?,?,?,?)",
            (
                secrets.token_hex(16),
                row["rid"],
                row["host_id"],
                row["task_reference_sha256"],
                state,
                _stamp(instant),
            ),
        )

    def claim_due(self, lease, host_ids, *, now=None):
        hosts, instant = _hosts(host_ids), _now(now)
        marks = ",".join("?" for _ in hosts)
        with self.base._write() as db:
            self._lease(db, lease, instant)
            row = db.execute(
                "SELECT * FROM defense_task_watches_v1 WHERE terminal=0 AND due_at<=? "  # noqa: S608 -- placeholders only.
                "AND (claim_ref IS NULL OR claim_until<=?) AND host_id IN ("
                + marks
                + ") ORDER BY due_at,rowid LIMIT 1",
                (_stamp(instant), _stamp(instant), *hosts),
            ).fetchone()  # noqa: S608 -- placeholders only.
            if row is None:
                return None
            events = db.execute("SELECT count(*) FROM defense_task_watch_events_v1").fetchone()[0]
            if events >= MAX_EVENTS - 1 or row["attempts"] >= MAX_ATTEMPTS:
                state = "capacity_limit" if events >= MAX_EVENTS - 1 else "attempt_limit"
                self._event(db, row, state, instant)
                db.execute(
                    "UPDATE defense_task_watches_v1 SET terminal=1,last_state=?,"
                    "updated_at=? WHERE rid=?",
                    (state, _stamp(instant), row["rid"]),
                )
                return None
            day = instant.date().isoformat()
            daily = row["daily_attempts"] if row["charged_day"] == day else 0
            if daily >= MAX_DAILY_ATTEMPTS:
                self._event(db, row, "daily_limit", instant)
                tomorrow = instant.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
                    days=1
                )
                db.execute(
                    "UPDATE defense_task_watches_v1 SET due_at=?,last_state='daily_limit',"
                    "updated_at=? WHERE rid=?",
                    (_stamp(tomorrow), _stamp(instant), row["rid"]),
                )
                return None
            claim = TaskWatchClaim(
                claim_ref=secrets.token_hex(16),
                host_id=row["host_id"],
                request_id=row["rid"],
                defense_scope=row["defense_scope"],
                task_reference_sha256=row["task_reference_sha256"],
                owner=lease.owner,
                epoch=lease.epoch,
                attempt=row["attempts"] + 1,
                claimed_at=_stamp(instant),
                expires_at=_stamp(
                    min(utc(lease.expires_at), instant + timedelta(seconds=CLAIM_SECONDS))
                ),
            )
            db.execute(
                "INSERT INTO defense_task_watch_attempts_v1(claim_ref,rid,owner,epoch,"
                "claimed_at,expires_at,attempt) VALUES(?,?,?,?,?,?,?)",
                (
                    claim.claim_ref,
                    claim.request_id,
                    claim.owner,
                    claim.epoch,
                    claim.claimed_at,
                    claim.expires_at,
                    claim.attempt,
                ),
            )
            db.execute(
                "UPDATE defense_task_watches_v1 SET claim_ref=?,claim_until=?,attempts=?,"
                "charged_day=?,daily_attempts=?,updated_at=? WHERE rid=?",
                (
                    claim.claim_ref,
                    claim.expires_at,
                    claim.attempt,
                    day,
                    daily + 1,
                    _stamp(instant),
                    claim.request_id,
                ),
            )
            return claim

    def assert_claim(self, lease, claim, *, now=None, connection=None):
        instant = _now(now)
        if connection is None:
            with self.base._connection() as db:
                return self.assert_claim(lease, claim, now=instant, connection=db)
        self._lease(connection, lease, instant)
        if type(claim) is not TaskWatchClaim or (claim.owner, claim.epoch) != (
            lease.owner,
            lease.epoch,
        ):
            raise DefenseConflict("Task watch claim owner changed")
        row = connection.execute(
            "SELECT a.*,w.claim_ref AS active_ref,w.host_id,w.defense_scope,"
            "w.task_reference_sha256 FROM defense_task_watch_attempts_v1 a "
            "JOIN defense_task_watches_v1 w ON w.rid=a.rid WHERE a.claim_ref=?",
            (claim.claim_ref,),
        ).fetchone()
        if (
            row is None
            or row["finished_at"] is not None
            or row["active_ref"] != claim.claim_ref
            or (
                row["rid"],
                row["owner"],
                row["epoch"],
                row["claimed_at"],
                row["expires_at"],
                row["attempt"],
                row["host_id"],
                row["defense_scope"],
                row["task_reference_sha256"],
            )
            != (
                claim.request_id,
                claim.owner,
                claim.epoch,
                claim.claimed_at,
                claim.expires_at,
                claim.attempt,
                claim.host_id,
                claim.defense_scope,
                claim.task_reference_sha256,
            )
            or not utc(claim.claimed_at) <= instant < utc(claim.expires_at)
        ):
            raise DefenseConflict("Task watch claim is no longer current")

    def finish(self, lease, claim, state: WatchState, *, interval_seconds: int, now=None):
        instant = _now(now)
        # Validate the public fixed enum before writing; never persist an exception string.
        TaskWatchEvent(
            event_ref="a" * 32,
            sequence=1,
            task_reference_sha256=claim.task_reference_sha256,
            host_id=claim.host_id,
            request_id=claim.request_id,
            state=state,
            observed_at=_stamp(instant),
        )
        if type(interval_seconds) is not int or not 30 <= interval_seconds <= 3600:
            raise DefenseConflict("Task watch interval is invalid")
        with self.base._write() as db:
            self.assert_claim(lease, claim, now=instant, connection=db)
            row = db.execute(
                "SELECT * FROM defense_task_watches_v1 WHERE rid=?", (claim.request_id,)
            ).fetchone()
            self._event(db, row, state, instant)
            failures = row["failures"] + 1 if state in {"unavailable", "unknown"} else 0
            delay = (
                min(900, interval_seconds * (2 ** min(failures, 5)))
                if failures
                else interval_seconds
            )
            db.execute(
                "UPDATE defense_task_watch_attempts_v1 SET finished_at=?,state=? WHERE claim_ref=?",
                (_stamp(instant), state, claim.claim_ref),
            )
            db.execute(
                "UPDATE defense_task_watches_v1 SET due_at=?,terminal=?,last_state=?,failures=?,"
                "claim_ref=NULL,claim_until=NULL,updated_at=? WHERE rid=?",
                (
                    _stamp(instant + timedelta(seconds=delay)),
                    int(state in TERMINAL),
                    state,
                    failures,
                    _stamp(instant),
                    claim.request_id,
                ),
            )

    @staticmethod
    def _event_view(row):
        return TaskWatchEvent(
            event_ref=row["event_ref"],
            sequence=row["sequence"],
            task_reference_sha256=row["task_reference_sha256"],
            host_id=row["host_id"],
            request_id=row["rid"],
            state=row["state"],
            observed_at=row["observed_at"],
            acknowledged_at=row["acknowledged_at"],
        ).model_dump(mode="json")

    def events(self, *, after_sequence=0, limit=20):
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence < 2**63
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise DefenseConflict("Task watch page is invalid")
        with self.base._connection() as db:
            rows = db.execute(
                "SELECT * FROM defense_task_watch_events_v1 WHERE sequence>? "
                "ORDER BY sequence LIMIT ?",
                (after_sequence, limit + 1),
            ).fetchall()
        visible = rows[:limit]
        return {
            "events": [self._event_view(row) for row in visible],
            "next_after_sequence": visible[-1]["sequence"] if len(rows) > limit else None,
        }

    def ack(self, event_ref, *, confirm_ack=True, now=None):
        if confirm_ack is not True:
            raise DefenseConflict("Task watch acknowledgement requires confirmation")
        if type(event_ref) is not str:
            raise DefenseConflict("Task watch event reference is invalid")
        TypeAdapter(Identifier).validate_python(event_ref)
        instant = _now(now)
        with self.base._write() as db:
            row = db.execute(
                "SELECT * FROM defense_task_watch_events_v1 WHERE event_ref=?", (event_ref,)
            ).fetchone()
            if row is None:
                raise DefenseConflict("Task watch event was not found")
            self._event_view(row)
            if row["acknowledged_at"] is None and instant < utc(row["observed_at"]):
                raise DefenseConflict("Task watch acknowledgement time is earlier than its event")
            db.execute(
                "UPDATE defense_task_watch_events_v1 SET "
                "acknowledged_at=COALESCE(acknowledged_at,?) WHERE event_ref=?",
                (_stamp(instant), event_ref),
            )
            return self._event_view(
                db.execute(
                    "SELECT * FROM defense_task_watch_events_v1 WHERE event_ref=?", (event_ref,)
                ).fetchone()
            )

    def counts(self):
        with self.base._connection() as db:
            tasks = db.execute(
                "SELECT count(*),COALESCE(sum(terminal=0),0) FROM defense_task_watches_v1"
            ).fetchone()
            events = db.execute(
                "SELECT count(*),COALESCE(sum(acknowledged_at IS NULL),0) "
                "FROM defense_task_watch_events_v1"
            ).fetchone()
        return {"tasks": tasks[0], "pending": tasks[1], "alerts": events[0], "unread": events[1]}
