"""Transactional security evidence, deterministic alerts and a monitor lease.

No raw journal text is stored. Alert evidence is bounded and remains separate
from acknowledgement, which never certifies incident resolution or host safety.
"""

import hashlib
import ipaddress
import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from opsark.redaction import redact
from opsark.security_models import SecurityEvent, SecurityObservation

WINDOW_SECONDS = 900
COOLDOWN_SECONDS = 600
EVENT_RETENTION_SECONDS = 86_400
MAX_EVENTS_PER_SCOPE = 10_000
MAX_OBSERVATIONS_PER_SCOPE = 100
MAX_ALERTS = 1000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SCOPE = re.compile(r"[0-9a-f]{64}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9;=_:.+-]{1,256}\Z")
_STATE_FIELDS = {
    "status",
    "last_attempt",
    "last_success",
    "next_poll",
    "detail",
    "last_observation_id",
}
_STATUSES = {"starting", "ok", "degraded", "unavailable", "busy", "stopped", "stale"}


def _utc(value: datetime | str) -> datetime:
    result = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(result, datetime) or result.tzinfo is None:
        raise ValueError("Security timestamps require an explicit timezone")
    return result.astimezone(UTC)


def _iso(value: datetime | str) -> str:
    return _utc(value).isoformat()


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _target(host_id: str, scope_hash: str) -> None:
    if not _IDENTIFIER.fullmatch(host_id) or not _SCOPE.fullmatch(scope_hash):
        raise ValueError("Invalid security target scope")


def _event_document(event: SecurityEvent) -> dict:
    document = event.model_dump(mode="json")
    document["occurred_at"] = _iso(event.occurred_at)
    return document


def _normalize(observation: SecurityObservation) -> SecurityObservation:
    result = SecurityObservation.model_validate(observation.model_dump(), strict=True)
    _target(result.host_id, result.scope_hash)
    if not _IDENTIFIER.fullmatch(result.id):
        raise ValueError("Invalid observation identifier")
    collected = _utc(result.collected_at)
    started, ended = _utc(result.window_started_at), _utc(result.window_ended_at)
    if not started <= ended or ended - started > timedelta(seconds=WINDOW_SECONDS + 60):
        raise ValueError("Invalid observation window")
    if ended > collected + timedelta(seconds=120):
        raise ValueError("Observation clock is beyond the permitted skew")
    gaps = list(dict.fromkeys(redact(gap)[:512] for gap in result.gaps))[:20]
    status = "degraded" if result.status == "complete" and gaps else result.status
    normalized: dict[str, SecurityEvent] = {}
    conflict = False
    for event in result.events:
        expected_id = hashlib.sha256(
            (result.scope_hash + "\n" + event.journal_cursor).encode()
        ).hexdigest()
        valid = (
            event.host_id == result.host_id
            and event.scope_hash == result.scope_hash
            and event.id == expected_id
            and bool(_CURSOR.fullmatch(event.journal_cursor))
            and started <= _utc(event.occurred_at) <= ended
            and (event.unit == "ssh.service") == (event.origin == "system_ssh")
            and not (event.kind == "authentication_accepted" and event.account_type == "invalid")
        )
        try:
            valid = valid and str(ipaddress.ip_address(event.source_ip)) == event.source_ip
        except ValueError:
            valid = False
        if not valid:
            conflict = True
            break
        previous = normalized.get(event.id)
        if previous is not None and _event_document(previous) != _event_document(event):
            conflict = True
            break
        normalized[event.id] = event.model_copy(update={"occurred_at": _utc(event.occurred_at)})
    if conflict or (result.status == "unavailable" and result.events):
        normalized.clear()
        status = "degraded" if result.status != "unavailable" else "unavailable"
        gaps.append("事件目标、时间、来源或稳定标识不一致；本批事件未用于计数。")
    return result.model_copy(
        update={
            "collected_at": collected,
            "window_started_at": started,
            "window_ended_at": ended,
            "status": status,
            "gaps": gaps[:20],
            "events": sorted(normalized.values(), key=lambda item: (item.occurred_at, item.id)),
        }
    )


class SecurityStore:
    """Persist safe projections and emit alerts only from distinct event evidence."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if self.path.is_symlink():
            raise ValueError("Security database cannot be a symbolic link")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL, scope_hash TEXT NOT NULL,
                    collected_at REAL NOT NULL, payload TEXT NOT NULL, input_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS observations_scope_time
                    ON observations(host_id,scope_hash,collected_at DESC);
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, host_id TEXT NOT NULL, scope_hash TEXT NOT NULL,
                    cursor TEXT NOT NULL, occurred_at REAL NOT NULL, payload TEXT NOT NULL,
                    UNIQUE(host_id,scope_hash,cursor)
                );
                CREATE INDEX IF NOT EXISTS events_scope_time
                    ON events(host_id,scope_hash,occurred_at DESC);
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
                    updated_at REAL NOT NULL, observation_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_seen (
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL, occurred_at REAL NOT NULL,
                    PRIMARY KEY(alert_id,event_id)
                );
                CREATE TABLE IF NOT EXISTS alert_refs (
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL, PRIMARY KEY(alert_id,event_id)
                );
                CREATE TABLE IF NOT EXISTS issues (
                    host_id TEXT NOT NULL, scope_hash TEXT NOT NULL, kind TEXT NOT NULL,
                    detail_hash TEXT NOT NULL, active INTEGER NOT NULL,
                    PRIMARY KEY(host_id,scope_hash,kind)
                );
                CREATE TABLE IF NOT EXISTS host_states (
                    host_id TEXT NOT NULL, scope_hash TEXT NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(host_id,scope_hash)
                );
                CREATE TABLE IF NOT EXISTS monitor_lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    owner TEXT NOT NULL, expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS coverage_marks (
                    host_id TEXT NOT NULL, scope_hash TEXT NOT NULL, covered_until REAL NOT NULL,
                    PRIMARY KEY(host_id,scope_hash)
                );
            """)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(observations)")}
            if "input_hash" not in columns:
                connection.execute(
                    "ALTER TABLE observations ADD COLUMN input_hash TEXT NOT NULL DEFAULT ''"
                )
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _save_alert(connection: sqlite3.Connection, alert: dict, fingerprint: str) -> None:
        connection.execute(
            """INSERT INTO alerts(id,fingerprint,updated_at,observation_id,payload)
               VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
               updated_at=excluded.updated_at,observation_id=excluded.observation_id,
               payload=excluded.payload""",
            (
                alert["id"],
                fingerprint,
                _utc(alert["last_seen"]).timestamp(),
                alert["observation_id"],
                _dump(alert),
            ),
        )
        connection.execute("DELETE FROM alert_refs WHERE alert_id=?", (alert["id"],))
        connection.executemany(
            "INSERT INTO alert_refs(alert_id,event_id) VALUES(?,?)",
            [(alert["id"], event_id) for event_id in alert["event_ids"]],
        )

    @staticmethod
    def _new_alert(
        observation: SecurityObservation,
        kind: str,
        origin: str,
        source_ip: str | None,
        title: str,
        detail: str,
        severity: str,
    ) -> tuple[dict, str]:
        fingerprint = _dump([observation.host_id, observation.scope_hash, kind, origin, source_ip])
        identifier = hashlib.sha256(fingerprint.encode()).hexdigest()
        instant = _iso(observation.collected_at)
        return (
            {
                "id": identifier,
                "host_id": observation.host_id,
                "scope_hash": observation.scope_hash,
                "kind": kind,
                "severity": severity,
                "origin": origin,
                "source_ip": source_ip,
                "title": title,
                "detail": detail,
                "first_seen": instant,
                "last_seen": instant,
                "unique_event_count": 0,
                "current_window_count": 0,
                "event_ids": [],
                "observation_id": observation.id,
                "status": "open",
                "notification_count": 1,
                "last_notified_at": instant,
            },
            fingerprint,
        )

    def _event_alert(
        self,
        connection: sqlite3.Connection,
        observation: SecurityObservation,
        kind: str,
        origin: str,
        source_ip: str,
        events: list[dict],
        current_count: int,
    ) -> tuple[int, int]:
        is_success = kind == "success_after_failures"
        title = "失败后出现成功，需核对授权" if is_success else "重复认证失败，需核对合法任务"
        detail = (
            "同一来源在十五分钟窗口内重复失败后出现认证成功；共享出口和合法任务也可能产生该模式，不能据此认定入侵。"
            if is_success
            else (
                "同一来源在十五分钟窗口内至少出现五条独立认证失败；"
                "可能是自动化尝试或错误配置的合法任务，不自动封禁。"
            )
        )
        if origin == "controlled_probe":
            title = "受控实验：" + title
            detail = "本告警来自明确登记的实验 SSH 服务，不是实际攻击认定。" + detail
        candidate, fingerprint = self._new_alert(
            observation, kind, origin, source_ip, title, detail, "high" if is_success else "warning"
        )
        row = connection.execute(
            "SELECT payload FROM alerts WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        existing = json.loads(row["payload"]) if row else None
        alert = existing or candidate
        fresh = []
        for event in events:
            inserted = (
                connection.execute(
                    "INSERT OR IGNORE INTO alert_seen(alert_id,event_id,occurred_at) VALUES(?,?,?)",
                    (alert["id"], event["id"], _utc(event["occurred_at"]).timestamp()),
                )
                if existing
                else None
            )
            if existing is None or (inserted is not None and inserted.rowcount):
                fresh.append(event)
        if not fresh:
            return 0, 0
        alert["last_seen"] = _iso(observation.collected_at)
        alert["observation_id"] = observation.id
        alert["current_window_count"] = current_count
        alert["unique_event_count"] += len(fresh)
        evidence = events[-20:]
        if is_success:
            # Retain enough failures as well as accepted logins to reproduce the rule.
            failure_refs = [e for e in events if e["kind"] == "authentication_failed"][-5:]
            success_refs = [e for e in events if e["kind"] == "authentication_accepted"][-15:]
            evidence = sorted(
                failure_refs + success_refs,
                key=lambda item: (_utc(item["occurred_at"]), item["id"]),
            )
        alert["event_ids"] = [event["id"] for event in evidence]
        notification_evidence = not is_success or any(
            event["kind"] == "authentication_accepted" for event in fresh
        )
        if notification_evidence and (
            existing is not None
            and (_utc(observation.collected_at) - _utc(alert["last_notified_at"])).total_seconds()
            >= COOLDOWN_SECONDS
        ):
            alert["notification_count"] += 1
            alert["last_notified_at"] = _iso(observation.collected_at)
            alert["status"] = "open"
        self._save_alert(connection, alert, fingerprint)
        if existing is None:
            connection.executemany(
                "INSERT INTO alert_seen(alert_id,event_id,occurred_at) VALUES(?,?,?)",
                [
                    (alert["id"], event["id"], _utc(event["occurred_at"]).timestamp())
                    for event in fresh
                ],
            )
        return (1, 0) if existing is None else (0, 1)

    def _issue_alert(
        self,
        connection: sqlite3.Connection,
        observation: SecurityObservation,
        kind: str,
    ) -> tuple[int, int]:
        detail = "；".join(observation.gaps) or (
            "未取得完整安全观察结果，不能将采集不可用解释为没有异常。"
        )
        detail_hash = hashlib.sha256(detail.encode()).hexdigest()
        previous = connection.execute(
            "SELECT active,detail_hash FROM issues WHERE host_id=? AND scope_hash=? AND kind=?",
            (observation.host_id, observation.scope_hash, kind),
        ).fetchone()
        changed = (
            previous is None or not previous["active"] or previous["detail_hash"] != detail_hash
        )
        connection.execute(
            """INSERT INTO issues VALUES(?,?,?,?,1)
               ON CONFLICT(host_id,scope_hash,kind) DO UPDATE SET
               active=1,detail_hash=excluded.detail_hash""",
            (observation.host_id, observation.scope_hash, kind, detail_hash),
        )
        if not changed:
            return 0, 0
        title = "安全观察采集失败" if kind == "collection_failed" else "安全观察存在覆盖缺口"
        candidate, fingerprint = self._new_alert(
            observation, kind, "collector", None, title, detail, "warning"
        )
        row = connection.execute(
            "SELECT payload FROM alerts WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if row is None:
            self._save_alert(connection, candidate, fingerprint)
            return 1, 0
        alert = json.loads(row["payload"])
        alert.update(
            {
                "detail": detail,
                "last_seen": _iso(observation.collected_at),
                "observation_id": observation.id,
            }
        )
        if (
            _utc(observation.collected_at) - _utc(alert["last_notified_at"])
        ).total_seconds() >= COOLDOWN_SECONDS:
            alert["notification_count"] += 1
            alert["last_notified_at"] = _iso(observation.collected_at)
            alert["status"] = "open"
        self._save_alert(connection, alert, fingerprint)
        return 0, 1

    def _rules(
        self,
        connection: sqlite3.Connection,
        observation: SecurityObservation,
    ) -> tuple[int, int]:
        rows = connection.execute(
            """SELECT payload FROM events WHERE host_id=? AND scope_hash=?
               AND occurred_at>=? AND occurred_at<=? ORDER BY occurred_at,id""",
            (
                observation.host_id,
                observation.scope_hash,
                (_utc(observation.window_ended_at) - timedelta(seconds=WINDOW_SECONDS)).timestamp(),
                _utc(observation.window_ended_at).timestamp(),
            ),
        ).fetchall()
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for row in rows:
            event = json.loads(row["payload"])
            groups[(event["origin"], event["source_ip"])].append(event)
        created, updated = 0, 0
        for (origin, source_ip), events in groups.items():
            failures = [event for event in events if event["kind"] == "authentication_failed"]
            if len(failures) < 5:
                continue
            new, changed = self._event_alert(
                connection,
                observation,
                "repeated_auth_failures",
                origin,
                source_ip,
                failures,
                len(failures),
            )
            created, updated = created + new, updated + changed
            # Later failures cannot explain an earlier successful login.
            fifth = _utc(failures[4]["occurred_at"])
            successes = [
                event
                for event in events
                if event["kind"] == "authentication_accepted" and _utc(event["occurred_at"]) > fifth
            ]
            if successes:
                latest_success = max(_utc(event["occurred_at"]) for event in successes)
                supporting = [
                    event for event in failures if _utc(event["occurred_at"]) < latest_success
                ] + successes
                supporting.sort(key=lambda item: (_utc(item["occurred_at"]), item["id"]))
                new, changed = self._event_alert(
                    connection,
                    observation,
                    "success_after_failures",
                    origin,
                    source_ip,
                    supporting,
                    len(supporting),
                )
                created, updated = created + new, updated + changed
        return created, updated

    @staticmethod
    def _prune(connection: sqlite3.Connection, observation: SecurityObservation) -> None:
        connection.execute(
            "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts "
            "ORDER BY updated_at DESC,id DESC LIMIT -1 OFFSET ?)",
            (MAX_ALERTS,),
        )
        connection.execute(
            """DELETE FROM observations WHERE host_id=? AND scope_hash=?
               AND id NOT IN (SELECT observation_id FROM alerts)
               AND id IN (SELECT id FROM observations WHERE host_id=? AND scope_hash=?
               ORDER BY collected_at DESC,id DESC LIMIT -1 OFFSET ?)""",
            (
                observation.host_id,
                observation.scope_hash,
                observation.host_id,
                observation.scope_hash,
                MAX_OBSERVATIONS_PER_SCOPE,
            ),
        )
        cutoff = (
            _utc(observation.collected_at) - timedelta(seconds=EVENT_RETENTION_SECONDS)
        ).timestamp()
        connection.execute(
            "DELETE FROM events WHERE occurred_at<? "
            "AND id NOT IN (SELECT event_id FROM alert_refs)",
            (cutoff,),
        )
        connection.execute(
            """DELETE FROM events WHERE host_id=? AND scope_hash=?
               AND id NOT IN (SELECT event_id FROM alert_refs)
               AND id IN (SELECT id FROM events WHERE host_id=? AND scope_hash=?
               ORDER BY occurred_at DESC,id DESC LIMIT -1 OFFSET ?)""",
            (
                observation.host_id,
                observation.scope_hash,
                observation.host_id,
                observation.scope_hash,
                MAX_EVENTS_PER_SCOPE,
            ),
        )
        connection.execute("DELETE FROM alert_seen WHERE event_id NOT IN (SELECT id FROM events)")

    def ingest(self, observation: SecurityObservation) -> dict:
        observation = _normalize(observation)
        counts = {"inserted_events": 0, "new_alerts": 0, "updated_alerts": 0}
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            original_json = observation.model_dump_json()
            input_hash = hashlib.sha256(original_json.encode()).hexdigest()
            previous = connection.execute(
                "SELECT payload,input_hash FROM observations WHERE id=?", (observation.id,)
            ).fetchone()
            if previous:
                if previous["input_hash"] != input_hash and previous["payload"] != original_json:
                    raise ValueError("An observation identifier cannot replace prior evidence")
                saved = json.loads(previous["payload"])
                return {**counts, "observation_status": saved["status"], "gaps": saved["gaps"]}
            conflict = False
            for event in observation.events:
                stored = connection.execute(
                    "SELECT payload FROM events WHERE id=? "
                    "OR (host_id=? AND scope_hash=? AND cursor=?)",
                    (event.id, event.host_id, event.scope_hash, event.journal_cursor),
                ).fetchall()
                if any(row["payload"] != _dump(_event_document(event)) for row in stored):
                    conflict = True
                    break
            covered = connection.execute(
                "SELECT covered_until FROM coverage_marks WHERE host_id=? AND scope_hash=?",
                (observation.host_id, observation.scope_hash),
            ).fetchone()
            input_complete = observation.status == "complete" and not conflict
            coverage_gap = None
            if covered:
                if observation.window_ended_at.timestamp() < covered["covered_until"] - 120:
                    conflict = True
                    input_complete = False
                    coverage_gap = "安全观察窗口明显回退；本批事件未用于计数，需要核对时钟。"
                elif (
                    input_complete
                    and observation.window_started_at.timestamp() > covered["covered_until"]
                ):
                    coverage_gap = "两次可覆盖窗口之间存在未观察时段；离线期间不能保证事件完整。"
            if conflict:
                observation = observation.model_copy(
                    update={
                        "events": [],
                        "status": "degraded",
                        "gaps": (
                            observation.gaps
                            + [coverage_gap or "稳定日志标识与已有事件冲突；本批事件未用于计数。"]
                        )[-20:],
                    }
                )
            elif coverage_gap:
                observation = observation.model_copy(
                    update={
                        "status": "degraded",
                        "gaps": (observation.gaps + [coverage_gap])[-20:],
                    }
                )
            if input_complete:
                connection.execute(
                    "INSERT INTO coverage_marks VALUES(?,?,?) "
                    "ON CONFLICT(host_id,scope_hash) DO UPDATE SET "
                    "covered_until=MAX(covered_until,excluded.covered_until)",
                    (
                        observation.host_id,
                        observation.scope_hash,
                        observation.window_ended_at.timestamp(),
                    ),
                )
            connection.execute(
                "INSERT INTO observations(id,host_id,scope_hash,collected_at,payload,input_hash) "
                "VALUES(?,?,?,?,?,?)",
                (
                    observation.id,
                    observation.host_id,
                    observation.scope_hash,
                    _utc(observation.collected_at).timestamp(),
                    observation.model_dump_json(),
                    input_hash,
                ),
            )
            for event in observation.events:
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?)",
                    (
                        event.id,
                        event.host_id,
                        event.scope_hash,
                        event.journal_cursor,
                        _utc(event.occurred_at).timestamp(),
                        _dump(_event_document(event)),
                    ),
                )
                counts["inserted_events"] += inserted.rowcount
            if observation.status == "unavailable":
                new, changed = self._issue_alert(connection, observation, "collection_failed")
            elif observation.status == "degraded":
                connection.execute(
                    "UPDATE issues SET active=0 WHERE host_id=? AND scope_hash=? "
                    "AND kind='collection_failed'",
                    (observation.host_id, observation.scope_hash),
                )
                new, changed = self._issue_alert(connection, observation, "observation_gap")
            else:
                connection.execute(
                    "UPDATE issues SET active=0 WHERE host_id=? AND scope_hash=?",
                    (observation.host_id, observation.scope_hash),
                )
                new, changed = 0, 0
            counts["new_alerts"], counts["updated_alerts"] = new, changed
            if observation.status != "unavailable":
                new, changed = self._rules(connection, observation)
                counts["new_alerts"] += new
                counts["updated_alerts"] += changed
            self._prune(connection, observation)
        return {**counts, "observation_status": observation.status, "gaps": observation.gaps}

    def list_alerts(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM alerts ORDER BY updated_at DESC,id DESC LIMIT 100"
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def get_alert(self, identifier: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM alerts WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                return None
            alert = json.loads(row["payload"])
            events = []
            for event_id in alert["event_ids"]:
                event = connection.execute(
                    "SELECT payload FROM events WHERE id=?", (event_id,)
                ).fetchone()
                if event:
                    events.append(json.loads(event["payload"]))
            alert["events"] = events
            alert["evidence_retained"] = len(events) == len(alert["event_ids"])
            return alert

    def acknowledge(self, identifier: str) -> dict | None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM alerts WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                return None
            alert = json.loads(row["payload"])
            alert["status"] = "acknowledged"
            connection.execute("UPDATE alerts SET payload=? WHERE id=?", (_dump(alert), identifier))
        return self.get_alert(identifier)

    def get_observation(self, identifier: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM observations WHERE id=?", (identifier,)
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def set_host_state(self, host_id: str, scope_hash: str, **fields: object) -> None:
        _target(host_id, scope_hash)
        if not fields or not fields.keys() <= _STATE_FIELDS:
            raise ValueError("Unknown security host-state fields")
        updates = {}
        for key, value in fields.items():
            if key in {"last_attempt", "last_success", "next_poll"}:
                if value is not None and not isinstance(value, (str, datetime)):
                    raise ValueError("Invalid security host-state timestamp")
                updates[key] = _iso(value) if value is not None else None
            elif key == "status":
                if not isinstance(value, str) or value not in _STATUSES:
                    raise ValueError("Unknown security host status")
                updates[key] = value
            elif value is None:
                updates[key] = None
            elif isinstance(value, str):
                if key == "last_observation_id" and not _IDENTIFIER.fullmatch(value):
                    raise ValueError("Invalid security observation reference")
                updates[key] = redact(value)[:512]
            else:
                raise ValueError("Invalid security host-state value")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM host_states WHERE host_id=? AND scope_hash=?",
                (host_id, scope_hash),
            ).fetchone()
            state: dict = (
                json.loads(row["payload"])
                if row
                else {"host_id": host_id, "scope_hash": scope_hash}
            )
            state.update(updates)
            connection.execute(
                "INSERT INTO host_states VALUES(?,?,?) ON CONFLICT(host_id,scope_hash) "
                "DO UPDATE SET payload=excluded.payload",
                (host_id, scope_hash, _dump(state)),
            )

    def host_states(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM host_states ORDER BY host_id,scope_hash"
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def claim_monitor(self, owner: str, now: datetime, ttl_seconds: int = 90) -> bool:
        if (
            not _IDENTIFIER.fullmatch(owner)
            or type(ttl_seconds) is not int
            or not 10 <= ttl_seconds <= 300
        ):
            raise ValueError("Invalid monitor lease request")
        instant = _utc(now).timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT owner,expires_at FROM monitor_lease WHERE singleton=1"
            ).fetchone()
            if row and row["owner"] != owner and row["expires_at"] > instant:
                return False
            connection.execute(
                "INSERT INTO monitor_lease VALUES(1,?,?) ON CONFLICT(singleton) "
                "DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at",
                (owner, instant + ttl_seconds),
            )
        return True

    def release_monitor(self, owner: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM monitor_lease WHERE singleton=1 AND owner=?", (owner,))
