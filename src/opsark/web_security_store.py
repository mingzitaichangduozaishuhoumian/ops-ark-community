"""Web rules over reduced events, reusing the event-agnostic SQLite evidence store.

The inherited schema, readers, acknowledgement, retention and host state methods
operate on JSON evidence. Web validation and ingestion are separate; no SSH
normalizer or rule is changed, and this class uses its own database file.
"""

import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import timedelta

from opsark.redaction import redact
from opsark.security_models import SecurityObservation
from opsark.security_store import (
    _CURSOR,
    _IDENTIFIER,
    COOLDOWN_SECONDS,
    SecurityStore,
    _dump,
    _iso,
    _target,
    _utc,
)
from opsark.web_security_models import WebSecurityObservation

SENSITIVE_CLASSES = {"secret_probe", "repo_probe", "cms_probe", "admin_probe", "traversal_probe"}


def _document(event):
    value = event.model_dump(mode="json")
    value["occurred_at"] = _iso(event.occurred_at)
    return value


def _metadata(observation):
    """Adapt only shared observation metadata to inherited generic issue/prune code."""
    return SecurityObservation(
        **{
            key: getattr(observation, key)
            for key in (
                "id",
                "host_id",
                "scope_hash",
                "collected_at",
                "window_started_at",
                "window_ended_at",
                "status",
                "gaps",
                "raw_records_seen",
                "duration_ms",
            )
        }
    )


def _normalize(observation):
    if not isinstance(observation, WebSecurityObservation):
        raise ValueError("A Web observation is required")
    result = WebSecurityObservation.model_validate(observation.model_dump(), strict=True)
    _target(result.host_id, result.scope_hash)
    if not _IDENTIFIER.fullmatch(result.id):
        raise ValueError("Invalid Web observation identifier")
    collected, started, ended = map(
        _utc, (result.collected_at, result.window_started_at, result.window_ended_at)
    )
    if (
        not started <= ended
        or ended - started > timedelta(seconds=960)
        or abs((ended - collected).total_seconds()) > 120
    ):
        raise ValueError("Invalid Web observation time window")
    gaps = list(dict.fromkeys(redact(gap)[:512] for gap in result.gaps))[:20]
    status = "degraded" if result.status == "complete" and gaps else result.status
    events = {}
    conflict = result.raw_records_seen < len(result.events) or (
        result.status == "unavailable" and bool(result.events)
    )
    for event in result.events:
        valid = (
            event.host_id == result.host_id
            and event.scope_hash == result.scope_hash
            and event.id
            == hashlib.sha256(
                (result.scope_hash + "\n" + event.journal_cursor).encode()
            ).hexdigest()
            and bool(_CURSOR.fullmatch(event.journal_cursor))
            and started <= _utc(event.occurred_at) <= ended
            and not (event.expected_error and event.status < 400)
        )
        try:
            valid = valid and str(ipaddress.ip_address(event.peer_ip)) == event.peer_ip
            if event.source_trust == "unresolved_proxy":
                valid = valid and event.source_ip is None
            else:
                valid = (
                    valid
                    and event.source_ip is not None
                    and str(ipaddress.ip_address(event.source_ip)) == event.source_ip
                )
                if event.source_trust in {"direct_peer", "forwarded_ignored"}:
                    valid = valid and event.source_ip == event.peer_ip
        except ValueError:
            valid = False
        old = events.get(event.id)
        if not valid or (old is not None and _document(old) != _document(event)):
            conflict = True
            break
        events[event.id] = event.model_copy(update={"occurred_at": _utc(event.occurred_at)})
    if conflict:
        events.clear()
        status = "unavailable" if result.status == "unavailable" else "degraded"
        gaps.append("Web 事件的范围、时间、来源或稳定标识不一致；本批未用于计数。")
    if status != "complete" and not gaps:
        gaps.append("Web 观察未完成，缺少完整覆盖依据。")
    return result.model_copy(
        update={
            "collected_at": collected,
            "window_started_at": started,
            "window_ended_at": ended,
            "status": status,
            "gaps": gaps[-20:],
            "events": sorted(
                events.values(), key=lambda event: (_utc(event.occurred_at), event.id)
            ),
        }
    )


class WebSecurityStore(SecurityStore):
    """Independent Web database with durable evidence and no action execution."""

    def __init__(self, path):
        super().__init__(path)
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS web_profiles (host_id TEXT,scope_hash TEXT,"
                "profile_digest TEXT NOT NULL,PRIMARY KEY(host_id,scope_hash))"
            )

    @staticmethod
    def _new_alert(
        observation,
        kind,
        origin,
        source_ip,
        title,
        detail,
        severity,
        *,
        site_id=None,
        source_trust="unresolved_proxy",
    ):
        if origin == "collector":
            origin = "web_collector"
            title = "Web 观察采集失败" if kind == "collection_failed" else "Web 观察存在覆盖缺口"
        fingerprint = _dump(
            ["web", observation.host_id, observation.scope_hash, kind, origin, site_id, source_ip]
        )
        instant = _iso(observation.collected_at)
        return {
            "id": hashlib.sha256(fingerprint.encode()).hexdigest(),
            "channel": "web",
            "host_id": observation.host_id,
            "scope_hash": observation.scope_hash,
            "kind": kind,
            "severity": severity,
            "origin": origin,
            "site_id": site_id,
            "source_ip": source_ip,
            "source_trust": source_trust,
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
        }, fingerprint

    def _raise_event_alert(
        self,
        connection,
        observation,
        kind,
        origin,
        site_id,
        source_ip,
        source_trust,
        events,
        matching,
    ):
        descriptions = {
            "web_scan": (
                "疑似 Web 路径探测，需核对用途",
                "十五分钟观察样本中至少五条请求涉及三个敏感路径类别；可能是扫描或授权检查，不能据此确认入侵或数据泄露。",
            ),
            "web_error_burst": (
                "Web 响应错误集中出现",
                "当前完整读取快照的五分钟已观察样本中，至少十条非健康检查请求里，"
                "至少五条为非预期 5xx 且占比不低于一半；该样本比例不是全量流量错误率。"
                "这是服务响应异常，不证明请求来源在攻击。",
            ),
            "web_request_anomaly": (
                "Web 慢请求集中出现",
                "当前完整读取快照的五分钟已观察样本中，至少十条非健康检查请求里，"
                "至少五条响应耗时达到两秒且占比不低于一半；该样本比例不是全量流量慢请求率。"
                "需核对应用和依赖，不能仅按请求量或 IP 判定攻击。",
            ),
        }
        title, detail = descriptions[kind]
        if source_trust == "unresolved_proxy":
            detail += "来源未验证，不能封禁网关或把它当作攻击者。"
        if source_trust == "site_aggregate":
            detail += "本告警按站点聚合，不归因于单个来源。"
        if origin == "controlled_web_probe":
            title = "受控实验：" + title
            detail = "本告警来自明确登记的 Web 实验站点，不是实际攻击认定。" + detail
        if observation.status != "complete":
            detail += "本次存在覆盖缺口，事件数仅是已取得证据的下界。"
        candidate, fingerprint = self._new_alert(
            observation,
            kind,
            origin,
            source_ip,
            title,
            detail,
            "warning",
            site_id=site_id,
            source_trust=source_trust,
        )
        row = connection.execute(
            "SELECT payload FROM alerts WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        alert = json.loads(row["payload"]) if row else candidate
        if row is None:
            self._save_alert(connection, alert, fingerprint)
        fresh = []
        for event in events:
            inserted = connection.execute(
                "INSERT OR IGNORE INTO alert_seen(alert_id,event_id,occurred_at) VALUES(?,?,?)",
                (alert["id"], event["id"], _utc(event["occurred_at"]).timestamp()),
            )
            if inserted.rowcount:
                fresh.append(event["id"])
        if not fresh:
            return 0, 0
        alert.update(
            last_seen=_iso(observation.collected_at),
            observation_id=observation.id,
            current_window_count=len(events),
            unique_event_count=alert["unique_event_count"] + len(fresh),
            matching_event_count=len(matching),
            observed_request_count=len(events),
            window_seconds=900 if kind == "web_scan" else 300,
            coverage_status=observation.status,
            metric_basis="observed_evidence" if kind == "web_scan" else "complete_snapshot_sample",
        )
        evidence = events[-20:]
        if kind == "web_scan":
            categories = {}
            for event in events:
                categories[event["path_class"]] = event
            selected = {event["id"]: event for event in categories.values()}
            for event in reversed(events):
                if len(selected) >= 20:
                    break
                selected[event["id"]] = event
            evidence = sorted(
                selected.values(), key=lambda item: (_utc(item["occurred_at"]), item["id"])
            )
        else:
            # Retain abnormal and normal support, rather than just the newest failures.
            bad = {event["id"] for event in matching}
            evidence = [event for event in events if event["id"] in bad][-10:] + [
                event for event in events if event["id"] not in bad
            ][-10:]
            evidence = sorted(evidence, key=lambda item: (_utc(item["occurred_at"]), item["id"]))
        alert["event_ids"] = [event["id"] for event in evidence]
        notify_ids = {event["id"] for event in matching}
        if (
            row
            and notify_ids.intersection(fresh)
            and (_utc(observation.collected_at) - _utc(alert["last_notified_at"])).total_seconds()
            >= COOLDOWN_SECONDS
        ):
            alert.update(
                notification_count=alert["notification_count"] + 1,
                last_notified_at=_iso(observation.collected_at),
                status="open",
            )
        self._save_alert(connection, alert, fingerprint)
        return (0, 1) if row else (1, 0)

    def _rules(self, connection, observation):
        rows = connection.execute(
            "SELECT payload FROM events WHERE host_id=? AND scope_hash=? "
            "AND occurred_at>=? AND occurred_at<=? ORDER BY occurred_at,id",
            (
                observation.host_id,
                observation.scope_hash,
                observation.window_ended_at.timestamp() - 900,
                observation.window_ended_at.timestamp(),
            ),
        ).fetchall()
        sources, sites = defaultdict(list), defaultdict(list)
        for row in rows:
            event = json.loads(row["payload"])
            sources[(event["origin"], event["site_id"], event["source_ip"])].append(event)
        # An absolute probing lower bound remains meaningful during partial reads.
        # Ratios do not: truncating normal traffic could fabricate a high error
        # fraction. Use only this complete snapshot, never old partial batches.
        ratio_window_complete = (
            observation.status == "complete"
            and observation.window_ended_at - observation.window_started_at
            >= timedelta(seconds=300)
        )
        if ratio_window_complete:
            for value in observation.events:
                event = _document(value)
                if event["path_class"] != "health" and _utc(
                    event["occurred_at"]
                ) >= observation.window_ended_at - timedelta(seconds=300):
                    sites[(event["origin"], event["site_id"])].append(event)
        created = updated = 0
        for (origin, site_id, source_ip), events in sources.items():
            sensitive = [event for event in events if event["path_class"] in SENSITIVE_CLASSES]
            if len(sensitive) < 5 or len({event["path_class"] for event in sensitive}) < 3:
                continue
            trust = (
                "unresolved_proxy"
                if source_ip is None
                else "forwarded_ignored"
                if any(event["source_trust"] == "forwarded_ignored" for event in sensitive)
                else sensitive[-1]["source_trust"]
            )
            a, b = self._raise_event_alert(
                connection,
                observation,
                "web_scan",
                origin,
                site_id,
                source_ip,
                trust,
                sensitive,
                sensitive,
            )
            created += a
            updated += b
        for (origin, site_id), events in sites.items():
            if len(events) < 10:
                continue
            for kind, matching in (
                (
                    "web_error_burst",
                    [
                        event
                        for event in events
                        if event["status"] >= 500 and not event["expected_error"]
                    ],
                ),
                (
                    "web_request_anomaly",
                    [event for event in events if event["request_time_ms"] >= 2000],
                ),
            ):
                if len(matching) >= 5 and len(matching) * 2 >= len(events):
                    a, b = self._raise_event_alert(
                        connection,
                        observation,
                        kind,
                        origin,
                        site_id,
                        None,
                        "site_aggregate",
                        events,
                        matching,
                    )
                    created += a
                    updated += b
        return created, updated

    def ingest(self, observation: SecurityObservation | WebSecurityObservation) -> dict:
        observation = _normalize(observation)
        counts = {"inserted_events": 0, "new_alerts": 0, "updated_alerts": 0}
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            input_hash = hashlib.sha256(observation.model_dump_json().encode()).hexdigest()
            old = connection.execute(
                "SELECT payload,input_hash FROM observations WHERE id=?", (observation.id,)
            ).fetchone()
            if old:
                if old["input_hash"] != input_hash:
                    raise ValueError("An observation identifier cannot replace prior Web evidence")
                saved = json.loads(old["payload"])
                return {**counts, "observation_status": saved["status"], "gaps": saved["gaps"]}
            conflict = False
            profile = connection.execute(
                "SELECT profile_digest FROM web_profiles WHERE host_id=? AND scope_hash=?",
                (observation.host_id, observation.scope_hash),
            ).fetchone()
            if profile and profile["profile_digest"] != observation.profile_digest:
                conflict = True
            for event in observation.events:
                stored = connection.execute(
                    "SELECT payload FROM events WHERE id=? "
                    "OR (host_id=? AND scope_hash=? AND cursor=?)",
                    (event.id, event.host_id, event.scope_hash, event.journal_cursor),
                ).fetchall()
                if any(row["payload"] != _dump(_document(event)) for row in stored):
                    conflict = True
                    break
            covered = connection.execute(
                "SELECT covered_until FROM coverage_marks WHERE host_id=? AND scope_hash=?",
                (observation.host_id, observation.scope_hash),
            ).fetchone()
            complete = observation.status == "complete" and not conflict
            gap = None
            if covered:
                if observation.window_ended_at.timestamp() < covered["covered_until"] - 120:
                    conflict = True
                    complete = False
                    gap = "Web 观察窗口明显回退；本批未用于计数，需要核对时钟。"
                elif (
                    complete
                    and observation.window_started_at.timestamp() > covered["covered_until"]
                ):
                    gap = "两次 Web 可覆盖窗口之间存在未观察时段；不能保证离线期间完整。"
            if conflict:
                observation = observation.model_copy(
                    update={
                        "events": [],
                        "status": "degraded",
                        "gaps": (
                            observation.gaps
                            + [gap or "Web 稳定日志标识或配置摘要与已有证据冲突；本批未用于计数。"]
                        )[-20:],
                    }
                )
            elif gap:
                observation = observation.model_copy(
                    update={"status": "degraded", "gaps": (observation.gaps + [gap])[-20:]}
                )
            connection.execute(
                "INSERT OR IGNORE INTO web_profiles(host_id,scope_hash,profile_digest) "
                "VALUES(?,?,?)",
                (observation.host_id, observation.scope_hash, observation.profile_digest),
            )
            if complete:
                connection.execute(
                    "INSERT INTO coverage_marks(host_id,scope_hash,covered_until) VALUES(?,?,?) "
                    "ON CONFLICT(host_id,scope_hash) "
                    "DO UPDATE SET covered_until=MAX(covered_until,excluded.covered_until)",
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
                    observation.collected_at.timestamp(),
                    observation.model_dump_json(),
                    input_hash,
                ),
            )
            for event in observation.events:
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO events"
                    "(id,host_id,scope_hash,cursor,occurred_at,payload) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        event.id,
                        event.host_id,
                        event.scope_hash,
                        event.journal_cursor,
                        event.occurred_at.timestamp(),
                        _dump(_document(event)),
                    ),
                )
                counts["inserted_events"] += inserted.rowcount
            if observation.status == "unavailable":
                new, changed = self._issue_alert(
                    connection, _metadata(observation), "collection_failed"
                )
            elif observation.status == "degraded":
                connection.execute(
                    "UPDATE issues SET active=0 WHERE host_id=? AND scope_hash=? "
                    "AND kind='collection_failed'",
                    (observation.host_id, observation.scope_hash),
                )
                new, changed = self._issue_alert(
                    connection, _metadata(observation), "observation_gap"
                )
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
            self._prune(connection, _metadata(observation))
        return {**counts, "observation_status": observation.status, "gaps": observation.gaps}
