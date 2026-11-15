"""Persistence, temporal rules and negative security-observation controls."""

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from opsark.security_models import SecurityEvent, SecurityObservation
from opsark.security_store import SecurityStore

NOW = datetime(2026, 10, 28, 4, tzinfo=UTC)
SCOPE = "a" * 64


def event(
    index,
    *,
    when=None,
    kind="authentication_failed",
    source="192.0.2.10",
    origin="system_ssh",
    scope=SCOPE,
    host="lab",
):
    cursor = f"s=fixture;i={index}"
    return SecurityEvent(
        id=hashlib.sha256((scope + "\n" + cursor).encode()).hexdigest(),
        host_id=host,
        scope_hash=scope,
        occurred_at=when or NOW - timedelta(seconds=100 - index),
        origin=origin,
        kind=kind,
        source_ip=source,
        method="publickey",
        account_type="other",
        journal_cursor=cursor,
        unit="ssh.service" if origin == "system_ssh" else "opsark-security-probe.service",
    )


def batch(
    events=(),
    *,
    identifier="batch-1",
    when=NOW,
    status="complete",
    gaps=None,
    host="lab",
    scope=SCOPE,
):
    return SecurityObservation(
        id=identifier,
        host_id=host,
        scope_hash=scope,
        collected_at=when,
        window_started_at=when - timedelta(minutes=15),
        window_ended_at=when,
        status=status,
        events=list(events),
        gaps=gaps or [],
        raw_records_seen=len(events),
    )


def store(tmp_path):
    return SecurityStore(tmp_path / "security.sqlite3")


def test_closes_connection_when_foreign_key_setup_fails(tmp_path, monkeypatch):
    current = store(tmp_path)

    def authorize(operation, name, *_):
        if operation == sqlite3.SQLITE_PRAGMA and name == "foreign_keys":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    with closing(sqlite3.connect(current.path)) as connection, monkeypatch.context() as setup:
        connection.set_authorizer(authorize)
        setup.setattr(sqlite3, "connect", lambda *_args, **_kwargs: connection)
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            current.list_alerts()
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_threshold_uses_unique_ids_not_overlapping_polls_and_survives_restart(tmp_path):
    path = tmp_path / "security.sqlite3"
    first = [event(index) for index in range(4)]
    current = SecurityStore(path)
    assert current.ingest(batch(first))["new_alerts"] == 0
    assert current.ingest(batch(first, identifier="overlap"))["inserted_events"] == 0
    assert current.list_alerts() == []
    restarted = SecurityStore(path)
    result = restarted.ingest(batch([*first, event(4)], identifier="fifth"))
    assert result["inserted_events"] == 1 and result["new_alerts"] == 1
    alert = restarted.list_alerts()[0]
    assert alert["unique_event_count"] == 5
    assert alert["notification_count"] == 1
    assert alert["kind"] == "repeated_auth_failures"
    again = restarted.ingest(
        batch([*first, event(4)], identifier="again", when=NOW + timedelta(seconds=30))
    )
    assert again["new_alerts"] == again["updated_alerts"] == 0
    assert restarted.list_alerts()[0] == alert


def test_same_observation_is_idempotent_but_cannot_be_rewritten(tmp_path):
    current = store(tmp_path)
    original = batch([event(1)])
    current.ingest(original)
    assert current.ingest(original)["inserted_events"] == 0
    with pytest.raises(ValueError, match="replace"):
        current.ingest(original.model_copy(update={"duration_ms": 10}))
    assert current.get_observation(original.id)["duration_ms"] == 0


def test_ip_origin_host_and_scope_are_independent_rule_groups(tmp_path):
    current = store(tmp_path)
    mixed = [event(index, source=f"192.0.2.{index}") for index in range(6)]
    mixed += [event(10 + index, origin="controlled_probe") for index in range(4)]
    mixed += [event(20 + index) for index in range(4)]
    current.ingest(batch(mixed))
    assert current.list_alerts() == []
    current.ingest(
        batch(
            [event(30 + index, scope="b" * 64) for index in range(4)],
            identifier="other-scope",
            scope="b" * 64,
        )
    )
    assert current.list_alerts() == []
    current.ingest(
        batch(
            [event(40 + index, scope="c" * 64, host="other") for index in range(4)],
            identifier="other-host",
            scope="c" * 64,
            host="other",
        )
    )
    assert current.list_alerts() == []


def test_rolling_window_handles_failures_across_clock_bucket_boundary(tmp_path):
    current = store(tmp_path)
    values = [event(index, when=NOW - timedelta(seconds=100 + index * 100)) for index in range(5)]
    current.ingest(batch(values))
    assert current.list_alerts()[0]["current_window_count"] == 5
    assert current.get_alert(current.list_alerts()[0]["id"])["evidence_retained"]


def test_success_requires_at_least_five_preceding_failures(tmp_path):
    current = store(tmp_path)
    values = [event(index, when=NOW - timedelta(seconds=90 - index)) for index in range(5)]
    before = event(20, when=NOW - timedelta(seconds=92), kind="authentication_accepted")
    current.ingest(batch([*values, before]))
    assert [alert["kind"] for alert in current.list_alerts()] == ["repeated_auth_failures"]
    after = event(21, when=NOW - timedelta(seconds=10), kind="authentication_accepted")
    current.ingest(batch([after], identifier="success"))
    high = next(a for a in current.list_alerts() if a["kind"] == "success_after_failures")
    assert high["severity"] == "high"
    assert "不能据此认定入侵" in high["detail"]
    assert high["unique_event_count"] == 6


def test_normal_logins_and_small_shared_exit_failure_bursts_do_not_alert(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index, kind="authentication_accepted") for index in range(10)]))
    current.ingest(batch([event(20 + index) for index in range(4)], identifier="small-burst"))
    assert current.list_alerts() == []


def test_controlled_probe_is_explicitly_labeled_and_never_intrusion_claim(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index, origin="controlled_probe") for index in range(5)]))
    alert = current.list_alerts()[0]
    assert alert["origin"] == "controlled_probe"
    assert alert["title"].startswith("受控实验")
    assert "不是实际攻击认定" in alert["detail"]
    assert "不自动封禁" in alert["detail"]


def test_success_alert_retains_failures_when_many_logins_follow(tmp_path):
    current = store(tmp_path)
    failures = [event(index, when=NOW - timedelta(seconds=100 - index)) for index in range(5)]
    successes = [
        event(20 + index, kind="authentication_accepted", when=NOW - timedelta(seconds=30 - index))
        for index in range(25)
    ]
    current.ingest(batch(failures + successes))
    high = next(a for a in current.list_alerts() if a["kind"] == "success_after_failures")
    evidence = current.get_alert(high["id"])["events"]
    assert len(evidence) == 20
    assert sum(e["kind"] == "authentication_failed" for e in evidence) == 5
    assert sum(e["kind"] == "authentication_accepted" for e in evidence) == 15


def test_failures_after_an_old_success_do_not_renotify_high_pattern(tmp_path):
    current = store(tmp_path)
    failures = [event(index) for index in range(5)]
    success = event(10, kind="authentication_accepted", when=NOW - timedelta(seconds=10))
    current.ingest(batch(failures + [success]))
    high = next(a for a in current.list_alerts() if a["kind"] == "success_after_failures")
    current.acknowledge(high["id"])
    later = NOW + timedelta(seconds=601)
    current.ingest(batch([event(20, when=later)], identifier="later-failure", when=later))
    unchanged = current.get_alert(high["id"])
    assert unchanged["notification_count"] == 1 and unchanged["status"] == "acknowledged"
    assert unchanged["unique_event_count"] == 6


def test_cooldown_requires_new_evidence_and_ack_does_not_resolve_incident(tmp_path):
    current = store(tmp_path)
    failures = [event(index) for index in range(5)]
    current.ingest(batch(failures))
    identifier = current.list_alerts()[0]["id"]
    acknowledged = current.acknowledge(identifier)
    assert acknowledged["status"] == "acknowledged"
    within = NOW + timedelta(seconds=60)
    current.ingest(
        batch([event(10, when=within - timedelta(seconds=1))], identifier="within", when=within)
    )
    assert current.get_alert(identifier)["notification_count"] == 1
    assert current.get_alert(identifier)["status"] == "acknowledged"
    later = NOW + timedelta(seconds=601)
    current.ingest(batch(failures, identifier="old-again", when=later))
    assert current.get_alert(identifier)["notification_count"] == 1
    current.ingest(
        batch([event(11, when=later - timedelta(seconds=1))], identifier="fresh", when=later)
    )
    assert current.get_alert(identifier)["notification_count"] == 2
    assert current.get_alert(identifier)["status"] == "open"
    assert current.get_alert(identifier)["unique_event_count"] == 7
    assert "resolved" not in current.get_alert(identifier)


def test_fresh_events_below_current_window_threshold_do_not_refresh_old_alert(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index) for index in range(5)]))
    identifier = current.list_alerts()[0]["id"]
    later = NOW + timedelta(minutes=20)
    current.ingest(batch([event(10, when=later)], identifier="later", when=later))
    assert current.get_alert(identifier)["unique_event_count"] == 5
    assert current.get_alert(identifier)["notification_count"] == 1


def test_empty_success_does_not_erase_prior_security_alert(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index) for index in range(5)]))
    original = current.list_alerts()[0]
    current.ingest(batch(identifier="empty", when=NOW + timedelta(minutes=1)))
    assert current.list_alerts()[0] == original


def test_same_cursor_with_changed_payload_drops_whole_batch_and_keeps_evidence(tmp_path):
    current = store(tmp_path)
    original = event(1)
    current.ingest(batch([original]))
    conflicting = original.model_copy(update={"source_ip": "192.0.2.99"})
    changed = batch([conflicting, *[event(index) for index in range(2, 8)]], identifier="conflict")
    result = current.ingest(changed)
    assert result["inserted_events"] == 0
    assert result["observation_status"] == "degraded"
    assert current.list_alerts()[0]["kind"] == "observation_gap"
    assert current.get_observation(changed.id)["events"] == []
    assert current.ingest(changed)["inserted_events"] == 0
    with closing(sqlite3.connect(current.path)) as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"host_id": "other"},
        {"scope_hash": "b" * 64},
        {"source_ip": "192.0.2.1\nattack"},
        {"unit": "opsark-security-probe.service"},
        {"id": "0" * 64},
        {"journal_cursor": "cursor with spaces"},
        {"occurred_at": NOW + timedelta(minutes=1)},
    ],
)
def test_malformed_or_scope_mismatched_event_never_counts(tmp_path, changes):
    current = store(tmp_path)
    invalid = event(1).model_copy(update=changes)
    result = current.ingest(batch([invalid]))
    assert result["inserted_events"] == 0
    assert result["observation_status"] == "degraded"
    assert current.list_alerts()[0]["kind"] == "observation_gap"


def test_duplicate_exact_events_inside_one_batch_count_once(tmp_path):
    current = store(tmp_path)
    events = [event(index) for index in range(4)]
    result = current.ingest(batch(events * 2))
    assert result["inserted_events"] == 4
    assert current.list_alerts() == []


def test_identical_collection_failure_quiet_until_recovery_and_fresh_failure(tmp_path):
    current = store(tmp_path)
    first = batch(status="unavailable", gaps=["SSH 采集失败。"])
    current.ingest(first)
    original = current.list_alerts()[0]
    current.acknowledge(original["id"])
    repeated = current.ingest(
        batch(
            identifier="still-down",
            when=NOW + timedelta(minutes=20),
            status="unavailable",
            gaps=["SSH 采集失败。"],
        )
    )
    assert repeated["updated_alerts"] == 0
    assert current.get_alert(original["id"])["notification_count"] == 1
    recovered_at = NOW + timedelta(minutes=21)
    current.ingest(batch(identifier="recovered", when=recovered_at))
    current.ingest(
        batch(
            identifier="down-again",
            when=recovered_at + timedelta(minutes=1),
            status="unavailable",
            gaps=["SSH 采集失败。"],
        )
    )
    alert = current.get_alert(original["id"])
    assert alert["notification_count"] == 2 and alert["status"] == "open"


def test_partial_or_gap_is_not_healthy_and_secret_text_is_redacted(tmp_path):
    current = store(tmp_path)
    result = current.ingest(batch(gaps=["Authorization: Bearer private-marker"]))
    assert result["observation_status"] == "degraded"
    serialized = str(current.get_observation("batch-1")) + str(current.list_alerts())
    assert "private-marker" not in serialized
    assert "[REDACTED]" in serialized


def test_offline_gap_is_persisted_once_and_next_clean_window_can_recover(tmp_path):
    current = store(tmp_path)
    current.ingest(batch())
    recovery = batch(identifier="gap", when=NOW + timedelta(minutes=20))
    result = current.ingest(recovery)
    assert result["observation_status"] == "degraded"
    assert "未观察时段" in result["gaps"][0]
    assert current.ingest(recovery)["observation_status"] == "degraded"
    next_result = current.ingest(batch(identifier="clean", when=NOW + timedelta(minutes=21)))
    assert next_result["observation_status"] == "complete"


def test_clock_window_regression_drops_events(tmp_path):
    current = store(tmp_path)
    current.ingest(batch())
    earlier = batch(
        [event(index, when=NOW - timedelta(minutes=10)) for index in range(5)],
        identifier="clock-back",
        when=NOW - timedelta(minutes=5),
    )
    result = current.ingest(earlier)
    assert result["inserted_events"] == 0
    assert result["observation_status"] == "degraded"
    assert any("回退" in gap for gap in result["gaps"])


def test_evidence_is_limited_to_twenty_and_survives_old_event_pruning(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index) for index in range(40)]))
    identifier = current.list_alerts()[0]["id"]
    assert len(current.get_alert(identifier)["events"]) == 20
    current.ingest(batch(identifier="day-later", when=NOW + timedelta(days=2)))
    detail = current.get_alert(identifier)
    assert len(detail["events"]) == 20 and detail["evidence_retained"]
    assert current.get_observation("batch-1") is not None


def test_recent_observations_bounded_without_deleting_alert_snapshot(tmp_path):
    current = store(tmp_path)
    current.ingest(batch([event(index) for index in range(5)]))
    for index in range(110):
        current.ingest(batch(identifier=f"empty-{index}", when=NOW + timedelta(seconds=index + 1)))
    assert current.get_observation("batch-1") is not None
    assert current.get_observation("empty-0") is None
    with closing(sqlite3.connect(current.path)) as connection:
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 101


def test_ack_unknown_alert_and_sql_payload_identifiers_are_safe(tmp_path):
    current = store(tmp_path)
    assert current.acknowledge("missing") is None
    assert current.get_alert("' OR 1=1 --") is None
    assert current.get_observation("' OR 1=1 --") is None
    current.ingest(batch([event(index) for index in range(5)]))
    assert len(current.list_alerts()) == 1


def test_host_state_scope_isolated_and_no_unknown_fields_or_naive_dates(tmp_path):
    current = store(tmp_path)
    current.set_host_state("lab", SCOPE, status="starting", last_attempt=NOW)
    current.set_host_state("lab", SCOPE, status="ok", last_success=NOW.isoformat())
    current.set_host_state("lab", "b" * 64, status="stopped", detail="token=private-marker")
    states = current.host_states()
    assert len(states) == 2 and states[0]["last_attempt"] == NOW.isoformat()
    assert states[0]["status"] == "ok"
    assert "private-marker" not in str(states)
    with pytest.raises(ValueError):
        current.set_host_state("lab", SCOPE, private_key="secret")
    with pytest.raises(ValueError):
        current.set_host_state("lab", SCOPE, status="healthy_forever")
    with pytest.raises(ValueError):
        current.set_host_state("lab", SCOPE, last_success=datetime(2026, 1, 1))


def test_monitor_lease_persists_and_renewal_release_respects_owner(tmp_path):
    path = tmp_path / "security.sqlite3"
    current = SecurityStore(path)
    assert current.claim_monitor("owner-a", NOW)
    restarted = SecurityStore(path)
    assert not restarted.claim_monitor("owner-b", NOW + timedelta(seconds=1))
    assert restarted.claim_monitor("owner-a", NOW + timedelta(seconds=30))
    restarted.release_monitor("owner-b")
    assert not restarted.claim_monitor("owner-b", NOW + timedelta(seconds=100))
    assert restarted.claim_monitor("owner-b", NOW + timedelta(seconds=121))
    current.release_monitor("owner-a")
    assert not current.claim_monitor("owner-c", NOW + timedelta(seconds=122))
    restarted.release_monitor("owner-b")
    assert current.claim_monitor("owner-c", NOW + timedelta(seconds=123))


def test_concurrent_monitor_claim_has_one_winner(tmp_path):
    current = store(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(
            pool.map(lambda index: current.claim_monitor(f"owner-{index}", NOW), range(4))
        )
    assert sum(outcomes) == 1


@pytest.mark.parametrize("ttl", [True, 0, 9, 301, "90"])
def test_invalid_lease_ttl_refused(tmp_path, ttl):
    with pytest.raises(ValueError):
        store(tmp_path).claim_monitor("owner", NOW, ttl)


def test_event_and_observation_dates_require_timezone(tmp_path):
    current = store(tmp_path)
    with pytest.raises(ValueError):
        current.ingest(batch().model_copy(update={"collected_at": NOW.replace(tzinfo=None)}))
    with pytest.raises(ValueError):
        current.ingest(
            batch([event(1).model_copy(update={"occurred_at": NOW.replace(tzinfo=None)})])
        )


def test_observation_symlink_refused(tmp_path):
    target = tmp_path / "target.sqlite3"
    target.touch()
    link = tmp_path / "linked.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symbolic links requires local privileges")
    with pytest.raises(ValueError):
        SecurityStore(link)
