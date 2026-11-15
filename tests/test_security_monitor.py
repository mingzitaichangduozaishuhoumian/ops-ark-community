import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from opsark import main
from opsark.baselines import scope_for
from opsark.config import HostConfig, Settings, load_settings
from opsark.models import HostPublic
from opsark.security_events import event_id
from opsark.security_models import SecurityEvent, SecurityObservation
from opsark.security_monitor import SecurityMonitor
from opsark.security_store import SecurityStore

TOKEN = "test-security-console-token-value-2026"
NOW = datetime(2026, 10, 28, 5, 0, tzinfo=UTC)


def host():
    return HostConfig(
        public=HostPublic(id="lab", name="Lab", address="192.0.2.10", source="ssh"),
        key_file=Path("unused"),
        known_hosts_file=Path("unused"),
    )


def settings(path, *, enabled=True):
    return Settings(
        data_dir=path,
        token=TOKEN,
        observation_enabled=enabled,
        observation_host_ids=("lab",),
    )


def batch(target, now=NOW, *, status="complete", events=False):
    scope = scope_for(target.public)
    values = []
    if events:
        for index in range(5):
            cursor = f"s=test;i={index}"
            values.append(
                SecurityEvent(
                    id=event_id(scope, cursor),
                    host_id=target.public.id,
                    scope_hash=scope,
                    occurred_at=NOW - timedelta(seconds=10 - index),
                    origin="controlled_probe",
                    kind="authentication_failed",
                    source_ip="127.0.0.1",
                    method="publickey",
                    account_type="other",
                    journal_cursor=cursor,
                    unit="opsark-security-probe.service",
                )
            )
    return SecurityObservation(
        id=str(uuid4()),
        host_id=target.public.id,
        scope_hash=scope,
        collected_at=now,
        window_started_at=now - timedelta(minutes=15),
        window_ended_at=now,
        status=status,
        events=values,
        gaps=[] if status == "complete" else ["journal_unavailable"],
        raw_records_seen=len(values),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"observation_enabled": True},
        {"observation_enabled": "true"},
        {"observation_host_ids": ("lab", "lab")},
        {"observation_host_ids": ("../host",)},
        {"observation_interval_seconds": 0},
        {"observation_interval_seconds": True},
    ],
)
def test_observation_settings_require_explicit_bounded_scope(tmp_path, overrides):
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, token=TOKEN, **overrides)


def test_environment_observation_flags_are_not_implicitly_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    for name in (
        "OPSARK_AI_BASE_URL",
        "OPSARK_AI_KEY",
        "OPSARK_AI_MODEL",
        "OPSARK_OBSERVE_ENABLED",
        "OPSARK_OBSERVE_HOSTS",
        "OPSARK_OBSERVE_INTERVAL",
    ):
        monkeypatch.delenv(name, raising=False)
    assert load_settings().observation_enabled is False
    monkeypatch.setenv("OPSARK_OBSERVE_ENABLED", "yes")
    with pytest.raises(ValueError):
        load_settings()
    monkeypatch.setenv("OPSARK_OBSERVE_ENABLED", "true")
    monkeypatch.setenv("OPSARK_OBSERVE_HOSTS", "lab")
    loaded = load_settings()
    assert loaded.observation_host_ids == ("lab",)
    assert loaded.observation_interval_seconds == 60
    monkeypatch.setenv("OPSARK_OBSERVE_INTERVAL", "arbitrary")
    with pytest.raises(ValueError):
        load_settings()


def test_unknown_observer_target_stops_before_any_collection(tmp_path):
    with pytest.raises(ValueError, match="已经登记"):
        SecurityMonitor(
            settings(tmp_path), {}, SecurityStore(tmp_path / "security.db"), threading.Lock()
        )


def test_disabled_observer_never_calls_network_or_claims_lease(tmp_path):
    calls = []
    target = host()
    monitor = SecurityMonitor(
        settings(tmp_path, enabled=False),
        {"lab": target},
        SecurityStore(tmp_path / "security.db"),
        threading.Lock(),
        collector=lambda host: calls.append(host),
    )
    monitor.start()
    monitor.poll_once()
    assert calls == []
    assert monitor.status()["enabled"] is False
    assert monitor.status()["running"] is False
    monitor.stop()


def test_polling_deduplicates_events_and_persists_over_restart(tmp_path):
    target = host()
    clock = [NOW]
    store = SecurityStore(tmp_path / "security.db")

    def collect(host):
        return batch(host, clock[0], events=True)

    monitor = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        store,
        threading.Lock(),
        collector=collect,
        now=lambda: clock[0],
    )
    monitor.poll_once()
    assert len(store.list_alerts()) == 1
    first = store.list_alerts()[0]
    assert first["unique_event_count"] == 5 and first["notification_count"] == 1
    clock[0] += timedelta(seconds=61)
    monitor.poll_once()
    assert store.list_alerts()[0]["unique_event_count"] == 5
    monitor.stop()
    reopened = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(store.path),
        threading.Lock(),
        collector=collect,
        now=lambda: clock[0],
    )
    reopened.poll_once()
    assert reopened.store.list_alerts()[0]["notification_count"] == 1
    reopened.stop()


def test_shared_investigation_lock_prevents_background_contention(tmp_path):
    calls = []
    lock = threading.Lock()
    target = host()
    monitor = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(tmp_path / "security.db"),
        lock,
        collector=lambda host: calls.append(host),
        now=lambda: NOW,
    )
    lock.acquire()
    try:
        monitor.poll_once()
    finally:
        lock.release()
    assert not calls
    assert monitor.status()["hosts"][0]["status"] == "busy"
    monitor.stop()


def test_two_monitor_instances_cannot_poll_same_database_simultaneously(tmp_path):
    target = host()
    calls = []
    store = SecurityStore(tmp_path / "security.db")

    def collect(host):
        calls.append(host.public.id)
        return batch(host)

    first = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        store,
        threading.Lock(),
        collector=collect,
        now=lambda: NOW,
    )
    second = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(store.path),
        threading.Lock(),
        collector=collect,
        now=lambda: NOW,
    )
    first.poll_once()
    second.poll_once()
    assert calls == ["lab"]
    first.stop()
    second.poll_once()
    assert calls == ["lab", "lab"]
    second.stop()


def test_collection_errors_create_safe_alert_and_recovery_changes_status(tmp_path):
    target = host()
    clock = [NOW]
    calls = [0]

    def collect(host):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("private-credential=/run/secrets/not-for-response")
        return batch(host, clock[0])

    monitor = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(tmp_path / "security.db"),
        threading.Lock(),
        collector=collect,
        now=lambda: clock[0],
    )
    monitor.poll_once()
    status = monitor.status()
    assert status["hosts"][0]["status"] == "unavailable"
    assert monitor.store.list_alerts()[0]["kind"] == "collection_failed"
    assert "private-credential" not in str(monitor.store.list_alerts())
    clock[0] += timedelta(seconds=61)
    monitor.poll_once()
    assert monitor.status()["hosts"][0]["status"] == "ok"
    clock[0] += timedelta(minutes=4)
    assert monitor.status()["hosts"][0]["status"] == "stale"
    monitor.stop()


def test_mismatched_collector_host_never_records_other_host_events(tmp_path):
    target = host()
    wrong = batch(target).model_copy(update={"host_id": "other"})
    monitor = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(tmp_path / "security.db"),
        threading.Lock(),
        collector=lambda host: wrong,
        now=lambda: NOW,
    )
    monitor.poll_once()
    assert monitor.status()["hosts"][0]["status"] == "unavailable"
    assert all(alert["host_id"] == "lab" for alert in monitor.store.list_alerts())
    monitor.stop()


def test_api_auth_evidence_and_acknowledgement_do_not_execute_or_resolve(tmp_path):
    application = main.create_app(Settings(data_dir=tmp_path, token=TOKEN))
    with TestClient(application) as client:
        auth = {"Authorization": "Bearer " + TOKEN}
        assert client.get("/api/security/status").status_code == 401
        assert client.get("/api/security/alerts").status_code == 401
        assert client.get("/api/security/status", headers=auth).json()["enabled"] is False
        observation = batch(host(), events=True)
        application.state.security_store.ingest(observation)
        alerts = client.get("/api/security/alerts", headers=auth).json()
        assert len(alerts) == 1
        alert_id = alerts[0]["id"]
        detail = client.get(f"/api/security/alerts/{alert_id}", headers=auth).json()
        assert len(detail["events"]) == 5
        assert detail["observation"]["id"] == observation.id
        assert "MESSAGE" not in str(detail) and "private_key" not in str(detail)
        endpoint = f"/api/security/alerts/{alert_id}/ack"
        assert client.post(endpoint, headers=auth, json={"acknowledge": False}).status_code == 422
        assert (
            client.post(
                endpoint,
                headers={**auth, "Origin": "https://attacker.example"},
                json={"acknowledge": True},
            ).status_code
            == 403
        )
        ack = client.post(endpoint, headers=auth, json={"acknowledge": True})
        assert ack.status_code == 200 and ack.json()["status"] == "acknowledged"
        assert (
            client.get(f"/api/security/observations/{observation.id}", headers=auth).status_code
            == 200
        )
        assert client.get("/api/security/alerts/not-found", headers=auth).status_code == 404
        assert client.get("/api/security/observations/not-found", headers=auth).status_code == 404
        assert application.state.store.list() == []


def test_background_lifecycle_stops_and_releases_monitor_lease(tmp_path):
    target = host()
    called = threading.Event()

    def collect(target):
        called.set()
        return batch(target, datetime.now(UTC))

    store = SecurityStore(tmp_path / "security.db")
    monitor = SecurityMonitor(
        settings(tmp_path), {"lab": target}, store, threading.Lock(), collector=collect
    )
    monitor.start()
    worker = monitor.thread
    monitor.start()
    assert monitor.thread is worker
    assert called.wait(timeout=3)
    monitor.stop()
    assert worker is not None and not worker.is_alive()
    assert store.host_states()[0]["last_observation_id"]
    assert store.claim_monitor("replacement", datetime.now(UTC))
    store.release_monitor("replacement")


def test_repeated_process_initialization_does_not_overwrite_active_host_state(tmp_path):
    target = host()
    store = SecurityStore(tmp_path / "security.db")
    first = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        store,
        threading.Lock(),
        collector=lambda h: batch(h),
        now=lambda: NOW,
    )
    first.poll_once()
    second = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        store,
        threading.Lock(),
        collector=lambda h: batch(h),
        now=lambda: NOW,
    )
    assert store.host_states()[0]["status"] == "ok"
    second.stop()
    first.stop()


def test_store_rejected_payload_is_recorded_as_unavailable_without_hot_retry(tmp_path):
    target = host()
    calls = []

    def collect(target):
        calls.append(target.public.id)
        return batch(target).model_copy(update={"id": "invalid observation id"})

    monitor = SecurityMonitor(
        settings(tmp_path),
        {"lab": target},
        SecurityStore(tmp_path / "security.db"),
        threading.Lock(),
        collector=collect,
        now=lambda: NOW,
    )
    monitor.poll_once()
    monitor.poll_once()
    assert calls == ["lab"]
    assert monitor.status()["hosts"][0]["status"] == "unavailable"
    assert monitor.store.list_alerts()[0]["kind"] == "collection_failed"
    monitor.stop()


def test_long_multi_host_round_renews_lease_before_it_can_expire(tmp_path):
    base = host()
    targets = {
        name: HostConfig(
            public=base.public.model_copy(update={"id": name}),
            key_file=base.key_file,
            known_hosts_file=base.known_hosts_file,
        )
        for name in ("one", "two", "three")
    }
    configured = Settings(
        data_dir=tmp_path,
        token=TOKEN,
        observation_enabled=True,
        observation_host_ids=tuple(targets),
    )
    store = SecurityStore(tmp_path / "security.db")
    clock = [NOW]

    def collect(target):
        clock[0] += timedelta(seconds=40)
        assert not store.claim_monitor("competing-process", clock[0])
        return batch(target, clock[0])

    monitor = SecurityMonitor(
        configured, targets, store, threading.Lock(), collector=collect, now=lambda: clock[0]
    )
    monitor.poll_once()
    assert len(store.host_states()) == 3
    assert all(state["status"] == "ok" for state in store.host_states())
    monitor.stop()
