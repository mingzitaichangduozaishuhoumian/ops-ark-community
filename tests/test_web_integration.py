import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from opsark import main
from opsark.baselines import scope_for
from opsark.config import HostConfig, Settings
from opsark.models import HostPublic
from opsark.security_models import SecurityObservation
from opsark.security_monitor import SecurityMonitor
from opsark.security_store import SecurityStore
from opsark.web_security_events import event_id, scope_for_web
from opsark.web_security_models import WebSecurityEvent, WebSecurityObservation
from opsark.web_security_store import WebSecurityStore

NOW = datetime(2026, 10, 28, 6, 0, tzinfo=UTC)
TOKEN = "test-web-integration-console-token-2026"


def host():
    return HostConfig(
        public=HostPublic(
            id="lab", name="lab", address="192.0.2.10", source="ssh", web_profile_digest="a" * 64
        ),
        key_file=Path("unused"),
        known_hosts_file=Path("unused"),
    )


def observation(target, now=NOW, *, count=6):
    scope = scope_for_web(target.public)
    classes = [
        "secret_probe",
        "repo_probe",
        "cms_probe",
        "admin_probe",
        "secret_probe",
        "repo_probe",
    ]
    events = []
    for index in range(count):
        cursor = f"s=web;i={index}"
        events.append(
            WebSecurityEvent(
                id=event_id(scope, cursor),
                host_id=target.public.id,
                scope_hash=scope,
                occurred_at=NOW - timedelta(seconds=30 - index),
                origin="controlled_web_probe",
                site_id="lab",
                source_ip="127.0.0.1",
                peer_ip="127.0.0.1",
                source_trust="direct_peer",
                method="GET",
                status=404,
                path_class=classes[index % len(classes)],
                client_class="probe",
                request_time_ms=1,
                bytes_sent=10,
                journal_cursor=cursor,
                request_id=f"{index:032x}",
            )
        )
    return WebSecurityObservation(
        id=str(uuid4()),
        host_id=target.public.id,
        scope_hash=scope,
        profile_digest=target.public.web_profile_digest,
        collected_at=now,
        window_started_at=now - timedelta(minutes=15),
        window_ended_at=now,
        status="complete",
        events=events,
        raw_records_seen=count,
    )


def test_web_profile_does_not_change_existing_ssh_scope():
    target = host().public
    assert scope_for(target) == scope_for(target.model_copy(update={"web_profile_digest": None}))
    changed = target.model_copy(update={"web_profile_digest": "b" * 64})
    assert scope_for(target) == scope_for(changed)
    assert scope_for_web(target) != scope_for_web(changed)


def test_web_enablement_requires_global_scope_and_pinned_profile(tmp_path):
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, token=TOKEN, web_observation_enabled=True)
    settings = Settings(
        data_dir=tmp_path,
        token=TOKEN,
        observation_enabled=True,
        observation_host_ids=("lab",),
        web_observation_enabled=True,
    )
    target = host()
    missing = HostConfig(
        public=target.public.model_copy(update={"web_profile_digest": None}),
        key_file=target.key_file,
        known_hosts_file=target.known_hosts_file,
    )
    with pytest.raises(ValueError, match="profile"):
        SecurityMonitor(
            settings,
            {"lab": missing},
            SecurityStore(tmp_path / "ssh.db"),
            threading.Lock(),
            web_store=WebSecurityStore(tmp_path / "web.db"),
        )


def test_two_channels_keep_independent_evidence_and_lease(tmp_path):
    target = host()
    settings = Settings(
        data_dir=tmp_path,
        token=TOKEN,
        observation_enabled=True,
        observation_host_ids=("lab",),
        web_observation_enabled=True,
    )

    def ssh(h):
        return SecurityObservation(
            id=str(uuid4()),
            host_id=h.public.id,
            scope_hash=scope_for(h.public),
            collected_at=NOW,
            window_started_at=NOW - timedelta(minutes=15),
            window_ended_at=NOW,
            status="complete",
        )

    web = WebSecurityStore(tmp_path / "web.db")
    monitor = SecurityMonitor(
        settings,
        {"lab": target},
        SecurityStore(tmp_path / "ssh.db"),
        threading.Lock(),
        collector=ssh,
        web_store=web,
        web_collector=observation,
        now=lambda: NOW,
    )
    monitor.poll_once()
    state = monitor.status()["hosts"][0]
    assert state["channels"]["ssh"]["status"] == "ok"
    assert state["channels"]["web"]["status"] == "ok"
    assert state["channels"]["ssh"]["scope_hash"] != state["channels"]["web"]["scope_hash"]
    assert len(web.list_alerts()) == 1
    assert monitor.store.list_alerts() == []
    monitor.stop()


def test_web_failure_never_hides_successful_ssh_read(tmp_path):
    target = host()
    settings = Settings(
        data_dir=tmp_path,
        token=TOKEN,
        observation_enabled=True,
        observation_host_ids=("lab",),
        web_observation_enabled=True,
    )

    def ssh(h):
        return SecurityObservation(
            id=str(uuid4()),
            host_id=h.public.id,
            scope_hash=scope_for(h.public),
            collected_at=NOW,
            window_started_at=NOW - timedelta(minutes=15),
            window_ended_at=NOW,
            status="complete",
        )

    def failed(_):
        raise RuntimeError("private-provider-marker")

    monitor = SecurityMonitor(
        settings,
        {"lab": target},
        SecurityStore(tmp_path / "ssh.db"),
        threading.Lock(),
        collector=ssh,
        web_store=WebSecurityStore(tmp_path / "web.db"),
        web_collector=failed,
        now=lambda: NOW,
    )
    monitor.poll_once()
    state = monitor.status()["hosts"][0]
    assert state["status"] == "unavailable"
    assert state["channels"]["ssh"]["status"] == "ok"
    assert state["channels"]["web"]["status"] == "unavailable"
    assert "private-provider-marker" not in str(state)
    monitor.stop()


def completed(detail, _settings):
    return {
        "status": "completed",
        "summary": "测试建议，需要人工复核。",
        "uncertainty": ["观察覆盖有限。"],
        "evidence_ids": [e["id"] for e in detail["events"]],
        "recommendations": [],
        "actions_executable": False,
        "model": "mock",
    }


def test_combined_api_web_ack_and_ai_binding_preserve_original_alerts(tmp_path, monkeypatch):
    app = main.create_app(Settings(data_dir=tmp_path, token=TOKEN))
    obs = observation(host())
    app.state.web_security_store.ingest(obs)
    with TestClient(app) as client:
        auth = {"Authorization": "Bearer " + TOKEN}
        alerts = client.get("/api/security/alerts", headers=auth).json()
        assert len(alerts) == 1 and alerts[0]["channel"] == "web"
        alert_id = alerts[0]["id"]
        assert client.get(f"/api/security/alerts/{alert_id}/analysis-input").status_code == 401
        preview = client.get(f"/api/security/alerts/{alert_id}/analysis-input", headers=auth).json()
        assert "127.0.0.1" not in str(preview) and "192.0.2.10" not in str(preview)
        endpoint = f"/api/security/alerts/{alert_id}/analyze"
        monkeypatch.setattr(main, "analyze_alert", completed)
        assert (
            client.post(
                endpoint,
                headers=auth,
                json={"confirm_send": True, "expected_input_digest": "0" * 64},
            ).status_code
            == 409
        )
        result = client.post(
            endpoint,
            headers=auth,
            json={"confirm_send": True, "expected_input_digest": preview["input_digest"]},
        )
        assert result.status_code == 200 and result.json()["actions_executable"] is False
        detail = client.get(f"/api/security/alerts/{alert_id}", headers=auth).json()
        assert detail["analysis"]["status"] == "completed" and detail["analysis_stale"] is False
        assert detail["observation"]["profile_digest"] == "a" * 64
        ack = client.post(
            f"/api/security/alerts/{alert_id}/ack", headers=auth, json={"acknowledge": True}
        )
        assert ack.json()["status"] == "acknowledged"
        assert (
            client.get(f"/api/security/observations/{obs.id}", headers=auth).json()["channel"]
            == "web"
        )
        app.state.web_security_store.ingest(
            observation(host(), NOW + timedelta(seconds=60), count=7)
        )
        newer = client.get(f"/api/security/alerts/{alert_id}", headers=auth).json()
        assert newer["analysis"] is None and newer["analysis_stale"] is True


def test_ai_response_for_changed_evidence_is_not_attached(tmp_path, monkeypatch):
    app = main.create_app(Settings(data_dir=tmp_path, token=TOKEN))
    app.state.web_security_store.ingest(observation(host()))
    with TestClient(app) as client:
        auth = {"Authorization": "Bearer " + TOKEN}
        alert_id = client.get("/api/security/alerts", headers=auth).json()[0]["id"]
        preview = client.get(f"/api/security/alerts/{alert_id}/analysis-input", headers=auth).json()

        def races(detail, settings):
            app.state.web_security_store.ingest(
                observation(host(), NOW + timedelta(seconds=60), count=7)
            )
            return completed(detail, settings)

        monkeypatch.setattr(main, "analyze_alert", races)
        response = client.post(
            f"/api/security/alerts/{alert_id}/analyze",
            headers=auth,
            json={"confirm_send": True, "expected_input_digest": preview["input_digest"]},
        )
        assert response.status_code == 409
        assert app.state.security_ai_store.get(alert_id) is None


def test_analysis_consent_rejects_non_boolean_and_cross_origin(tmp_path):
    app = main.create_app(Settings(data_dir=tmp_path, token=TOKEN))
    app.state.web_security_store.ingest(observation(host()))
    with TestClient(app) as client:
        auth = {"Authorization": "Bearer " + TOKEN}
        alert_id = client.get("/api/security/alerts", headers=auth).json()[0]["id"]
        preview = client.get(f"/api/security/alerts/{alert_id}/analysis-input", headers=auth).json()
        endpoint = f"/api/security/alerts/{alert_id}/analyze"
        body = {"confirm_send": True, "expected_input_digest": preview["input_digest"]}
        for value in (False, 1, "true"):
            assert (
                client.post(
                    endpoint, headers=auth, json={**body, "confirm_send": value}
                ).status_code
                == 422
            )
        assert (
            client.post(
                endpoint, headers={**auth, "Origin": "https://attacker.example"}, json=body
            ).status_code
            == 403
        )
        disabled = client.post(endpoint, headers=auth, json=body)
        assert disabled.status_code == 200 and disabled.json()["status"] == "disabled"
        assert app.state.security_ai_store.get(alert_id) is None


def test_provider_change_invalidates_old_preview_and_saved_advice(tmp_path, monkeypatch):
    old = main.create_app(
        Settings(
            data_dir=tmp_path,
            token=TOKEN,
            ai_base_url="https://old.example/v1",
            ai_key="test-provider-reference",
            ai_model="mock",
        )
    )
    old.state.web_security_store.ingest(observation(host()))
    monkeypatch.setattr(main, "analyze_alert", completed)
    auth = {"Authorization": "Bearer " + TOKEN}
    with TestClient(old) as client:
        alert_id = client.get("/api/security/alerts", headers=auth).json()[0]["id"]
        endpoint = f"/api/security/alerts/{alert_id}"
        preview = client.get(endpoint + "/analysis-input", headers=auth).json()
        assert (
            client.post(
                endpoint + "/analyze",
                headers=auth,
                json={"confirm_send": True, "expected_input_digest": preview["input_digest"]},
            ).status_code
            == 200
        )
    changed = main.create_app(
        Settings(
            data_dir=tmp_path,
            token=TOKEN,
            ai_base_url="https://new.example/v1",
            ai_key="test-provider-reference",
            ai_model="mock",
        )
    )
    with TestClient(changed) as client:
        detail = client.get(endpoint, headers=auth).json()
        assert detail["analysis"] is None and detail["analysis_stale"] is True
        assert (
            client.post(
                endpoint + "/analyze",
                headers=auth,
                json={"confirm_send": True, "expected_input_digest": preview["input_digest"]},
            ).status_code
            == 409
        )
        live_preview = client.get(endpoint + "/analysis-input", headers=auth).json()
        assert live_preview["provider_host"] == "new.example"
        assert live_preview["input_digest"] != preview["input_digest"]
