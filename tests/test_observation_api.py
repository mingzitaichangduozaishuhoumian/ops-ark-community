from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from opsark import main
from opsark.config import Settings
from opsark.diagnostics import diagnose
from opsark.replay import collect_replay

TOKEN = "observation-test-token-not-a-production-secret"
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture
def client(tmp_path):
    with TestClient(main.create_app(Settings(data_dir=tmp_path, token=TOKEN))) as instance:
        yield instance


def investigate(client, sample, scenario="container_restart"):
    response = client.post(
        "/api/investigations",
        headers=AUTH,
        json={
            "source": "replay",
            "scenario": scenario,
            "sample_id": sample,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def save(client, report_id, **kwargs):
    return client.post(
        f"/api/reports/{report_id}/baseline",
        headers=AUTH,
        json={"confirm_observation_only": True},
        **kwargs,
    )


def test_confirmed_baseline_is_immutable_and_only_applies_to_future_reports(client):
    first = investigate(client, "container-healthy")
    assert first["comparison"]["status"] == "no_baseline"
    denied = client.post(
        f"/api/reports/{first['id']}/baseline",
        headers=AUTH,
        json={"confirm_observation_only": False},
    )
    assert denied.status_code == 422
    saved = save(client, first["id"])
    assert saved.status_code == 200
    assert saved.json()["purpose"] == "observation_only"
    assert saved.json()["restore_capable"] is False
    assert save(client, first["id"]).json()["id"] == saved.json()["id"]
    original = client.get(f"/api/reports/{first['id']}", headers=AUTH).json()
    assert original["comparison"]["status"] == "no_baseline"
    second = investigate(client, "container-oom")
    comparison = second["comparison"]
    assert comparison["baseline_report_id"] == first["id"]
    assert any(change["field"] == "container.restart_count" for change in comparison["changes"])
    evidence = {item["id"] for item in second["evidence"]}
    assert all(set(change["evidence_ids"]) <= evidence for change in comparison["changes"])
    assert second["action"]["executable"] is False
    exported = client.get(f"/api/reports/{second['id']}/export", headers=AUTH).text
    assert "观测基线" in exported and first["id"] in exported
    listed = client.get("/api/baselines", headers=AUTH).json()
    assert len(listed) == 1
    assert "features" not in listed[0]


def test_baseline_routes_keep_auth_origin_and_input_boundaries(client):
    report = investigate(client, "container-healthy")
    endpoint = f"/api/reports/{report['id']}/baseline"
    assert client.get("/api/baselines").status_code == 401
    assert client.post(endpoint, json={"confirm_observation_only": True}).status_code == 401
    assert (
        client.post(
            endpoint,
            headers={**AUTH, "Origin": "https://other.example"},
            json={"confirm_observation_only": True},
        ).status_code
        == 403
    )
    assert (
        client.post(
            endpoint,
            headers=AUTH,
            json={"confirm_observation_only": True, "features": {"fake": "value"}},
        ).status_code
        == 422
    )
    assert save(client, "not-a-report").status_code == 404


def test_changed_target_scope_stops_comparison(client, monkeypatch):
    first = investigate(client, "container-healthy")
    assert save(client, first["id"]).status_code == 200
    original = main.collect_replay

    def changed(sample_id):
        host, collection = original(sample_id)
        return host.model_copy(update={"address": "192.0.2.11"}), collection

    monkeypatch.setattr(main, "collect_replay", changed)
    report = investigate(client, "container-oom")
    assert report["comparison"]["status"] == "scope_changed"
    assert report["comparison"]["changes"] == []


def test_old_or_empty_reports_cannot_be_saved_as_current_baselines(client):
    host, collection = collect_replay("container-healthy")
    old = diagnose("container_restart", host, collection)
    old.scope_hash = ""
    old.target = None
    client.app.state.store.save(old)
    assert save(client, old.id).status_code == 409
    empty = investigate(client, "collection-unavailable", "web_502")
    assert save(client, empty["id"]).status_code == 409


def test_baselines_survive_new_app_instances(tmp_path: Path):
    settings = Settings(data_dir=tmp_path, token=TOKEN)
    with TestClient(main.create_app(settings)) as first_client:
        report = investigate(first_client, "container-healthy")
        snapshot = save(first_client, report["id"]).json()
    with TestClient(main.create_app(settings)) as second_client:
        report = investigate(second_client, "container-oom")
        assert report["comparison"]["baseline_id"] == snapshot["id"]


def test_health_results_never_complete_recovery_or_enable_actions(client):
    report = investigate(client, "container-healthy")
    assert any(check["status"] == "passed" for check in report["verification"])
    assert any(check["status"] in {"not_run", "uncovered"} for check in report["verification"])
    assert report["action"]["executable"] is False
    failed = investigate(client, "web-port-mismatch", "web_502")
    assert any(check["status"] == "failed" for check in failed["verification"])
    broken = investigate(client, "web-permission-denied", "web_502")
    assert any(check["status"] == "error" for check in broken["verification"])


@pytest.mark.parametrize(
    "body,expected",
    [("token=original-response-secret", False), ("actual [REDACTED] content", True)],
)
def test_redaction_replacements_cannot_create_a_successful_body_match(
    client, monkeypatch, body, expected
):
    original = main.collect_replay

    def response_with_sensitive_content(sample_id):
        host, collection = original(sample_id)
        definition = host.health_checks[0].model_copy(update={"expected_body": "[REDACTED]"})
        host = host.model_copy(update={"health_checks": [definition]})
        checks = [
            check.model_copy(update={"stdout": body + "\nOPSARK_HTTP_STATUS:200\n"})
            if check.name == "http_shop"
            else check
            for check in collection.checks
        ]
        return host, collection.model_copy(update={"checks": checks})

    monkeypatch.setattr(main, "collect_replay", response_with_sensitive_content)
    report = investigate(client, "container-healthy")
    check = next(item for item in report["verification"] if item.get("http_status") is not None)
    assert check["body_matches"] is expected
    assert check["status"] == ("passed" if expected else "failed")
    assert "original-response-secret" not in str(report)
    saved = save(client, report["id"])
    assert saved.status_code == 200
    assert saved.json()["features"]["http.shop.body_matches"] == str(expected).lower()
