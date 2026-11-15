"""New routes remain authenticated, cache reads and unavailable without target policy."""

from fastapi.testclient import TestClient

from opsark.config import Settings
from opsark.main import create_app

TOKEN = "synthetic-recovery-console-token-long-enough"


def test_new_history_and_capability_are_authenticated_without_remote_side_effects(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, token=TOKEN))
    calls = []
    app.state.patch_service.invoker = lambda *_a, **_k: calls.append(True)
    client = TestClient(app)
    assert client.get("/api/activation-recoveries").status_code == 401
    headers = {"Authorization": "Bearer " + TOKEN}
    cap = client.get("/api/capabilities", headers=headers)
    assert cap.status_code == 200 and cap.json()["activation_recovery"] is True
    result = client.get("/api/activation-recoveries", headers=headers)
    assert result.status_code == 200
    assert result.json()["enabled"] is False and result.json()["records"] == []
    assert not calls


def test_request_body_cannot_supply_authority_or_server_secrets(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, token=TOKEN))
    client = TestClient(app)
    headers = {"Authorization": "Bearer " + TOKEN}
    value = {
        "host_id": "unregistered",
        "job_id": "1" * 32,
        "activation_id": "2" * 32,
        "expected_mode_revision": 0,
        "verified": True,
        "api_key": "sensitive-test-value",
    }
    result = client.post("/api/activation-recoveries/plans", headers=headers, json=value)
    assert result.status_code == 422
    assert "sensitive-test-value" not in result.text


def test_unknown_host_never_admits_a_recovery(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, token=TOKEN))
    calls = []
    app.state.patch_service.invoker = lambda *_a, **_k: calls.append(True)
    result = TestClient(app).post(
        "/api/activation-recoveries/plans",
        headers={"Authorization": "Bearer " + TOKEN},
        json={
            "host_id": "unregistered",
            "job_id": "1" * 32,
            "activation_id": "2" * 32,
            "expected_mode_revision": 0,
        },
    )
    assert result.status_code in {403, 404, 409}
    assert not calls
