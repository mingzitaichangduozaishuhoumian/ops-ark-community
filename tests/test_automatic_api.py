"""The observation route cannot grant authority or submit a repair."""

import sqlite3

from fastapi.testclient import TestClient

from opsark.config import Settings
from opsark.main import create_app

TOKEN = "automatic-api-fixture-token-long-enough"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_automatic_route_requires_auth_and_defaults_to_no_authority(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, token=TOKEN))
    with TestClient(app) as client:
        assert client.get("/api/automatic/status").status_code == 401
        assert client.get("/api/capabilities", headers=AUTH).json()["automatic_repair"] is True
        response = client.get("/api/automatic/status", headers=AUTH)
        assert response.status_code == 200
        state = response.json()
        assert state["enabled"] is False
        assert state["hosts"] == state["grants"] == state["jobs"] == []
        assert state["latched_hosts"] == []
        assert client.post("/api/automatic/status", headers=AUTH, json={}).status_code == 405
        assert client.post("/api/automatic/grants", headers=AUTH, json={}).status_code == 404
        assert client.post("/api/automatic/reset", headers=AUTH, json={}).status_code == 404
        assert app.state.patch_store.list_jobs() == []
    assert app.state.automatic_monitor.stop_event.is_set()
    assert app.state.automatic_store.path.name == "automatic.sqlite3"


def test_unreadable_safety_state_returns_unavailable_without_empty_success(tmp_path, monkeypatch):
    app = create_app(Settings(data_dir=tmp_path, token=TOKEN))

    def unavailable():
        raise sqlite3.DatabaseError("private fixture details must not leak")

    monkeypatch.setattr(app.state.automatic_monitor, "status", unavailable)
    response = TestClient(app).get("/api/automatic/status", headers=AUTH)
    assert response.status_code == 503
    assert "private fixture" not in response.text
