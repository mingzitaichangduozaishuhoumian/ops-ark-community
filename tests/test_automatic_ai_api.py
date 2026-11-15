"""Authenticated AI console events do not authorize retries or package execution."""

import hashlib
import json

from fastapi.testclient import TestClient

from opsark.automation_store import AutomationStore, ModeChange
from opsark.config import Settings
from opsark.control_modes import ControlPolicy
from opsark.main import create_app


def test_ai_alert_auth_ack_and_status_are_bounded_local_records(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, token="test-console-token-" * 3))
    store = app.state.automatic_store
    alert = store.emit_ai_alert("example", "a" * 64, "blocked", "当前分析未通过本地校验。")
    headers = {"Authorization": "Bearer " + app.state.settings.token}
    with TestClient(app) as client:
        assert client.get("/api/automatic/ai/alerts").status_code == 401
        assert client.post(f"/api/automatic/ai/alerts/{alert['id']}/ack").status_code == 401
        assert client.get("/api/automatic/ai/alerts", headers=headers).json() == [alert]
        status = client.get("/api/automatic/status", headers=headers).json()
        assert status["ai"]["enabled"] is False and status["ai"]["requests"] == []
        before = app.state.automation_store.status()
        response = client.post(f"/api/automatic/ai/alerts/{alert['id']}/ack", headers=headers)
        assert response.status_code == 200 and response.json()["acknowledged"] is True
        assert (
            client.post("/api/automatic/ai/alerts/invalid/ack", headers=headers).status_code == 404
        )
        assert (
            client.post(
                "/api/automatic/ai/alerts/" + "0" * 64 + "/ack", headers=headers
            ).status_code
            == 404
        )
        assert app.state.automation_store.status() == before
        assert app.state.patch_store.list_jobs() == []
        assert store.ai_requests() == []


def test_absent_ai_opt_in_preserves_legacy_mode_scope(tmp_path):
    policy = ControlPolicy()
    old_policy = policy.model_dump(mode="json", exclude={"automatic_ai"})
    old_scope = hashlib.sha256(
        ("no-executor/v1\n" + json.dumps(old_policy, sort_keys=True)).encode()
    ).hexdigest()
    store = AutomationStore(tmp_path / "automation.sqlite3", policy)
    assert store.scope == old_scope
    store.change_mode(ModeChange(mode="manual", expected_revision=0))
    before = store.status()
    restored = AutomationStore(tmp_path / "automation.sqlite3", ControlPolicy())
    assert restored.status() == before
