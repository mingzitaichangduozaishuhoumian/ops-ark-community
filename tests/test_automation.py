import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from opsark.automation_store import AutomationStore, ModeChange, StaleModeError, load_policy
from opsark.config import Settings
from opsark.control_modes import ControlPolicy
from opsark.main import create_app

TOKEN = "test-automation-console-token-2026"


def test_mode_persists_across_restarts_without_implying_execution(tmp_path):
    path = tmp_path / "automation.db"
    store = AutomationStore(path, ControlPolicy())
    assert store.status()["mode"] == "manual"
    assert store.status()["revision"] == 0
    selected = store.change_mode(ModeChange(mode="automatic", expected_revision=0))
    assert selected["mode"] == "automatic"
    assert selected["revision"] == 1
    assert selected["execution_available"] is False
    restarted = AutomationStore(path, ControlPolicy())
    assert restarted.status() == selected
    same = restarted.change_mode(ModeChange(mode="automatic", expected_revision=1))
    assert same == selected


def test_policy_change_returns_to_manual_and_invalidates_old_process(tmp_path):
    path = tmp_path / "automation.db"
    old = AutomationStore(path, ControlPolicy())
    old.change_mode(ModeChange(mode="automatic", expected_revision=0))
    changed = AutomationStore(path, ControlPolicy(host_ids=("new-server",)))
    assert changed.status()["mode"] == "manual"
    assert changed.status()["revision"] == 2
    with pytest.raises(StaleModeError):
        old.status()
    with pytest.raises(StaleModeError):
        old.change_mode(ModeChange(mode="automatic", expected_revision=1))


def test_competing_tabs_cannot_overwrite_a_newer_selection(tmp_path):
    path = tmp_path / "automation.db"
    stores = [AutomationStore(path, ControlPolicy()) for _ in range(2)]

    def change(pair):
        store, mode = pair
        try:
            return store.change_mode(ModeChange(mode=mode, expected_revision=0))["revision"]
        except StaleModeError:
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(change, zip(stores, ("assisted", "automatic"), strict=True)))
    assert sorted(map(str, outcomes)) == ["1", "stale"]
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM automation_audit").fetchone()[0] == 2


def test_deployment_policy_has_bounded_size_and_strict_fields(tmp_path):
    path = tmp_path / "policy.json"
    assert load_policy(None) == ControlPolicy()
    path.write_text(json.dumps({"enabled": True, "allowed_packages": ["curl"]}))
    assert load_policy(path).allowed_packages == ("curl",)
    path.write_text('{"enabled":"yes"}')
    with pytest.raises(ValueError):
        load_policy(path)
    path.write_text(" " * 8193)
    with pytest.raises(ValueError):
        load_policy(path)


def test_mode_api_auth_origin_strict_schema_and_restart(tmp_path):
    settings = Settings(data_dir=tmp_path, token=TOKEN)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    client = TestClient(create_app(settings))
    assert client.get("/api/automation").status_code == 401
    assert client.put("/api/automation", json={}).status_code == 401
    assert client.get("/api/capabilities", headers=headers).json()["automation_modes"] is True
    assert client.get("/api/automation", headers=headers).json()["mode"] == "manual"
    route = "/api/automation"
    body = {"mode": "assisted", "expected_revision": 0}
    assert (
        client.put(
            route, headers=headers | {"Origin": "https://other.invalid"}, json=body
        ).status_code
        == 403
    )
    for malformed in (
        {"mode": "root", "expected_revision": 0},
        {"mode": "automatic", "expected_revision": False},
        {"mode": "automatic", "expected_revision": "0"},
        body | {"policy": {"enabled": True}},
        body | {"command": "apt-get upgrade"},
    ):
        assert client.put(route, headers=headers, json=malformed).status_code == 422
    selected = client.put(route, headers=headers, json=body)
    assert selected.status_code == 200
    assert selected.json()["execution_available"] is False
    assert client.put(route, headers=headers, json=body).status_code == 409
    restarted = TestClient(create_app(settings))
    assert restarted.get(route, headers=headers).json()["mode"] == "assisted"
