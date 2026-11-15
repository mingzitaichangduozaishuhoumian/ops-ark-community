"""Application assembly preserves disabled defaults and separates execution identities."""

import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_defense_client import keyset as keyset  # noqa: F401 -- synthetic owned fixture.
from test_defense_client import target as target  # noqa: F401 -- no real credentials.

from opsark.config import Settings

TOKEN = "synthetic-application-assembly-token-only"


@pytest.fixture
def main_module(tmp_path, monkeypatch):
    # main creates its module-level app on import. Never let that app consult a
    # developer's environment or the repository's deployment directory.
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "bootstrap"))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    return importlib.import_module("opsark.main")


def test_default_defense_routes_do_not_enable_any_executor(tmp_path, main_module):
    app = main_module.create_app(Settings(tmp_path / "data", TOKEN))
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    assert app.state.mode_coordinator is None
    mode = client.get("/api/automation").json()
    assert mode["mode"] == "manual" and mode["revision"] == 0 and mode["mode_sync_complete"]
    assert not mode["execution_available"]
    assert app.state.defense_service.targets == {}
    status = client.get("/api/ssh-defense/status")
    assert status.status_code == 200
    capabilities = client.get("/api/capabilities").json()
    assert capabilities["ssh_defense_transactions"] is False
    assert capabilities["ssh_defense_execution"] is False
    assert capabilities["ssh_defense_continuous_execution"] is False
    assert capabilities["ssh_defense_ai"] is False
    assert app.state.defense_service.ai_service is app.state.defense_ai_service
    assert app.state.defense_ai_service.store is app.state.defense_service.store
    asset = client.get("/defense.js")
    assert asset.status_code == 200 and "OpsArkDefense" in asset.text
    assert asset.headers["content-type"].startswith("text/javascript")
    ai_response = client.get(
        "/api/hosts/no-host/ssh-defense/ai/preview",
        params={"cursor_request_id": "a" * 32, "source_ref": "b" * 32},
    )
    assert ai_response.status_code == 409
    assert client.get("/api/hosts/no-host/ssh-defense/ai/analyses/" + "c" * 32).status_code == 409
    assert client.post(
        "/api/hosts/no-host/ssh-defense/arm",
        json={
            "expected_mode_revision": 0,
            "confirm_arm": True,
        },
    ).status_code in {404, 409}
    assert client.get("/api/automation").json()["revision"] == 0


def test_defense_only_assembly_has_shared_pending_without_apt_permission(
    tmp_path, target, monkeypatch, main_module
):
    main = main_module
    monkeypatch.setattr(main, "load_hosts", lambda _: {"fixture": target.host})
    monkeypatch.setattr(main, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main, "load_defense_targets", lambda *_: {"fixture": target})
    app = main.create_app(Settings(tmp_path / "data", TOKEN))
    coordinator = app.state.mode_coordinator
    assert coordinator is not None
    assert app.state.patch_service.targets == {}
    assert coordinator.mode_lock is app.state.defense_service.mode_lock
    assert coordinator.mode_lock is not app.state.patch_service.mode_lock
    assert app.state.patch_service.admission_lock is coordinator.mode_lock
    mode = coordinator.status()
    assert mode["sync_channels"] == ["ssh-defense"]
    assert not mode["mode_sync_complete"] and not mode["execution_available"]
    assert mode["policy"]["enabled"] is False
    assert not app.state.defense_service.policy.enabled


def test_unimplemented_continuous_worker_flag_cannot_silently_enable_execution(
    tmp_path, main_module
):
    settings = Settings(
        tmp_path / "data",
        TOKEN,
        defense_worker_enabled=True,
        defense_inventory_path=tmp_path / "registry",
        defense_policy_path=tmp_path / "policy",
    )
    with pytest.raises(ValueError, match="尚未完成装配验收"):
        main_module.create_app(settings)
