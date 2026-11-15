"""Default-off assembly, fixed local session API and owned-only dispatcher."""

import hashlib
import sqlite3
from contextlib import closing
from threading import Event
from time import monotonic
from types import SimpleNamespace

import pytest
from defense_recheck_process_restart import (
    RestartAcceptanceError,
    _decode_settings,
    _settings_document,
)
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from test_defense_api import NOW, FakeRoot, policy
from test_defense_api import harness as harness
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_store import session as session

from opsark.config import Settings, load_settings
from opsark.defense_session_api import register_defense_session_routes
from opsark.defense_session_worker import DefenseSessionWorker
from opsark.defense_store import DefenseConflict

TOKEN = "synthetic-single-session-api-console-token-only"
PRIVATE = "FAKE_PRIVATE_UNCLASSIFIED_INPUT"
REF = "1" * 32


class LocalCoordinator:
    def __init__(self, session):
        self.scene, self.calls = session, []
        self.refs = ()

    def status(self):
        return {"owned_sessions": len(self.refs), "mutation_owner": True}

    def owned_session_refs(self):
        return self.refs

    def start(self, host_id, cursor_rid, *, session_ref, expected_mode_revision):
        self.calls.append(("start", host_id, cursor_rid, session_ref, expected_mode_revision))
        declaration = self.scene.declaration
        if (
            host_id != declaration.runtime.context.host_id
            or cursor_rid != declaration.cursor_rid
            or session_ref != REF
            or expected_mode_revision != declaration.runtime.mode.revision
        ):
            raise DefenseConflict(PRIVATE)
        record = self.scene.store.declare(declaration, now=NOW)
        self.refs = (REF,)
        return record

    def get(self, session_ref):
        return self.scene.store.get(session_ref, now=NOW)

    def ai_receipt(self, host_id, session_ref):
        record = self.get(session_ref)
        if host_id != record.declaration.runtime.context.host_id:
            raise DefenseConflict(PRIVATE)
        return {
            "v": 1,
            "session_ref": session_ref,
            "analysis_id": None,
            "status": "not_started" if record.declaration.runtime.requires_ai else "not_required",
            "decision": None,
            "usage_state": None,
            "input_digest": None,
            "proof_sha256": None,
            "actions_executable": False,
        }

    def list(self, host_id, *, after_sequence=0, limit=20):
        self.calls.append(("list", host_id, after_sequence, limit))
        rows = []
        if self.refs and after_sequence == 0:
            rows.append({"sequence": 1, "record": self.get(REF)})
        return {"sessions": rows, "next_after_sequence": None}

    def stop(self, session_ref=None):
        self.calls.append(("stop", session_ref))
        if session_ref is not None:
            return self.scene.store.halt(session_ref, reason="requested", now=NOW)
        return self.status()


class Dispatcher:
    def __init__(self):
        self.enabled, self.wakes = True, 0

    def wake(self):
        self.wakes += 1

    def status(self):
        return {"enabled": self.enabled, "running": False, "reason_code": "idle"}


@pytest.fixture
def api(session):
    app, coordinator, worker = FastAPI(), LocalCoordinator(session), Dispatcher()

    def authorize(request: Request):
        if request.headers.get("Authorization") != "Bearer " + TOKEN:
            raise HTTPException(401, "Authentication required")

    register_defense_session_routes(app, coordinator, worker, [Depends(authorize)])
    return TestClient(app), coordinator, worker


def body(coordinator):
    declaration = coordinator.scene.declaration
    return {
        "cursor_request_id": declaration.cursor_rid,
        "session_ref": REF,
        "expected_mode_revision": declaration.runtime.mode.revision,
        "confirm_session": True,
    }


def test_session_api_auth_before_state_and_fixed_small_projection(api):
    client, coordinator, worker = api
    path = "/api/hosts/fixture/ssh-defense/sessions"
    assert client.get("/api/ssh-defense/sessions/status").status_code == 401
    assert client.get(path).status_code == 401
    assert client.post(path, json=body(coordinator)).status_code == 401
    assert coordinator.calls == [] and worker.wakes == 0
    client.headers["Authorization"] = "Bearer " + TOKEN
    status = client.get("/api/ssh-defense/sessions/status")
    assert status.status_code == 200 and status.json()["continuous_execution"] is False
    assert status.json()["session_only"] is True
    response = client.post(path, json=body(coordinator))
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    row = response.json()
    assert row["session_ref"] == REF and row["business_verdict"] == "pending"
    assert row["can_stop"] and worker.wakes == 1
    assert not {"source", "runtime", "typed_declaration", "owner", "settings", "ai_key"} & set(row)
    assert coordinator.scene.declaration.runtime.provider_fingerprint is None
    assert client.post(path, json=body(coordinator)).json() == row
    assert client.get(path + "/" + REF).json() == row
    page = client.get(path).json()
    assert page["sessions"][0]["sequence"] == 1
    assert client.get(path.replace("fixture", "other") + "/" + REF).status_code == 409


@pytest.mark.parametrize(
    "change",
    [
        {"confirm_session": 1},
        {"confirm_session": "true"},
        {"confirm_session": False},
        {"expected_mode_revision": True},
        {"prompt": PRIVATE},
        {"target_address": PRIVATE},
        {"budget": 9},
    ],
)
def test_start_is_exact_confirmation_no_prompt_address_or_budget(api, change):
    client, coordinator, worker = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    response = client.post(
        "/api/hosts/fixture/ssh-defense/sessions", json=body(coordinator) | change
    )
    assert response.status_code == 422 and PRIVATE not in response.text
    assert coordinator.calls == [] and worker.wakes == 0


def test_stop_requires_original_hash_and_only_halts_no_fee_or_latch_release(api):
    client, coordinator, _ = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    path = "/api/hosts/fixture/ssh-defense/sessions"
    row = client.post(path, json=body(coordinator)).json()
    stop = path + "/" + REF + "/stop"
    assert (
        client.post(
            stop, json={"expected_declaration_sha256": "f" * 64, "confirm_stop": True}
        ).status_code
        == 409
    )
    assert not any(call[0] == "stop" for call in coordinator.calls)
    request = {"expected_declaration_sha256": row["declaration_sha256"], "confirm_stop": True}
    first = client.post(stop, json=request)
    second = client.post(stop, json=request)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() and first.json()["effective_phase"] == "stopped"
    assert first.json()["business_verdict"] == "pending" and not first.json()["can_stop"]
    assert client.post(stop, json=request | {"confirm_stop": 1}).status_code == 422
    assert client.post(stop, json=request | {"log": PRIVATE}).status_code == 422


def test_default_off_api_still_reads_history_and_cannot_start(api):
    client, coordinator, worker = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    worker.enabled = False
    path = "/api/hosts/fixture/ssh-defense/sessions"
    assert client.post(path, json=body(coordinator)).status_code == 403
    assert client.get(path).status_code == 200 and coordinator.calls == [("list", "fixture", 0, 20)]
    assert not worker.wakes


@pytest.mark.parametrize(
    "query", ["limit=0", "limit=21", "after_sequence=-1", "after_sequence=" + PRIVATE]
)
def test_history_page_is_bounded_without_input_echo(api, query):
    client, coordinator, _ = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    response = client.get("/api/hosts/fixture/ssh-defense/sessions?" + query)
    assert response.status_code == 422 and PRIVATE not in response.text and not coordinator.calls


@pytest.mark.parametrize("value", [1, "true", None])
def test_deployment_switch_requires_real_bool(tmp_path, value):
    with pytest.raises(ValueError):
        Settings(tmp_path, TOKEN, defense_session_enabled=value)


def test_session_environment_is_default_off_explicit_and_separate(tmp_path, monkeypatch):
    for name in tuple(__import__("os").environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    assert not load_settings().defense_session_enabled
    with pytest.raises(ValueError):
        Settings(tmp_path, TOKEN, defense_session_enabled=True)
    monkeypatch.setenv("OPSARK_DEFENSE_SESSION_ENABLED", "true")
    monkeypatch.setenv("OPSARK_DEFENSE_INVENTORY", str(tmp_path / "registry"))
    monkeypatch.setenv("OPSARK_DEFENSE_POLICY", str(tmp_path / "policy"))
    enabled = load_settings()
    assert enabled.defense_session_enabled and not enabled.defense_worker_enabled
    monkeypatch.setenv("OPSARK_DEFENSE_SESSION_ENABLED", PRIVATE)
    with pytest.raises(ValueError):
        load_settings()


def test_old_process_fixture_refuses_a_sender_even_after_json_decode(tmp_path):
    settings = Settings(
        tmp_path,
        TOKEN,
        defense_inventory_path=tmp_path / "registry",
        defense_policy_path=tmp_path / "policy",
        defense_session_enabled=True,
    )
    with pytest.raises(RestartAcceptanceError):
        _settings_document(settings)
    from dataclasses import asdict

    document = asdict(settings)
    document["data_dir"] = str(tmp_path)
    document["defense_inventory_path"] = str(tmp_path / "registry")
    document["defense_policy_path"] = str(tmp_path / "policy")
    with pytest.raises(RestartAcceptanceError):
        _decode_settings(document)


class QueueCoordinator:
    def __init__(self):
        self.refs: tuple[str, ...] = ()
        self.calls = []
        self.block, self.started, self.fenced = Event(), Event(), Event()

    def owned_session_refs(self):
        return self.refs

    def tick(self, session_ref):
        self.calls.append(session_ref)
        self.started.set()
        assert self.block.wait(3)
        return SimpleNamespace(effective_phase="completed")

    def stop(self, session_ref=None):
        self.fenced.set()


def test_dispatcher_only_ticks_owned_memory_refs_and_stop_fences_before_join():
    coordinator = QueueCoordinator()
    worker = DefenseSessionWorker(coordinator, enabled=True)
    assert worker.tick() is False and not coordinator.calls
    coordinator.refs = (REF,)
    assert worker.start() and coordinator.started.wait(3)
    began = monotonic()
    assert not worker.stop(timeout=0)
    assert coordinator.fenced.is_set() and monotonic() - began < 0.5
    coordinator.block.set()
    assert worker.stop(timeout=3)
    assert coordinator.calls == [REF] and worker.tick() is False


def test_real_main_default_does_not_start_sender_or_make_rpc(tmp_path, main_module, monkeypatch):
    app = main_module.create_app(Settings(tmp_path / "data", TOKEN))
    worker = app.state.defense_session_worker
    monkeypatch.setattr(worker, "start", lambda: pytest.fail("Default sender must not start"))
    root = app.state.defense_service
    monkeypatch.setattr(root, "invoker", lambda *_a, **_kw: pytest.fail("Default network"))
    with TestClient(app, headers={"Authorization": "Bearer " + TOKEN}) as client:
        status = client.get("/api/ssh-defense/sessions/status").json()
        assert status["enabled"] is False and status["running"] is False
        assert status["owned_sessions"] == 0 and status["continuous_execution"] is False
        assert client.get("/api/automation").json()["mode"] == "manual"
    assert root.stopped.is_set() and worker.stopped.is_set()


def test_explicit_main_session_starts_only_owned_thread_and_stop_prevents_apply(
    tmp_path, main_module, monkeypatch, target
):
    monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": target.host})
    monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": target})
    monkeypatch.setattr(main_module, "load_defense_policy", lambda _: policy(target))
    settings = Settings(
        tmp_path / "data",
        TOKEN,
        defense_inventory_path=tmp_path / "registry",
        defense_policy_path=tmp_path / "policy",
        defense_session_enabled=True,
    )
    app = main_module.create_app(settings)
    controller = app.state.defense_service
    controller.clock = lambda: NOW
    app.state.defense_session_coordinator.clock = controller.clock
    root = FakeRoot(target, controller.clock)

    def invoke(registered, call, role, *, admit=None, timeout=28):
        assert 0 < timeout <= 30
        return root(registered, call, role, admit=admit)

    controller.invoker = invoke
    entered, release = Event(), Event()
    original_prepare = controller.prepare

    def blocked_prepare(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(controller, "prepare", blocked_prepare)
    prefix = "/api/hosts/fixture/ssh-defense"
    with TestClient(app, headers={"Authorization": "Bearer " + TOKEN}) as client:
        status = client.get("/api/ssh-defense/sessions/status").json()
        assert status["enabled"] and status["running"] and status["owned_sessions"] == 0
        assert not root.sent
        assert (
            client.put(
                "/api/automation", json={"mode": "automatic", "expected_revision": 0}
            ).status_code
            == 200
        )
        armed = client.post(
            prefix + "/arm", json={"expected_mode_revision": 1, "confirm_arm": True}
        )
        assert armed.status_code == 200
        posted = client.post(
            prefix + "/sessions",
            json={
                "cursor_request_id": armed.json()["request_id"],
                "session_ref": REF,
                "expected_mode_revision": 1,
                "confirm_session": True,
            },
        )
        assert posted.status_code == 200
        before = posted.json()
        try:
            assert entered.wait(3)
            stopped = client.post(
                prefix + "/sessions/" + REF + "/stop",
                json={
                    "expected_declaration_sha256": before["declaration_sha256"],
                    "confirm_stop": True,
                },
            )
        finally:
            release.set()
        assert stopped.status_code == 200 and stopped.json()["business_verdict"] == "pending"
        assert stopped.json()["effective_phase"] == "stopped"
        assert not any(op == "apply" for op, _ in root.sent)
        assert app.state.automation_store.status()["mode"] == "automatic"
        assert client.get("/api/capabilities").json()["ssh_defense_continuous_execution"] is False
    assert app.state.defense_session_worker.stopped.is_set()
    assert not app.state.defense_session_worker.status()["running"]


def old_catalog_and_rows(directory):
    result = {}
    for path in sorted(directory.glob("*.sqlite3")):
        hasher = hashlib.sha256()
        with closing(sqlite3.connect(path)) as db, db:
            catalog = db.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'defense_session%' "
                "AND tbl_name NOT LIKE 'defense_session%' ORDER BY type,name"
            ).fetchall()
            hasher.update(repr(catalog).encode())
            for kind, name, _, _ in catalog:
                if kind != "table":
                    continue
                quoted = '"' + name.replace('"', '""') + '"'
                rows = db.execute("SELECT rowid,* FROM " + quoted + " ORDER BY rowid").fetchall()  # noqa: S608 -- quoted names from owned SQLite catalog.
                hasher.update(repr(rows).encode())
        result[path.name] = hasher.hexdigest()
    return result


def test_default_off_old_schema_migration_only_adds_known_session_tables(
    tmp_path, main_module, monkeypatch
):
    settings = Settings(tmp_path / "data", TOKEN)
    app = main_module.create_app(settings)
    session_tables = {
        "defense_sessions_v1",
        "defense_session_selections_v1",
        "defense_session_ai_v1",
        "defense_session_actions_v1",
        "defense_session_requests_v1",
    }
    with closing(sqlite3.connect(settings.data_dir / "security.sqlite3")) as db, db:
        for name in reversed(sorted(session_tables)):
            db.execute("DROP TABLE " + name)  # noqa: S608 -- fixed known table literals.
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE 'defense_session%'"
        ).fetchall()
    before = old_catalog_and_rows(settings.data_dir)
    assert len(before) == 10
    rebuilt = main_module.create_app(settings)
    monkeypatch.setattr(
        rebuilt.state.defense_service, "invoker", lambda *_a, **_kw: pytest.fail("Migration RPC")
    )
    with TestClient(rebuilt, headers={"Authorization": "Bearer " + TOKEN}) as client:
        assert client.get("/api/ssh-defense/sessions/status").json()["enabled"] is False
        assert client.get("/api/automation").json()["mode"] == "manual"
    assert old_catalog_and_rows(settings.data_dir) == before
    with closing(sqlite3.connect(settings.data_dir / "security.sqlite3")) as db, db:
        names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'defense_session%'"
            )
        }
        assert names == session_tables
    assert not app.state.defense_session_worker.status()["running"]
