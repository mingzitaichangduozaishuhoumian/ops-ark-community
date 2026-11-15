"""Default-off configuration and authenticated local follow-up API contracts."""

import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from time import monotonic, sleep

import pytest
from defense_recheck_process_restart import DATABASES, _decode_settings, _settings_document
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_recheck_application import application as application
from test_defense_recheck_application import approved_action

from opsark.config import Settings, load_settings
from opsark.defense_store import DefenseConflict
from opsark.defense_task_watch_api import register_defense_task_watch_routes

TOKEN = "synthetic-task-watch-api-token-only"
PRIVATE = "unclassified-secret-payload-must-not-be-echoed"
REF = "a" * 32
WATCH_TABLES = {
    "defense_task_watch_lease_v1",
    "defense_task_watch_discovery_v1",
    "defense_task_watches_v1",
    "defense_task_watch_attempts_v1",
    "defense_task_watch_events_v1",
}
WATCH_INDEXES = {"defense_task_watch_apply_cursor_v1", "defense_task_watch_due_v1"}


def event():
    return {
        "event_ref": REF,
        "sequence": 1,
        "task_reference_sha256": "b" * 64,
        "host_id": "synthetic-target",
        "request_id": "c" * 32,
        "state": "unavailable",
        "observed_at": "2026-11-06T00:00:00Z",
        "acknowledged_at": None,
    }


class LocalWatch:
    def __init__(self):
        self.row = event()
        self.calls = []
        self.clock = lambda: datetime(2026, 11, 6, 0, 0, 1, tzinfo=UTC)

    def status(self):
        return {"enabled": False, "running": False, "continuous_execution": False}

    def events(self, *, after_sequence=0, limit=20):
        self.calls.append(("events", after_sequence, limit))
        return {"events": [dict(self.row)], "next_after_sequence": None}

    def ack(self, event_ref, *, confirm_ack=True, now=None):
        self.calls.append(("ack", event_ref, confirm_ack))
        if event_ref != REF:
            raise DefenseConflict(PRIVATE)
        self.row["acknowledged_at"] = self.row["acknowledged_at"] or "2026-11-06T00:00:01Z"
        return dict(self.row)


@pytest.fixture
def api():
    app, watch = FastAPI(), LocalWatch()

    def authorize(request: Request):
        if request.headers.get("Authorization") != "Bearer " + TOKEN:
            raise HTTPException(401, "Authentication required")

    register_defense_task_watch_routes(app, watch, watch, [Depends(authorize)])
    return TestClient(app), watch


def test_watch_api_is_authenticated_no_store_access_without_token(api):
    client, store = api
    assert client.get("/api/ssh-defense/task-watch").status_code == 401
    assert client.get("/api/ssh-defense/task-watch/events").status_code == 401
    assert client.post("/api/ssh-defense/task-watch/events/" + REF + "/ack").status_code == 401
    assert store.calls == []


def test_local_watch_page_and_ack_are_explicit_idempotent_no_store_error_echo(api):
    client, store = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    response = client.get("/api/ssh-defense/task-watch")
    assert response.status_code == 200 and response.json()["continuous_execution"] is False
    assert response.headers["Cache-Control"] == "no-store"
    page = client.get("/api/ssh-defense/task-watch/events?after_sequence=2&limit=1")
    assert page.status_code == 200 and store.calls[-1] == ("events", 2, 1)
    route = "/api/ssh-defense/task-watch/events/" + REF + "/ack"
    first = client.post(route, json={"confirm_ack": True})
    second = client.post(route, json={"confirm_ack": True})
    assert first.status_code == second.status_code == 200 and first.json() == second.json()
    assert first.json()["state"] == "unavailable"
    missing = client.post(route.replace(REF, "d" * 32), json={"confirm_ack": True})
    assert missing.status_code == 409 and PRIVATE not in missing.text


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"confirm_ack": 1},
        {"confirm_ack": "true"},
        {"confirm_ack": False},
        {"confirm_ack": True, "log": PRIVATE},
    ],
)
def test_ack_validation_never_echoes_unknown_content(api, body):
    client, store = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    response = client.post("/api/ssh-defense/task-watch/events/" + REF + "/ack", json=body)
    assert response.status_code == 422 and PRIVATE not in response.text
    assert store.calls == []


@pytest.mark.parametrize(
    "query", ["limit=21", "limit=0", "after_sequence=-1", "after_sequence=" + PRIVATE]
)
def test_followup_page_validation_is_bounded_and_does_not_echo(api, query):
    client, store = api
    client.headers["Authorization"] = "Bearer " + TOKEN
    response = client.get("/api/ssh-defense/task-watch/events?" + query)
    assert response.status_code == 422 and PRIVATE not in response.text
    assert store.calls == []


@pytest.mark.parametrize(
    "update",
    [
        {"defense_task_watch_enabled": "true"},
        {"defense_task_watch_enabled": True},
        {"defense_task_watch_host_ids": ["fixture"]},
        {"defense_task_watch_host_ids": ("fixture", "fixture")},
        {"defense_task_watch_host_ids": ("../fixture",)},
        {"defense_task_watch_host_ids": tuple("host-" + str(i) for i in range(11))},
        {"defense_task_watch_interval_seconds": True},
        {"defense_task_watch_interval_seconds": 29},
        {"defense_task_watch_interval_seconds": 3601},
    ],
)
def test_watch_settings_reject_implicit_or_unbounded_scope(tmp_path, update):
    with pytest.raises(ValueError):
        Settings(tmp_path, TOKEN, **update)


def test_watch_settings_environment_is_explicit_and_fixed(tmp_path, monkeypatch):
    for name in (
        "OPSARK_DEFENSE_TASK_WATCH_ENABLED",
        "OPSARK_DEFENSE_TASK_WATCH_HOSTS",
        "OPSARK_DEFENSE_TASK_WATCH_INTERVAL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    disabled = load_settings()
    assert not disabled.defense_task_watch_enabled and disabled.defense_task_watch_host_ids == ()
    monkeypatch.setenv("OPSARK_DEFENSE_TASK_WATCH_ENABLED", "true")
    monkeypatch.setenv("OPSARK_DEFENSE_TASK_WATCH_HOSTS", "fixture")
    monkeypatch.setenv("OPSARK_DEFENSE_TASK_WATCH_INTERVAL", "30")
    monkeypatch.setenv("OPSARK_DEFENSE_INVENTORY", str(tmp_path / "registry.json"))
    monkeypatch.setenv("OPSARK_DEFENSE_POLICY", str(tmp_path / "policy.json"))
    enabled = load_settings()
    assert enabled.defense_task_watch_enabled and enabled.defense_task_watch_host_ids == (
        "fixture",
    )
    assert enabled.defense_task_watch_interval_seconds == 30 and not enabled.defense_worker_enabled
    monkeypatch.setenv("OPSARK_DEFENSE_TASK_WATCH_INTERVAL", "6_0")
    with pytest.raises(ValueError):
        load_settings()


def test_real_main_default_never_starts_followup_or_grants_execution(
    tmp_path, main_module, monkeypatch
):
    app = main_module.create_app(Settings(tmp_path / "data", TOKEN))
    watcher = app.state.defense_task_watcher
    monkeypatch.setattr(watcher, "start", lambda: pytest.fail("Default follow-up must not start"))
    monkeypatch.setattr(
        app.state.defense_service, "invoker", lambda *_a, **_kw: pytest.fail("Default RPC")
    )
    with TestClient(app, headers={"Authorization": "Bearer " + TOKEN}) as client:
        status = client.get("/api/ssh-defense/task-watch").json()
        assert status["enabled"] is False and status["running"] is False
        assert status["counts"] == {"tasks": 0, "pending": 0, "alerts": 0, "unread": 0}
        caps = client.get("/api/capabilities").json()
        assert caps["ssh_defense_task_watch"] and not caps["ssh_defense_continuous_execution"]
        assert client.get("/api/ssh-defense/task-watch/events").json()["events"] == []


def test_real_main_rejects_unregistered_followup_targets(tmp_path, main_module):
    settings = Settings(tmp_path / "data", TOKEN, defense_task_watch_host_ids=("unregistered",))
    with pytest.raises(ValueError, match="独立防护登记"):
        main_module.create_app(settings)


def test_manual_main_watch_queries_original_task_and_ack_cannot_release_or_replay(
    application, main_module
):
    app0, client0, root, *_ = application
    action = approved_action(application)
    assert (
        client0.put("/api/automation", json={"mode": "manual", "expected_revision": 1}).status_code
        == 200
    )
    settings = replace(
        app0.state.settings,
        defense_task_watch_enabled=True,
        defense_task_watch_host_ids=("fixture",),
        defense_task_watch_interval_seconds=30,
        defense_inventory_path=Path("synthetic-registry"),
        defense_policy_path=Path("synthetic-policy"),
    )
    app = main_module.create_app(settings)
    controller, watcher = app.state.defense_service, app.state.defense_task_watcher
    controller.clock, watcher.clock = (
        app0.state.defense_service.clock,
        app0.state.defense_service.clock,
    )
    reached = Event()

    def invoke(target, call, role, *, admit=None):
        reply = root(target, call, role, admit=admit)
        reached.set()
        return reply

    controller.invoker = invoke
    before = tuple(root.sent)
    usage = controller.store.execution_usage(action["request_id"])
    mode = app.state.automation_store.status()
    with TestClient(app, headers={"Authorization": "Bearer " + settings.token}) as client:
        assert reached.wait(3), "The explicit watch did not query the existing action"
        deadline = monotonic() + 3
        while watcher.status()["counts"]["alerts"] == 0 and monotonic() < deadline:
            sleep(0.02)
        watcher.stop()
        events = client.get("/api/ssh-defense/task-watch/events").json()["events"]
        assert len(events) == 1 and events[0]["request_id"] == action["request_id"]
        ref = events[0]["event_ref"]
        first = client.post(
            "/api/ssh-defense/task-watch/events/" + ref + "/ack", json={"confirm_ack": True}
        )
        second = client.post(
            "/api/ssh-defense/task-watch/events/" + ref + "/ack", json={"confirm_ack": True}
        )
        assert first.status_code == second.status_code == 200 and first.json() == second.json()
    assert root.sent[len(before) :] == [("query", action["request_id"])]
    assert controller.store.execution_usage(action["request_id"]) == usage
    assert app.state.automation_store.status() == mode
    assert not watcher.status()["running"]


def test_process_settings_decode_preserves_tuple_contract_and_rejects_implicit_watch(tmp_path):
    settings = Settings(tmp_path, TOKEN, defense_task_watch_host_ids=("fixture",))
    decoded = _decode_settings(json.loads(json.dumps(_settings_document(settings))))
    assert decoded == settings and decoded.defense_task_watch_host_ids == ("fixture",)
    enabled = replace(
        settings,
        defense_task_watch_enabled=True,
        defense_inventory_path=tmp_path / "registry",
        defense_policy_path=tmp_path / "policy",
    )
    with pytest.raises(RuntimeError, match="offline_settings_required"):
        _settings_document(enabled)
    document = _settings_document(settings)
    document["defense_task_watch_host_ids"] = "fixture"
    with pytest.raises(RuntimeError, match="invalid_tuple_settings"):
        _decode_settings(document)


def _old_store_image(path):
    with closing(sqlite3.connect(path)) as database, database:
        names = database.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        original = [
            row for row in names if row[2] not in WATCH_TABLES and row[1] not in WATCH_INDEXES
        ]
        rows = {}
        for kind, name, _, sql in original:
            if kind == "table":
                quoted = '"' + name.replace('"', '""') + '"'
                if "WITHOUT ROWID" in (sql or "").upper():
                    columns = database.execute("PRAGMA table_info(" + quoted + ")").fetchall()
                    ordering = ",".join('"' + row[1].replace('"', '""') + '"' for row in columns)
                    query = "SELECT * FROM " + quoted + " ORDER BY " + ordering  # noqa: S608 -- quoted identifiers from owned tmp SQLite schema.
                else:
                    query = "SELECT _rowid_,* FROM " + quoted + " ORDER BY _rowid_"  # noqa: S608 -- quoted identifiers from owned tmp SQLite schema.
                rows[name] = database.execute(query).fetchall()
        return original, rows


def test_default_old_schema_upgrade_only_adds_watch_tables_and_keeps_old_records(
    application, main_module
):
    app0, client, root, *_ = application
    action = approved_action(application)
    assert (
        client.put("/api/automation", json={"mode": "manual", "expected_revision": 1}).status_code
        == 200
    )
    root.lose = "query"
    assert (
        client.post(
            "/api/hosts/fixture/ssh-defense/transactions/" + action["request_id"] + "/query",
            json={},
        ).status_code
        == 503
    )
    security = app0.state.settings.data_dir / "security.sqlite3"
    with closing(sqlite3.connect(security)) as database, database:
        watch_schema = [
            row
            for row in database.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            )
            if row[1].startswith("defense_task_watch") or row[2].startswith("defense_task_watch")
        ]
        assert {row[1] for row in watch_schema if row[0] == "table"} == WATCH_TABLES
        assert {
            row[1] for row in watch_schema if row[0] == "index" and row[3] is not None
        } == WATCH_INDEXES
        assert all(
            row[0] == "table"
            and row[1] in WATCH_TABLES
            or row[0] == "index"
            and (row[1] in WATCH_INDEXES or row[3] is None and row[2] in WATCH_TABLES)
            for row in watch_schema
        )
        apply_index = next(
            row for row in watch_schema if row[1] == "defense_task_watch_apply_cursor_v1"
        )
        assert apply_index[2] == "defense_requests"
        assert (
            "".join(apply_index[3].split()).lower().replace("ifnotexists", "")
            == "createindexdefense_task_watch_apply_cursor_v1ondefense_requests(op)"
        )
        database.execute("DROP INDEX defense_task_watch_apply_cursor_v1")
        for name in WATCH_TABLES:
            database.execute('DROP TABLE "' + name.replace('"', '""') + '"')
        assert not any(
            row[0].startswith("defense_task_watch") or row[1].startswith("defense_task_watch")
            for row in database.execute("SELECT name,tbl_name FROM sqlite_master")
        )
    original = {name: _old_store_image(app0.state.settings.data_dir / name) for name in DATABASES}
    sent = tuple(root.sent)
    app = main_module.create_app(app0.state.settings)
    with TestClient(
        app, headers={"Authorization": "Bearer " + app0.state.settings.token}
    ) as client:
        assert client.get("/api/ssh-defense/task-watch").json()["enabled"] is False
        assert client.get("/api/ssh-defense/task-watch/events").json()["events"] == []
    assert {
        name: _old_store_image(app0.state.settings.data_dir / name) for name in DATABASES
    } == original
    assert len(original) == 10
    with closing(sqlite3.connect(security)) as database, database:
        restored_watch_schema = [
            row
            for row in database.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            )
            if row[1].startswith("defense_task_watch") or row[2].startswith("defense_task_watch")
        ]
    assert restored_watch_schema == watch_schema
    assert tuple(root.sent) == sent
    assert app.state.defense_store.transaction(action["request_id"]).query_required
