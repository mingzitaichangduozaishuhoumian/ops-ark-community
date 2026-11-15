"""Actual authenticated application routes; all remote results are synthetic."""

import hashlib
import importlib.util
import json
import os
import shlex
from dataclasses import replace
from pathlib import Path

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_compose_discovery import SECRET, host, project, row

from opsark.compose_discovery import commands_for_compose_discovery
from opsark.config import Settings, load_hosts

TOKEN = "synthetic-compose-discovery-console"
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture
def application(tmp_path, monkeypatch):
    # main's default app must also be inert before its first import.
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "isolated-default"))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    from opsark import main

    registered = replace(host(tmp_path), compose_project="demo")
    registrations = {
        "fixture": registered,
        "not-configured": replace(
            registered,
            public=registered.public.model_copy(update={"id": "not-configured"}),
            compose_project=None,
        ),
        "pending": replace(
            registered,
            public=registered.public.model_copy(update={"id": "pending"}),
            container_binding_confirmed=False,
        ),
    }
    monkeypatch.setattr(main, "load_hosts", lambda _: registrations)
    monkeypatch.setattr(main, "list_samples", lambda: [])
    calls = []

    def collect(target, scope):
        calls.append((target.public.id, scope))
        return project(target, [row()])

    monkeypatch.setattr(main, "run_compose_discovery", collect)
    app = main.create_app(Settings(data_dir=tmp_path / "controller", token=TOKEN))
    with TestClient(app) as client:
        yield client, main, registered, calls


def test_registered_project_is_private_and_unconfigured_requests_make_no_remote_call(application):
    client, _, _, calls = application
    listing = client.get("/api/hosts", headers=AUTH).json()
    assert listing[0]["compose_discovery_configured"] is True
    assert listing[1]["compose_discovery_configured"] is False
    assert listing[2]["container_binding_confirmed"] is False
    assert "compose_project" not in listing[0] and "key_file" not in listing[0]
    assert client.get("/api/capabilities", headers=AUTH).json()["host_compose_discovery"] is True
    for target, expected in (("missing", 404), ("not-configured", 409)):
        assert (
            client.post(f"/api/hosts/{target}/compose-discovery", json={}, headers=AUTH).status_code
            == expected
        )
    assert client.post("/api/hosts/fixture/compose-discovery", json={}).status_code == 401
    assert calls == []


def test_discovery_and_preview_use_registered_scope_and_fresh_result_without_writing(
    application, tmp_path
):
    client, _, _, calls = application
    before = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "controller").glob("*.sqlite3*")
        if path.is_file()
    }
    response = client.post("/api/hosts/fixture/compose-discovery", json={}, headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    candidate = body["candidates"][0]
    selection = {
        "candidate_id": candidate["candidate_id"],
        "snapshot_digest": body["snapshot_digest"],
        "host_port": 8081,
    }
    preview = client.post(
        "/api/hosts/fixture/compose-discovery/preview", json=selection, headers=AUTH
    )
    assert preview.status_code == 200
    assert 'container_name = "demo-api-1"' in preview.json()["inventory_fragment"]
    assert preview.json()["actions_enabled"] is False
    assert preview.json()["nginx_dependency"] == "unverified"
    assert calls == [("fixture", "demo"), ("fixture", "demo")]
    assert before == {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (tmp_path / "controller").glob("*.sqlite3*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "extra",
    [
        {"project": "unrelated"},
        {"address": "192.0.2.99"},
        {"command": "id"},
        {"current": {"Env": SECRET}},
    ],
)
def test_api_never_accepts_client_targets_parameters_or_cached_current(application, extra):
    client, _, _, calls = application
    response = client.post("/api/hosts/fixture/compose-discovery", json=extra, headers=AUTH)
    assert response.status_code == 422 and SECRET not in response.text
    assert calls == []


def test_stale_preview_and_unobserved_ports_are_rejected_and_lock_is_released(
    application, monkeypatch
):
    client, main, registered, calls = application
    current = project(registered, [row()])
    selection = {
        "candidate_id": current.candidates[0].candidate_id,
        "snapshot_digest": current.snapshot_digest,
        "host_port": 8081,
    }
    monkeypatch.setattr(
        main,
        "run_compose_discovery",
        lambda *_: project(registered, [row(ports="127.0.0.1:8082->8000/tcp")]),
    )
    assert (
        client.post(
            "/api/hosts/fixture/compose-discovery/preview", json=selection, headers=AUTH
        ).status_code
        == 409
    )
    monkeypatch.setattr(main, "run_compose_discovery", lambda *_: current)
    selection["host_port"] = 9000
    assert (
        client.post(
            "/api/hosts/fixture/compose-discovery/preview", json=selection, headers=AUTH
        ).status_code
        == 409
    )
    selection["host_port"] = 8081
    assert (
        client.post(
            "/api/hosts/fixture/compose-discovery/preview", json=selection, headers=AUTH
        ).status_code
        == 200
    )
    assert calls == []


def test_backend_failure_never_echoes_exception_and_releases_collection_slot(
    application, monkeypatch
):
    client, main, registered, _ = application

    def fail(*_):
        raise ValueError(SECRET)

    monkeypatch.setattr(main, "run_compose_discovery", fail)
    response = client.post("/api/hosts/fixture/compose-discovery", json={}, headers=AUTH)
    assert response.status_code == 503 and SECRET not in response.text
    monkeypatch.setattr(main, "run_compose_discovery", lambda *_: project(registered, [row()]))
    assert (
        client.post("/api/hosts/fixture/compose-discovery", json={}, headers=AUTH).status_code
        == 200
    )


@pytest.mark.parametrize("scope", ["Demo", "demo;id", "../demo", "demo*", "", True, ["demo"]])
def test_inventory_rejects_ambiguous_or_arbitrary_discovery_scope(tmp_path, scope):
    inventory = _inventory(tmp_path, "demo")
    inventory.write_text(
        inventory.read_text().replace(
            'compose_project = "demo"', "compose_project = " + json.dumps(scope)
        )
    )
    with pytest.raises(ValueError, match="Compose"):
        load_hosts(Settings(data_dir=tmp_path, token=TOKEN, inventory_path=inventory))


def _inventory(tmp_path, scope):
    (tmp_path / "key").write_text("synthetic-unused-reference")
    (tmp_path / "pin").write_text("synthetic-public-pin")
    path = tmp_path / "inventory.toml"
    path.write_text(
        '[credentials.readonly]\nkey_file="key"\nknown_hosts_file="pin"\n'
        '[[hosts]]\nid="fixture"\naddress="192.0.2.10"\nsite_domain="example.test"\n'
        'credential="readonly"\ncompose_project = ' + json.dumps(scope) + "\n"
    )
    return path


def test_policy_export_grants_only_deployment_project_without_reading_private_key(
    tmp_path, monkeypatch
):
    inventory = _inventory(tmp_path, "demo")
    original = Path.open

    def checked(path, *args, **kwargs):
        assert path != tmp_path / "key", "Private key body must not be opened for policy export"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked)
    target = load_hosts(Settings(data_dir=tmp_path, token=TOKEN, inventory_path=inventory))[
        "fixture"
    ]
    assert target.compose_project == "demo" and "compose_project" not in target.public.model_dump()
    spec = importlib.util.spec_from_file_location(
        "compose_exporter", Path(__file__).parents[1] / "deploy/readonly/export_policy.py"
    )
    assert spec is not None and spec.loader is not None
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    output = tmp_path / "policy.json"
    exporter.export_policy(inventory, "fixture", output)
    commands = json.loads(output.read_text())["commands"]
    command = commands_for_compose_discovery(target, "demo")["compose_inventory"]
    assert commands["LC_ALL=C " + command] == shlex.split(command)
    foreign = commands_for_compose_discovery(target, "unrelated")["compose_inventory"]
    assert "LC_ALL=C " + foreign not in commands
    assert "synthetic-unused-reference" not in output.read_text()
    assert "Env" not in command and "Command" not in command and "Mounts" not in command


def test_onboarding_project_is_optional_explicit_and_does_not_connect(application, monkeypatch):
    import tomllib

    client, _, _, calls = application
    message = paramiko.Message()
    message.add_string("ssh-ed25519")
    message.add_string(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    public = paramiko.Ed25519Key(data=message.asbytes())
    body = {
        "host_id": "new",
        "name": "new",
        "address": "192.0.2.12",
        "site_domain": "example.test",
        "container_name": "unknown-container",
        "host_key": f"ssh-ed25519 {public.get_base64()}",
        "expected_fingerprint": public.fingerprint,
    }
    monkeypatch.setattr(paramiko, "SSHClient", lambda: pytest.fail("Enrollment must not connect"))
    old = client.post("/api/host-onboarding/prepare", json=body, headers=AUTH)
    assert old.status_code == 200
    assert "compose_project" not in tomllib.loads(old.json()["inventory"])["hosts"][0]
    scoped = client.post(
        "/api/host-onboarding/prepare", json=body | {"compose_project": "demo"}, headers=AUTH
    )
    assert scoped.status_code == 200
    assert tomllib.loads(scoped.json()["inventory"])["hosts"][0]["compose_project"] == "demo"
    refused = client.post(
        "/api/host-onboarding/prepare", json=body | {"compose_project": "demo*"}, headers=AUTH
    )
    assert refused.status_code == 422 and calls == []
    pending_body = {key: value for key, value in body.items() if key != "container_name"}
    pending = client.post(
        "/api/host-onboarding/prepare",
        json=pending_body | {"compose_project": "demo"},
        headers=AUTH,
    )
    assert pending.status_code == 200
    pending_record = tomllib.loads(pending.json()["inventory"])["hosts"][0]
    assert pending_record["container_binding_confirmed"] is False
    assert "container_name" not in pending_record
    assert (
        client.post("/api/host-onboarding/prepare", json=pending_body, headers=AUTH).status_code
        == 422
    )


def test_pending_container_can_be_discovered_but_only_preview_confirms_registration(application):
    client, _, _, calls = application
    response = client.post("/api/hosts/pending/compose-discovery", json={}, headers=AUTH)
    assert response.status_code == 200
    result = response.json()
    preview = client.post(
        "/api/hosts/pending/compose-discovery/preview",
        json={
            "candidate_id": result["candidates"][0]["candidate_id"],
            "snapshot_digest": result["snapshot_digest"],
            "host_port": 8081,
        },
        headers=AUTH,
    )
    assert preview.status_code == 200
    assert "container_binding_confirmed = true\n" in preview.json()["inventory_fragment"]
    pending = next(
        item for item in client.get("/api/hosts", headers=AUTH).json() if item["id"] == "pending"
    )
    assert pending["container_binding_confirmed"] is False
    assert calls == [("pending", "demo"), ("pending", "demo")]
