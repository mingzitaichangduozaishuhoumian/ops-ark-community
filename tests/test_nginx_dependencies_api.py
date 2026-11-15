"""Authenticated synthetic API acceptance; no deployment files or SSH access."""

import json
import os
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_nginx_dependencies import host, joined, projection

from opsark import nginx_dependencies as discovery
from opsark.collector import nginx_dependencies_command
from opsark.compose_discovery import commands_for_compose_discovery
from opsark.config import Settings
from opsark.models import CheckResult
from opsark.platforms import TOOLS

TOKEN = "synthetic-nginx-dependency-api-0000000000"
AUTH = {"Authorization": "Bearer " + TOKEN}


@pytest.fixture
def application(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "inert-default"))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    from opsark import main

    target = host(tmp_path)
    monkeypatch.setattr(
        main,
        "load_hosts",
        lambda _: {
            "fixture": target,
            "disabled": replace(
                target,
                public=target.public.model_copy(update={"id": "disabled"}),
                nginx_scope_digest=None,
            ),
        },
    )
    monkeypatch.setattr(main, "list_samples", lambda: [])
    calls = []

    def collect(target, _settings):
        calls.append(target.public.id)
        return joined(tmp_path)

    monkeypatch.setattr(main, "run_nginx_dependencies", collect)
    app = main.create_app(Settings(data_dir=tmp_path / "fake-controller", token=TOKEN))
    with TestClient(app) as client:
        yield client, main, calls


def test_api_uses_only_registered_scope_and_never_calls_a_model(application):
    client, _, calls = application
    result = client.post("/api/hosts/fixture/nginx-dependencies", json={}, headers=AUTH)
    assert result.status_code == 200 and result.json()["actions_enabled"] is False
    assert result.json()["loaded_generation"] == "unknown" and result.json()["model_calls"] == 0
    assert result.json()["relationships"][0]["binding"] == "unique"
    assert calls == ["fixture"]
    listing = client.get("/api/hosts", headers=AUTH).json()
    assert listing[0]["nginx_dependencies_configured"] is True
    assert listing[0]["nginx_dependency_scope_digest"] == result.json()["scope_digest"]
    assert listing[0]["nginx_dependency_binding_digest"] == result.json()["binding_digest"]
    assert client.get("/nginx-dependencies.js").status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"path": "/etc/passwd"},
        {"scope": "other"},
        {"project": "other"},
        {"command": "id"},
        {"current": {"unknown": True}},
    ],
)
def test_api_rejects_all_client_parameters_without_collection(application, body):
    client, _, calls = application
    result = client.post("/api/hosts/fixture/nginx-dependencies", json=body, headers=AUTH)
    assert result.status_code == 422 and calls == []


def test_missing_disabled_and_unauthenticated_targets_make_no_call(application):
    client, _, calls = application
    assert client.post("/api/hosts/fixture/nginx-dependencies", json={}).status_code == 401
    assert (
        client.post("/api/hosts/missing/nginx-dependencies", json={}, headers=AUTH).status_code
        == 404
    )
    assert (
        client.post("/api/hosts/disabled/nginx-dependencies", json={}, headers=AUTH).status_code
        == 409
    )
    assert calls == []


def test_host_lock_rejects_overlap_and_releases_after_failure(application, monkeypatch):
    client, main, calls = application

    def first(*_):
        nested = client.post("/api/hosts/fixture/nginx-dependencies", json={}, headers=AUTH)
        assert nested.status_code == 409
        raise ValueError("synthetic failure must not be in API output")

    monkeypatch.setattr(main, "run_nginx_dependencies", first)
    failed = client.post("/api/hosts/fixture/nginx-dependencies", json={}, headers=AUTH)
    assert failed.status_code == 503 and "synthetic failure" not in failed.text
    monkeypatch.setattr(main, "run_nginx_dependencies", lambda *_: joined_response())
    # A second controlled failure reaches collection, proving the lock released.
    second = client.post("/api/hosts/fixture/nginx-dependencies", json={}, headers=AUTH)
    assert second.status_code == 503 and calls == []


def joined_response():
    raise ValueError("controlled second call")


@pytest.mark.parametrize(
    ("fault", "reason"),
    [("compose_drift", "evidence_changed"), ("helper_timeout", "collection_unavailable")],
)
def test_route_discards_incomplete_observation_and_releases_lock(
    application, tmp_path, monkeypatch, fault, reason
):
    client, main, _ = application
    target = host(tmp_path)
    commands = commands_for_compose_discovery(target, target.compose_project)
    helper = nginx_dependencies_command(target)
    candidate = {
        "id": "a" * 64,
        "name": "demo-api-1",
        "state": "running",
        "project": "demo",
        "service": "api",
        "ports": "127.0.0.1:8081->8000/tcp",
    }
    replies = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": "OPSARK_ARCH=x86_64\n"
        + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS),
        "compose_version": "2.40.1\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}',
    }
    sessions = []
    canary = "SYNTHETIC_UNCLASSIFIED_PARTIAL_OUTPUT"
    projected = projection()

    class Session:
        def __init__(self):
            self.commands = []
            self.closed = False
            self.fault = fault if not sessions else None
            sessions.append(self)

        def close(self):
            self.closed = True

    def connect(session, registered):
        assert session is sessions[-1] and registered == target

    def check(session, name, command, budget, *, require_eof):
        assert session is sessions[-1] and not session.closed and require_eof and budget > 0
        session.commands.append(name)
        if name == "nginx_dependencies":
            assert command == helper
            if session.fault == "helper_timeout":
                return CheckResult(name=name, status="timeout", exit_code=None, stdout=canary)
            return CheckResult(name=name, stdout=json.dumps(projected))
        assert command == commands[name]
        if name != "compose_inventory":
            return CheckResult(name=name, stdout=replies[name])
        if session.fault == "compose_drift" and session.commands.count(name) == 2:
            return CheckResult(name=name, stdout=json.dumps(candidate | {"id": "b" * 64}))
        return CheckResult(name=name, stdout=json.dumps(candidate))

    monkeypatch.setattr(main, "run_nginx_dependencies", discovery.run_nginx_dependencies)
    monkeypatch.setattr(discovery.paramiko, "SSHClient", Session)
    monkeypatch.setattr(discovery, "_connect_registered", connect)
    monkeypatch.setattr(discovery, "run_check", check)
    endpoint = "/api/hosts/fixture/nginx-dependencies"

    response = client.post(endpoint, json={}, headers=AUTH)
    assert response.status_code == 200 and canary not in response.text
    refused = response.json()
    assert (refused["status"], refused["reason"], refused["disk_configuration"]) == (
        "unavailable",
        reason,
        "unavailable",
    )
    assert refused["scope_digest"] is refused["binding_digest"] is None
    assert refused["snapshot_digest"] is refused["compose_snapshot_digest"] is None
    assert refused["files"] == refused["relationships"] == refused["shared_dependencies"] == []
    assert refused["loaded_generation"] == "unknown"
    assert refused["actions_enabled"] is False and refused["model_calls"] == 0
    expected = [*commands, "nginx_dependencies"]
    assert sessions[0].commands == (
        expected + ["compose_inventory"] if fault == "compose_drift" else expected
    )

    stable = client.post(endpoint, json={}, headers=AUTH)
    assert stable.status_code == 200
    observed = stable.json()
    assert observed["status"] == "observed" and observed["disk_configuration"] == "observed"
    assert observed["loaded_generation"] == "unknown"
    assert observed["actions_enabled"] is False and observed["model_calls"] == 0
    assert observed["relationships"][0]["binding"] == "unique"
    assert len(sessions) == 2 and all(session.closed for session in sessions)
    assert sessions[1].commands == expected + ["compose_inventory"]
