"""Exercise the enrolled investigation and comparison through the authenticated API."""

import json
import os
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_compose_generation import CONTAINER, PROJECT, RECEIPT, SCOPE, SERVICE, check, make_host

from opsark import compose_generation as generation
from opsark.config import Settings
from opsark.models import CheckResult
from opsark.platforms import TOOLS
from opsark.replay import collect_replay

TOKEN = "synthetic-compose-generation-route-token"
AUTH = {"Authorization": "Bearer " + TOKEN}
REQUEST = {"source": "ssh", "scenario": "container_restart", "host_id": "test"}


@pytest.fixture
def app(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "inert"))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    from opsark import main

    host = make_host(tmp_path)
    disabled = replace(
        host,
        public=host.public.model_copy(update={"id": "disabled"}),
        compose_generation_scope_digest=None,
    )
    monkeypatch.setattr(main, "load_hosts", lambda _: {"test": host, "disabled": disabled})
    monkeypatch.setattr(main, "list_samples", lambda: [])
    receipt_queue = []
    calls = []
    states = []

    def collect(target, commands, *, output_limit):
        assert target is host and commands == {generation.CHECK: generation.COMMAND}
        assert output_limit == generation.MAX_OUTPUT + 1
        calls.append("generation")
        return {generation.CHECK: check(receipt_queue.pop(0))}

    def diagnose(target, scenario):
        assert target in (host, disabled) and scenario == "container_restart"
        calls.append("investigate")
        collection = collect_replay("container-healthy")[1]
        container = next(check for check in collection.checks if check.name == "container_state")
        value = json.loads(container.stdout)
        value["Name"] = "/" + (states.pop(0) if states else target.public.container_name)
        container.stdout = json.dumps(value)
        tools = "OPSARK_ARCH=x86_64\n" + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS)
        collection.checks.append(CheckResult(name="platform_tools", stdout=tools))
        return collection.model_copy(update={"host_id": target.public.id, "source": "ssh"})

    monkeypatch.setattr(main, "collect_ssh", diagnose)
    monkeypatch.setattr(generation, "collect_registered_receipts", collect)
    application = main.create_app(Settings(data_dir=tmp_path / "controller", token=TOKEN))
    with TestClient(application) as client:
        yield client, receipt_queue, calls, states


def investigate(client, request=REQUEST):
    response = client.post("/api/investigations", headers=AUTH, json=request)
    assert response.status_code == 200
    return response.json()


def base_report(client, queue):
    queue.extend([RECEIPT, RECEIPT])
    report = investigate(client)
    path = f"/api/reports/{report['id']}"
    response = client.post(
        path + "/baseline", headers=AUTH, json={"confirm_observation_only": True}
    )
    assert response.status_code == 200
    return path


def test_auth_changed_metadata_and_historical_baseline(app):
    client, queue, calls, _ = app
    assert client.post("/api/investigations", json=REQUEST).status_code == 401
    assert (
        client.post(
            "/api/investigations", headers=AUTH, json=REQUEST | {"service": "unapproved"}
        ).status_code
        == 422
    )
    assert calls == []
    path = base_report(client, queue)
    assert client.get(path + "/compose-generation", headers=AUTH).json()["status"] == "unavailable"
    new = RECEIPT | {"container": "67" * 32, "image": "78" * 32}
    queue.extend([new, new])
    report = investigate(client)
    path = f"/api/reports/{report['id']}"
    assert client.get(path + "/compose-generation").status_code == 401
    result = client.get(path + "/compose-generation", headers=AUTH)
    assert result.status_code == 200
    assert (
        result.json()
        == generation.GenerationComparison(
            status="observed",
            container="changed",
            image="changed",
            compose_configuration="unchanged",
        ).model_dump()
    )
    assert (
        client.post(
            path + "/baseline", headers=AUTH, json={"confirm_observation_only": True}
        ).status_code
        == 200
    )
    assert client.get(path + "/compose-generation", headers=AUTH).json() == result.json()
    exported = [json.dumps(report), result.text]
    for suffix in ("", "/export", "/handoff"):
        response = client.get(path + suffix, headers=AUTH)
        assert response.status_code == 200
        exported.append(response.text)
    for text in exported:
        assert all(
            value not in text
            for value in (SCOPE, RECEIPT["binding"], new["container"], new["image"])
        )
    assert calls == ["generation", "investigate", "generation"] * 2


def test_target_change_during_collection_and_unenrolled_scope(app):
    client, queue, calls, states = app
    base_report(client, queue)
    queue.extend([RECEIPT, RECEIPT | {"container": "89" * 32}])
    report = investigate(client)
    path = f"/api/reports/{report['id']}/compose-generation"
    assert client.get(path, headers=AUTH).json()["status"] == "unavailable"
    queue.append(RECEIPT | {"unexpected": "synthetic-secret-never-reflected"})
    report = investigate(client)
    path = f"/api/reports/{report['id']}/compose-generation"
    assert client.get(path, headers=AUTH).json()["status"] == "unavailable"
    states.append("wrong-container")
    queue.append(RECEIPT)
    report = investigate(client)
    path = f"/api/reports/{report['id']}/compose-generation"
    assert client.get(path, headers=AUTH).json()["status"] == "unavailable"
    investigate(client, REQUEST | {"host_id": "disabled"})
    assert calls == ["generation", "investigate", "generation"] * 2 + [
        "generation",
        "investigate",
        "generation",
        "investigate",
        "investigate",
    ]


def test_exact_policy_opt_in_does_not_read_key_contents(tmp_path):
    from deploy.readonly.export_policy import export_policy

    inventory = tmp_path / "hosts.toml"
    (tmp_path / "fake-key").write_text("fixture-key-contents", encoding="ascii")
    (tmp_path / "fake-known").write_text("fixture-known-host", encoding="ascii")
    base = (
        '[credentials.lab]\nkey_file="fake-key"\nknown_hosts_file="fake-known"\n\n'
        '[[hosts]]\nid="test"\naddress="192.0.2.10"\nsite_domain="example.test"\ncredential="lab"\n'
        f'compose_project="{PROJECT}"\ncontainer_name="{CONTAINER}"\n'
    )
    inventory.write_text(base, encoding="ascii")
    output = tmp_path / "policy.json"
    export_policy(inventory, "test", output)
    old = json.loads(output.read_bytes())["commands"]
    inventory.write_text(
        base + f'compose_generation_service="{SERVICE}"\n'
        f'compose_generation_scope_digest="{SCOPE}"\n',
        encoding="ascii",
    )
    export_policy(inventory, "test", output)
    raw = output.read_bytes()
    assert b"fixture-key-contents" not in raw and SERVICE.encode() not in raw
    assert json.loads(raw)["commands"] == old | {
        "LC_ALL=C " + generation.COMMAND: generation.COMMAND.split()
    }
    inventory.write_text(base + f'compose_generation_scope_digest="{SCOPE}"\n', encoding="ascii")
    with pytest.raises(ValueError):
        export_policy(inventory, "test", output)
