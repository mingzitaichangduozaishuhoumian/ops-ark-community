import copy
import json
import os
import runpy
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from deploy.readonly import compose_volume_metadata as helper
from opsark import compose_volume_metadata as metadata
from opsark.config import HostConfig, Settings, compose_volume_scope_sha256, load_hosts
from opsark.models import CheckResult, HostPublic

TOKEN = "synthetic-volume-controller-token-000000"
AUTH = {"Authorization": "Bearer " + TOKEN}
ROUTE = "/api/hosts/fixture/compose-volume-metadata"


def host(tmp_path):
    return HostConfig(
        public=HostPublic(
            id="fixture",
            name="fixture",
            address="192.0.2.40",
            source="ssh",
            username="opsark-readonly",
            trusted_hosts_digest="1" * 64,
        ),
        key_file=tmp_path / "synthetic-key-ref",
        known_hosts_file=tmp_path / "synthetic-hosts-ref",
        compose_project="demo",
        compose_volume_scope_digest=compose_volume_scope_sha256("demo"),
    )


def response(target):
    value = {
        "schema": "opsark-compose-volume-metadata/v1",
        "status": "observed",
        "reason": None,
        "scope_digest": target.compose_volume_scope_digest,
        "observed_containers": 2,
        "coverage": "compose_labeled_local_named_volumes",
        "mount_mode": "unknown",
        "actions_enabled": False,
        "model_calls": 0,
        "volumes": [
            {
                "volume_ref": "a" * 32,
                "sharing": "shared_across_services",
                "services": [
                    {"service_ref": "b" * 32, "container_count": 1},
                    {"service_ref": "c" * 32, "container_count": 1},
                ],
            }
        ],
    }
    return value | {"snapshot_digest": metadata._digest(value)}


def check(value):
    return CheckResult(name=metadata.CHECK, stdout=json.dumps(value))


@pytest.fixture
def app(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "inert"))
    monkeypatch.setenv("OPSARK_TOKEN", TOKEN)
    from opsark import main

    target = host(tmp_path)
    disabled = replace(
        target,
        public=target.public.model_copy(update={"id": "disabled"}),
        compose_volume_scope_digest=None,
    )
    monkeypatch.setattr(main, "load_hosts", lambda _: {"fixture": target, "disabled": disabled})
    monkeypatch.setattr(main, "list_samples", lambda: [])
    calls = []

    def collect(registered, commands, *, output_limit):
        assert registered is target and commands == {metadata.CHECK: metadata.COMMAND}
        assert output_limit == metadata.MAX_OUTPUT + 1
        calls.append(True)
        return {metadata.CHECK: check(response(registered))}

    monkeypatch.setattr(metadata, "collect_registered_receipts", collect)
    application = main.create_app(Settings(data_dir=tmp_path / "controller", token=TOKEN))
    with TestClient(application) as client:
        yield client, target, calls


def test_authenticated_opt_in_collection_and_public_opaque_binding(app):
    client, _, calls = app
    assert client.post(ROUTE, json={}).status_code == 401
    assert client.post(ROUTE, json={"project": "synthetic-other"}, headers=AUTH).status_code == 422
    assert (
        client.post(ROUTE.replace("fixture", "disabled"), json={}, headers=AUTH).status_code == 409
    )
    assert calls == []
    data = client.post(ROUTE, json={}, headers=AUTH).json()
    assert data["schema"] == "opsark-compose-volume-metadata/v1" and data["status"] == "observed"
    assert (
        data["mount_mode"] == "unknown"
        and data["volumes"][0]["sharing"] == "shared_across_services"
    )
    assert data["actions_enabled"] is False and data["model_calls"] == 0 and calls == [True]
    hosts = {row["id"]: row for row in client.get("/api/hosts", headers=AUTH).json()}
    assert data["binding_digest"] == hosts["fixture"]["compose_volume_binding_digest"]
    assert "compose_volume_binding_digest" not in hosts["disabled"]
    assert client.get("/compose-volumes.js").status_code == 200


@pytest.mark.parametrize(
    "change",
    [
        "scope",
        "digest",
        "secret",
        "duplicate",
        "sharing",
        "count",
        "across_volumes",
        "partial",
        "old_coverage",
    ],
)
def test_strict_projection_refuses_inconsistent_or_sensitive_evidence(tmp_path, change):
    target = host(tmp_path)
    settings = Settings(tmp_path / "synthetic", TOKEN)
    value = copy.deepcopy(response(target))
    if change == "scope":
        value["scope_digest"] = "b" * 64
    elif change == "secret":
        value["volumes"][0]["unexpected"] = TOKEN
    elif change == "duplicate":
        value["volumes"].append(value["volumes"][0])
    elif change == "sharing":
        value["volumes"][0]["sharing"] = "one_service"
    elif change == "count":
        value["volumes"][0]["services"][0]["container_count"] = 2
    elif change == "across_volumes":
        value["observed_containers"] = 3
        value["volumes"].append(
            {
                "volume_ref": "d" * 32,
                "sharing": "one_service",
                "services": [{"service_ref": "e" * 32, "container_count": 2}],
            }
        )
    elif change == "partial":
        value.update(status="unavailable", reason="evidence_changed", coverage="unavailable")
    elif change == "old_coverage":
        value["coverage"] = "compose_labeled_named_volumes"
    value["snapshot_digest"] = (
        "0" * 64
        if change == "digest"
        else metadata._digest(
            {key: item for key, item in value.items() if key != "snapshot_digest"}
        )
    )
    with pytest.raises(ValueError):
        metadata.parse_projection(check(value), target, settings)


def test_full_route_discards_malformed_transport_without_echo(app, monkeypatch):
    client, _, _ = app
    monkeypatch.setattr(
        metadata,
        "collect_registered_receipts",
        lambda *_args, **_kw: {
            metadata.CHECK: CheckResult(name=metadata.CHECK, stdout=TOKEN, status="timeout")
        },
    )
    rejected = client.post(ROUTE, json={}, headers=AUTH)
    assert rejected.status_code == 200 and TOKEN not in rejected.text
    result = rejected.json()
    assert result["status"] == "unavailable" and result["volumes"] == []
    assert result["binding_digest"] is result["scope_digest"] is result["snapshot_digest"] is None


def test_transport_cap_preserves_exact_protocol_limit(tmp_path):
    target = host(tmp_path)
    settings = Settings(tmp_path / "synthetic", TOKEN)
    result = check(response(target))
    result.stdout += " " * (metadata.MAX_OUTPUT - len(result.stdout))
    assert metadata.parse_projection(result, target, settings).status == "observed"
    result.stdout += " "
    with pytest.raises(ValueError):
        metadata.parse_projection(result, target, settings)


def test_actual_host_projection_passes_controller_and_hides_private_identifiers(tmp_path):
    target = host(tmp_path)
    project, volume = "demo", "synthetic-private-volume"
    names = ("synthetic-api-service", "synthetic-worker-service")
    inventory = b"".join(
        helper.canonical(
            {"id": digit * 64, "state": "running", "project": project, "service": service}
        )
        for digit, service in zip("de", names, strict=True)
    )
    raw_scope = helper.canonical({"schema_version": 1, "compose_project": project})
    assert helper.digest(raw_scope) == target.compose_volume_scope_digest
    commands = []

    def run(argv):
        commands.append(argv)
        if argv[3] == "info":
            return helper.canonical({"id": "fixture-engine", "os": "linux", "security": []})
        if argv[3] == "volume":
            return helper.canonical(
                {
                    "name": volume,
                    "driver": "local",
                    "scope": "local",
                    "project": project,
                    "volume": "fixture-volume-label",
                }
            )
        return inventory

    result = helper.collect(raw_scope, run)
    raw = helper.canonical(result)
    assert all(value.encode() not in raw for value in (volume, *names, "d" * 64, "e" * 64))
    projected = metadata.parse_projection(check(result), target, Settings(tmp_path / "data", TOKEN))
    assert projected.status == "observed" and len(projected.volumes[0].services) == 2
    assert len(commands) == 8 and sum(f"volume={volume}" in command for command in commands) == 2


def test_scope_configuration_binds_exact_project_and_export_is_opt_in(tmp_path):
    (tmp_path / "local-key-ref").write_text("synthetic-reference", encoding="ascii")
    (tmp_path / "local-host-ref").write_text("synthetic-public-pin", encoding="ascii")
    inventory = tmp_path / "inventory.toml"
    base = """[credentials.fixture]
key_file = "local-key-ref"
known_hosts_file = "local-host-ref"

[[hosts]]
id = "fixture"
address = "192.0.2.40"
site_domain = "fixture.invalid"
container_name = "fixture"
username = "opsark-readonly"
compose_project = "demo"
credential = "fixture"
"""
    exporter = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "deploy/readonly/export_policy.py")
    )
    export = exporter["export_policy"]
    inventory.write_text(base, encoding="ascii")
    old = tmp_path / "old-policy.json"
    export(inventory, "fixture", old)
    command = "LC_ALL=C " + metadata.COMMAND
    assert command not in json.loads(old.read_text(encoding="ascii"))["commands"]
    scoped = base + f'compose_volume_scope_digest = "{compose_volume_scope_sha256("demo")}"\n'
    inventory.write_text(scoped, encoding="ascii")
    new = tmp_path / "new-policy.json"
    export(inventory, "fixture", new)
    assert (
        json.loads(new.read_text(encoding="ascii"))["commands"][command] == metadata.COMMAND.split()
    )
    inventory.write_text(
        scoped.replace('compose_project = "demo"', 'compose_project = "different"'),
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="Compose"):
        load_hosts(Settings(tmp_path / "data", TOKEN, inventory_path=inventory))
