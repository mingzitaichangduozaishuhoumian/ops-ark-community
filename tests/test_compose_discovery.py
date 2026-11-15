import contextlib
import json
import shlex
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from test_ssh_transport import TOOL_OUTPUT, SyntheticSSHServer, ssh_target

from opsark import collector, host_preflight
from opsark import compose_discovery as discovery
from opsark.config import HostConfig
from opsark.models import CheckResult, Collection, HostPublic

NOW = datetime(2026, 11, 6, tzinfo=UTC)
SECRET = "synthetic-do-not-export-discovery"


def host(tmp_path):
    return HostConfig(
        public=HostPublic(id="fixture", name="fixture", address="192.0.2.10", source="ssh"),
        key_file=tmp_path / "synthetic-key-reference",
        known_hosts_file=tmp_path / "synthetic-pin-reference",
    )


def row(**updates):
    return {
        "id": "a" * 64,
        "name": "demo-api-1",
        "state": "running",
        "project": "demo",
        "service": "api",
        "ports": "127.0.0.1:8081->8000/tcp, [::1]:8081->8000/tcp, 9000/tcp",
    } | updates


def project(target, rows, **updates):
    check = CheckResult(
        name="compose_inventory", stdout="\n".join(json.dumps(item) for item in rows)
    ).model_copy(update=updates)
    return discovery.project_compose_discovery(
        target,
        "demo",
        check,
        collected_at=NOW,
        duration_ms=5,
    )


def test_discovery_records_candidates_without_claiming_dependency_or_business_health(tmp_path):
    result = project(host(tmp_path), [row()])
    assert result.status == "candidates" and len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.container_name == "demo-api-1" and candidate.service_name == "api"
    assert len(candidate.published_ports) == 2
    assert {port.host_ip for port in candidate.published_ports} == {"127.0.0.1", "::1"}
    assert all(
        port.host_port == 8081 and port.container_port == 8000 for port in candidate.published_ports
    )
    assert result.nginx_dependency == "unverified" and result.actions_enabled is False
    assert "9000" not in result.model_dump_json()
    assert result.snapshot_digest and candidate.registration_supported


def test_order_and_collection_time_do_not_change_snapshot_but_identity_or_ports_do(tmp_path):
    target = host(tmp_path)
    rows = [row(), row(id="b" * 64, name="demo-api-2")]
    original = project(target, rows)
    changed_time = discovery.project_compose_discovery(
        target,
        "demo",
        CheckResult(
            name="compose_inventory", stdout="\n".join(json.dumps(item) for item in reversed(rows))
        ),
        collected_at=NOW + timedelta(hours=1),
        duration_ms=10,
    )
    assert original.snapshot_digest == changed_time.snapshot_digest
    assert all(candidate.service_instances == 2 for candidate in original.candidates)
    assert (
        original.snapshot_digest
        != project(target, [row(ports="127.0.0.1:8082->8000/tcp")]).snapshot_digest
    )
    changed_target = replace(target, public=target.public.model_copy(update={"port": 2222}))
    assert original.snapshot_digest != project(changed_target, rows).snapshot_digest


@pytest.mark.parametrize(
    "project_name", ["", "Demo", "../demo", "demo;id", "demo\n--all", "-demo", "x" * 64]
)
def test_project_scope_rejects_arbitrary_parameters_before_creating_ssh_client(
    tmp_path, monkeypatch, project_name
):
    monkeypatch.setattr(discovery.paramiko, "SSHClient", lambda: pytest.fail("No client admission"))
    with pytest.raises(discovery.DiscoveryRefused, match="authorized Compose project is invalid"):
        discovery.run_compose_discovery(host(tmp_path), project_name)


def test_fixed_command_projects_only_selected_labels_state_and_ports(tmp_path):
    commands = discovery.commands_for_compose_discovery(host(tmp_path), "demo")
    argv = shlex.split(commands["compose_inventory"])
    assert argv[argv.index("--filter") + 1] == "label=com.docker.compose.project=demo"
    assert argv[argv.index("--format") + 1] == discovery.FORMAT
    assert argv[argv.index("--host") + 1] == "unix:///var/run/docker.sock"
    assert "container ls --all --no-trunc" in commands["compose_inventory"]
    for forbidden in (
        ".Env",
        ".Command",
        ".Mounts",
        ".Labels",
        ".Image",
        " compose config",
        " inspect ",
    ):
        assert forbidden not in commands["compose_inventory"]


@pytest.mark.parametrize(
    "change",
    [
        {"project": "unrelated"},
        {"service": ""},
        {"id": "short"},
        {"name": "../name"},
        {"state": "healthy"},
        {"ports": "localhost:8080->80/tcp"},
        {"ports": "[fe80::1%eth0]:8080->80/tcp"},
        {"ports": "127.0.0.1:1-128->1/tcp"},
        {"ports": "127.0.0.1:8080->80/tcp, 127.0.0.1:8080->80/tcp"},
        {"Env": SECRET},
        {"database_dump": "CREATE TABLE private_data(password text);"},
    ],
)
def test_unclassified_or_out_of_scope_row_refuses_entire_collection(tmp_path, change):
    result = project(host(tmp_path), [row(id="b" * 64, name="demo-valid-1"), row(**change)])
    assert result.status == "unavailable" and result.reason == "inventory_invalid"
    assert result.candidates == [] and result.snapshot_digest is None
    assert SECRET not in result.model_dump_json() and "CREATE TABLE" not in result.model_dump_json()


@pytest.mark.parametrize(
    "update,reason",
    [
        ({"truncated": True}, "inventory_truncated"),
        ({"status": "timeout", "exit_code": None, "stderr": SECRET}, "inventory_unavailable"),
        ({"stderr": SECRET}, "inventory_unavailable"),
        ({"name": "unknown"}, "inventory_unavailable"),
        ({"stdout": '{"id":1,"id":2}'}, "inventory_invalid"),
        ({"stdout": "\ufffd"}, "inventory_limit"),
    ],
)
def test_incomplete_or_failed_collection_never_becomes_an_empty_healthy_project(
    tmp_path, update, reason
):
    result = project(host(tmp_path), [row()], **update)
    assert result.status == "unavailable" and result.reason == reason
    assert result.snapshot_digest is None and not result.candidates
    assert SECRET not in result.model_dump_json()


def test_empty_complete_project_is_explicit_and_duplicate_identity_is_rejected(tmp_path):
    result = project(host(tmp_path), [])
    assert result.status == "empty" and result.reason == "no_label_candidates"
    assert result.snapshot_digest and result.nginx_dependency == "unverified"
    assert project(host(tmp_path), [row(), row()]).status == "unavailable"


def test_bounded_port_ranges_and_exposed_only_ports(tmp_path):
    result = project(host(tmp_path), [row(ports="0.0.0.0:8081-8083->80-82/tcp, 9000-9002/udp")])
    assert result.status == "candidates"
    assert [port.host_port for port in result.candidates[0].published_ports] == [8081, 8082, 8083]
    assert project(host(tmp_path), [row(ports="80/tcp")]).candidates[0].published_ports == []


def test_registration_preview_uses_current_observed_tcp_port_and_writes_nothing(tmp_path):
    import tomllib

    current = project(host(tmp_path), [row()])
    selection = discovery.ComposeSelection(
        candidate_id=current.candidates[0].candidate_id,
        snapshot_digest=current.snapshot_digest,
        host_port=8081,
    )
    before = list(tmp_path.iterdir())
    preview = discovery.preview_compose_registration(current, selection)
    assert tomllib.loads(preview.inventory_fragment) == {
        "compose_project": "demo",
        "container_name": "demo-api-1",
        "container_binding_confirmed": True,
        "expected_upstream_port": 8081,
    }
    assert preview.nginx_dependency == "unverified" and preview.actions_enabled is False
    assert list(tmp_path.iterdir()) == before
    changed = project(host(tmp_path), [row(ports="127.0.0.1:8082->8000/tcp")])
    with pytest.raises(discovery.DiscoveryRefused, match="no longer matches"):
        discovery.preview_compose_registration(changed, selection)
    with pytest.raises(discovery.DiscoveryRefused, match="TCP port"):
        discovery.preview_compose_registration(
            current, selection.model_copy(update={"host_port": 9000})
        )
    with pytest.raises(discovery.DiscoveryRefused, match="candidate"):
        discovery.preview_compose_registration(
            current, selection.model_copy(update={"candidate_id": "f" * 64})
        )


def test_udp_and_exposed_only_candidates_cannot_fill_an_unverified_upstream(tmp_path):
    current = project(host(tmp_path), [row(ports="127.0.0.1:9000->9000/udp, 80/tcp")])
    assert not current.candidates[0].registration_supported
    with pytest.raises(discovery.DiscoveryRefused, match="candidate"):
        discovery.preview_compose_registration(
            current,
            discovery.ComposeSelection(
                candidate_id=current.candidates[0].candidate_id,
                snapshot_digest=current.snapshot_digest,
                host_port=9000,
            ),
        )


def test_total_project_ports_and_serialized_response_are_bounded(tmp_path, monkeypatch):
    rows = [
        row(
            id=f"{index:064x}",
            name=f"demo-api-{index}",
            ports=f"127.0.0.1:{1000 + index * 128}-{1127 + index * 128}->1-128/tcp",
        )
        for index in range(3)
    ]
    assert project(host(tmp_path), rows).reason == "inventory_limit"
    result = project(host(tmp_path), [row()])
    assert len(result.model_dump_json().encode()) <= discovery.MAX_RESPONSE_BYTES
    monkeypatch.setattr(discovery, "MAX_RESPONSE_BYTES", 1)
    assert project(host(tmp_path), [row()]).reason == "inventory_limit"


def test_pending_binding_never_grants_or_queries_placeholder_container(tmp_path, monkeypatch):
    target = replace(host(tmp_path), compose_project="demo", container_binding_confirmed=False)
    for scenario in ("web_502", "container_restart"):
        commands = collector.commands_for(target, scenario)
        assert "container_state" not in commands and "container_logs" not in commands
        assert not any(" inspect " in item or " logs " in item for item in commands.values())
    assert "container_state" not in collector.commands_for_preflight(target)
    assert "compose_inventory" in discovery.commands_for_compose_discovery(target, "demo")
    monkeypatch.setattr(
        collector,
        "_collect",
        lambda *_: Collection(
            host_id=target.public.id,
            source="ssh",
            started_at=NOW,
            checks=[],
        ),
    )
    collection = collector.collect_ssh(target, "container_restart")
    assert {check.name for check in collection.checks} == {"container_state", "container_logs"}
    assert all(check.status == "unavailable" for check in collection.checks)
    ready_outputs = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": TOOL_OUTPUT,
        "nginx_status": "active\n",
        "disk_bytes": (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/test 100000 12000 88000 12% /\n"
        ),
        "disk_inodes": (
            "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/test 10000 1000 9000 10% /\n"
        ),
        "compose_version": "v2.31.0\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":[]}',
    }
    monkeypatch.setattr(
        host_preflight,
        "collect_ssh_preflight",
        lambda *_: Collection(
            host_id=target.public.id,
            source="ssh",
            started_at=NOW,
            checks=[
                CheckResult(name=name, stdout=output) for name, output in ready_outputs.items()
            ],
        ),
    )
    result = host_preflight.run_host_preflight(target)
    assert result.status == "needs_attention"
    missing = next(check for check in result.checks if check.id == "container_state")
    assert missing.reason == "registration_unconfirmed" and missing.status == "unavailable"


@pytest.mark.parametrize(
    "probe,output,reason,count",
    [
        ("os_release", "ID=unsupported\n", "platform_unavailable", 1),
        (
            "platform_tools",
            TOOL_OUTPUT.replace("OPSARK_TOOL_docker=1", "OPSARK_TOOL_docker=0"),
            "platform_unavailable",
            2,
        ),
        ("compose_version", "1.29.2\n", "compose_unavailable", 3),
        (
            "docker_rootful",
            '{"OSType":"linux","SecurityOptions":["name=rootless"]}',
            "engine_unavailable",
            4,
        ),
    ],
)
def test_unverified_capability_stops_before_enumeration(
    tmp_path, monkeypatch, probe, output, reason, count
):
    seen, closed = [], []
    monkeypatch.setattr(
        discovery.paramiko, "SSHClient", lambda: SimpleNamespace(close=lambda: closed.append(True))
    )
    monkeypatch.setattr(discovery, "_connect_registered", lambda *_: None)
    outputs = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": TOOL_OUTPUT,
        "compose_version": "v2.31.0\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":[]}',
    } | {probe: output}

    def run(_client, name, _command, budget):
        assert 0 < budget <= discovery.COMMAND_TIMEOUT
        seen.append(name)
        return CheckResult(name=name, stdout=outputs[name])

    monkeypatch.setattr(discovery, "run_check", run)
    result = discovery.run_compose_discovery(host(tmp_path), "demo")
    assert result.status == "unavailable" and result.reason == reason
    assert len(seen) == count and "compose_inventory" not in seen and closed == [True]


def test_actual_loopback_ssh_uses_fixed_metadata_only_and_requires_host_pin(tmp_path, monkeypatch):
    original = SyntheticSSHServer.check_channel_exec_request

    def respond(self, channel, command):
        extra = None
        if command.endswith(b" compose version --short"):
            extra = "v2.31.0\n"
        elif b"docker --host unix:///var/run/docker.sock info --format" in command:
            extra = '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}\n'
        elif b" container ls --all --no-trunc --filter " in command:
            extra = json.dumps(row()) + "\n"
        if extra is None:
            return original(self, channel, command)
        self.commands.append(command.decode())

        def send():
            with contextlib.suppress(OSError, EOFError):
                channel.sendall(extra.encode())
                channel.send_exit_status(0)
                channel.shutdown_write()

        threading.Thread(target=send, daemon=True).start()
        return True

    monkeypatch.setattr(SyntheticSSHServer, "check_channel_exec_request", respond)
    with ssh_target(tmp_path) as (target, commands):
        result = discovery.run_compose_discovery(target, "demo")
        assert result.status == "candidates"
        assert commands == [
            "LC_ALL=C " + command
            for command in discovery.commands_for_compose_discovery(target, "demo").values()
        ]
    refused_path = tmp_path / "refused"
    refused_path.mkdir()
    with ssh_target(refused_path, trusted=False) as (target, commands):
        result = discovery.run_compose_discovery(target, "demo")
        assert result.reason == "connection_failed" and commands == []
