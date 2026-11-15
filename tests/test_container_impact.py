"""Container restart advice uses only a stable, exact read-only observation."""

import json
from dataclasses import replace

import pytest
from test_nginx_dependencies import SITE, host, projection, server, settings

from opsark import nginx_dependencies as discovery
from opsark.collector import nginx_dependencies_command
from opsark.compose_discovery import commands_for_compose_discovery
from opsark.models import CheckResult
from opsark.platforms import TOOLS

TARGET = "a" * 64
CONTROL = "b" * 64
REPLACEMENT = "c" * 64
TARGET_NAME = "demo-api-1"
SITE_B = "/etc/nginx/sites-enabled/other.conf"
SITE_CONTROL = "/etc/nginx/sites-enabled/control.conf"


@pytest.fixture
def enrolled(tmp_path):
    target = host(tmp_path)
    return replace(
        target,
        container_binding_confirmed=True,
        public=target.public.model_copy(
            update={"container_name": TARGET_NAME, "trusted_hosts_digest": "f" * 64}
        ),
    )


@pytest.fixture
def local_reads(enrolled, monkeypatch):
    commands = commands_for_compose_discovery(enrolled, "demo")
    checks = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": "OPSARK_ARCH=x86_64\n"
        + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS),
        "compose_version": "2.40.1\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}',
    }
    state = {"calls": [], "snapshots": [], "disk": None}

    class Session:
        def close(self):
            state["calls"].append("close")

    def connect(_client, target):
        assert target == enrolled
        state["calls"].append("connect")

    def check(_client, name, command, budget, *, require_eof):
        assert require_eof and 0 < budget <= discovery.COMMAND_TIMEOUT
        state["calls"].append(name)
        if name == "nginx_dependencies":
            assert command == nginx_dependencies_command(enrolled)
            if state["disk"] == "timeout":
                return CheckResult(
                    name=name,
                    status="timeout",
                    exit_code=None,
                    stdout="synthetic private partial result",
                )
            return CheckResult(name=name, stdout=json.dumps(state["disk"]))
        assert command == commands[name]
        if name == "compose_inventory":
            return CheckResult(
                name=name, stdout="\n".join(map(json.dumps, state["snapshots"].pop(0)))
            )
        return CheckResult(name=name, stdout=checks[name])

    monkeypatch.setattr(discovery.paramiko, "SSHClient", Session)
    monkeypatch.setattr(discovery, "_connect_registered", connect)
    monkeypatch.setattr(discovery, "run_check", check)
    return state


def compose_row(cid, name, port, *, state="running"):
    return {
        "id": cid,
        "name": name,
        "state": state,
        "project": "demo",
        "service": "api" if name == TARGET_NAME else "control",
        "ports": f"127.0.0.1:{port}->8000/tcp",
    }


def disk_routes():
    return projection(
        **{
            SITE_B: server("shared.example.test"),
            SITE_CONTROL: server("control.example.test", upstream="http://127.0.0.1:8082"),
        }
    )


def test_restart_impact_lists_only_sites_bound_to_the_original_container(
    enrolled, local_reads, tmp_path
):
    rows = [compose_row(TARGET, TARGET_NAME, 8081), compose_row(CONTROL, "demo-control-1", 8082)]
    local_reads.update(snapshots=[rows, list(reversed(rows))], disk=disk_routes())
    value = discovery.run_container_restart_impact(enrolled, settings(tmp_path), TARGET)
    assert value.status == "observed" and value.reason is None and value.observed_at is not None
    assert value.loaded_generation == "unknown"
    assert [(site.domain, site.file, site.line) for site in value.sites] == [
        ("a.example.test", SITE, 1),
        ("shared.example.test", SITE_B, 1),
    ]
    assert set(value.model_dump()) == {
        "status",
        "reason",
        "observed_at",
        "loaded_generation",
        "sites",
    }
    encoded = value.model_dump_json()
    assert all(
        marker not in encoded for marker in (TARGET, TARGET_NAME, "8081", "control.example.test")
    )
    assert local_reads["calls"] == [
        "connect",
        *commands_for_compose_discovery(enrolled, "demo"),
        "nginx_dependencies",
        "compose_inventory",
        "close",
    ]


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("same_name_replacement", "container_not_observed"),
        ("different_name", "container_not_observed"),
        ("stopped", "container_not_observed"),
        ("mid_capture_replacement", "evidence_changed"),
        ("ambiguous", "ambiguous_binding"),
        ("helper_timeout", "collection_unavailable"),
    ],
)
def test_restart_impact_withholds_partial_results(enrolled, local_reads, tmp_path, fault, reason):
    row = compose_row(TARGET, TARGET_NAME, 8081)
    other = compose_row(CONTROL, "demo-control-1", 8082)
    old, new, disk = [row, other], [row, other], disk_routes()
    if fault == "same_name_replacement":
        old = new = [row | {"id": REPLACEMENT}, other]
    elif fault == "different_name":
        old = new = [row | {"name": "demo-different-1"}, other]
    elif fault == "stopped":
        old = new = [row | {"state": "exited"}, other]
    elif fault == "mid_capture_replacement":
        new = [row | {"id": REPLACEMENT}, other]
    elif fault == "ambiguous":
        old = new = [row, compose_row(CONTROL, "demo-control-1", 8081)]
    elif fault == "helper_timeout":
        disk = "timeout"
    local_reads.update(snapshots=[old, new], disk=disk)
    value = discovery.run_container_restart_impact(enrolled, settings(tmp_path), TARGET)
    assert value.model_dump() == {
        "status": "unavailable",
        "reason": reason,
        "observed_at": None,
        "loaded_generation": "unknown",
        "sites": [],
    }
    assert local_reads["calls"][-1] == "close"
    assert local_reads["calls"].count("compose_inventory") == (
        1 if fault == "helper_timeout" else 2
    )


def test_restart_impact_empty_observation_contains_no_supported_route(
    enrolled, local_reads, tmp_path
):
    rows = [compose_row(TARGET, TARGET_NAME, 18081)]
    local_reads.update(snapshots=[rows, rows], disk=disk_routes())
    value = discovery.run_container_restart_impact(enrolled, settings(tmp_path), TARGET)
    assert value.status == "observed" and value.observed_at is not None and value.sites == []
    assert value.loaded_generation == "unknown"


def test_restart_impact_refuses_unpinned_or_short_identity_without_transport(
    enrolled, local_reads, tmp_path
):
    unpinned = replace(
        enrolled, public=enrolled.public.model_copy(update={"trusted_hosts_digest": None})
    )
    for target, cid in ((enrolled, TARGET[:12]), (unpinned, TARGET)):
        result = discovery.run_container_restart_impact(target, settings(tmp_path), cid)
        assert result.status == "unavailable" and result.reason == "collection_unavailable"
    assert local_reads["calls"] == []
