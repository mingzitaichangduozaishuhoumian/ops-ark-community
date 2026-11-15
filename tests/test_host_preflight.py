from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_ssh_transport import TOOL_OUTPUT, ssh_target

from opsark import collector, host_preflight
from opsark.config import HostConfig
from opsark.models import CheckResult, Collection, HealthCheck, HostPublic

CHECK_IDS = (
    "os_release",
    "platform_tools",
    "nginx_status",
    "container_state",
    "disk_bytes",
    "disk_inodes",
    "compose_version",
    "docker_rootful",
)
PRIVATE_MARKER = "do-not-return-preflight-fixture"


def commands_for_expected_probes(host):
    probes = collector.commands_for_preflight(host)
    return ["LC_ALL=C " + probes[check] for check in CHECK_IDS]


def check_statuses(result):
    assert tuple(check.id for check in result.checks) == CHECK_IDS
    return {check.id: check.status for check in result.checks}


def test_preflight_uses_only_existing_vetted_commands_over_local_ssh(tmp_path):
    with ssh_target(tmp_path) as (target, commands):
        public = target.public.model_copy(
            update={
                "nginx_config_path": "/etc/nginx/conf.d/registered.conf",
                "health_checks": [
                    HealthCheck(
                        id="registered", domain="shop.example.com", read_only_confirmed=True
                    )
                ],
            }
        )
        target = replace(target, public=public)
        result = host_preflight.run_host_preflight(target)

    assert result.connection == "ok"
    assert result.platform == "compatible"
    assert commands == commands_for_expected_probes(target)
    check_statuses(result)


def test_ready_preflight_returns_only_bounded_classified_metadata(monkeypatch, tmp_path):
    target = HostConfig(
        HostPublic(
            id="registered", name="private-fixture-name", address="192.0.2.41", source="ssh"
        ),
        tmp_path / "preflight-private-key-path",
        tmp_path / "preflight-known-hosts-path",
    )
    checks = [
        CheckResult(
            name="os_release", stdout=f'ID=ubuntu\nVERSION_ID="24.04"\n# {PRIVATE_MARKER}\n'
        ),
        CheckResult(name="platform_tools", stdout=TOOL_OUTPUT),
        CheckResult(name="nginx_status", stdout="active\n"),
        CheckResult(name="container_state", stdout='{"Name":"/api","State":{"Status":"running"}}'),
        CheckResult(
            name="disk_bytes",
            stdout="Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/private-device 100000 12000 88000 12% /\n",
        ),
        CheckResult(
            name="disk_inodes",
            stdout="Filesystem Inodes IUsed IFree IUse% Mounted on\n"
            "/dev/private-device 10000 1100 8900 11% /\n",
        ),
        CheckResult(name="compose_version", stdout="2.40.3+ds1-0ubuntu1~24.04.1\n"),
        CheckResult(
            name="docker_rootful",
            stdout='{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}\n',
        ),
    ]
    started_at = datetime(2026, 11, 4, tzinfo=UTC)

    def collect(registered):
        assert registered is target
        return Collection(
            host_id=target.public.id,
            source="ssh",
            started_at=started_at,
            checks=checks,
            duration_ms=12,
        )

    monkeypatch.setattr(host_preflight, "collect_ssh_preflight", collect)
    result = host_preflight.run_host_preflight(target)

    assert result.host_id == "registered"
    assert result.status == "ready"
    assert result.connection == "ok"
    assert result.platform == "compatible"
    assert result.os_family == "ubuntu"
    assert result.architecture == "x86_64"
    assert result.missing_tools == []
    assert result.checked_at == started_at
    assert result.duration_ms == 12
    assert set(check_statuses(result).values()) == {"ok"}
    serialized = result.model_dump_json()
    for marker in (
        PRIVATE_MARKER,
        target.public.name,
        target.public.address,
        target.key_file.name,
        target.known_hosts_file.name,
        "/dev/private-device",
        '"stdout"',
        '"stderr"',
        "24.04",
        "2.40.3+ds1-0ubuntu1",
    ):
        assert marker not in serialized


@pytest.mark.parametrize(
    "trusted, username, statuses",
    [
        (False, "opsark-readonly", {"error"}),
        (True, "unregistered-ssh-role", {"error", "permission_denied"}),
    ],
)
def test_untrusted_key_and_failed_authentication_issue_no_commands(
    tmp_path, trusted, username, statuses
):
    with ssh_target(tmp_path, trusted=trusted) as (target, commands):
        target = replace(target, public=target.public.model_copy(update={"username": username}))
        result = host_preflight.run_host_preflight(target)
    assert result.status == "unreachable"
    assert result.connection in statuses
    assert result.platform == "unknown"
    assert commands == []


def local_only_host(tmp_path: Path) -> HostConfig:
    known = tmp_path / "preflight-known-hosts"
    known.write_text("", encoding="utf-8")
    return HostConfig(
        HostPublic(id="registered", name="Probe", address="127.0.0.1", source="ssh"),
        tmp_path / "unused-key",
        known,
    )


def test_changed_pin_is_rejected_before_connect(monkeypatch, tmp_path):
    target = local_only_host(tmp_path)
    public = target.public.model_copy(update={"trusted_hosts_digest": "0" * 64})

    def unexpected_connect(*_args, **_kwargs):
        pytest.fail("A changed host pin must be rejected before the connection")

    monkeypatch.setattr(collector.paramiko.SSHClient, "connect", unexpected_connect)
    result = host_preflight.run_host_preflight(replace(target, public=public))
    assert result.status == "unreachable"
    assert result.connection == "error"


@pytest.mark.parametrize(
    "failure, status",
    [(TimeoutError, "timeout"), (collector.paramiko.AuthenticationException, "permission_denied")],
)
def test_connection_failure_is_classified_without_exception_text(
    monkeypatch, tmp_path, failure, status
):
    def fail_connect(*_args, **_kwargs):
        raise failure(PRIVATE_MARKER)

    monkeypatch.setattr(collector.paramiko.SSHClient, "connect", fail_connect)
    result = host_preflight.run_host_preflight(local_only_host(tmp_path))
    assert result.status == "unreachable"
    assert result.connection == status
    assert PRIVATE_MARKER not in result.model_dump_json()


@pytest.mark.parametrize(
    "os_release, tool_output, command_count",
    [
        ('ID=fedora\nVERSION_ID="42"\n', TOOL_OUTPUT, 1),
        ('ID=ubuntu\nVERSION_ID="24.04"\n', TOOL_OUTPUT.replace("x86_64", "s390x"), 2),
    ],
)
def test_unsupported_targets_never_execute_service_checks(
    tmp_path, os_release, tool_output, command_count
):
    with ssh_target(tmp_path, os_release=os_release, tool_output=tool_output) as (target, commands):
        result = host_preflight.run_host_preflight(target)
    assert result.connection == "ok"
    assert result.status == result.platform == "unsupported"
    assert commands == commands_for_expected_probes(target)[:command_count]
    statuses = check_statuses(result)
    assert {statuses[name] for name in CHECK_IDS[2:]} == {"unavailable"}


def test_truncated_os_probe_cannot_select_an_adapter(tmp_path):
    output = 'ID=ubuntu\nVERSION_ID="24.04"\n# ' + PRIVATE_MARKER * (
        collector.MAX_OUTPUT_BYTES // len(PRIVATE_MARKER) + 1
    )
    with ssh_target(tmp_path, os_release=output) as (target, commands):
        result = host_preflight.run_host_preflight(target)
    assert result.connection == "ok"
    assert result.status == "needs_attention"
    assert result.platform == "unknown"
    assert commands == commands_for_expected_probes(target)[:1]
    assert check_statuses(result)["os_release"] != "ok"
    assert PRIVATE_MARKER not in result.model_dump_json()


def test_total_probe_budget_stops_before_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(collector, "COLLECTION_TIMEOUT", 0.0)
    with ssh_target(tmp_path) as (target, commands):
        result = host_preflight.run_host_preflight(target)
    assert result.connection == "ok"
    assert result.status == "needs_attention"
    assert result.platform == "unknown"
    assert check_statuses(result)["os_release"] == "timeout"
    assert commands == []


def test_missing_tool_skips_its_probes_without_claiming_readiness(tmp_path):
    tools = TOOL_OUTPUT.replace("OPSARK_TOOL_df=1", "OPSARK_TOOL_df=0")
    with ssh_target(tmp_path, tool_output=tools) as (target, commands):
        result = host_preflight.run_host_preflight(target)
    assert result.platform == "compatible"
    assert result.status == "needs_attention"
    assert result.missing_tools == ["df"]
    statuses = check_statuses(result)
    assert statuses["disk_bytes"] == statuses["disk_inodes"] == "unavailable"
    assert (
        commands
        == commands_for_expected_probes(target)[:4] + commands_for_expected_probes(target)[6:]
    )


@pytest.mark.parametrize(
    "version",
    ["v2.31.0\n", "2.40.3-desktop.1\n", "2.28.1+build.abc\n", "2.40.3+ds1-0ubuntu1~24.04.1\n"],
)
def test_compose_version_accepts_verified_major_two_without_pinning_a_release(version):
    assert host_preflight._capability(CheckResult(name="compose_version", stdout=version)) == (
        "ok",
        None,
    )


@pytest.mark.parametrize(
    "options", [[], ["name=seccomp,profile=builtin", "name=cgroupns", "no-new-privileges"]]
)
def test_rootful_engine_uses_classified_linux_security_metadata(options):
    import json

    check = CheckResult(
        name="docker_rootful", stdout=json.dumps({"OSType": "linux", "SecurityOptions": options})
    )
    assert host_preflight._capability(check) == ("ok", None)


@pytest.mark.parametrize(
    "version,reason",
    [
        ("1.29.2\n", "unsupported_version"),
        ("3.0.0\n", "unsupported_version"),
        ("3.0.0+ds1-0ubuntu1~24.04.1\n", "unsupported_version"),
        ("Docker Compose version v2.31.0\n", "invalid_output"),
        ("2.1\n", "invalid_output"),
        ("02.1.0\n", "invalid_output"),
        ("2.1.0-beta..invalid\n", "invalid_output"),
        ("2.40.3~24.04.1\n", "invalid_output"),
        ("2.40.3+~24.04.1\n", "invalid_output"),
        ("2.40.3+ds1-0ubuntu1~24.04\n", "invalid_output"),
        ("2.40.3+ds1-0ubuntu1~24.04.x\n", "invalid_output"),
        ("2.40.3+ds1-0ubuntu1~24.04.1~24.04.2\n", "invalid_output"),
        ("v2.31.0\n" + PRIVATE_MARKER, "invalid_output"),
        ("v2.1.0-" + "a" * 200, "invalid_output"),
    ],
)
def test_compose_version_refuses_other_major_or_unclassified_output(version, reason):
    assert host_preflight._capability(CheckResult(name="compose_version", stdout=version)) == (
        "error",
        reason,
    )


@pytest.mark.parametrize("name", ["compose_version", "docker_rootful"])
@pytest.mark.parametrize(
    "update,status,reason",
    [
        (
            {"status": "permission_denied", "stderr": PRIVATE_MARKER},
            "permission_denied",
            "permission_denied",
        ),
        ({"status": "timeout", "stderr": PRIVATE_MARKER}, "timeout", "timeout"),
        ({"status": "unavailable", "exit_code": None}, "unavailable", "probe_unavailable"),
        ({"truncated": True}, "error", "output_truncated"),
        ({"stderr": PRIVATE_MARKER}, "error", "invalid_output"),
    ],
)
def test_new_capability_probes_keep_failure_and_truncation_explicit(name, update, status, reason):
    valid = "2.31.0\n" if name == "compose_version" else '{"OSType":"linux","SecurityOptions":[]}'
    check = CheckResult(name=name, stdout=valid).model_copy(update=update)
    assert host_preflight._capability(check) == (status, reason)


@pytest.mark.parametrize(
    "raw,reason",
    [
        ('{"OSType":"linux","SecurityOptions":["name=rootless"]}', "rootless_unsupported"),
        ('{"OSType":"linux","SecurityOptions":["rootless"]}', "rootless_unsupported"),
        ('{"OSType":"windows","SecurityOptions":[]}', "engine_unsupported"),
        ('{"OSType":"linux","SecurityOptions":null}', "invalid_output"),
        ('{"OSType":"linux","SecurityOptions":[1]}', "invalid_output"),
        (
            '{"OSType":"linux","SecurityOptions":[],"Env":"' + PRIVATE_MARKER + '"}',
            "invalid_output",
        ),
        ('{"OSType":"linux","SecurityOptions":[],"SecurityOptions":[]}', "invalid_output"),
        ('{"OSType":"linux","SecurityOptions":NaN}', "invalid_output"),
    ],
)
def test_engine_probe_requires_complete_linux_mode_metadata(raw, reason):
    assert host_preflight._capability(CheckResult(name="docker_rootful", stdout=raw)) == (
        "error",
        reason,
    )


def test_compose_plugin_absence_is_a_fixed_gap_without_error_text():
    check = CheckResult(
        name="compose_version",
        status="error",
        exit_code=1,
        stderr="docker: 'compose' is not a docker command.\n",
    )
    assert host_preflight._capability(check) == ("error", "plugin_unavailable")


@pytest.mark.parametrize(
    "stderr",
    [
        PRIVATE_MARKER,
        "plugin failed: " + PRIVATE_MARKER,
        "docker: 'compose' is not a docker command.\n" + PRIVATE_MARKER,
    ],
)
def test_generic_compose_failure_does_not_claim_plugin_absence_or_echo_text(stderr):
    check = CheckResult(name="compose_version", status="error", exit_code=1, stderr=stderr)
    assert host_preflight._capability(check) == ("error", "probe_failed")


@pytest.mark.parametrize("name", ["compose_version", "docker_rootful"])
def test_old_or_incomplete_preflight_cannot_be_ready_without_new_capabilities(
    tmp_path, monkeypatch, name
):
    host = local_only_host(tmp_path)
    outputs = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": TOOL_OUTPUT,
        "nginx_status": "active\n",
        "container_state": '{"Name":"/api","State":{"Status":"running"}}',
        "disk_bytes": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
        "/dev/test 100000 12000 88000 12% /\n",
        "disk_inodes": "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
        "/dev/test 10000 1000 9000 10% /\n",
        "compose_version": "v2.31.0\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":[]}',
    }
    outputs.pop(name)
    monkeypatch.setattr(
        host_preflight,
        "collect_ssh_preflight",
        lambda _: Collection(
            host_id=host.public.id,
            source="ssh",
            started_at=datetime.now(UTC),
            checks=[CheckResult(name=key, stdout=value) for key, value in outputs.items()],
        ),
    )
    result = host_preflight.run_host_preflight(host)
    assert result.status == "needs_attention"
    failed = next(check for check in result.checks if check.id == name)
    assert failed.status == "unavailable" and failed.reason == "probe_unavailable"
    assert PRIVATE_MARKER not in result.model_dump_json()


@pytest.mark.parametrize("name", ["compose_version", "docker_rootful"])
def test_unchanged_restricted_guard_refusal_is_a_policy_gap(name):
    check = CheckResult(
        name=name,
        status="error",
        exit_code=126,
        stderr="OpsArk restricted collector refused this request.\n",
    )
    assert host_preflight._capability(check) == ("error", "policy_refused")
