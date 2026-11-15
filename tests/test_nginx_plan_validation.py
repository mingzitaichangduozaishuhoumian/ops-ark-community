"""Verify offline Nginx validation boundaries without contacting Docker or a server."""

import hashlib
import json
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from nginx_restore_lab import CANDIDATE as LAB_CANDIDATE
from test_nginx_config_plan import CREATED, inspect, prepare
from test_nginx_config_plan import plan_files as plan_files
from test_nginx_config_snapshot import CONTENT, snapshot_tool
from test_nginx_config_snapshot import tree as tree

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux directory and file trust rules"
)

IMAGE = "sha256:" + "a" * 64
CONTAINER_ID = "b" * 64
DIAGNOSTIC_CANARY = "PRIVATE-NGINX-SYNTAX-DIAGNOSTIC"


@pytest.fixture
def prepared_lab(plan_files):
    plan_files.candidate.write_bytes(LAB_CANDIDATE)
    prepare(plan_files, hashlib.sha256(LAB_CANDIDATE).hexdigest())
    return plan_files


def validate(files, now=CREATED):
    return snapshot_tool.validate_plan(files.output, IMAGE, policy=files.policy, now=now)


def test_validation_reports_syntax_without_approving_or_rewriting(prepared_lab, monkeypatch):
    files = prepared_lab
    expected = inspect(files)
    plan_before = {path.name: path.read_bytes() for path in files.output.iterdir()}
    backup_before = {path.name: path.read_bytes() for path in files.backup.iterdir()}
    calls = []

    def syntax(data, image):
        calls.append((data, image))
        return "passed"

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", syntax)
    assert validate(files) == {**expected, "syntax_status": "passed"}
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    assert inspect(files) == expected
    assert expected["approval_status"] == "not_approved"
    assert files.source.read_bytes() == CONTENT
    assert {path.name: path.read_bytes() for path in files.output.iterdir()} == plan_before
    assert {path.name: path.read_bytes() for path in files.backup.iterdir()} == backup_before


@pytest.mark.parametrize(
    ("cause", "expected"),
    [("drift", "drift"), ("expired", "expired"), ("lost_backup", "unavailable")],
)
def test_validation_refuses_stale_plan_before_launch(prepared_lab, monkeypatch, cause, expected):
    files = prepared_lab
    now = CREATED
    if cause == "drift":
        files.source.write_bytes(CONTENT + b"# changed by operator\n")
    elif cause == "expired":
        now += timedelta(minutes=10)
    else:
        (files.backup / "manifest.json").unlink()

    def unexpected(*_args):
        pytest.fail("stale plan reached the Docker runner")

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", unexpected)
    result = validate(files, now)
    assert result == inspect(files, now)
    assert result["plan_status"] == expected
    assert result["syntax_status"] == "not_checked"
    assert result["approval_status"] == "not_approved"


@pytest.mark.parametrize(
    ("cause", "expected"),
    [("drift", "drift"), ("expired", "expired"), ("candidate_tamper", "tampered")],
)
def test_validation_withholds_success_if_input_changes_during_launch(
    prepared_lab, monkeypatch, cause, expected
):
    files = prepared_lab
    current = CREATED
    calls = []

    def syntax(data, image):
        nonlocal current
        calls.append((data, image))
        if cause == "drift":
            files.source.write_bytes(CONTENT + b"# external edit during validation\n")
        elif cause == "expired":
            current += timedelta(minutes=10)
        else:
            (files.output / "candidate.conf").write_bytes(LAB_CANDIDATE + b"# altered\n")
        return "passed"

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", syntax)
    result = validate(files, lambda: current)
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    assert result == inspect(files, current)
    assert result["plan_status"] == expected
    assert result["syntax_status"] == "not_checked"
    assert result["approval_status"] == "not_approved"


def test_validation_does_not_run_unapproved_nginx_directives(plan_files, monkeypatch):
    files = plan_files
    unsafe = b"include /etc/nginx/" + DIAGNOSTIC_CANARY.encode() + b";\n" + LAB_CANDIDATE
    files.candidate.write_bytes(unsafe)
    ready = prepare(files, hashlib.sha256(unsafe).hexdigest())

    def unexpected(*_args, **_kwargs):
        pytest.fail("candidate outside the supported grammar reached a subprocess")

    monkeypatch.setattr(snapshot_tool.subprocess, "run", unexpected)
    result = validate(files)
    assert result == {**ready, "syntax_status": "unsupported"}
    assert DIAGNOSTIC_CANARY not in repr(result)


def option(arguments, name):
    for index, argument in enumerate(arguments):
        if argument.startswith(name + "="):
            return argument.removeprefix(name + "=")
        if argument == name:
            return arguments[index + 1]
    raise AssertionError(f"Docker command is missing required {name}")


class DockerFixture:
    def __init__(self, *, nginx_status=0, image_volumes=b"null", ownership=True, timeout=False):
        self.nginx_status = nginx_status
        self.image_volumes = image_volumes
        self.ownership = ownership
        self.timeout = timeout
        self.calls = []
        self.labels = []

    def run(self, arguments, **options):
        arguments = list(arguments)
        assert options.get("shell", False) is False
        assert options.get("timeout", 0) > 0
        assert arguments[:4] == [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
        ]
        directory = Path(arguments[4])
        assert directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert not {"DOCKER_CONTEXT", "DOCKER_HOST", "HTTP_PROXY"} & options["env"].keys()
        command = arguments[5:]
        assert "opsark-candidate" not in repr(command)
        self.calls.append(command)
        output = b""
        code = 0
        match command[0]:
            case "image":
                assert command[1] == "inspect" and command[-1] == IMAGE
                output = IMAGE.encode() + b"\n" + self.image_volumes + b"\n"
            case "create":
                self.labels.append(option(command, "--label"))
                output = CONTAINER_ID.encode() + b"\n"
            case "container":
                assert command[1] == "inspect"
                label = self.labels[0].split("=", 1)[1] if self.ownership else "wrong-owner"
                output = CONTAINER_ID.encode() + b"\n" + label.encode() + b"\n"
            case "start":
                assert command == ["start", "--attach", "--interactive", CONTAINER_ID]
                assert options["input"] == LAB_CANDIDATE
                assert options["stdout"] == options["stderr"] == subprocess.DEVNULL
                if self.timeout:
                    raise subprocess.TimeoutExpired(arguments, options["timeout"])
                code = self.nginx_status
                output = DIAGNOSTIC_CANARY.encode()
            case "rm":
                assert command == ["rm", "--force", CONTAINER_ID]
            case _:
                pytest.fail("unexpected Docker operation")
        return subprocess.CompletedProcess(arguments, code, output, DIAGNOSTIC_CANARY.encode())


@pytest.mark.parametrize(
    ("status", "expected"), [(0, "passed"), (10, "failed"), (125, "unavailable")]
)
def test_docker_validation_isolated_and_output_free(
    prepared_lab, monkeypatch, capsys, status, expected
):
    files = prepared_lab
    docker = DockerFixture(nginx_status=status)
    monkeypatch.setenv("DOCKER_HOST", "tcp://private-daemon.example.test:1234")
    monkeypatch.setenv("DOCKER_CONTEXT", "private-context")
    monkeypatch.setenv("HTTP_PROXY", "http://private-proxy.example.test:1234")
    monkeypatch.setattr(snapshot_tool.subprocess, "run", docker.run)
    result = validate(files)
    assert result == {**inspect(files), "syntax_status": expected}
    assert result["approval_status"] == "not_approved"
    assert [call[0] for call in docker.calls] == [
        "image",
        "create",
        "container",
        "start",
        "container",
        "rm",
    ]
    command = docker.calls[1]
    assert option(command, "--pull") == "never"
    assert option(command, "--network") == "none"
    assert option(command, "--ipc") == "none"
    assert option(command, "--cap-drop") == "ALL"
    assert option(command, "--security-opt") == "no-new-privileges:true"
    assert option(command, "--user") == "65534:65534"
    assert option(command, "--log-driver") == "none"
    assert option(command, "--memory") == option(command, "--memory-swap") == "64m"
    assert option(command, "--pids-limit") == "16"
    assert option(command, "--cpus") == "0.25"
    assert {"--read-only", "--no-healthcheck", IMAGE} <= set(command)
    assert docker.labels == [
        "io.opsark.nginx-validation="
        + option(command, "--name").removeprefix("opsark-nginx-validation-")
    ]
    for banned in ("--mount", "--volume", "-v", "--privileged", "--publish", "--cap-add"):
        assert not any(arg == banned or arg.startswith(banned + "=") for arg in command)
    stdout, stderr = capsys.readouterr()
    assert DIAGNOSTIC_CANARY not in json.dumps(result) + stdout + stderr
    assert "opsark-candidate" not in json.dumps(result) + stdout + stderr


def test_validation_rejects_unpinned_image_before_start(prepared_lab, monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("unpinned image reached a subprocess")

    monkeypatch.setattr(snapshot_tool.subprocess, "run", unexpected)
    with pytest.raises(snapshot_tool.SnapshotError):
        snapshot_tool.validate_plan(
            prepared_lab.output, "nginx:latest", policy=prepared_lab.policy, now=CREATED
        )


def test_docker_validation_uses_only_one_fixed_readonly_tls_bind(monkeypatch):
    docker = DockerFixture()
    monkeypatch.setattr(snapshot_tool.subprocess, "run", docker.run)
    path = Path("/root/opsark-fixture/tls")
    assert snapshot_tool._docker_syntax(LAB_CANDIDATE, IMAGE, tls_directory=path) == "passed"
    command = docker.calls[1]
    assert command.count("--mount") == 1
    assert option(command, "--mount") == (
        "type=bind,src=/root/opsark-fixture/tls,dst=/fixture-tls,readonly,bind-propagation=rprivate"
    )
    assert option(command, "--network") == "none"
    assert option(command, "--user") == "65534:65534"


@pytest.mark.parametrize("component", ["fixture,dst=/other", 'fixture"quoted', "fixture\nflag"])
def test_tls_bind_rejects_docker_csv_and_control_characters(monkeypatch, component):
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid bind source reached Docker")

    monkeypatch.setattr(snapshot_tool.subprocess, "run", unexpected)
    with pytest.raises(snapshot_tool.SnapshotError):
        snapshot_tool._docker_syntax(
            LAB_CANDIDATE, IMAGE, tls_directory=Path("/root") / component / "tls"
        )


def test_supported_negative_fixture_reaches_the_syntax_checker(plan_files, monkeypatch):
    broken = LAB_CANDIDATE.replace(b'"opsark-candidate";', b'"opsark-candidate"')
    assert broken != LAB_CANDIDATE
    plan_files.candidate.write_bytes(broken)
    ready = prepare(plan_files, hashlib.sha256(broken).hexdigest())

    def syntax(data, image):
        assert data == broken and image == IMAGE
        return "failed"

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", syntax)
    assert validate(plan_files) == {**ready, "syntax_status": "failed"}


@pytest.mark.parametrize("cause", ["image_volumes", "unverified_owner"])
def test_validation_will_not_start_untrusted_container(prepared_lab, monkeypatch, cause):
    docker = (
        DockerFixture(image_volumes=b'{"/container-private":{}}')
        if cause == "image_volumes"
        else DockerFixture(ownership=False)
    )
    monkeypatch.setattr(snapshot_tool.subprocess, "run", docker.run)
    assert validate(prepared_lab) == {**inspect(prepared_lab), "syntax_status": "unavailable"}
    operations = [call[0] for call in docker.calls]
    assert "start" not in operations and "rm" not in operations
    if cause == "image_volumes":
        assert operations == ["image"]


def test_validator_cleans_up_its_verified_container_after_timeout(prepared_lab, monkeypatch):
    docker = DockerFixture(timeout=True)
    monkeypatch.setattr(snapshot_tool.subprocess, "run", docker.run)
    assert validate(prepared_lab) == {**inspect(prepared_lab), "syntax_status": "unavailable"}
    assert docker.calls[-2][0:2] == ["container", "inspect"]
    assert docker.calls[-1] == ["rm", "--force", CONTAINER_ID]
