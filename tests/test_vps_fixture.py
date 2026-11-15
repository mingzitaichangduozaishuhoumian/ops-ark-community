"""Fixture ownership and process boundaries; no Docker daemon is contacted."""

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "opsark_vps_fixture", Path(__file__).resolve().parents[1] / "deploy/vps_lab/fixture.py"
)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def owned():
    return {
        "Id": "a" * 64,
        "Name": "/opsark-lab-api",
        "Labels": {"io.opsark.fixture": "v1", "io.opsark.fixture.id": "opsark-lab-api"},
        "State": {"Status": "running", "ExitCode": 0, "OOMKilled": False},
        "RestartCount": 0,
        "MemoryLimit": 67108864,
        "Image": "sha256:" + "b" * 64,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("Name", "/unrelated-api"),
        ("Id", "not-an-immutable-id"),
        ("Labels", {}),
        ("Labels", {"io.opsark.fixture": "v1"}),
        ("Labels", {"io.opsark.fixture": "v1", "io.opsark.fixture.id": "other"}),
    ],
)
def test_unowned_container_cannot_be_removed_or_replaced(monkeypatch, field, value):
    container = owned()
    container[field] = value
    monkeypatch.setattr(fixture, "inspect_container", lambda: container)
    calls = []
    monkeypatch.setattr(fixture, "docker", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(fixture.FixtureError, match="refusing_unowned_container"):
        fixture.replace_container()
    with pytest.raises(fixture.FixtureError, match="refusing_unowned_container"):
        fixture.remove_container(container)
    assert calls == []


def test_container_identity_is_rechecked_before_removal(monkeypatch):
    changed = {**owned(), "Id": "c" * 64}
    monkeypatch.setattr(fixture, "inspect_container", lambda: changed)
    calls = []
    monkeypatch.setattr(fixture, "docker", lambda *args: calls.append(args))
    with pytest.raises(fixture.FixtureError, match="changed_before_removal"):
        fixture.remove_container(owned())
    assert calls == []


def test_fixed_local_docker_and_clean_environment_ignore_user_overrides(monkeypatch):
    for variable in ("DOCKER_HOST", "DOCKER_TLS", "DOCKER_CERT_PATH", "HTTPS_PROXY"):
        monkeypatch.setenv(variable, "untrusted-fixture-override")
    captured = {}
    monkeypatch.setattr(fixture, "tool", lambda name: "/usr/bin/" + name)

    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        assert Path(argv[2]).is_dir()
        return subprocess.CompletedProcess(argv, 0, "linux\n", "")

    monkeypatch.setattr(fixture.subprocess, "run", run)
    fixture.require_linux_docker()
    assert captured["argv"][0:2] == ["/usr/bin/docker", "--config"]
    assert captured["argv"][3:] == [
        "--host",
        "unix:///var/run/docker.sock",
        "info",
        "--format",
        "{{.OSType}}",
    ]
    assert not Path(captured["argv"][2]).exists()
    assert captured["env"] == fixture.environment()
    assert "untrusted-fixture-override" not in str(captured)
    assert captured.get("shell", False) is False
    assert captured["timeout"] == 15


def test_only_missing_image_triggers_a_fixed_public_image_pull(monkeypatch):
    calls = []

    def docker(*args, **kwargs):
        calls.append((args, kwargs))
        return (
            subprocess.CompletedProcess([], 1, "", "No such image")
            if len(calls) == 1
            else subprocess.CompletedProcess([], 0, "", "")
        )

    monkeypatch.setattr(fixture, "docker", docker)
    fixture.ensure_image()
    assert calls[1] == (("pull", "python:3.13-slim"), {"timeout": 180})
    calls.clear()
    monkeypatch.setattr(
        fixture,
        "docker",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 1, "", "permission denied private-daemon-detail"
        ),
    )
    with pytest.raises(fixture.FixtureError, match="fixture_image_inspection_failed"):
        fixture.ensure_image()


def test_existing_image_is_not_pulled(monkeypatch):
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess([], 0, "sha256:fixed-image", "")

    monkeypatch.setattr(fixture, "docker", docker)
    fixture.ensure_image()
    assert len(calls) == 1
    assert calls[0][0:2] == ("image", "inspect")


@pytest.mark.parametrize("fail", [False, True])
def test_new_workload_has_fixed_loopback_and_resource_boundaries(monkeypatch, fail):
    monkeypatch.setattr(fixture, "inspect_container", lambda: None)
    monkeypatch.setattr(fixture, "port_available", lambda port: True)
    monkeypatch.setattr(fixture, "ensure_image", lambda: None)
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess([], 0, "d" * 64 + "\n", "")

    monkeypatch.setattr(fixture, "docker", docker)
    result = fixture.replace_container(fail=fail)
    assert result["mode"] == ("fail42" if fail else "healthy")
    assert len(calls) == 1
    argv = calls[0]
    for flag, value in (
        ("--name", "opsark-lab-api"),
        ("--publish", "127.0.0.1:18881:8081"),
        ("--network", "bridge"),
        ("--memory", "64m"),
        ("--cpus", "0.25"),
        ("--pids-limit", "32"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--user", "65534:65534"),
        ("--restart", "on-failure:2" if fail else "no"),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--read-only" in argv
    assert "io.opsark.fixture=v1" in argv
    assert "io.opsark.fixture.id=opsark-lab-api" in argv
    assert "--privileged" not in argv and "--volume" not in argv and "--mount" not in argv
    assert argv[-6:-4] == ("python:3.13-slim", "python")
    if fail:
        assert "time.sleep(11)" in argv[-1]
        assert "sys.exit(42)" in argv[-1]
        assert "file=sys.stderr" in argv[-1]


def test_initialization_refuses_occupied_ports_before_writing(monkeypatch):
    monkeypatch.setattr(fixture, "configuration_directory", lambda: None)
    monkeypatch.setattr(fixture, "safe_configuration", lambda: None)
    monkeypatch.setattr(fixture, "inspect_container", lambda: None)
    monkeypatch.setattr(fixture, "port_available", lambda port: False)
    calls = []
    monkeypatch.setattr(fixture, "write_new_configuration", lambda data: calls.append("write"))
    with pytest.raises(fixture.FixtureError, match="nginx_port_occupied"):
        fixture.initialize()
    assert calls == []


def test_init_syntax_failure_removes_only_new_configuration_without_reload(monkeypatch, tmp_path):
    conf = tmp_path / "opsark-vps-lab.conf"
    monkeypatch.setattr(fixture, "CONF", conf)
    monkeypatch.setattr(fixture, "configuration_directory", lambda: None)
    monkeypatch.setattr(
        fixture, "safe_configuration", lambda: conf.read_bytes() if conf.exists() else None
    )
    monkeypatch.setattr(fixture, "inspect_container", lambda: None)
    monkeypatch.setattr(fixture, "port_available", lambda port: True)
    calls = []

    def invalid():
        raise fixture.FixtureError("nginx_syntax_check_failed_no_reload")

    monkeypatch.setattr(fixture, "check_nginx", invalid)
    monkeypatch.setattr(fixture, "replace_container", lambda: calls.append("replace"))
    monkeypatch.setattr(fixture, "reload_nginx", lambda: calls.append("reload"))
    with pytest.raises(fixture.FixtureError, match="syntax_check_failed"):
        fixture.initialize()
    assert not conf.exists()
    assert calls == []


def test_cleanup_refuses_foreign_configuration_before_mutating_container(monkeypatch):
    monkeypatch.setattr(fixture, "inspect_container", owned)
    calls = []

    def foreign():
        raise fixture.FixtureError("refusing_unowned_nginx_configuration")

    monkeypatch.setattr(fixture, "safe_configuration", foreign)
    monkeypatch.setattr(fixture, "remove_container", lambda item: calls.append("remove"))
    with pytest.raises(fixture.FixtureError, match="unowned_nginx"):
        fixture.cleanup()
    assert calls == []


def test_cleanup_restores_fixture_file_when_syntax_fails(monkeypatch, tmp_path):
    conf = tmp_path / "opsark-vps-lab.conf"
    original = fixture.CONF_TEXT.encode()
    conf.write_bytes(original)
    monkeypatch.setattr(fixture, "CONF", conf)
    monkeypatch.setattr(fixture, "safe_configuration", lambda: original)
    monkeypatch.setattr(fixture, "configuration_directory", lambda: None)
    monkeypatch.setattr(fixture, "inspect_container", owned)
    calls = []

    def invalid():
        assert not conf.exists()
        raise fixture.FixtureError("nginx_syntax_check_failed_no_reload")

    monkeypatch.setattr(fixture, "check_nginx", invalid)
    monkeypatch.setattr(fixture, "reload_nginx", lambda: calls.append("reload"))
    monkeypatch.setattr(fixture, "remove_container", lambda item: calls.append("remove"))
    with pytest.raises(fixture.FixtureError, match="syntax_check_failed"):
        fixture.cleanup()
    assert conf.read_bytes() == original
    assert calls == []


@pytest.mark.parametrize("name", ["start", "stop"])
def test_state_changes_only_use_verified_fixture_id(monkeypatch, name):
    monkeypatch.setattr(fixture, "require_root", lambda: None)
    monkeypatch.setattr(fixture, "tool", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(fixture, "require_linux_docker", lambda: None)
    monkeypatch.setattr(fixture, "inspect_container", owned)
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(fixture, "docker", docker)
    result = fixture.action(name)
    assert result["ok"]
    assert calls == [(name, "a" * 64)]


def test_missing_services_are_not_a_passing_probe(monkeypatch):
    monkeypatch.setattr(fixture, "inspect_container", lambda: None)
    monkeypatch.setattr(fixture, "safe_configuration", lambda: None)
    monkeypatch.setattr(
        fixture, "probe", lambda port: pytest.fail("Must not probe unconfigured ports")
    )
    result = fixture.status_result()
    assert result["container"] is None
    assert result["nginx"]["status"] == "not_configured"
    assert result["upstream"]["expected_healthy"] is False


def test_status_uses_restricted_inspection_without_environment(monkeypatch):
    monkeypatch.setattr(fixture, "inspect_container", owned)
    monkeypatch.setattr(fixture, "safe_configuration", lambda: None)
    monkeypatch.setattr(fixture, "probe", lambda port: {"status": "observed", "http_status": 200})
    result = fixture.status_result()
    assert set(result["container"]) == {
        "Id",
        "Name",
        "State",
        "RestartCount",
        "MemoryLimit",
        "Image",
    }
    assert ".Config.Env" not in fixture.INSPECT_FORMAT


def test_non_root_and_arbitrary_cli_arguments_are_rejected(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1001, raising=False)
    with pytest.raises(fixture.FixtureError, match="administrator_root_required"):
        fixture.require_root()
    monkeypatch.setattr(fixture.sys, "argv", ["fixture.py", "stop", "unrelated-private-target"])
    assert fixture.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "one_fixed_action_required"
    assert "unrelated-private-target" not in str(result)


@pytest.mark.parametrize("uid,mode", [(1001, 0o100644), (0, 0o100666), (0, 0o040755)])
def test_configuration_ownership_and_mode_rejected_before_reading(monkeypatch, uid, mode):
    fake_path = SimpleNamespace(
        is_symlink=lambda: False,
        exists=lambda: True,
        stat=lambda: SimpleNamespace(st_uid=uid, st_mode=mode, st_size=128),
        read_bytes=lambda: pytest.fail("Unowned configuration contents must not be read"),
    )
    monkeypatch.setattr(fixture, "CONF", fake_path)
    with pytest.raises(fixture.FixtureError, match="refusing_unowned_nginx_configuration"):
        fixture.safe_configuration()


def test_root_owned_foreign_configuration_marker_is_refused(monkeypatch):
    content = b"server { listen 8080; }\n"
    fake_path = SimpleNamespace(
        is_symlink=lambda: False,
        exists=lambda: True,
        stat=lambda: SimpleNamespace(st_uid=0, st_mode=0o100644, st_size=len(content)),
        read_bytes=lambda: content,
    )
    monkeypatch.setattr(fixture, "CONF", fake_path)
    monkeypatch.setattr(fixture, "configuration_directory", lambda: None)
    monkeypatch.setattr(
        fixture, "inspect_container", lambda: pytest.fail("Refuse before Docker changes")
    )
    with pytest.raises(fixture.FixtureError, match="refusing_unowned_nginx_configuration"):
        fixture.initialize()


def test_configuration_symlink_is_refused(monkeypatch):
    monkeypatch.setattr(fixture, "CONF", SimpleNamespace(is_symlink=lambda: True))
    with pytest.raises(fixture.FixtureError, match="refusing_unowned_nginx_configuration"):
        fixture.safe_configuration()


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, b"OPSARK_LAB_OK\n", True),
        (503, b"OPSARK_LAB_OK\n", False),
        (200, b"unrelated response", False),
        (301, b"", False),
    ],
)
def test_loopback_probe_requires_actual_status_and_exact_marker(
    monkeypatch, status, body, expected
):
    calls = []

    class Connection:
        def __init__(self, host, port, timeout):
            assert host == "127.0.0.1" and port == fixture.NGINX_PORT and timeout == 2

        def request(self, method, path, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return SimpleNamespace(status=status, read=lambda limit: body)

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(fixture.http.client, "HTTPConnection", Connection)
    result = fixture.probe(fixture.NGINX_PORT)
    assert result["expected_healthy"] is expected
    assert calls == [
        ("GET", "/healthz", {"Host": "opsark-lab.invalid", "Accept-Encoding": "identity"}),
        "closed",
    ]
