"""Exercise isolated runtime admission, HTTP evidence, and one-shot reload without Docker."""

import hashlib
import http.client
import importlib
import json
import os
import socket
import stat
import subprocess
import sys
from collections import deque
from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

CONTAINER = "a" * 64
IMAGE = "sha256:" + "b" * 64
SITE_DEV = 2049
SITE_INO = 20499


def site_proof(data, *, inode=SITE_INO):
    return hashlib.sha256(data).hexdigest(), {
        "dev": SITE_DEV,
        "ino": inode,
        "size": len(data),
        "mtime_ns": 100,
        "ctime_ns": 200,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
    }


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.import_module("deploy.nginx.fixture_runtime")


class Docker:
    def __init__(self, module, workspace):
        self.module = module
        self.calls = []
        self.probes = deque()
        self.after_probe = lambda: None
        self.site = site_proof(module.fixture_action.ORIGINAL)
        self.metadata = {
            ".Id": CONTAINER,
            ".Image": IMAGE,
            ".State.Running": True,
            ".State.Pid": 314,
            ".State.StartedAt": "2026-11-05T02:00:00Z",
            ".Path": module.NGINX_COMMAND[0],
            ".Args": list(module.NGINX_COMMAND[1:]),
            ".Config.User": "65534:65534",
            '(index .Config.Labels "io.opsark.nginx.fixture")': workspace.name,
            ".HostConfig.NetworkMode": "none",
            '(index .HostConfig "Privileged")': False,
            ".HostConfig.ReadonlyRootfs": True,
            '(index .HostConfig "CapAdd")': [],
            ".HostConfig.CapDrop": ["ALL"],
            ".HostConfig.SecurityOpt": ["no-new-privileges:true"],
            '(index .HostConfig "PidMode")': "",
            ".HostConfig.IpcMode": "none",
            ".HostConfig.CgroupnsMode": "private",
            '(index .HostConfig "CgroupnsMode")': "private",
            '(index .HostConfig "UTSMode")': "",
            '(index .HostConfig "Devices")': [],
            '(index .HostConfig "DeviceRequests")': [],
            '(index .HostConfig "DeviceCgroupRules")': [],
            '(index .HostConfig "PortBindings")': {},
            ".HostConfig.Tmpfs": {module.STATE_DIR: module.TMPFS},
            ".NetworkSettings.Networks": {"none": {}},
            ".Mounts": [
                {
                    "Type": "bind",
                    "RW": False,
                    "Propagation": "rprivate",
                    "Source": str(workspace / "etc/nginx/conf.d"),
                    "Destination": "/fixture-sites",
                },
                {
                    "Type": "bind",
                    "RW": False,
                    "Propagation": "rprivate",
                    "Source": str(workspace / "runtime/nginx.conf"),
                    "Destination": "/fixture-wrapper.conf",
                },
            ],
        }

    def run(self, args, **kwargs):
        assert args[:5] == [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            "synthetic-empty-config",
        ]
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        assert kwargs["timeout"] <= 5 and kwargs["check"] is False
        command = args[5:]
        self.calls.append(command)
        if command[0] == "container":
            assert command[1:3] == ["inspect", "--format"] and command[-1] == CONTAINER
            contents = "\n".join(json.dumps(self.metadata[k]) for k in self.module._INSPECT_FIELDS)
            return subprocess.CompletedProcess(args, 0, contents.encode() + b"\n")
        if command[0] == "exec":
            assert command[1:6] == [CONTAINER, "/usr/bin/python3", "-I", "-B", "-c"]
            digest, identity = self.site
            assert command[7:] == [digest, str(identity["dev"]), str(identity["ino"])]
            result = self.probes.popleft()
            self.after_probe()
            return subprocess.CompletedProcess(args, int(result is None), result or b"")
        raise AssertionError("An unexpected Docker operation was requested")

    def hup(self, descriptor):
        assert descriptor == 10_000 + self.metadata[".State.Pid"]
        self.calls.append(["hup"])

    def operations(self):
        return [call[0] for call in self.calls]

    def published(self):
        self.site = site_proof(self.module.fixture_action.CANDIDATE, inode=SITE_INO + 1)

    def observed_site(self):
        digest, identity = self.site
        return digest, identity.copy()


@pytest.fixture
def fixture(module, monkeypatch, tmp_path):
    workspace = tmp_path / "opsark-nginx-fixture-012345abcdef"
    policy = SimpleNamespace(config_directory=workspace / "etc/nginx/conf.d")
    monkeypatch.setattr(module.fixture_action, "fixture_policy", lambda _: policy)
    monkeypatch.setattr(module.config_snapshot, "_directory", lambda *_: nullcontext(4))
    monkeypatch.setattr(module.config_snapshot, "_read", lambda *_: (module.WRAPPER, {}))
    monkeypatch.setattr(module.config_snapshot, "_machine", lambda _: "d" * 64)
    monkeypatch.setattr(module.fixture_context, "has_context", lambda _: False)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    docker = Docker(module, workspace)
    monkeypatch.setattr(module.subprocess, "run", docker.run)
    runtime = module.FixtureRuntime(workspace, CONTAINER, IMAGE, "synthetic-empty-config")
    monkeypatch.setattr(runtime, "_site", docker.observed_site)
    monkeypatch.setattr(runtime, "_pin", lambda pid: 10_000 + pid)
    monkeypatch.setattr(runtime, "_close_pidfd", lambda _: None)
    monkeypatch.setattr(runtime, "_send_hup", docker.hup)
    return runtime, docker


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        (".Image", "sha256:" + "c" * 64),
        (".State.Pid", True),
        (".Config.User", "0:0"),
        ('(index .Config.Labels "io.opsark.nginx.fixture")', "other-fixture"),
        (".HostConfig.NetworkMode", "bridge"),
        (".NetworkSettings.Networks", {"none": {}, "bridge": {}}),
        ('(index .HostConfig "Privileged")', True),
        (".HostConfig.ReadonlyRootfs", False),
        ('(index .HostConfig "CapAdd")', ["NET_ADMIN"]),
        (".HostConfig.SecurityOpt", []),
        (".HostConfig.IpcMode", "host"),
        ('(index .HostConfig "UTSMode")', "host"),
        ('(index .HostConfig "Devices")', [{"PathOnHost": "/dev/synthetic"}]),
        ('(index .HostConfig "DeviceRequests")', [{"Driver": "synthetic"}]),
        ('(index .HostConfig "DeviceCgroupRules")', ["c 1:3 rwm"]),
        ('(index .HostConfig "PortBindings")', {"18087/tcp": [{}]}),
        (".HostConfig.Tmpfs", {}),
    ],
)
def test_unsafe_metadata_refuses_before_any_exec_or_signal(module, fixture, field, invalid):
    runtime, docker = fixture
    docker.metadata[field] = invalid
    with pytest.raises(module.RuntimeRefused):
        runtime.preflight()
    assert runtime.identity is None and runtime.reload_and_verify() is False
    assert docker.operations() == ["container"]


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("Source", "/etc/nginx/conf.d"), ("RW", True), ("Propagation", "shared")],
)
def test_unsafe_mount_refuses_before_any_exec(module, fixture, field, invalid):
    runtime, docker = fixture
    docker.metadata[".Mounts"][0][field] = invalid
    with pytest.raises(module.RuntimeRefused):
        runtime.preflight()
    assert docker.operations() == ["container"]


def test_changed_wrapper_is_refused_without_docker(module, fixture, monkeypatch):
    runtime, docker = fixture
    monkeypatch.setattr(module.config_snapshot, "_read", lambda *_: (b"foreign wrapper", {}))
    with pytest.raises(module.RuntimeRefused):
        runtime.preflight()
    assert not docker.calls


def test_reload_sends_one_hup_and_retries_only_observation(fixture):
    runtime, docker = fixture
    docker.probes.extend([b"original\n", b"original\n", None, b"candidate\n"])
    assert runtime.preflight() is True
    docker.published()
    assert runtime.reload_and_verify() is True
    operations = docker.operations()
    assert operations.count("hup") == 1
    signal_index = operations.index("hup")
    assert operations[:signal_index].count("exec") == 1
    assert operations[signal_index + 1 :].count("exec") == 3
    assert not docker.probes


def test_preflight_needs_the_original_response(fixture):
    runtime, docker = fixture
    docker.probes.extend([b"original\n", b"candidate\n"])
    assert runtime.preflight() is True
    assert runtime.preflight() is False and runtime.reload_and_verify() is False
    assert runtime.identity is None and "hup" not in docker.operations()


def test_runtime_fingerprint_distinguishes_process_epochs_without_signaling(module, fixture):
    runtime, docker = fixture
    original = runtime.fingerprint()
    docker.metadata[".State.StartedAt"] = "2026-11-05T02:01:00Z"
    restarted = runtime.fingerprint()
    assert original != restarted and docker.operations() == ["container", "container"]
    docker.probes.append(b"candidate\n")
    assert runtime.preflight(b"candidate") is True
    assert runtime.fingerprint() == restarted
    docker.metadata[".State.Pid"] += 1
    with pytest.raises(module.RuntimeRefused):
        runtime.fingerprint()
    assert "hup" not in docker.operations()


def test_host_cgroup_namespace_is_refused_before_any_exec(module, fixture):
    runtime, docker = fixture
    for key in (".HostConfig.CgroupnsMode", '(index .HostConfig "CgroupnsMode")'):
        docker.metadata[key] = "host"
    with pytest.raises(module.RuntimeRefused):
        runtime.preflight()
    assert docker.operations() == ["container"]


@pytest.mark.parametrize(
    ("field", "changed"), [(".State.Pid", 315), (".State.StartedAt", "2026-11-05T02:01:00Z")]
)
def test_runtime_identity_drift_before_reload_refuses_signal(fixture, field, changed):
    runtime, docker = fixture
    docker.probes.append(b"original\n")
    assert runtime.preflight() is True
    docker.published()
    docker.metadata[field] = changed
    assert runtime.reload_and_verify() is False
    assert "hup" not in docker.operations()


def test_candidate_seen_after_runtime_restart_is_not_verified(fixture):
    runtime, docker = fixture
    docker.probes.extend([b"original\n", b"candidate\n"])
    assert runtime.preflight() is True
    docker.published()
    docker.after_probe = lambda: docker.metadata.update({".State.Pid": 315})
    assert runtime.reload_and_verify() is False
    assert docker.operations().count("hup") == 1


def test_preflight_rejects_same_bytes_at_replaced_site_inode(fixture):
    runtime, docker = fixture
    docker.probes.append(b"original\n")
    docker.after_probe = lambda: docker.site[1].update(ino=SITE_INO + 1)
    assert runtime.preflight() is False and runtime.identity is None
    assert "hup" not in docker.operations()


def test_master_exiting_after_runtime_check_has_no_signal_fallback(fixture, monkeypatch):
    runtime, docker = fixture
    docker.probes.append(b"original\n")
    assert runtime.preflight() is True
    docker.published()

    def exited(descriptor):
        assert descriptor == 10314
        raise ProcessLookupError

    monkeypatch.setattr(runtime, "_send_hup", exited)
    assert runtime.reload_and_verify() is False
    assert docker.operations().count("exec") == 1


@pytest.mark.parametrize(
    ("target", "control", "unknown", "interfaces", "mismatch", "reported"),
    [
        ((200, b"opsark-original"), (200, b"opsark-control"), 404, ["lo"], None, "original"),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], None, "candidate"),
        ((200, b"opsark-candidate"), (200, b"wrong"), 404, ["lo"], None, None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 200, ["lo"], None, None),
        ((503, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], None, None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo", "eth0"], None, None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "wrapper", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "device", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "inode", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "digest", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "context", "candidate"),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "context-device", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "context-inode", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "context-digest", None),
        ((200, b"opsark-candidate"), (200, b"opsark-control"), 404, ["lo"], "context-extra", None),
        (
            (200, b"opsark-candidate"),
            (200, b"opsark-control"),
            404,
            ["lo"],
            "context-missing",
            None,
        ),
    ],
)
def test_probe_checks_target_sibling_and_unknown_host(
    module, monkeypatch, capsys, target, control, unknown, interfaces, mismatch, reported
):
    received = []
    responses = {
        "target.opsark.invalid": target,
        "control.opsark.invalid": control,
        "unknown.opsark.invalid": (unknown, b"fixture body"),
    }

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 18087, 1)

        def request(self, method, path, *, headers):
            assert method == "GET" and path == "/healthz"
            self.host = headers["Host"]
            received.append(self.host)

        def getresponse(self):
            code, body = responses[self.host]
            return SimpleNamespace(status=code, read=lambda limit: body[:limit])

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(socket, "if_nameindex", lambda: list(enumerate(interfaces, 1)))

    read_bytes = Path.read_bytes
    expected_site = (
        module.fixture_action.ORIGINAL
        if target[1] == b"opsark-original"
        else module.fixture_action.CANDIDATE
    )
    digest, identity = site_proof(expected_site)
    argv = ["-c", digest, str(identity["dev"]), str(identity["ino"])]
    dependencies = {}
    dependency_stats = {}
    dependency_reads = []
    if mismatch and mismatch.startswith("context"):
        records = []
        for index, (name, data) in enumerate(module.fixture_context.FIXTURE_FILES.items()):
            fd = 98000 + index
            inode = SITE_INO + index + 1
            nested = name == "includes/sites.conf"
            records.append([name, hashlib.sha256(data).hexdigest(), SITE_DEV, inode])
            dependencies[Path("/fixture-runtime") / name] = (
                fd,
                b"x" + data[1:] if nested and mismatch == "context-digest" else data,
            )
            dependency_stats[fd] = SimpleNamespace(
                st_dev=SITE_DEV + (nested and mismatch == "context-device"),
                st_ino=inode + (nested and mismatch == "context-inode"),
            )
        if mismatch == "context-extra":
            records.append(["includes/unreviewed.conf", "a" * 64, SITE_DEV, SITE_INO + 8])
        if mismatch == "context-missing":
            records.pop()
        argv.append(json.dumps(records))
    monkeypatch.setattr(sys, "argv", argv)

    def container_wrapper(path):
        if path == Path("/fixture-wrapper.conf"):
            return module.WRAPPER if mismatch != "wrapper" else b"stale wrapper inode"
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", container_wrapper)
    open_path, fstat = Path.open, os.fstat
    site_bytes = b"x" + expected_site[1:] if mismatch == "digest" else expected_site
    site_stat = SimpleNamespace(
        st_dev=SITE_DEV + (mismatch == "device"),
        st_ino=SITE_INO + (mismatch == "inode"),
        st_size=len(site_bytes),
        st_mode=stat.S_IFREG | 0o644,
        st_mtime_ns=100,
        st_ctime_ns=200,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
    )
    site_fd = 98124

    class MountedFile(BytesIO):
        def __init__(self, fd, data):
            super().__init__(data)
            self.fd = fd

        def fileno(self):
            return self.fd

    def container_site(path, *args, **kwargs):
        if path == Path("/fixture-sites") / module.TARGET:
            assert args == ("rb",)
            return MountedFile(site_fd, site_bytes)
        if path in dependencies:
            assert args == ("rb",)
            dependency_reads.append(path)
            return MountedFile(*dependencies[path])
        return open_path(path, *args, **kwargs)

    file_stats = {site_fd: site_stat, **dependency_stats}

    def container_stat(fd):
        return file_stats[fd] if fd in file_stats else fstat(fd)

    monkeypatch.setattr(Path, "open", container_site)
    monkeypatch.setattr(os, "fstat", container_stat)
    if reported is None:
        with pytest.raises(SystemExit) as error:
            exec(compile(module._PROBE, "<fixture-probe>", "exec"), {})  # noqa: S102 -- fixed probe
        assert error.value.code == 1
        assert capsys.readouterr().out == ""
    else:
        exec(compile(module._PROBE, "<fixture-probe>", "exec"), {})  # noqa: S102 -- fixed probe
        assert capsys.readouterr().out == reported + "\n"
    assert received == (
        list(responses) if interfaces == ["lo"] and mismatch in (None, "context") else []
    )
    if mismatch == "context":
        assert dependency_reads == list(dependencies)
    elif mismatch in ("context-extra", "context-missing"):
        assert not dependency_reads


def test_cli_status_reads_original_id_without_constructing_runtime(module, monkeypatch, capsys):
    action_id = "f" * 64
    workspace = Path("/var/lib/opsark-nginx-fixture-012345abcdef")
    receipt = {"schema_version": 1, "action_id": action_id, "status": "unknown"}

    def inspect(path, identifier):
        assert path == workspace and identifier == action_id
        return receipt

    def unexpected(*_args, **_kwargs):
        pytest.fail("status entered a runtime mutation path")

    monkeypatch.setattr(module.fixture_action, "inspect_action", inspect)
    monkeypatch.setattr(module.fixture_action, "apply_fixture", unexpected)
    monkeypatch.setattr(module, "TemporaryDirectory", unexpected)
    monkeypatch.setattr(
        sys,
        "argv",
        ["fixture_runtime.py", "status", "--workspace", str(workspace), "--action-id", action_id],
    )
    assert module.main() == 1
    assert json.loads(capsys.readouterr().out) == receipt
