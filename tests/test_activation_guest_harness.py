"""Host-side ownership and isolation admission; these are not guest acceptance results."""

import copy
import json

import activation_guest_acceptance as harness
import pytest


def isolated():
    return {
        "Mounts": [],
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": False,
            "CgroupnsMode": "private",
            "PidMode": "",
            "IpcMode": "private",
            "PortBindings": {},
            "Binds": [],
            "RestartPolicy": {"Name": "no"},
            "Memory": 1_073_741_824,
            "NanoCpus": 1_000_000_000,
            "PidsLimit": 256,
            "CapAdd": ["SYS_ADMIN", "SYS_PTRACE"],
        },
    }


def test_reviewed_isolation_is_accepted():
    harness.verify_isolation(isolated())
    snapshot = isolated()
    snapshot["HostConfig"]["CapAdd"] = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
    harness.verify_isolation(snapshot)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("NetworkMode", "bridge"),
        ("Privileged", True),
        ("CgroupnsMode", "host"),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("PortBindings", {"22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "22"}]}),
        ("Binds", ["/:/host"]),
        ("RestartPolicy", {"Name": "always"}),
        ("Memory", 0),
        ("NanoCpus", 0),
        ("PidsLimit", 0),
        ("CapAdd", ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"]),
    ],
)
def test_isolation_drift_is_rejected(key, value):
    snapshot = isolated()
    snapshot["HostConfig"][key] = value
    with pytest.raises(RuntimeError, match="isolation"):
        harness.verify_isolation(snapshot)


def test_mount_is_rejected():
    snapshot = isolated()
    snapshot["Mounts"] = [{"Type": "bind", "Source": "/var/run/docker.sock"}]
    with pytest.raises(RuntimeError, match="isolation"):
        harness.verify_isolation(snapshot)


@pytest.mark.parametrize(("identifier", "token"), [("other", "run"), ("id", "other")])
def test_ownership_mismatch_is_rejected(monkeypatch, identifier, token):
    monkeypatch.setattr(
        harness,
        "docker",
        lambda _: json.dumps([{"Id": identifier, "Config": {"Labels": {harness.LABEL: token}}}]),
    )
    with pytest.raises(RuntimeError, match="ownership"):
        harness.inspect_owned("id", "run")


@pytest.mark.parametrize("image", ["ubuntu:24.04", "debian:latest", "attacker/debian:12"])
def test_unapproved_image_never_reaches_docker(monkeypatch, tmp_path, image):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Unapproved image reached Docker")

    monkeypatch.setattr(harness, "docker", forbidden)
    with pytest.raises(ValueError, match="Debian"):
        harness.run(image, tmp_path)


def test_missing_opt_in_never_reaches_docker(monkeypatch, tmp_path):
    monkeypatch.delenv("OPSARK_DISPOSABLE_ACTIVATION_LAB", raising=False)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Missing opt-in reached Docker")

    monkeypatch.setattr(harness, "docker", forbidden)
    with pytest.raises(RuntimeError, match="OPSARK_DISPOSABLE"):
        harness.run("debian:12", tmp_path)


def test_remote_docker_environment_is_removed(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://unapproved:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    seen = {}
    monkeypatch.setattr(harness.shutil, "which", lambda _: "/trusted/docker")

    def capture(argv, **kwargs):
        seen.update(argv=copy.deepcopy(argv), **kwargs)
        return type("Result", (), {"stdout": "ok"})()

    monkeypatch.setattr(harness.subprocess, "run", capture)
    assert harness.docker(["info"]) == "ok"
    assert not any(k.startswith("DOCKER_") for k in seen["env"])
    assert seen["argv"][1:3] == [
        "--host",
        (
            "npipe:////./pipe/dockerDesktopLinuxEngine"
            if harness.os.name == "nt"
            else "unix:///var/run/docker.sock"
        ),
    ]
