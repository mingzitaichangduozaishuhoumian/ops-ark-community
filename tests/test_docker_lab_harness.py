"""The CI-only SSH harness must reject every route outside its exec allowlist."""

import contextlib

import paramiko
import pytest
from docker_lab import ssh_server
from docker_lab.ssh_server import DockerLabSSH

from opsark.collector import commands_for
from opsark.config import HostConfig
from opsark.models import HostPublic


def connect(harness, *, key=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(str(harness.known_hosts_file))
    try:
        client.connect(
            "127.0.0.1",
            port=harness.port,
            username="opsark-lab",
            pkey=key or harness.user_key,
            look_for_keys=False,
            allow_agent=False,
            timeout=3,
            auth_timeout=3,
        )
    except Exception:
        client.close()
        raise
    return client


def test_lab_rejects_unregistered_exec_shell_sftp_and_forwarding(tmp_path):
    with DockerLabSSH(tmp_path, {"timeout -k 1s 5s cat /etc/os-release"}) as harness:
        with contextlib.closing(connect(harness)) as client:
            with pytest.raises(paramiko.SSHException):
                client.exec_command("touch arbitrary-command", timeout=3)
            transport = client.get_transport()
            assert transport is not None
            for request in ("shell", "sftp", "pty"):
                with (
                    contextlib.closing(transport.open_session(timeout=3)) as channel,
                    pytest.raises(paramiko.SSHException),
                ):
                    if request == "shell":
                        channel.invoke_shell()
                    elif request == "sftp":
                        channel.invoke_subsystem("sftp")
                    else:
                        channel.get_pty()
            with pytest.raises(paramiko.ChannelException):
                transport.open_channel(
                    "direct-tcpip", ("127.0.0.1", 80), ("127.0.0.1", 2222), timeout=3
                )
        assert harness.rejected == ["touch arbitrary-command"]
        assert harness.executed == []


def test_lab_rejects_a_different_client_key(tmp_path):
    with DockerLabSSH(tmp_path, {"timeout -k 1s 5s cat /etc/os-release"}) as harness:
        with pytest.raises(paramiko.AuthenticationException):
            connect(harness, key=paramiko.RSAKey.generate(2048))
        assert harness.executed == []


def test_lab_only_registers_timeout_bounded_commands(tmp_path):
    with pytest.raises(ValueError, match="timeout-bounded"):
        DockerLabSSH(tmp_path, {"docker inspect unrelated"})


def test_lab_reports_kernel_journal_unavailable_without_reading_host(tmp_path, monkeypatch):
    host = HostConfig(
        HostPublic(id="kernel-gap", name="Fixture", address="127.0.0.1", source="ssh"),
        tmp_path / "unused-key",
        tmp_path / "unused-known",
    )
    command = commands_for(host, "container_restart")["memory_events"]

    def forbidden(*_args, **_kwargs):
        pytest.fail("The Docker fixture must not read its host kernel journal")

    monkeypatch.setattr(ssh_server.subprocess, "run", forbidden)
    with (
        DockerLabSSH(tmp_path, {command}) as harness,
        contextlib.closing(connect(harness)) as client,
    ):
        _, stdout, stderr = client.exec_command("LC_ALL=C " + command, timeout=3)
        assert stdout.read() == b""
        assert stderr.read() == b"Kernel journal is outside the disposable Docker lab scope.\n"
        assert stdout.channel.recv_exit_status() == 125
