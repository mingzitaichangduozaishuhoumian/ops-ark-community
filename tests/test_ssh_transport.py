"""Use an actual local SSH connection; the server only returns synthetic bytes."""

import contextlib
import socket
import threading
import time

import paramiko

from opsark.collector import collect_ssh
from opsark.config import HostConfig
from opsark.models import HostPublic
from opsark.platforms import TOOLS

TOOL_OUTPUT = "OPSARK_ARCH=x86_64\n" + "".join(f"OPSARK_TOOL_{tool}=1\n" for tool in TOOLS)


class SyntheticSSHServer(paramiko.ServerInterface):
    def __init__(self, user_key, commands, os_release, tool_output):
        self.user_key = user_key
        self.commands = commands
        self.os_release = os_release
        self.tool_output = tool_output

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        if username == "opsark-readonly" and key == self.user_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, channel_id):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        self.commands.append(command.decode())

        def respond():
            time.sleep(0.02)
            if b"cat /etc/os-release" in command:
                output = self.os_release.encode()
            elif b"OPSARK_ARCH" in command:
                output = self.tool_output.encode()
            elif b"df -Pk" in command:
                output = (
                    b"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    b"/dev/test 100000 99000 1000 99% /\n"
                )
            elif b"df -Pi" in command:
                output = (
                    b"Filesystem Inodes IUsed IFree IUse% Mounted on\n"
                    b"/dev/test 10000 1000 9000 10% /\n"
                )
            else:
                output = b"1000 /var/log/nginx\n"
            with contextlib.suppress(OSError, EOFError):
                channel.sendall(output)
                channel.send_exit_status(0)
                channel.shutdown_write()

        threading.Thread(target=respond, daemon=True).start()
        return True


@contextlib.contextmanager
def ssh_target(
    tmp_path, *, trusted=True, os_release='ID=ubuntu\nVERSION_ID="24.04"\n', tool_output=TOOL_OUTPUT
):
    server_key = paramiko.RSAKey.generate(2048)
    user_key = paramiko.RSAKey.generate(2048)
    key_file = tmp_path / "test-private-key"
    user_key.write_private_key_file(str(key_file))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    known_hosts = tmp_path / "test-known-hosts"
    known_hosts.write_text(
        f"[127.0.0.1]:{port} {server_key.get_name()} {server_key.get_base64()}\n"
        if trusted
        else "",
        encoding="utf-8",
    )
    commands = []
    stop = threading.Event()

    def serve():
        transport = None
        channels = []
        try:
            connection, _ = listener.accept()
            transport = paramiko.Transport(connection)
            transport.add_server_key(server_key)
            transport.start_server(
                server=SyntheticSSHServer(user_key, commands, os_release, tool_output)
            )
            while transport.is_active() and not stop.is_set():
                channel = transport.accept(0.1)
                if channel is not None:
                    channels.append(channel)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            if transport is not None:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield (
            HostConfig(
                public=HostPublic(
                    id="wire-test",
                    name="SSH wire test",
                    address="127.0.0.1",
                    port=port,
                    source="ssh",
                ),
                key_file=key_file,
                known_hosts_file=known_hosts,
            ),
            commands,
        )
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


def test_actual_authenticated_ssh_collection_uses_fixed_read_commands(tmp_path):
    with ssh_target(tmp_path) as (target, commands):
        collection = collect_ssh(target, "disk")
    assert collection.source == "ssh"
    assert len(collection.checks) == 5
    assert all(check.status == "ok" for check in collection.checks)
    assert "99%" in collection.checks[2].stdout
    assert len(commands) == 5
    assert all(command.startswith("LC_ALL=C timeout") for command in commands)


def test_actual_unknown_host_key_is_refused_before_exec(tmp_path):
    with ssh_target(tmp_path, trusted=False) as (target, commands):
        collection = collect_ssh(target, "disk")
    assert collection.checks[0].name == "connection"
    assert collection.checks[0].status == "error"
    assert commands == []


def test_unsupported_system_stops_before_tools_and_scenario_commands(tmp_path):
    with ssh_target(tmp_path, os_release='ID=fedora\nVERSION_ID="42"\n') as (target, commands):
        collection = collect_ssh(target, "disk")
    assert len(commands) == 1
    assert "cat /etc/os-release" in commands[0]
    assert all(check.status == "unavailable" for check in collection.checks[1:])


def test_missing_tool_skips_affected_checks_but_keeps_other_evidence(tmp_path):
    tools = TOOL_OUTPUT.replace("OPSARK_TOOL_df=1", "OPSARK_TOOL_df=0")
    with ssh_target(tmp_path, tool_output=tools) as (target, commands):
        collection = collect_ssh(target, "disk")
    assert not any("df -P" in command for command in commands)
    assert any("du -xsk" in command for command in commands)
    assert all(
        check.status == "unavailable" and "df" in check.stderr
        for check in collection.checks
        if check.name in {"disk_bytes", "disk_inodes"}
    )


def test_unknown_architecture_stops_before_scenario_commands(tmp_path):
    with ssh_target(tmp_path, tool_output=TOOL_OUTPUT.replace("x86_64", "s390x")) as (
        target,
        commands,
    ):
        collection = collect_ssh(target, "disk")
    assert len(commands) == 2
    assert all(check.status == "unavailable" for check in collection.checks[2:])


def test_malformed_probe_cannot_enable_scenario_commands(tmp_path):
    with ssh_target(tmp_path, tool_output=TOOL_OUTPUT + "OPSARK_TOOL_df=1\n") as (target, commands):
        collection = collect_ssh(target, "disk")
    assert len(commands) == 2
    assert all(check.status == "unavailable" for check in collection.checks[2:])
