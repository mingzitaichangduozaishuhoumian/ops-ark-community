import hashlib
import json
import re
import shlex
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread

import paramiko
import pytest
from test_patch_client_eof import ssh_reply

from opsark.collector import MAX_OUTPUT_BYTES, collect_ssh, commands_for, run_check
from opsark.config import HostConfig
from opsark.models import HostPublic


def host() -> HostConfig:
    return HostConfig(
        public=HostPublic(id="test", name="Test", address="127.0.0.1", source="ssh"),
        key_file=Path("private-reference"),
        known_hosts_file=Path("known-reference"),
    )


def test_commands_only_read_state_and_never_request_full_docker_environment():
    for scenario in ("web_502", "disk", "container_restart", "ssh_security"):
        for command in commands_for(host(), scenario).values():
            assert command.startswith("timeout -k 1s 5s")
            assert not any(
                word in command for word in ("sudo ", " rm ", " restart ", ".Config.Env")
            )
    command = commands_for(host(), "container_restart")["container_state"]
    assert "inspect --format" in command
    assert "-u DOCKER_CONTEXT" in command
    assert "--host unix:///var/run/docker.sock" in command
    assert "-u DOCKER_TLS " in command
    assert "--tls" not in command
    template = shlex.split(command)[-2]
    fields = re.findall(r"{{json ([.A-Za-z]+)}}", template)
    assert {field for field in fields if field.startswith(".State")} == {
        ".State.Status",
        ".State.Running",
        ".State.OOMKilled",
        ".State.ExitCode",
    }
    assert ".State.Health" not in template and ".State.Error" not in template
    assert ".Config.Cmd" not in template and ".Config.Entrypoint" not in template
    # Render only the selected scalar fields. A health log and error are not
    # referenced by the actual command, so their content cannot enter the reply.
    selected = {
        ".Name": "/site",
        ".State.Status": "exited",
        ".State.Running": False,
        ".State.OOMKilled": True,
        ".State.ExitCode": 137,
        ".Image": "sha256:" + "a" * 64,
        ".Config.Image": "public-site:stable",
        ".NetworkSettings.Ports": {},
    }
    rendered = re.sub(
        r"{{json ([.A-Za-z]+)}}", lambda match: json.dumps(selected[match[1]]), template
    )
    rendered = rendered.replace("{{.RestartCount}}", "1").replace(
        "{{.HostConfig.Memory}}", "1048576"
    )
    assert json.loads(rendered)["State"] == {
        "Status": "exited",
        "Running": False,
        "OOMKilled": True,
        "ExitCode": 137,
    }
    with pytest.raises(ValueError):
        commands_for(host(), "arbitrary-command")


class Channel:
    def __init__(self, output=b"active\n", stderr=b"", code=0):
        self.output = output
        self.stderr = stderr
        self.code = code
        self.closed = False
        self.eof_received = True

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv(self, amount):
        part, self.output = self.output[:amount], self.output[amount:]
        return part

    def recv_stderr(self, amount):
        part, self.stderr = self.stderr[:amount], self.stderr[amount:]
        return part

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.code

    def close(self):
        self.closed = True

    def get_transport(self):
        return self

    def is_active(self):
        return True


class Stream:
    def __init__(self, channel):
        self.channel = channel

    def close(self):
        pass


class Client:
    def __init__(self, channel):
        self.channel = channel

    def exec_command(self, command, timeout):
        assert command.startswith("LC_ALL=C timeout")
        return Stream(self.channel), Stream(self.channel), Stream(self.channel)


def test_read_limits_close_the_remote_channel():
    channel = Channel(output=b"x" * (MAX_OUTPUT_BYTES + 10))
    result = run_check(Client(channel), "log", "timeout 5s tail", 1)
    assert result.truncated
    assert len(result.stdout) == MAX_OUTPUT_BYTES
    assert channel.closed


def test_permission_denied_is_missing_evidence():
    result = run_check(
        Client(Channel(output=b"", stderr=b"Permission denied", code=1)),
        "log",
        "timeout 5s tail",
        1,
    )
    assert result.status == "permission_denied"


def test_budget_timeout_is_not_success():
    result = run_check(Client(Channel()), "log", "timeout 5s tail", 0)
    assert result.status == "timeout"
    assert result.exit_code is None


def test_real_paramiko_channel_keeps_tail_after_early_exit_status(monkeypatch):
    # Paramiko deliberately exposes exit-status before remote output reaches EOF.
    # Use its actual channel and byte buffers instead of teaching a fake that
    # exit_status_ready means the command has no more bytes to send.
    channel = paramiko.Channel(0)
    channel.exit_status = 0
    channel.status_event.set()
    observed_status, release_tail = Event(), Event()
    original_ready = channel.exit_status_ready

    def status_ready():
        ready = original_ready()
        if ready:
            observed_status.set()
        return ready

    monkeypatch.setattr(channel, "exit_status_ready", status_ready)

    def send_tail():
        if release_tail.wait(2):
            channel.in_buffer.feed(b"complete stdout tail\n")
            channel.in_stderr_buffer.feed(b"complete stderr tail\n")
            channel._handle_eof(None)

    sender = Thread(target=send_tail, daemon=True)
    sender.start()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_check, Client(channel), "log", "timeout 5s tail", 1)
        try:
            assert observed_status.wait(1)
            with pytest.raises(TimeoutError):
                future.result(timeout=0.05)
            release_tail.set()
            result = future.result(timeout=2)
        finally:
            release_tail.set()
            sender.join(timeout=2)
    assert result.status == "ok" and result.exit_code == 0
    assert result.stdout == "complete stdout tail\n"
    assert result.stderr == "complete stderr tail\n"


def test_exit_status_without_remote_eof_waits_until_existing_deadline():
    channel = Channel(output=b"partial stdout", stderr=b"partial stderr", code=0)
    channel.eof_received = False
    result = run_check(Client(channel), "log", "timeout 5s tail", 0.05)
    assert result.status == "timeout" and result.exit_code is None
    assert result.stdout == "partial stdout"
    assert result.stderr == "partial stderr"
    assert channel.closed


def test_closed_channel_without_known_exit_status_is_not_success():
    channel = Channel(output=b"unverified output", code=-1)
    channel.eof_received = False
    channel.closed = True
    result = run_check(Client(channel), "log", "timeout 5s tail", 1)
    assert result.status == "error" and result.exit_code == -1


def test_closed_channel_on_live_transport_can_complete_without_eof():
    channel = Channel(output=b"complete output", code=0)
    channel.eof_received = False
    channel.closed = True
    result = run_check(Client(channel), "log", "timeout 5s tail", 1)
    assert result.status == "ok" and result.exit_code == 0


def test_closed_channel_with_unverifiable_transport_cannot_complete():
    class MissingTransport(Channel):
        def get_transport(self):
            return None

    channel = MissingTransport(output=b"unverified output", code=0)
    channel.eof_received = False
    channel.closed = True
    result = run_check(Client(channel), "log", "timeout 5s tail", 1)
    assert result.status == "error" and result.exit_code == 0
    assert result.stdout == "unverified output"


def test_remote_eof_without_exit_status_still_uses_absolute_deadline():
    class NoExitStatus(Channel):
        def exit_status_ready(self):
            return False

    channel = NoExitStatus(output=b"complete bytes but no exit status")
    result = run_check(Client(channel), "log", "timeout 5s tail", 0.05)
    assert result.status == "timeout" and result.exit_code is None
    assert result.stdout == "complete bytes but no exit status"
    assert channel.closed


def test_real_ssh_transport_abort_after_success_status_is_incomplete(tmp_path):
    keys = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    steps = [
        ("stdout", b"unverified stdout\n"),
        ("stderr", b"unverified stderr\n"),
        ("status", 0),
        ("delay", 0.2),
        ("abort", None),
    ]
    with ssh_reply(tmp_path, keys, steps) as fixture:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.load_host_keys(str(fixture.target.host.known_hosts_file))
        client.connect(
            "127.0.0.1",
            port=fixture.target.host.public.port,
            username="opsark-repair",
            pkey=keys[1],
            allow_agent=False,
            look_for_keys=False,
            timeout=3,
            auth_timeout=3,
            banner_timeout=3,
        )

        class LocalReadAdapter:
            def exec_command(self, command, timeout):
                assert command == "LC_ALL=C timeout 5s tail"
                # Reuse the authenticated fixture's fixed-command transport;
                # the collector still reads real SSH channel streams.
                streams = client.exec_command("opsark-patch-v1", timeout=timeout)
                streams[0].write(b"{}\n")
                streams[0].flush()
                return streams

        try:
            result = run_check(LocalReadAdapter(), "log", "timeout 5s tail", 4)
        finally:
            client.close()
    assert result.status == "error" and result.exit_code == 0
    assert result.stdout == "unverified stdout\n"
    assert result.stderr.startswith("unverified stderr\n")
    assert "完整结果" in result.stderr
    assert fixture.record["requests"] == [{}]


def test_success_exit_with_journal_permission_warning_is_not_a_complete_check():
    result = run_check(
        Client(
            Channel(
                output=b"-- No entries --\n",
                stderr=(
                    b"Hint: You are currently not seeing messages from other users and the system."
                ),
            )
        ),
        "memory_events",
        "timeout 5s journalctl",
        1,
    )
    assert result.status == "permission_denied"


def test_application_stderr_is_part_of_successful_docker_log_output():
    result = run_check(
        Client(Channel(output=b"", stderr=b"database connection timeout\n", code=0)),
        "container_logs",
        "timeout 5s docker logs",
        1,
    )
    assert result.status == "ok"
    assert "database connection timeout" in result.stdout
    assert result.stderr == ""


def test_unknown_host_key_rejected_without_running_checks(monkeypatch):
    record = {"commands": []}

    class RejectingClient:
        def set_missing_host_key_policy(self, policy):
            assert isinstance(policy, paramiko.RejectPolicy)

        def load_host_keys(self, path):
            record["known"] = path

        def connect(self, **kwargs):
            record["connect"] = kwargs
            raise paramiko.SSHException("unknown host key with private-path-value")

        def close(self):
            record["closed"] = True

    monkeypatch.setattr(paramiko, "SSHClient", RejectingClient)
    result = collect_ssh(host(), "disk")
    assert result.checks[0].status == "error"
    assert result.checks[0].name == "connection"
    assert "private-path-value" not in result.checks[0].stderr
    assert record["connect"]["allow_agent"] is False
    assert record["connect"]["look_for_keys"] is False
    assert record["closed"]


@pytest.mark.parametrize("code,expected,truncated", [(28, "timeout", False), (63, "error", True)])
def test_curl_timeout_and_body_limit_are_not_success(code, expected, truncated):
    result = run_check(
        Client(Channel(output=b"partial", code=code)), "http_shop", "timeout 5s curl", 1
    )
    assert result.status == expected
    assert result.truncated is truncated


def test_changed_trust_record_stops_before_connecting(tmp_path, monkeypatch):
    path = tmp_path / "known"
    path.write_bytes(b"original-trust-profile")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    registered = host()
    target = HostConfig(
        public=registered.public.model_copy(update={"trusted_hosts_digest": digest}),
        key_file=tmp_path / "unused-key",
        known_hosts_file=path,
    )
    path.write_bytes(b"changed-trust-profile")
    calls = []

    class NoConnect:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            calls.append("connect")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", NoConnect)
    result = collect_ssh(target, "disk")
    assert result.checks[0].name == "connection"
    assert result.checks[0].status == "error"
    assert calls == []


def test_invalid_utf8_does_not_insert_a_matching_replacement_character():
    result = run_check(
        Client(Channel(output=b"\xff\nOPSARK_HTTP_STATUS:200\n")), "http_shop", "timeout 5s curl", 1
    )
    assert result.status == "error"
    assert "UTF-8" in result.stderr
