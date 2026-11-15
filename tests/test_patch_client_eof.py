"""Authenticated local SSH replies can carry data after an exit-status message."""

import hashlib
import json
import socket
import threading
import time
from contextlib import contextmanager, suppress
from types import SimpleNamespace

import paramiko
import pytest
from test_patch_client import JOB, request

from opsark import patch_client
from opsark.config import HostConfig
from opsark.models import HostPublic
from opsark.patch_client import PatchTarget, UnknownPatchResult, invoke


@pytest.fixture(scope="module")
def keys():
    return paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)


@contextmanager
def ssh_reply(tmp_path, keys, steps):
    """Serve only the fixed patch command on a temporary loopback listener."""
    server_key, client_key = keys
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    executed = threading.Event()
    record = {"requests": [], "steps": [], "errors": []}

    class Server(paramiko.ServerInterface):
        def check_auth_publickey(self, username, key):
            if username == "opsark-repair" and key == client_key:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "publickey"

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            if command != b"opsark-patch-v1":
                return False
            executed.set()
            return True

    def serve():
        transport = channel = None
        try:
            connection, _address = listener.accept()
            transport = paramiko.Transport(connection)
            transport.add_server_key(server_key)
            transport.start_server(server=Server())
            channel = transport.accept(timeout=5)
            if channel is None or not executed.wait(5):
                raise AssertionError("Authenticated fixed exec was not received")
            channel.settimeout(5)
            body = bytearray()
            while data := channel.recv(8192):
                body.extend(data)
            record["requests"].append(json.loads(body))
            for kind, value in steps:
                if kind == "stdout":
                    channel.sendall(value)
                elif kind == "stderr":
                    channel.sendall_stderr(value)
                elif kind == "status":
                    channel.send_exit_status(value)
                elif kind == "eof":
                    channel.shutdown_write()
                elif kind == "delay":
                    time.sleep(value)
                elif kind == "abort":
                    transport.close()
                elif kind == "close":
                    channel.close()
                else:
                    raise AssertionError("Unsupported fixture stage")
                record["steps"].append(kind)
        except (OSError, EOFError, paramiko.SSHException) as error:
            record["errors"].append(type(error).__name__)
        finally:
            if channel is not None:
                with suppress(OSError):
                    channel.close()
            if transport is not None:
                transport.close()
            listener.close()

    known, repair, readonly = (tmp_path / name for name in ("known", "repair", "readonly"))
    known.write_text(f"[127.0.0.1]:{port} {server_key.get_name()} {server_key.get_base64()}\n")
    client_key.write_private_key_file(str(repair))
    readonly.write_text("controlled-unused-readonly-reference")
    public = HostPublic(
        id="local-patch-fixture",
        name="local-patch-fixture",
        address="127.0.0.1",
        port=port,
        source="ssh",
        trusted_hosts_digest=hashlib.sha256(known.read_bytes()).hexdigest(),
    )
    target = PatchTarget(HostConfig(public, readonly, known), repair, "a" * 64)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(target=target, record=record)
    finally:
        listener.close()
        thread.join(timeout=6)
        assert not thread.is_alive(), "Local fixture did not finish within its own budget"


def test_real_ssh_late_scan_tail_is_drained_after_exit_status(tmp_path, keys):
    payload = json.dumps({"status": "partial", "payload": "x" * 345000}).encode()
    steps = [
        ("stdout", payload[:-2]),
        ("status", 0),
        ("delay", 0.3),
        ("stdout", payload[-2:] + b"\n"),
        ("eof", None),
    ]
    with ssh_reply(tmp_path, keys, steps) as fixture:
        result = invoke(fixture.target, request(), timeout=8)
    assert result == {"status": "partial", "payload": "x" * 345000}
    assert fixture.record["requests"] == [request()]
    assert fixture.record["steps"] == [kind for kind, _value in steps]


def test_real_ssh_valid_json_cannot_hide_late_trailing_garbage(tmp_path, keys):
    steps = [
        ("stdout", b'{"status":"verified"}'),
        ("status", 0),
        ("delay", 0.2),
        ("stdout", b'\n{"untrusted":"late document"}\n'),
        ("eof", None),
    ]
    with (
        ssh_reply(tmp_path, keys, steps) as fixture,
        pytest.raises(UnknownPatchResult) as caught,
    ):
        invoke(fixture.target, request("submit"), timeout=8)
    assert caught.value.job_id == JOB
    assert isinstance(caught.value.__cause__, json.JSONDecodeError)
    assert fixture.record["requests"] == [request("submit")]
    assert fixture.record["steps"] == [kind for kind, _value in steps]


def test_real_ssh_late_stderr_keeps_its_independent_hard_budget(tmp_path, keys, monkeypatch):
    monkeypatch.setattr(patch_client, "MAX_ERROR_BYTES", 64)
    steps = [
        ("stdout", b'{"status":"verified"}'),
        ("status", 0),
        ("delay", 0.2),
        ("stderr", b"private-late-error" + b"x" * 65),
        ("eof", None),
    ]
    with (
        ssh_reply(tmp_path, keys, steps) as fixture,
        pytest.raises(UnknownPatchResult) as caught,
    ):
        invoke(fixture.target, request("submit"), timeout=8)
    assert caught.value.job_id == JOB and "private-late-error" not in str(caught.value)
    assert str(caught.value.__cause__) == "Repair error output exceeded budget"
    assert fixture.record["requests"] == [request("submit")]
    assert "stderr" in fixture.record["steps"]


def test_real_ssh_eof_before_status_waits_for_known_success(tmp_path, keys):
    steps = [
        ("stdout", b'{"status":"complete"}\n'),
        ("eof", None),
        ("delay", 0.2),
        ("status", 0),
    ]
    with ssh_reply(tmp_path, keys, steps) as fixture:
        result = invoke(fixture.target, request(), timeout=8)
    assert result == {"status": "complete"}
    assert fixture.record["requests"] == [request()]


def test_real_ssh_normal_channel_close_on_live_transport_is_complete(tmp_path, keys):
    steps = [
        ("stdout", b'{"status":"complete"}\n'),
        ("status", 0),
        ("close", None),
        ("delay", 0.2),
    ]
    with ssh_reply(tmp_path, keys, steps) as fixture:
        result = invoke(fixture.target, request(), timeout=8)
    assert result == {"status": "complete"}
    assert fixture.record["requests"] == [request()]


def test_real_ssh_eof_and_close_without_status_cannot_authorize_success(tmp_path, keys):
    steps = [("stdout", b'{"status":"verified"}\n'), ("eof", None), ("delay", 0.2)]
    with (
        ssh_reply(tmp_path, keys, steps) as fixture,
        pytest.raises(UnknownPatchResult) as caught,
    ):
        invoke(fixture.target, request("submit"), timeout=8)
    assert caught.value.job_id == JOB
    assert str(caught.value.__cause__) == "Repair entry returned no successful result"
    assert fixture.record["requests"] == [request("submit")]


@pytest.mark.parametrize("operation", ["scan", "submit"])
def test_real_ssh_transport_loss_without_eof_cannot_complete_a_valid_json_reply(
    tmp_path, keys, operation
):
    steps = [
        ("stdout", b'{"status":"verified"}\n'),
        ("status", 0),
        ("delay", 0.2),
        ("abort", None),
    ]
    with (
        ssh_reply(tmp_path, keys, steps) as fixture,
        pytest.raises(patch_client.PatchClientError) as caught,
    ):
        invoke(fixture.target, request(operation), timeout=8)
    if operation == "submit":
        assert isinstance(caught.value, UnknownPatchResult)
        assert caught.value.job_id == JOB
    else:
        assert not isinstance(caught.value, UnknownPatchResult)
    assert isinstance(caught.value.__cause__, EOFError)
    assert fixture.record["requests"] == [request(operation)]
    assert fixture.record["steps"] == [kind for kind, _value in steps]
