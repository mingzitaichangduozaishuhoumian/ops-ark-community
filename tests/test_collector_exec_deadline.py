"""Exercise actual Paramiko exec-ACK waits with an entirely in-memory transport."""

import os
import threading
import time
from dataclasses import replace

import paramiko
import pytest
from fastapi import HTTPException

from opsark import collector
from opsark import compose_discovery as discovery
from opsark.config import HostConfig, Settings
from opsark.models import HostPublic
from opsark.platforms import TOOLS


class MemoryTransport:
    def __init__(self, replies=None, *, silent_open=False):
        self.replies = replies or {}
        self.silent_open = silent_open
        self.active = True
        self.channels = []
        self.commands = []
        self.sent = threading.Event()
        self.closed = threading.Event()
        self.close_calls = 0

    def get_log_channel(self):
        return "opsark-memory-exec-deadline"

    def is_active(self):
        return self.active

    def open_session(self, timeout):
        if self.silent_open:
            self.sent.set()
            assert self.closed.wait(1), "Channel-open wait was not released by its deadline"
        if not self.active:
            raise self.get_exception() or paramiko.SSHException("synthetic closed transport")
        channel = paramiko.Channel(len(self.channels) + 1)
        channel._set_transport(self)
        channel.active = True
        channel.remote_chanid = channel.chanid
        self.channels.append(channel)
        return channel

    def _send_user_message(self, message):
        value = paramiko.Message(message.asbytes())
        if value.get_byte() != b"\x62":  # SSH_MSG_CHANNEL_REQUEST
            return
        channel_id = value.get_int()
        assert value.get_text() == "exec" and value.get_boolean() is True
        command = value.get_text()
        self.commands.append(command)
        self.sent.set()
        response = self.replies.get(command)
        if response is not None:
            channel = self.channels[channel_id - 1]
            channel.in_buffer.feed(response)
            channel.exit_status = 0
            channel.status_event.set()
            channel._handle_eof(None)
            channel._request_success(None)

    def get_exception(self):
        return None

    def close(self):
        self.close_calls += 1
        self.active = False
        self.closed.set()
        for channel in self.channels:
            with channel.lock:
                channel._set_closed()


def client_for(transport):
    client = paramiko.SSHClient()
    client._transport = transport
    return client


def registered(tmp_path, *, name="fixture"):
    return HostConfig(
        HostPublic(id=name, name=name, address="192.0.2.10", source="ssh"),
        tmp_path / "unused-synthetic-key",
        tmp_path / "unused-synthetic-pin",
        compose_project="demo",
    )


def preflight_replies(host):
    outputs = {
        "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
        "platform_tools": "OPSARK_ARCH=x86_64\n"
        + "".join(f"OPSARK_TOOL_{name}=1\n" for name in TOOLS),
        "nginx_status": "active\n",
        "container_state": '{"Name":"/api","State":{"Status":"running"}}',
        "disk_bytes": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
        "/dev/synthetic 100000 12000 88000 12% /\n",
        "disk_inodes": "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
        "/dev/synthetic 10000 1100 8900 11% /\n",
        "compose_version": "v2.31.0\n",
        "docker_rootful": '{"OSType":"linux","SecurityOptions":["name=seccomp,profile=builtin"]}\n',
    }
    return {
        "LC_ALL=C " + command: outputs[name].encode()
        for name, command in collector.commands_for_preflight(host).items()
    }


@pytest.mark.parametrize("silent_open", [False, True])
def test_actual_paramiko_open_or_exec_ack_wait_is_closed_within_budget(silent_open):
    transport = MemoryTransport(silent_open=silent_open)
    client = client_for(transport)
    started = time.monotonic()
    result = collector.run_check(client, "os_release", "timeout 5s cat /etc/os-release", 0.04)
    assert time.monotonic() - started < 0.8
    assert result.status == "timeout" and result.exit_code is None
    assert transport.closed.is_set() and not transport.is_active()
    assert client.get_transport() is transport  # Closing this Transport did not replace the client.
    assert all(channel.closed for channel in transport.channels)
    assert not result.stdout and "synthetic" not in result.stderr
    client.close()


def test_actual_paramiko_ack_and_complete_data_do_not_poison_next_check():
    command = "LC_ALL=C timeout 5s read"
    transport = MemoryTransport({command: b"complete metadata\n"})
    client = client_for(transport)
    try:
        for _ in range(2):
            result = collector.run_check(client, "fixed", "timeout 5s read", 1)
            assert result.status == "ok" and result.exit_code == 0
            assert result.stdout == "complete metadata\n" and not result.stderr
        assert transport.is_active() and transport.close_calls == 0
        assert len(transport.commands) == 2
    finally:
        client.close()


@pytest.mark.parametrize("silent_open", [False, True])
def test_saved_eof_after_open_or_actual_exec_ack_deadline_is_timeout(silent_open):
    class SavedEOF(MemoryTransport):
        def get_exception(self):
            return EOFError("synthetic private peer error")

    transport = SavedEOF(silent_open=silent_open)
    client = client_for(transport)
    try:
        result = collector.run_check(client, "fixed", "timeout 5s read", 0.04)
        assert result.status == "timeout" and result.exit_code is None
        assert transport.closed.is_set() and "synthetic" not in result.stderr
    finally:
        client.close()


def test_actual_channel_peer_eof_before_deadline_is_a_classified_error():
    class PeerEOF(MemoryTransport):
        def get_exception(self):
            return EOFError("synthetic private peer error")

        def _send_user_message(self, message):
            super()._send_user_message(message)
            if message.asbytes().startswith(b"\x62"):
                self.close()

    transport = PeerEOF()
    client = client_for(transport)
    try:
        result = collector.run_check(client, "fixed", "timeout 5s read", 1)
        assert result.status == "error" and result.exit_code is None
        assert "synthetic" not in result.stderr
    finally:
        client.close()


@pytest.mark.parametrize("failure", [EOFError, OSError, paramiko.SSHException])
def test_actual_channel_close_frame_network_error_cannot_escape_or_claim_success(failure):
    class CloseFrameError(MemoryTransport):
        def _send_user_message(self, message):
            if message.asbytes().startswith(b"\x61"):  # SSH_MSG_CHANNEL_CLOSE
                raise failure("synthetic private close error")
            super()._send_user_message(message)

    transport = CloseFrameError({"LC_ALL=C timeout 5s read": b"complete metadata\n"})
    client = client_for(transport)
    try:
        result = collector.run_check(client, "fixed", "timeout 5s read", 1)
        assert result.status == "error" and result.exit_code is None
        assert "synthetic" not in result.stderr
        assert all(channel.closed for channel in transport.channels)
    finally:
        client.close()


def test_real_client_without_transport_is_classified_without_exec(monkeypatch):
    client = paramiko.SSHClient()
    monkeypatch.setattr(client, "exec_command", lambda *_a, **_k: pytest.fail("No transport"))
    result = collector.run_check(client, "fixed", "timeout 5s read", 0.04)
    assert result.status == "error" and result.exit_code is None
    assert not result.stdout


def test_outer_close_between_transport_check_and_dispatch_does_not_read_none():
    class ClosedDuringAdmission(MemoryTransport):
        def is_active(self):
            previously_active = super().is_active()
            client.close()
            return previously_active

    transport = ClosedDuringAdmission()
    client = client_for(transport)
    result = collector.run_check(client, "fixed", "timeout 5s read", 1)
    assert result.status == "error" and result.exit_code is None
    assert client.get_transport() is None and not transport.commands
    assert "synthetic" not in result.stderr


def test_replaced_client_transport_is_not_used_for_dispatch_or_deadline():
    command = "LC_ALL=C timeout 5s read"
    replacement = MemoryTransport({command: b"wrong connection\n"})

    class ReplacedDuringAdmission(MemoryTransport):
        def is_active(self):
            client._transport = replacement
            return super().is_active()

    original = ReplacedDuringAdmission()
    client = client_for(original)
    try:
        result = collector.run_check(client, "fixed", "timeout 5s read", 0.04)
        assert result.status == "timeout" and result.exit_code is None
        assert original.closed.is_set() and original.commands == [command]
        assert client.get_transport() is replacement
        assert replacement.is_active() and not replacement.commands and replacement.close_calls == 0
    finally:
        client.close()


def test_timer_start_failure_refuses_to_send_a_command(monkeypatch):
    class UnavailableTimer(DeferredTimer):
        def start(self):
            raise RuntimeError("synthetic timer unavailable")

    transport = MemoryTransport()
    client = client_for(transport)
    monkeypatch.setattr(collector.threading, "Timer", UnavailableTimer)
    result = collector.run_check(client, "fixed", "timeout 5s read", 1)
    assert result.status == "error" and not transport.commands
    assert "synthetic" not in result.stderr
    client.close()


def test_later_check_timeout_does_not_reconnect_or_raise_for_remaining_probes(
    monkeypatch, tmp_path
):
    host = registered(tmp_path)
    commands = collector.commands_for_preflight(host)
    replies = preflight_replies(host)
    del replies["LC_ALL=C " + commands["nginx_status"]]
    transport = MemoryTransport(replies)
    client = client_for(transport)
    monkeypatch.setattr(collector.paramiko, "SSHClient", lambda: client)
    monkeypatch.setattr(collector, "_connect_registered", lambda *_: None)
    monkeypatch.setattr(collector, "COMMAND_TIMEOUT", 0.04)
    result = collector.collect_ssh_preflight(host)
    states = {check.name: check.status for check in result.checks}
    assert states["os_release"] == states["platform_tools"] == "ok"
    assert all(states[name] == "timeout" for name in tuple(commands)[2:])
    assert transport.commands == ["LC_ALL=C " + command for command in tuple(commands.values())[:3]]
    assert client.get_transport() is None  # Only the owning collection finally closed the client.


def test_receipt_batch_keeps_earlier_receipt_and_never_sends_after_command_timeout(
    monkeypatch, tmp_path
):
    host = registered(tmp_path)
    host = replace(host, public=host.public.model_copy(update={"trusted_hosts_digest": "1" * 64}))
    transport = MemoryTransport({"LC_ALL=C first-fixed": b"OK\n"})
    client = client_for(transport)
    monkeypatch.setattr(collector.paramiko, "SSHClient", lambda: client)
    monkeypatch.setattr(collector, "_connect_registered", lambda *_: None)
    monkeypatch.setattr(collector, "COMMAND_TIMEOUT", 0.04)
    results = collector.collect_registered_receipts(
        host,
        {"first": "first-fixed", "second": "silent-fixed", "third": "not-sent"},
        output_limit=96,
    )
    assert results["first"].status == "ok" and results["first"].stdout == "OK\n"
    assert results["second"].status == results["third"].status == "timeout"
    assert transport.commands == ["LC_ALL=C first-fixed", "LC_ALL=C silent-fixed"]


class DeferredTimer:
    instances = []

    def __init__(self, _interval, function):
        self.function = function
        self.ident = None
        self.cancelled = False
        self.instances.append(self)

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True


def test_wall_deadline_after_ack_wins_even_when_timer_has_not_been_scheduled(monkeypatch):
    DeferredTimer.instances = []
    now = [0.0]
    command = "LC_ALL=C timeout 5s read"

    class LateAck(MemoryTransport):
        def _send_user_message(self, message):
            super()._send_user_message(message)
            now[0] = 0.1

    old = LateAck({command: b"late complete output\n"})
    client = client_for(old)
    monkeypatch.setattr(collector.threading, "Timer", DeferredTimer)
    monkeypatch.setattr(collector.time, "monotonic", lambda: now[0])
    first = collector.run_check(client, "fixed", "timeout 5s read", 0.05)
    assert first.status == "timeout" and first.exit_code is None
    assert old.is_active() and not DeferredTimer.instances[0].cancelled
    new = MemoryTransport({command: b"new complete metadata\n"})
    client._transport = new
    DeferredTimer.instances[
        0
    ].function()  # Delayed callback can only close its captured old object.
    second = collector.run_check(client, "fixed", "timeout 5s read", 1)
    assert second.status == "ok" and second.stdout == "new complete metadata\n"
    assert old.closed.is_set() and new.is_active()
    client.close()


def test_cancelled_old_timer_cannot_close_transport_during_next_check(monkeypatch):
    DeferredTimer.instances = []
    command = "LC_ALL=C timeout 5s read"
    transport = MemoryTransport({command: b"complete\n"})
    client = client_for(transport)
    monkeypatch.setattr(collector.threading, "Timer", DeferredTimer)
    for _ in range(2):
        assert collector.run_check(client, "fixed", "timeout 5s read", 1).status == "ok"
    for timer in DeferredTimer.instances:
        assert timer.cancelled
        timer.function()
    assert transport.is_active() and transport.close_calls == 0
    client.close()


def test_delayed_close_tail_never_holds_lifecycle_or_closes_a_replacement(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    real_timer = threading.Timer
    timers = []

    class DelayedClose(MemoryTransport):
        def close(self):
            if self.closed.is_set():
                return
            super().close()  # Releases the actual ACK waiter first.
            entered.set()
            assert release.wait(1), "Test did not release only its own close callback"

    def timer(interval, callback):
        value = real_timer(interval, callback)
        timers.append(value)
        return value

    old = DelayedClose()
    client = client_for(old)
    monkeypatch.setattr(collector.threading, "Timer", timer)
    try:
        started = time.monotonic()
        result = collector.run_check(client, "fixed", "timeout 5s read", 0.03)
        assert entered.is_set() and time.monotonic() - started < 0.8
        assert result.status == "timeout" and any(timer.is_alive() for timer in timers)
        replacement = MemoryTransport({"LC_ALL=C timeout 5s read": b"complete\n"})
        client._transport = replacement
        assert collector.run_check(client, "fixed", "timeout 5s read", 1).status == "ok"
        assert replacement.is_active()
    finally:
        release.set()
        for timer in timers:
            timer.join(2)
        client.close()
    assert all(not timer.is_alive() for timer in timers)


def test_two_host_route_releases_global_slot_after_silent_ack(monkeypatch, tmp_path):
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path / "fake-default"))
    monkeypatch.setenv("OPSARK_TOKEN", "synthetic-deadline-token-00000000000000000000")
    from opsark import main

    bad, good = registered(tmp_path, name="bad"), registered(tmp_path, name="good")
    stalled, healthy = MemoryTransport(), MemoryTransport(preflight_replies(good))
    client_class = paramiko.SSHClient

    def connect(client, host):
        client._transport = stalled if host.public.id == "bad" else healthy

    monkeypatch.setattr(main, "load_hosts", lambda _: {"bad": bad, "good": good})
    monkeypatch.setattr(collector.paramiko, "SSHClient", client_class)
    monkeypatch.setattr(collector, "_connect_registered", connect)
    monkeypatch.setattr(discovery, "_connect_registered", connect)
    monkeypatch.setattr(discovery, "COMMAND_TIMEOUT", 0.1)
    app = main.create_app(
        Settings(
            data_dir=tmp_path / "fake-app", token="synthetic-deadline-token-00000000000000000000"
        )
    )
    routes = {route.path: route.endpoint for route in app.routes if hasattr(route, "path")}
    first = routes["/api/hosts/{host_id}/compose-discovery"]
    second = routes["/api/hosts/{host_id}/preflight"]
    outcomes = []
    thread = threading.Thread(
        target=lambda: outcomes.append(first("bad", main.HostPreflightRequest()))
    )
    thread.start()
    try:
        assert stalled.sent.wait(1)
        with pytest.raises(HTTPException) as conflict:
            second("good", main.HostPreflightRequest())
        assert conflict.value.status_code == 409
        thread.join(1)
        assert not thread.is_alive() and outcomes[0].status == "unavailable"
        assert second("good", main.HostPreflightRequest()).status == "ready"
        assert not stalled.is_active()
    finally:
        stalled.close()
        thread.join(2)
        healthy.close()
