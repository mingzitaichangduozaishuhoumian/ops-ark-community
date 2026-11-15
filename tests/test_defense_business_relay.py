"""Business relay contracts with RAM sockets, channels and process doubles only."""

import ast
import builtins
import copy
import inspect
import json
import shlex
import socket
import stat
import threading
import time
from dataclasses import FrozenInstanceError
from pathlib import PurePosixPath
from types import SimpleNamespace
from typing import cast

import defense_business_relay as relay
import defense_native_relay as native
import pytest
from test_defense_native_relay import RamChannel, RamSocket, inspections, scope


def prepared(channel=None):
    channel = channel or RamChannel()
    instance = relay.FixedBusinessRelay(scope(), lambda *, timeout: channel)
    instance._deadline = time.monotonic() + 10
    return instance, channel


def test_fixed_business_endpoint_cannot_change_the_existing_defense_endpoint():
    assert relay.ADDRESS == ("127.0.0.1", 22422)
    assert native.ADDRESS == ("127.0.0.1", 22423)
    assert list(inspect.signature(relay.FixedBusinessRelay).parameters) == ["scope", "open_channel"]
    assert relay.RelayScope is native.RelayScope
    assert relay.FixedBusinessRelay._pump is native.FixedDefenseRelay._pump
    assert relay.FixedBusinessRelay._serve is native.FixedDefenseRelay._serve
    assert relay.FixedBusinessRelay._admit is native.FixedDefenseRelay._admit
    assert relay.FixedBusinessRelay.close is native.FixedDefenseRelay.close
    assert native.PROXY_SOURCE.count("22423") == 2
    assert "22422" not in native.PROXY_SOURCE
    old = native.FixedDefenseRelay(scope(), lambda *, timeout: None)
    new = relay.FixedBusinessRelay(scope(), lambda *, timeout: None)
    assert old.command != new.command
    assert "stream.connect(('198.18.241.2',22423))" in shlex.split(old.command)[-1]
    assert "stream.connect(('198.18.241.2',22422))" in shlex.split(new.command)[-1]


def test_proxy_has_only_two_fixed_numeric_destination_differences():
    class RestoreOldPort(ast.NodeTransformer):
        def visit_Constant(self, node):
            if type(node.value) is int and node.value == 22422:
                return ast.copy_location(ast.Constant(value=22423), node)
            return node

    old = ast.parse(native.PROXY_SOURCE)
    new = RestoreOldPort().visit(ast.parse(relay.PROXY_SOURCE))
    assert ast.dump(old) == ast.dump(new)
    assert relay.PROXY_SOURCE.count("22422") == 2 and "22423" not in relay.PROXY_SOURCE
    assert "stream.bind(('198.18.241.4',0))" in relay.PROXY_SOURCE


def test_remote_command_compiles_and_retains_exact_inspector_and_deadlines():
    parts = shlex.split(relay.remote_command(scope()))
    assert parts[:8] == [
        "/usr/bin/timeout",
        "-k",
        "1s",
        "36s",
        "/usr/bin/python3",
        "-I",
        "-u",
        "-c",
    ]
    assert len(parts) == 9
    assert inspect.getsource(native._verify_inspections) in parts[-1]
    assert native.INSPECTOR_SOURCE in parts[-1]
    assert "'exec','-i',S['container_id']" in parts[-1]
    compile(parts[-1], "<business-inspector>", "exec")
    compile(relay.PROXY_SOURCE, "<business-proxy>", "exec")


def test_scope_is_frozen_and_tampering_is_revalidated_before_building_command():
    value = scope()
    with pytest.raises(FrozenInstanceError):
        value.container_id = "f" * 64
    object.__setattr__(value, "container_id", "b" * 64 + ";id")
    with pytest.raises(relay.RelayRefused):
        relay.remote_command(value)
    with pytest.raises(relay.RelayRefused):
        relay.remote_command(cast(relay.RelayScope, SimpleNamespace()))


def test_business_pump_preserves_partial_writes_and_both_half_closes():
    instance, channel = prepared(RamChannel([b"collector-server", b""]))
    stream = RamSocket([b"collector-client", b""])
    connection = instance._admit(stream, ("127.0.0.1", 12345))
    instance._serve(connection)
    assert bytes(channel.output) == b"collector-client"
    assert bytes(stream.output) == b"collector-server"
    assert channel.half_closed and socket.SHUT_WR in stream.shutdowns
    assert channel.closed and stream.closed
    assert channel.commands == [instance.command]
    assert instance.statistics["finished"] == 1
    assert instance.statistics["failed"] == 0 and instance.statistics["active"] == 0
    assert set(instance.statistics) == {
        "accepted",
        "refused",
        "finished",
        "failed",
        "bytes_to_target",
        "bytes_to_client",
        "active",
        "stopped",
    }


@pytest.mark.parametrize("bad", ["stderr", "bytes"])
def test_transport_errors_do_not_retain_or_forward_private_diagnostics(bad):
    class FastSocket(RamSocket):
        def send(self, raw):
            self.output.extend(raw)
            return len(raw)

    channel = RamChannel(stderr=bad == "stderr") if bad == "stderr" else RamChannel([b"x" * 262145])
    instance, _ = prepared(channel)
    connection = instance._admit(FastSocket([b""]), ("127.0.0.1", 12345))
    instance._serve(connection)
    assert instance.statistics["failed"] == 1
    assert instance.statistics["active"] == 0 and channel.closed
    assert not any("error" in key or "stderr" in key or "payload" in key for key in vars(instance))


def test_business_admission_has_same_concurrency_count_time_and_loopback_limits():
    instance, _ = prepared()
    for _ in range(4):
        assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is not None
    rejected = RamSocket()
    assert instance._admit(rejected, ("127.0.0.1", 1)) is None and rejected.closed
    foreign = RamSocket()
    assert instance._admit(foreign, ("192.0.2.1", 1)) is None and foreign.closed
    instance._connections.clear()
    instance._counts["accepted"] = 32
    assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is None
    instance._counts["accepted"] = 0
    instance._deadline = time.monotonic() - 1
    assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is None


def test_busy_business_port_fails_without_trying_another_address_or_opening_ssh(monkeypatch):
    attempts = []

    class BusySocket:
        def setsockopt(self, *_args):
            pass

        def bind(self, address):
            attempts.append(address)
            raise OSError("synthetic transport marker")

        def close(self):
            pass

    monkeypatch.setattr(relay.socket, "socket", lambda *_: BusySocket())
    instance, channel = prepared()
    with pytest.raises(relay.RelayRefused):
        instance.__enter__()
    assert attempts == [("127.0.0.1", 22422)]
    assert native.ADDRESS == ("127.0.0.1", 22423) and not channel.commands


def test_mock_listener_context_closes_owned_workers_and_never_foreign_transport(monkeypatch):
    stream, channel = RamSocket([b"hi", b""]), RamChannel([b"ok", b""])
    values = [(stream, ("127.0.0.1", 12345))]

    class Listener:
        closed = False
        address = None

        def setsockopt(self, *_args):
            pass

        def bind(self, address):
            self.address = address

        def listen(self, count):
            assert count == 4

        def settimeout(self, seconds):
            assert seconds == 0.1

        def accept(self):
            if self.closed:
                raise OSError()
            if values:
                return values.pop(0)
            time.sleep(0.001)
            raise TimeoutError()

        def close(self):
            self.closed = True

    listener = Listener()
    monkeypatch.setattr(relay.socket, "socket", lambda *_: listener)
    with relay.FixedBusinessRelay(scope(), lambda *, timeout: channel) as instance:
        end = time.monotonic() + 2
        while instance.statistics["finished"] != 1 and time.monotonic() < end:
            time.sleep(0.01)
        assert instance.statistics["finished"] == 1
        assert listener.address == ("127.0.0.1", 22422)
    assert listener.closed and channel.closed and stream.closed
    assert not instance._acceptor.is_alive()
    assert not any(worker.is_alive() for worker in instance._threads)


def test_watchdog_releases_a_waiting_owned_business_channel():
    entered, closed = threading.Event(), threading.Event()

    class WaitingChannel(RamChannel):
        def exec_command(self, command):
            entered.set()
            assert closed.wait(timeout=2)
            raise OSError("private failure text must not be retained")

        def close(self):
            super().close()
            closed.set()

    instance, channel = prepared(WaitingChannel())
    connection = instance._admit(RamSocket(), ("127.0.0.1", 1))
    worker = threading.Thread(target=instance._serve, args=(connection,))
    instance._threads.append(worker)
    worker.start()
    assert entered.wait(timeout=2)
    connection.deadline = time.monotonic() - 1
    instance._expire()
    instance.close()
    assert channel.closed and not worker.is_alive()


@pytest.mark.parametrize("changed", [False, True])
def test_generated_business_inspector_runs_only_fixed_exec_after_all_ram_gates(changed):
    spec, image, container, network = inspections()
    if changed:
        network["Internal"] = False
    calls, executed = [], []

    class RamPath:
        def __init__(self, value):
            self.value = PurePosixPath(value)

        def __truediv__(self, value):
            return RamPath(self.value / value)

        def is_absolute(self):
            return self.value.is_absolute()

        def resolve(self, *, strict):
            return self

        def __eq__(self, other):
            return isinstance(other, RamPath) and self.value == other.value

        @property
        def parents(self):
            return tuple(RamPath(value) for value in self.value.parents)

        def lstat(self):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)

        def stat(self):
            return self.lstat()

        def exists(self):
            return False

    class RamOutput:
        def __init__(self, value):
            self.raw = json.dumps([value]).encode()

        def read(self, size):
            return self.raw[:size]

        def close(self):
            pass

    def popen(arguments, **kwargs):
        calls.append((arguments, kwargs))
        kind, identity = arguments[-3], arguments[-1]
        assert arguments[:5] == [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            spec["workspace"],
        ]
        assert kwargs["stdin"] == -3 and kwargs["stderr"] == -3
        value = {"image": image, "container": container, "network": network}[kind]
        assert (
            identity
            == {
                "image": spec["image_id"],
                "container": spec["container_id"],
                "network": spec["network_id"],
            }[kind]
        )
        return SimpleNamespace(stdout=RamOutput(value), wait=lambda **_: 0, poll=lambda: 0)

    modules = {
        "json": json,
        "stat": stat,
        "os": SimpleNamespace(
            geteuid=lambda: 0, execv=lambda path, args: executed.append((path, args))
        ),
        "signal": SimpleNamespace(SIGALRM=14, signal=lambda *_: None, alarm=lambda *_: None),
        "subprocess": SimpleNamespace(Popen=popen, PIPE=-1, DEVNULL=-3),
        "sys": SimpleNamespace(
            platform="linux", exit=lambda code: (_ for _ in ()).throw(SystemExit(code))
        ),
        "pathlib": SimpleNamespace(Path=RamPath),
    }
    safe_builtins = dict(vars(builtins), __import__=lambda name, *_args, **_kwargs: modules[name])
    source = shlex.split(relay.remote_command(scope()))[-1]
    if changed:
        with pytest.raises(SystemExit) as refused:
            exec(  # noqa: S102 -- trusted program, RAM-only OS/process/path modules.
                compile(source, "<mock-business-inspector>", "exec"),
                {"__builtins__": safe_builtins},
            )
        assert refused.value.code == 111 and not executed
    else:
        exec(compile(source, "<mock-business-inspector>", "exec"), {"__builtins__": safe_builtins})  # noqa: S102 -- trusted program; OS/process/path modules are RAM doubles.
        assert executed[0][0] == "/usr/bin/timeout"
        arguments = executed[0][1]
        assert arguments[-5:-1] == ["/usr/bin/python3", "-I", "-u", "-c"]
        assert arguments[-1] == relay.PROXY_SOURCE
        assert "stream.connect(('198.18.241.2',22422))" in arguments[-1]
        assert "22423" not in arguments[-1]
    assert len(calls) == 3
    assert native.ADDRESS == ("127.0.0.1", 22423)


def test_changed_management_profile_is_still_rejected_by_shared_inspector():
    spec, image, container, network = inspections()
    native._verify_inspections(spec, image, container, network)
    for changed in ("memory", "mount", "port", "cap", "label"):
        candidate = copy.deepcopy(container)
        if changed == "memory":
            candidate["HostConfig"]["MemorySwap"] = -1
        elif changed == "mount":
            candidate["Mounts"][0]["RW"] = True
        elif changed == "port":
            candidate["HostConfig"]["PortBindings"] = {"22422/tcp": [{}]}
        elif changed == "cap":
            candidate["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
        else:
            candidate["Config"]["Labels"][native.LABEL] = "foreign"
        with pytest.raises(ValueError):
            native._verify_inspections(spec, image, candidate, network)
