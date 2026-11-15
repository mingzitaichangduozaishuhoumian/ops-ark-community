"""RAM-only sockets/channels and JSON inspection fixtures; never real SSH/Docker."""

import builtins
import copy
import json
import shlex
import socket
import stat
import threading
import time
from dataclasses import asdict
from pathlib import PurePosixPath
from types import SimpleNamespace

import defense_native_relay as relay
import pytest


def scope(**changes):
    value = {
        "stage_root": "/var/lib/opsark-release-lab/" + "a" * 14,
        "workspace": "/var/lib/opsark-release-lab/" + "a" * 14 + "/controller-fresh",
        "container_id": "b" * 64,
        "network_id": "c" * 64,
        "image_id": "sha256:" + "d" * 64,
        "fixture_id": "e" * 16,
    }
    value.update(changes)
    return relay.RelayScope(**value)


def inspections():
    spec = asdict(scope())
    name = "opsark-requests-" + spec["fixture_id"]
    image = {"Id": spec["image_id"], "Config": {"Labels": {"base": "synthetic"}, "Volumes": None}}
    container = {
        "Id": spec["container_id"],
        "Image": spec["image_id"],
        "Name": "/" + name + "-management",
        "State": {"Running": True, "Paused": False},
        "Config": {
            "Labels": {"base": "synthetic", relay.LABEL: spec["fixture_id"]},
            "User": "0:0",
            "Entrypoint": ["/usr/bin/timeout"],
            "Cmd": ["-k", "2s", "600s", "/bin/sleep", "infinity"],
            "Volumes": None,
        },
        "HostConfig": {
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges:true"],
            "NetworkMode": name,
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "Devices": [],
            "DeviceRequests": None,
            "PortBindings": {},
            "PublishAllPorts": False,
            "VolumesFrom": None,
            "PidsLimit": 96,
            "Memory": 192 * 1024**2,
            "MemorySwap": 192 * 1024**2,
            "NanoCpus": 500_000_000,
            "Ulimits": [
                {"Name": "core", "Soft": 0, "Hard": 0},
                {"Name": "nofile", "Soft": 256, "Hard": 256},
            ],
            "LogConfig": {"Type": "none"},
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [
            {
                "Source": spec["workspace"] + "/" + source,
                "Destination": dest,
                "RW": False,
                "Type": "bind",
                "Propagation": "rprivate",
            }
            for source, dest in (("code", "/fixture-code"), ("management", "/fixture-client"))
        ],
        "NetworkSettings": {
            "Networks": {
                name: {
                    "NetworkID": spec["network_id"],
                    "IPAddress": "198.18.241.4",
                    "IPPrefixLen": 28,
                    "GlobalIPv6Address": "",
                }
            }
        },
    }
    addresses = ("198.18.241.2", "198.18.241.3", "198.18.241.4", "198.18.241.5")
    identities = ("1" * 64, "2" * 64, spec["container_id"], "3" * 64)
    endpoints = {
        identity: {"Name": name + "-" + role, "IPv4Address": address + "/28", "IPv6Address": ""}
        for identity, role, address in zip(
            identities, ("target", "candidate", "management", "alternate"), addresses, strict=True
        )
    }
    network = {
        "Id": spec["network_id"],
        "Name": name,
        "Driver": "bridge",
        "Internal": True,
        "EnableIPv6": False,
        "Ingress": False,
        "Attachable": False,
        "Options": {},
        "Labels": {relay.LABEL: spec["fixture_id"]},
        "IPAM": {"Config": [{"Subnet": "198.18.241.0/28", "Gateway": "198.18.241.1"}]},
        "Containers": endpoints,
    }
    return spec, image, container, network


@pytest.mark.parametrize(
    "field,value",
    [
        ("container_id", "b" * 12),
        ("container_id", "b" * 64 + ";id"),
        ("container_id", True),
        ("network_id", "C" * 64),
        ("image_id", "opsark:latest"),
        ("fixture_id", "e" * 14),
        ("stage_root", "/var/lib/opsark-release-lab"),
        ("stage_root", "/var/lib/opsark-release-lab/" + "a" * 14 + "/../elsewhere"),
        ("workspace", "/var/lib/opsark-release-lab/other/workspace"),
        ("workspace", "/var/lib/opsark-release-lab/" + "a" * 14 + "/nested/workspace"),
        ("workspace", "/var/lib/opsark-release-lab/" + "a" * 14 + "/$(id)"),
    ],
)
def test_scope_refuses_unbound_parameters(field, value):
    with pytest.raises(relay.RelayRefused):
        scope(**{field: value})


def test_command_is_fixed_shell_quoted_source_and_compiles_without_running():
    parts = shlex.split(relay.remote_command(scope()))
    assert parts[:9] == [
        "/usr/bin/timeout",
        "-k",
        "1s",
        "36s",
        "/usr/bin/python3",
        "-I",
        "-u",
        "-c",
        parts[8],
    ]
    assert len(parts) == 9
    assert "_verify_inspections(S,image,container,network)" in parts[-1]
    assert "'exec','-i',S['container_id']" in parts[-1]
    assert "stream.connect(('198.18.241.2',22423))" in parts[-1]
    assert "stream.bind(('198.18.241.4',0))" in parts[-1]
    compile(parts[-1], "<fixed-inspector>", "exec")
    compile(relay.PROXY_SOURCE, "<fixed-proxy>", "exec")


@pytest.mark.parametrize("cap_drop", [["ALL"], ["CAP_ALL"]])
@pytest.mark.parametrize("cap_add", [None, []])
@pytest.mark.parametrize("ip_range", [None, ""])
def test_exact_management_profile_is_accepted(cap_drop, cap_add, ip_range):
    spec, image, container, network = inspections()
    container["HostConfig"]["CapDrop"] = cap_drop
    container["HostConfig"]["CapAdd"] = cap_add
    if ip_range is not None:
        network["IPAM"]["Config"][0]["IPRange"] = ip_range
    relay._verify_inspections(spec, image, container, network)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Privileged", True),
        ("CapDrop", []),
        ("CapAdd", ["NET_ADMIN"]),
        ("ReadonlyRootfs", False),
        ("SecurityOpt", []),
        ("NetworkMode", "host"),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("CgroupnsMode", "host"),
        ("UTSMode", "host"),
        ("UsernsMode", "host"),
        ("Devices", [{"PathOnHost": "/dev/null"}]),
        ("DeviceRequests", [{}]),
        ("PortBindings", {"22423/tcp": [{}]}),
        ("PublishAllPorts", True),
        ("VolumesFrom", ["foreign"]),
        ("Memory", 1024**3),
        ("MemorySwap", -1),
        ("NanoCpus", 0),
        ("PidsLimit", 0),
        ("LogConfig", {"Type": "json-file"}),
        ("RestartPolicy", {"Name": "always"}),
    ],
)
def test_changed_management_security_profile_is_refused(field, value):
    spec, image, container, network = inspections()
    container["HostConfig"][field] = value
    with pytest.raises(ValueError):
        relay._verify_inspections(spec, image, container, network)


@pytest.mark.parametrize("change", range(14))
def test_identity_network_mount_or_runtime_drift_is_refused(change):
    spec, image, container, network = inspections()
    if change == 0:
        container["State"]["Running"] = False
    elif change == 1:
        container["Name"] = container["Name"].replace("management", "candidate")
    elif change == 2:
        container["Config"]["Cmd"][2] = "infinity"
    elif change == 3:
        container["Config"]["Labels"][relay.LABEL] = "foreign"
    elif change == 4:
        container["Mounts"][0]["Source"] = "/var/run/docker.sock"
    elif change == 5:
        container["Mounts"][0]["RW"] = True
    elif change == 6:
        container["NetworkSettings"]["Networks"][network["Name"]]["IPAddress"] = "198.18.241.3"
    elif change == 7:
        network["Internal"] = False
    elif change == 8:
        network["EnableIPv6"] = True
    elif change == 9:
        network["IPAM"]["Config"][0]["IPRange"] = "198.18.241.0/29"
    elif change == 10:
        network["Containers"]["f" * 64] = copy.deepcopy(next(iter(network["Containers"].values())))
    elif change == 11:
        image["Config"]["Volumes"] = {"/unexpected": {}}
    elif change == 12:
        container["Image"] = "sha256:" + "0" * 64
    elif change == 13:
        network["Labels"]["foreign"] = "yes"
    with pytest.raises(ValueError):
        relay._verify_inspections(spec, image, container, network)


class RamSocket:
    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.output = bytearray()
        self.closed = False
        self.shutdowns = []

    def setblocking(self, _value):
        pass

    def recv(self, size):
        if not self.chunks:
            raise BlockingIOError()
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def send(self, raw):
        self.output.extend(raw[:3])
        return min(3, len(raw))

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        self.closed = True


class RamChannel:
    def __init__(self, chunks=(), stderr=False):
        self.chunks = list(chunks)
        self.output = bytearray()
        self.closed = False
        self.eof_received = not self.chunks
        self.stderr = stderr
        self.half_closed = False
        self.commands = []
        self.delivered = 0

    def settimeout(self, _value):
        pass

    def exec_command(self, command):
        self.commands.append(command)

    def send_ready(self):
        return not self.closed

    def send(self, data):
        self.output.extend(data[:2])
        return min(2, len(data))

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, size):
        value = self.chunks.pop(0)
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        self.eof_received = not self.chunks
        self.delivered += len(value[:size])
        return value[:size]

    def recv_stderr_ready(self):
        return self.stderr

    def exit_status_ready(self):
        return False

    def shutdown_write(self):
        self.half_closed = True

    def close(self):
        self.closed = True


def prepared_relay(channel=None):
    channel = channel or RamChannel()
    instance = relay.FixedDefenseRelay(scope(), lambda *, timeout: channel)
    instance._deadline = time.monotonic() + 10
    return instance, channel


def test_bidirectional_partial_writes_and_half_close_leave_only_safe_counts():
    instance, channel = prepared_relay(RamChannel([b"ssh-server-data", b""]))
    stream = RamSocket([b"ssh-client-data", b""])
    connection = instance._admit(stream, ("127.0.0.1", 12345))
    instance._serve(connection)
    assert bytes(channel.output) == b"ssh-client-data"
    assert bytes(stream.output) == b"ssh-server-data"
    assert channel.half_closed and socket.SHUT_WR in stream.shutdowns
    assert channel.closed and stream.closed
    assert channel.commands == [instance.command]
    assert instance.statistics == {
        "accepted": 1,
        "refused": 0,
        "finished": 1,
        "failed": 0,
        "bytes_to_target": 15,
        "bytes_to_client": 15,
        "active": 0,
        "stopped": False,
    }


def test_remote_stderr_or_byte_budget_ends_without_retaining_content():
    class FastSocket(RamSocket):
        def send(self, raw):
            self.output.extend(raw)
            return len(raw)

    for channel in (RamChannel(stderr=True), RamChannel([b"x" * 262145])):
        instance, _ = prepared_relay(channel)
        connection = instance._admit(FastSocket([b""]), ("127.0.0.1", 1))
        instance._serve(connection)
        assert instance.statistics["failed"] == 1
        assert instance.statistics["active"] == 0
        assert channel.closed
        if not channel.stderr:
            assert channel.delivered == 262145


def test_admission_has_fixed_loopback_concurrency_count_and_time_limits():
    instance, _ = prepared_relay()
    for _ in range(4):
        assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is not None
    refused = RamSocket()
    assert instance._admit(refused, ("127.0.0.1", 1)) is None and refused.closed
    foreign = RamSocket()
    assert instance._admit(foreign, ("192.0.2.1", 1)) is None and foreign.closed
    instance._connections.clear()
    instance._counts["accepted"] = 32
    assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is None
    instance._counts["accepted"] = 0
    instance._deadline = time.monotonic() - 1
    assert instance._admit(RamSocket(), ("127.0.0.1", 1)) is None


def test_stop_or_deadline_prevents_remote_command_and_does_not_close_foreign_transport():
    instance, channel = prepared_relay()
    connection = instance._admit(RamSocket(), ("127.0.0.1", 1))
    instance._stopped.set()
    instance._serve(connection)
    assert not channel.commands and not channel.closed
    assert connection.stream.closed


def test_watchdog_close_unblocks_exec_ack_wait_and_joins_owned_worker():
    entered, closed = threading.Event(), threading.Event()

    class WaitingChannel(RamChannel):
        def exec_command(self, command):
            entered.set()
            assert closed.wait(timeout=2)
            raise OSError("synthetic secret must not be retained")

        def close(self):
            super().close()
            closed.set()

    instance, channel = prepared_relay(WaitingChannel())
    connection = instance._admit(RamSocket(), ("127.0.0.1", 1))
    worker = threading.Thread(target=instance._serve, args=(connection,))
    instance._threads.append(worker)
    worker.start()
    assert entered.wait(timeout=2)
    connection.deadline = time.monotonic() - 1
    instance._expire()
    instance.close()
    assert channel.closed and not worker.is_alive()
    assert instance.statistics["failed"] == 1


def test_busy_port_is_refused_without_opening_channels(monkeypatch):
    attempts = []

    class BusySocket:
        def setsockopt(self, *_args):
            pass

        def bind(self, address):
            attempts.append(address)
            raise OSError("synthetic private socket marker")

        def close(self):
            pass

    monkeypatch.setattr(relay.socket, "socket", lambda *_: BusySocket())
    instance, channel = prepared_relay()
    with pytest.raises(relay.RelayRefused, match="fixed isolated"):
        instance.__enter__()
    assert attempts == [("127.0.0.1", 22423)] and not channel.commands


def test_close_is_idempotent_without_ever_starting_a_listener():
    instance, channel = prepared_relay()
    instance.close()
    instance.close()
    assert instance.statistics["stopped"] and not channel.closed


@pytest.mark.parametrize("changed", [False, True])
def test_actual_generated_inspector_only_executes_after_all_mock_gates(changed):
    spec, image, container, network = inspections()
    if changed:
        container["HostConfig"]["Privileged"] = True
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
            exec(compile(source, "<mock-fixed-inspector>", "exec"), {"__builtins__": safe_builtins})  # noqa: S102 -- trusted generated code; all OS/process/path modules are RAM doubles.
        assert refused.value.code == 111 and not executed
    else:
        exec(compile(source, "<mock-fixed-inspector>", "exec"), {"__builtins__": safe_builtins})  # noqa: S102 -- trusted generated code; all OS/process/path modules are RAM doubles.
        assert executed[0][0] == "/usr/bin/timeout"
        arguments = executed[0][1]
        assert arguments[-5:-1] == ["/usr/bin/python3", "-I", "-u", "-c"]
        assert arguments[-1] == relay.PROXY_SOURCE
        assert arguments[4:12] == [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            spec["workspace"],
            "exec",
            "-i",
            spec["container_id"],
        ]
    assert len(calls) == 3


def test_mock_listener_context_reclaims_acceptor_and_owned_workers(monkeypatch):
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
    with relay.FixedDefenseRelay(scope(), lambda *, timeout: channel) as instance:
        end = time.monotonic() + 2
        while instance.statistics["finished"] != 1 and time.monotonic() < end:
            time.sleep(0.01)
        assert instance.statistics["finished"] == 1
        assert listener.address == ("127.0.0.1", 22423)
    assert listener.closed and channel.closed and stream.closed
    assert not instance._acceptor.is_alive()
    assert not any(worker.is_alive() for worker in instance._threads)


def test_failed_acceptor_start_closes_listener_without_retaining_exception(monkeypatch):
    closed = []

    class Listener:
        def setsockopt(self, *_args):
            pass

        def bind(self, address):
            assert address == relay.ADDRESS

        def listen(self, _count):
            pass

        def settimeout(self, _seconds):
            pass

        def close(self):
            closed.append(True)

    class FailedThread:
        def start(self):
            raise RuntimeError("synthetic exception must not escape")

    monkeypatch.setattr(relay.socket, "socket", lambda *_: Listener())
    monkeypatch.setattr(relay.threading, "Thread", lambda **_: FailedThread())
    instance, _ = prepared_relay()
    with pytest.raises(relay.RelayRefused):
        instance.__enter__()
    instance.close()
    assert closed and instance._listener is None and instance._acceptor is None


def test_failed_stream_thread_start_reclaims_admitted_socket(monkeypatch):
    stream = RamSocket()
    closed = []

    class Listener:
        def accept(self):
            return stream, ("127.0.0.1", 12345)

        def close(self):
            closed.append(True)

    class FailedThread:
        def start(self):
            raise RuntimeError("synthetic exception must not escape")

    instance, _ = prepared_relay()
    instance._listener = Listener()
    monkeypatch.setattr(relay.threading, "Thread", lambda **_: FailedThread())
    instance._accept()
    assert closed and stream.closed and not instance._connections and not instance._threads
    assert instance.statistics["failed"] == 1
