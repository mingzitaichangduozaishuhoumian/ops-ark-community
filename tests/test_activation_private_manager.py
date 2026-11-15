"""Private PID1 peer parsing and ownership: no sockets or native libraries are opened."""

import ctypes
import stat
import struct
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_patch_agent import remote as remote
from test_root_activation import activation_env as activation_env

UNIT_PATH = b"/org/freedesktop/systemd1/unit/dbus_2eservice"
FD = 73


def pointer_value(value):
    return value.value or 0


class FakeChannel:
    def __init__(self, state):
        self.state = state
        self.detached = False
        self.closed = False

    def __enter__(self):
        self.state.calls.append("socket_enter")
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.closed:
            raise AssertionError("Socket owner closed twice")
        self.closed = True
        self.state.calls.append("socket_close")
        if not self.detached:
            self.state.fd_closes.append(("socket", FD))

    def settimeout(self, seconds):
        assert seconds == 5

    def connect(self, address):
        assert address == "/run/systemd/private"
        self.state.calls.append("connect")
        if self.state.failure == "connect":
            raise OSError("controlled private connect failure")

    def getsockopt(self, level, option, length):
        assert (level, option, length) == (1, 17, struct.calcsize("3i"))
        return self.state.peer_raw or struct.pack("3i", *self.state.peer)

    def fileno(self):
        assert not self.closed and not self.detached
        return FD

    def detach(self):
        assert not self.detached and not self.closed
        self.detached = True
        self.state.calls.append("detach")
        return FD


class FakeLibrary:
    def __init__(self, state):
        self.state = state
        self.messages = {}
        self.bus_owned_fd = False
        self.next_message = 100

    def rc(self, name, positive=0):
        self.state.calls.append(name)
        if name in self.state.rc_overrides:
            return self.state.rc_overrides[name]
        return -5 if self.state.failure == name else positive

    def allocate(self, output, kind):
        self.next_message += 1
        output._obj.value = self.next_message
        self.messages[self.next_message] = kind
        self.state.allocated.append(self.next_message)

    def sd_bus_new(self, output):
        rc = self.rc("new")
        if rc >= 0 or self.state.allocate_on_error:
            output._obj.value = 41 if not self.state.null_bus else None
        return rc

    def sd_bus_set_bus_client(self, bus, client):
        assert pointer_value(bus) == 41 and client == 0
        return self.rc("client")

    def sd_bus_set_method_call_timeout(self, bus, timeout):
        assert pointer_value(bus) == 41 and timeout == 5_000_000
        return self.rc("timeout")

    def sd_bus_set_fd(self, bus, input_fd, output_fd):
        assert pointer_value(bus) == 41 and input_fd == output_fd == FD
        rc = self.rc("set_fd")
        if rc >= 0:
            assert not self.bus_owned_fd
            self.bus_owned_fd = True
        return rc

    def sd_bus_start(self, bus):
        assert pointer_value(bus) == 41 and self.bus_owned_fd
        return self.rc("start")

    def sd_bus_call_method(
        self, bus, destination, path, interface, method, error, output, signature, unit
    ):
        assert pointer_value(bus) == 41
        assert (destination, path, interface, method) == (
            b"org.freedesktop.systemd1",
            b"/org/freedesktop/systemd1",
            b"org.freedesktop.systemd1.Manager",
            b"GetUnit",
        )
        assert error is None and signature == b"s" and unit.value == b"dbus.service"
        rc = self.rc("get_unit")
        if not self.state.null_message and (rc >= 0 or self.state.allocate_on_error):
            self.allocate(output, "unit")
        return rc

    def sd_bus_message_read_basic(self, message, kind, output):
        assert self.messages[pointer_value(message)] == "unit" and kind == b"o"
        output._obj.value = self.state.object_path
        return self.rc("read_path", 1)

    def sd_bus_get_property(
        self, bus, destination, path, interface, name, error, output, signature
    ):
        assert pointer_value(bus) == 41 and destination == b"org.freedesktop.systemd1"
        assert path == UNIT_PATH and interface == b"org.freedesktop.systemd1.Service"
        expected = {
            b"EnvironmentFiles": b"a(sb)",
            b"ExecStop": b"a(sasbttttuii)",
            b"ExecStopPost": b"a(sasbttttuii)",
        }
        assert name in expected and signature == expected[name] and error is None
        self.state.properties.append(name)
        rc = self.rc("get_property")
        if not self.state.null_property and (rc >= 0 or self.state.allocate_on_error):
            self.allocate(output, name)
        return rc

    def sd_bus_message_peek_type(self, message, kind, contents):
        name = self.messages[pointer_value(message)]
        kind._obj.value = self.state.array_kind
        signature = b"(sb)" if name == b"EnvironmentFiles" else b"(sasbttttuii)"
        contents._obj.value = self.state.contents_override or signature
        return self.rc("peek", 1)

    def sd_bus_message_enter_container(self, message, kind, signature):
        assert kind == b"a" and signature in {b"(sb)", b"(sasbttttuii)"}
        return self.rc("enter", 1)

    def sd_bus_message_at_end(self, message, complete):
        if self.messages[pointer_value(message)] == "unit":
            assert complete == 1
            return self.rc("unit_at_end", self.state.path_at_end)
        assert complete == 0
        return self.rc("array_at_end", 0 if self.state.nonempty else 1)

    def sd_bus_message_exit_container(self, message):
        assert self.messages[pointer_value(message)] != "unit"
        return self.rc("exit", 1)

    def sd_bus_message_unref(self, message):
        identifier = pointer_value(message)
        assert identifier in self.messages, "Message released twice or never allocated"
        self.messages.pop(identifier)
        self.state.unref_messages.append(identifier)

    def sd_bus_unref(self, bus):
        assert pointer_value(bus) == 41
        self.state.bus_unrefs += 1
        assert self.state.bus_unrefs == 1, "Bus released twice"
        if self.bus_owned_fd:
            self.state.fd_closes.append(("bus", FD))
            self.bus_owned_fd = False


@pytest.fixture
def peer(activation_env, monkeypatch):
    e = activation_env
    state = SimpleNamespace(
        calls=[],
        properties=[],
        allocated=[],
        unref_messages=[],
        fd_closes=[],
        bus_unrefs=0,
        failure=None,
        allocate_on_error=False,
        null_bus=False,
        null_message=False,
        null_property=False,
        peer=(1, 0, 0),
        peer_raw=None,
        object_path=UNIT_PATH,
        path_at_end=1,
        array_kind=b"a",
        contents_override=None,
        nonempty=False,
        rc_overrides={},
        metas=[SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_dev=1, st_ino=2)] * 2,
        metadata_reads=0,
        library_loads=0,
    )
    library = FakeLibrary(state)

    class SocketPath:
        def __init__(self, path):
            assert path == "/run/systemd/private"
            self.parents = (Path("/run/systemd"), Path("/run"), Path("/"))

        def __str__(self):
            return "/run/systemd/private"

        def lstat(self):
            index = min(state.metadata_reads, len(state.metas) - 1)
            state.metadata_reads += 1
            return state.metas[index]

    def socket_factory(family, kind):
        assert (family, kind) == (1, 2 | 4)
        state.calls.append("socket_new")
        state.channel = FakeChannel(state)
        return state.channel

    def load_library():
        state.library_loads += 1
        return library

    monkeypatch.setattr(e.module, "Path", SocketPath)
    monkeypatch.setattr(e.core, "directory", lambda *_a, **_k: None)
    monkeypatch.setattr(e.module, "_systemd_library", load_library)
    monkeypatch.setattr(
        e.module,
        "socket",
        SimpleNamespace(
            AF_UNIX=1,
            SOCK_STREAM=2,
            SOCK_CLOEXEC=4,
            SOL_SOCKET=1,
            SO_PEERCRED=17,
            socket=socket_factory,
        ),
    )
    return SimpleNamespace(**vars(e), peer_state=state, private_library=library)


def prove(e, missing=None):
    return e.module._prove_empty_properties(
        "dbus.service", set(e.module.EMPTY_COMPLEX_PROPERTIES) if missing is None else missing
    )


def assert_released(e, *, bus_created=True, fd_owner="bus"):
    state = e.peer_state
    assert Counter(state.allocated) == Counter(state.unref_messages)
    assert not e.private_library.messages
    assert state.bus_unrefs == int(bus_created)
    assert state.fd_closes == [(fd_owner, FD)]
    assert state.calls.count("socket_close") == 1


def test_private_pid1_peer_proves_only_three_typed_empty_arrays_and_releases_once(peer):
    prove(peer)
    state = peer.peer_state
    assert state.properties == [b"EnvironmentFiles", b"ExecStop", b"ExecStopPost"]
    assert state.calls.count("connect") == state.calls.count("detach") == 1
    assert state.calls.index("set_fd") < state.calls.index("detach") < state.calls.index("start")
    assert_released(peer)


@pytest.mark.parametrize("missing", [set(), {"ExecStart"}, {"Unknown"}, {"ExecStop", "User"}])
def test_unrecognized_missing_property_never_loads_library_or_connects(peer, missing):
    with pytest.raises(peer.core.Rejected):
        prove(peer, missing)
    assert peer.peer_state.calls == [] and peer.peer_state.library_loads == 0


@pytest.mark.parametrize("peer_identity", [(2, 0, 0), (1, 1000, 0), (0, 0, 0), (1, -1, 0)])
def test_wrong_private_peer_rejects_before_bus_ownership(peer, peer_identity):
    peer.peer_state.peer = peer_identity
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer, bus_created=False, fd_owner="socket")
    assert "new" not in peer.peer_state.calls


@pytest.mark.parametrize(
    "mode,owner",
    [(stat.S_IFREG | 0o600, 0), (stat.S_IFLNK | 0o777, 0), (stat.S_IFSOCK | 0o600, 1000)],
)
def test_private_endpoint_must_be_root_owned_unix_socket_before_connect(peer, mode, owner):
    peer.peer_state.metas = [SimpleNamespace(st_mode=mode, st_uid=owner, st_dev=1, st_ino=2)]
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert peer.peer_state.calls == [] and peer.peer_state.bus_unrefs == 0


def test_changed_private_socket_inode_rejects_and_socket_owner_closes(peer):
    peer.peer_state.metas = [
        SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_dev=1, st_ino=2),
        SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_dev=1, st_ino=3),
    ]
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer, bus_created=False, fd_owner="socket")


@pytest.mark.parametrize(
    "path",
    [
        None,
        b"/wrong/unit",
        b"/org/freedesktop/systemd1/unit/../escape",
        b"/org/freedesktop/systemd1/unit/dbus\nservice",
    ],
)
def test_get_unit_requires_one_bounded_object_path_and_releases_message(peer, path):
    peer.peer_state.object_path = path
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer)


@pytest.mark.parametrize(
    "failure",
    [
        "new",
        "client",
        "timeout",
        "set_fd",
        "start",
        "get_unit",
        "read_path",
        "unit_at_end",
        "get_property",
        "peek",
        "enter",
        "array_at_end",
        "exit",
    ],
)
def test_every_native_failure_releases_only_allocated_messages_bus_and_one_fd(peer, failure):
    state = peer.peer_state
    state.failure = failure
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(
        peer,
        bus_created=failure != "new",
        fd_owner="socket" if failure in {"new", "client", "timeout", "set_fd"} else "bus",
    )


@pytest.mark.parametrize("failure", ["new", "get_unit", "get_property"])
def test_error_with_partial_native_allocation_also_releases_once(peer, failure):
    state = peer.peer_state
    state.failure, state.allocate_on_error = failure, True
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer, fd_owner="socket" if failure == "new" else "bus")


@pytest.mark.parametrize("field", ["null_bus", "null_message", "null_property"])
def test_success_code_without_required_output_pointer_rejects(peer, field):
    setattr(peer.peer_state, field, True)
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(
        peer, bus_created=field != "null_bus", fd_owner="socket" if field == "null_bus" else "bus"
    )


@pytest.mark.parametrize(
    "field,value",
    [("array_kind", b"s"), ("contents_override", b"s"), ("nonempty", True), ("path_at_end", 0)],
)
def test_typed_reply_wrong_container_signature_nonempty_or_trailing_path_rejects(
    peer, field, value
):
    setattr(peer.peer_state, field, value)
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer)


def test_connect_failure_leaves_fd_with_socket_and_never_creates_bus(peer):
    peer.peer_state.failure = "connect"
    with pytest.raises(OSError):
        prove(peer)
    assert_released(peer, bus_created=False, fd_owner="socket")


@pytest.mark.parametrize("operation", ["read_path", "peek", "enter", "exit"])
def test_native_cursor_zero_is_not_success_and_still_cleans_up(peer, operation):
    peer.peer_state.rc_overrides[operation] = 0
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer)


@pytest.mark.parametrize("operation", ["unit_at_end", "array_at_end"])
def test_at_end_must_be_exactly_one(peer, operation):
    peer.peer_state.rc_overrides[operation] = 2
    with pytest.raises(peer.core.Rejected):
        prove(peer)
    assert_released(peer)


def test_invalid_peer_reply_size_closes_socket_without_bus_creation(peer):
    peer.peer_state.peer_raw = b"short"
    with pytest.raises(struct.error):
        prove(peer)
    assert_released(peer, bus_created=False, fd_owner="socket")


class CFunction:
    argtypes = None
    restype = None

    def __call__(self, *args):
        raise AssertionError("ABI-binding tests must not invoke any native function")


@pytest.fixture
def native_binding(activation_env, monkeypatch):
    e = activation_env
    calls = []
    functions = {
        name: CFunction()
        for name in (
            "sd_bus_new",
            "sd_bus_set_bus_client",
            "sd_bus_set_method_call_timeout",
            "sd_bus_set_fd",
            "sd_bus_start",
            "sd_bus_call_method",
            "sd_bus_message_read_basic",
            "sd_bus_get_property",
            "sd_bus_message_peek_type",
            "sd_bus_message_enter_container",
            "sd_bus_message_at_end",
            "sd_bus_message_exit_container",
            "sd_bus_message_unref",
            "sd_bus_unref",
        )
    }
    library = SimpleNamespace(**functions)
    state = SimpleNamespace(
        machine="x86_64", fail_trust=False, calls=calls, functions=functions, library=library
    )

    class LibraryPath:
        def __init__(self, value):
            self.value = str(value)

        def __truediv__(self, part):
            return LibraryPath(self.value.rstrip("/") + "/" + part)

        def __str__(self):
            return self.value

        def resolve(self, *, strict):
            assert strict is True
            calls.append(("resolve", self.value))
            return self

        @property
        def parents(self):
            return (Path("/usr/lib"), Path("/usr"), Path("/"))

    def trusted(path, maximum, *, private):
        assert maximum == 4 * 1024 * 1024 and private is False
        calls.append(("trusted_read", str(path)))
        if state.fail_trust:
            raise e.core.Rejected("controlled library trust failure")
        return b"bounded-trusted-native-library"

    def load(path):
        calls.append(("CDLL", path))
        return library

    monkeypatch.setattr(e.module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        e.module, "os", SimpleNamespace(uname=lambda: SimpleNamespace(machine=state.machine))
    )
    monkeypatch.setattr(e.module, "Path", LibraryPath)
    monkeypatch.setattr(
        e.core, "directory", lambda path, *, private: calls.append(("parent", str(path), private))
    )
    monkeypatch.setattr(e.core, "read_bytes", trusted)
    monkeypatch.setattr(
        e.module,
        "ctypes",
        SimpleNamespace(
            c_void_p=ctypes.c_void_p,
            c_char_p=ctypes.c_char_p,
            c_int=ctypes.c_int,
            c_uint64=ctypes.c_uint64,
            c_char=ctypes.c_char,
            POINTER=ctypes.POINTER,
            CDLL=load,
        ),
    )
    return SimpleNamespace(**vars(e), binding=state)


@pytest.mark.parametrize(
    "machine,triplet", [("x86_64", "x86_64-linux-gnu"), ("aarch64", "aarch64-linux-gnu")]
)
def test_systemd_ffi_uses_absolute_trusted_architecture_path_and_explicit_abi(
    native_binding, machine, triplet
):
    e = native_binding
    e.binding.machine = machine
    assert e.module._systemd_library() is e.binding.library
    calls = e.binding.calls
    filename = "/usr/lib/" + triplet + "/libsystemd.so.0"
    assert calls[0] == ("resolve", filename)
    assert calls[-2:] == [("trusted_read", filename), ("CDLL", filename)]
    pointer, string = ctypes.c_void_p, ctypes.c_char_p
    assert e.binding.functions["sd_bus_new"].argtypes == [ctypes.POINTER(pointer)]
    assert e.binding.functions["sd_bus_set_fd"].argtypes == [pointer, ctypes.c_int, ctypes.c_int]
    assert e.binding.functions["sd_bus_set_method_call_timeout"].argtypes == [
        pointer,
        ctypes.c_uint64,
    ]
    assert e.binding.functions["sd_bus_call_method"].argtypes == [
        pointer,
        string,
        string,
        string,
        string,
        pointer,
        ctypes.POINTER(pointer),
        string,
    ]
    assert e.binding.functions["sd_bus_get_property"].argtypes == [
        pointer,
        string,
        string,
        string,
        string,
        pointer,
        ctypes.POINTER(pointer),
        string,
    ]
    assert e.binding.functions["sd_bus_message_read_basic"].argtypes == [
        pointer,
        ctypes.c_char,
        pointer,
    ]
    assert e.binding.functions["sd_bus_message_peek_type"].argtypes == [
        pointer,
        ctypes.POINTER(ctypes.c_char),
        ctypes.POINTER(string),
    ]
    assert all(
        function.restype is (pointer if name.endswith("unref") else ctypes.c_int)
        for name, function in e.binding.functions.items()
    )


@pytest.mark.parametrize(
    "platform,machine", [("win32", "x86_64"), ("darwin", "aarch64"), ("linux", "mips")]
)
def test_unsupported_native_platform_or_architecture_has_no_library_search_or_load(
    native_binding, platform, machine
):
    e = native_binding
    e.module.sys.platform = platform
    e.binding.machine = machine
    with pytest.raises(e.core.Rejected):
        e.module._systemd_library()
    assert e.binding.calls == []


def test_untrusted_native_library_fails_before_loading_any_code(native_binding):
    e = native_binding
    e.binding.fail_trust = True
    with pytest.raises(e.core.Rejected):
        e.module._systemd_library()
    assert not any(call[0] == "CDLL" for call in e.binding.calls)
