"""Pure fake processes/files only. No Docker, SSH, Linux signal or server I/O."""

import ast
import hashlib
import inspect
import os
import shutil
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import ssh_defense_transport_lab as lab
from browser_defense_transport_restart_smoke import _restart_proof

RID = "1" * 32
REF = "2" * 32
FIXTURE = "3" * 16
PUBLIC_EXTRA = {
    "transport_profile",
    "transport_profile_sha256",
    "transport_ref_sha256",
    "command_sha256",
}


@pytest.fixture
def fake_io(monkeypatch):
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit, **kwargs: path.read_bytes())

    def create(path, raw, *, mode=0o600):
        with path.open("xb") as output:
            output.write(raw)
        path.chmod(mode)

    monkeypatch.setattr(lab.native, "owned_create", create)
    monkeypatch.setattr(lab.native, "require_root", lambda root: None)
    monkeypatch.setattr(lab.native, "publish_socket_signal", lambda path: create(path, b"ready\n"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(lab.native.canonical(value) + b"\n")


def metadata(sources=None):
    return {
        "transport_profile": lab.PROFILE,
        "transport_profile_sha256": lab.PROFILE_SHA256,
        "transport_ref": REF,
        "source_sha256": sources or {"synthetic": "a" * 64},
    }


def command(ref="4" * 32):
    return {
        "schema": "opsark-controller-command/v1",
        "request_id": ref,
        "operation": lab.OPERATION,
        "fixture_id": FIXTURE,
    }


def request(ref="4" * 32):
    return {
        "schema": "opsark-root-transport-restart-command/v1",
        "request_id": ref,
        "operation": lab.OPERATION,
        "fixture_id": FIXTURE,
        "transport_ref": REF,
        "command_sha256": lab.native.digest(command(ref)),
    }


def state(replaced=False):
    fields = dict.fromkeys(lab.IMMUTABLE_FIELDS, "a" * 64)
    fields.update(dict.fromkeys(lab.TRANSPORT_FIELDS, "c" * 64 if replaced else "b" * 64))
    return {
        "fields": fields,
        "request_id_sha256": hashlib.sha256(RID.encode()).hexdigest(),
        "manifest_sha256": "d" * 64,
        "identity_binding_sha256": "e" * 64,
        "usage_count": 1,
        "intent_count": 1,
    }


class FakeProcess:
    def __init__(self, pid):
        self.pid, self.args, self.returncode = pid, list(lab.ARGV), None
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, *, timeout):
        self.waits.append(timeout)
        self.returncode = 0
        return 0


@pytest.fixture
def transport(monkeypatch):
    value = cast(Any, lab.FixedTransport())
    old, new = FakeProcess(100), FakeProcess(200)
    value.current, value.identity, value.starts = old, {"pid": 100, "start": 10}, 1
    trace = []
    observations = [state(), state(True)]
    monkeypatch.setattr(
        lab, "no_inflight", lambda process: trace.append(("quiescent", process.pid))
    )
    monkeypatch.setattr(lab, "snapshot", lambda process: observations[process is new])

    def stop():
        trace.append(("stop", value.current.pid))
        value.current.wait(timeout=3)

    def start():
        assert old.poll() is not None
        trace.append(("start", 200))
        value.current, value.identity, value.starts = new, {"pid": 200, "start": 20}, 2
        return new

    monkeypatch.setattr(value, "stop", stop)
    monkeypatch.setattr(value, "start", start)
    return SimpleNamespace(
        value=value,
        old=old,
        new=new,
        trace=trace,
        states=observations,
        counters={"prepare": 1, "provision": 1, "nft_initialize": 1, "root_initialize": 1},
    )


def test_restart_holds_reaps_then_replaces_only_current_child_once(transport):
    t = transport
    proof = t.value.restart(request(), metadata(), t.counters)
    assert t.trace == [("quiescent", 100), ("stop", 100), ("start", 200), ("quiescent", 200)]
    assert t.old.poll() is not None and t.new.poll() is None and t.value.current is t.new
    assert t.value.starts == 2 and proof["restart_count"] == 1
    assert proof["transport_ref_sha256"] == hashlib.sha256(REF.encode("ascii")).hexdigest()
    assert proof["command_sha256"] == lab.native.digest(command())
    core = {key: value for key, value in proof.items() if key not in PUBLIC_EXTRA}
    assert _restart_proof(core, {"rid": RID, "ledger": state()}) == core
    with pytest.raises(lab.native.LabError):
        t.value.restart(request(), metadata(), t.counters)
    assert len(t.trace) == 4
    t.value.stop()
    assert t.new.poll() is not None and t.trace[-1] == ("stop", 200)


@pytest.mark.parametrize("field", lab.IMMUTABLE_FIELDS)
def test_any_protected_state_or_authority_change_rejects_without_another_restart(transport, field):
    t = transport
    t.states[1]["fields"][field] = "f" * 64
    with pytest.raises(lab.native.LabError):
        t.value.restart(request(), metadata(), t.counters)
    assert t.value.restart_count == 1 and t.value.current is t.new
    with pytest.raises(lab.native.LabError):
        t.value.restart(request(), metadata(), t.counters)
    t.value.stop()
    assert t.new.poll() is not None


@pytest.mark.parametrize("field", lab.TRANSPORT_FIELDS)
def test_old_transport_identity_or_socket_is_not_accepted_as_a_restart(transport, field):
    transport.states[1]["fields"][field] = transport.states[0]["fields"][field]
    with pytest.raises(lab.native.LabError):
        transport.value.restart(request(), metadata(), transport.counters)
    assert transport.value.restart_count == 1


def test_busy_original_transport_is_refused_before_any_signal_or_spawn(transport, monkeypatch):
    def busy(_process):
        raise lab.native.LabError("Synthetic in-flight request")

    monkeypatch.setattr(lab, "no_inflight", busy)
    with pytest.raises(lab.native.LabError):
        transport.value.restart(request(), metadata(), transport.counters)
    assert transport.trace == [] and transport.old.poll() is None
    assert transport.value.restart_count == 1 and transport.value.starts == 1


@pytest.mark.parametrize(
    "change",
    [
        {"operation": "restart"},
        {"pid": 100},
        {"argv": ["/bin/sh"]},
        {"transport_ref": "f" * 32},
        {"fixture_id": "other"},
        {"request_id": "bad"},
        {"command_sha256": "f" * 64},
    ],
)
def test_restart_request_never_accepts_pid_shell_scope_or_changed_command(change):
    with pytest.raises(lab.native.LabError):
        lab.checked_request(request() | change, metadata())


def test_listener_checks_exact_22423_pid_birth_and_socket_owner(monkeypatch):
    process = FakeProcess(100)
    record = {"pid": 100, "ppid": os.getpid(), "start": 10, "uid": 0, "state": "S"}
    suffix = f":{22423:04X}"
    row = ["0:", "02F112C6" + suffix, "00000000:0000", "0A", "0:0", "0:0", "0", "0", "0", "12345"]
    raw = ["header\n" + " ".join(row) + "\n"]
    children = [b""]

    class Proc:
        def __init__(self, value):
            self.value = str(value)

        def __truediv__(self, value):
            return Proc(self.value + "/" + str(value))

        def read_text(self, **kwargs):
            assert self.value == "/proc/net/tcp"
            return raw[0]

        def read_bytes(self):
            assert self.value.endswith("/task/100/children")
            return children[0]

        def iterdir(self):
            assert self.value == "/proc/100/fd"
            return [SimpleNamespace(is_symlink=lambda: True)]

    monkeypatch.setattr(lab, "Path", Proc)
    monkeypatch.setattr(lab.native, "process_record", lambda pid: dict(record))
    monkeypatch.setattr(lab.native, "verify_program", lambda record, executable: None)
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit, **kwargs: b"100\n")
    monkeypatch.setattr(lab.os, "readlink", lambda path: "socket:[12345]")
    monkeypatch.setattr(lab.native, "request_connections", lambda: [])
    identity, inode = lab.listener_identity(process)
    assert identity["pid"] == 100 and inode == 12345 and suffix == ":5797"
    assert lab.no_inflight(process) == identity
    children[0] = b"201"
    with pytest.raises(lab.native.LabError):
        lab.no_inflight(process)
    children[0] = b""
    raw[0] = raw[0].replace(":5797", ":5796")
    with pytest.raises(lab.native.LabError):
        lab.listener_identity(process)


def test_successful_exec_without_ready_still_has_bound_cleanup_identity(monkeypatch):
    transport = lab.FixedTransport()
    process = FakeProcess(100)
    record = {"pid": 100, "ppid": os.getpid(), "start": 10, "uid": 0, "state": "S"}
    signals, closed = [], []
    times = iter(range(20))
    monkeypatch.setattr(lab.native.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(lab.native, "process_record", lambda pid: dict(record))
    monkeypatch.setattr(lab.native, "verify_program", lambda record, executable: None)
    monkeypatch.setattr(lab.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(lab.time, "sleep", lambda seconds: None)

    def unavailable(_process):
        raise lab.native.LabError("Synthetic missing PID/listener")

    monkeypatch.setattr(lab, "listener_identity", unavailable)
    monkeypatch.setattr(lab.os, "pidfd_open", lambda pid: 999, raising=False)
    monkeypatch.setattr(
        lab.signal,
        "pidfd_send_signal",
        lambda fd, signal: signals.append((fd, signal)),
        raising=False,
    )
    monkeypatch.setattr(lab.os, "close", lambda fd: closed.append(fd))
    with pytest.raises(lab.native.LabError):
        transport.start()
    assert transport.current is process and transport.identity == lab.native.process_identity(
        record
    )
    transport.stop()
    assert process.poll() is not None and signals == [(999, lab.signal.SIGTERM)] and closed == [999]
    with pytest.raises(lab.native.LabError):
        transport.start()


def test_exact_child_identity_change_refuses_signal(monkeypatch):
    transport = cast(Any, lab.FixedTransport())
    transport.current, transport.identity = (
        FakeProcess(100),
        {"pid": 100, "ppid": os.getpid(), "start": 10, "uid": 0},
    )
    monkeypatch.setattr(
        lab.native,
        "process_record",
        lambda pid: {"pid": 100, "ppid": os.getpid(), "start": 11, "uid": 0},
    )
    monkeypatch.setattr(
        lab.os, "pidfd_open", lambda pid: pytest.fail("Unbound PID opened"), raising=False
    )
    with pytest.raises(lab.native.LabError):
        transport.stop()


def test_source_sixteen_preserves_every_frozen_fifteen_lf_and_sha(fake_io):
    root = Path(lab.__file__).resolve().parents[1]
    sources = lab.verify_source_closure(root)
    assert len(sources) == 16
    assert sources["tests/ssh_defense_session_lab.py"] == lab.SESSION_SHA256
    assert all(b"\r\n" not in (root / name).read_bytes() for name in sources)
    assert len(lab.ENV) == 2
    assert (lab.base.LIFETIME_SECONDS, lab.base.WORK_SECONDS, lab.base.CLEANUP_SECONDS) == (
        600,
        480,
        120,
    )
    assert lab.business.STATE_PROFILE["target_bind_count"] == 3
    assert len(lab.OPERATIONS - lab.business.OPERATIONS) == 1


def test_stage_adds_only_new_source_and_fresh_transport_authority(tmp_path, monkeypatch, fake_io):
    root = Path(lab.__file__).resolve().parents[1]
    sources = lab._SOURCE_CLOSURE(root)
    calls = []

    def previous_stage(workspace, policy, expected):
        calls.append(expected)
        assert lab.session.verify_source_closure is lab._SOURCE_CLOSURE
        for name in ("code", "authority", "client", "management", "ready", "state"):
            (workspace / name).mkdir()
        for name in sources:
            destination = workspace / "code" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        return (
            workspace / "code",
            workspace / "client",
            workspace / "management",
            workspace / "authority",
            workspace / "ready",
            workspace / "state",
            {},
            {},
        )

    def copy_source(source, destination):
        assert not destination.exists()
        shutil.copyfile(source, destination)

    monkeypatch.setattr(lab, "_STAGE_SESSION", previous_stage)
    monkeypatch.setattr(lab.business, "copy_source", copy_source)
    result = lab.stage_transport(
        tmp_path, tmp_path / "policy", lab.session.profile_metadata("auto-ack")
    )
    meta = lab.base.read_json(result[3] / lab.PROFILE_FILE)
    assert len(meta["source_sha256"]) == 16 and len(calls) == 1
    assert meta["transport_profile_sha256"] == lab.PROFILE_SHA256
    assert lab.validate_metadata(meta, result[0]) == meta
    with pytest.raises(lab.native.LabError):
        lab.stage_transport(
            tmp_path, tmp_path / "policy", lab.session.profile_metadata("auto-apply-loss")
        )
    assert len(calls) == 1


def test_host_once_claim_binds_private_result_then_returns_core_plus_four(
    tmp_path, monkeypatch, fake_io, transport
):
    workspace = tmp_path / "workspace"
    (workspace / "ready").mkdir(parents=True)
    (workspace / "authority").mkdir()
    meta = metadata()
    write(workspace / "authority" / lab.PROFILE_FILE, meta)
    proof = transport.value.restart(request(), meta, transport.counters)
    write(
        workspace / "ready" / lab.RESULT,
        {
            "schema": "opsark-root-transport-restart-result/v1",
            "completed": True,
            "command_sha256": request()["command_sha256"],
            "transport_ref_sha256": lab.transport_ref_sha256(REF),
            "proof": proof,
        },
    )
    monkeypatch.setattr(lab, "verify_source_closure", lambda root: meta["source_sha256"])
    monkeypatch.setattr(
        lab.native, "socket_signal_ready", lambda path: path.name == lab.RESULT_READY
    )
    network = SimpleNamespace(workspace=workspace, fixture=FIXTURE)
    with lab.bound_transport():
        actual = lab.process_command(command(), tmp_path, network, None, {})
        assert actual == proof and PUBLIC_EXTRA.issubset(actual)
        with pytest.raises(lab.native.LabError):
            lab.process_command(command("5" * 32), tmp_path, network, None, {})
    assert (tmp_path / (lab.PREFIX + ".once.json")).exists()
    assert (workspace / "ready" / lab.REQUEST_READY).exists()


def test_original_mailbox_cached_result_never_dispatches_restart_again(
    tmp_path, monkeypatch, fake_io
):
    original = command()
    answer = {
        "request_id": original["request_id"],
        "operation": lab.OPERATION,
        "command_sha256": lab.native.digest(original),
        "completed": True,
        "result": {"restart_count": 1},
    }
    write(tmp_path / "controller-ready.json", {"fixture_id": FIXTURE})
    write(tmp_path / "controller-commands" / (original["request_id"] + ".json"), original)
    write(tmp_path / "controller-results" / (original["request_id"] + ".json"), answer)
    monkeypatch.setattr(
        lab.business,
        "live_resources",
        lambda ready: pytest.fail("Cached command recreated resources"),
    )
    with lab.bound_transport():
        assert lab.business.command(tmp_path, lab.OPERATION, original["request_id"]) == answer


@pytest.mark.parametrize("action", ["status", lab.OPERATION])
def test_cli_dynamic_operation_and_existing_source_check_use_sixteen(
    tmp_path, monkeypatch, capsys, fake_io, action
):
    calls = []

    def existing(root):
        assert lab.session.verify_source_closure is lab.verify_source_closure
        calls.append(("source16", root))

    monkeypatch.setattr(lab.session, "existing_profile", existing)
    monkeypatch.setattr(lab.business, "status", lambda root: {"ready": True})
    monkeypatch.setattr(
        lab.business,
        "command",
        lambda root, op, ref: calls.append((op, ref)) or {"completed": True},
    )
    args = [action, "--root", str(tmp_path), "--image", "sha256:" + "a" * 64, "--confirm-isolated"]
    if action == lab.OPERATION:
        args += ["--request-id", "4" * 32]
    assert lab.main(args) == 0
    assert calls[0] == ("source16", tmp_path)
    assert "true" in capsys.readouterr().out


def test_restart_method_contains_no_reprovision_initialize_or_private_key_read():
    source = inspect.getsource(lab.FixedTransport.restart)
    calls = {
        node.func.attr
        for node in ast.walk(ast.parse(textwrap.dedent(source)))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not calls & {"provision_roles", "prepare_ssh", "run", "_initialize", "initialize"}
    source = inspect.getsource(lab.snapshot)
    assert (
        '"key_file_identity_sha256": native.digest(_file_identity(FIXTURE_ROOT / "host"))' in source
    )
    assert '_public_sha(FIXTURE_ROOT / "host")' not in source
