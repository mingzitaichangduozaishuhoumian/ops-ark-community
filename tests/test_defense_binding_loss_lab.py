"""Pure local negative-fixture contracts; no servers, containers or real signals."""

import ast
import copy
import hashlib
import inspect
import os
import shutil
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import ssh_defense_binding_loss_lab as lab
from browser_defense_binding_loss_smoke import _restart_proof
from test_defense_transport_lab import FakeProcess
from test_defense_transport_lab import fake_io as fake_io

RID, REF, FIXTURE = "1" * 32, "2" * 32, "3" * 16
EXTRA = {
    "binding_loss_profile",
    "binding_loss_profile_sha256",
    "binding_loss_ref_sha256",
    "command_sha256",
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
        "schema": "opsark-protected-listener-restart-command/v1",
        "request_id": ref,
        "operation": lab.OPERATION,
        "fixture_id": FIXTURE,
        "binding_loss_ref": REF,
        "command_sha256": lab.native.digest(command(ref)),
    }


def metadata():
    return {
        "binding_loss_profile": lab.PROFILE,
        "binding_loss_profile_sha256": lab.PROFILE_SHA256,
        "binding_loss_ref": REF,
        "source_sha256": {"synthetic": "a" * 64},
    }


def frame(changed=False):
    fields = dict.fromkeys(lab.PRESERVED, "a" * 64)
    fields.update(
        root_binding_sha256="b" * 64,
        current_binding_sha256="e" * 64 if changed else "b" * 64,
        protected_process_sha256="f" * 64 if changed else "c" * 64,
        protected_listener_sha256="f" * 64 if changed else "d" * 64,
    )
    return {
        "fields": fields,
        "binding_matches": not changed,
        "usage_count": 1,
        "intent_count": 1,
        "prefix": {"identity": [1, 2], "length": 10, "sha256": "a" * 64},
        "request_id_sha256": hashlib.sha256(RID.encode()).hexdigest(),
        "manifest_sha256": "5" * 64,
        "identity_binding_sha256": "6" * 64,
    }


@pytest.fixture
def held(monkeypatch):
    value = cast(Any, lab.FixedProtected())
    old, new, protocol = FakeProcess(100), FakeProcess(200), FakeProcess(300)
    old.args = new.args = list(lab.ARGV)
    value.current, value.identity, value.starts = old, {"pid": 100, "start": 10}, 1
    transport = SimpleNamespace(current=protocol, starts=1, restart_count=0)
    trace = []
    frames = [frame(), frame(True)]

    def capture(protected, passed, prefix=None):
        assert passed is transport and passed.current is protocol
        if prefix is not None:
            assert prefix == frames[0]["prefix"]
        return frames[protected.current is new]

    def stop():
        trace.append(("stop", value.current.pid))
        value.current.wait(timeout=3)

    def start():
        assert old.poll() is not None
        trace.append(("start", 200))
        value.current, value.identity, value.starts = new, {"pid": 200, "start": 20}, 2
        return new

    monkeypatch.setattr(lab, "capture", capture)
    monkeypatch.setattr(
        lab, "protected_quiescent", lambda process: trace.append(("protected_quiet", process.pid))
    )
    monkeypatch.setattr(
        lab.previous, "no_inflight", lambda process: trace.append(("protocol_quiet", process.pid))
    )
    monkeypatch.setattr(value, "stop", stop)
    monkeypatch.setattr(value, "start", start)
    return SimpleNamespace(
        value=value,
        old=old,
        new=new,
        protocol=transport,
        trace=trace,
        frames=frames,
        counters={"prepare": 1, "provision": 1, "nft_initialize": 1, "root_initialize": 1},
    )


def test_one_protected_restart_keeps_protocol_and_root_but_proves_old_binding_invalid(held):
    h = held
    proof = h.value.restart(request(), metadata(), h.counters, h.protocol)
    assert h.trace == [
        ("protocol_quiet", 300),
        ("protected_quiet", 100),
        ("stop", 100),
        ("start", 200),
        ("protocol_quiet", 300),
        ("protected_quiet", 200),
    ]
    assert h.protocol.current.pid == 300 and h.protocol.current.poll() is None
    assert h.protocol.starts == 1 and h.protocol.restart_count == 0
    assert proof["execution_continuation_supported"] is False and proof["binding_changed"] is True
    core = {key: value for key, value in proof.items() if key not in EXTRA}
    assert _restart_proof(core, {"rid": RID, "ledger": frame()}) == core
    assert proof["binding_loss_ref_sha256"] == hashlib.sha256(REF.encode()).hexdigest()
    with pytest.raises(lab.native.LabError):
        h.value.restart(request(), metadata(), h.counters, h.protocol)
    assert len(h.trace) == 6
    h.value.stop()
    assert h.new.poll() is not None and h.protocol.current.poll() is None


@pytest.mark.parametrize("field", lab.PRESERVED)
def test_any_root_transport_authority_or_old_log_prefix_change_refuses_success(held, field):
    held.frames[1]["fields"][field] = "0" * 64
    with pytest.raises(lab.native.LabError):
        held.value.restart(request(), metadata(), held.counters, held.protocol)
    assert held.value.restart_count == 1
    held.value.stop()
    assert held.new.poll() is not None and held.protocol.current.poll() is None


@pytest.mark.parametrize("field", lab.REPLACED)
def test_reused_protected_birth_socket_or_binding_is_not_a_negative_restart(held, field):
    held.frames[1]["fields"][field] = held.frames[0]["fields"][field]
    with pytest.raises(lab.native.LabError):
        held.value.restart(request(), metadata(), held.counters, held.protocol)
    assert held.value.restart_count == 1


def test_invalid_original_binding_is_not_adopted_or_repaired(held):
    held.frames[0]["binding_matches"] = False
    with pytest.raises(lab.native.LabError):
        held.value.restart(request(), metadata(), held.counters, held.protocol)
    assert held.value.starts == 1 and held.old.poll() is None
    assert not any(item[0] in {"start", "stop"} for item in held.trace)


def test_unchanged_held_protocol_is_required_even_for_direct_method_use(held):
    with pytest.raises(lab.native.LabError):
        held.value.restart(request(), metadata(), held.counters)
    assert held.trace == [] and held.value.restart_count == 0


def test_frozen_root_bound_rejects_new_listener_without_mutating_original_state(monkeypatch):
    from deploy.defense import ssh_fixture as fixture
    from deploy.defense import ssh_requests as root

    original = {"boot_ref": "a" * 64, "binding": [1, 2, 3, 100, 10, 111, 4, 5]}
    copied = copy.deepcopy(original)
    monkeypatch.setattr(root, "_boot", lambda: "a" * 64)
    monkeypatch.setattr(
        fixture, "_bound_listener", lambda directory, profile: [1, 2, 3, 200, 20, 222, 4, 5]
    )
    with pytest.raises(root.Refused) as refused:
        root._bound(original, 0)
    assert refused.value.code == "binding_changed" and original == copied


def test_source17_strongly_pins_sixteen_and_does_not_expand_state_profile(fake_io):
    root = Path(lab.__file__).resolve().parents[1]
    sources = lab.verify_source_closure(root)
    assert (
        len(sources) == 17 and sources["tests/ssh_defense_transport_lab.py"] == lab.TRANSPORT_SHA256
    )
    assert all(b"\r\n" not in (root / name).read_bytes() for name in sources)
    assert lab.previous.OPERATION not in lab.OPERATIONS
    assert lab.business.STATE_PROFILE["sshd_restart_supported"] is False
    assert lab.business.STATE_PROFILE["target_bind_count"] == 3
    assert (lab.base.LIFETIME_SECONDS, lab.base.WORK_SECONDS, lab.base.CLEANUP_SECONDS) == (
        600,
        480,
        120,
    )


def test_fresh_stage_finishes17_authorities_before_any_container(tmp_path, monkeypatch, fake_io):
    root = Path(lab.__file__).resolve().parents[1]
    previous_sources = lab._SOURCE(root)
    calls = []

    def old_stage(workspace, policy, expected):
        assert lab.previous.verify_source_closure is lab._SOURCE
        calls.append(expected)
        for name in ("code", "authority", "client", "management", "ready", "state"):
            (workspace / name).mkdir()
        for name in previous_sources:
            dst = workspace / "code" / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, dst)
        lab.base.write_new(
            workspace / "authority" / lab.previous.PROFILE_FILE,
            {
                "transport_profile": lab.previous.PROFILE,
                "transport_profile_sha256": lab.previous.PROFILE_SHA256,
                "transport_ref": "7" * 32,
                "source_sha256": previous_sources,
            },
        )
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

    monkeypatch.setattr(lab, "_STAGE", old_stage)
    monkeypatch.setattr(
        lab.business, "copy_source", lambda source, dest: shutil.copyfile(source, dest)
    )
    monkeypatch.setattr(lab.session, "sync_directory", lambda directory: None)
    result = lab.stage(tmp_path, tmp_path / "policy", lab.session.profile_metadata("auto-ack"))
    value = lab.base.read_json(result[3] / lab.PROFILE_FILE)
    inherited = lab.base.read_json(result[3] / lab.previous.PROFILE_FILE)
    assert len(value["source_sha256"]) == len(inherited["source_sha256"]) == 17
    assert inherited["transport_ref"] == "7" * 32 and not any(result[5].iterdir())
    assert lab.validate_metadata(value, result[0]) == value and len(calls) == 1


@pytest.mark.parametrize("action", ["status", lab.OPERATION])
def test_cli_new_operation_and_source17_are_used(tmp_path, monkeypatch, capsys, fake_io, action):
    calls = []

    def existing(root):
        assert lab.session.verify_source_closure is lab.verify_source_closure
        calls.append("source17")

    monkeypatch.setattr(lab.session, "existing_profile", existing)
    monkeypatch.setattr(lab.business, "status", lambda root: {"ready": True})
    monkeypatch.setattr(lab.business, "command", lambda root, op, ref: {"completed": True})
    args = [action, "--root", str(tmp_path), "--image", "sha256:" + "a" * 64, "--confirm-isolated"]
    if action == lab.OPERATION:
        args.extend(["--request-id", "4" * 32])
    assert lab.main(args) == 0 and calls == ["source17"]
    assert "true" in capsys.readouterr().out


def test_cli_and_direct_operation_both_refuse_protocol_restart(tmp_path, capsys):
    with pytest.raises(SystemExit):
        lab.main([lab.previous.OPERATION])
    assert "invalid choice" in capsys.readouterr().err
    with pytest.raises(lab.native.LabError):
        lab.process_command({"operation": lab.previous.OPERATION}, tmp_path, None, None, {})


def test_snapshot_is_explicitly_local_and_untrusted_when_binding_is_lost(monkeypatch):
    monkeypatch.setattr(lab, "_SNAPSHOT", lambda network, target: {"usage_count": 1, "intents": 1})
    monkeypatch.setattr(
        lab.base,
        "projection",
        lambda network, target: {
            "binding_matches": False,
            "binding_ref": "a" * 64,
            "current_binding_sha256": "b" * 64,
        },
    )
    value = lab.independent_snapshot(None, None)
    assert value["binding_matches"] is False and value["trusted_current_root_observation"] is False
    assert value["source_category"] == lab.SOURCE_CATEGORY
    assert value["original_binding_sha256"] != value["current_binding_sha256"]


def test_host_claim_is_single_use_and_public_result_is_core_plus_four(
    tmp_path, monkeypatch, fake_io, held
):
    workspace = tmp_path / "workspace"
    (workspace / "ready").mkdir(parents=True)
    (workspace / "authority").mkdir()
    meta = metadata()
    lab.base.write_new(workspace / "authority" / lab.PROFILE_FILE, meta)
    proof = held.value.restart(request(), meta, held.counters, held.protocol)
    lab.base.write_new(
        workspace / "ready" / lab.RESULT,
        {
            "schema": "opsark-protected-listener-restart-result/v1",
            "completed": True,
            "command_sha256": request()["command_sha256"],
            "binding_loss_ref_sha256": lab.ref_sha(REF),
            "proof": proof,
        },
    )
    monkeypatch.setattr(lab, "verify_source_closure", lambda root: meta["source_sha256"])
    monkeypatch.setattr(
        lab.native, "socket_signal_ready", lambda path: path.name == lab.RESULT_READY
    )
    network = SimpleNamespace(workspace=workspace, fixture=FIXTURE)
    with lab.bound_profile(), lab.previous.bound_transport():
        result = lab.process_command(command(), tmp_path, network, None, {})
        assert result == proof and EXTRA.issubset(result)
        with pytest.raises(lab.native.LabError):
            lab.process_command(command("7" * 32), tmp_path, network, None, {})
    assert (tmp_path / (lab.PREFIX + ".once.json")).exists()
    assert (workspace / "ready" / lab.REQUEST_READY).exists()


def test_cached_same_command_returns_receipt_without_second_restart(tmp_path, monkeypatch, fake_io):
    original = command()
    result = {
        "request_id": original["request_id"],
        "operation": lab.OPERATION,
        "command_sha256": lab.native.digest(original),
        "completed": True,
        "result": {"restart_count": 1, "execution_continuation_supported": False},
    }
    for directory in ("controller-commands", "controller-results"):
        (tmp_path / directory).mkdir()
    lab.base.write_new(tmp_path / "controller-ready.json", {"fixture_id": FIXTURE})
    lab.base.write_new(
        tmp_path / "controller-commands" / (original["request_id"] + ".json"), original
    )
    lab.base.write_new(tmp_path / "controller-results" / (original["request_id"] + ".json"), result)
    monkeypatch.setattr(
        lab.business, "live_resources", lambda value: pytest.fail("Cached result rebuilt a fixture")
    )
    with lab.bound_profile(), lab.previous.bound_transport():
        assert lab.business.command(tmp_path, lab.OPERATION, original["request_id"]) == result


def test_failed_protected_ready_keeps_exact_child_for_inherited_pidfd_cleanup(monkeypatch):
    value = lab.FixedProtected()
    process = FakeProcess(100)
    process.args = list(lab.ARGV)
    record = {"pid": 100, "ppid": os.getpid(), "start": 10, "uid": 0, "state": "S"}
    times = iter(range(20))
    signals = []
    monkeypatch.setattr(lab.native.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(lab.native, "process_record", lambda pid: dict(record))
    monkeypatch.setattr(lab.native, "verify_program", lambda record, executable: None)
    monkeypatch.setattr(lab.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(lab.time, "sleep", lambda seconds: None)

    def unavailable(process):
        raise lab.native.LabError("synthetic missing protected readiness")

    monkeypatch.setattr(lab, "protected_identity", unavailable)
    monkeypatch.setattr(lab.os, "pidfd_open", lambda pid: 999, raising=False)
    monkeypatch.setattr(
        lab.previous.signal,
        "pidfd_send_signal",
        lambda fd, signal: signals.append((fd, signal)),
        raising=False,
    )
    monkeypatch.setattr(lab.os, "close", lambda fd: None)
    with pytest.raises(lab.native.LabError):
        value.start()
    assert value.current is process and value.identity == lab.native.process_identity(record)
    value.stop()
    assert process.poll() is not None and signals == [(999, lab.previous.signal.SIGTERM)]


def test_restart_contains_no_rebind_initialize_or_protocol_start_calls():
    source = textwrap.dedent(inspect.getsource(lab.FixedProtected.restart))
    calls = [
        node.func
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert all(
        node.attr
        not in {"_initialize", "initialize", "prepare_ssh", "provision_roles", "run", "_save"}
        for node in calls
    )
    assert all(
        isinstance(node.value, ast.Name) and node.value.id == "self"
        for node in calls
        if node.attr in {"start", "stop"}
    )
    assert lab.previous.FixedTransport.stop is lab.FixedProtected.stop
