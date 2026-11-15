"""Exercise the real bounded client with owned synthetic keys and fake Paramiko only."""

import hashlib
import os
import shutil
import sys
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.defense import request_protocol as root_wire
from opsark import defense_client as client
from opsark.config import HostConfig
from opsark.defense_models import (
    POLICY_SHA256,
    DefenseCall,
    DefenseCandidate,
    DefenseManifest,
    DefenseReply,
    DefenseRequest,
    canonical,
    rebuild_manifest,
)
from opsark.models import HostPublic

RID, CURSOR, SOURCE, ACTION = (c * 32 for c in "abcd")
SCOPE, BOOT, BINDING, EVIDENCE = (c * 64 for c in "1234")
DEADLINE = "2026-11-06T10:00:00.000000Z"


@pytest.fixture(scope="module")
def keyset():
    return tuple(paramiko.ECDSAKey.generate() for _ in range(6))


def write_key(path, key):
    key.write_private_key_file(str(path))
    path.chmod(0o600)
    return path


@pytest.fixture
def target(tmp_path, keyset):
    known = tmp_path / "defense-hosts"
    known.write_text(f"[192.0.2.10]:22423 {keyset[0].get_name()} {keyset[0].get_base64()}\n")
    collector = write_key(tmp_path / "collector", keyset[1])
    apt = write_key(tmp_path / "apt", keyset[5])
    host = HostConfig(
        HostPublic(
            id="fixture",
            name="fixture",
            address="192.0.2.10",
            port=22,
            username="opsark-readonly",
            source="ssh",
        ),
        collector,
        known,
    )
    credentials = [
        client.RoleCredential(
            "defense-" + role,
            22423,
            write_key(tmp_path / role, keyset[index]),
            known,
            hashlib.sha256(known.read_bytes()).hexdigest(),
        )
        for index, role in enumerate(("readonly", "observe", "control"), 2)
    ]
    return client.DefenseTarget(host, *credentials, SCOPE, POLICY_SHA256, BOOT, BINDING, (apt,))


def request(op="prepare", **fields):
    bodies = {
        "arm": {"observation_grant_ref": "f" * 32, "policy_sha256": POLICY_SHA256},
        "prepare": {
            "cursor_id": CURSOR,
            "source_ref": SOURCE,
            "evidence_sha256": EVIDENCE,
            "policy_sha256": POLICY_SHA256,
            "mode": "semi",
            "mode_revision": 2,
            "controller_grant_ref": "e" * 32,
            "root_grant_ref": "f" * 32,
        },
        "query": {"kind": "action"},
        "mode_sync": {"mode": "semi", "mode_revision": 2, "policy_sha256": POLICY_SHA256},
    }
    return DefenseRequest.model_validate(
        {
            "v": 1,
            "op": op,
            "request_id": RID,
            "scope_sha256": SCOPE,
            "body": bodies.get(op, {}) | fields,
        }
    )


def reply(op="prepare", **changes):
    value = {
        "v": 1,
        "op": op,
        "request_id": RID,
        "scope_sha256": SCOPE,
        "policy_sha256": POLICY_SHA256,
        "boot_ref": BOOT,
        "binding_ref": BINDING,
        "mode": "semi",
        "mode_revision": 2,
        "state": "ready",
        "action_id": ACTION,
        "cursor_id": CURSOR,
        "manifest_sha256": "0" * 64,
        "deadline_at": DEADLINE,
        "remaining_ms": None,
        "reason_code": "ok",
        "candidates": [],
    }
    manifest = rebuild_manifest(request(), DefenseReply.model_validate(value))
    return value | {"manifest_sha256": manifest.sha256} | changes


def action_call(op="query", *, expected=True, **fields):
    manifest = rebuild_manifest(request(), DefenseReply.model_validate(reply()))
    req = (
        request(op, **fields)
        if op == "query"
        else DefenseRequest.model_validate(
            {
                "v": 1,
                "op": op,
                "request_id": RID,
                "scope_sha256": SCOPE,
                "body": {"manifest_sha256": manifest.sha256, "approval": None} | fields,
            }
        )
    )
    return DefenseCall(req, request(), manifest if expected else None)


class Channel:
    def __init__(self, output=None, *, errors=b"", code=0):
        self.output = bytearray(canonical(reply()) + b"\n" if output is None else output)
        self.errors = bytearray(errors)
        self.code = code
        self.sent = []
        self.closed = False
        self.eof_received = True
        self.never_finish = False
        self.fail_send = False
        self.late_output = b""
        self.late_error = b""
        self.exit_calls = 0

    def settimeout(self, _timeout):
        pass

    def sendall(self, body):
        self.sent.append(body)
        if self.fail_send:
            raise OSError("sensitive path and private wire must not escape")

    def shutdown_write(self):
        pass

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv(self, count):
        # Fragmentation exercises actual drains rather than one convenient readline.
        count = min(count, 31)
        chunk = bytes(self.output[:count])
        del self.output[:count]
        return chunk

    def recv_stderr(self, count):
        chunk = bytes(self.errors[:count])
        del self.errors[:count]
        return chunk

    def exit_status_ready(self):
        return not self.never_finish

    def recv_exit_status(self):
        self.exit_calls += 1
        self.output.extend(self.late_output)
        self.errors.extend(self.late_error)
        self.late_output = self.late_error = b""
        return self.code

    def close(self):
        self.closed = True


class Client:
    def __init__(self):
        self.channel = Channel()
        self.keys = paramiko.HostKeys()
        self.connect_calls = []
        self.exec_calls = []
        self.closed = threading.Event()
        self.connect_error = self.exec_error = None
        self.block_exec = False

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.keys

    def connect(self, hostname, **options):
        self.connect_calls.append((hostname, options))
        if self.connect_error:
            raise self.connect_error

    def exec_command(self, command, **options):
        self.exec_calls.append((command, options))
        if self.block_exec:
            assert self.closed.wait(1)
            raise EOFError("sensitive exec interruption")
        if self.exec_error:
            raise self.exec_error
        stream = SimpleNamespace(channel=self.channel)
        return stream, stream, stream

    def close(self):
        self.closed.set()


@pytest.fixture
def ssh(monkeypatch):
    instance = Client()
    monkeypatch.setattr(client.paramiko, "SSHClient", lambda: instance)
    return instance


def test_real_paramiko_stdin_wrapper_cannot_send_eof_before_request(target, ssh, monkeypatch):
    events = []

    class OrderedChannel(Channel):
        def sendall(self, body):
            assert not any(event[0] == "eof" for event in events)
            events.append(("request", body))
            super().sendall(body)

        def shutdown_write(self):
            events.append(("eof", len(self.sent)))

    ssh.channel = OrderedChannel()

    def execute(command, **options):
        ssh.exec_calls.append((command, options))
        return (
            paramiko.channel.ChannelStdinFile(ssh.channel, "wb"),
            paramiko.channel.ChannelFile(ssh.channel, "rb"),
            paramiko.channel.ChannelStderrFile(ssh.channel, "rb"),
        )

    monkeypatch.setattr(ssh, "exec_command", execute)
    result = client.invoke(target, request(), "control")
    assert result.reply.state == "ready"
    assert events[0] == ("request", request().wire_bytes())
    assert events[1] == ("eof", 1)
    assert len(ssh.exec_calls) == len(ssh.channel.sent) == 1


def test_once_dedicated_role_bound_reply_and_root_exact_manifest(target, ssh):
    result = client.invoke(target, request(), "control")
    assert result.reply.state == "ready" and result.manifest is not None
    assert result.manifest.sha256 == result.reply.manifest_sha256
    assert len(result.manifest.model_dump()) == 16
    assert len(result.reply.model_dump()) == 17
    assert result.reply_sha256 == hashlib.sha256(result.reply_bytes).hexdigest()
    assert result.manifest.model_dump() == {
        "v": 1,
        "request_id": RID,
        "action_id": ACTION,
        "scope_sha256": SCOPE,
        "policy_sha256": POLICY_SHA256,
        "cursor_id": CURSOR,
        "source_ref": SOURCE,
        "evidence_sha256": EVIDENCE,
        "boot_ref": BOOT,
        "binding_ref": BINDING,
        "mode": "semi",
        "mode_revision": 2,
        "controller_grant_ref": "e" * 32,
        "root_grant_ref": "f" * 32,
        "ttl_ms": 60000,
        "deadline_at": DEADLINE,
    }
    assert result.manifest.sha256 == root_wire.digest(result.manifest.model_dump())
    assert POLICY_SHA256 == root_wire.POLICY_SHA256
    assert root_wire.parse(ssh.channel.sent[0]) == request().model_dump(mode="json")
    assert ssh.channel.sent == [request().wire_bytes()]
    assert len(ssh.connect_calls) == len(ssh.exec_calls) == 1
    hostname, options = ssh.connect_calls[0]
    assert hostname == target.host.public.address and options["port"] == 22423
    assert options["username"] == target.control.username
    assert client._key_identity(options["pkey"]) == target.control.key_identity
    assert options["look_for_keys"] is options["allow_agent"] is False
    assert "key_filename" not in options and "password" not in options
    assert all(
        0 < options[k] <= 4
        for k in ("timeout", "auth_timeout", "banner_timeout", "channel_timeout")
    )
    assert ssh.exec_calls[0][0] == client.COMMANDS["control"]
    assert ssh.exec_calls[0][1]["get_pty"] is False
    assert isinstance(ssh.policy, paramiko.RejectPolicy)
    assert ssh.keys.lookup("[192.0.2.10]:22423") and not ssh.keys.lookup("192.0.2.10")
    assert not result.mode_ack


def test_local_admission_is_rechecked_before_exec_and_before_request_bytes(target, ssh):
    stages = []

    def admit():
        stages.append((len(ssh.exec_calls), len(ssh.channel.sent)))

    result = client.invoke(target, request(), "control", admit=admit)
    assert result.reply.state == "ready"
    assert stages == [(0, 0), (1, 0)]
    assert ssh.channel.sent == [request().wire_bytes()]
    assert b"admit" not in ssh.channel.sent[0]


@pytest.mark.parametrize("revoke_at", [1, 2])
def test_revoked_local_admission_does_not_send_mutation_body(target, ssh, revoke_at):
    calls = 0

    def admit():
        nonlocal calls
        calls += 1
        if calls == revoke_at:
            raise ValueError("synthetic private context must never be reflected")

    expected = client.DefenseClientError if revoke_at == 1 else client.UnknownDefenseResult
    with pytest.raises(expected) as error:
        client.invoke(target, request(), "control", admit=admit)
    assert ssh.channel.sent == []
    assert len(ssh.connect_calls) == 1
    assert len(ssh.exec_calls) == revoke_at - 1
    assert error.value.query_required is (revoke_at == 2)
    assert "private context" not in str(error.value)


@pytest.mark.parametrize(
    "role,op,kind",
    [
        ("readonly", "query", "mode"),
        ("observe", "arm", None),
        ("observe", "query", "cursor"),
        ("control", "mode_sync", None),
    ],
)
def test_each_role_uses_own_username_key_and_fixed_command(target, ssh, role, op, kind):
    req = request(op, **({"kind": kind} if kind else {}))
    value = reply(
        op,
        action_id=None,
        cursor_id=None,
        manifest_sha256=None,
        deadline_at=None,
        state="not_found",
        reason_code="not_found",
    )
    ssh.channel.output = bytearray(canonical(value) + b"\n")
    result = client.invoke(target, req, role)
    credential = getattr(target, role)
    assert result.reply.state == "not_found"
    assert ssh.connect_calls[0][1]["username"] == credential.username
    assert client._key_identity(ssh.connect_calls[0][1]["pkey"]) == credential.key_identity
    assert ssh.exec_calls[0][0] == client.COMMANDS[role]


@pytest.mark.parametrize(
    "case",
    [
        "truncated",
        "extra",
        "cr",
        "duplicate",
        "whitespace",
        "wrong_exit",
        "stderr",
        "no_eof",
        "late_bytes",
        "late_stderr",
        "output_budget",
        "error_budget",
        "partial_send",
    ],
)
def test_unconfirmed_mutation_is_unknown_once(target, ssh, case):
    ch = ssh.channel
    if case == "truncated":
        del ch.output[-1:]
    elif case == "extra":
        ch.output.extend(b"{}\n")
    elif case == "cr":
        ch.output[-1:] = b"\r\n"
    elif case == "duplicate":
        ch.output[:1] = b'{"v":1,'
    elif case == "whitespace":
        ch.output[-1:] = b" \n"
    elif case == "wrong_exit":
        ch.code = 1
    elif case == "stderr":
        ch.errors.extend(b"private message")
    elif case == "no_eof":
        ch.eof_received = False
        ch.closed = True
    elif case == "late_bytes":
        ch.late_output = b"x"
    elif case == "late_stderr":
        ch.late_error = b"private late stderr"
    elif case == "output_budget":
        ch.output.extend(b"x" * 4096)
    elif case == "error_budget":
        ch.errors.extend(b"x" * 4097)
    else:
        ch.fail_send = True
    with pytest.raises(client.UnknownDefenseResult) as caught:
        client.invoke(target, request(), "control")
    assert caught.value.query_required and caught.value.request_id == RID
    assert caught.value.code == "result_unknown"
    assert "private" not in str(caught.value) and str(target.control.key_file) not in str(
        caught.value
    )
    assert ssh.channel.sent == [request().wire_bytes()]
    assert len(ssh.connect_calls) == len(ssh.exec_calls) == 1


def test_timeout_during_exec_ack_is_bounded_and_unknown(target, ssh):
    ssh.block_exec = True
    with pytest.raises(client.UnknownDefenseResult):
        client.invoke(target, request(), "control", timeout=0.1)
    assert len(ssh.connect_calls) == len(ssh.exec_calls) == 1
    assert ssh.closed.is_set() and not ssh.channel.sent


def test_no_eof_even_with_exit_status_times_out(target, ssh):
    ssh.channel.eof_received = False
    with pytest.raises(client.UnknownDefenseResult):
        client.invoke(target, request(), "control", timeout=0.1)
    assert ssh.channel.exit_calls == 0


def test_late_final_data_after_exit_status_is_drained(target, ssh):
    ssh.channel.late_output = bytes(ssh.channel.output[-2:])
    del ssh.channel.output[-2:]
    result = client.invoke(target, request(), "control")
    assert result.reply.state == "ready" and ssh.channel.exit_calls == 2


def test_hostkey_rejection_never_dispatches_or_leaks_error(target, ssh, keyset):
    ssh.connect_error = paramiko.BadHostKeyException("private-host", keyset[0], keyset[1])
    with pytest.raises(client.DefenseClientError) as caught:
        client.invoke(target, request(), "control")
    assert type(caught.value) is client.DefenseClientError
    assert not caught.value.query_required and not ssh.exec_calls and not ssh.channel.sent
    assert "private-host" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "f" * 32),
        ("scope_sha256", "f" * 64),
        ("policy_sha256", "f" * 64),
        ("boot_ref", "f" * 64),
        ("binding_ref", "f" * 64),
        ("manifest_sha256", "f" * 64),
        ("action_id", "f" * 32),
        ("cursor_id", "f" * 32),
        ("mode", "auto"),
        ("mode_revision", 3),
        ("mode_revision", True),
        ("v", True),
        ("remaining_ms", True),
        ("remaining_ms", 1),
        ("state", "synced"),
        ("deadline_at", "not-UTC"),
        ("reason_code", "freeform"),
        ("unknown_field", 1),
    ],
)
def test_schema_binding_and_manifest_mismatches_stop_mutation(target, ssh, field, value):
    ssh.channel.output = bytearray(canonical(reply(**{field: value})) + b"\n")
    with pytest.raises(client.UnknownDefenseResult):
        client.invoke(target, request(), "control")
    assert len(ssh.channel.sent) == 1


@pytest.mark.parametrize("ttl", [True, False, 0, -1, 60001, 1.0, "1", None])
def test_active_ttl_is_strict_1_to_60000(target, ssh, ttl):
    ssh.channel.output = bytearray(
        canonical(reply("query", state="active", remaining_ms=ttl)) + b"\n"
    )
    with pytest.raises(client.DefenseClientError) as caught:
        client.invoke(target, action_call(), "readonly")
    assert type(caught.value) is client.DefenseClientError
    assert len(ssh.channel.sent) == 1


@pytest.mark.parametrize("ttl", [1, 60000])
def test_active_ttl_boundaries_are_confirmed(target, ssh, ttl):
    ssh.channel.output = bytearray(
        canonical(reply("query", state="active", remaining_ms=ttl)) + b"\n"
    )
    assert client.invoke(target, action_call(), "readonly").reply.remaining_ms == ttl


def test_action_query_recovers_manifest_from_original_prepare_and_is_never_mode_ack(target, ssh):
    ssh.channel.output = bytearray(
        canonical(reply("query", state="active", remaining_ms=59000)) + b"\n"
    )
    result = client.invoke(target, action_call(expected=False), "readonly")
    assert result.manifest is not None and result.manifest.sha256 == result.reply.manifest_sha256
    assert not result.mode_ack


@pytest.mark.parametrize("op,mode", [("apply", "semi"), ("apply", "auto"), ("revoke", "semi")])
def test_bound_apply_and_revoke_take_real_single_dispatch_path(target, ssh, op, mode):
    prepare = request(mode=mode)
    value = reply(mode=mode)
    manifest = rebuild_manifest(prepare, DefenseReply.model_validate(value))
    approval = (
        None
        if mode == "auto"
        else {
            "approval_id": "f" * 32,
            "purpose": op,
            "request_id": RID,
            "manifest_sha256": manifest.sha256,
            "approved_at": "2026-11-06T09:59:00Z",
            "expires_at": DEADLINE,
        }
    )
    action = DefenseRequest.model_validate(
        {
            "v": 1,
            "op": op,
            "request_id": RID,
            "scope_sha256": SCOPE,
            "body": {"manifest_sha256": manifest.sha256, "approval": approval},
        }
    )
    value.update(
        op=op,
        manifest_sha256=manifest.sha256,
        state="active" if op == "apply" else "revoked",
        remaining_ms=59000 if op == "apply" else None,
    )
    ssh.channel.output = bytearray(canonical(value) + b"\n")
    result = client.invoke(target, DefenseCall(action, prepare, manifest), "control")
    assert result.manifest == manifest and not result.mode_ack
    assert ssh.channel.sent == [action.wire_bytes()]
    assert len(ssh.connect_calls) == len(ssh.exec_calls) == 1


def test_only_mode_query_matching_expected_revision_is_ack(target, ssh):
    ssh.channel.output = bytearray(
        canonical(
            reply(
                "query",
                state="synced",
                action_id=None,
                cursor_id=None,
                manifest_sha256=None,
                deadline_at=None,
            )
        )
        + b"\n"
    )
    call = DefenseCall(
        request("query", kind="mode"), expected_mode="semi", expected_mode_revision=2
    )
    assert client.invoke(target, call, "readonly").mode_ack
    ssh.channel.output = bytearray(
        canonical(
            reply(
                "query",
                state="synced",
                action_id=None,
                cursor_id=None,
                manifest_sha256=None,
                deadline_at=None,
            )
        )
        + b"\n"
    )
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, replace(call, expected_mode_revision=3), "readonly")


@pytest.mark.parametrize("mutation", ["changed", "replacement", "hardlink", "permissions"])
def test_credential_change_before_reopen_fails_without_connect(target, ssh, mutation, keyset):
    path = target.control.key_file
    if mutation == "changed":
        write_key(path, keyset[5])
    elif mutation == "replacement":
        other = path.with_suffix(".replacement")
        shutil.copyfile(path, other)
        other.chmod(0o600)
        os.replace(other, path)
    elif mutation == "hardlink":
        os.link(path, path.with_suffix(".link"))
    elif os.name == "posix":
        path.chmod(0o644)
    else:
        pytest.skip("POSIX permission bits; Windows DACL checked by separate test")
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, request(), "control")
    assert not ssh.connect_calls and not ssh.channel.sent


def test_same_key_different_path_is_not_independent_identity(target, tmp_path):
    duplicate = tmp_path / "duplicate-role"
    shutil.copyfile(target.control.key_file, duplicate)
    duplicate.chmod(0o600)
    repeated = client.RoleCredential(
        "other-role",
        22423,
        duplicate,
        target.control.known_hosts_file,
        target.control.trusted_hosts_digest,
    )
    with pytest.raises(client.DefenseClientError):
        replace(target, observe=repeated)


def test_collector_and_apt_identity_cannot_be_reused_under_another_path(target, tmp_path):
    for excluded in (target.host.key_file, *target.other_key_files):
        duplicate = tmp_path / (excluded.name + "-copy")
        shutil.copyfile(excluded, duplicate)
        duplicate.chmod(0o600)
        credential = client.RoleCredential(
            "other-role",
            22423,
            duplicate,
            target.control.known_hosts_file,
            target.control.trusted_hosts_digest,
        )
        with pytest.raises(client.DefenseClientError):
            replace(target, control=credential)


def test_changed_hostpin_and_host_registration_invalidate_target(target, ssh):
    target.control.known_hosts_file.write_text("private changed pin")
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, request(), "control")
    assert not ssh.connect_calls


def test_registered_host_address_cannot_change_after_binding(target, ssh):
    target.host.public.address = "192.0.2.11"
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, request(), "control")
    assert not ssh.connect_calls


def test_other_channel_key_change_invalidates_defense_binding(target, ssh, keyset):
    write_key(target.other_key_files[0], keyset[0])
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, request(), "control")
    assert not ssh.connect_calls


@pytest.mark.parametrize("port", [22, True, "22423", 22422])
def test_ordinary_host_port_cannot_replace_role_port(target, port):
    with pytest.raises(client.DefenseClientError):
        replace(target.control, port=port)


def test_normal_ssh_pin_does_not_authenticate_defense_listener(target):
    path = target.control.known_hosts_file
    path.write_text(path.read_text().replace("[192.0.2.10]:22423", "192.0.2.10"))
    control = replace(
        target.control, trusted_hosts_digest=hashlib.sha256(path.read_bytes()).hexdigest()
    )
    with pytest.raises(client.DefenseClientError):
        replace(target, control=control)


@pytest.mark.parametrize(
    "role,op", [("readonly", "prepare"), ("observe", "mode_sync"), ("control", "arm")]
)
def test_role_operation_is_locally_enforced(target, ssh, role, op):
    with pytest.raises(client.DefenseClientError) as caught:
        client.invoke(target, request(op), role)
    assert caught.value.code == "request_invalid" and not ssh.connect_calls


@pytest.mark.parametrize(
    "change",
    [
        {"classification": "eligible", "evidence_sha256": None},
        {"classification": "insufficient", "evidence_sha256": EVIDENCE},
        {"source_alias": "private-address"},
        {"distinct_failure_ports": True},
        {"distinct_failure_ports": 257},
        {"extra": "secret"},
    ],
)
def test_candidate_exact_types_enums_and_evidence(change):
    value = {
        "source_ref": SOURCE,
        "source_alias": "fixture-a",
        "classification": "eligible",
        "distinct_failure_ports": 5,
        "evidence_sha256": EVIDENCE,
    }
    with pytest.raises(ValidationError):
        DefenseCandidate.model_validate(value | change)


def cursor_reply(**changes):
    candidates = [
        {
            "source_ref": SOURCE,
            "source_alias": "fixture-a",
            "classification": "eligible",
            "distinct_failure_ports": 5,
            "evidence_sha256": EVIDENCE,
        },
        {
            "source_ref": "e" * 32,
            "source_alias": "fixture-b",
            "classification": "insufficient",
            "distinct_failure_ports": 0,
            "evidence_sha256": None,
        },
    ]
    return (
        reply("query", state="armed", action_id=None, manifest_sha256=None, candidates=candidates)
        | changes
    )


def test_cursor_candidate_response_uses_real_readonly_client(target, ssh):
    ssh.channel.output = bytearray(canonical(cursor_reply()) + b"\n")
    result = client.invoke(target, request("query", kind="cursor"), "readonly")
    assert result.reply.candidates[0].evidence_sha256 == EVIDENCE
    assert result.reply.candidates[1].classification == "insufficient"
    assert result.manifest is None and not result.mode_ack


@pytest.mark.parametrize(
    "change",
    [
        {"source_alias": "fixture-b"},
        {"source_ref": "e" * 32},
        {"distinct_failure_ports": True},
        {"distinct_failure_ports": 257},
        {"source_alias": "198.18.241.3"},
        {"evidence_sha256": None},
    ],
)
def test_cursor_candidate_mismatch_is_unavailable_on_real_client(target, ssh, change):
    value = cursor_reply()
    value["candidates"][0].update(change)
    ssh.channel.output = bytearray(canonical(value) + b"\n")
    with pytest.raises(client.DefenseClientError):
        client.invoke(target, request("query", kind="cursor"), "readonly")
    assert len(ssh.channel.sent) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"v": True},
        {"address": "192.0.2.99"},
        {"command": "free shell"},
        {"key_file": "secret"},
    ],
)
def test_request_cannot_introduce_transport_authority(changes):
    with pytest.raises(ValidationError):
        DefenseRequest.model_validate(request().model_dump(mode="python") | changes)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"v":1,"v":1}\n',
        b"{}\n{}\n",
        b"{}\r\n",
        b'{"n":NaN}\n',
        b'{"n":Infinity}\n',
        b"{}",
        b"[" * 18 + b"0" + b"]" * 18 + b"\n",
    ],
)
def test_framing_duplicate_nonfinite_and_depth_rejected(raw):
    with pytest.raises((ValueError, ValidationError)):
        DefenseRequest.parse(raw)


def test_manifest_is_exact_frozen_and_bool_is_never_integer():
    manifest = rebuild_manifest(request(), DefenseReply.model_validate(reply()))
    for change in ({"ttl_ms": True}, {"ttl_ms": 59999}, {"metadata": {}}, {"v": True}):
        with pytest.raises(ValidationError):
            DefenseManifest.model_validate(manifest.model_dump() | change)
    with pytest.raises(ValidationError):
        setattr(manifest, "ttl_ms", 1)  # noqa: B010 -- exercise frozen model without a type error.


def test_repr_and_exception_do_not_expose_credentials(target):
    assert str(target.control.key_file) not in repr(target)
    assert str(target.control.key_file) not in repr(target.control)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
def test_windows_everyone_read_access_is_rejected(target):
    import subprocess

    executable = os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe")
    result = subprocess.run(  # noqa: S603 -- only an owned synthetic pytest key is changed.
        [executable, str(target.control.key_file), "/grant", "*S-1-1-0:R"],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    with pytest.raises(client.DefenseClientError):
        replace(target.control)
