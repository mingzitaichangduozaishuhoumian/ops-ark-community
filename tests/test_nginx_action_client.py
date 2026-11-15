"""Verify the fixed operation transport without opening a socket or a key file."""

import json
from dataclasses import replace
from ipaddress import IPv4Address
from types import SimpleNamespace
from unittest.mock import Mock

import paramiko
import pytest
from paramiko.channel import ChannelStdinFile

from opsark import nginx_action_client as client
from opsark.config import HostConfig
from opsark.models import HostPublic


@pytest.mark.parametrize(
    ("operation", "fields"),
    [
        ("status", {"action_id": "c" * 64}),
        (
            "reconcile_status",
            {
                "action_id": "c" * 64,
                "plan_id": "d" * 32,
                "plan_digest": "e" * 64,
                "mode_revision": 3,
            },
        ),
    ],
)
def test_fixed_ssh_command_and_historical_policy_reconciliation(monkeypatch, operation, fields):
    endpoint = SimpleNamespace(address="192.0.2.10", port=2222)
    target = SimpleNamespace(host=SimpleNamespace(public=endpoint), policy_digest="a" * 64)
    channel = Mock(closed=False, eof_received=True)
    channel.recv_ready.side_effect = [True, False]
    channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = True
    channel.recv_exit_status.return_value = 0
    channel.recv.return_value = b'{"schema_version":1,"status":"missing"}\n'
    ssh = Mock()
    stdin = Mock()
    ssh.exec_command.return_value = (stdin, SimpleNamespace(channel=channel), None)
    factory = Mock(return_value=ssh)
    key = object()
    monkeypatch.setattr(client.paramiko, "SSHClient", factory)
    monkeypatch.setattr(client, "_credentials", lambda _target: (key, {}))
    assert client.invoke(target, operation, policy_digest="b" * 64, **fields)["status"] == "missing"
    assert factory.call_count == 1 and ssh.exec_command.call_count == 1
    assert ssh.exec_command.call_args.args == ("opsark-nginx-action-v1",)
    assert ssh.exec_command.call_args.kwargs["get_pty"] is False
    assert isinstance(ssh.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
    assert ssh.connect.call_args.args == ("192.0.2.10",)
    assert ssh.connect.call_args.kwargs["username"] == "opsark-nginx-action"
    assert ssh.connect.call_args.kwargs["port"] == 2222
    assert ssh.connect.call_args.kwargs["pkey"] is key
    assert not ssh.connect.call_args.kwargs["look_for_keys"]
    assert not ssh.connect.call_args.kwargs["allow_agent"]
    assert json.loads(channel.sendall.call_args.args[0]) == {
        "schema_version": 1,
        "op": operation,
        "policy_digest": "b" * 64,
        **fields,
    }
    stdin.close.assert_called_once_with()
    with pytest.raises(ValueError):
        client.invoke(target, "prepare", policy_digest="b" * 64, plan_id="c" * 32, mode_revision=1)
    with pytest.raises(ValueError):
        client.invoke(target, "status", action_id="c" * 64, command="unregistered")
    with pytest.raises(ValueError):
        client.invoke(target, "reconcile_status", action_id="c" * 64)
    assert factory.call_count == 1


def test_real_paramiko_stdin_wrapper_sends_eof_after_request_bytes(monkeypatch):
    target = SimpleNamespace(
        host=SimpleNamespace(public=SimpleNamespace(address="192.0.2.10", port=22)),
        policy_digest="a" * 64,
    )
    channel = Mock(closed=False, eof_received=False)
    channel.recv_ready.side_effect = [True, False]
    channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = True
    channel.recv_exit_status.return_value = 0
    channel.recv.return_value = b'{"schema_version":1,"status":"missing"}\n'
    events = []

    def send(payload):
        assert not channel.eof_received
        assert json.loads(payload) == {
            "schema_version": 1,
            "op": "plan_status",
            "policy_digest": "a" * 64,
            "plan_id": "b" * 32,
        }
        events.append("send")

    def shutdown_write():
        # The real wrapper can close again during finalization. SSH EOF is idempotent.
        if not channel.eof_received:
            events.append("eof")
            channel.eof_received = True

    channel.sendall.side_effect = send
    channel.shutdown_write.side_effect = shutdown_write
    ssh = Mock()
    # Return a fresh stdin wrapper so the mock cannot keep it alive after unpacking.
    ssh.exec_command.side_effect = lambda *_args, **_kwargs: (
        ChannelStdinFile(channel, "wb", -1),
        SimpleNamespace(channel=channel),
        None,
    )
    monkeypatch.setattr(client.paramiko, "SSHClient", lambda: ssh)
    monkeypatch.setattr(client, "_credentials", lambda _target: (object(), {}))
    assert client.invoke(target, "plan_status", plan_id="b" * 32)["status"] == "missing"
    assert events == ["send", "eof"]
    ssh.exec_command.assert_called_once()


def test_unclassified_stderr_is_not_read_or_replayed(monkeypatch):
    target = SimpleNamespace(
        host=SimpleNamespace(public=SimpleNamespace(address="192.0.2.10", port=22)),
        policy_digest="a" * 64,
    )
    channel = Mock(closed=False, eof_received=False)
    channel.recv_stderr_ready.return_value = True
    ssh = Mock()
    ssh.exec_command.return_value = (Mock(), SimpleNamespace(channel=channel), None)
    monkeypatch.setattr(client.paramiko, "SSHClient", lambda: ssh)
    monkeypatch.setattr(client, "_credentials", lambda _target: (object(), {}))
    with pytest.raises(client.NginxActionTransportError):
        client.invoke(target, "prepare", plan_id="b" * 32, mode_revision=1)
    assert ssh.exec_command.call_count == 1
    channel.recv_stderr.assert_not_called()
    channel.close.assert_called_once_with()


def test_inventory_rejects_overlapping_write_address_before_loading_credentials(
    tmp_path, monkeypatch
):
    path = tmp_path / "inventory.json"
    key = tmp_path / "test-role-reference"
    inventory = {
        "schema_version": 1,
        "targets": {"nginx": {"key_file": str(key), "policy_digest": "a" * 64}},
    }
    called = []

    def read(requested, _limit, *, private):
        called.append(requested)
        assert requested == path and private
        return json.dumps(inventory).encode(), None

    monkeypatch.setattr(client, "_read_file", read)
    host = HostConfig(
        HostPublic(id="nginx", name="Fixture", address="192.0.2.10", source="ssh"),
        tmp_path / "collector-reference",
        tmp_path / "public-pin",
    )
    writer = HostConfig(
        HostPublic(
            id="alias",
            name="Fixture",
            address=str(IPv4Address(host.public.address).ipv6_mapped),
            source="ssh",
        ),
        tmp_path / "writer-reference",
        tmp_path / "public-pin",
    )
    with pytest.raises(ValueError):
        client.load_nginx_targets(path, {"nginx": host}, (SimpleNamespace(host=writer),))
    assert called == [path]


def test_action_key_must_match_dedicated_role_algorithm(tmp_path, monkeypatch):
    host = HostConfig(
        HostPublic(
            id="nginx",
            name="Fixture",
            address="192.0.2.10",
            source="ssh",
            trusted_hosts_digest="c" * 64,
        ),
        tmp_path / "collector-reference",
        tmp_path / "public-pin",
    )
    action_key = tmp_path / "action-reference"
    reads = []

    def read(path, _limit, *, private):
        reads.append((path, private))
        return b"synthetic", object()

    monkeypatch.setattr(client, "_read_file", read)
    monkeypatch.setattr(client, "_private_key", lambda _raw: Mock(spec=paramiko.RSAKey))
    with pytest.raises(ValueError, match="Ed25519"):
        client.NginxActionTarget(host, action_key, "a" * 64)
    assert reads == [(action_key, True)]


def test_disk_registration_keeps_the_original_nginx_action_transport(tmp_path, monkeypatch):
    public = HostPublic(
        id="nginx",
        name="Fixture",
        address="192.0.2.10",
        source="ssh",
        trusted_hosts_digest="c" * 64,
    )
    host = HostConfig(public, tmp_path / "collector-reference", tmp_path / "public-pin")
    action_key = tmp_path / "action-reference"

    def read(path, _limit, *, private):
        assert private
        return path.name.encode("ascii"), SimpleNamespace(path=path)

    def key(raw):
        result = Mock(spec=paramiko.Ed25519Key)
        result.fixture_identity = raw.decode("ascii")
        return result

    monkeypatch.setattr(client, "_read_file", read)
    monkeypatch.setattr(client, "_private_key", key)
    monkeypatch.setattr(client, "_key_identity", lambda value: value.fixture_identity)
    monkeypatch.setattr(client, "_credentials", lambda _target: (None, {}))
    original = client.NginxActionTarget(host, action_key, "a" * 64)
    for disk in ("b" * 64, "d" * 64):
        changed = replace(
            host, public=public.model_copy(update={"disk_reclaim_scope_digest": disk})
        )
        current = client.NginxActionTarget(changed, action_key, "a" * 64)
        assert current.transport_scope == original.transport_scope
        assert current.target_scope == original.target_scope
    other_host = replace(host, public=public.model_copy(update={"port": 2222}))
    other = client.NginxActionTarget(other_host, action_key, "a" * 64)
    assert other.transport_scope != original.transport_scope
