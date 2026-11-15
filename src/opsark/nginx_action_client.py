"""Bounded transport for the separately registered Nginx action account."""

import hashlib
import ipaddress
import json
import re
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, cast

import paramiko
from paramiko.hostkeys import HostKeyEntry

from opsark.baselines import scope_for
from opsark.config import HostConfig
from opsark.defense_client import (
    MAX_KEY_BYTES,
    MAX_KNOWN_HOSTS_BYTES,
    _key_identity,
    _private_key,
    _read_file,
)

COMMAND = "opsark-nginx-action-v1"
USERNAME = "opsark-nginx-action"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {
    "prepare": {"plan_id", "mode_revision"},
    "plan_status": {"plan_id"},
    "submit": {"plan_id", "action_id", "plan_digest", "approval_id", "mode_revision"},
    "status": {"action_id"},
    "reconcile_status": {"action_id", "plan_id", "plan_digest", "mode_revision"},
    "observe": {"action_id"},
    "rollback_prepare": {"plan_id", "original_action_id", "mode_revision"},
}


class NginxActionTransportError(RuntimeError):
    """No trustworthy response. The caller retains any original intent."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON field")
    return result


def _nonfinite(_value):
    raise ValueError("Non-finite JSON")


def _host_address(host):
    address = ipaddress.ip_address(host.public.address)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


@dataclass(frozen=True, repr=False)
class NginxActionTarget:
    username: ClassVar[str] = USERNAME
    host: HostConfig
    key_file: Path
    policy_digest: str
    other_key_files: tuple[Path, ...] = ()
    transport_scope: str = field(init=False)
    target_scope: str = field(init=False)
    _seal: object = field(init=False)
    _excluded: tuple = field(init=False)
    _host_scope: str = field(init=False)

    def __post_init__(self):
        public = self.host.public
        if (
            public.source != "ssh"
            or public.username == self.username
            or type(public.port) is not int
            or not 1 <= public.port <= 65535
            or type(public.trusted_hosts_digest) is not str
            or not DIGEST.fullmatch(public.trusted_hosts_digest)
            or type(self.policy_digest) is not str
            or not DIGEST.fullmatch(self.policy_digest)
            or not isinstance(self.key_file, Path)
            or not self.key_file.is_absolute()
        ):
            raise ValueError("Nginx 处置需要已核验的目标和独立凭据。")
        ipaddress.ip_address(public.address)
        raw, seal = _read_file(self.key_file, MAX_KEY_BYTES, private=True)
        key = _private_key(raw)
        if not isinstance(key, paramiko.Ed25519Key):
            raise ValueError("Nginx 处置角色需要独立的 Ed25519 凭据。")
        identity = _key_identity(key)
        excluded = []
        for path in dict.fromkeys((self.host.key_file, *self.other_key_files)):
            raw, existing = _read_file(path, MAX_KEY_BYTES, private=True)
            if existing.path == seal.path or _key_identity(_private_key(raw)) == identity:
                raise ValueError("Nginx 处置凭据必须独立于采集凭据。")
            excluded.append(existing)
        host_scope = scope_for(public)
        transport_scope = hashlib.sha256(
            canonical([host_scope, self.username, identity])
        ).hexdigest()
        object.__setattr__(self, "_seal", seal)
        object.__setattr__(self, "_excluded", tuple(excluded))
        object.__setattr__(self, "_host_scope", host_scope)
        object.__setattr__(self, "transport_scope", transport_scope)
        object.__setattr__(
            self,
            "target_scope",
            hashlib.sha256(canonical([transport_scope, self.policy_digest])).hexdigest(),
        )
        _credentials(self)


def _credentials(target):
    host = target.host
    public = host.public
    if scope_for(public) != target._host_scope:
        raise ValueError("Nginx 处置目标已改变。")
    raw, seal = _read_file(target.key_file, MAX_KEY_BYTES, private=True)
    if seal != target._seal:
        raise ValueError("Nginx 处置凭据已改变。")
    key = _private_key(raw)
    for expected in target._excluded:
        _, actual = _read_file(expected.path, MAX_KEY_BYTES, private=True)
        if actual != expected:
            raise ValueError("同机采集凭据已改变。")
    raw, known = _read_file(host.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
    if known.sha256 != public.trusted_hosts_digest:
        raise ValueError("Nginx 处置主机指纹记录已改变。")
    name = public.address if public.port == 22 else f"[{public.address}]:{public.port}"
    keys = paramiko.HostKeys()
    for line in raw.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        entry = HostKeyEntry.from_line(line)
        if entry is None or entry.key is None:
            raise ValueError("不支持的 Nginx 处置主机指纹记录。")
        if name in entry.hostnames or any(
            item.startswith("|1|") and paramiko.HostKeys.hash_host(name, item) == item
            for item in entry.hostnames
        ):
            keys.add(name, entry.key.get_name(), entry.key)
    if not keys.lookup(name):
        raise ValueError("缺少 Nginx 处置目标的可信指纹。")
    return key, keys


def load_nginx_targets(path, hosts, other_writers):
    if path is None:
        return {}
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("path")
        raw, seal = _read_file(path, 16384, private=True)
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "targets"}
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["targets"]) is not dict
            or len(value["targets"]) != 1
        ):
            raise ValueError("inventory")
        host_id, record = next(iter(value["targets"].items()))
        if (
            host_id not in hosts
            or type(record) is not dict
            or set(record) != {"key_file", "policy_digest"}
        ):
            raise ValueError("target")
        record = cast(dict[str, object], record)
        key_file, policy = record["key_file"], record["policy_digest"]
        if type(key_file) is not str or not 0 < len(key_file) <= 1024 or type(policy) is not str:
            raise ValueError("credential_reference")
        host = hosts[host_id]
        address = _host_address(host)
        if any(_host_address(item.host) == address for item in other_writers):
            raise ValueError("overlapping_writer")
        aliases = [
            item
            for item in hosts.values()
            if item.public.source == "ssh" and _host_address(item) == address
        ]
        if any(item.public.username == USERNAME for item in aliases):
            raise ValueError("overlapping_role")
        target = NginxActionTarget(
            host,
            Path(key_file),
            policy,
            tuple(item.key_file for item in aliases),
        )
        _, current = _read_file(path, 16384, private=True)
        if current != seal:
            raise ValueError("inventory_changed")
        return {host_id: target}
    except Exception:
        raise ValueError("Nginx 处置登记、独立凭据或目标范围未能核实。") from None


def invoke(target, operation, *, policy_digest=None, **fields):
    """Send one fixed command and one bounded JSON request, without replay."""
    return _invoke_fixed(
        target,
        operation,
        policy_digest,
        fields,
        command=COMMAND,
        allowed_fields=FIELDS,
        username=USERNAME,
    )


def _invoke_fixed(target, operation, policy_digest, fields, *, command, allowed_fields, username):
    if operation not in allowed_fields or set(fields) != allowed_fields[operation]:
        raise ValueError("Nginx 处置请求字段不符合约定。")
    policy = target.policy_digest if policy_digest is None else policy_digest
    if (
        type(policy) is not str
        or not DIGEST.fullmatch(policy)
        or (
            policy != target.policy_digest
            and operation not in {"status", "plan_status", "reconcile_status"}
        )
    ):
        raise ValueError("Nginx 处置策略摘要不符合约定。")
    data = (
        canonical({"schema_version": 1, "op": operation, "policy_digest": policy, **fields}) + b"\n"
    )
    if len(data) > 2048:
        raise ValueError("Nginx 处置请求超过大小限制。")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    expires = time.monotonic() + 60
    expired = threading.Event()
    channel = None

    def remaining():
        left = expires - time.monotonic()
        if expired.is_set() or left <= 0:
            raise TimeoutError("Nginx action deadline")
        return left

    def close_at_deadline():
        expired.set()
        with suppress(OSError, paramiko.SSHException):
            client.close()

    timer = threading.Timer(60, close_at_deadline)
    timer.daemon = True
    timer.start()
    try:
        key, pins = _credentials(target)
        for name in pins:
            for kind, pin in pins[name].items():
                client.get_host_keys().add(name, kind, pin)
        public = target.host.public
        budget = min(4.0, remaining() / 4)
        client.connect(
            public.address,
            port=public.port,
            username=username,
            pkey=key,
            look_for_keys=False,
            allow_agent=False,
            timeout=budget,
            banner_timeout=budget,
            auth_timeout=budget,
            channel_timeout=budget,
        )
        stdin, stdout, _stderr = client.exec_command(command, timeout=remaining(), get_pty=False)
        channel = stdout.channel
        channel.settimeout(remaining())
        channel.sendall(data)
        # Paramiko's stdin wrapper sends EOF when closed.
        stdin.close()
        output = bytearray()
        while True:
            remaining()
            if channel.recv_stderr_ready():
                raise ValueError("Nginx action returned unclassified error output")
            if channel.recv_ready():
                output.extend(channel.recv(min(4096, 16385 - len(output))))
                if len(output) > 16384:
                    raise ValueError("Nginx action response exceeded budget")
            if channel.closed and not channel.eof_received:
                transport = channel.get_transport()
                if transport is None or not transport.is_active():
                    raise EOFError("Nginx action transport closed early")
            if (
                (channel.eof_received or channel.closed)
                and channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                break
            time.sleep(min(0.01, remaining()))
        if channel.recv_exit_status() != 0:
            raise ValueError("No trustworthy Nginx action response")
        remaining()
        result = json.loads(output, object_pairs_hook=_unique, parse_constant=_nonfinite)
        if type(result) is not dict:
            raise ValueError("Unexpected Nginx action response")
        return result
    except (OSError, ValueError, EOFError, RecursionError, paramiko.SSHException):
        raise NginxActionTransportError("Nginx 处置通道未取得可信结果。") from None
    finally:
        timer.cancel()
        if channel is not None:
            with suppress(OSError, paramiko.SSHException):
                channel.close()
        with suppress(OSError, paramiko.SSHException):
            client.close()
