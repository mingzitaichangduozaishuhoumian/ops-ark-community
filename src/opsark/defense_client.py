"""One fixed-role SSH dispatch. The durable caller owns admission and never retries."""

import ctypes
import hashlib
import io
import ipaddress
import math
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

import paramiko
from paramiko.hostkeys import HostKeyEntry

from opsark.config import HostConfig
from opsark.defense_models import (
    POLICY_SHA256,
    ActionBody,
    DefenseCall,
    DefenseManifest,
    DefenseReply,
    DefenseRequest,
    DefenseRole,
    ModeBody,
    PrepareBody,
    QueryBody,
    canonical,
    rebuild_manifest,
    utc,
)

MAX_OUTPUT_BYTES = 4096
MAX_ERROR_BYTES = 4096
MAX_KEY_BYTES = 32768
MAX_KNOWN_HOSTS_BYTES = 1048576
DEFAULT_TIMEOUT = 28.0  # Root alarm 20s; wrapper TERM 22s + KILL 2s; connect budget 4s.
_ENTRY = (
    "/usr/bin/timeout --signal=TERM --kill-after=2s 22s /usr/bin/python3 -I -B "
    "/usr/local/libexec/opsark-defense/deploy/defense/ssh_requests.py"
)
COMMANDS = {"readonly": _ENTRY, "observe": _ENTRY + " --observe", "control": _ENTRY + " --control"}
_OPERATIONS = {
    "readonly": frozenset({"query"}),
    "observe": frozenset({"arm", "query"}),
    "control": frozenset({"mode_sync", "prepare", "apply", "revoke", "query"}),
}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


class DefenseClientError(RuntimeError):
    """Only fixed public codes, never transport errors, paths or credentials."""

    def __init__(self, code: str = "unavailable"):
        self.code = code
        self.query_required = False
        super().__init__("Defense request could not be confirmed.")


class UnknownDefenseResult(DefenseClientError):
    """Dispatch may have reached Root; only query the durable original RID."""

    def __init__(self, request_id: str):
        super().__init__("result_unknown")
        self.request_id = request_id
        self.query_required = True


def _identity(meta: os.stat_result) -> tuple[int, ...]:
    return (
        meta.st_dev,
        meta.st_ino,
        meta.st_mode,
        meta.st_nlink,
        meta.st_uid,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns if os.name == "posix" else 0,
    )


def _windows_private(descriptor: int) -> None:
    """Accept file ownership/DACL only for the current user, SYSTEM and Administrators."""
    if sys.platform != "win32":
        raise ValueError("Invalid credential security")

    import msvcrt
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
        ctypes.POINTER(pointer),
    ]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        pointer,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.GetAclInformation.argtypes = [pointer, pointer, wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [pointer, wintypes.DWORD, ctypes.POINTER(pointer)]
    advapi.GetAce.restype = wintypes.BOOL

    def sid_text(sid):
        value = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise ValueError("Invalid credential ACL")
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, pointer))

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ValueError("Invalid credential owner")
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ValueError("Invalid credential owner")
        user_sid = ctypes.cast(buffer, ctypes.POINTER(pointer))[0]
        trusted = {sid_text(user_sid), "S-1-5-18", "S-1-5-32-544"}
    finally:
        kernel.CloseHandle(token)
    owner, dacl, security = pointer(), pointer(), pointer()
    result = advapi.GetSecurityInfo(
        msvcrt.get_osfhandle(descriptor),
        1,
        0x00000005,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security),
    )
    if result:
        raise ValueError("Invalid credential security")
    try:
        if not dacl.value or sid_text(owner) not in trusted:
            raise ValueError("Unsafe credential ACL")

        class AclSize(ctypes.Structure):
            _fields_ = [
                ("count", wintypes.DWORD),
                ("used", wintypes.DWORD),
                ("free", wintypes.DWORD),
            ]

        info = AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ValueError("Invalid credential ACL")
        for index in range(info.count):
            ace = pointer()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or ace.value is None:
                raise ValueError("Invalid credential ACL")
            header = ctypes.string_at(ace, 4)
            # Standard deny ACEs grant no access; inherit-only ACEs do not apply here.
            if header[1] & 0x08 or header[0] == 1:
                continue
            if header[0] != 0 or int.from_bytes(header[2:4], "little") < 12:
                raise ValueError("Unsupported credential ACL")
            # OWNER RIGHTS is scoped to the already-verified owner, not another user.
            if sid_text(pointer(ace.value + 8)) not in trusted | {"S-1-3-4"}:
                raise ValueError("Unsafe credential ACL")
    finally:
        kernel.LocalFree(security)


@dataclass(frozen=True, repr=False)
class _Seal:
    path: Path
    identity: tuple[int, ...]
    sha256: str


def _read_file(path: Path, limit: int, *, private: bool) -> tuple[bytes, _Seal]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or ".." in path.parts
        or path.drive.startswith("\\\\")
        or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))
    ):
        raise ValueError("Invalid defense credential reference")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= limit
        or getattr(before, "st_file_attributes", 0) & 0x400
        or private
        and os.name == "posix"
        and (before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o077)
    ):
        raise ValueError("Unsafe defense credential file")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        identity = _identity(before)
        if _identity(os.fstat(descriptor)) != identity:
            raise ValueError("Defense credential changed")
        if private and os.name == "nt":
            _windows_private(descriptor)
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if (
            not raw
            or len(raw) > limit
            or _identity(os.fstat(descriptor)) != identity
            or _identity(path.lstat()) != identity
        ):
            raise ValueError("Defense credential changed")
    finally:
        os.close(descriptor)
    return bytes(raw), _Seal(path.resolve(strict=True), identity, hashlib.sha256(raw).hexdigest())


def _private_key(raw: bytes) -> paramiko.PKey:
    text = raw.decode("ascii", errors="strict")
    # Read only verified in-memory bytes. Never permit Paramiko to reopen a path.
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError("Unsupported defense key")


def _key_identity(key: paramiko.PKey) -> str:
    return hashlib.sha256(key.asbytes()).hexdigest()


@dataclass(frozen=True, repr=False)
class RoleCredential:
    """Deployment-only fixed role identity, with file/content/public-identity seals."""

    username: str
    port: int
    key_file: Path
    known_hosts_file: Path
    trusted_hosts_digest: str
    _key_seal: _Seal = field(init=False)
    _hosts_seal: _Seal = field(init=False)
    key_identity: str = field(init=False)

    def __post_init__(self):
        try:
            if (
                type(self.username) is not str
                or not _USERNAME.fullmatch(self.username)
                or self.username in {"root", "opsark-repair"}
                or type(self.port) is not int
                or self.port != 22423
                or type(self.trusted_hosts_digest) is not str
                or not _SHA.fullmatch(self.trusted_hosts_digest)
            ):
                raise ValueError("Invalid defense role")
            raw, key_seal = _read_file(self.key_file, MAX_KEY_BYTES, private=True)
            key_identity = _key_identity(_private_key(raw))
            _, hosts_seal = _read_file(self.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
            if hosts_seal.sha256 != self.trusted_hosts_digest:
                raise ValueError("Defense host pin changed")
            object.__setattr__(self, "_key_seal", key_seal)
            object.__setattr__(self, "_hosts_seal", hosts_seal)
            object.__setattr__(self, "key_identity", key_identity)
        except Exception:
            raise DefenseClientError("credential_invalid") from None


@dataclass(frozen=True, repr=False)
class DefenseTarget:
    """Settings loader binds these only to registered hosts and existing dedicated keys.

    ``other_key_files`` must include all APT repair identities registered for this host;
    its normal collector identity is always checked automatically.
    """

    host: HostConfig
    readonly: RoleCredential
    observe: RoleCredential
    control: RoleCredential
    root_scope_sha256: str
    root_policy_sha256: str
    boot_ref: str
    binding_ref: str
    other_key_files: tuple[Path, ...] = ()
    _excluded: tuple[_Seal, ...] = field(init=False)
    _host_binding: tuple[str, str] = field(init=False)

    def __post_init__(self):
        try:
            host = self.host.public
            ipaddress.ip_address(host.address)
            if (
                host.source != "ssh"
                or not host.id
                or type(self.root_scope_sha256) is not str
                or not _SHA.fullmatch(self.root_scope_sha256)
                or self.root_policy_sha256 != POLICY_SHA256
                or type(self.boot_ref) is not str
                or not _SHA.fullmatch(self.boot_ref)
                or type(self.binding_ref) is not str
                or not _SHA.fullmatch(self.binding_ref)
                or type(self.other_key_files) is not tuple
            ):
                raise ValueError("Invalid defense target")
            roles = (self.readonly, self.observe, self.control)
            if (
                any(type(c) is not RoleCredential for c in roles)
                or len({c.username for c in roles}) != 3
                or len({c.key_identity for c in roles}) != 3
                or len({c._key_seal.path for c in roles}) != 3
            ):
                raise ValueError("Defense roles require independent identities")
            excluded = []
            identities = {c.key_identity for c in roles}
            paths = {c._key_seal.path for c in roles}
            for path in (self.host.key_file, *self.other_key_files):
                raw, seal = _read_file(path, MAX_KEY_BYTES, private=True)
                if seal.path in paths or _key_identity(_private_key(raw)) in identities:
                    raise ValueError("Defense identity overlaps another channel")
                excluded.append(seal)
            object.__setattr__(self, "_excluded", tuple(excluded))
            object.__setattr__(self, "_host_binding", (host.id, host.address))
            for role in ("readonly", "observe", "control"):
                _credentials(self, role)
        except Exception:
            raise DefenseClientError("target_invalid") from None


def _credentials(
    target: DefenseTarget, role: DefenseRole
) -> tuple[RoleCredential, paramiko.PKey, paramiko.HostKeys]:
    if (
        target.host.public.source != "ssh"
        or (target.host.public.id, target.host.public.address) != target._host_binding
    ):
        raise ValueError("Defense host registration changed")
    # Recheck all three roles and excluded channels before every connection, not only
    # the selected role: a changed registry identity invalidates the complete binding.
    selected = None
    for name in ("readonly", "observe", "control"):
        credential = getattr(target, name)
        raw, seal = _read_file(credential.key_file, MAX_KEY_BYTES, private=True)
        key = _private_key(raw)
        if seal != credential._key_seal or _key_identity(key) != credential.key_identity:
            raise ValueError("Defense credential changed")
        hosts_raw, hosts_seal = _read_file(
            credential.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False
        )
        if hosts_seal != credential._hosts_seal:
            raise ValueError("Defense host pin changed")
        if name == role:
            selected = credential, key, hosts_raw
    for expected in target._excluded:
        _, seal = _read_file(expected.path, MAX_KEY_BYTES, private=True)
        if seal != expected:
            raise ValueError("Other channel credential changed")
    if selected is None:
        raise ValueError("Invalid defense role")
    credential, key, hosts_raw = selected
    keys = paramiko.HostKeys()
    hostname = f"[{target.host.public.address}]:{credential.port}"
    for line in hosts_raw.decode("utf-8", errors="strict").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        entry = HostKeyEntry.from_line(line)
        if entry is None or entry.key is None:
            raise ValueError("Invalid defense host pin")
        # Keep only this listener's own pin; the ordinary SSH listener is not trusted.
        if hostname in entry.hostnames or (
            entry.hostnames[0].startswith("|1|")
            and paramiko.HostKeys.hash_host(hostname, entry.hostnames[0]) == entry.hostnames[0]
        ):
            keys.add(hostname, entry.key.get_name(), entry.key)
    if not keys.lookup(hostname):
        raise ValueError("Missing defense listener pin")
    return credential, key, keys


@dataclass(frozen=True)
class DefenseResult:
    reply: DefenseReply
    manifest: DefenseManifest | None
    reply_bytes: bytes = field(repr=False)
    reply_sha256: str
    mode_ack: bool


def _call_context(target: DefenseTarget, request: DefenseRequest | DefenseCall) -> DefenseCall:
    call = request if isinstance(request, DefenseCall) else DefenseCall(request)
    req = DefenseRequest.model_validate(call.request.model_dump(mode="python"))
    if req.scope_sha256 != target.root_scope_sha256:
        raise ValueError("Defense scope mismatch")
    if hasattr(req.body, "policy_sha256") and req.body.policy_sha256 != target.root_policy_sha256:
        raise ValueError("Defense policy mismatch")
    prepare = call.prepare_request
    if prepare is not None:
        prepare = DefenseRequest.model_validate(prepare.model_dump(mode="python"))
        if (
            prepare.op != "prepare"
            or prepare.request_id != req.request_id
            or prepare.scope_sha256 != req.scope_sha256
            or not isinstance(prepare.body, PrepareBody)
            or prepare.body.policy_sha256 != target.root_policy_sha256
        ):
            raise ValueError("Invalid original defense prepare")
    manifest = call.expected_manifest
    if manifest is not None:
        manifest = DefenseManifest.model_validate(manifest.model_dump(mode="python"))
        if (
            manifest.request_id != req.request_id
            or manifest.scope_sha256 != req.scope_sha256
            or manifest.policy_sha256 != target.root_policy_sha256
            or manifest.boot_ref != target.boot_ref
            or manifest.binding_ref != target.binding_ref
        ):
            raise ValueError("Invalid expected defense manifest")
    if isinstance(req.body, ActionBody):
        if manifest is None or req.body.manifest_sha256 != manifest.sha256:
            raise ValueError("Defense action requires exact stored manifest")
        approval = req.body.approval
        if (
            req.op == "apply"
            and ((manifest.mode == "auto") != (approval is None))
            or req.op == "apply"
            and approval is not None
            and utc(approval.expires_at) > utc(manifest.deadline_at)
        ):
            raise ValueError("Invalid defense apply declaration")
    if (
        req.op == "query"
        and isinstance(req.body, QueryBody)
        and req.body.kind == "action"
        and prepare is None
        and manifest is None
    ):
        raise ValueError("Defense action query requires original context")
    if (
        (call.expected_mode is None) != (call.expected_mode_revision is None)
        or call.expected_mode is not None
        and call.expected_mode not in {"manual", "semi", "auto"}
        or call.expected_mode_revision is not None
        and (
            type(call.expected_mode_revision) is not int
            or not 1 <= call.expected_mode_revision <= 2**31 - 1
        )
    ):
        raise ValueError("Invalid defense expected mode")
    return DefenseCall(req, prepare, manifest, call.expected_mode, call.expected_mode_revision)


def _validate_reply(target: DefenseTarget, call: DefenseCall, raw: bytes) -> DefenseResult:
    reply = DefenseReply.parse(raw)
    if canonical(reply) + b"\n" != raw:
        raise ValueError("Noncanonical defense reply")
    req = call.request
    if (
        reply.op != req.op
        or reply.request_id != req.request_id
        or reply.scope_sha256 != target.root_scope_sha256
        or reply.policy_sha256 != target.root_policy_sha256
        or reply.boot_ref != target.boot_ref
        or reply.binding_ref != target.binding_ref
    ):
        raise ValueError("Defense reply binding mismatch")
    kind = (
        req.body.kind
        if isinstance(req.body, QueryBody)
        else {"arm": "cursor", "mode_sync": "mode"}.get(req.op, "action")
    )
    states = {
        "cursor": {"armed", "attached", "consumed", "expired", "invalid"},
        "action": {"ready", "ready_expired", "active", "expired", "revoked", "unknown"},
        "mode": {"synced"},
    }[kind]
    if reply.state not in states | {"rejected", "not_found"}:
        raise ValueError("Defense reply state mismatch")
    manifest = None
    if kind == "action" and reply.action_id is not None:
        if reply.cursor_id is None or reply.manifest_sha256 is None or reply.deadline_at is None:
            raise ValueError("Incomplete defense action")
        prepare = req if req.op == "prepare" else call.prepare_request
        manifest = (
            rebuild_manifest(prepare, reply) if prepare is not None else call.expected_manifest
        )
        if (
            manifest is None
            or manifest.sha256 != reply.manifest_sha256
            or manifest.action_id != reply.action_id
            or manifest.cursor_id != reply.cursor_id
            or manifest.deadline_at != reply.deadline_at
            or manifest.mode != reply.mode
            or manifest.mode_revision != reply.mode_revision
            or call.expected_manifest is not None
            and manifest != call.expected_manifest
        ):
            raise ValueError("Defense manifest mismatch")
    elif kind == "action":
        if reply.state not in {"rejected", "not_found"} or any(
            v is not None for v in (reply.cursor_id, reply.manifest_sha256, reply.deadline_at)
        ):
            raise ValueError("Missing defense action")
    elif kind == "cursor":
        if reply.action_id is not None or reply.manifest_sha256 is not None:
            raise ValueError("Invalid defense cursor")
        if (reply.cursor_id is None) != (reply.deadline_at is None) or (
            reply.state not in {"rejected", "not_found"} and reply.cursor_id is None
        ):
            raise ValueError("Missing defense cursor")
    elif any(
        v is not None
        for v in (reply.action_id, reply.cursor_id, reply.manifest_sha256, reply.deadline_at)
    ):
        raise ValueError("Invalid defense mode reply")
    if reply.state == "not_found" and any(
        v is not None
        for v in (reply.action_id, reply.cursor_id, reply.manifest_sha256, reply.deadline_at)
    ):
        raise ValueError("Invalid defense not found payload")
    if reply.candidates and not (
        req.op == "query" and kind == "cursor" and reply.state in {"armed", "attached", "invalid"}
    ):
        raise ValueError("Unexpected defense candidates")
    if (
        req.op == "query"
        and kind == "cursor"
        and reply.state in {"armed", "attached", "invalid"}
        and len(reply.candidates) != 2
    ):
        raise ValueError("Incomplete defense candidate set")
    if (
        req.op == "mode_sync"
        and reply.state == "synced"
        and isinstance(req.body, ModeBody)
        and (reply.mode, reply.mode_revision) != (req.body.mode, req.body.mode_revision)
    ):
        raise ValueError("Defense mode mismatch")
    ack = (
        req.op == "query"
        and kind == "mode"
        and reply.state == "synced"
        and call.expected_mode is not None
        and reply.mode == call.expected_mode
        and reply.mode_revision == call.expected_mode_revision
    )
    if (
        req.op == "query"
        and kind == "mode"
        and reply.state == "synced"
        and call.expected_mode is not None
        and not ack
    ):
        raise ValueError("Defense mode mismatch")
    return DefenseResult(reply, manifest, raw, hashlib.sha256(raw).hexdigest(), ack)


def invoke(
    target: DefenseTarget,
    request: DefenseRequest | DefenseCall,
    role: DefenseRole,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    admit: Callable[[], None] | None = None,
) -> DefenseResult:
    """At most one connect/exec/send. Persist sendable BEFORE calling this function.

    A failure after attempting exec (including an interrupted/partial send) is unknown
    for mutations. Recover only by querying the original RID with its durable context.
    """
    try:
        if (
            type(target) is not DefenseTarget
            or type(role) is not str
            or role not in _OPERATIONS
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 30
            or admit is not None
            and not callable(admit)
        ):
            raise ValueError("Invalid defense invocation")
        call = _call_context(target, request)
        req = call.request
        if req.op not in _OPERATIONS[role]:
            raise ValueError("Invalid defense role operation")
        body = req.wire_bytes()
    except Exception:
        raise DefenseClientError("request_invalid") from None
    try:
        client = paramiko.SSHClient()
    except Exception:
        raise DefenseClientError() from None
    expired = threading.Event()
    deadline = time.monotonic() + timeout
    channel = None
    stdin = stdout = stderr = None
    dispatch_possible = False

    def close_at_deadline():
        expired.set()
        with suppress(Exception):
            client.close()

    def remaining():
        left = deadline - time.monotonic()
        if expired.is_set() or left <= 0:
            raise TimeoutError("Defense deadline")
        return left

    watchdog = threading.Timer(timeout, close_at_deadline)
    watchdog.daemon = True
    watchdog.start()
    try:
        credential, key, keys = _credentials(target, role)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        for name in keys:
            for kind, public_key in keys[name].items():
                client.get_host_keys().add(name, kind, public_key)
        budget = min(4.0, remaining())
        client.connect(
            target._host_binding[1],
            port=credential.port,
            username=credential.username,
            pkey=key,
            look_for_keys=False,
            allow_agent=False,
            timeout=budget,
            banner_timeout=budget,
            auth_timeout=budget,
            channel_timeout=budget,
        )
        remaining()
        if admit is not None:
            admit()
            remaining()
        # Exec starts the fixed Root entry before stdin; conservatively unknown from here.
        dispatch_possible = True
        # Paramiko's stdin file destructor sends channel EOF. Keep every wrapper
        # alive until the explicit request write and output drain have finished.
        stdin, stdout, stderr = client.exec_command(
            COMMANDS[role], timeout=remaining(), get_pty=False
        )
        channel = stdout.channel
        channel.settimeout(remaining())
        if admit is not None:
            admit()
            remaining()
        channel.sendall(body)
        channel.shutdown_write()
        output, errors = bytearray(), bytearray()
        while True:
            remaining()
            if channel.recv_ready():
                chunk = channel.recv(min(4096, MAX_OUTPUT_BYTES - len(output) + 1))
                if not chunk or len(output) + len(chunk) > MAX_OUTPUT_BYTES:
                    raise ValueError("Defense output budget")
                output.extend(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(min(4096, MAX_ERROR_BYTES - len(errors) + 1))
                if not chunk or len(errors) + len(chunk) > MAX_ERROR_BYTES:
                    raise ValueError("Defense error budget")
                errors.extend(chunk)
            if channel.closed and not channel.eof_received:
                raise EOFError("Defense closed without output EOF")
            if (
                channel.eof_received
                and channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                code = channel.recv_exit_status()
                # recv_exit_status itself may release data already queued behind status.
                if channel.recv_ready() or channel.recv_stderr_ready():
                    continue
                break
            time.sleep(min(0.01, remaining()))
        remaining()
        if code != 0 or errors:
            raise ValueError("Defense process unavailable")
        result = _validate_reply(target, call, bytes(output))
        remaining()
        return result
    except Exception:
        if dispatch_possible and req.op != "query":
            raise UnknownDefenseResult(req.request_id) from None
        raise DefenseClientError() from None
    finally:
        watchdog.cancel()
        if channel is not None:
            with suppress(Exception):
                channel.close()
        for stream in (stdin, stdout, stderr):
            if stream is not None:
                with suppress(Exception):
                    stream.close()
        with suppress(Exception):
            client.close()
