#!/usr/bin/env python3
"""Operate one bounded SSH source containment in a disposable local fixture."""

import argparse
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

if not __package__:
    sys.dont_write_bytecode = True
    entry = Path(__file__).absolute()
    for path in (entry, *entry.parents):
        info = path.lstat()
        expected = stat.S_ISREG if path == entry else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit("An administrator-owned fixture tool is required.")
    sys.path.insert(0, str(entry.parents[2]))

from deploy.defense import ssh_fixture_evidence, ssh_fixture_nft  # noqa: E402

ROOT = Path("/run/opsark-ssh-defense")
PORT = 22422
SOURCES = frozenset({"127.0.0.2", "127.0.0.4"})
MARKER = b"opsark-ssh-defense-fixture-v1\n"
GRANT_NS = 120_000_000_000
MAX_LEDGER = 16_384
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
LEDGER = "ledger.json"


@dataclass(frozen=True)
class FixtureProfile:
    marker: bytes
    interface: str
    address: str
    sources: frozenset[str]


PROFILES = {
    "loopback": FixtureProfile(MARKER, "lo", "127.0.0.1", SOURCES),
    "private": FixtureProfile(
        b"opsark-ssh-defense-private-v1\n",
        "eth0",
        "198.18.241.2",
        frozenset({"198.18.241.3", "198.18.241.5"}),
    ),
}


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_uid,
        info.st_ctime_ns,
        info.st_mtime_ns,
    )


def _read(directory: int, name: str, limit: int, *, private: bool = True) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & (0o077 if private else 0o022)
            or not 0 < info.st_size <= limit
        ):
            raise ValueError("Untrusted fixture state")
        data = file.read(limit + 1)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        identity = _file_identity(info)
        if (
            len(data) != info.st_size
            or _file_identity(current) != identity
            or _file_identity(os.fstat(file.fileno())) != identity
        ):
            raise ValueError("Fixture state changed")
        return data


def _proc_address(address: str) -> str:
    return socket.inet_aton(address)[::-1].hex().upper()


def _verify_interface(profile: FixtureProfile) -> int:
    import fcntl

    interfaces = {
        line.partition(":")[0].strip()
        for line in Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]
    }
    if interfaces != {"lo", profile.interface}:
        raise ValueError("The fixture network interfaces do not match")
    if profile.interface == "eth0":
        request = struct.pack("256s", profile.interface.encode("ascii"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as query:
            address = fcntl.ioctl(query.fileno(), 0x8915, request)[20:24]
        rows = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        routes = [tuple(fields[:3] + fields[7:8]) for fields in map(str.split, rows)]
        ipv6_routes = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
        ipv6_default = any(
            fields[:2] == ["0" * 32, "00"] and fields[-1] != "lo"
            for fields in map(str.split, ipv6_routes)
        )
        expected_route = (
            "eth0",
            _proc_address("198.18.241.0"),
            "00000000",
            _proc_address("255.255.255.240"),
        )
        if (
            address != socket.inet_aton(profile.address)
            or routes != [expected_route]
            or ipv6_default
        ):
            raise ValueError("The fixture address or isolated route does not match")
    return socket.if_nametoindex(profile.interface)


def _listener(directory: int, *, profile: str = "loopback") -> list[int]:
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise ValueError("An isolated Docker fixture is required")
    scope = PROFILES[profile]
    if _read(directory, "lab.marker", len(scope.marker)) != scope.marker:
        raise ValueError("The fixture marker is absent")
    interface = _verify_interface(scope)
    ns = os.stat("/proc/self/ns/net")
    if not os.path.samestat(ns, os.stat("/proc/1/ns/net")):
        raise ValueError("Network namespace changed")
    raw = _read(directory, "sshd.pid", 16, private=False)
    if not re.fullmatch(rb"[1-9][0-9]{0,8}\n", raw):
        raise ValueError("Invalid native listener identity")
    pid = int(raw)
    process = Path("/proc") / str(pid)
    if (
        process.stat().st_uid != 0
        or (process / "exe").resolve(strict=True) != Path("/usr/sbin/sshd").resolve(strict=True)
        or not os.path.samestat(ns, (process / "ns/net").stat())
    ):
        raise ValueError("Native fixture listener changed")
    started = int((process / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[19])
    port = f"{PORT:04X}"
    rows = [
        fields
        for line in Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        if (fields := line.split())[3] == "0A" and fields[1].endswith(":" + port)
    ]
    if len(rows) != 1 or rows[0][1] != _proc_address(scope.address) + ":" + port:
        raise ValueError("The exact fixture listener is absent")
    inode = int(rows[0][9])
    descriptors = tuple((process / "fd").iterdir())
    if not any(
        descriptor.is_symlink() and _is_listener_fd(descriptor, inode) for descriptor in descriptors
    ):
        raise ValueError("The socket does not belong to the approved native listener")
    log = os.stat("sshd.log", dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(log.st_mode)
        or log.st_uid != 0
        or log.st_nlink != 1
        or stat.S_IMODE(log.st_mode) != 0o600
        or not any(_same_open_file(descriptor, log) for descriptor in descriptors)
    ):
        raise ValueError("The log does not belong to the approved native listener")
    return [ns.st_dev, ns.st_ino, interface, pid, started, inode, log.st_dev, log.st_ino]


def _bound_listener(directory: int, profile: str) -> list[int]:
    return _listener(directory) if profile == "loopback" else _listener(directory, profile=profile)


def _nft(profile, method, *args):
    return method(*args) if profile == "loopback" else method(*args, profile=profile)


def _is_listener_fd(path: Path, inode: int) -> bool:
    with suppress(FileNotFoundError):
        return os.readlink(path) == f"socket:[{inode}]"
    return False


def _same_open_file(path: Path, info: os.stat_result) -> bool:
    with suppress(FileNotFoundError):
        return os.path.samestat(path.stat(), info)
    return False


@contextmanager
def _locked():
    import fcntl

    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        parent = ROOT.parent.lstat()
        if (
            info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_mode & 0o022
        ):
            raise ValueError("Fixture directory is not private")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def _ledger(directory: int, binding: list[int]) -> dict:
    try:
        raw = _read(directory, LEDGER, MAX_LEDGER)
    except FileNotFoundError:
        return {"binding": binding, "grants": {}}
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"binding", "grants"}
        or value["binding"] != binding
        or not isinstance(value["grants"], dict)
        or len(value["grants"]) > 8
        or raw != _json(value) + b"\n"
    ):
        raise ValueError("Untrusted fixture ledger")
    return value


def _save(directory: int, ledger: dict) -> None:
    raw = _json(ledger) + b"\n"
    if len(raw) > MAX_LEDGER:
        raise ValueError("Fixture ledger exceeded its bound")
    pending = ".pending-" + secrets.token_hex(8)
    fd = os.open(
        pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        os.rename(pending, LEDGER, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(pending, dir_fd=directory)


def _grant(directory: int, ledger: dict, source: str, *, profile: str = "loopback") -> dict:
    grants = ledger["grants"]
    now = time.monotonic_ns()
    if (
        source not in PROFILES[profile].sources
        or len(grants) >= 8
        or _nft(profile, ssh_fixture_nft.observe) is not None
        or _unfinished(grants, now)
        or any(
            grant["phase"] == "ready" and grant["source"] == source and grant["expires"] > now
            for grant in grants.values()
        )
    ):
        raise ValueError("A new fixture grant was refused")
    identifier = secrets.token_hex(16)
    if identifier in grants:
        raise ValueError("Unexpected duplicate grant identity")
    grants[identifier] = {
        "source": source,
        "mark": ssh_fixture_evidence.bookmark(ROOT / "sshd.log"),
        "expires": now + GRANT_NS,
        "phase": "ready",
    }
    _save(directory, ledger)
    return {"grant_id": identifier, "status": "ready"}


def _unfinished(grants: dict, now: int) -> bool:
    return any(
        grant["phase"] in {"intent", "revoke_intent"}
        or (grant["phase"] == "active" and now < grant["expiry_bound"])
        for grant in grants.values()
    )


def _result(identifier: str, status: str, remaining: int | None = None) -> dict:
    return {"action_id": identifier, "status": status, "remaining_ms": remaining}


def _observe(
    directory: int,
    ledger: dict,
    identifier: str,
    grant: dict,
    *,
    profile: str = "loopback",
    reconcile_intent: bool = True,
) -> dict:
    phase = grant["phase"]
    if phase == "ready":
        raise ValueError("The approved action has no recorded intent")
    if phase == "revoked":
        return _result(identifier, "revoked")
    live = _nft(profile, ssh_fixture_nft.observe)
    if live is not None and (live[0], live[2]) == (grant["source"], identifier):
        if phase == "intent" and reconcile_intent:
            grant.update(
                phase="active", expiry_bound=time.monotonic_ns() + (live[1] + 100) * 1_000_000
            )
            _save(directory, ledger)
        if phase in ("intent", "active"):
            return _result(identifier, "active", live[1])
    if phase == "active" and time.monotonic_ns() >= grant["expiry_bound"]:
        return _result(identifier, "expired")
    return _result(identifier, "unknown")


def _apply(
    directory: int, ledger: dict, identifier: str, grant: dict, *, profile: str = "loopback"
) -> dict:
    if grant["phase"] != "ready":
        return _observe(directory, ledger, identifier, grant, profile=profile)
    now = time.monotonic_ns()
    if (
        now >= grant["expires"]
        or _nft(profile, ssh_fixture_nft.observe) is not None
        or _unfinished(ledger["grants"], now)
    ):
        raise ValueError("The grant is no longer eligible")
    evidence = ssh_fixture_evidence.inspect(ROOT / "sshd.log", grant["mark"], grant["source"])
    if (
        not DIGEST.fullmatch(evidence)
        or time.monotonic_ns() >= grant["expires"]
        or _bound_listener(directory, profile) != ledger["binding"]
    ):
        raise ValueError("The grant evidence is no longer eligible")
    grant.update(phase="intent", evidence_sha256=evidence)
    _save(directory, ledger)
    if (
        ssh_fixture_evidence.inspect(ROOT / "sshd.log", grant["mark"], grant["source"]) != evidence
        or time.monotonic_ns() >= grant["expires"]
        or _bound_listener(directory, profile) != ledger["binding"]
    ):
        raise ValueError("Fixture evidence changed after recording the intent")
    _nft(profile, ssh_fixture_nft.add, grant["source"], identifier)
    return _observe(directory, ledger, identifier, grant, profile=profile)


def _revoke(
    directory: int, ledger: dict, identifier: str, grant: dict, *, profile: str = "loopback"
) -> dict:
    current = _observe(directory, ledger, identifier, grant, profile=profile)
    if current["status"] != "active":
        return current
    grant["phase"] = "revoke_intent"
    _save(directory, ledger)
    _nft(profile, ssh_fixture_nft.remove, grant["source"], identifier)
    live = _nft(profile, ssh_fixture_nft.observe)
    if live is not None and (live[0], live[2]) == (grant["source"], identifier):
        return _result(identifier, "unknown")
    grant["phase"] = "revoked"
    _save(directory, ledger)
    return _result(identifier, "revoked")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="loopback")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("initialize")
    grant = commands.add_parser("grant")
    grant.add_argument("--source", required=True)
    grant.add_argument("--confirm", action="store_true", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--grant-id", required=True)
    status = commands.add_parser("status")
    readonly_status = commands.add_parser("status-readonly")
    revoke = commands.add_parser("revoke")
    for action in (status, readonly_status, revoke):
        action.add_argument("--action-id", required=True)
    revoke.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    try:
        with _locked() as directory:
            binding = _bound_listener(directory, args.profile)
            ledger = _ledger(directory, binding)
            if args.command == "initialize":
                _nft(args.profile, ssh_fixture_nft.initialize)
                _save(directory, ledger)
                result = {"status": "initialized"}
            elif args.command == "grant":
                result = _grant(directory, ledger, args.source, profile=args.profile)
            else:
                identifier = args.grant_id if args.command == "apply" else args.action_id
                if not IDENTIFIER.fullmatch(identifier):
                    raise ValueError("Invalid action identity")
                record = ledger["grants"][identifier]
                if record["source"] not in PROFILES[args.profile].sources:
                    raise ValueError("Invalid approved source")
                if args.command == "status-readonly":
                    result = _observe(
                        directory,
                        ledger,
                        identifier,
                        record,
                        profile=args.profile,
                        reconcile_intent=False,
                    )
                else:
                    operation = {"apply": _apply, "status": _observe, "revoke": _revoke}[
                        args.command
                    ]
                    result = operation(directory, ledger, identifier, record, profile=args.profile)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, IndexError):
        print("The isolated SSH defense action could not be confirmed.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
