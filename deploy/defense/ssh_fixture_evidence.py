"""Read bounded native SSH authentication evidence for a private lab fixture."""

import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path

_MAX_BYTES = 65_536
_MAX_LINES = 256
_MAX_LINE_BYTES = 2048
_REQUIRED_FAILURES = 5
_SOURCES = {"127.0.0.2", "127.0.0.4", "198.18.241.3", "198.18.241.5"}
_USER = b"opsark-ssh-lab"
_ERROR = "SSH fixture evidence could not be verified"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_AUTH = re.compile(
    rb"(?P<kind>Failed|Accepted) (?P<method>[A-Za-z0-9_./-]{1,64}) for "
    rb"(?P<invalid>invalid user )?(?P<user>[A-Za-z0-9._@-]{1,64}) "
    rb"from (?P<peer>[0-9A-Fa-f:.]{2,45}) port (?P<port>[1-9][0-9]{0,4}) "
    rb"ssh2(?:: [\x20-\x7e]{1,1024})?(?: \[preauth\])?"
)


def _log_identity(info: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or not 0 <= info.st_size <= _MAX_BYTES
    ):
        raise ValueError
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _trusted_directory(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError


def _read_log(path: Path) -> tuple[int, int, bytes]:
    if (
        os.geteuid() != 0
        or not isinstance(path, Path)
        or path.anchor != "/"
        or len(path.parts) < 2
        or ".." in path.parts
    ):
        raise ValueError
    flags = os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        _trusted_directory(parent)
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            _trusted_directory(parent)
        before = _log_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "rb") as handle:
            if _log_identity(os.fstat(handle.fileno())) != before:
                raise ValueError
            data = handle.read(_MAX_BYTES + 1)
            if (
                len(data) != before[2]
                or _log_identity(os.fstat(handle.fileno())) != before
                or _log_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != before
            ):
                raise ValueError
        if data and not data.endswith(b"\n"):
            raise ValueError
        return before[0], before[1], data
    finally:
        os.close(parent)


def bookmark(path: Path) -> dict:
    """Pin the existing inode and complete prefix before a local grant is issued."""
    try:
        dev, ino, data = _read_log(path)
        return {"dev": dev, "ino": ino, "offset": len(data), "prefix_sha256": _sha(data)}
    except (OSError, TypeError, ValueError):
        raise ValueError(_ERROR) from None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _eligible_failures(appended: bytes, source: str) -> list[str]:
    lines = appended.split(b"\n")
    if len(lines) > _MAX_LINES + 1 or lines[-1] != b"":
        raise ValueError
    failures: dict[int, str] = {}
    for raw in lines[:-1]:
        # OpenSSH's native -E output can terminate records with CRLF.
        line = raw.removesuffix(b"\r")
        if len(line) > _MAX_LINE_BYTES or re.fullmatch(rb"[\x20-\x7e]*", line) is None:
            raise ValueError
        # OpenSSH VERBOSE may print a key-file lookup before the authentication outcome.
        if line.startswith(b"Accepted key ") and b" found at " in line:
            continue
        if not line.startswith((b"Failed publickey for ", b"Accepted ")):
            continue
        event = _AUTH.fullmatch(line)
        if event is None:
            raise ValueError
        peer = ipaddress.ip_address(event["peer"].decode("ascii"))
        port = int(event["port"])
        if port > 65535:
            raise ValueError
        if event["kind"] == b"Accepted":
            mapped = peer.ipv4_mapped if isinstance(peer, ipaddress.IPv6Address) else None
            if str(peer) == source or (mapped is not None and str(mapped) == source):
                raise ValueError
        elif str(peer) == source and event["user"] == _USER and event["invalid"] is None:
            failures.setdefault(port, _sha(line))
    if len(failures) < _REQUIRED_FAILURES:
        raise ValueError
    return list(failures.values())[:_REQUIRED_FAILURES]


def inspect(path: Path, mark: dict, source: str) -> str:
    """Return a digest of fresh eligible evidence, with no log text or credentials."""
    try:
        if (
            source not in _SOURCES
            or not isinstance(mark, dict)
            or set(mark) != {"dev", "ino", "offset", "prefix_sha256"}
            or any(type(mark[key]) is not int for key in ("dev", "ino", "offset"))
            or not 0 <= mark["offset"] <= _MAX_BYTES
            or not isinstance(mark["prefix_sha256"], str)
            or not _DIGEST.fullmatch(mark["prefix_sha256"])
        ):
            raise ValueError
        dev, ino, data = _read_log(path)
        offset = mark["offset"]
        if (
            (dev, ino) != (mark["dev"], mark["ino"])
            or len(data) <= offset
            or (offset and data[offset - 1 : offset] != b"\n")
            or _sha(data[:offset]) != mark["prefix_sha256"]
        ):
            raise ValueError
        failures = _eligible_failures(data[offset:], source)
        return _sha(
            json.dumps(
                ["opsark-ssh-fixture-evidence/v1", mark, source, failures],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
    except (OSError, TypeError, ValueError):
        raise ValueError(_ERROR) from None
