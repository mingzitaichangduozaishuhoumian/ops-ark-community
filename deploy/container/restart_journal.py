"""Private durable record primitives for the dedicated container restart role."""

import os
import secrets
import stat
import sys
from contextlib import contextmanager, suppress

if __package__:
    from .restart_runtime import canonical, decode, digest, need
else:
    from restart_runtime import canonical, decode, digest, need

if sys.platform == "linux":
    import fcntl

MAX_RECORD = 8192


@contextmanager
def directory(path, *, locked=False):
    need(
        sys.platform == "linux"
        and os.geteuid() == 0
        and path.anchor == "/"
        and ".." not in path.parts,
        "policy_refused",
    )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            metadata = os.fstat(fd)
            need(metadata.st_uid == 0 and not metadata.st_mode & 0o022, "policy_refused")
            if locked:
                os.fsync(fd)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        metadata = os.fstat(fd)
        need(metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o700, "policy_refused")
        if locked:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                need(False, "busy")
            os.fsync(fd)
        yield fd
    finally:
        os.close(fd)


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read(fd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        item = os.open(name, flags, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(item, "rb") as handle:
        before = os.fstat(handle.fileno())
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= MAX_RECORD
        )
        raw = handle.read(MAX_RECORD + 1)
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(
            len(raw) == before.st_size
            and identity(before) == identity(os.fstat(handle.fileno())) == identity(current)
        )
    value = decode(raw)
    need(type(value) is dict and raw == canonical(value) + b"\n")
    return value


def record(fd, name):
    envelope = read(fd, name)
    if envelope is None:
        return None
    need(
        set(envelope) == {"body", "sha256"}
        and type(envelope["body"]) is dict
        and envelope["sha256"] == digest(envelope["body"])
    )
    return envelope["body"]


def publish(fd, name, body):
    need(record(fd, name) is None, "conflict")
    raw = canonical({"body": body, "sha256": digest(body)}) + b"\n"
    need(0 < len(raw) <= MAX_RECORD)
    pending = ".pending-" + secrets.token_hex(16)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    item = os.open(pending, flags, 0o600, dir_fd=fd)
    try:
        with os.fdopen(item, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(pending, dir_fd=fd)
