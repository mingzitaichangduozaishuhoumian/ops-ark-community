#!/usr/bin/python3 -I
"""Install the reviewed Compose volume helper after its exact policy is enrolled."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import types
from contextlib import contextmanager
from pathlib import Path

POLICY = Path("/etc/opsark/readonly-policy.json")
TARGET = Path("/usr/local/libexec/opsark-compose-volume-metadata")
SCOPE = Path("/etc/opsark/compose-volume-metadata-scope.json")
MARKER = Path("/etc/opsark/compose-volume-metadata-installed.json")
COMMAND = "LC_ALL=C timeout -k 1s 5s /usr/local/libexec/opsark-compose-volume-metadata"
SCHEMA = "opsark-compose-volume-metadata-install/v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
LIMIT = 65_536


def need(condition):
    if not condition:
        raise ValueError("Compose volume helper installation refused")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def reviewed(source, name, raw):
    """Execute only the exact root-owned bytes already read from the reviewed tree."""
    module = types.ModuleType(name)
    module.__file__ = str(source)
    exec(compile(raw, str(source), "exec"), vars(module))  # noqa: S102 -- fixed reviewed file.
    return module


def filesystem_tools(source):
    # Bootstrap the existing Nginx install filesystem helpers without adding a
    # search path or letting Python load a sibling __pycache__ file as root.
    path = source / "install_nginx_dependencies.py"
    for parent in reversed(path.parents):
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and row.st_mode & 0o022 == 0)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as reader:
        before = os.fstat(reader.fileno())
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_mode & 0o022 == 0
            and before.st_nlink == 1
            and 0 < before.st_size <= LIMIT
        )
        raw = reader.read(LIMIT + 1)
        after = os.fstat(reader.fileno())
        current = path.lstat()
        need(
            len(raw) == before.st_size and identity(before) == identity(after) == identity(current)
        )
    return reviewed(path, "compose_volume_install_files", raw)


@contextmanager
def installation_slot(path, tools):
    import fcntl

    for parent in reversed((path, *path.parents)):
        tools.trusted(parent, directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(
            before.st_uid == 0
            and before.st_mode & 0o022 == 0
            and os.path.samestat(before, path.lstat())
        )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def installed_digest(path, mode, limit, tools):
    raw = installed_bytes(path, mode, limit, tools)
    return digest(raw) if raw is not None else None


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def installed_bytes(path, mode, limit, tools):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_IMODE(before.st_mode) == mode and before.st_gid == 0)
    raw = tools.read_root(path, limit)
    need(identity(before) == identity(path.lstat()))
    return raw


def authorized(guard):
    need(guard.load_policy(POLICY).get(COMMAND) == ["timeout", "-k", "1s", "5s", str(TARGET)])


def marker(tools, helper, old, desired):
    raw = installed_bytes(MARKER, 0o600, 4096, tools)
    if raw is None:
        need(old == (None, None))
        return old
    data = helper.strict(raw)
    need(type(data) is dict and raw == helper.canonical(data) and data.get("schema") == SCHEMA)
    installed = (data.get("helper_sha256"), data.get("scope_sha256"))

    def valid(pair):
        return all(type(value) is str and SHA.fullmatch(value) for value in pair)

    base = {"schema", "helper_sha256", "scope_sha256"}
    if data.keys() == base:
        need(valid(installed) and old == installed)
    else:
        need(data.keys() == base | {"pending_helper_sha256", "pending_scope_sha256"})
        pending = (data["pending_helper_sha256"], data["pending_scope_sha256"])
        need(
            (installed == (None, None) or valid(installed))
            and valid(pending)
            and pending == desired
            and old in (installed, (pending[0], installed[1]), pending)
        )
    return installed


def write_verified(path, raw, mode, tools):
    tools.write_root(path, raw, mode)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == mode
            and before.st_nlink == 1
            and os.path.samestat(before, path.lstat())
            and before.st_size == len(raw)
        )
        with os.fdopen(os.dup(fd), "rb") as reader:
            need(reader.read(len(raw) + 1) == raw)
        need(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()))
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(source, scope_path, expected):
    need(sys.platform == "linux" and os.geteuid() == 0 and bool(SHA.fullmatch(expected)))
    tools = filesystem_tools(source)
    helper_path = source / "compose_volume_metadata.py"
    helper_raw = tools.read_root(helper_path, LIMIT)
    helper = reviewed(helper_path, "reviewed_compose_volume_helper", helper_raw)
    guard_path = source / "guard.py"
    guard = reviewed(
        guard_path, "reviewed_compose_volume_guard", tools.read_root(guard_path, LIMIT)
    )
    scope_raw = tools.read_root(scope_path, 4096)
    need(digest(scope_raw) == expected)
    helper.scope_project(scope_raw)
    desired = (digest(helper_raw), expected)

    with installation_slot(MARKER.parent, tools):
        authorized(guard)
        old = (
            installed_digest(TARGET, 0o755, LIMIT, tools),
            installed_digest(SCOPE, 0o600, 4096, tools),
        )
        installed = marker(tools, helper, old, desired)
        # Durable marker precedes any replacement. Resume admits only this exact
        # pending pair and only the intermediate states this ordering produces.
        final = {"schema": SCHEMA, "helper_sha256": desired[0], "scope_sha256": desired[1]}
        pending = final | {
            "helper_sha256": installed[0],
            "scope_sha256": installed[1],
            "pending_helper_sha256": desired[0],
            "pending_scope_sha256": desired[1],
        }
        write_verified(MARKER, helper.canonical(pending), 0o600, tools)
        write_verified(TARGET, helper_raw, 0o755, tools)
        write_verified(SCOPE, scope_raw, 0o600, tools)
        need(
            (
                installed_digest(TARGET, 0o755, LIMIT, tools),
                installed_digest(SCOPE, 0o600, 4096, tools),
            )
            == desired
        )
        authorized(guard)
        write_verified(MARKER, helper.canonical(final), 0o600, tools)
    return {
        "installed": True,
        "helper_sha256": desired[0],
        "scope_sha256": desired[1],
        "permissions_expanded": False,
        "ssh_restarted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        result = install(Path(__file__).absolute().parent, args.scope, args.expected_sha256)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        print('{"installed":false,"reason":"install_refused"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
