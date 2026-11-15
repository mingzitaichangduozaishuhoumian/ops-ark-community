#!/usr/bin/python3 -I
"""Install the opted-in Compose generation helper under the existing read-only guard."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import types
from pathlib import Path

POLICY = Path("/etc/opsark/readonly-policy.json")
TARGET = Path("/usr/local/libexec/opsark-compose-generation")
SCOPE = Path("/etc/opsark/compose-generation-scope.json")
MARKER = Path("/etc/opsark/compose-generation-installed.json")
KEY = Path("/etc/opsark/compose-generation-key")
COMMAND = "LC_ALL=C timeout -k 1s 5s /usr/local/libexec/opsark-compose-generation"
SCHEMA = "opsark-compose-generation-install/v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
LIMIT = 65536


def need(ok):
    if not ok:
        raise ValueError("Compose generation helper installation refused")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_shared(source):
    path = source / "install_compose_volume_metadata.py"
    for parent in reversed(path.parents):
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022)
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and not before.st_mode & 0o022
        and before.st_nlink == 1
        and 0 < before.st_size <= LIMIT
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        need(os.fstat(stream.fileno()) == before)
        raw = stream.read(LIMIT + 1)
        # Reading may update atime. The already-open inode still has to be current.
        after = os.fstat(stream.fileno())
        need(
            len(raw) == before.st_size
            and os.path.samestat(before, after)
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
            and os.path.samestat(before, path.lstat())
        )
    module = types.ModuleType("reviewed_compose_generation_install_files")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), vars(module))  # noqa: S102 -- checked root-only source.
    return module


def checked_marker(shared, tools, helper, old, desired):
    raw = shared.installed_bytes(MARKER, 0o600, 4096, tools)
    if raw is None:
        need(old == (None, None))
        return old
    value = helper.decode(raw, "scope_invalid")
    need(type(value) is dict and raw == helper.canonical(value) and value.get("schema") == SCHEMA)
    prior = (value.get("helper_sha256"), value.get("scope_sha256"))

    def valid(pair):
        return all(type(item) is str and SHA.fullmatch(item) is not None for item in pair)

    base = {"schema", "helper_sha256", "scope_sha256"}
    if value.keys() == base:
        need(valid(prior) and old == prior)
    else:
        need(value.keys() == base | {"pending_helper_sha256", "pending_scope_sha256"})
        pending = (value["pending_helper_sha256"], value["pending_scope_sha256"])
        need(
            (prior == (None, None) or valid(prior))
            and valid(pending)
            and pending == desired
            and old in (prior, (pending[0], prior[1]), pending)
        )
    return prior


def install(source, scope_path, expected):
    need(sys.platform == "linux" and os.geteuid() == 0 and SHA.fullmatch(expected) is not None)
    shared = load_shared(source)
    tools = shared.filesystem_tools(source)
    helper_path, guard_path = source / "compose_generation.py", source / "guard.py"
    helper_raw = tools.read_root(helper_path, LIMIT)
    helper = shared.reviewed(helper_path, "reviewed_compose_generation", helper_raw)
    guard = shared.reviewed(
        guard_path, "reviewed_generation_guard", tools.read_root(guard_path, LIMIT)
    )
    scope_raw = tools.read_root(scope_path, 4096)
    need(digest(scope_raw) == expected)
    helper.checked_scope(scope_raw)
    desired = (digest(helper_raw), expected)

    def require_policy():
        need(guard.load_policy(POLICY).get(COMMAND) == ["timeout", "-k", "1s", "5s", str(TARGET)])

    def installed():
        return (
            shared.installed_digest(TARGET, 0o755, LIMIT, tools),
            shared.installed_digest(SCOPE, 0o600, 4096, tools),
        )

    with shared.installation_slot(MARKER.parent, tools):
        require_policy()
        key, key_identity = helper.read_private(KEY, 32)
        need(len(key) == 32)
        del key
        prior = checked_marker(shared, tools, helper, installed(), desired)
        final = {"schema": SCHEMA, "helper_sha256": desired[0], "scope_sha256": desired[1]}
        pending = final | {
            "helper_sha256": prior[0],
            "scope_sha256": prior[1],
            "pending_helper_sha256": desired[0],
            "pending_scope_sha256": desired[1],
        }
        shared.write_verified(MARKER, helper.canonical(pending), 0o600, tools)
        shared.write_verified(TARGET, helper_raw, 0o755, tools)
        shared.write_verified(SCOPE, scope_raw, 0o600, tools)
        need(installed() == desired and helper.identity(KEY.lstat()) == key_identity)
        require_policy()
        shared.write_verified(MARKER, helper.canonical(final), 0o600, tools)
    return {"installed": True, "helper_sha256": desired[0], "scope_sha256": expected}


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
