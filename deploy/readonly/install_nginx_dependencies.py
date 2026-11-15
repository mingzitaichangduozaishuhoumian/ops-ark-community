#!/usr/bin/python3 -I
"""Explicit administrator install of the bounded projection helper and its scope."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

POLICY = Path("/etc/opsark/readonly-policy.json")
TARGET = Path("/usr/local/libexec/opsark-nginx-dependencies")
SCOPE = Path("/etc/opsark/nginx-dependency-scope.json")
MARKER = Path("/etc/opsark/nginx-dependency-installed.json")
COMMAND = "LC_ALL=C timeout -k 1s 5s /usr/local/libexec/opsark-nginx-dependencies"


def trusted(path, *, directory=False):
    s = path.lstat()
    if (
        not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
        or s.st_uid != 0
        or s.st_mode & 0o022
    ):
        raise ValueError("Untrusted deployment path")


def write_root(path, raw, mode):
    for parent in reversed(path.parents):
        trusted(parent, directory=True)
    temp = path.with_name(".opsark-nginx-install-" + path.name + "-" + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, 0, 0)
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def read_root(path, limit):
    if not path.is_absolute():
        raise ValueError("Administrator input must be absolute")
    for parent in reversed(path.parents):
        trusted(parent, directory=True)
    trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != 0
            or s.st_mode & 0o022
            or s.st_nlink != 1
            or not 0 < s.st_size <= limit
        ):
            raise ValueError("Administrator input metadata rejected")
        raw = os.read(fd, limit + 1)
        if len(raw) != s.st_size:
            raise ValueError("Administrator input changed")
        return raw
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        raise ValueError("A root administrator and independently checked scope digest are required")
    scope_raw = read_root(args.scope, 4096)
    if hashlib.sha256(scope_raw).hexdigest() != args.expected_sha256:
        raise ValueError("Scope digest differs")
    source = Path(__file__).resolve().parent / "nginx_dependencies.py"
    helper = read_root(source, 65536)
    spec = importlib.util.spec_from_file_location("reviewed_nginx_projection", source)
    if spec is None or spec.loader is None:
        raise ValueError("Reviewed helper unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.checked_scope(scope_raw)
    policy = json.loads(read_root(POLICY, 262144))
    if policy.get("commands", {}).get(COMMAND) != ["timeout", "-k", "1s", "5s", str(TARGET)]:
        raise ValueError("Exact helper command is not in the installed read-only policy")
    prior = json.loads(read_root(MARKER, 4096)) if MARKER.exists() else {}
    for path, key in ((TARGET, "helper_sha256"), (SCOPE, "scope_sha256")):
        if path.exists() or path.is_symlink():
            old = read_root(path, 65536)
            if hashlib.sha256(old).hexdigest() not in {prior.get(key), prior.get("pending_" + key)}:
                raise ValueError("Refusing an unrelated or drifted existing file")
    helper_sha = hashlib.sha256(helper).hexdigest()
    # The marker admits both sides of an interrupted administrator update.
    write_root(
        MARKER,
        module.canonical(
            {
                "helper_sha256": prior.get("helper_sha256"),
                "scope_sha256": prior.get("scope_sha256"),
                "pending_helper_sha256": helper_sha,
                "pending_scope_sha256": args.expected_sha256,
            }
        ),
        0o600,
    )
    write_root(TARGET, helper, 0o755)
    write_root(SCOPE, scope_raw, 0o600)
    write_root(
        MARKER,
        module.canonical({"helper_sha256": helper_sha, "scope_sha256": args.expected_sha256}),
        0o600,
    )
    print(
        json.dumps(
            {
                "installed": True,
                "helper_sha256": helper_sha,
                "scope_sha256": args.expected_sha256,
                "permissions_expanded": False,
                "ssh_restarted": False,
            }
        )
    )


if __name__ == "__main__":
    main()
