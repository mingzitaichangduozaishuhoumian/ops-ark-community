#!/usr/bin/python3 -I
"""Install the fixed Nginx log helper for an existing restricted policy."""

import argparse
import hashlib
import json
import os
import re
import shlex
import stat
from pathlib import Path

TARGET = Path("/usr/local/libexec/opsark-nginx-error-window")
POLICY = Path("/etc/opsark/readonly-policy.json")
MARKER = Path("/etc/opsark/nginx-error-window-installed.json")
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
RAW_LOG = ["timeout", "-k", "1s", "5s", "tail", "-n", "80", "--", "/var/log/nginx/error.log"]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def installer(source):
    path = source / "install_nginx_dependencies.py"
    for folder in (source, *source.parents):
        info = folder.lstat()
        if not folder.is_dir() or folder.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Untrusted deployment directory")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or not 0 < info.st_size <= 65_536
        ):
            raise ValueError("Untrusted deployment helper")
        raw = stream.read(65_537)
        before = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        after = path.lstat()
        current = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(raw) != info.st_size or current != before:
            raise ValueError("Deployment helper changed while reading")
    module = {"__name__": "opsark_readonly_installer", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), module)  # noqa: S102 -- trusted bounded root source.
    return module["read_root"], module["write_root"]


def install(source, domain, expected):
    if (
        os.geteuid() != 0
        or SHA.fullmatch(expected) is None
        or not 0 < len(domain) <= 253
        or not all(LABEL.fullmatch(label) for label in domain.split("."))
    ):
        raise ValueError("Administrator, literal domain and independently reviewed digest required")
    read, write = installer(source)
    raw = read(source / "nginx_error_window.py", 65_536)
    if digest(raw) != expected:
        raise ValueError("Reviewed helper digest differs")
    argv = ["timeout", "-k", "1s", "5s", "/usr/bin/python3", "-I", "-B", str(TARGET), domain]
    policy = json.loads(read(POLICY, 262_144))
    commands = policy.get("commands", {})
    if commands.get("LC_ALL=C " + shlex.join(argv)) != argv:
        raise ValueError("Installed policy lacks the exact helper command")
    if any(value == RAW_LOG for value in commands.values()):
        raise ValueError("Installed policy still admits the legacy raw log command")

    prior = json.loads(read(MARKER, 4096)) if os.path.lexists(MARKER) else {}
    recorded = {prior.get("helper_sha256"), prior.get("pending_helper_sha256")}
    if os.path.lexists(TARGET) and digest(read(TARGET, 65_536)) not in recorded:
        raise ValueError("Unrelated or drifted helper already exists")

    def record(row):
        payload = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        write(MARKER, payload, 0o600)

    record({"helper_sha256": prior.get("helper_sha256"), "pending_helper_sha256": expected})
    write(TARGET, raw, 0o755)
    record({"helper_sha256": expected})
    return {"installed": True, "helper_sha256": expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        result = install(Path(__file__).resolve().parent, args.site, args.expected_sha256)
    except (OSError, ValueError, TypeError, AttributeError):
        raise SystemExit("Nginx log helper install refused") from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
