#!/usr/bin/python3 -I
"""Install only the OpsArk dedicated forced-command account; never restart SSH."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
from pathlib import Path

ACCOUNT = "opsark-readonly"
HOME = Path("/var/lib/opsark-readonly")
POLICY = Path("/etc/opsark/readonly-policy.json")
MARKER = Path("/etc/opsark/readonly-installed.json")
LIBEXEC = Path("/usr/local/libexec")
SUDOERS = Path("/etc/sudoers.d/opsark-readonly")
READINESS_HELPER = "opsark-http-readiness"
MAX_READINESS_HELPER_BYTES = 65_536


def run(argv):
    return subprocess.run(  # noqa: S603 -- reviewed fixed administrative argv, never Shell text.
        argv,
        check=True,
        capture_output=True,
        timeout=10,
        env={  # noqa: S603
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "HOME": "/root",
        },
    )


def trusted(path, *, directory=False):
    metadata = path.lstat()
    valid_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not valid_type or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("Refusing untrusted deployment path: " + str(path))


def write_root(path, data, mode):
    if path.exists() or path.is_symlink():
        trusted(path)
    temporary = path.with_name("." + path.name + ".opsark-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def readiness_digest(path, marker):
    if not (path.exists() or path.is_symlink()):
        return None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_READINESS_HELPER_BYTES
        ):
            raise ValueError("Refusing an unrelated HTTP readiness helper")
        data = os.read(descriptor, MAX_READINESS_HELPER_BYTES + 1)
        if len(data) != metadata.st_size:
            raise ValueError("Refusing an unrelated HTTP readiness helper")
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(data).hexdigest()
    if digest not in (
        marker.get("readiness_helper_sha256"),
        marker.get("pending_readiness_helper_sha256"),
    ):
        raise ValueError("Refusing an unrelated HTTP readiness helper")
    return digest


def public_key(path):
    trusted(path)
    lines = path.read_text(encoding="ascii").splitlines()
    if len(lines) != 1:
        raise ValueError("Exactly one public key is required")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise ValueError("An independent Ed25519 public key is required")
    decoded = base64.b64decode(fields[1], validate=True)
    if len(decoded) != 51 or decoded[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        raise ValueError("Invalid Ed25519 public key payload")
    return " ".join(fields[:2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run the reviewed installer as administrator root")
    os.umask(0o077)
    source = Path(__file__).resolve().parent
    for directory in (Path("/etc"), Path("/var/lib"), Path("/usr/local"), Path("/etc/sudoers.d")):
        trusted(directory, directory=True)
    for filename in ("guard.py", "ssh_entry.py", "http_readiness.py"):
        trusted(source / filename)
    readiness_bytes = (source / "http_readiness.py").read_text(encoding="utf-8").encode("utf-8")
    if not 0 < len(readiness_bytes) <= MAX_READINESS_HELPER_BYTES:
        raise ValueError("The reviewed HTTP readiness helper size is invalid")
    readiness_sha = hashlib.sha256(readiness_bytes).hexdigest()
    trusted(args.policy)
    key = public_key(args.public_key)
    spec = importlib.util.spec_from_file_location("opsark_reviewed_guard", source / "guard.py")
    if spec is None or spec.loader is None:
        raise ValueError("Reviewed guard module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy_bytes = args.policy.read_bytes()
    commands = module.parse_policy(policy_bytes)
    for executable in ("useradd", "usermod", "visudo", "sudo", "timeout"):
        if shutil.which(executable, path="/usr/sbin:/usr/bin:/sbin:/bin") is None:
            raise ValueError("Required system tool missing: " + executable)
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        account = None
    own_install = False
    marker = {}
    if MARKER.exists():
        trusted(MARKER)
        marker = json.loads(MARKER.read_text(encoding="utf-8"))
        own_install = bool(
            account and marker.get("account") == ACCOUNT and marker.get("uid") == account.pw_uid
        )
    if account is not None and (
        not own_install or account.pw_dir != str(HOME) or account.pw_shell != "/bin/sh"
    ):
        raise ValueError("Refusing to adopt an existing unrelated account")
    if account is None and HOME.exists():
        raise ValueError("Refusing an existing unrelated home directory")
    for path in (POLICY, LIBEXEC / "opsark-readonly-guard", LIBEXEC / "opsark-ssh-entry", SUDOERS):
        if (path.exists() or path.is_symlink()) and not own_install:
            raise ValueError("Refusing to overwrite an existing unrelated deployment file")
    if LIBEXEC.exists() or LIBEXEC.is_symlink():
        trusted(LIBEXEC, directory=True)
    prior_readiness_sha = readiness_digest(
        LIBEXEC / READINESS_HELPER, marker if own_install else {}
    )
    if not POLICY.parent.exists():
        POLICY.parent.mkdir(mode=0o755)
        os.chmod(POLICY.parent, 0o755)  # noqa: S103 -- root-owned public traversal, policy is 0600.
        os.chown(POLICY.parent, 0, 0)
    trusted(POLICY.parent, directory=True)
    if account is None:
        run(
            [
                "/usr/sbin/useradd",
                "--no-create-home",
                "--user-group",
                "--home-dir",
                str(HOME),
                "--shell",
                "/bin/sh",
                ACCOUNT,
            ]
        )
        account = pwd.getpwnam(ACCOUNT)
    groups = set(os.getgrouplist(ACCOUNT, account.pw_gid))
    if groups != {account.pw_gid}:
        raise ValueError("Dedicated account must not have supplementary privileged groups")
    # Record ownership before subsequent writes so a reviewed interrupted install
    # can resume, while an unrelated account is never silently adopted.
    in_progress = {
        "schema_version": 1,
        "account": ACCOUNT,
        "uid": account.pw_uid,
        "installation_state": "in_progress",
        "readiness_helper_sha256": prior_readiness_sha,
        "pending_readiness_helper_sha256": readiness_sha,
    }
    write_root(MARKER, (json.dumps(in_progress) + "\n").encode(), 0o600)
    run(["/usr/sbin/usermod", "--lock", ACCOUNT])
    for directory, mode in (
        (POLICY.parent, 0o755),
        (LIBEXEC, 0o755),
        (HOME, 0o755),
        (HOME / ".ssh", 0o755),
    ):
        if directory.exists() or directory.is_symlink():
            trusted(directory, directory=True)
        else:
            directory.mkdir(mode=mode)
            os.chmod(directory, mode)
            os.chown(directory, 0, 0)
    os.chmod(HOME, 0o755)  # noqa: S103 -- root owns home; SSH user needs read/traversal only.
    os.chmod(HOME / ".ssh", 0o755)  # noqa: S103 -- public key only; user cannot change it.
    guard_bytes = (source / "guard.py").read_text(encoding="utf-8").encode("utf-8")
    entry_bytes = (source / "ssh_entry.py").read_text(encoding="utf-8").encode("utf-8")
    write_root(LIBEXEC / "opsark-readonly-guard", guard_bytes, 0o755)
    write_root(LIBEXEC / "opsark-ssh-entry", entry_bytes, 0o755)
    write_root(LIBEXEC / READINESS_HELPER, readiness_bytes, 0o755)
    write_root(POLICY, policy_bytes, 0o600)
    authorization = (
        'restrict,no-user-rc,command="/usr/local/libexec/opsark-ssh-entry" '
        + key
        + " opsark-dedicated-readonly\n"
    )
    write_root(HOME / ".ssh/authorized_keys", authorization.encode("ascii"), 0o644)
    sudoers = (
        "Defaults:opsark-readonly env_reset,!requiretty,"
        'secure_path="/usr/sbin:/usr/bin:/sbin:/bin"\n'
        "opsark-readonly ALL=(root) NOPASSWD: /usr/local/libexec/opsark-readonly-guard\n"
    )
    candidate = SUDOERS.with_name(".opsark-validate-" + str(os.getpid()))
    try:
        write_root(candidate, sudoers.encode("ascii"), 0o440)
        run(["/usr/sbin/visudo", "-cf", str(candidate)])
        write_root(SUDOERS, sudoers.encode("ascii"), 0o440)
    finally:
        if candidate.exists():
            candidate.unlink()
    record = {
        "schema_version": 1,
        "account": ACCOUNT,
        "uid": account.pw_uid,
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "readiness_helper_sha256": readiness_sha,
        "allowed_commands": len(commands),
        "installation_state": "complete",
    }
    write_root(MARKER, (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    print(
        json.dumps(
            {
                **record,
                "ssh_daemon_configuration_changed": False,
                "docker_group_membership": False,
                "journal_group_membership": False,
            }
        )
    )


if __name__ == "__main__":
    main()
