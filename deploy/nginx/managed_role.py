"""Stage a dedicated SSH public key and check the fixed local role policy."""

import base64
import ipaddress
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

_INSTALL_ROOT = Path("/usr/local/lib/opsark-nginx-action")
_ENTRY = _INSTALL_ROOT / "deploy/nginx/managed_role.py"
_REFUSED = "Nginx SSH role operation refused.\n"


def _local_administrator() -> bool:
    return sys.platform == "linux" and os.geteuid() == 0


if __name__ == "__main__":
    try:
        if (
            not _local_administrator()
            or Path(__file__) != _ENTRY
            or not sys.flags.isolated
            or not sys.dont_write_bytecode
        ):
            raise ValueError
        for directory in _ENTRY.parents:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError
        for path in (
            _ENTRY,
            _INSTALL_ROOT / "deploy/__init__.py",
            _ENTRY.with_name("__init__.py"),
            _ENTRY.with_name("config_snapshot.py"),
        ):
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or info.st_mode & 0o022
                or (path.name == "__init__.py" and info.st_size != 0)
            ):
                raise ValueError
        for directory in (_ENTRY.parent, _ENTRY.parent.parent):
            try:
                (directory / "__pycache__").lstat()
            except FileNotFoundError:
                continue
            raise ValueError
        sys.path.insert(0, str(_INSTALL_ROOT))
    except (OSError, ValueError):
        sys.stderr.write(_REFUSED)
        raise SystemExit(126) from None


from deploy.nginx import config_snapshot as snapshot  # noqa: E402 - verify installed source first.

ACCOUNT = "opsark-nginx-action"
SSHD_DROP_IN = "/etc/ssh/sshd_config.d/00-opsark-nginx-action.conf"
AUTHORIZED_KEYS = "/etc/ssh/opsark-nginx-action/authorized_keys"
SSH_ENTRY = "/usr/local/lib/opsark-nginx-action/deploy/nginx/managed_ssh_entry.py"
ROOT_ACTION = "/usr/local/lib/opsark-nginx-action/deploy/nginx/managed_action.py"
SUDOERS = "/etc/sudoers.d/opsark-nginx-action"
STAGED_KEY = Path("/var/lib/opsark/nginx-action/authorized_keys.staged")
_MAX_KEY = 512
_MAX_EFFECTIVE = 32_768
_CHECK_SECONDS = 5
_KEY = re.compile(rb"ssh-ed25519 ([A-Za-z0-9+/]{68})(?: [!-~][ -~]{0,127})?(?:\r?\n)?\Z")
_KEY_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
_REQUIRED = {
    b"acceptenv": b"OPSARK_UNUSED",
    b"allowagentforwarding": b"no",
    b"allowstreamlocalforwarding": b"no",
    b"allowtcpforwarding": b"no",
    b"authenticationmethods": b"publickey",
    b"authorizedkeyscommand": b"none",
    b"authorizedkeysfile": AUTHORIZED_KEYS.encode("ascii"),
    b"authorizedprincipalscommand": b"none",
    b"authorizedprincipalsfile": b"none",
    b"chrootdirectory": b"none",
    b"disableforwarding": b"yes",
    b"exposeauthinfo": b"no",
    b"forcecommand": SSH_ENTRY.encode("ascii"),
    b"gssapiauthentication": b"no",
    b"hostbasedauthentication": b"no",
    b"kbdinteractiveauthentication": b"no",
    b"maxsessions": b"1",
    b"passwordauthentication": b"no",
    b"permitemptypasswords": b"no",
    b"permitlisten": b"none",
    b"permitopen": b"none",
    b"permittty": b"no",
    b"permittunnel": b"no",
    b"permituserenvironment": b"no",
    b"permituserrc": b"no",
    b"pubkeyacceptedalgorithms": b"ssh-ed25519",
    b"pubkeyauthentication": b"yes",
    b"strictmodes": b"yes",
    b"trustedusercakeys": b"none",
    b"usedns": b"no",
    b"usepam": b"yes",
    b"x11forwarding": b"no",
}


class RoleRefused(ValueError):
    """Role input did not establish the supported local scope."""


def _render_key(raw: bytes) -> bytes:
    match = _KEY.fullmatch(raw) if type(raw) is bytes and len(raw) <= _MAX_KEY else None
    if match is None:
        raise RoleRefused("Expected one dedicated Ed25519 public key")
    encoded = match[1]
    decoded = base64.b64decode(encoded, validate=True)
    if (
        len(decoded) != len(_KEY_PREFIX) + 32
        or not decoded.startswith(_KEY_PREFIX)
        or decoded[len(_KEY_PREFIX) :] == b"\0" * 32
    ):
        raise RoleRefused("Expected one dedicated Ed25519 public key")
    return f'restrict,command="{SSH_ENTRY}" ssh-ed25519 '.encode("ascii") + encoded + b"\n"


def authorization_from_file(path: Path) -> bytes:
    """Return one authorized_keys line to the trusted local installer in memory."""
    if not _local_administrator() or not isinstance(path, Path):
        raise RoleRefused("Administrator public key input unavailable")
    try:
        with snapshot._directory(path.parent, snapshot.DEFAULT_POLICY) as parent:
            raw, _identity = snapshot._read(parent, path.name, _MAX_KEY, snapshot.DEFAULT_POLICY)
        return _render_key(raw)
    except (OSError, ValueError):
        raise RoleRefused("Administrator public key input unavailable") from None


def preflight_argv(peer: str, local: str, port: int) -> tuple[str, ...]:
    """Build the fixed extended test command for one real listener and peer."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise RoleRefused("Unsupported SSH connection sample")
    if any(type(value) is not str or not value or "%" in value for value in (peer, local)):
        raise RoleRefused("Unsupported SSH connection sample")
    try:
        address = str(ipaddress.ip_address(peer))
        listener = str(ipaddress.ip_address(local))
    except ValueError:
        raise RoleRefused("Unsupported SSH connection sample") from None
    sample = f"user={ACCOUNT},host={address},addr={address},laddr={listener},lport={port}"
    return "/usr/sbin/sshd", "-T", "-C", sample


def verify_effective(raw: bytes) -> dict[str, int | str | bool]:
    """Validate the closed relevant fields without returning config or credentials."""
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= _MAX_EFFECTIVE
        or not raw.isascii()
        or any(value < 32 and value not in (9, 10, 13) for value in raw)
        or b"\x7f" in raw
    ):
        raise RoleRefused("Effective SSH role policy could not be verified")
    seen = set()
    for line in raw.splitlines():
        name, separator, value = line.partition(b" ")
        if not separator or re.fullmatch(rb"[a-z][a-z0-9]*", name) is None:
            raise RoleRefused("Effective SSH role policy could not be verified")
        if name == b"setenv" or (name == b"rdomain" and value != b"none"):
            raise RoleRefused("Effective SSH role policy could not be verified")
        if name in _REQUIRED:
            if name in seen or value != _REQUIRED[name]:
                raise RoleRefused("Effective SSH role policy could not be verified")
            seen.add(name)
    if seen != _REQUIRED.keys():
        raise RoleRefused("Effective SSH role policy could not be verified")
    return {
        "schema_version": 1,
        "role": ACCOUNT,
        "effective_policy_verified": True,
        "authentication_verified": False,
    }


def _stage_key(public_key: Path) -> None:
    data = authorization_from_file(public_key)
    with snapshot._directory(STAGED_KEY.parent, snapshot.DEFAULT_POLICY, private=True) as directory:
        pending = ".pending-key-" + secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(pending, flags, 0o600, dir_fd=directory)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(descriptor)
            os.link(
                pending,
                STAGED_KEY.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        finally:
            os.unlink(pending, dir_fd=directory)
        os.fsync(directory)


def _read_effective(peer: str, local: str, port: int) -> bytes:
    deadline = time.monotonic() + _CHECK_SECONDS
    with subprocess.Popen(  # noqa: S603 - only the fixed sshd extended test argv.
        preflight_argv(peer, local, port),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    ) as check:
        try:
            if check.stdout is None:
                raise RoleRefused("Effective SSH role policy could not be verified")
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(check.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise RoleRefused("Effective SSH role policy could not be verified")
                    block = os.read(
                        check.stdout.fileno(), min(8192, _MAX_EFFECTIVE + 1 - len(output))
                    )
                    if not block:
                        break
                    output.extend(block)
                    if len(output) > _MAX_EFFECTIVE:
                        raise RoleRefused("Effective SSH role policy could not be verified")
            if check.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                raise RoleRefused("Effective SSH role policy could not be verified")
            return bytes(output)
        finally:
            if check.poll() is None:
                with suppress(ProcessLookupError):
                    check.kill()


def _fields(args: list[str], expected: set[str]) -> dict[str, str]:
    if len(args) != 2 * len(expected):
        raise RoleRefused("Invalid SSH role command arguments")
    arguments = iter(args)
    fields = dict(zip(arguments, arguments, strict=True))
    if fields.keys() != expected:
        raise RoleRefused("Invalid SSH role command arguments")
    return fields


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if not _local_administrator() or not args:
            raise RoleRefused("Administrator SSH role command unavailable")
        if args[0] == "stage-key":
            fields = _fields(args[1:], {"--public-key"})
            _stage_key(Path(fields["--public-key"]))
        elif args[0] == "check-effective":
            fields = _fields(args[1:], {"--peer", "--local", "--port"})
            port = fields["--port"]
            if re.fullmatch(r"[1-9][0-9]{0,4}", port) is None:
                raise RoleRefused("Unsupported SSH connection sample")
            proof = verify_effective(
                _read_effective(fields["--peer"], fields["--local"], int(port))
            )
            sys.stdout.write(json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n")
        else:
            raise RoleRefused("Invalid SSH role command arguments")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.stderr.write(_REFUSED)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
