#!/usr/bin/python3 -I
"""Install the exact managed Nginx helper package into the root-owned library."""

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

if sys.platform == "linux":
    import fcntl

LIBRARY = Path("/usr/local/lib/opsark-nginx-action")
POLICY_PATH = Path("/etc/opsark/nginx-action.json")
PRIVATE_ROOT = Path("/var/lib/opsark/nginx-action")
INTERPRETER = "/usr/bin/python3"
PACKAGE_MARKERS = ("deploy/__init__.py", "deploy/nginx/__init__.py", "deploy/readonly/__init__.py")
HELPERS = (
    "deploy/nginx/managed_action.py",
    "deploy/nginx/managed_context.py",
    "deploy/nginx/managed_role.py",
    "deploy/nginx/managed_runtime.py",
    "deploy/nginx/managed_startup.py",
    "deploy/nginx/managed_ssh_entry.py",
    "deploy/nginx/action_journal.py",
    "deploy/nginx/config_snapshot.py",
    "deploy/readonly/nginx_dependencies.py",
)
SSH_ENTRY = "deploy/nginx/managed_ssh_entry.py"
MAX_HELPER_BYTES = 524_288
MAX_POLICY_BYTES = 16_384
STATE_DIRECTORIES = ("actions", "backups", "plans", "startup")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def _trusted_directories(path: Path) -> None:
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Untrusted helper directory")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_trusted(path: Path, *, mode: int | None = None, maximum: int = MAX_HELPER_BYTES) -> bytes:
    _trusted_directories(path.parent)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_size > maximum
        or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
    ):
        raise ValueError("Untrusted helper file")
    expected = _identity(before)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        if _identity(os.fstat(handle.fileno())) != expected:
            raise ValueError("Helper changed")
        raw = handle.read(maximum + 1)
        if (
            len(raw) != before.st_size
            or _identity(os.fstat(handle.fileno())) != expected
            or _identity(path.lstat()) != expected
        ):
            raise ValueError("Helper changed")
    return raw


def package(source: Path) -> dict[str, bytes]:
    _trusted_directories(source)
    files = dict.fromkeys(PACKAGE_MARKERS, b"")
    for name in HELPERS:
        raw = _read_trusted(source / name)
        if not raw:
            raise ValueError("Missing helper source")
        compile(raw, name, "exec", dont_inherit=True)
        files[name] = raw
    return files


def _file_mode(name: str) -> int:
    return 0o755 if name == SSH_ENTRY else 0o644


def _verify(library: Path, files: dict[str, bytes]) -> None:
    _trusted_directories(library)
    expected = {library / name for name in files}
    directories = {library / "deploy", library / "deploy/nginx", library / "deploy/readonly"}
    for directory in directories | {library}:
        _trusted_directories(directory)
        for child in directory.iterdir():
            if child not in directories and child not in expected:
                raise ValueError("Unexpected installed helper entry")
    for name, raw in files.items():
        if _read_trusted(library / name, mode=_file_mode(name)) != raw:
            raise ValueError("Installed helper differs")


def _preflight_import(library: Path) -> None:
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from deploy.nginx import managed_action, managed_role, managed_ssh_entry; "
        "raise SystemExit(0 if managed_action.MAX_WIRE == 8192 "
        "and managed_role.ACCOUNT == 'opsark-nginx-action' "
        "and managed_ssh_entry.COMMAND == 'opsark-nginx-action-v1' else 1)"
    )
    subprocess.run(  # noqa: S603 -- fixed distro Python, audited library, fixed check.
        [INTERPRETER, "-I", "-B", "-c", code, str(library)],
        check=True,
        timeout=8,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=ENV,
    )


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_new(source: Path, destination: Path) -> None:
    # Linux renameat2 with AT_FDCWD and RENAME_NOREPLACE. Never publish a second hard link.
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise ValueError("Atomic no-replace installation is unavailable") from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        failure = ctypes.get_errno()
        raise OSError(failure, os.strerror(failure))


def install(source: Path, library: Path) -> dict[str, object]:
    files = package(source)
    _trusted_directories(library.parent)
    try:
        library.lstat()
    except FileNotFoundError:
        pass
    else:
        _verify(library, files)
        _preflight_import(library)
        return _receipt(files, installed=False)

    with TemporaryDirectory(prefix=".opsark-nginx-action-", dir=library.parent) as temp:
        staged = Path(temp) / "helpers"
        for name, raw in files.items():
            path = staged / name
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _file_mode(name))
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), _file_mode(name))
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        for directory in (
            staged / "deploy/nginx",
            staged / "deploy/readonly",
            staged / "deploy",
            staged,
        ):
            directory.chmod(0o755)  # noqa: S103 -- root-owned helpers and unprivileged SSH entry.
            _sync_directory(directory)
        _verify(staged, files)
        _preflight_import(staged)
        try:
            _rename_new(staged, library)
        except OSError as error:
            if error.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
            _verify(library, files)
            return _receipt(files, installed=False)
        _sync_directory(library.parent)
    _verify(library, files)
    return _receipt(files, installed=True)


def _receipt(files: dict[str, bytes], *, installed: bool) -> dict[str, object]:
    manifest = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    return {
        "schema_version": 1,
        "status": "installed" if installed else "already_installed",
        "file_count": len(manifest),
        "package_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
    }


def _directory(path: Path, mode: int, *, exact: bool = False) -> None:
    _trusted_directories(path.parent)
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    else:
        if exact:
            os.chown(path, 0, 0)
        path.chmod(mode)
        _sync_directory(path.parent)
    _trusted_directories(path)
    if exact and (path.lstat().st_gid != 0 or stat.S_IMODE(path.lstat().st_mode) != mode):
        raise ValueError("Unexpected state directory ownership or mode")


def _existing_policy(path: Path, approved: bytes) -> bool:
    try:
        current = _read_trusted(path, mode=0o600, maximum=MAX_POLICY_BYTES)
    except FileNotFoundError:
        return False
    if current != approved:
        raise ValueError("Existing policy differs from the approved policy")
    return True


def _check_policy(library: Path, approved: bytes) -> None:
    _trusted_directories(library)
    code = (
        "import sys; from datetime import UTC, datetime; sys.path.insert(0, sys.argv[1]); "
        "from deploy.nginx.managed_context import parse_policy; "
        "policy = parse_policy(sys.stdin.buffer.read(16385)); "
        "raise SystemExit(0 if datetime.now(UTC) < policy.expires_at else 1)"
    )
    subprocess.run(  # noqa: S603 -- verified installer package and fixed local parser.
        [INTERPRETER, "-I", "-B", "-c", code, str(library)],
        input=approved,
        check=True,
        timeout=8,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=ENV,
    )


def _publish_policy(path: Path, approved: bytes) -> None:
    with TemporaryDirectory(prefix=".opsark-nginx-policy-", dir=path.parent) as temp:
        staged = Path(temp) / "policy"
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(approved)
            handle.flush()
            os.fsync(handle.fileno())
        _rename_new(staged, path)
        _sync_directory(path.parent)


def initialize_state(library: Path, approved: bytes, policy_path: Path, root: Path) -> dict:
    _check_policy(library, approved)
    _directory(policy_path.parent, 0o755)
    _existing_policy(policy_path, approved)
    _directory(root.parent, 0o755)
    _directory(root, 0o700, exact=True)
    lock = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        existed = _existing_policy(policy_path, approved)
        for name in STATE_DIRECTORIES:
            _directory(root / name, 0o700, exact=True)
        if not existed:
            _publish_policy(policy_path, approved)
        if not _existing_policy(policy_path, approved):
            raise ValueError("Policy was not durably installed")
    finally:
        os.close(lock)
    return {
        "status": "already_initialized" if existed else "initialized",
        "policy_sha256": hashlib.sha256(approved).hexdigest(),
        "private_directory_count": len(STATE_DIRECTORIES),
    }


def _requested_policy(arguments: list[str]) -> bytes | None:
    if not arguments:
        return None
    if len(arguments) != 4 or arguments[0] != "--policy" or arguments[2] != "--policy-sha256":
        raise ValueError("Explicit policy path and digest required")
    path, expected = Path(arguments[1]), arguments[3]
    if (
        not path.is_absolute()
        or ".." in path.parts
        or re.fullmatch(r"[a-f0-9]{64}", expected) is None
    ):
        raise ValueError("Invalid policy source reference")
    raw = _read_trusted(path, mode=0o600, maximum=MAX_POLICY_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Policy differs from the approved digest")
    return raw


def main() -> int:
    try:
        if (
            sys.platform != "linux"
            or not sys.flags.isolated
            or not sys.dont_write_bytecode
            or sys.version_info < (3, 12)
            or os.geteuid() != 0
        ):
            raise ValueError("Installer requires isolated system Python and root")
        os.umask(0o077)
        source = Path(__file__).absolute()
        _read_trusted(source)
        approved = _requested_policy(sys.argv[1:])
        receipt = install(source.parents[2], LIBRARY)
        if approved is not None:
            receipt["registration"] = initialize_state(LIBRARY, approved, POLICY_PATH, PRIVATE_ROOT)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        print('{"schema_version":1,"status":"refused"}')
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
