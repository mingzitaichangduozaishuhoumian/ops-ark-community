#!/usr/bin/env python3
"""Capture and prepare one Nginx disk configuration file on a trusted Linux host."""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

MAX_CONFIG_BYTES = 262_144
MAX_MANIFEST_BYTES = 4096
_CONFIG = "nginx.conf"
_CANDIDATE = "candidate.conf"
_MANIFEST = "manifest.json"
_APPROVAL = "approval.json"
_PENDING_MANIFEST = ".manifest.pending"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLAN_LIFETIME = timedelta(minutes=10)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.conf\Z")
_MACHINE_ID = re.compile(rb"[0-9a-f]{32}\n?\Z")
_SOURCE_FIELDS = ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid")
_FIXTURE = re.compile(
    rb"\s*server\s*\{\s*listen\s+127\.0\.0\.1:18087\s*;\s*"
    rb"server_name\s+target\.opsark\.invalid\s*;\s*location\s+=\s+/healthz\s*\{\s*"
    rb"default_type\s+text/plain\s*;\s*return\s+200\s+\"opsark-candidate\"\s*;?\s*\}\s*\}\s*\Z"
)
_DOCKER_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
_VALIDATION_LABEL = "io.opsark.nginx-validation"
_VALIDATOR = r"""
import os
import subprocess
import sys
from pathlib import Path

os.umask(0o077)
root = Path('/run/opsark-nginx-check')
try:
    data = sys.stdin.buffer.read(262145)
    if not 0 < len(data) <= 262144:
        raise ValueError
    (root / 'candidate.conf').write_bytes(data)
    wrapper = root / 'fixture.conf'
    wrapper.write_text('''pid /run/opsark-nginx-check/nginx.pid;
error_log stderr crit;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path /run/opsark-nginx-check/body;
    proxy_temp_path /run/opsark-nginx-check/proxy;
    fastcgi_temp_path /run/opsark-nginx-check/fastcgi;
    uwsgi_temp_path /run/opsark-nginx-check/uwsgi;
    scgi_temp_path /run/opsark-nginx-check/scgi;
    include /run/opsark-nginx-check/candidate.conf;
}
''', encoding='ascii')
    checked = subprocess.run(
        ['/usr/sbin/nginx', '-t', '-q', '-e', 'stderr', '-p', str(root), '-c', str(wrapper)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/bin','LC_ALL':'C'}, timeout=5, check=False,
    )
except (OSError, ValueError, subprocess.SubprocessError):
    sys.exit(11)
sys.exit(0 if checked.returncode == 0 else 10)
"""


class SnapshotError(ValueError):
    """A snapshot operation could not establish the required safety checks."""


@dataclass(frozen=True)
class SnapshotPolicy:
    anchor: Path
    config_directory: Path
    machine_id: Path
    owner_uid: int


DEFAULT_POLICY = SnapshotPolicy(Path("/"), Path("/etc/nginx/conf.d"), Path("/etc/machine-id"), 0)


def _check_runtime(policy: SnapshotPolicy) -> None:
    if sys.platform != "linux" or os.geteuid() != policy.owner_uid:
        raise SnapshotError("Snapshot operations require the trusted Linux administrator")


def _validate_name(name: str) -> None:
    if not _NAME.fullmatch(name) or ".." in name:
        raise SnapshotError("Unapproved Nginx configuration file")


def _absolute(path: Path) -> None:
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts:
        raise SnapshotError("Snapshot paths must be canonical absolute paths")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise SnapshotError("Duplicate manifest field")
        value[name] = item
    return value


def _check_dir(fd: int, policy: SnapshotPolicy, *, private: bool = False) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != policy.owner_uid
        or info.st_mode & (0o077 if private else 0o022)
    ):
        raise SnapshotError("An owned, trusted directory is required")


@contextmanager
def _directory(path: Path, policy: SnapshotPolicy, *, private: bool = False):
    _absolute(path)
    _absolute(policy.anchor)
    if not path.is_relative_to(policy.anchor):
        raise SnapshotError("Directory is outside the trusted root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(policy.anchor, flags)
    try:
        _check_dir(fd, policy)
        for part in path.relative_to(policy.anchor).parts:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            _check_dir(fd, policy)
        if private:
            _check_dir(fd, policy, private=True)
        yield fd
    finally:
        os.close(fd)


def _signature(info: os.stat_result) -> dict[str, int]:
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


def _read(
    parent: int, name: str, limit: int, policy: SnapshotPolicy, *, private: bool = False
) -> tuple[bytes, dict[str, int]]:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != policy.owner_uid
            or before.st_mode & (0o7077 if private else 0o7022)
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise SnapshotError("An owned, ordinary, bounded file is required")
        data = handle.read(limit + 1)
        identity = _signature(before)
        after = os.fstat(handle.fileno())
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            len(data) != before.st_size
            or not stat.S_ISREG(current.st_mode)
            or after.st_nlink != 1
            or current.st_nlink != 1
            or _signature(after) != identity
            or _signature(current) != identity
        ):
            raise SnapshotError("File changed while reading")
    return data, identity


def _machine(policy: SnapshotPolicy) -> str:
    with _directory(policy.machine_id.parent, policy) as directory:
        data, _identity = _read(directory, policy.machine_id.name, 33, policy)
    if not _MACHINE_ID.fullmatch(data) or data.strip() == b"0" * 32:
        raise SnapshotError("Trusted machine identity is unavailable")
    return _sha(data.strip())


def _write(parent: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _proof(integrity: str, disk: str, sha256: str | None = None) -> dict[str, str | int]:
    result: dict[str, str | int] = {
        "schema_version": 1,
        "backup_integrity": integrity,
        "disk_status": disk,
        "rollback_status": "not_rehearsed",
    }
    if sha256 is not None:
        result["sha256"] = sha256
    return result


def _snapshot_path(path: Path, policy: SnapshotPolicy) -> None:
    _absolute(path)
    if path == policy.anchor or path.is_relative_to(policy.config_directory.parent):
        raise SnapshotError("Snapshot must be in a separate private directory")


def _publish(
    output: Path,
    member: str | None,
    data: bytes | None,
    manifest: dict,
    recheck: Callable[[], None],
    policy: SnapshotPolicy,
    *,
    manifest_name: str = _MANIFEST,
) -> None:
    raw = _json(manifest) + b"\n"
    if len(raw) > MAX_MANIFEST_BYTES:
        raise SnapshotError("Manifest exceeds its size limit")
    if (member is None) != (data is None):
        raise SnapshotError("Bundle content is incomplete")
    with _directory(output.parent, policy) as parent:
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        fd = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(output.name, flags, dir_fd=parent)
            _check_dir(fd, policy, private=True)
            os.fchmod(fd, 0o700)
            if member is not None and data is not None:
                _write(fd, member, data)
            _write(fd, _PENDING_MANIFEST, raw)
            os.fsync(fd)
            recheck()
            os.rename(_PENDING_MANIFEST, manifest_name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            os.fsync(parent)
        except BaseException:
            if fd is not None:
                for name in (manifest_name, _PENDING_MANIFEST, member):
                    if name is not None:
                        with suppress(FileNotFoundError):
                            os.unlink(name, dir_fd=fd)
            with suppress(OSError):
                os.rmdir(output.name, dir_fd=parent)
            raise
        finally:
            if fd is not None:
                os.close(fd)


def capture(
    source: Path, expected_sha256: str, output: Path, *, policy: SnapshotPolicy = DEFAULT_POLICY
) -> dict[str, str | int]:
    """Copy an administrator-reviewed regular file and publish its private manifest last."""
    _check_runtime(policy)
    _absolute(source)
    _snapshot_path(output, policy)
    _validate_name(source.name)
    if source.parent != policy.config_directory or not _digest(expected_sha256):
        raise SnapshotError("Unapproved Nginx configuration file or digest")
    try:
        with _directory(source.parent, policy) as directory:
            data, identity = _read(directory, source.name, MAX_CONFIG_BYTES, policy)
        actual = _sha(data)
        if not hmac.compare_digest(actual, expected_sha256):
            raise SnapshotError("Configuration digest differs from the reviewed digest")
        manifest = {
            "schema_version": 1,
            "source_name": source.name,
            "source_identity": identity,
            "machine_sha256": _machine(policy),
            "content_sha256": actual,
        }
        manifest["manifest_sha256"] = _sha(_json(manifest))

        def recheck() -> None:
            if not _live_matches(data, manifest, policy):
                raise SnapshotError("Configuration changed before snapshot publication")

        _publish(output, _CONFIG, data, manifest, recheck, policy)
    except OSError as error:
        raise SnapshotError("Configuration snapshot could not be saved") from error
    return _proof("intact", "unchanged", actual)


def _members(parent: int, expected: set[str]) -> None:
    names = set()
    with os.scandir(parent) as entries:
        for entry in entries:
            if entry.name not in expected:
                raise SnapshotError("Unexpected snapshot member")
            names.add(entry.name)
    if names != expected:
        raise SnapshotError("Snapshot is incomplete")


def _read_bundle(path: Path, member: str, policy: SnapshotPolicy) -> tuple[bytes, bytes]:
    _snapshot_path(path, policy)
    expected_members = {member, _MANIFEST}
    with _directory(path, policy, private=True) as directory:
        _members(directory, expected_members)
        raw, manifest_identity = _read(
            directory, _MANIFEST, MAX_MANIFEST_BYTES, policy, private=True
        )
        data, identity = _read(directory, member, MAX_CONFIG_BYTES, policy, private=True)
        for name, expected in ((_MANIFEST, manifest_identity), (member, identity)):
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or _signature(current) != expected
            ):
                raise SnapshotError("Bundle changed while inspecting")
        _members(directory, expected_members)
    return raw, data


def _trusted_identity(identity: object, policy: SnapshotPolicy) -> bool:
    return (
        isinstance(identity, dict)
        and set(identity) == set(_SOURCE_FIELDS)
        and all(type(number) is int for number in identity.values())
        and identity["uid"] == policy.owner_uid
        and 0 < identity["size"] <= MAX_CONFIG_BYTES
        and 0 <= identity["mode"] <= 0o777
        and not identity["mode"] & 0o022
    )


def _load_manifest(data: bytes, policy: SnapshotPolicy) -> dict:
    manifest = json.loads(data, object_pairs_hook=_unique)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "source_name",
        "source_identity",
        "machine_sha256",
        "content_sha256",
        "manifest_sha256",
    }:
        raise SnapshotError("Invalid snapshot manifest")
    declared = manifest.pop("manifest_sha256")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or not _digest(manifest["machine_sha256"])
        or not _digest(manifest["content_sha256"])
        or not _digest(declared)
        or not hmac.compare_digest(declared, _sha(_json(manifest)))
        or not isinstance(manifest["source_name"], str)
        or not _trusted_identity(manifest["source_identity"], policy)
    ):
        raise SnapshotError("Invalid snapshot manifest")
    _validate_name(manifest["source_name"])
    return manifest


def _backup(snapshot: Path, policy: SnapshotPolicy) -> tuple[bytes, dict, str]:
    raw, data = _read_bundle(snapshot, _CONFIG, policy)
    manifest = _load_manifest(raw, policy)
    if _sha(data) != manifest["content_sha256"] or len(data) != manifest["source_identity"]["size"]:
        raise SnapshotError("Snapshot contents do not match the manifest")
    return data, manifest, _sha(raw)


def _live_matches(data: bytes, manifest: dict, policy: SnapshotPolicy) -> bool:
    if not hmac.compare_digest(_machine(policy), manifest["machine_sha256"]):
        raise SnapshotError("Snapshot belongs to a different machine")
    with _directory(policy.config_directory, policy) as directory:
        current, identity = _read(directory, manifest["source_name"], MAX_CONFIG_BYTES, policy)
    return current == data and identity == manifest["source_identity"]


def inspect(snapshot: Path, *, policy: SnapshotPolicy = DEFAULT_POLICY) -> dict[str, str | int]:
    """Check private backup integrity and compare it with the current disk file."""
    _check_runtime(policy)
    try:
        data, manifest, _digest = _backup(snapshot, policy)
    except (OSError, ValueError, RecursionError):
        return _proof("tampered", "unavailable")
    sha256 = manifest["content_sha256"]
    try:
        unchanged = _live_matches(data, manifest, policy)
    except (OSError, SnapshotError):
        return _proof("intact", "unavailable", sha256)
    return _proof("intact", "unchanged" if unchanged else "drift", sha256)


def _clock(now: datetime | None) -> datetime:
    current = datetime.now(UTC) if now is None else now
    if not isinstance(current, datetime) or current.utcoffset() is None:
        raise SnapshotError("Plan time requires a timezone")
    return current.astimezone(UTC)


def _plan_proof(status: str, manifest: dict | None = None) -> dict[str, str | int]:
    result: dict[str, str | int] = {
        "schema_version": 1,
        "plan_status": status,
        "syntax_status": "not_checked",
        "approval_status": "not_approved",
    }
    if manifest is not None:
        for field in ("plan_id", "candidate_sha256", "expires_at"):
            result[field] = manifest[field]
        if "context_sha256" in manifest:
            result["context_sha256"] = manifest["context_sha256"]
    return result


def _candidate(path: Path, policy: SnapshotPolicy) -> tuple[bytes, dict[str, int]]:
    with _directory(path.parent, policy) as directory:
        return _read(directory, path.name, MAX_CONFIG_BYTES, policy, private=True)


def _context_digest(reader: Callable[[], str] | None) -> str | None:
    if reader is None:
        return None
    digest = reader()
    if not _digest(digest):
        raise SnapshotError("Invalid Nginx dependency context digest")
    return digest


def _context_matches(manifest: dict, reader: Callable[[], str] | None) -> bool:
    expected = manifest.get("context_sha256")
    if (expected is None) != (reader is None):
        raise SnapshotError("The Nginx dependency context does not match the plan scope")
    if expected is None:
        return True
    current = _context_digest(reader)
    return current is not None and hmac.compare_digest(expected, current)


def prepare(
    snapshot: Path,
    candidate: Path,
    expected_sha256: str,
    output: Path,
    *,
    policy: SnapshotPolicy = DEFAULT_POLICY,
    now: datetime | None = None,
    context_reader: Callable[[], str] | None = None,
) -> dict[str, str | int]:
    """Prepare a local unapproved plan after matching a verified backup to current disk."""
    _check_runtime(policy)
    for path in (snapshot, candidate, output):
        _snapshot_path(path, policy)
    if (
        snapshot.is_relative_to(output)
        or output.is_relative_to(snapshot)
        or candidate.is_relative_to(snapshot)
        or candidate.is_relative_to(output)
        or not _digest(expected_sha256)
    ):
        raise SnapshotError("Plan inputs and output must be distinct and reviewed")
    started = _clock(now)
    try:
        expires = started + _PLAN_LIFETIME
        context_sha256 = _context_digest(context_reader)
        original, backup, backup_sha256 = _backup(snapshot, policy)
        if not _live_matches(original, backup, policy):
            raise SnapshotError("Configuration differs from the verified backup")
        data, identity = _candidate(candidate, policy)
        candidate_sha256 = _sha(data)
        if data == original or not hmac.compare_digest(candidate_sha256, expected_sha256):
            raise SnapshotError("Candidate is unchanged or its digest differs")
        manifest = {
            "schema_version": 1,
            "plan_id": secrets.token_hex(16),
            "created_at": started.isoformat(),
            "expires_at": expires.isoformat(),
            "backup_path": str(snapshot),
            "backup_manifest_sha256": backup_sha256,
            "source_name": backup["source_name"],
            "source_identity": backup["source_identity"],
            "machine_sha256": backup["machine_sha256"],
            "source_sha256": backup["content_sha256"],
            "candidate_sha256": candidate_sha256,
            "candidate_size": len(data),
        }
        if context_sha256 is not None:
            manifest["context_sha256"] = context_sha256
        manifest["manifest_sha256"] = _sha(_json(manifest))

        def recheck() -> None:
            if (
                _backup(snapshot, policy) != (original, backup, backup_sha256)
                or not _live_matches(original, backup, policy)
                or _candidate(candidate, policy) != (data, identity)
                or _context_digest(context_reader) != context_sha256
                or not started <= _clock(now) < expires
            ):
                raise SnapshotError("A plan input changed before publication")

        _publish(output, _CANDIDATE, data, manifest, recheck, policy)
    except SnapshotError:
        raise
    except (OSError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise SnapshotError("Nginx change preparation could not be verified") from error
    return _plan_proof("ready", manifest)


def _plan(plan: Path, policy: SnapshotPolicy) -> tuple[dict, datetime, datetime, bytes]:
    raw, data = _read_bundle(plan, _CANDIDATE, policy)
    manifest = json.loads(raw, object_pairs_hook=_unique)
    fields = {
        "schema_version",
        "plan_id",
        "created_at",
        "expires_at",
        "backup_path",
        "backup_manifest_sha256",
        "source_name",
        "source_identity",
        "machine_sha256",
        "source_sha256",
        "candidate_sha256",
        "candidate_size",
        "manifest_sha256",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) not in (fields, fields | {"context_sha256"})
        or ("context_sha256" in manifest and not _digest(manifest["context_sha256"]))
        or raw != _json(manifest) + b"\n"
    ):
        raise SnapshotError("Invalid canonical plan manifest")
    declared = manifest.pop("manifest_sha256")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or not isinstance(manifest["plan_id"], str)
        or not _PLAN_ID.fullmatch(manifest["plan_id"])
        or not all(
            _digest(manifest[field])
            for field in (
                "backup_manifest_sha256",
                "machine_sha256",
                "source_sha256",
                "candidate_sha256",
            )
        )
        or not _digest(declared)
        or not hmac.compare_digest(declared, _sha(_json(manifest)))
        or not isinstance(manifest["source_name"], str)
        or not _trusted_identity(manifest["source_identity"], policy)
        or not isinstance(manifest["backup_path"], str)
        or type(manifest["candidate_size"]) is not int
        or manifest["candidate_size"] != len(data)
        or manifest["candidate_sha256"] != _sha(data)
        or manifest["source_sha256"] == manifest["candidate_sha256"]
    ):
        raise SnapshotError("Invalid Nginx preparation proof")
    _validate_name(manifest["source_name"])
    backup_path = Path(manifest["backup_path"])
    _snapshot_path(backup_path, policy)
    if backup_path.is_relative_to(plan) or plan.is_relative_to(backup_path):
        raise SnapshotError("Invalid plan backup reference")
    started = _clock(datetime.fromisoformat(manifest["created_at"]))
    expires = _clock(datetime.fromisoformat(manifest["expires_at"]))
    if (
        started.isoformat() != manifest["created_at"]
        or expires.isoformat() != manifest["expires_at"]
        or expires - started != _PLAN_LIFETIME
    ):
        raise SnapshotError("Invalid plan expiry")
    return manifest, started, expires, data


def _plan_state(
    plan: Path,
    policy: SnapshotPolicy,
    current: datetime,
    *,
    context_reader: Callable[[], str] | None = None,
) -> tuple[str, dict | None, bytes | None]:
    try:
        manifest, started, expires, data = _plan(plan, policy)
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        return "tampered", None, None
    if current >= expires:
        return "expired", manifest, None
    if current < started:
        return "unavailable", manifest, None
    try:
        original, backup, backup_sha256 = _backup(Path(manifest["backup_path"]), policy)
        if (
            backup_sha256 != manifest["backup_manifest_sha256"]
            or any(
                backup[field] != manifest[field]
                for field in ("source_name", "source_identity", "machine_sha256")
            )
            or backup["content_sha256"] != manifest["source_sha256"]
        ):
            raise SnapshotError("The referenced backup differs from the plan")
        unchanged = _live_matches(original, backup, policy) and _context_matches(
            manifest, context_reader
        )
    except (OSError, TypeError, ValueError, RecursionError):
        return "unavailable", manifest, None
    return ("ready", manifest, data) if unchanged else ("drift", manifest, None)


def inspect_plan(
    plan: Path,
    *,
    policy: SnapshotPolicy = DEFAULT_POLICY,
    now: datetime | None = None,
    context_reader: Callable[[], str] | None = None,
) -> dict[str, str | int]:
    """Inspect an independent unapproved plan and compare its expected live state."""
    _check_runtime(policy)
    status, manifest, _data = _plan_state(plan, policy, _clock(now), context_reader=context_reader)
    return _plan_proof(status, manifest)


def _docker(base: list[str], args: list[str], *, timeout: int = 4, data: bytes | None = None):
    return subprocess.run(  # noqa: S603 -- fixed argv and verified local image/container IDs.
        [*base, *args],
        stdin=subprocess.DEVNULL if data is None else None,
        input=data,
        stdout=subprocess.DEVNULL if data is not None else subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        env=_DOCKER_ENV,
        check=False,
    )


def _owned_container(base: list[str], name: str, token: str, expected: str | None) -> str | None:
    form = '{{.Id}}\n{{index .Config.Labels "' + _VALIDATION_LABEL + '"}}'
    inspected = _docker(base, ["container", "inspect", "--format", form, name])
    if inspected.returncode != 0 or len(inspected.stdout) > 128:
        return None
    values = inspected.stdout.decode("ascii").splitlines()
    if (
        len(values) != 2
        or not _SHA256.fullmatch(values[0])
        or values[1] != token
        or (expected is not None and values[0] != expected)
    ):
        return None
    return values[0]


def _docker_syntax(
    data: bytes,
    image: str,
    *,
    validator: str = _VALIDATOR,
    extra_tmpfs: tuple[str, ...] = (),
    tls_directory: Path | None = None,
) -> str:
    tls_mount = ()
    if tls_directory is not None:
        _absolute(tls_directory)
        if tls_directory.name != "tls" or not re.fullmatch(
            r"(?:/[a-zA-Z0-9_.-]+)+", str(tls_directory)
        ):
            raise SnapshotError("Invalid fixture TLS mount")
        # The context caller verifies the seal before launch and again afterward.
        # This fixed mount is independent of the static runtime tmpfs.
        tls_mount = (
            "--mount",
            f"type=bind,src={tls_directory},dst=/fixture-tls,readonly,bind-propagation=rprivate",
        )
    # The host temp directory is an empty Docker client config, never a candidate mount.
    with TemporaryDirectory(prefix="opsark-nginx-docker-", dir="/tmp") as config:
        base = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", config]
        image_probe = _docker(
            base,
            ["image", "inspect", "--format", '{{.Id}}\n{{json (index .Config "Volumes")}}', image],
        )
        if image_probe.returncode != 0 or len(image_probe.stdout) > 128:
            return "unavailable"
        parts = image_probe.stdout.decode("ascii").splitlines()
        # Refuse image-defined volumes, which Docker would mount even without --volume.
        if len(parts) != 2 or parts[0] != image or parts[1] not in {"null", "{}"}:
            return "unavailable"
        token = secrets.token_hex(16)
        name = "opsark-nginx-validation-" + token
        created_id = None
        try:
            created = _docker(
                base,
                [
                    "create",
                    "--pull",
                    "never",
                    "--name",
                    name,
                    "--label",
                    f"{_VALIDATION_LABEL}={token}",
                    "--interactive",
                    "--network",
                    "none",
                    "--ipc",
                    "none",
                    "--read-only",
                    "--user",
                    "65534:65534",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--no-healthcheck",
                    "--log-driver",
                    "none",
                    "--pids-limit",
                    "16",
                    "--memory",
                    "64m",
                    "--memory-swap",
                    "64m",
                    "--cpus",
                    "0.25",
                    "--ulimit",
                    "nofile=64:64",
                    "--workdir",
                    "/",
                    "--tmpfs",
                    "/run/opsark-nginx-check:rw,nosuid,nodev,noexec,mode=0700,uid=65534,gid=65534,size=2m",
                    *(arg for spec in extra_tmpfs for arg in ("--tmpfs", spec)),
                    *tls_mount,
                    "--entrypoint",
                    "/usr/bin/python3",
                    image,
                    "-I",
                    "-B",
                    "-c",
                    validator,
                ],
                timeout=6,
            )
            if created.returncode != 0 or len(created.stdout) > 65:
                return "unavailable"
            value = created.stdout.decode("ascii").strip()
            if not _SHA256.fullmatch(value):
                return "unavailable"
            created_id = value
            if _owned_container(base, name, token, created_id) is None:
                return "unavailable"
            checked = _docker(
                base, ["start", "--attach", "--interactive", created_id], timeout=12, data=data
            )
            result = {0: "passed", 10: "failed"}.get(checked.returncode, "unavailable")
        finally:
            owned = _owned_container(base, name, token, created_id)
            if owned is not None:
                removed = _docker(base, ["rm", "--force", owned])
                if removed.returncode != 0:
                    raise SnapshotError("The isolated validator could not be cleaned up")
            elif created_id is not None:
                raise SnapshotError("The isolated validator identity could not be confirmed")
        return result


def _fixture_syntax(data: bytes, image: str) -> str:
    if len(data) > 1024 or not _FIXTURE.fullmatch(data):
        return "unsupported"
    try:
        return _docker_syntax(data, image)
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"


def _pinned_image(image: str) -> None:
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        raise SnapshotError("Validation needs a pinned local image ID")


def _read_clock(now: datetime | Callable[[], datetime] | None) -> datetime:
    return _clock(now if now is None or isinstance(now, datetime) else now())


def validate_plan(
    plan: Path,
    image: str,
    *,
    policy: SnapshotPolicy = DEFAULT_POLICY,
    now: datetime | Callable[[], datetime] | None = None,
    context_reader: Callable[[], str] | None = None,
    syntax_check: Callable[[bytes, str], str] | None = None,
) -> dict[str, str | int]:
    """Check a supported fixture plan in an isolated non-root local Docker validator."""
    _check_runtime(policy)
    _pinned_image(image)
    _require_syntax_scope(context_reader, syntax_check)
    status, manifest, data = _plan_state(
        plan, policy, _read_clock(now), context_reader=context_reader
    )
    result = _plan_proof(status, manifest)
    if status != "ready" or data is None:
        return result
    syntax_status = (_fixture_syntax if syntax_check is None else syntax_check)(data, image)
    if syntax_status == "unsupported":
        result["syntax_status"] = syntax_status
        return result
    status, after, _data = _plan_state(
        plan, policy, _read_clock(now), context_reader=context_reader
    )
    if after is not None and after != manifest:
        return _plan_proof("tampered")
    result = _plan_proof(status, after)
    if status == "ready" and syntax_status in {"passed", "failed", "unavailable"}:
        result["syntax_status"] = syntax_status
    return result


def _require_syntax_scope(
    context_reader: Callable[[], str] | None, syntax_check: Callable[[bytes, str], str] | None
) -> None:
    if (context_reader is None) != (syntax_check is None) or (
        syntax_check is not None and not callable(syntax_check)
    ):
        raise SnapshotError(
            "Context validation requires a dependency reader and isolated validator"
        )


def _approval_proof(status: str, receipt: dict | None = None) -> dict[str, str | int]:
    result: dict[str, str | int] = {
        "schema_version": 1,
        "approval_status": status,
        "syntax_status": "passed" if receipt is not None else "not_checked",
    }
    if receipt is not None:
        for field in ("approval_id", "plan_id", "candidate_sha256", "image_sha256", "expires_at"):
            result[field] = receipt[field]
        if "context_sha256" in receipt:
            result["context_sha256"] = receipt["context_sha256"]
    return result


def _sealed_manifest_sha256(manifest: dict) -> str:
    # _plan() accepts only the canonical on-disk document including the final newline.
    return _sha(_json({**manifest, "manifest_sha256": _sha(_json(manifest))}) + b"\n")


def _plan_reference(plan: Path, approval: Path, policy: SnapshotPolicy) -> None:
    _snapshot_path(plan, policy)
    _snapshot_path(approval, policy)
    if plan.is_relative_to(approval) or approval.is_relative_to(plan):
        raise SnapshotError("Approval must be separate from its plan")


def approve_plan(
    plan: Path,
    image: str,
    expected_plan_id: str,
    expected_candidate_sha256: str,
    output: Path,
    *,
    confirm: bool = False,
    policy: SnapshotPolicy = DEFAULT_POLICY,
    now: datetime | Callable[[], datetime] | None = None,
    context_reader: Callable[[], str] | None = None,
    syntax_check: Callable[[bytes, str], str] | None = None,
) -> dict[str, str | int]:
    """Record explicit approval for one unchanged, freshly validated fixture plan."""
    _check_runtime(policy)
    _pinned_image(image)
    _require_syntax_scope(context_reader, syntax_check)
    _plan_reference(plan, output, policy)
    if (
        confirm is not True
        or not isinstance(expected_plan_id, str)
        or not _PLAN_ID.fullmatch(expected_plan_id)
        or not _digest(expected_candidate_sha256)
    ):
        raise SnapshotError("Approval requires explicit plan and candidate confirmation")

    try:
        with _directory(output.parent, policy) as parent:
            try:
                os.stat(output.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SnapshotError("Approval output already exists")
        started = _read_clock(now)
        status, manifest, data = _plan_state(plan, policy, started, context_reader=context_reader)
        if (
            status != "ready"
            or manifest is None
            or data is None
            or not hmac.compare_digest(expected_plan_id, manifest["plan_id"])
            or not hmac.compare_digest(expected_candidate_sha256, manifest["candidate_sha256"])
        ):
            raise SnapshotError("Plan is not ready or does not match the reviewed identity")
        backup = Path(manifest["backup_path"])
        if output.is_relative_to(backup) or backup.is_relative_to(output):
            raise SnapshotError("Approval must be separate from its plan backup")
        if (_fixture_syntax if syntax_check is None else syntax_check)(data, image) != "passed":
            raise SnapshotError("Fresh isolated syntax validation did not pass")

        approved_at = _read_clock(now)
        if approved_at < started:
            raise SnapshotError("Approval clock moved backward during validation")

        def require_unchanged(current: datetime) -> None:
            if current < approved_at or _plan_state(
                plan, policy, current, context_reader=context_reader
            ) != (
                "ready",
                manifest,
                data,
            ):
                raise SnapshotError("The reviewed plan changed or expired during approval")

        require_unchanged(approved_at)
        receipt = {
            "schema_version": 1,
            "approval_id": secrets.token_hex(16),
            "plan_path": str(plan),
            "plan_id": manifest["plan_id"],
            "plan_manifest_sha256": _sealed_manifest_sha256(manifest),
            "candidate_sha256": manifest["candidate_sha256"],
            "machine_sha256": manifest["machine_sha256"],
            "image_sha256": image,
            "approved_at": approved_at.isoformat(),
            "expires_at": manifest["expires_at"],
            "syntax_status": "passed",
        }
        if "context_sha256" in manifest:
            receipt["context_sha256"] = manifest["context_sha256"]
        receipt["manifest_sha256"] = _sha(_json(receipt))
        _publish(
            output,
            None,
            None,
            receipt,
            lambda: require_unchanged(_read_clock(now)),
            policy,
            manifest_name=_APPROVAL,
        )
    except SnapshotError:
        raise
    except (OSError, ValueError, OverflowError, RecursionError) as error:
        raise SnapshotError("Approval could not be recorded") from error
    return _approval_proof("approved", receipt)


def _approval(approval: Path, policy: SnapshotPolicy) -> tuple[dict, datetime, datetime]:
    _snapshot_path(approval, policy)
    with _directory(approval, policy, private=True) as directory:
        _members(directory, {_APPROVAL})
        raw, _identity = _read(directory, _APPROVAL, MAX_MANIFEST_BYTES, policy, private=True)
        _members(directory, {_APPROVAL})
    receipt = json.loads(raw, object_pairs_hook=_unique)
    fields = {
        "schema_version",
        "approval_id",
        "plan_path",
        "plan_id",
        "plan_manifest_sha256",
        "candidate_sha256",
        "machine_sha256",
        "image_sha256",
        "approved_at",
        "expires_at",
        "syntax_status",
        "manifest_sha256",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) not in (fields, fields | {"context_sha256"})
        or ("context_sha256" in receipt and not _digest(receipt["context_sha256"]))
        or raw != _json(receipt) + b"\n"
    ):
        raise SnapshotError("Invalid canonical approval receipt")
    declared = receipt.pop("manifest_sha256")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or not isinstance(receipt["plan_path"], str)
        or not all(
            isinstance(receipt[field], str) and _PLAN_ID.fullmatch(receipt[field])
            for field in ("approval_id", "plan_id")
        )
        or not all(
            _digest(receipt[field])
            for field in ("plan_manifest_sha256", "machine_sha256", "candidate_sha256")
        )
        or receipt["syntax_status"] != "passed"
        or not _digest(declared)
        or not hmac.compare_digest(declared, _sha(_json(receipt)))
    ):
        raise SnapshotError("Invalid approval receipt")
    _pinned_image(receipt["image_sha256"])
    _plan_reference(Path(receipt["plan_path"]), approval, policy)
    approved_at = _clock(datetime.fromisoformat(receipt["approved_at"]))
    expires = _clock(datetime.fromisoformat(receipt["expires_at"]))
    if (
        approved_at.isoformat() != receipt["approved_at"]
        or expires.isoformat() != receipt["expires_at"]
        or not timedelta(0) < expires - approved_at <= _PLAN_LIFETIME
    ):
        raise SnapshotError("Invalid approval lifetime")
    return receipt, approved_at, expires


def inspect_approval(
    approval: Path,
    *,
    policy: SnapshotPolicy = DEFAULT_POLICY,
    now: datetime | Callable[[], datetime] | None = None,
    context_reader: Callable[[], str] | None = None,
) -> dict[str, str | int]:
    """Check a local approval and the current state of the exact plan it names."""
    _check_runtime(policy)
    current = _read_clock(now)
    try:
        receipt, approved_at, expires = _approval(approval, policy)
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        return _approval_proof("tampered")
    if current >= expires:
        return _approval_proof("expired", receipt)
    if current < approved_at:
        return _approval_proof("unavailable", receipt)
    status, plan, _data = _plan_state(
        Path(receipt["plan_path"]), policy, current, context_reader=context_reader
    )
    if (
        plan is None
        or _sealed_manifest_sha256(plan) != receipt["plan_manifest_sha256"]
        or any(
            plan[field] != receipt[field]
            for field in ("plan_id", "machine_sha256", "candidate_sha256", "expires_at")
        )
        or plan.get("context_sha256") != receipt.get("context_sha256")
        or datetime.fromisoformat(plan["created_at"]) > approved_at
    ):
        return _approval_proof("unavailable", receipt)
    return _approval_proof("approved" if status == "ready" else status, receipt)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid snapshot command.\n")


def main() -> int:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    take = commands.add_parser("capture")
    take.add_argument("source", type=Path)
    take.add_argument("--expected-sha256", required=True)
    take.add_argument("--output", required=True, type=Path)
    view = commands.add_parser("inspect")
    view.add_argument("snapshot", type=Path)
    preflight = commands.add_parser("prepare")
    preflight.add_argument("snapshot", type=Path)
    preflight.add_argument("candidate", type=Path)
    preflight.add_argument("--expected-sha256", required=True)
    preflight.add_argument("--output", required=True, type=Path)
    view_plan = commands.add_parser("inspect-plan")
    view_plan.add_argument("plan", type=Path)
    check_plan = commands.add_parser("validate-plan")
    check_plan.add_argument("plan", type=Path)
    check_plan.add_argument("--image", required=True)
    authorize = commands.add_parser("approve-plan")
    authorize.add_argument("plan", type=Path)
    authorize.add_argument("--image", required=True)
    authorize.add_argument("--expected-plan-id", required=True)
    authorize.add_argument("--expected-candidate-sha256", required=True)
    authorize.add_argument("--output", required=True, type=Path)
    authorize.add_argument("--confirm", required=True, action="store_true")
    view_approval = commands.add_parser("inspect-approval")
    view_approval.add_argument("approval", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "capture":
            result = capture(args.source, args.expected_sha256, args.output)
        elif args.action == "inspect":
            result = inspect(args.snapshot)
        elif args.action == "prepare":
            result = prepare(args.snapshot, args.candidate, args.expected_sha256, args.output)
        elif args.action == "inspect-plan":
            result = inspect_plan(args.plan)
        elif args.action == "validate-plan":
            result = validate_plan(args.plan, args.image)
        elif args.action == "approve-plan":
            result = approve_plan(
                args.plan,
                args.image,
                args.expected_plan_id,
                args.expected_candidate_sha256,
                args.output,
                confirm=args.confirm,
            )
        else:
            result = inspect_approval(args.approval)
    except SnapshotError:
        parser.exit(1, "Nginx configuration snapshot refused.\n")
    print(json.dumps(result, sort_keys=True))
    if args.action == "validate-plan":
        return int(result["plan_status"] != "ready" or result["syntax_status"] != "passed")
    if args.action == "inspect-approval":
        return int(result["approval_status"] != "approved")
    return int("tampered" in (result.get("backup_integrity"), result.get("plan_status")))


if __name__ == "__main__":
    raise SystemExit(main())
