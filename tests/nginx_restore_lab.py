#!/usr/bin/env python3
"""Rehearse an exact one-file Nginx restore in a disposable networkless Docker guest."""

import argparse
import hashlib
import http.client
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, suppress
from pathlib import Path

NGINX = Path("/usr/sbin/nginx")
TARGET = Path("/etc/nginx/conf.d/opsark-isolated-restore-fixture.conf")
PORT = 18087
FIXTURE_UID = 65534
FIXTURE_GID = 65534
TARGET_HOST = "target.opsark.invalid"
CONTROL_HOST = "control.opsark.invalid"
UNKNOWN_HOST = "unknown.opsark.invalid"
ORIGINAL_BODY = b"opsark-original"
CANDIDATE_BODY = b"opsark-candidate"
CONTROL_BODY = b"opsark-control"
ORIGINAL = b"""server {
    listen 127.0.0.1:18087;
    server_name target.opsark.invalid;
    location = /healthz { default_type text/plain; return 200 "opsark-original"; }
}
"""
CANDIDATE = ORIGINAL.replace(ORIGINAL_BODY, CANDIDATE_BODY)
APPROVED_DIGEST = "a96b88b8f8b63e80fb8e8d0b28769d0ecbaa7bc4860eab6166cd13f01f85c95e"
INVALID = b"opsark_invalid_fixture;\n" + ORIGINAL
_TIMEOUT = 8
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}


class LabError(ValueError):
    """The isolated rehearsal refused a step or did not obtain its expected proof."""


def _require(value: bool, step: str) -> None:
    if not value:
        raise LabError(step)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordinary(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and not info.st_mode & 0o7022
    )


def _trusted_parents(path: Path) -> None:
    for parent in path.parents:
        info = parent.lstat()
        _require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "untrusted experiment path",
        )


def _isolation(snapshot_tool: Path, approved: str) -> None:
    _require(sys.platform == "linux" and os.geteuid() == 0, "Linux root guest required")
    _require(
        Path("/.dockerenv").is_file()
        and {name for _, name in socket.if_nameindex()} == {"lo"}
        and not Path("/var/run/docker.sock").exists(),
        "disposable networkless Docker guest required",
    )
    status = Path("/proc/self/status").read_text(encoding="ascii")
    _require("NoNewPrivs:\t1\n" in status, "guest needs no-new-privileges")
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            # CHOWN, KILL, SETGID and SETUID are needed to constrain and stop Nginx.
            _require(int(line.split()[1], 16) & 0xE1 == 0xE1, "guest capabilities are incomplete")
            break
    else:
        raise LabError("guest capabilities could not be verified")
    # Refuse mounted configuration, including a host bind on any ancestor of the fixture.
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        mount = Path(fields[4])
        if mount != Path("/") and (mount in TARGET.parents or mount == TARGET):
            raise LabError("the fixture configuration directory must not be mounted")
        if mount == Path("/run") and fields[fields.index("-") + 1] != "tmpfs":
            raise LabError("the fixture runtime directory must not be bind-mounted")
    _require(approved == APPROVED_DIGEST == _sha(CANDIDATE), "fixture digest approval mismatch")
    _require(
        snapshot_tool.is_absolute() and ".." not in snapshot_tool.parts,
        "an absolute snapshot tool path is required",
    )
    _trusted_parents(snapshot_tool)
    _require(_ordinary(snapshot_tool.lstat()), "untrusted snapshot tool")
    _trusted_parents(TARGET)
    _require(not os.path.lexists(TARGET), "fixture configuration already exists")
    _trusted_parents(NGINX)
    _require(_ordinary(NGINX.lstat()), "trusted Nginx binary unavailable")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _cas(expected: bytes, replacement: bytes, identity: os.stat_result) -> None:
    fd = os.open(TARGET, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "r+b") as handle:
        info = os.fstat(handle.fileno())
        _require(_ordinary(info) and _same_file(info, identity), "fixture identity changed")
        _require(handle.read(512) == expected, "fixture compare-and-swap refused")
        _require(_same_file(TARGET.lstat(), info), "fixture path changed before writing")
        handle.seek(0)
        handle.write(replacement)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())


@contextmanager
def _fixture():
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(ORIGINAL)
            handle.flush()
            os.fsync(handle.fileno())
        yield identity
    finally:
        with suppress(FileNotFoundError):
            if _same_file(TARGET.lstat(), identity):
                TARGET.unlink()


def _snapshot(tool: Path, *args: str) -> dict:
    call = subprocess.run(  # noqa: S603 -- trusted tool and fixed fixture arguments.
        [sys.executable, "-I", str(tool), *args],
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
        env=_ENV,
    )
    _require(call.returncode == 0 and len(call.stdout) <= 1024, "snapshot tool refused the fixture")
    try:
        result = json.loads(call.stdout)
    except ValueError as error:
        raise LabError("snapshot tool receipt invalid") from error
    _require(isinstance(result, dict), "snapshot tool receipt invalid")
    return result


def _expect_snapshot(receipt: dict, disk: str) -> None:
    _require(
        receipt
        == {
            "schema_version": 1,
            "backup_integrity": "intact",
            "disk_status": disk,
            "rollback_status": "not_rehearsed",
            "sha256": _sha(ORIGINAL),
        },
        "unexpected snapshot proof",
    )


def _write_wrapper(root: Path) -> tuple[Path, Path]:
    # Root keeps the wrapper; the unprivileged master has write access only to runtime state.
    root.chmod(0o711)
    state = root / "state"
    state.mkdir(mode=0o770)
    os.chown(state, 0, FIXTURE_GID)
    state.chmod(0o770)
    for name in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
        directory = state / name
        directory.mkdir(mode=0o770)
        os.chown(directory, 0, FIXTURE_GID)
        directory.chmod(0o770)
    wrapper = root / "fixture.conf"
    wrapper.write_text(
        f"""daemon off;
master_process on;
worker_processes 1;
pid {state}/nginx.pid;
error_log stderr crit;
events {{ worker_connections 16; }}
http {{
    access_log off;
    client_body_temp_path {state}/body;
    proxy_temp_path {state}/proxy;
    fastcgi_temp_path {state}/fastcgi;
    uwsgi_temp_path {state}/uwsgi;
    scgi_temp_path {state}/scgi;
    server {{
        listen 127.0.0.1:{PORT} default_server;
        server_name _;
        return 404;
    }}
    server {{
        listen 127.0.0.1:{PORT};
        server_name {CONTROL_HOST};
        location = /healthz {{ default_type text/plain; return 200 "{CONTROL_BODY.decode()}"; }}
    }}
    include {TARGET};
}}
""",
        encoding="ascii",
    )
    wrapper.chmod(0o644)
    return wrapper, state


def _nginx(wrapper: Path) -> list[str]:
    return [str(NGINX), "-e", "stderr", "-p", str(wrapper.parent), "-c", str(wrapper)]


def _syntax(wrapper: Path, *, valid: bool) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed disposable Nginx fixture.
        [*_nginx(wrapper), "-t", "-q"],
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
        env=_ENV,
        user=FIXTURE_UID,
        group=FIXTURE_GID,
        extra_groups=(),
    )
    if valid:
        _require(result.returncode == 0, "fixture syntax validation failed")
    else:
        _require(
            result.returncode != 0
            and b'unknown directive "opsark_invalid_fixture"' in result.stderr,
            "the deliberately invalid syntax was not rejected as expected",
        )


@contextmanager
def _running(wrapper: Path):
    process = subprocess.Popen(  # noqa: S603 -- fixed disposable Nginx fixture.
        _nginx(wrapper),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_ENV,
        user=FIXTURE_UID,
        group=FIXTURE_GID,
        extra_groups=(),
        start_new_session=True,
    )
    try:
        yield process
    finally:
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            process.wait(timeout=_TIMEOUT)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=_TIMEOUT)
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)


def _http(host: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
    try:
        connection.request("GET", "/healthz", headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read(512)
    finally:
        connection.close()


def _healthy(process, target_body: bytes) -> None:
    deadline = time.monotonic() + _TIMEOUT
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if (
                _http(TARGET_HOST) == (200, target_body)
                and _http(CONTROL_HOST) == (200, CONTROL_BODY)
                and _http(UNKNOWN_HOST)[0] == 404
            ):
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise LabError("registered fixture or control HTTP response failed")


def rehearse(snapshot_tool: Path, approved: str) -> dict[str, int | bool | str]:
    _isolation(snapshot_tool, approved)
    with tempfile.TemporaryDirectory(prefix="opsark-nginx-restore-", dir="/run") as temporary:
        root = Path(temporary)
        wrapper, state = _write_wrapper(root)
        backup = root / "snapshot"
        with _fixture() as identity:
            _syntax(wrapper, valid=True)
            with _running(wrapper) as process:
                _healthy(process, ORIGINAL_BODY)
                _expect_snapshot(
                    _snapshot(
                        snapshot_tool,
                        "capture",
                        str(TARGET),
                        "--expected-sha256",
                        _sha(ORIGINAL),
                        "--output",
                        str(backup),
                    ),
                    "unchanged",
                )
                _cas(ORIGINAL, INVALID, identity)
                _syntax(wrapper, valid=False)
                _healthy(process, ORIGINAL_BODY)

                _cas(INVALID, CANDIDATE, identity)
                _syntax(wrapper, valid=True)
                _require(_sha(TARGET.read_bytes()) == approved, "candidate digest changed")
                _require(
                    (state / "nginx.pid").read_text(encoding="ascii").strip() == str(process.pid),
                    "fixture master identity changed",
                )
                process.send_signal(signal.SIGHUP)
                _healthy(process, CANDIDATE_BODY)

                _expect_snapshot(_snapshot(snapshot_tool, "inspect", str(backup)), "drift")
                restored = (backup / "nginx.conf").read_bytes()
                _require(restored == ORIGINAL, "restored bytes differ from the original fixture")
                _cas(CANDIDATE, restored, identity)
                _syntax(wrapper, valid=True)
                restored_proof = _snapshot(snapshot_tool, "inspect", str(backup))
                _require(
                    restored_proof.get("disk_status") in {"unchanged", "drift"},
                    "restored disk identity could not be compared",
                )
                _expect_snapshot(restored_proof, restored_proof["disk_status"])
                _require(TARGET.read_bytes() == restored, "restored disk bytes changed")
                process.send_signal(signal.SIGHUP)
                _healthy(process, ORIGINAL_BODY)
    return {
        "schema_version": 1,
        "isolated": True,
        "native_syntax_checked": True,
        "approved_fixture_changes": 1,
        "invalid_syntax_rejected": True,
        "invalid_candidate_left_running_http_unchanged": True,
        "same_host_backup_verified": True,
        "restore_compare_and_swap_passed": True,
        "snapshot_bytes_restored": True,
        "successful_reloads": 2,
        "target_http_verified_at_all_stages": True,
        "control_http_verified_at_all_stages": True,
        "unknown_host_rejected_at_all_stages": True,
        "nginx_stopped": True,
        "result": "passed",
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid isolated Nginx rehearsal command.\n")


def main() -> int:
    parser = _Parser(description=__doc__, epilog=f"Reviewed fixture SHA256 {APPROVED_DIGEST}")
    parser.add_argument("--snapshot-tool", required=True, type=Path)
    parser.add_argument("--approve-candidate-sha256", required=True)
    parser.add_argument("--confirm-isolated", required=True, action="store_true")
    args = parser.parse_args()
    try:
        result = rehearse(args.snapshot_tool, args.approve_candidate_sha256)
    except LabError as error:
        parser.exit(1, f"Isolated Nginx rehearsal refused: {error}.\n")
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, "Isolated Nginx rehearsal failed.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
