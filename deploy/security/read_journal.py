#!/usr/bin/python3 -I
"""Bounded root-managed journal projection. No arguments, input or raw log export."""

import contextlib
import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from itertools import islice
from pathlib import Path

SCHEMA_VERSION = 1
WINDOW_US = 900_000_000
MAX_RAW_BYTES = 262_144
MAX_OUTPUT_BYTES = 12_288
MAX_RECORDS = 200
MAX_EVENTS = 80
WALL_SECONDS = 4.0
GUARD_LOCK_PATH = Path("/run/opsark-readonly.lock")
MAX_FD_SCAN = 128
UNITS = {"ssh.service": "system_ssh", "opsark-security-probe.service": "controlled_probe"}
GAP_CODES = {
    "journal_unavailable",
    "journal_timeout",
    "journal_output_limit",
    "journal_access_incomplete",
    "journal_record_limit",
    "malformed_journal_record",
    "untrusted_auth_metadata",
    "unsupported_auth_format",
    "invalid_event_metadata",
    "event_outside_window",
    "duplicate_journal_cursor",
    "conflicting_journal_cursor",
    "projection_event_limit",
    "projection_output_limit",
    "reader_privilege_unavailable",
    "reader_invocation_invalid",
    "reader_failed",
}
CURSOR = re.compile(r"[A-Za-z0-9;=_:.+-]{1,256}\Z")
MICROSECONDS = re.compile(r"[0-9]{1,20}\Z")
AUTH_CANDIDATE = re.compile(r"^(?:Failed|Accepted) [^\s]{1,64} for ")
AUTH = re.compile(
    r"^(Failed|Accepted) (password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?:(invalid user) )?([A-Za-z0-9._@-]{1,64}) from ([^\s]{1,64}) port "
    r"([0-9]{1,5})(?: ssh2(?:: [^\r\n]{0,1000})?)?(?: \[preauth\])?$"
)
ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "HOME": "/nonexistent",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
    "PAGER": "cat",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def timestamp_argument(value):
    return f"@{value // 1_000_000}.{value % 1_000_000:06d}"


def journal_command(started_us, ended_us):
    fields = (
        "__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_COMM,_EXE,MESSAGE"
    )
    return [
        "/usr/bin/timeout",
        "-k",
        "1s",
        "3s",
        "/usr/bin/journalctl",
        "--system",
        "--no-pager",
        "--output=json",
        "--output-fields=" + fields,
        "--lines=200",
        "--since=" + timestamp_argument(started_us),
        "--until=" + timestamp_argument(ended_us),
        "--unit=ssh.service",
        "--unit=opsark-security-probe.service",
    ]


def kill_process(process):
    with contextlib.suppress(ProcessLookupError, OSError):
        os.killpg(process.pid, signal.SIGKILL)


def inherited_guard_fds(lock_path=GUARD_LOCK_PATH, *, owner_uid=0, trusted_ancestor=Path("/")):
    """Find an already-open guard lock without opening or following an arbitrary fd path.

    Production always uses the fixed root-owned /run path and root trust boundary.
    The explicit path/owner/ancestor seam permits real unprivileged Linux fixture tests.
    """
    if not lock_path.is_absolute() or not trusted_ancestor.is_absolute():
        raise ValueError("Guard lock path must be absolute")
    try:
        expected = lock_path.lstat()
    except FileNotFoundError:
        return ()  # Direct administrator invocation need not have a guard parent.
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_uid != owner_uid
        or stat.S_IMODE(expected.st_mode) != 0o600
        or expected.st_nlink != 1
    ):
        raise ValueError("Untrusted guard lock")
    parents = (lock_path.parent, *lock_path.parent.parents)
    if trusted_ancestor not in parents:
        raise ValueError("Guard lock outside trusted ancestry")
    for parent in parents:
        details = parent.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != owner_uid
            or details.st_mode & 0o022
        ):
            raise ValueError("Untrusted guard lock parent")
        if parent == trusted_ancestor:
            break
    matches = []
    # /proc entries themselves are kernel fd links. Never readlink/open them:
    # only fstat existing numeric descriptors and compare the trusted inode.
    with os.scandir("/proc/self/fd") as entries:
        for entry in islice(entries, MAX_FD_SCAN):
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            descriptor = int(entry.name)
            if descriptor < 3:
                continue
            try:
                actual = os.fstat(descriptor)
            except OSError:
                continue  # Descriptor may have closed since enumeration.
            if (
                (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
                and stat.S_ISREG(actual.st_mode)
                and actual.st_uid == owner_uid
                and stat.S_IMODE(actual.st_mode) == 0o600
                and actual.st_nlink == 1
            ):
                matches.append(descriptor)
    current = lock_path.lstat()
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError("Guard lock changed during discovery")
    return tuple(sorted(matches))


def read_bounded(started_us, ended_us):
    lock_fds = inherited_guard_fds()
    process = subprocess.Popen(  # noqa: S603 -- all command fields are fixed or local clock values.
        journal_command(started_us, ended_us),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=ENVIRONMENT.copy(),
        shell=False,
        start_new_session=True,
        pass_fds=lock_fds,
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    gaps = []
    deadline = time.monotonic() + WALL_SECONDS
    streams = (process.stdout, process.stderr)
    try:
        with selectors.DefaultSelector() as selector:
            for stream, label in zip(streams, ("stdout", "stderr"), strict=True):
                if stream is None:
                    raise ValueError("Missing bounded stream")
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    gaps.append("journal_timeout")
                    break
                capacity = MAX_RAW_BYTES - sum(map(len, output.values()))
                if capacity <= 0:
                    gaps.append("journal_output_limit")
                    break
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, min(4096, capacity))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        capacity -= len(chunk)
                        if capacity <= 0:
                            break
        if gaps:
            kill_process(process)
        try:
            code = process.wait(timeout=max(0.05, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            gaps.append("journal_timeout")
            kill_process(process)
            code = process.wait(timeout=0.5)
    finally:
        if process.poll() is None:
            kill_process(process)
            process.wait(timeout=0.5)
        for stream in streams:
            if stream is not None:
                stream.close()
    if code in (124, 137):
        gaps.append("journal_timeout")
    elif code != 0 and not gaps:
        gaps.append("journal_unavailable")
    if output["stderr"]:
        gaps.append("journal_access_incomplete")
    return bytes(output["stdout"]), list(dict.fromkeys(gaps)), code


def project_record(record, started_us, ended_us):
    if not isinstance(record, dict):
        return None, "malformed_journal_record"
    message = record.get("MESSAGE")
    if not isinstance(message, str):
        return None, "malformed_journal_record"
    # VERBOSE audits such as "Accepted key ... found at ..." do not report
    # an authentication result. Keep unknown result methods as explicit gaps.
    if AUTH_CANDIDATE.match(message) is None:
        return None, None
    unit = record.get("_SYSTEMD_UNIT")
    comm, executable, identifier = (
        record.get("_COMM"),
        record.get("_EXE"),
        record.get("SYSLOG_IDENTIFIER"),
    )
    system_metadata = (
        unit == "ssh.service"
        and isinstance(comm, str)
        and comm in {"sshd", "sshd-session"}
        and isinstance(executable, str)
        and executable in {"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"}
        and isinstance(identifier, str)
        and identifier in {"sshd", "sshd-session"}
    )
    probe_metadata = (
        unit == "opsark-security-probe.service"
        and comm == "opsark-sshd-lab"
        and executable == "/usr/local/libexec/opsark-sshd-lab"
        and identifier == "opsark-security-probe"
    )
    if not system_metadata and not probe_metadata:
        return None, "untrusted_auth_metadata"
    match = AUTH.fullmatch(message)
    if match is None:
        return None, "unsupported_auth_format"
    action, method, invalid, account, source, port = match.groups()
    cursor, timestamp, boot = (
        record.get("__CURSOR"),
        record.get("__REALTIME_TIMESTAMP"),
        record.get("_BOOT_ID"),
    )
    if (
        not isinstance(cursor, str)
        or not CURSOR.fullmatch(cursor)
        or not isinstance(timestamp, str)
        or not MICROSECONDS.fullmatch(timestamp)
        or not isinstance(boot, str)
        or not re.fullmatch(r"[0-9a-f]{32}", boot)
        or not 1 <= int(port) <= 65535
        or "%" in source
        or (action == "Accepted" and invalid is not None)
    ):
        return None, "invalid_event_metadata"
    occurred_us = int(timestamp)
    if not started_us <= occurred_us <= ended_us:
        return None, "event_outside_window"
    try:
        source_ip = str(ipaddress.ip_address(source))
    except ValueError:
        return None, "invalid_event_metadata"
    return {
        "cursor": cursor,
        "occurred_us": str(occurred_us),
        "unit": unit,
        "origin": UNITS[unit],
        "kind": "authentication_failed" if action == "Failed" else "authentication_accepted",
        "source_ip": source_ip,
        "method": method.split("/")[0],
        "account_type": "invalid" if invalid else "root" if account == "root" else "other",
    }, None


def encode(payload):
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_payload(raw, started_us, ended_us, gaps=None, *, available=True):
    gaps = list(dict.fromkeys(gaps or []))
    if any(gap not in GAP_CODES for gap in gaps):
        raise ValueError("Unknown internal gap code")
    rows = raw.splitlines()
    if len(rows) >= MAX_RECORDS:
        gaps.append("journal_record_limit")
    by_cursor, conflicts = {}, set()
    for row in rows[:MAX_RECORDS]:
        if len(row) > 16384:
            gaps.append("malformed_journal_record")
            continue
        try:
            record = json.loads(row, object_pairs_hook=unique_object)
        except (ValueError, UnicodeDecodeError):
            gaps.append("malformed_journal_record")
            continue
        projection, gap = project_record(record, started_us, ended_us)
        if gap:
            gaps.append(gap)
        if projection is None:
            continue
        cursor = projection["cursor"]
        if cursor in by_cursor:
            if by_cursor[cursor] != projection:
                gaps.append("conflicting_journal_cursor")
                conflicts.add(cursor)
            else:
                gaps.append("duplicate_journal_cursor")
        else:
            by_cursor[cursor] = projection
    events = sorted(
        (event for cursor, event in by_cursor.items() if cursor not in conflicts),
        key=lambda event: (int(event["occurred_us"]), event["cursor"]),
    )
    if len(events) > MAX_EVENTS:
        gaps.append("projection_event_limit")
        events = events[-MAX_EVENTS:]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "window_started_us": str(started_us),
        "window_ended_us": str(ended_us),
        "status": "complete",
        "gaps": [],
        "raw_records_seen": min(len(rows), MAX_RECORDS),
        "events": events,
    }
    payload["gaps"] = list(dict.fromkeys(gaps))
    payload["status"] = "unavailable" if not available else "degraded" if gaps else "complete"
    if not available:
        payload["events"] = []
    while len(encode(payload)) + 1 > MAX_OUTPUT_BYTES and payload["events"]:
        if "projection_output_limit" not in payload["gaps"]:
            payload["gaps"].append("projection_output_limit")
        payload["status"] = "degraded"
        payload["events"].pop(0)
    return payload


def observe():
    ended_us = time.time_ns() // 1000
    started_us = ended_us - WINDOW_US
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return build_payload(
            b"", started_us, ended_us, ["reader_privilege_unavailable"], available=False
        )
    raw, gaps, code = read_bounded(started_us, ended_us)
    return build_payload(raw, started_us, ended_us, gaps, available=code == 0)


def main():
    try:
        if len(sys.argv) != 1:
            ended_us = time.time_ns() // 1000
            payload = build_payload(
                b"", ended_us - WINDOW_US, ended_us, ["reader_invocation_invalid"], available=False
            )
        else:
            payload = observe()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        ended_us = time.time_ns() // 1000
        payload = build_payload(
            b"", ended_us - WINDOW_US, ended_us, ["reader_failed"], available=False
        )
    sys.stdout.buffer.write(encode(payload) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
