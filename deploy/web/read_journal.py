#!/usr/bin/python3 -I
"""Bounded root-managed journal projection. No arguments, input or raw log export."""

import contextlib
import hashlib
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
from decimal import Decimal
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
PROFILE_PATH = Path("/etc/opsark/web-observation.json")
PROFILE_MAX_BYTES = 16384
PATH_CLASSES = {
    "health",
    "normal",
    "static",
    "robots",
    "callback",
    "secret_probe",
    "repo_probe",
    "cms_probe",
    "admin_probe",
    "traversal_probe",
    "other",
}
CLIENT_CLASSES = {"browser", "declared_crawler", "probe", "other"}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER"}
GAP_CODES = {
    "journal_unavailable",
    "journal_timeout",
    "journal_output_limit",
    "journal_access_incomplete",
    "journal_record_limit",
    "malformed_journal_record",
    "untrusted_web_metadata",
    "invalid_web_message",
    "profile_unavailable",
    "unresolved_proxy_source",
    "request_time_capped",
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
        "--unit=nginx.service",
        "--identifier=opsark_web",
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


def validate_profile(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "sites"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Invalid Web profile")
    sites = value["sites"]
    if not isinstance(sites, list) or not 1 <= len(sites) <= 3:
        raise ValueError("Invalid Web sites")
    result = {}
    fields = {
        "id",
        "domain",
        "origin",
        "trusted_proxies",
        "forwarded_header",
        "expected_error_statuses",
    }
    for site in sites:
        if not isinstance(site, dict) or set(site) != fields:
            raise ValueError("Invalid Web site fields")
        name = site["id"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", name)
            or name in result
        ):
            raise ValueError("Invalid Web site identifier")
        domain = site["domain"]
        if (
            not isinstance(domain, str)
            or len(domain) > 253
            or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                for part in domain.split(".")
            )
        ):
            raise ValueError("Invalid Web site domain")
        if site["origin"] not in {"system_web", "controlled_web_probe"} or site[
            "forwarded_header"
        ] not in {"x-forwarded-for", "cf-connecting-ip"}:
            raise ValueError("Invalid Web source profile")
        proxies = site["trusted_proxies"]
        if not isinstance(proxies, list) or len(proxies) > 8:
            raise ValueError("Invalid trusted proxy list")
        networks = []
        for address in proxies:
            if not isinstance(address, str):
                raise ValueError("Invalid trusted proxy")
            network = ipaddress.ip_network(address, strict=True)
            if network.prefixlen == 0 or str(network) != address:
                raise ValueError("Universal or noncanonical trusted proxy refused")
            networks.append(network)
        expected = site["expected_error_statuses"]
        if (
            not isinstance(expected, list)
            or len(expected) > 20
            or any(type(code) is not int or not 400 <= code <= 599 for code in expected)
            or len(set(expected)) != len(expected)
        ):
            raise ValueError("Invalid expected error statuses")
        result[name] = {**site, "networks": networks}
    return result


def load_profile(path=PROFILE_PATH):
    for parent in (path.parent, *path.parent.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("Untrusted profile parent")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > PROFILE_MAX_BYTES
        ):
            raise ValueError("Untrusted Web profile")
        raw = handle.read(PROFILE_MAX_BYTES + 1)
    if len(raw) > PROFILE_MAX_BYTES:
        raise ValueError("Web profile too large")
    return validate_profile(json.loads(raw, object_pairs_hook=unique_object)), hashlib.sha256(
        raw
    ).hexdigest()


def address(value):
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise ValueError("Invalid network address")
    return str(ipaddress.ip_address(value))


def project_record(record, started_us, ended_us, profile):
    if not isinstance(record, dict):
        return None, "malformed_journal_record"
    if (
        record.get("_SYSTEMD_UNIT"),
        record.get("_COMM"),
        record.get("_EXE"),
        record.get("SYSLOG_IDENTIFIER"),
    ) != ("nginx.service", "nginx", "/usr/sbin/nginx", "opsark_web"):
        return None, "untrusted_web_metadata"
    fields = {
        "schema_version",
        "site_id",
        "msec",
        "peer_ip",
        "xff",
        "xff_present",
        "cf_ip",
        "cf_present",
        "method",
        "status",
        "path_class",
        "client_class",
        "request_time",
        "bytes_sent",
        "request_id",
    }
    try:
        message = record.get("MESSAGE")
        if not isinstance(message, str) or len(message) > 2048:
            raise ValueError("Invalid Web message")
        value = json.loads(message, object_pairs_hook=unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
        ):
            raise ValueError("Invalid Web message fields")
        site = profile[value["site_id"]]
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
        ):
            raise ValueError("Invalid journal identity")
        occurred = int(timestamp)
        if not started_us <= occurred <= ended_us:
            return None, "event_outside_window"
        if (
            not isinstance(value["msec"], str)
            or not re.fullmatch(r"[0-9]{1,15}\.[0-9]{3}", value["msec"])
            or abs(int(Decimal(value["msec"]) * 1_000_000) - occurred) > 120_000_000
        ):
            raise ValueError("Invalid request timestamp")
        peer = address(value["peer_ip"])
        if (
            value["method"] not in METHODS
            or value["path_class"] not in PATH_CLASSES
            or value["client_class"] not in CLIENT_CLASSES
        ):
            raise ValueError("Unsupported request projection")
        if (
            type(value["status"]) is not int
            or not 100 <= value["status"] <= 599
            or type(value["bytes_sent"]) is not int
            or not 0 <= value["bytes_sent"] < 2**63
        ):
            raise ValueError("Invalid response metadata")
        if not isinstance(value["request_id"], str) or not re.fullmatch(
            r"[0-9a-f]{32}", value["request_id"]
        ):
            raise ValueError("Invalid request identity")
        if not isinstance(value["request_time"], str) or not re.fullmatch(
            r"[0-9]{1,6}\.[0-9]{3}", value["request_time"]
        ):
            raise ValueError("Invalid response time")
        duration = int(Decimal(value["request_time"]) * 1000)
        for key in ("xff", "cf_ip"):
            if not isinstance(value[key], str) or len(value[key]) > 45:
                raise ValueError("Unscreened forwarded data")
        if any(value[key] not in {"0", "1"} for key in ("xff_present", "cf_present")):
            raise ValueError("Invalid forwarded presence")
        trusted = any(ipaddress.ip_address(peer) in network for network in site["networks"])
        candidate_name, presence = (
            ("xff", "xff_present")
            if site["forwarded_header"] == "x-forwarded-for"
            else ("cf_ip", "cf_present")
        )
        source, trust = peer, "direct_peer"
        gap = "request_time_capped" if duration > 60000 else None
        if trusted:
            try:
                source = address(value[candidate_name])
                if value[presence] != "1":
                    raise ValueError("Missing forwarded address")
                trust = "trusted_proxy"
            except ValueError:
                source, trust, gap = None, "unresolved_proxy", "unresolved_proxy_source"
        elif value["xff_present"] == "1" or value["cf_present"] == "1":
            trust = "forwarded_ignored"
        return {
            "cursor": cursor,
            "occurred_us": str(occurred),
            "site_id": site["id"],
            "origin": site["origin"],
            "source_ip": source,
            "peer_ip": peer,
            "source_trust": trust,
            "method": value["method"],
            "status": value["status"],
            "path_class": value["path_class"],
            "client_class": value["client_class"],
            "request_time_ms": min(duration, 60000),
            "bytes_sent": value["bytes_sent"],
            "request_id": value["request_id"],
            "expected_error": value["status"] in site["expected_error_statuses"],
        }, gap
    except (ValueError, KeyError, TypeError, ArithmeticError):
        return None, "invalid_web_message"


def encode(payload):
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_payload(raw, started_us, ended_us, profile, profile_digest, gaps=None, *, available=True):
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
        projection, gap = project_record(record, started_us, ended_us, profile)
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
        "profile_digest": profile_digest,
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
            b"",
            started_us,
            ended_us,
            {},
            "0" * 64,
            ["reader_privilege_unavailable"],
            available=False,
        )
    try:
        profile, digest = load_profile()
    except (OSError, ValueError, UnicodeError):
        return build_payload(
            b"", started_us, ended_us, {}, "0" * 64, ["profile_unavailable"], available=False
        )
    raw, gaps, code = read_bounded(started_us, ended_us)
    return build_payload(raw, started_us, ended_us, profile, digest, gaps, available=code == 0)


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("No arguments accepted")
        payload = observe()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        ended = time.time_ns() // 1000
        payload = build_payload(
            b"", ended - WINDOW_US, ended, {}, "0" * 64, ["reader_failed"], available=False
        )
    sys.stdout.buffer.write(encode(payload) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
