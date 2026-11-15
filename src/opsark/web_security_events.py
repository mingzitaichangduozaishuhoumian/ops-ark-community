"""Authenticated bounded SSH collection of reduced, evidence-linked security events."""

import hashlib
import ipaddress
import json
import re
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import paramiko

from opsark.baselines import scope_for
from opsark.collector import COMMAND_TIMEOUT, CONNECTION_TIMEOUT, run_check
from opsark.config import HostConfig
from opsark.models import CheckResult
from opsark.web_security_models import WebSecurityEvent, WebSecurityObservation

SECURITY_WEB_COMMAND = "timeout -k 1s 5s /usr/bin/python3 -I /usr/local/libexec/opsark-web-read"
MAX_PAYLOAD_BYTES = 12_288
WINDOW_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 120
_CURSOR = re.compile(r"[A-Za-z0-9;=_:.+-]{1,256}\Z")
_MICROSECONDS = re.compile(r"[0-9]{1,20}\Z")
_GAPS = {
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
_PROJECTION_FIELDS = {
    "cursor",
    "occurred_us",
    "site_id",
    "origin",
    "source_ip",
    "peer_ip",
    "source_trust",
    "method",
    "status",
    "path_class",
    "client_class",
    "request_time_ms",
    "bytes_sent",
    "request_id",
    "expected_error",
}


def profile_digest(public):
    value = getattr(public, "web_profile_digest", None)
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else "0" * 64


def scope_for_web(public):
    return hashlib.sha256(
        (scope_for(public) + "\nweb\n" + profile_digest(public)).encode()
    ).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _instant(value):
    if not isinstance(value, str) or not _MICROSECONDS.fullmatch(value):
        raise ValueError("Invalid journal timestamp")
    micros = int(value)
    return datetime.fromtimestamp(micros // 1_000_000, UTC).replace(microsecond=micros % 1_000_000)


def _empty(host, collected_at, duration_ms, gap):
    return WebSecurityObservation(
        id=str(uuid4()),
        host_id=host.public.id,
        scope_hash=scope_for_web(host.public),
        profile_digest=profile_digest(host.public),
        collected_at=collected_at,
        window_started_at=collected_at - timedelta(seconds=WINDOW_SECONDS),
        window_ended_at=collected_at,
        status="unavailable",
        gaps=[gap],
        duration_ms=duration_ms,
    )


def event_id(scope_hash, cursor):
    return hashlib.sha256((scope_hash + "\n" + cursor).encode("utf-8")).hexdigest()


def parse_observation(host, result, *, collected_at=None, duration_ms=0):
    collected_at = collected_at or datetime.now(UTC)
    if collected_at.tzinfo is None:
        raise ValueError("Observation time must be timezone aware")
    collected_at = collected_at.astimezone(UTC)
    if result.status != "ok" or type(result.exit_code) is not int or result.exit_code != 0:
        return _empty(host, collected_at, duration_ms, "security_command_" + result.status)
    try:
        size = len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
    except UnicodeEncodeError:
        return _empty(host, collected_at, duration_ms, "invalid_security_payload")
    if result.truncated or size > MAX_PAYLOAD_BYTES or result.stderr:
        return _empty(host, collected_at, duration_ms, "security_output_incomplete")
    scope_hash = scope_for_web(host.public)
    try:
        payload = json.loads(result.stdout, object_pairs_hook=_unique_object)
        if (
            not isinstance(payload, dict)
            or set(payload)
            != {
                "schema_version",
                "profile_digest",
                "window_started_us",
                "window_ended_us",
                "status",
                "gaps",
                "raw_records_seen",
                "events",
            }
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or payload["status"] not in {"complete", "degraded", "unavailable"}
            or not isinstance(payload["gaps"], list)
            or len(payload["gaps"]) > 20
            or any(not isinstance(gap, str) or gap not in _GAPS for gap in payload["gaps"])
            or type(payload["raw_records_seen"]) is not int
            or not 0 <= payload["raw_records_seen"] <= 200
            or not isinstance(payload["events"], list)
            or len(payload["events"]) > 80
            or (payload["status"] == "complete" and payload["gaps"])
            or (payload["status"] != "complete" and not payload["gaps"])
            or (payload["status"] == "unavailable" and payload["events"])
        ):
            raise ValueError("Invalid security schema")
        expected_digest = profile_digest(host.public)
        if expected_digest == "0" * 64:
            return _empty(host, collected_at, duration_ms, "web_profile_not_registered")
        if payload["profile_digest"] != expected_digest and not (
            payload["status"] == "unavailable"
            and not payload["events"]
            and payload["profile_digest"] == "0" * 64
        ):
            return _empty(host, collected_at, duration_ms, "web_profile_changed")
        started, ended = (
            _instant(payload["window_started_us"]),
            _instant(payload["window_ended_us"]),
        )
        if (ended - started).total_seconds() != WINDOW_SECONDS:
            raise ValueError("Invalid observation window")
        if abs((ended - collected_at).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
            return _empty(host, collected_at, duration_ms, "remote_clock_outside_budget")
        if len(payload["events"]) > payload["raw_records_seen"]:
            raise ValueError("Event count exceeds read records")
        events, conflicts, gaps = {}, set(), list(dict.fromkeys(payload["gaps"]))
        for row in payload["events"]:
            if not isinstance(row, dict) or set(row) != _PROJECTION_FIELDS:
                raise ValueError("Invalid event projection")
            cursor = row["cursor"]
            if not isinstance(cursor, str) or not _CURSOR.fullmatch(cursor):
                raise ValueError("Invalid event cursor")
            occurred = _instant(row["occurred_us"])
            if not started <= occurred <= ended:
                raise ValueError("Event outside window")
            peer = row["peer_ip"]
            source = row["source_ip"]
            if not isinstance(peer, str) or "%" in peer or str(ipaddress.ip_address(peer)) != peer:
                raise ValueError("Invalid peer address")
            if source is not None and (
                not isinstance(source, str)
                or "%" in source
                or str(ipaddress.ip_address(source)) != source
            ):
                raise ValueError("Invalid source address")
            if row["source_trust"] == "unresolved_proxy":
                if source is not None:
                    raise ValueError("Unverified proxy cannot identify a client")
            elif source is None or (
                row["source_trust"] in {"direct_peer", "forwarded_ignored"} and source != peer
            ):
                raise ValueError("Source attribution contradicts transport peer")
            if (
                any(
                    type(row[key]) is not int for key in ("status", "request_time_ms", "bytes_sent")
                )
                or type(row["expected_error"]) is not bool
            ):
                raise ValueError("Invalid numeric request metadata")
            event = WebSecurityEvent(
                id=event_id(scope_hash, cursor),
                host_id=host.public.id,
                scope_hash=scope_hash,
                occurred_at=occurred,
                journal_cursor=cursor,
                **{
                    key: value for key, value in row.items() if key not in {"cursor", "occurred_us"}
                },
            )
            if cursor in events:
                if events[cursor] != event:
                    gaps.append("conflicting_journal_cursor")
                    conflicts.add(cursor)
                else:
                    gaps.append("duplicate_journal_cursor")
            else:
                events[cursor] = event
        result_events = sorted(
            (event for cursor, event in events.items() if cursor not in conflicts),
            key=lambda event: (event.occurred_at, event.id),
        )
        return WebSecurityObservation(
            id=str(uuid4()),
            host_id=host.public.id,
            scope_hash=scope_hash,
            profile_digest=expected_digest,
            collected_at=collected_at,
            window_started_at=started,
            window_ended_at=ended,
            status="degraded" if gaps and payload["status"] == "complete" else payload["status"],
            gaps=list(dict.fromkeys(gaps)),
            events=result_events,
            raw_records_seen=payload["raw_records_seen"],
            duration_ms=duration_ms,
        )
    except (ValueError, TypeError, OverflowError, OSError):
        return _empty(host, collected_at, duration_ms, "invalid_security_payload")


def collect_web_security(host: HostConfig) -> WebSecurityObservation:
    started = time.monotonic()
    collected_at = datetime.now(UTC)
    if (
        host.public.source != "ssh"
        or host.public.username == "root"
        or not host.public.trusted_hosts_digest
        or profile_digest(host.public) == "0" * 64
    ):
        return _empty(host, collected_at, 0, "security_target_not_registered")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        with host.known_hosts_file.open("rb") as handle:
            if (
                hashlib.file_digest(handle, "sha256").hexdigest()
                != host.public.trusted_hosts_digest
            ):
                return _empty(host, collected_at, 0, "security_trust_record_changed")
        client.load_host_keys(str(host.known_hosts_file))
        client.connect(
            hostname=host.public.address,
            port=host.public.port,
            username=host.public.username,
            key_filename=str(host.key_file),
            allow_agent=False,
            look_for_keys=False,
            timeout=CONNECTION_TIMEOUT,
            auth_timeout=CONNECTION_TIMEOUT,
            banner_timeout=CONNECTION_TIMEOUT,
            channel_timeout=COMMAND_TIMEOUT,
        )
        result = run_check(client, "web_security_events", SECURITY_WEB_COMMAND, COMMAND_TIMEOUT)
    except (OSError, ValueError, paramiko.SSHException):
        result = CheckResult(name="web_security_events", status="unavailable", exit_code=None)
    finally:
        client.close()
    return parse_observation(
        host,
        result,
        collected_at=collected_at,
        duration_ms=round((time.monotonic() - started) * 1000),
    )
