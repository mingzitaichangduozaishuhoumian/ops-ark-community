"""Strict, bounded v1 wire grammar for the private SSH request dispatcher."""

import hashlib
import json
import re
from datetime import UTC, datetime

ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OPS = {"arm", "prepare", "apply", "query", "revoke", "mode_sync"}
REASONS = {
    "ok",
    "not_found",
    "request_conflict",
    "mode_unsynced",
    "authorization_denied",
    "quota_exhausted",
    "cursor_expired",
    "evidence_gap",
    "success_seen",
    "binding_changed",
    "policy_changed",
    "capacity_full",
    "result_unknown",
}
POLICY_SHA256 = hashlib.sha256(
    b"opsark-defense-requests/v1;private;198.18.241.0/28;target=.2:22422;"
    b"sources=.3,.5;management=.4;arm=120s;ttl=60000ms;ports=5;"
    b"success=deny;capacity=8;single-element;no-retry-after-intent"
).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def keys(value, expected) -> None:
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError("Invalid fields")


def identifier(value) -> None:
    if type(value) is not str or ID.fullmatch(value) is None:
        raise ValueError("Invalid identity")


def sha(value) -> None:
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise ValueError("Invalid digest")


def revision(value) -> None:
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        raise ValueError("Invalid revision")


def utc(value) -> datetime:
    if (
        type(value) is not str
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is None
    ):
        raise ValueError("Invalid UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def decode(raw: bytes, *, limit=4096):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("Invalid length")
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        raise ValueError("Invalid framing")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite number")),
        )
    except RecursionError:
        raise ValueError("JSON nesting limit exceeded") from None
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 16:
            raise ValueError("JSON nesting limit exceeded")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def approval(value) -> None:
    if value is None:
        return
    keys(
        value,
        ("approval_id", "purpose", "request_id", "manifest_sha256", "approved_at", "expires_at"),
    )
    identifier(value["approval_id"])
    identifier(value["request_id"])
    sha(value["manifest_sha256"])
    if value["purpose"] not in {"apply", "revoke"}:
        raise ValueError("Invalid purpose")
    utc(value["approved_at"])
    utc(value["expires_at"])


def parse(raw: bytes) -> dict:
    request = decode(raw)
    keys(request, ("v", "op", "request_id", "scope_sha256", "body"))
    if type(request["v"]) is not int or request["v"] != 1:
        raise ValueError("Invalid version")
    if type(request["op"]) is not str or request["op"] not in OPS:
        raise ValueError("Invalid operation")
    identifier(request["request_id"])
    sha(request["scope_sha256"])
    body = request["body"]
    op = request["op"]
    if op == "arm":
        keys(body, ("observation_grant_ref", "policy_sha256"))
        identifier(body["observation_grant_ref"])
        sha(body["policy_sha256"])
    elif op == "prepare":
        keys(
            body,
            (
                "cursor_id",
                "source_ref",
                "evidence_sha256",
                "policy_sha256",
                "mode",
                "mode_revision",
                "controller_grant_ref",
                "root_grant_ref",
            ),
        )
        for key in ("cursor_id", "source_ref", "controller_grant_ref", "root_grant_ref"):
            identifier(body[key])
        for key in ("policy_sha256", "evidence_sha256"):
            sha(body[key])
        revision(body["mode_revision"])
        if body["mode"] not in ("semi", "auto"):
            raise ValueError("Invalid mode")
    elif op in {"apply", "revoke"}:
        keys(body, ("manifest_sha256", "approval"))
        sha(body["manifest_sha256"])
        approval(body["approval"])
        if op == "revoke" and body["approval"] is None:
            raise ValueError("Revoke requires an exact declaration")
    elif op == "query":
        keys(body, ("kind",))
        if body["kind"] not in ("cursor", "action", "mode"):
            raise ValueError("Invalid kind")
    else:
        keys(body, ("mode", "mode_revision", "policy_sha256"))
        sha(body["policy_sha256"])
        revision(body["mode_revision"])
        if body["mode"] not in ("manual", "semi", "auto"):
            raise ValueError("Invalid mode")
    return request
