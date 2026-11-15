#!/usr/bin/env python3
"""Fixed private-fixture JSON dispatcher; deployment and authorization are explicit."""

import argparse
import copy
import hashlib
import os
import secrets
import signal
import stat
import sys
import time
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

if not __package__:
    sys.dont_write_bytecode = True
    entry = Path(__file__).absolute()
    for path in (entry, *entry.parents):
        info = path.lstat()
        expected = stat.S_ISREG if path == entry else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit("An administrator-owned request tool is required.")
    for name in (
        "request_protocol.py",
        "ssh_fixture.py",
        "ssh_fixture_evidence.py",
        "ssh_fixture_nft.py",
    ):
        info = entry.with_name(name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit("Administrator-owned request modules are required.")
    for package in (entry.parent / "__init__.py", entry.parent.parent / "__init__.py"):
        if package.exists():
            info = package.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise SystemExit("Administrator-owned request packages are required.")
    sys.path.insert(0, str(entry.parents[2]))

from deploy.defense import request_protocol as wire  # noqa: E402
from deploy.defense import ssh_fixture as fixture  # noqa: E402
from deploy.defense import ssh_fixture_evidence as evidence  # noqa: E402
from deploy.defense import ssh_fixture_nft as nft  # noqa: E402

ROOT = Path("/var/lib/opsark-ssh-defense-requests")
LEDGER = "requests.json"
MAX_LEDGER = 196_608
PRINCIPAL = "opsark-defense-control-v1"
SOURCES = {"fixture-a": "198.18.241.3", "fixture-b": "198.18.241.5"}
ARM_NS = 120_000_000_000
TTL_NS = 60_000_000_000
SLACK_NS = 100_000_000
NATIVE_ADMISSION_NS = 5_000_000_000
# add has three fixed nft commands, followed by our one exact observation (3s each).
NATIVE_BUDGET_NS = 4 * nft._TIMEOUT * 1_000_000_000
DISPATCH_SECONDS = 20


class Refused(ValueError):
    """A bounded public refusal reason."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _now():
    return datetime.now(UTC)


def _mono():
    return time.monotonic_ns()


def _boot():
    raw = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    if len(raw) != 37 or raw[-1:] != b"\n":
        raise ValueError("Untrusted boot identity")
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def _locked(*, initialize=False):
    """Open every fixed path component without following symlinks; never create on query."""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Root Linux deployment required")
    import fcntl

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for index, part in enumerate(ROOT.parts[1:]):
            parent = os.fstat(directory)
            if parent.st_uid != 0 or parent.st_mode & 0o022:
                raise ValueError("Untrusted directory")
            if initialize and index == len(ROOT.parts) - 2:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory)
                    os.fsync(directory)
                except FileExistsError:
                    raise ValueError(
                        "Request directory already exists; recovery is manual"
                    ) from None
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Untrusted request directory")
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory
    finally:
        os.close(directory)


def _save(directory, state):
    raw = wire.canonical(state) + b"\n"
    if len(raw) > MAX_LEDGER:
        raise ValueError("State limit exceeded")
    pending = ".pending-" + secrets.token_hex(16)
    descriptor = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,  # ty: ignore[unresolved-attribute] -- Linux-only
        0o600,
        dir_fd=directory,
    )
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        os.rename(pending, LEDGER, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(pending, dir_fd=directory)


def _deployment(value):
    wire.keys(value, ("v", "scope_sha256", "policy_sha256", "observation_grant", "defense_grants"))
    if type(value["v"]) is not int or value["v"] != 1:
        raise ValueError("Invalid deployment")
    wire.sha(value["scope_sha256"])
    if value["policy_sha256"] != wire.POLICY_SHA256:
        raise ValueError("Fixed policy required")
    observation = value["observation_grant"]
    wire.keys(observation, ("grant_ref", "not_before", "deadline_at"))
    wire.identifier(observation["grant_ref"])
    if wire.utc(observation["not_before"]) >= wire.utc(observation["deadline_at"]):
        raise ValueError("Invalid observation window")
    grants = value["defense_grants"]
    if type(grants) is not list or len(grants) > 8:
        raise ValueError("Invalid defense grants")
    seen = {observation["grant_ref"]}
    for grant in grants:
        wire.keys(
            grant,
            (
                "root_grant_ref",
                "controller_grant_ref",
                "mode",
                "mode_revision",
                "not_before",
                "deadline_at",
                "max_uses",
                "source_aliases",
            ),
        )
        for key in ("root_grant_ref", "controller_grant_ref"):
            wire.identifier(grant[key])
        if grant["root_grant_ref"] in seen:
            raise ValueError("Duplicate grant")
        seen.add(grant["root_grant_ref"])
        wire.revision(grant["mode_revision"])
        if grant["mode"] not in ("semi", "auto"):
            raise ValueError("Invalid grant mode")
        if type(grant["max_uses"]) is not int or not 1 <= grant["max_uses"] <= 8:
            raise ValueError("Invalid grant quota")
        if wire.utc(grant["not_before"]) >= wire.utc(grant["deadline_at"]):
            raise ValueError("Invalid grant window")
        aliases = grant["source_aliases"]
        if type(aliases) is not list or not aliases or len(aliases) != len(set(aliases)):
            raise ValueError("Invalid sources")
        if any(type(alias) is not str or alias not in SOURCES for alias in aliases):
            raise ValueError("Invalid sources")
    return value


def _initialize(directory, deployment, binding):
    _deployment(deployment)
    # Missing after initialization never has this meaning: this function is admin-only.
    try:
        fixture._read(directory, LEDGER, MAX_LEDGER)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("Already initialized")
    if nft.observe(profile="private") is not None:
        raise ValueError("Existing native action")
    state = {
        "v": 1,
        "principal": PRINCIPAL,
        "deployment": deployment,
        "boot_ref": _boot(),
        "binding": binding,
        "binding_ref": wire.digest(binding),
        "mode": {"mode": "manual", "mode_revision": 1},
        "records": {},
        "usage": [],
    }
    _save(directory, state)


def _read_ledger(directory):
    before = os.stat(LEDGER, dir_fd=directory, follow_symlinks=False)
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("Request file must be private")
    raw = fixture._read(directory, LEDGER, MAX_LEDGER)
    after = os.stat(LEDGER, dir_fd=directory, follow_symlinks=False)
    if fixture._file_identity(before) != fixture._file_identity(after):
        raise ValueError("Request file changed")
    return raw


def _load(directory):
    raw = _read_ledger(directory)
    state = wire.decode(raw, limit=MAX_LEDGER)
    wire.keys(
        state,
        (
            "v",
            "principal",
            "deployment",
            "boot_ref",
            "binding",
            "binding_ref",
            "mode",
            "records",
            "usage",
        ),
    )
    if state["v"] != 1 or type(state["v"]) is not int or state["principal"] != PRINCIPAL:
        raise ValueError("Invalid ledger")
    _deployment(state["deployment"])
    wire.sha(state["boot_ref"])
    binding = state["binding"]
    if type(binding) is not list or len(binding) != 8 or any(type(x) is not int for x in binding):
        raise ValueError("Invalid binding")
    if wire.digest(binding) != state["binding_ref"]:
        raise ValueError("Invalid binding hash")
    wire.keys(state["mode"], ("mode", "mode_revision"))
    wire.revision(state["mode"]["mode_revision"])
    if state["mode"]["mode"] not in ("manual", "semi", "auto"):
        raise ValueError("Invalid mode")
    records = state["records"]
    if type(records) is not dict or len(records) > 48:
        raise ValueError("Invalid request index")
    ids = set()
    attached = set()
    counts = {"cursor": 0, "action": 0, "mode": 0}
    for rid, record in records.items():
        wire.identifier(rid)
        wire.keys(record, ("kind", "request", "request_hash", "phase", "reason", "payload"))
        request = wire.parse(wire.canonical(record["request"]) + b"\n")
        if (
            request["request_id"] != rid
            or request["scope_sha256"] != state["deployment"]["scope_sha256"]
        ):
            raise ValueError("Invalid request scope")
        if record["request_hash"] != wire.digest(request):
            raise ValueError("Invalid request hash")
        kind = {"arm": "cursor", "prepare": "action", "mode_sync": "mode"}.get(request["op"])
        if kind is None or record["kind"] != kind:
            raise ValueError("Invalid request kind")
        counts[kind] += 1
        if type(record["reason"]) is not str or record["reason"] not in wire.REASONS:
            raise ValueError("Invalid public reason")
        if record["phase"] == "rejected":
            if record["payload"] is not None:
                raise ValueError("Invalid rejection")
            continue
        payload = record["payload"]
        if kind == "cursor":
            wire.keys(
                payload, ("cursor_id", "mark", "refs", "deadline_at", "deadline_ns", "attached_to")
            )
            wire.identifier(payload["cursor_id"])
            if payload["cursor_id"] in ids:
                raise ValueError("Duplicate cursor identity")
            ids.add(payload["cursor_id"])
            _valid_mark(payload["mark"])
            wire.keys(payload["mark"], ("dev", "ino", "offset", "prefix_sha256"))
            if any(type(payload["mark"][key]) is not int for key in ("dev", "ino", "offset")):
                raise ValueError("Invalid bookmark")
            wire.sha(payload["mark"]["prefix_sha256"])
            wire.keys(payload["refs"], SOURCES)
            for ref in payload["refs"].values():
                wire.identifier(ref)
                if ref in ids:
                    raise ValueError("Duplicate ref")
                ids.add(ref)
            if record["phase"] not in ("armed", "attached", "consumed"):
                raise ValueError("Invalid cursor phase")
            if payload["attached_to"] is not None:
                wire.identifier(payload["attached_to"])
            wire.utc(payload["deadline_at"])
        elif kind == "action":
            wire.keys(
                payload,
                (
                    "action_id",
                    "cursor_id",
                    "prepared_mark",
                    "manifest",
                    "deadline_ns",
                    "approval",
                    "apply_hash",
                    "expiry_bound",
                    "intent_bound",
                    "native_deadline_ns",
                    "revoke_hash",
                    "revoke_approval",
                ),
            )
            wire.identifier(payload["action_id"])
            wire.identifier(payload["cursor_id"])
            _valid_mark(payload["prepared_mark"])
            if payload["cursor_id"] in attached:
                raise ValueError("Duplicate cursor binding")
            attached.add(payload["cursor_id"])
            manifest = _manifest(
                state, request, payload["action_id"], payload["manifest"]["deadline_at"]
            )
            if payload["manifest"] != manifest:
                raise ValueError("Invalid manifest")
            if record["phase"] not in ("ready", "intent", "active", "revoke_intent", "revoked"):
                raise ValueError("Invalid action phase")
            phase = record["phase"]
            if phase == "ready" and any(
                payload[key] is not None
                for key in (
                    "approval",
                    "apply_hash",
                    "expiry_bound",
                    "intent_bound",
                    "native_deadline_ns",
                    "revoke_hash",
                    "revoke_approval",
                )
            ):
                raise ValueError("Ready record contains an intent")
            if phase != "ready" and (
                payload["apply_hash"] is None
                or payload["intent_bound"] is None
                or payload["native_deadline_ns"] is None
            ):
                raise ValueError("Missing intent identity")
            if phase in ("active", "revoke_intent", "revoked") and payload["expiry_bound"] is None:
                raise ValueError("Missing active expiry")
            if phase in ("revoke_intent", "revoked") and payload["revoke_hash"] is None:
                raise ValueError("Missing revoke identity")
            wire.approval(payload["approval"])
            wire.approval(payload["revoke_approval"])
            for key in ("expiry_bound", "intent_bound", "native_deadline_ns"):
                if payload[key] is not None and (type(payload[key]) is not int or payload[key] < 0):
                    raise ValueError("Invalid expiry")
            for key in ("apply_hash", "revoke_hash"):
                if payload[key] is not None:
                    wire.sha(payload[key])
            if payload["action_id"] in ids:
                raise ValueError("Duplicate identity")
            ids.add(payload["action_id"])
        elif record["phase"] != "synced" or payload is not None:
            raise ValueError("Invalid mode record")
        if kind != "mode" and (
            type(payload["deadline_ns"]) is not int or payload["deadline_ns"] < 0
        ):
            raise ValueError("Invalid monotonic deadline")
    if counts["cursor"] > 8 or counts["action"] > 8 or counts["mode"] > 32:
        raise ValueError("Request capacity exceeded")
    usage = state["usage"]
    if type(usage) is not list or len(usage) != len(set(usage)) or len(usage) > 8:
        raise ValueError("Invalid usage")
    for rid in usage:
        if (
            rid not in records
            or records[rid]["kind"] != "action"
            or records[rid]["phase"] in ("ready", "rejected")
        ):
            raise ValueError("Invalid usage tombstone")
    for rid, record in records.items():
        if (
            record["kind"] == "action"
            and record["phase"] not in ("ready", "rejected")
            and rid not in usage
        ):
            raise ValueError("Missing consumed quota")
    _crosslinks(state)
    if raw != wire.canonical(state) + b"\n":
        raise ValueError("Noncanonical ledger")
    return state


def _valid_mark(mark):
    wire.keys(mark, ("dev", "ino", "offset", "prefix_sha256"))
    if any(type(mark[key]) is not int or mark[key] < 0 for key in ("dev", "ino", "offset")):
        raise ValueError("Invalid bookmark")
    if mark["offset"] > evidence._MAX_BYTES:
        raise ValueError("Invalid bookmark bound")
    wire.sha(mark["prefix_sha256"])


def _crosslinks(state):
    records = state["records"]
    for rid, record in records.items():
        payload = record["payload"]
        if record["kind"] == "cursor" and payload is not None:
            target = payload["attached_to"]
            if (target is None) != (record["phase"] == "armed"):
                raise ValueError("Invalid cursor attachment phase")
            if target is not None and (
                target not in records
                or records[target]["kind"] != "action"
                or records[target]["payload"] is None
                or records[target]["payload"]["cursor_id"] != payload["cursor_id"]
            ):
                raise ValueError("Missing attached action")
        if record["kind"] != "action" or payload is None:
            continue
        cursor = _cursor(state, payload["cursor_id"])
        if cursor["payload"]["attached_to"] != rid:
            raise ValueError("Missing cursor attachment")
        body = record["request"]["body"]
        alias = next(
            (
                alias
                for alias, ref in cursor["payload"]["refs"].items()
                if ref == body["source_ref"]
            ),
            None,
        )
        grants = [
            g
            for g in state["deployment"]["defense_grants"]
            if g["root_grant_ref"] == body["root_grant_ref"]
        ]
        if len(grants) != 1 or alias not in grants[0]["source_aliases"]:
            raise ValueError("Invalid prepared authorization")
        grant = grants[0]
        if any(
            grant[key] != body[key] for key in ("mode", "mode_revision", "controller_grant_ref")
        ):
            raise ValueError("Changed prepared authorization")
        if body["policy_sha256"] != wire.POLICY_SHA256:
            raise ValueError("Changed prepared policy")
        if (
            wire.utc(payload["manifest"]["deadline_at"])
            > min(wire.utc(grant["deadline_at"]), wire.utc(cursor["payload"]["deadline_at"]))
            or payload["deadline_ns"] > cursor["payload"]["deadline_ns"]
        ):
            raise ValueError("Expanded prepared deadline")
        if _reserved(state, grant["root_grant_ref"]) > grant["max_uses"]:
            raise ValueError("Expanded quota")
        if record["phase"] != "ready" and (
            payload["native_deadline_ns"] > payload["deadline_ns"]
            or payload["intent_bound"]
            != payload["native_deadline_ns"] + NATIVE_BUDGET_NS + TTL_NS + SLACK_NS
        ):
            raise ValueError("Expanded native admission deadline")
        expected_cursor_phase = "attached" if record["phase"] == "ready" else "consumed"
        if cursor["phase"] != expected_cursor_phase:
            raise ValueError("Cursor and action phases disagree")
        for operation, hash_key, approval_key in (
            ("apply", "apply_hash", "approval"),
            ("revoke", "revoke_hash", "revoke_approval"),
        ):
            if payload[hash_key] is not None:
                exact = {
                    "v": 1,
                    "op": operation,
                    "request_id": rid,
                    "scope_sha256": state["deployment"]["scope_sha256"],
                    "body": {
                        "manifest_sha256": wire.digest(payload["manifest"]),
                        "approval": payload[approval_key],
                    },
                }
                if wire.digest(exact) != payload[hash_key]:
                    raise ValueError("Changed operation declaration")


def _manifest(state, request, action_id, deadline):
    wire.utc(deadline)
    body = request["body"]
    return {
        "v": 1,
        "request_id": request["request_id"],
        "action_id": action_id,
        "scope_sha256": request["scope_sha256"],
        "policy_sha256": wire.POLICY_SHA256,
        "cursor_id": body["cursor_id"],
        "source_ref": body["source_ref"],
        "evidence_sha256": body["evidence_sha256"],
        "boot_ref": state["boot_ref"],
        "binding_ref": state["binding_ref"],
        "mode": body["mode"],
        "mode_revision": body["mode_revision"],
        "controller_grant_ref": body["controller_grant_ref"],
        "root_grant_ref": body["root_grant_ref"],
        "ttl_ms": 60000,
        "deadline_at": deadline,
    }


def _assert_prefix(mark):
    dev, ino, data = evidence._read_log(fixture.ROOT / "sshd.log")
    if (
        (dev, ino) != (mark["dev"], mark["ino"])
        or len(data) < mark["offset"]
        or hashlib.sha256(data[: mark["offset"]]).hexdigest() != mark["prefix_sha256"]
    ):
        raise Refused("evidence_gap")


def _candidate(cursor, alias):
    import ipaddress

    payload = cursor["payload"]
    source = SOURCES[alias]
    count = 0
    classification = "gap"
    try:
        dev, ino, data = evidence._read_log(fixture.ROOT / "sshd.log")
        mark = payload["mark"]
        offset = mark["offset"]
        if (
            (dev, ino) != (mark["dev"], mark["ino"])
            or len(data) < offset
            or (offset and data[offset - 1 : offset] != b"\n")
            or hashlib.sha256(data[:offset]).hexdigest() != mark["prefix_sha256"]
        ):
            raise ValueError
        lines = data[offset:].split(b"\n")
        if len(lines) > evidence._MAX_LINES + 1 or lines[-1] != b"":
            raise ValueError
        ports = set()
        success = False
        for raw in lines[:-1]:
            line = raw.removesuffix(b"\r")
            if len(line) > evidence._MAX_LINE_BYTES or any(x < 32 or x > 126 for x in line):
                raise ValueError
            if line.startswith(b"Accepted key ") and b" found at " in line:
                continue
            if not line.startswith((b"Failed publickey for ", b"Accepted ")):
                continue
            event = evidence._AUTH.fullmatch(line)
            if event is None or int(event["port"]) > 65535:
                raise ValueError
            peer = ipaddress.ip_address(event["peer"].decode("ascii"))
            mapped = peer.ipv4_mapped if isinstance(peer, ipaddress.IPv6Address) else None
            if event["kind"] == b"Accepted":
                success |= str(peer) == source or (mapped is not None and str(mapped) == source)
            elif (
                str(peer) == source and event["user"] == evidence._USER and event["invalid"] is None
            ):
                ports.add(int(event["port"]))
        count = len(ports)
        classification = "success_seen" if success else "insufficient"
        if not success and count >= 5:
            digest = evidence.inspect(fixture.ROOT / "sshd.log", mark, source)
            return {
                "source_ref": payload["refs"][alias],
                "source_alias": alias,
                "classification": "eligible",
                "distinct_failure_ports": count,
                "evidence_sha256": digest,
            }
    except (OSError, ValueError, TypeError):
        classification = "gap"
        count = 0
    return {
        "source_ref": payload["refs"][alias],
        "source_alias": alias,
        "classification": classification,
        "distinct_failure_ports": count,
        "evidence_sha256": None,
    }


def _cursor(state, cursor_id):
    for record in state["records"].values():
        if (
            record["kind"] == "cursor"
            and record["payload"] is not None
            and record["payload"]["cursor_id"] == cursor_id
        ):
            return record
    raise Refused("authorization_denied")


def _bound(state, fixture_directory):
    if (
        _boot() != state["boot_ref"]
        or fixture._bound_listener(fixture_directory, "private") != state["binding"]
    ):
        raise Refused("binding_changed")


def _cursor_live(cursor):
    if _mono() >= cursor["payload"]["deadline_ns"] or _now() >= wire.utc(
        cursor["payload"]["deadline_at"]
    ):
        raise Refused("cursor_expired")


def _eligible(cursor, body):
    _cursor_live(cursor)
    alias = next(
        (key for key, ref in cursor["payload"]["refs"].items() if ref == body["source_ref"]), None
    )
    if alias is None:
        raise Refused("authorization_denied")
    candidate = _candidate(cursor, alias)
    if candidate["classification"] == "success_seen":
        raise Refused("success_seen")
    if (
        candidate["classification"] != "eligible"
        or candidate["evidence_sha256"] != body["evidence_sha256"]
    ):
        raise Refused("evidence_gap")
    return alias


def _grant(state, body, alias):
    if state["mode"] != {"mode": body["mode"], "mode_revision": body["mode_revision"]}:
        raise Refused("mode_unsynced")
    if body["mode"] == "manual":
        raise Refused("authorization_denied")
    for grant in state["deployment"]["defense_grants"]:
        if grant["root_grant_ref"] == body["root_grant_ref"]:
            if (
                any(
                    grant[key] != body[key]
                    for key in ("controller_grant_ref", "mode", "mode_revision")
                )
                or alias not in grant["source_aliases"]
                or not wire.utc(grant["not_before"]) <= _now() < wire.utc(grant["deadline_at"])
            ):
                break
            return grant
    raise Refused("authorization_denied")


def _reserved(state, root_grant):
    return sum(
        record["kind"] == "action"
        and record["payload"] is not None
        and record["request"]["body"]["root_grant_ref"] == root_grant
        for record in state["records"].values()
    )


def _action_observation(record, live):
    payload = record["payload"]
    phase = record["phase"]
    if phase == "revoked":
        if live is not None:
            return "unknown", None, "result_unknown"
        return "revoked", None, "ok"
    if phase == "ready":
        expired = _mono() >= payload["deadline_ns"] or _now() >= wire.utc(
            payload["manifest"]["deadline_at"]
        )
        return ("ready_expired", None, "cursor_expired") if expired else ("ready", None, "ok")
    if phase == "revoke_intent":
        return "unknown", None, "result_unknown"
    bound = payload["expiry_bound"] if phase == "active" else payload["intent_bound"]
    # The caller checks the source against the cursor's fixed alias.
    if (
        live is not None
        and bound is not None
        and _mono() < bound
        and live[2] == payload["action_id"]
        and 1 <= live[1] <= 60000
        and live[1] * 1_000_000 <= max(0, bound - _mono()) + SLACK_NS
    ):
        return "active", live[1], "ok"
    if phase == "active" and live is None and bound is not None and _mono() >= bound:
        return "expired", None, "ok"
    return "unknown", None, "result_unknown"


def _live_for(state, record):
    live = nft.observe(profile="private")
    if live is not None:
        cursor = _cursor(state, record["payload"]["cursor_id"])
        alias = next(
            (
                key
                for key, ref in cursor["payload"]["refs"].items()
                if ref == record["request"]["body"]["source_ref"]
            ),
            None,
        )
        if alias is None or live[0] != SOURCES[alias]:
            return ("unknown", None, "result_unknown")
    return _action_observation(record, live)


def _unfinished(state):
    live = nft.observe(profile="private")
    if live is not None:
        return True
    for record in state["records"].values():
        if record["kind"] != "action" or record["payload"] is None:
            continue
        status, _, _ = _action_observation(record, None)
        if status not in ("expired", "revoked", "ready_expired"):
            return True
    return False


def _reply(
    state, request, record=None, *, status=None, reason=None, remaining=None, candidates=None
):
    mode = state["mode"]
    payload = record["payload"] if record else None
    result = {
        "v": 1,
        "op": request["op"],
        "request_id": request["request_id"],
        "scope_sha256": request["scope_sha256"],
        "policy_sha256": wire.POLICY_SHA256,
        "boot_ref": state["boot_ref"],
        "binding_ref": state["binding_ref"],
        "mode": mode["mode"],
        "mode_revision": mode["mode_revision"],
        "state": status or "not_found",
        "action_id": None,
        "cursor_id": None,
        "manifest_sha256": None,
        "deadline_at": None,
        "remaining_ms": remaining,
        "reason_code": reason or "ok",
        "candidates": candidates or [],
    }
    if record is None:
        return result
    if payload is not None and record["kind"] == "action":
        manifest = payload["manifest"]
        result.update(
            action_id=payload["action_id"],
            cursor_id=payload["cursor_id"],
            manifest_sha256=wire.digest(manifest),
            deadline_at=manifest["deadline_at"],
            mode=manifest["mode"],
            mode_revision=manifest["mode_revision"],
        )
    elif payload is not None and record["kind"] == "cursor":
        result.update(cursor_id=payload["cursor_id"], deadline_at=payload["deadline_at"])
    if status is not None:
        return result
    if record["phase"] == "rejected":
        result.update(state="rejected", reason_code=record["reason"])
    elif record["kind"] == "action":
        current, ttl, code = _live_for(state, record)
        result.update(state=current, remaining_ms=ttl, reason_code=code)
    elif record["kind"] == "mode":
        body = record["request"]["body"]
        same = mode == {"mode": body["mode"], "mode_revision": body["mode_revision"]}
        result.update(
            state="synced" if same else "rejected", reason_code="ok" if same else "mode_unsynced"
        )
    else:
        try:
            _cursor_live(record)
        except Refused:
            result.update(state="expired", reason_code="cursor_expired")
        else:
            result["state"] = record["phase"]
            if request["op"] == "query" and record["phase"] != "consumed":
                result["candidates"] = [_candidate(record, alias) for alias in SOURCES]
                if any(item["classification"] == "gap" for item in result["candidates"]):
                    result.update(state="invalid", reason_code="evidence_gap")
    return result


def _new_record(request, kind, payload, phase, reason="ok"):
    return {
        "kind": kind,
        "request": request,
        "request_hash": wire.digest(request),
        "phase": phase,
        "reason": reason,
        "payload": payload,
    }


def _approve(request, record):
    approval = request["body"]["approval"]
    manifest = record["payload"]["manifest"]
    if request["op"] == "apply" and manifest["mode"] == "auto":
        if approval is not None:
            raise Refused("authorization_denied")
        return
    # This verifies the trusted controller's exact declaration, not a human-proof signature.
    if approval is None or any(
        (
            approval["purpose"] != request["op"],
            approval["request_id"] != request["request_id"],
            approval["manifest_sha256"] != wire.digest(manifest),
        )
    ):
        raise Refused("authorization_denied")
    approved = wire.utc(approval["approved_at"])
    expires = wire.utc(approval["expires_at"])
    if not approved <= _now() < expires or not timedelta(0) < expires - approved <= timedelta(
        seconds=120
    ):
        raise Refused("authorization_denied")
    if request["op"] == "apply" and expires > wire.utc(manifest["deadline_at"]):
        raise Refused("authorization_denied")


def _gate(state, record, fixture_directory):
    _bound(state, fixture_directory)
    payload = record["payload"]
    body = record["request"]["body"]
    if payload["manifest"] != _manifest(
        state, record["request"], payload["action_id"], payload["manifest"]["deadline_at"]
    ):
        raise Refused("policy_changed")
    cursor = _cursor(state, payload["cursor_id"])
    if cursor["payload"]["attached_to"] != record["request"]["request_id"]:
        raise Refused("request_conflict")
    _assert_prefix(payload["prepared_mark"])
    alias = _eligible(cursor, body)
    grant = _grant(state, body, alias)
    if _reserved(state, grant["root_grant_ref"]) > grant["max_uses"]:
        raise Refused("quota_exhausted")
    if _mono() >= payload["deadline_ns"] or _now() >= wire.utc(payload["manifest"]["deadline_at"]):
        raise Refused("cursor_expired")
    return alias


def _fresh_ids(state, count, rid):
    used = set(state["records"]) | {rid}
    for record in state["records"].values():
        payload = record["payload"]
        if payload is not None:
            used.add(payload["cursor_id"])
            if record["kind"] == "cursor":
                used.update(payload["refs"].values())
            else:
                used.add(payload["action_id"])
    result = []
    for _ in range(count):
        identifier = secrets.token_hex(16)
        if identifier in used:
            raise Refused("request_conflict")
        used.add(identifier)
        result.append(identifier)
    return result


def _create(state, request, kind, fixture_directory):
    body = request["body"]
    if kind == "mode":
        current = state["mode"]
        proposed = {"mode": body["mode"], "mode_revision": body["mode_revision"]}
        if body["mode_revision"] < current["mode_revision"] or (
            body["mode_revision"] == current["mode_revision"] and proposed != current
        ):
            raise Refused("mode_unsynced")
        state["mode"] = proposed
        return _new_record(request, kind, None, "synced")
    if kind == "cursor":
        grant = state["deployment"]["observation_grant"]
        if body["observation_grant_ref"] != grant["grant_ref"]:
            raise Refused("authorization_denied")
        now = _now()
        if not wire.utc(grant["not_before"]) <= now or now + timedelta(seconds=120) > wire.utc(
            grant["deadline_at"]
        ):
            raise Refused("authorization_denied")
        if any(
            r["kind"] == "cursor" and r["payload"] is not None for r in state["records"].values()
        ):
            raise Refused("quota_exhausted")
        cursor_id, first_ref, second_ref = _fresh_ids(state, 3, request["request_id"])
        return _new_record(
            request,
            kind,
            {
                "cursor_id": cursor_id,
                "mark": evidence.bookmark(fixture.ROOT / "sshd.log"),
                "refs": dict(zip(SOURCES, (first_ref, second_ref), strict=True)),
                "deadline_at": wire.timestamp(now + timedelta(seconds=120)),
                "deadline_ns": _mono() + ARM_NS,
                "attached_to": None,
            },
            "armed",
        )
    cursor = _cursor(state, body["cursor_id"])
    if cursor["payload"]["attached_to"] is not None:
        raise Refused("request_conflict")
    alias = _eligible(cursor, body)
    grant = _grant(state, body, alias)
    if _reserved(state, grant["root_grant_ref"]) >= grant["max_uses"]:
        raise Refused("quota_exhausted")
    if _unfinished(state):
        raise Refused("capacity_full")
    deadline = min(wire.utc(cursor["payload"]["deadline_at"]), wire.utc(grant["deadline_at"]))
    deadline_ns = min(
        cursor["payload"]["deadline_ns"], _mono() + int((deadline - _now()).total_seconds() * 1e9)
    )
    action_id = _fresh_ids(state, 1, request["request_id"])[0]
    record = _new_record(
        request,
        kind,
        {
            "action_id": action_id,
            "cursor_id": body["cursor_id"],
            "prepared_mark": evidence.bookmark(fixture.ROOT / "sshd.log"),
            "manifest": _manifest(state, request, action_id, wire.timestamp(deadline)),
            "deadline_ns": deadline_ns,
            "approval": None,
            "apply_hash": None,
            "expiry_bound": None,
            "intent_bound": None,
            "native_deadline_ns": None,
            "revoke_hash": None,
            "revoke_approval": None,
        },
        "ready",
    )
    cursor["payload"]["attached_to"] = request["request_id"]
    cursor["phase"] = "attached"
    _gate(state, record, fixture_directory)
    return record


def _apply(directory, state, request, record, fixture_directory):
    payload = record["payload"]
    if request["body"]["manifest_sha256"] != wire.digest(payload["manifest"]):
        raise Refused("request_conflict")
    request_hash = wire.digest(request)
    if payload["apply_hash"] is not None and payload["apply_hash"] != request_hash:
        raise Refused("request_conflict")
    if record["phase"] != "ready":
        return _reply(state, request, record)
    _approve(request, record)
    alias = _gate(state, record, fixture_directory)
    if nft.observe(profile="private") is not None:
        raise Refused("capacity_full")
    # A different unknown intent always blocks admission, including an empty kernel set.
    for other in state["records"].values():
        if other is not record and other["kind"] == "action" and other["payload"] is not None:
            status, _, _ = _action_observation(other, None)
            if status not in ("expired", "revoked", "ready_expired"):
                raise Refused("capacity_full")
    record["phase"] = "intent"
    native_deadline = min(payload["deadline_ns"], _mono() + NATIVE_ADMISSION_NS)
    payload.update(
        approval=request["body"]["approval"],
        apply_hash=request_hash,
        native_deadline_ns=native_deadline,
        intent_bound=native_deadline + NATIVE_BUDGET_NS + TTL_NS + SLACK_NS,
    )
    state["usage"].append(request["request_id"])
    cursor = _cursor(state, payload["cursor_id"])
    cursor["phase"] = "consumed"
    _save(directory, state)
    # Everything below an intent is at-most-once: a crash/error is never retried as add.
    if nft.observe(profile="private") is not None:
        raise Refused("result_unknown")
    _approve(request, record)
    _gate(state, record, fixture_directory)
    if _mono() >= payload["native_deadline_ns"]:
        raise Refused("result_unknown")
    nft.add(SOURCES[alias], payload["action_id"], profile="private")
    live = nft.observe(profile="private")
    if live is None or (live[0], live[2]) != (SOURCES[alias], payload["action_id"]):
        raise Refused("result_unknown")
    current, _, _ = _action_observation(record, live)
    if current != "active":
        raise Refused("result_unknown")
    payload["expiry_bound"] = min(payload["intent_bound"], _mono() + live[1] * 1_000_000 + SLACK_NS)
    record["phase"] = "active"
    _save(directory, state)
    return _reply(state, request, record)


def _revoke(directory, state, request, record):
    payload = record["payload"]
    if request["body"]["manifest_sha256"] != wire.digest(payload["manifest"]):
        raise Refused("request_conflict")
    request_hash = wire.digest(request)
    if payload["revoke_hash"] is not None:
        if payload["revoke_hash"] != request_hash:
            raise Refused("request_conflict")
        return _reply(state, request, record)
    if record["phase"] != "active":
        return _reply(state, request, record)
    if state["mode"]["mode"] == "manual":
        raise Refused("authorization_denied")
    _approve(request, record)
    current, _, _ = _live_for(state, record)
    if current != "active":
        return _reply(state, request, record)
    cursor = _cursor(state, payload["cursor_id"])
    alias = next(
        key
        for key, ref in cursor["payload"]["refs"].items()
        if ref == record["request"]["body"]["source_ref"]
    )
    record["phase"] = "revoke_intent"
    payload.update(revoke_hash=request_hash, revoke_approval=request["body"]["approval"])
    _save(directory, state)
    nft.remove(SOURCES[alias], payload["action_id"], profile="private")
    if nft.observe(profile="private") is not None:
        raise Refused("result_unknown")
    record["phase"] = "revoked"
    _save(directory, state)
    return _reply(state, request, record)


def dispatch(directory, fixture_directory, request, role):
    """Execute parsed input. Roles are fixed argv selected by a trusted administrator."""
    state = _load(directory)
    rid, op = request["request_id"], request["op"]
    record = state["records"].get(rid)
    try:
        if request["scope_sha256"] != state["deployment"]["scope_sha256"]:
            raise Refused("authorization_denied")
        if op != "query" and not (
            (op == "arm" and role == "observe") or (op != "arm" and role == "control")
        ):
            raise Refused("authorization_denied")
        _bound(state, fixture_directory)
        if op == "query":
            if record is None:
                return _reply(state, request, status="not_found", reason="not_found")
            if record["kind"] != request["body"]["kind"]:
                raise Refused("request_conflict")
            return _reply(state, request, record)
        if op in ("arm", "prepare", "mode_sync"):
            kind = {"arm": "cursor", "prepare": "action", "mode_sync": "mode"}[op]
            if record is not None:
                if record["request_hash"] != wire.digest(request):
                    raise Refused("request_conflict")
                return _reply(state, request, record)
            if request["body"]["policy_sha256"] != wire.POLICY_SHA256:
                raise Refused("policy_changed")
            capacity = 32 if kind == "mode" else 8
            if sum(r["kind"] == kind for r in state["records"].values()) >= capacity:
                raise Refused("capacity_full")
            original = copy.deepcopy(state)
            try:
                record = _create(state, request, kind, fixture_directory)
                _bound(state, fixture_directory)
            except Refused as refused:
                state = original
                record = _new_record(request, kind, None, "rejected", refused.code)
            state["records"][rid] = record
            _save(directory, state)
            return _reply(state, request, record)
        if record is None:
            return _reply(state, request, status="not_found", reason="not_found")
        if record["kind"] != "action":
            raise Refused("request_conflict")
        if record["phase"] == "rejected":
            return _reply(state, request, record)
        if op == "apply":
            return _apply(directory, state, request, record, fixture_directory)
        return _revoke(directory, state, request, record)
    except Refused as refused:
        uncertain = record is not None and (
            record["phase"] in ("intent", "revoke_intent")
            or (op == "query" and refused.code == "binding_changed")
        )
        return _reply(
            state,
            request,
            record,
            status="unknown" if uncertain else "rejected",
            reason=refused.code
            if refused.code == "binding_changed"
            else ("result_unknown" if uncertain else refused.code),
        )


def _timed_out(signum, frame):
    raise TimeoutError("Fixed dispatcher deadline elapsed")


@contextmanager
def _deadline():
    if sys.platform != "linux":
        raise ValueError("Linux dispatcher deadline required")
    previous = signal.signal(signal.SIGALRM, _timed_out)
    signal.setitimer(signal.ITIMER_REAL, DISPATCH_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    roles = parser.add_mutually_exclusive_group()
    roles.add_argument("--control", action="store_true")
    roles.add_argument("--observe", action="store_true")
    roles.add_argument("--initialize", action="store_true")
    args = parser.parse_args(argv)
    try:
        with _deadline():
            # Read the entire bounded stream, not just readline(): extra stdin is a protocol error.
            raw = sys.stdin.buffer.read(4097)
            request = wire.decode(raw) if args.initialize else wire.parse(raw)
            with _locked(initialize=args.initialize) as directory, fixture._locked() as target:
                binding = fixture._bound_listener(target, "private")
                if args.initialize:
                    _initialize(directory, request, binding)
                    print('{"v":1,"state":"initialized"}')
                    return 0
                role = "control" if args.control else "observe" if args.observe else "readonly"
                result = dispatch(directory, target, request, role)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, IndexError, UnicodeError):
        print("The isolated defense request could not be confirmed.", file=sys.stderr)
        return 1
    print(wire.canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
