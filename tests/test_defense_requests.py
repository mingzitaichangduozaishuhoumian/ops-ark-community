"""Request-state tests use real atomic files with portable fd-relative adapters.

The adapters replace only Linux ownership/dirfd/listener/nft boundaries, never the
request state machine, wire parser, manifest, durable serializer, or evidence parser.
"""

import io
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.defense import request_protocol as wire
from deploy.defense import ssh_requests as root

SCOPE = "a" * 64
OBS = "1" * 32
GRANT = "2" * 32
CONTROL = "3" * 32
ARM = "4" * 32
MODE = "5" * 32
RID = "6" * 32


def request(op, rid=RID, **body):
    return wire.parse(
        wire.canonical(
            {
                "v": 1,
                "op": op,
                "request_id": rid,
                "scope_sha256": SCOPE,
                "body": body,
            }
        )
        + b"\n"
    )


def failures(count=5, *, source="198.18.241.3", same_port=False):
    return b"".join(
        (
            f"Failed publickey for opsark-ssh-lab from {source} "
            f"port {31000 if same_port else 31000 + index} ssh2\n"
        ).encode()
        for index in range(count)
    )


class Crash(RuntimeError):
    pass


@pytest.fixture
def lab(tmp_path, monkeypatch):
    actual_os = os
    monkeypatch.setattr(root, "_deadline", nullcontext)
    writes = []
    directory = 987654

    def absolute(name, dir_fd=None):
        return tmp_path / name if dir_fd == directory else name

    def open_at(name, flags, mode=0o777, *, dir_fd=None):
        return actual_os.open(absolute(name, dir_fd), flags, mode)

    def rename_at(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        return actual_os.replace(absolute(src, src_dir_fd), absolute(dst, dst_dir_fd))

    adapter = SimpleNamespace(**{name: getattr(actual_os, name) for name in dir(actual_os)})
    adapter.O_NOFOLLOW = getattr(actual_os, "O_NOFOLLOW", 0)
    adapter.open = open_at
    adapter.rename = rename_at
    adapter.unlink = lambda name, dir_fd=None: actual_os.unlink(absolute(name, dir_fd))
    adapter.fsync = lambda descriptor: (
        writes.append("directory-fsync") if descriptor == directory else actual_os.fsync(descriptor)
    )
    monkeypatch.setattr(root, "os", adapter)
    monkeypatch.setattr(
        root.fixture, "_read", lambda fd, name, limit: (tmp_path / name).read_bytes()
    )
    monkeypatch.setattr(root, "_read_ledger", lambda fd: (tmp_path / root.LEDGER).read_bytes())
    now = [datetime(2026, 11, 5, 12, 0, tzinfo=UTC)]
    mono = [10_000_000_000]
    boot = ["b" * 64]
    binding = list(range(8))
    monkeypatch.setattr(root, "_now", lambda: now[0])
    monkeypatch.setattr(root, "_mono", lambda: mono[0])
    monkeypatch.setattr(root, "_boot", lambda: boot[0])
    monkeypatch.setattr(root.fixture, "_bound_listener", lambda fd, profile: binding[:])
    log: dict[str, Any] = {"data": b"", "dev": 1, "ino": 2}

    def read_log(path):
        data = log["data"]
        if len(data) > 65536 or (data and not data.endswith(b"\n")):
            raise ValueError
        return log["dev"], log["ino"], data

    monkeypatch.setattr(root.evidence, "_read_log", read_log)
    kernel: dict[str, Any] = {"live": None, "adds": 0, "removes": 0, "fail": None}

    def observe(*, profile):
        assert profile == "private"
        live = kernel["live"]
        if live is None:
            return None
        source, expires, action = live
        remaining = (expires - mono[0]) // 1_000_000
        return (source, remaining, action) if remaining > 0 else None

    def add(source, action, *, profile):
        kernel["adds"] += 1
        if kernel["fail"] == "before-add":
            raise Crash
        assert observe(profile=profile) is None
        kernel["live"] = source, mono[0] + root.TTL_NS, action
        if kernel["fail"] == "after-add":
            raise Crash

    def remove(source, action, *, profile):
        kernel["removes"] += 1
        if kernel["fail"] == "before-remove":
            raise Crash
        assert observe(profile=profile)[::2] == (source, action)
        kernel["live"] = None
        if kernel["fail"] == "after-remove":
            raise Crash

    monkeypatch.setattr(root.nft, "observe", observe)
    monkeypatch.setattr(root.nft, "add", add)
    monkeypatch.setattr(root.nft, "remove", remove)
    deployment = {
        "v": 1,
        "scope_sha256": SCOPE,
        "policy_sha256": wire.POLICY_SHA256,
        "observation_grant": {
            "grant_ref": OBS,
            "not_before": wire.timestamp(now[0] - timedelta(seconds=1)),
            "deadline_at": wire.timestamp(now[0] + timedelta(hours=1)),
        },
        "defense_grants": [
            {
                "root_grant_ref": GRANT,
                "controller_grant_ref": CONTROL,
                "mode": "semi",
                "mode_revision": 2,
                "not_before": wire.timestamp(now[0] - timedelta(seconds=1)),
                "deadline_at": wire.timestamp(now[0] + timedelta(hours=1)),
                "max_uses": 1,
                "source_aliases": ["fixture-a", "fixture-b"],
            }
        ],
    }
    root._initialize(directory, deployment, binding)
    mutex = threading.Lock()

    def call(req, role="control"):
        with mutex:
            return root.dispatch(directory, 123, req, role)

    def advance(seconds):
        now[0] += timedelta(seconds=seconds)
        mono[0] += int(seconds * 1_000_000_000)

    def query(rid=RID, kind="action"):
        return call(request("query", rid, kind=kind), "readonly")

    def arm():
        return call(
            request("arm", ARM, observation_grant_ref=OBS, policy_sha256=wire.POLICY_SHA256),
            "observe",
        )

    def prepare():
        call(
            request(
                "mode_sync", MODE, mode="semi", mode_revision=2, policy_sha256=wire.POLICY_SHA256
            )
        )
        cursor = arm()
        log["data"] += failures()
        candidate = query(ARM, "cursor")["candidates"][0]
        req = request(
            "prepare",
            cursor_id=cursor["cursor_id"],
            source_ref=candidate["source_ref"],
            evidence_sha256=candidate["evidence_sha256"],
            policy_sha256=wire.POLICY_SHA256,
            mode="semi",
            mode_revision=2,
            controller_grant_ref=CONTROL,
            root_grant_ref=GRANT,
        )
        return req, call(req)

    def approved(reply, op="apply"):
        return request(
            op,
            manifest_sha256=reply["manifest_sha256"],
            approval={
                "approval_id": "7" * 32,
                "purpose": op,
                "request_id": RID,
                "manifest_sha256": reply["manifest_sha256"],
                "approved_at": wire.timestamp(now[0]),
                "expires_at": wire.timestamp(now[0] + timedelta(seconds=20)),
            },
        )

    return SimpleNamespace(
        call=call,
        advance=advance,
        query=query,
        arm=arm,
        prepare=prepare,
        approved=approved,
        directory=directory,
        path=tmp_path / root.LEDGER,
        log=log,
        kernel=kernel,
        mono=mono,
        now=now,
        boot=boot,
        binding=binding,
        writes=writes,
        deployment=deployment,
    )


def test_ready_mapping_is_durable_idempotent_and_query_has_zero_writes(lab):
    req, ready = lab.prepare()
    assert ready["state"] == "ready"
    snapshot = lab.path.read_bytes()
    before = len(lab.writes)
    assert lab.call(req) == ready
    assert lab.query()["action_id"] == ready["action_id"]
    assert lab.path.read_bytes() == snapshot
    assert len(lab.writes) == before
    assert lab.kernel["adds"] == 0
    manifest = root._load(lab.directory)["records"][RID]["payload"]["manifest"]
    assert wire.digest(manifest) == ready["manifest_sha256"]
    assert manifest["request_id"] == RID and manifest["ttl_ms"] == 60000


def test_same_rid_different_request_and_cursor_contention(lab):
    req, ready = lab.prepare()
    changed = {**req, "body": {**req["body"], "source_ref": "f" * 32}}
    assert lab.call(changed)["reason_code"] == "request_conflict"
    rival = {**req, "request_id": "8" * 32}
    assert lab.call(rival)["reason_code"] == "request_conflict"
    assert lab.query()["action_id"] == ready["action_id"]
    assert lab.kernel["adds"] == 0


def test_concurrent_duplicate_prepare_and_apply_are_one_mapping_one_add(lab):
    req, ready = lab.prepare()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lab.call, [req] * 8))
    assert {reply["action_id"] for reply in results} == {ready["action_id"]}
    apply = lab.approved(ready)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lab.call, [apply] * 8))
    assert all(reply["state"] == "active" for reply in results)
    assert lab.kernel["adds"] == 1
    assert root._load(lab.directory)["usage"] == [RID]


def test_readonly_role_cannot_create_and_missing_query_never_creates(lab):
    snapshot = lab.path.read_bytes()
    req = request("arm", ARM, observation_grant_ref=OBS, policy_sha256=wire.POLICY_SHA256)
    assert lab.call(req, "readonly")["reason_code"] == "authorization_denied"
    assert lab.call(req, "control")["reason_code"] == "authorization_denied"
    assert lab.query()["state"] == "not_found"
    assert lab.path.read_bytes() == snapshot


def test_arm_cannot_be_repeated_to_extend_or_replace_bookmark(lab):
    first = lab.arm()
    state = lab.path.read_bytes()
    lab.advance(10)
    lab.log["data"] = failures()
    assert lab.arm() == first
    assert lab.path.read_bytes() == state
    other = request("arm", "9" * 32, observation_grant_ref=OBS, policy_sha256=wire.POLICY_SHA256)
    assert lab.call(other, "observe")["reason_code"] == "quota_exhausted"


@pytest.mark.parametrize(
    "data,classification,count",
    [
        (failures(4), "insufficient", 4),
        (failures(5, same_port=True), "insufficient", 1),
        (failures(), "eligible", 5),
        (failures(source="198.18.241.4"), "insufficient", 0),
        (
            failures() + b"Accepted publickey for other from 198.18.241.3 port 42000 ssh2\n",
            "success_seen",
            5,
        ),
        (
            failures() + b"Accepted publickey for other from ::ffff:198.18.241.3 port 42000 ssh2\n",
            "success_seen",
            5,
        ),
        (failures() + b"Accepted nonsense\n", "gap", 0),
        (b"X" * 2049 + b"\n", "gap", 0),
        (b"line\n" * 257, "gap", 0),
        (failures()[:-1], "gap", 0),
        (b"X" * 65536 + b"\n", "gap", 0),
    ],
    ids=[
        "four",
        "one-port",
        "five",
        "management",
        "success",
        "mapped-success",
        "malformed",
        "long-line",
        "too-many-lines",
        "partial",
        "too-large",
    ],
)
def test_candidates_use_real_bounded_evidence_parser(lab, data, classification, count):
    lab.arm()
    lab.log["data"] = data
    result = lab.query(ARM, "cursor")["candidates"][0]
    assert result["classification"] == classification
    assert result["distinct_failure_ports"] == count
    assert (result["evidence_sha256"] is not None) == (classification == "eligible")


def test_pre_arm_alerts_and_missing_cursor_cannot_prepare(lab):
    lab.log["data"] = failures()
    lab.arm()
    assert lab.query(ARM, "cursor")["candidates"][0]["classification"] == "insufficient"
    req = request(
        "prepare",
        cursor_id="e" * 32,
        source_ref="d" * 32,
        evidence_sha256="c" * 64,
        policy_sha256=wire.POLICY_SHA256,
        mode="semi",
        mode_revision=2,
        controller_grant_ref=CONTROL,
        root_grant_ref=GRANT,
    )
    assert lab.call(req)["state"] == "rejected"
    assert lab.kernel["adds"] == 0


@pytest.mark.parametrize(
    "mutation", ["inode", "truncate", "rewrite", "success", "boot", "listener"]
)
def test_recheck_before_apply_rejects_evidence_or_binding_change(lab, mutation):
    lab.log["data"] = b"prefix\n"
    _, ready = lab.prepare()
    if mutation == "inode":
        lab.log["ino"] += 1
    elif mutation == "truncate":
        lab.log["data"] = b""
    elif mutation == "rewrite":
        lab.log["data"] = b"PREFIX\n" + failures()
    elif mutation == "success":
        lab.log["data"] += b"Accepted publickey for any from 198.18.241.3 port 33000 ssh2\n"
    elif mutation == "boot":
        lab.boot[0] = "f" * 64
    else:
        lab.binding[4] += 1
    assert lab.call(lab.approved(ready))["state"] == "rejected"
    assert lab.kernel["adds"] == 0


def test_manual_revision_change_blocks_prepared_apply_and_revoke(lab):
    _, ready = lab.prepare()
    mode = request(
        "mode_sync", "8" * 32, mode="manual", mode_revision=3, policy_sha256=wire.POLICY_SHA256
    )
    assert lab.call(mode)["state"] == "synced"
    assert lab.call(lab.approved(ready))["reason_code"] == "mode_unsynced"
    assert lab.kernel["adds"] == 0
    assert lab.query(MODE, "mode")["state"] == "rejected"


def test_expired_ready_and_old_source_ref_do_not_execute(lab):
    _, ready = lab.prepare()
    lab.advance(121)
    assert lab.query()["state"] == "ready_expired"
    assert lab.call(lab.approved(ready))["state"] == "rejected"
    assert lab.query(ARM, "cursor")["state"] == "expired"
    assert lab.kernel["adds"] == 0


def test_exact_approval_required_and_revoke_has_independent_purpose(lab):
    _, ready = lab.prepare()
    valid = lab.approved(ready)
    for changed in [
        None,
        {**valid["body"]["approval"], "purpose": "revoke"},
        {**valid["body"]["approval"], "request_id": "f" * 32},
        {**valid["body"]["approval"], "manifest_sha256": "f" * 64},
        {
            **valid["body"]["approval"],
            "expires_at": wire.timestamp(lab.now[0] + timedelta(seconds=121)),
        },
    ]:
        invalid = {**valid, "body": {**valid["body"], "approval": changed}}
        assert lab.call(invalid)["state"] == "rejected"
    assert lab.call(valid)["state"] == "active"
    assert lab.call({**valid, "op": "revoke"})["state"] == "rejected"
    revoked = lab.call(lab.approved(ready, "revoke"))
    assert revoked["state"] == "revoked"
    assert lab.kernel["removes"] == 1
    assert lab.call(valid)["state"] == "revoked"
    assert lab.kernel["adds"] == 1


def test_kernel_ttl_declines_and_terminal_cannot_resurrect(lab):
    _, ready = lab.prepare()
    apply = lab.approved(ready)
    assert lab.call(apply)["remaining_ms"] == 60000
    lab.advance(10)
    assert lab.query()["remaining_ms"] == 50000
    lab.kernel["live"] = "198.18.241.3", lab.mono[0] + root.TTL_NS, ready["action_id"]
    assert lab.query()["state"] == "unknown"
    lab.advance(61)
    assert lab.query()["state"] == "expired"
    lab.kernel["live"] = "198.18.241.3", lab.mono[0] + root.TTL_NS, ready["action_id"]
    assert lab.query()["state"] == "unknown"
    assert lab.call(apply)["state"] == "unknown"
    assert lab.kernel["adds"] == 1


@pytest.mark.parametrize(
    "point,expected",
    [
        ("intent-before-commit", "ready"),
        ("intent-after-commit", "unknown"),
        ("before-add", "unknown"),
        ("after-add", "active"),
        ("active-before-commit", "active"),
        ("active-after-commit", "active"),
    ],
)
def test_apply_crash_cuts_reload_original_rid_never_reissue(lab, monkeypatch, point, expected):
    _, ready = lab.prepare()
    apply = lab.approved(ready)
    save = root._save
    saves = [0]

    def crash_save(directory, state):
        saves[0] += 1
        trigger = (saves[0] == 1 and point.startswith("intent-")) or (
            saves[0] == 2 and point.startswith("active-")
        )
        if trigger and "before-commit" in point:
            raise Crash
        save(directory, state)
        if trigger and "after-commit" in point:
            raise Crash

    monkeypatch.setattr(root, "_save", crash_save)
    lab.kernel["fail"] = point
    with pytest.raises(Crash):
        lab.call(apply)
    before = lab.path.read_bytes()
    assert lab.query()["state"] == expected
    assert lab.path.read_bytes() == before
    adds = lab.kernel["adds"]
    if expected != "ready":
        lab.call(apply)
        assert lab.kernel["adds"] == adds
        assert root._load(lab.directory)["usage"] == [RID]
        lab.advance(61)
        persisted = root._load(lab.directory)["records"][RID]["phase"]
        assert lab.query()["state"] == ("expired" if persisted == "active" else "unknown")


@pytest.mark.parametrize("after_commit", [False, True])
def test_prepare_commit_or_ack_loss_has_no_half_index(lab, monkeypatch, after_commit):
    # Prepare all evidence first, then fault only the single mapping commit.
    req, ready = lab.prepare()
    state = root._load(lab.directory)
    del state["records"][RID]
    state["records"][ARM]["phase"] = "armed"
    state["records"][ARM]["payload"]["attached_to"] = None
    root._save(lab.directory, state)
    save = root._save

    def fail(directory, value):
        if after_commit:
            save(directory, value)
        raise Crash

    monkeypatch.setattr(root, "_save", fail)
    with pytest.raises(Crash):
        lab.call(req)
    result = lab.query()
    assert result["state"] == ("ready" if after_commit else "not_found")
    if after_commit:
        again = lab.call(req)
        assert again["action_id"] == result["action_id"]
        assert again["deadline_at"] == ready["deadline_at"]
    assert lab.kernel["adds"] == 0


@pytest.mark.parametrize("point", ["before-remove", "after-remove", "revoked-before-commit"])
def test_revoke_unknown_empty_set_is_not_false_confirmed(lab, monkeypatch, point):
    _, ready = lab.prepare()
    lab.call(lab.approved(ready))
    revoke = lab.approved(ready, "revoke")
    save = root._save

    def fail(directory, state):
        if point == "revoked-before-commit" and state["records"][RID]["phase"] == "revoked":
            raise Crash
        save(directory, state)

    monkeypatch.setattr(root, "_save", fail)
    lab.kernel["fail"] = point
    with pytest.raises(Crash):
        lab.call(revoke)
    assert lab.query()["state"] == "unknown"
    removes = lab.kernel["removes"]
    assert lab.call(revoke)["state"] == "unknown"
    assert lab.kernel["removes"] == removes
    lab.advance(61)
    assert lab.query()["state"] == "unknown"


@pytest.mark.parametrize(
    "problem", ["missing", "corrupt", "noncanonical", "missing-usage", "wrong-scope"]
)
def test_ledger_loss_or_corruption_never_initializes_or_resets_usage(lab, problem):
    _, ready = lab.prepare()
    lab.call(lab.approved(ready))
    state = root._load(lab.directory)
    if problem == "missing":
        lab.path.unlink()
    elif problem == "corrupt":
        lab.path.write_bytes(b"broken\n")
    elif problem == "noncanonical":
        lab.path.write_bytes(b" " + lab.path.read_bytes())
    elif problem == "missing-usage":
        state["usage"] = []
        root._save(lab.directory, state)
    else:
        state["records"][RID]["request"]["scope_sha256"] = "f" * 64
        root._save(lab.directory, state)
    with pytest.raises((ValueError, OSError)):
        lab.query()
    assert lab.kernel["adds"] == 1


def test_explicit_initialization_does_not_overwrite_existing_ledger(lab):
    before = lab.path.read_bytes()
    with pytest.raises(ValueError, match="Already initialized"):
        root._initialize(lab.directory, lab.deployment, lab.binding)
    assert before == lab.path.read_bytes()


def test_auto_requires_matching_predeployed_root_and_controller_grant_and_revision(lab):
    lab.call(
        request("mode_sync", MODE, mode="auto", mode_revision=2, policy_sha256=wire.POLICY_SHA256)
    )
    cursor = lab.arm()
    lab.log["data"] = failures()
    candidate = lab.query(ARM, "cursor")["candidates"][0]
    req = request(
        "prepare",
        cursor_id=cursor["cursor_id"],
        source_ref=candidate["source_ref"],
        evidence_sha256=candidate["evidence_sha256"],
        policy_sha256=wire.POLICY_SHA256,
        mode="auto",
        mode_revision=2,
        controller_grant_ref=CONTROL,
        root_grant_ref=GRANT,
    )
    assert lab.call(req)["reason_code"] == "authorization_denied"
    assert lab.kernel["adds"] == 0


@pytest.mark.parametrize(
    "raw",
    [
        b'{"v":1,"v":1}\n',
        b"{}\n{}\n",
        b"{}",
        b"{}\r\n",
        b"{}\n ",
        b'{"v":NaN}\n',
        b'{"v":Infinity}\n',
        b"\xff\n",
        b" " * 4096 + b"\n",
    ],
    ids=[
        "duplicate",
        "extra-line",
        "truncated",
        "crlf",
        "trailing",
        "nan",
        "infinity",
        "invalid-utf8",
        "oversize",
    ],
)
def test_wire_rejects_duplicate_invalid_and_overlong_input(raw):
    with pytest.raises((ValueError, UnicodeError)):
        wire.parse(raw)


@pytest.mark.parametrize(
    "change",
    [
        {"v": True},
        {"v": 1.0},
        {"unknown": "field"},
        {"op": ["query"]},
        {"body": {"kind": "action", "command": "anything"}},
    ],
)
def test_wire_exact_keys_types(change):
    original = request("query", kind="action")
    with pytest.raises((ValueError, TypeError)):
        wire.parse(wire.canonical({**original, **change}) + b"\n")


def test_cli_uses_dispatch_and_rejects_extra_lines_without_writes(lab, monkeypatch, capsys):
    from contextlib import nullcontext

    monkeypatch.setattr(root, "_locked", lambda **kwargs: nullcontext(lab.directory))
    monkeypatch.setattr(root.fixture, "_locked", lambda: nullcontext(123))
    raw = wire.canonical(request("query", kind="action")) + b"\n"
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    before = lab.path.read_bytes()
    assert root.main([]) == 0
    reply = wire.decode(capsys.readouterr().out.encode())
    assert reply["state"] == "not_found"
    assert set(reply) == {
        "v",
        "op",
        "request_id",
        "scope_sha256",
        "policy_sha256",
        "boot_ref",
        "binding_ref",
        "mode",
        "mode_revision",
        "state",
        "action_id",
        "cursor_id",
        "manifest_sha256",
        "deadline_at",
        "remaining_ms",
        "reason_code",
        "candidates",
    }
    assert "198.18" not in str(reply) and "/" not in str(reply)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw + b"{}\n")))
    assert root.main([]) == 1
    assert lab.path.read_bytes() == before


def test_arm_ack_loss_is_recovered_only_by_original_rid(lab, monkeypatch):
    save = root._save

    def lost_ack(directory, state):
        save(directory, state)
        raise Crash

    monkeypatch.setattr(root, "_save", lost_ack)
    with pytest.raises(Crash):
        lab.arm()
    recovered = lab.query(ARM, "cursor")
    assert recovered["state"] == "armed"
    assert recovered["cursor_id"] is not None
    assert lab.arm()["cursor_id"] == recovered["cursor_id"]


def test_same_mode_revision_is_idempotent_and_lower_or_different_is_rejected(lab):
    req = request("mode_sync", MODE, mode="semi", mode_revision=2, policy_sha256=wire.POLICY_SHA256)
    assert lab.call(req)["state"] == "synced"
    before = lab.path.read_bytes()
    assert lab.call(req)["state"] == "synced"
    assert lab.path.read_bytes() == before
    other = request(
        "mode_sync", "f" * 32, mode="auto", mode_revision=2, policy_sha256=wire.POLICY_SHA256
    )
    assert lab.call(other)["reason_code"] == "mode_unsynced"
    lower = request(
        "mode_sync", "e" * 32, mode="manual", mode_revision=1, policy_sha256=wire.POLICY_SHA256
    )
    assert lab.call(lower)["reason_code"] == "mode_unsynced"


def test_auto_positive_still_needs_predeployed_grants_and_null_approval(lab):
    # Represent a different explicit administrator deployment, before arming or mode sync.
    state = root._load(lab.directory)
    state["deployment"]["defense_grants"][0]["mode"] = "auto"
    root._save(lab.directory, state)
    lab.call(
        request("mode_sync", MODE, mode="auto", mode_revision=2, policy_sha256=wire.POLICY_SHA256)
    )
    cursor = lab.arm()
    lab.log["data"] = failures()
    candidate = lab.query(ARM, "cursor")["candidates"][0]
    body = dict(
        cursor_id=cursor["cursor_id"],
        source_ref=candidate["source_ref"],
        evidence_sha256=candidate["evidence_sha256"],
        policy_sha256=wire.POLICY_SHA256,
        mode="auto",
        mode_revision=2,
        controller_grant_ref=CONTROL,
        root_grant_ref=GRANT,
    )
    for field in ("controller_grant_ref", "root_grant_ref"):
        invalid = request(
            "prepare",
            "c" * 32 if field.startswith("controller") else "d" * 32,
            **{**body, field: "f" * 32},
        )
        assert lab.call(invalid)["reason_code"] == "authorization_denied"
    ready = lab.call(request("prepare", **body))
    assert ready["state"] == "ready"
    assert lab.call(lab.approved(ready))["state"] == "rejected"
    apply = request("apply", manifest_sha256=ready["manifest_sha256"], approval=None)
    assert lab.call(apply)["state"] == "active"
    assert lab.kernel["adds"] == 1


def test_manual_mode_blocks_independent_revoke(lab):
    _, ready = lab.prepare()
    lab.call(lab.approved(ready))
    lab.call(
        request(
            "mode_sync", "f" * 32, mode="manual", mode_revision=3, policy_sha256=wire.POLICY_SHA256
        )
    )
    assert lab.call(lab.approved(ready, "revoke"))["reason_code"] == "authorization_denied"
    assert lab.kernel["removes"] == 0


def test_prepare_pins_entire_tail_not_just_five_failure_hashes(lab):
    _, ready = lab.prepare()
    # Native evidence digest intentionally covers five first failures. The request
    # layer additionally pins the entire observed prefix before allowing apply.
    state = root._load(lab.directory)
    mark = state["records"][RID]["payload"]["prepared_mark"]
    assert mark["offset"] == len(lab.log["data"])
    lab.log["data"] = failures(4)
    assert lab.call(lab.approved(ready))["state"] == "rejected"
    assert lab.kernel["adds"] == 0


def test_deep_json_is_a_bounded_parse_error():
    with pytest.raises(ValueError):
        wire.decode(b"[" * 1500 + b"0" + b"]" * 1500 + b"\n")


def test_boot_change_query_is_unknown_and_does_not_rewrite_ledger(lab):
    lab.prepare()
    before = lab.path.read_bytes()
    lab.boot[0] = "f" * 64
    response = lab.query()
    assert response["state"] == "unknown"
    assert response["reason_code"] == "binding_changed"
    assert lab.path.read_bytes() == before


def test_rejected_request_tombstones_exhaust_capacity_without_reclamation(lab):
    body = dict(
        cursor_id="e" * 32,
        source_ref="d" * 32,
        evidence_sha256="c" * 64,
        policy_sha256=wire.POLICY_SHA256,
        mode="semi",
        mode_revision=2,
        controller_grant_ref=CONTROL,
        root_grant_ref=GRANT,
    )
    for index in range(8):
        rid = f"{index + 100:032x}"
        assert lab.call(request("prepare", rid, **body))["state"] == "rejected"
    before = lab.path.read_bytes()
    ninth = lab.call(request("prepare", "f" * 32, **body))
    assert ninth["reason_code"] == "capacity_full"
    assert lab.path.read_bytes() == before
    assert len(root._load(lab.directory)["records"]) == 8


def test_revoke_null_is_a_protocol_error():
    with pytest.raises(ValueError):
        request("revoke", manifest_sha256="a" * 64, approval=None)


def test_consumed_cursor_no_longer_projects_live_source_refs(lab):
    _, ready = lab.prepare()
    lab.call(lab.approved(ready))
    reply = lab.query(ARM, "cursor")
    assert reply["state"] == "consumed"
    assert reply["candidates"] == []


@pytest.mark.parametrize("element", ["original", "other-id", "other-source"])
def test_revoked_with_any_live_element_is_unknown_without_writes(lab, element):
    _, ready = lab.prepare()
    lab.call(lab.approved(ready))
    lab.call(lab.approved(ready, "revoke"))
    source = "198.18.241.5" if element == "other-source" else "198.18.241.3"
    action = "f" * 32 if element == "other-id" else ready["action_id"]
    lab.kernel["live"] = source, lab.mono[0] + root.TTL_NS, action
    before = lab.path.read_bytes()
    assert lab.query()["state"] == "unknown"
    assert lab.path.read_bytes() == before
    assert lab.call(lab.approved(ready, "revoke"))["state"] == "unknown"
    assert lab.kernel["adds"] == 1
    assert lab.kernel["removes"] == 1


def test_arm_same_batch_random_collision_rejects_without_cursor_mapping(lab, monkeypatch):
    monkeypatch.setattr(root.secrets, "token_hex", lambda count: "d" * 32)
    result = lab.arm()
    assert result["state"] == "rejected"
    assert result["reason_code"] == "request_conflict"
    assert result["cursor_id"] is None
    assert root._load(lab.directory)["records"][ARM]["payload"] is None


@pytest.mark.parametrize("collision", ["cursor_id", "source_ref", "rid"])
def test_prepare_random_collision_rejects_without_action_or_cursor_attachment(
    lab, monkeypatch, collision
):
    lab.call(
        request("mode_sync", MODE, mode="semi", mode_revision=2, policy_sha256=wire.POLICY_SHA256)
    )
    cursor = lab.arm()
    lab.log["data"] = failures()
    candidate = lab.query(ARM, "cursor")["candidates"][0]
    existing = {"cursor_id": cursor["cursor_id"], "source_ref": candidate["source_ref"], "rid": RID}
    monkeypatch.setattr(root.secrets, "token_hex", lambda count: existing[collision])
    req = request(
        "prepare",
        cursor_id=cursor["cursor_id"],
        source_ref=candidate["source_ref"],
        evidence_sha256=candidate["evidence_sha256"],
        policy_sha256=wire.POLICY_SHA256,
        mode="semi",
        mode_revision=2,
        controller_grant_ref=CONTROL,
        root_grant_ref=GRANT,
    )
    result = lab.call(req)
    assert result["state"] == "rejected"
    assert result["reason_code"] == "request_conflict"
    assert result["action_id"] is None
    state = root._load(lab.directory)
    assert state["records"][ARM]["payload"]["attached_to"] is None
    assert state["records"][RID]["payload"] is None
    assert lab.kernel["adds"] == 0


def test_allocator_rejects_existing_action_id(lab, monkeypatch):
    _, ready = lab.prepare()
    state = root._load(lab.directory)
    monkeypatch.setattr(root.secrets, "token_hex", lambda count: ready["action_id"])
    with pytest.raises(root.Refused, match="request_conflict"):
        root._fresh_ids(state, 1, "f" * 32)


def test_normal_native_queue_delay_keeps_full_kernel_ttl_then_tightens_bound(lab, monkeypatch):
    _, ready = lab.prepare()
    add = root.nft.add

    def delayed_add(*args, **kwargs):
        lab.advance(0.3)
        return add(*args, **kwargs)

    monkeypatch.setattr(root.nft, "add", delayed_add)
    result = lab.call(lab.approved(ready))
    assert result["state"] == "active"
    assert result["remaining_ms"] == 60000
    payload = root._load(lab.directory)["records"][RID]["payload"]
    assert payload["expiry_bound"] == lab.mono[0] + root.TTL_NS + root.SLACK_NS
    assert payload["native_deadline_ns"] <= payload["deadline_ns"]
    lab.advance(1)
    assert lab.query()["remaining_ms"] == 59000
    assert lab.kernel["adds"] == 1


def test_native_admission_deadline_after_intent_stops_without_add_or_refund(lab, monkeypatch):
    _, ready = lab.prepare()
    save = root._save

    def delayed_commit(directory, state):
        save(directory, state)
        if state["records"][RID]["phase"] == "intent":
            lab.advance(6)

    monkeypatch.setattr(root, "_save", delayed_commit)
    apply = lab.approved(ready)
    assert lab.call(apply)["state"] == "unknown"
    assert lab.kernel["adds"] == 0
    assert root._load(lab.directory)["usage"] == [RID]
    assert lab.call(apply)["state"] == "unknown"
    assert lab.kernel["adds"] == 0


@pytest.mark.parametrize("change", ["success", "mode", "listener"])
def test_second_gate_after_durable_intent_rechecks_every_mutable_condition(
    lab, monkeypatch, change
):
    _, ready = lab.prepare()
    save = root._save

    def change_after_intent(directory, state):
        save(directory, state)
        if state["records"][RID]["phase"] != "intent":
            return
        if change == "success":
            lab.log["data"] += b"Accepted publickey for any from 198.18.241.3 port 33000 ssh2\n"
        elif change == "mode":
            state["mode"] = {"mode": "manual", "mode_revision": 3}
        else:
            lab.binding[4] += 1

    monkeypatch.setattr(root, "_save", change_after_intent)
    assert lab.call(lab.approved(ready))["state"] == "unknown"
    assert lab.kernel["adds"] == 0
    assert root._load(lab.directory)["usage"] == [RID]


def test_approval_exact_expiration_is_denied(lab):
    _, ready = lab.prepare()
    apply = lab.approved(ready)
    lab.advance(20)
    assert lab.call(apply)["state"] == "rejected"
    assert lab.kernel["adds"] == 0


def test_linux_dispatch_deadline_has_fixed_budget_and_restores_timer(monkeypatch):
    calls = []
    handlers = {}

    def signal_handler(number, handler):
        calls.append(("signal", number, handler))
        previous = handlers.get(number, "previous-handler")
        handlers[number] = handler
        return previous

    fake_signal = SimpleNamespace(
        SIGALRM=14,
        ITIMER_REAL=0,
        signal=signal_handler,
        setitimer=lambda kind, seconds: calls.append(("timer", kind, seconds)),
    )
    monkeypatch.setattr(root, "signal", fake_signal)
    monkeypatch.setattr(root, "sys", SimpleNamespace(platform="linux"))
    with pytest.raises(TimeoutError), root._deadline():
        handlers[14](14, None)
    assert ("timer", 0, 20) in calls
    assert ("timer", 0, 0) in calls
    assert handlers[14] == "previous-handler"


def test_cli_input_timeout_returns_only_fixed_error_and_does_not_write(lab, monkeypatch, capsys):
    class TimedInput:
        def read(self, limit):
            assert limit == 4097
            raise TimeoutError("untrusted diagnostic must not escape")

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=TimedInput()))
    before = lab.path.read_bytes()
    assert root.main([]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "The isolated defense request could not be confirmed.\n"
    assert lab.path.read_bytes() == before
