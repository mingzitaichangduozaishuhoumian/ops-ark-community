"""Check the isolated SSH defense executor with an injected kernel and ledger."""

import importlib
import json
import sys
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

DIRECTORY = 23
SOURCE = "127.0.0.2"
OTHER_SOURCE = "127.0.0.4"
IDENTIFIER = "1" * 32
OTHER_IDENTIFIER = "2" * 32
EVIDENCE = "3" * 64
BINDING = [11, 12, 13, 14, 15]
BOOKMARK = {"dev": 1, "ino": 2, "offset": 3, "prefix_sha256": "4" * 64}


class Interrupted(BaseException):
    """Simulate process loss without unwinding through the CLI error handling."""


@pytest.fixture
def fixture(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    executor = importlib.import_module("deploy.defense.ssh_fixture")
    clock = 1_000_000_000
    grant = {
        "source": SOURCE,
        "mark": BOOKMARK,
        "expires": clock + executor.GRANT_NS,
        "phase": "ready",
    }
    lab = SimpleNamespace(
        executor=executor,
        now=clock,
        live=None,
        ledger={"binding": BINDING, "grants": {IDENTIFIER: grant}},
        saved=[],
        evidence_reads=[],
        bookmarks=[],
        mutations=[],
    )

    def save(directory, ledger):
        assert directory == DIRECTORY
        lab.saved.append(deepcopy(ledger))

    def listener(directory):
        assert directory == DIRECTORY
        return BINDING

    def inspect(path, mark, source):
        assert path == executor.ROOT / "sshd.log"
        assert mark == BOOKMARK and source == SOURCE
        lab.evidence_reads.append(source)
        return EVIDENCE

    def bookmark(path):
        assert path == executor.ROOT / "sshd.log"
        lab.bookmarks.append(path)
        return BOOKMARK

    def add(source, identifier):
        stored = lab.saved[-1]["grants"][identifier]
        assert (stored["phase"], stored["evidence_sha256"]) == ("intent", EVIDENCE)
        lab.mutations.append(("add", source, identifier))
        lab.live = (source, 60_000, identifier)

    def remove(source, identifier):
        assert lab.saved[-1]["grants"][identifier]["phase"] == "revoke_intent"
        lab.mutations.append(("remove", source, identifier))
        lab.live = None

    monkeypatch.setattr(executor, "time", SimpleNamespace(monotonic_ns=lambda: lab.now))
    monkeypatch.setattr(executor, "_save", save)
    monkeypatch.setattr(executor, "_listener", listener)
    monkeypatch.setattr(executor.ssh_fixture_evidence, "inspect", inspect)
    monkeypatch.setattr(executor.ssh_fixture_evidence, "bookmark", bookmark)
    monkeypatch.setattr(executor.ssh_fixture_nft, "observe", lambda: lab.live)
    monkeypatch.setattr(executor.ssh_fixture_nft, "add", add)
    monkeypatch.setattr(executor.ssh_fixture_nft, "remove", remove)
    return lab


def invoke(lab, operation):
    return getattr(lab.executor, operation)(
        DIRECTORY, lab.ledger, IDENTIFIER, lab.ledger["grants"][IDENTIFIER]
    )


def test_applied_intent_is_durable_before_insertion_and_retry_only_queries(fixture):
    result = invoke(fixture, "_apply")
    assert result == {"action_id": IDENTIFIER, "status": "active", "remaining_ms": 60_000}
    assert [row["grants"][IDENTIFIER]["phase"] for row in fixture.saved] == ["intent", "active"]
    reads = fixture.evidence_reads.copy()
    fixture.ledger = deepcopy(fixture.saved[-1])
    fixture.live = (SOURCE, 42_000, IDENTIFIER)
    assert invoke(fixture, "_apply") == result | {"remaining_ms": 42_000}
    assert fixture.mutations == [("add", SOURCE, IDENTIFIER)]
    assert fixture.evidence_reads == reads and len(fixture.saved) == 2


@pytest.mark.parametrize("kernel_committed", [False, True])
def test_lost_insert_reply_queries_and_requires_exact_kernel_identity(
    fixture, monkeypatch, kernel_committed
):
    add = fixture.executor.ssh_fixture_nft.add

    def interrupt(source, identifier):
        if kernel_committed:
            add(source, identifier)
        else:
            assert fixture.saved[-1]["grants"][identifier]["phase"] == "intent"
            fixture.mutations.append(("add", source, identifier))
        raise Interrupted

    monkeypatch.setattr(fixture.executor.ssh_fixture_nft, "add", interrupt)
    with pytest.raises(Interrupted):
        invoke(fixture, "_apply")
    reads = fixture.evidence_reads.copy()
    fixture.ledger = deepcopy(fixture.saved[-1])
    exact = fixture.live
    for wrong in ((OTHER_SOURCE, 10_000, IDENTIFIER), (SOURCE, 10_000, OTHER_IDENTIFIER), None):
        fixture.live = wrong
        assert invoke(fixture, "_apply")["status"] == "unknown"
        assert len(fixture.saved) == 1
    fixture.live = exact
    result = invoke(fixture, "_observe")
    if kernel_committed:
        assert result == {"action_id": IDENTIFIER, "status": "active", "remaining_ms": 60_000}
        assert fixture.saved[-1]["grants"][IDENTIFIER]["phase"] == "active"
    else:
        fixture.now += fixture.executor.GRANT_NS
        assert result["status"] == invoke(fixture, "_apply")["status"] == "unknown"
        assert len(fixture.saved) == 1
    assert fixture.mutations == [("add", SOURCE, IDENTIFIER)]
    assert fixture.evidence_reads == reads


def test_kernel_timeout_cannot_rearm_the_same_intent(fixture):
    invoke(fixture, "_apply")
    fixture.ledger = deepcopy(fixture.saved[-1])
    fixture.live = None
    expiry = fixture.ledger["grants"][IDENTIFIER]["expiry_bound"]
    fixture.now = expiry - 1
    assert invoke(fixture, "_observe")["status"] == "unknown"
    fixture.now = expiry
    assert invoke(fixture, "_apply")["status"] == "expired"
    fixture.now += fixture.executor.GRANT_NS
    assert invoke(fixture, "_apply")["status"] == "expired"
    assert fixture.mutations == [("add", SOURCE, IDENTIFIER)] and len(fixture.saved) == 2


def test_evidence_change_after_intent_prevents_insertion_and_retry(fixture, monkeypatch):
    reads = iter((EVIDENCE, "9" * 64))
    monkeypatch.setattr(fixture.executor.ssh_fixture_evidence, "inspect", lambda *_: next(reads))
    with pytest.raises(ValueError):
        invoke(fixture, "_apply")
    fixture.ledger = deepcopy(fixture.saved[-1])
    assert invoke(fixture, "_apply")["status"] == "unknown"
    assert fixture.saved[-1]["grants"][IDENTIFIER]["phase"] == "intent"
    assert not fixture.mutations


@pytest.mark.parametrize("phase", ["intent", "revoke_intent", "active"])
def test_unresolved_prior_action_fences_even_a_different_grant(fixture, phase):
    fixture.ledger["grants"][OTHER_IDENTIFIER] = {
        "source": OTHER_SOURCE,
        "phase": phase,
        "expiry_bound": fixture.now + 10_000,
    }
    with pytest.raises(ValueError):
        fixture.executor._grant(DIRECTORY, fixture.ledger, OTHER_SOURCE)
    with pytest.raises(ValueError):
        invoke(fixture, "_apply")
    assert not fixture.bookmarks and not fixture.evidence_reads and not fixture.mutations


@pytest.mark.parametrize("gateway", [None, "ipv4", "ipv6"])
def test_private_profile_requires_an_exact_connected_route(fixture, monkeypatch, gateway):
    executor = fixture.executor
    native = {
        "/proc/net/dev": "headers\nheaders\nlo: stats\neth0: stats\n",
        "/proc/net/route": (
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00F112C6 00000000 0001 0 0 0 F0FFFFFF 0 0 0\n"
        ),
        "/proc/net/ipv6_route": f"{'0' * 32} 00 fields lo\n",
    }
    if gateway == "ipv4":
        native["/proc/net/route"] += "eth0 00000000 01F112C6 0003 0 0 0 00000000 0 0 0\n"
    elif gateway == "ipv6":
        native["/proc/net/ipv6_route"] += f"{'0' * 32} 00 fields eth0\n"
    monkeypatch.setattr(
        executor, "Path", lambda path: SimpleNamespace(read_text=lambda **_kwargs: native[path])
    )
    monkeypatch.setitem(
        sys.modules,
        "fcntl",
        SimpleNamespace(ioctl=lambda *_args: bytes(20) + executor.socket.inet_aton("198.18.241.2")),
    )
    monkeypatch.setattr(
        executor.socket, "socket", lambda *_args: nullcontext(SimpleNamespace(fileno=lambda: 23))
    )
    monkeypatch.setattr(executor.socket, "if_nametoindex", lambda _interface: 7)
    if gateway is None:
        assert executor._verify_interface(executor.PROFILES["private"]) == 7
    else:
        with pytest.raises(ValueError):
            executor._verify_interface(executor.PROFILES["private"])


@pytest.mark.parametrize("source", ["127.0.0.1", "127.0.0.3", "::ffff:127.0.0.2"])
def test_grant_refuses_protected_or_unregistered_sources(fixture, source):
    with pytest.raises(ValueError):
        fixture.executor._grant(DIRECTORY, fixture.ledger, source)
    assert not fixture.bookmarks and not fixture.saved and not fixture.mutations


def test_grant_pins_a_new_private_bookmark_before_becoming_ready(fixture, monkeypatch):
    monkeypatch.setattr(
        fixture.executor, "secrets", SimpleNamespace(token_hex=lambda size: OTHER_IDENTIFIER)
    )
    result = fixture.executor._grant(DIRECTORY, fixture.ledger, OTHER_SOURCE)
    assert result == {"grant_id": OTHER_IDENTIFIER, "status": "ready"}
    assert fixture.saved[-1]["grants"][OTHER_IDENTIFIER] == {
        "source": OTHER_SOURCE,
        "phase": "ready",
        "mark": BOOKMARK,
        "expires": fixture.now + fixture.executor.GRANT_NS,
    }
    assert len(fixture.bookmarks) == 1 and not fixture.mutations


@pytest.mark.parametrize("blocker", ["kernel_active", "grant_expired"])
def test_apply_refuses_before_collecting_evidence_when_not_eligible(fixture, blocker):
    if blocker == "kernel_active":
        fixture.live = (OTHER_SOURCE, 10_000, OTHER_IDENTIFIER)
        with pytest.raises(ValueError):
            fixture.executor._grant(DIRECTORY, fixture.ledger, OTHER_SOURCE)
    else:
        fixture.now = fixture.ledger["grants"][IDENTIFIER]["expires"]
    with pytest.raises(ValueError):
        invoke(fixture, "_apply")
    assert not fixture.bookmarks and not fixture.evidence_reads and not fixture.saved
    assert not fixture.mutations


def test_revoke_persists_independent_intent_and_never_mutates_twice(fixture):
    invoke(fixture, "_apply")
    result = invoke(fixture, "_revoke")
    assert result == {"action_id": IDENTIFIER, "status": "revoked", "remaining_ms": None}
    assert [row["grants"][IDENTIFIER]["phase"] for row in fixture.saved] == [
        "intent",
        "active",
        "revoke_intent",
        "revoked",
    ]
    fixture.ledger = deepcopy(fixture.saved[-1])
    assert invoke(fixture, "_revoke") == invoke(fixture, "_apply") == result
    assert fixture.mutations == [("add", SOURCE, IDENTIFIER), ("remove", SOURCE, IDENTIFIER)]


def test_lost_revocation_with_kernel_element_still_live_stays_query_only(fixture, monkeypatch):
    invoke(fixture, "_apply")

    def interrupt(source, identifier):
        assert fixture.saved[-1]["grants"][identifier]["phase"] == "revoke_intent"
        fixture.mutations.append(("remove", source, identifier))
        raise Interrupted

    monkeypatch.setattr(fixture.executor.ssh_fixture_nft, "remove", interrupt)
    with pytest.raises(Interrupted):
        invoke(fixture, "_revoke")
    fixture.ledger = deepcopy(fixture.saved[-1])
    assert fixture.live is not None
    assert invoke(fixture, "_revoke")["status"] == "unknown"
    assert invoke(fixture, "_apply")["status"] == "unknown"
    assert fixture.mutations == [("add", SOURCE, IDENTIFIER), ("remove", SOURCE, IDENTIFIER)]


@pytest.mark.parametrize(
    ("phase", "live_action", "status", "remaining"),
    [
        ("intent", IDENTIFIER, "active", 39_502),
        ("intent", OTHER_IDENTIFIER, "unknown", None),
        ("active", None, "expired", None),
        ("revoke_intent", IDENTIFIER, "unknown", None),
        ("revoked", None, "revoked", None),
    ],
)
def test_private_readonly_status_uses_exact_ledger_without_reconciliation_writes(
    fixture, monkeypatch, capsys, phase, live_action, status, remaining
):
    executor = fixture.executor
    source = "198.18.241.3"
    record = fixture.ledger["grants"][IDENTIFIER]
    record.update(source=source, phase=phase, expiry_bound=fixture.now)
    before = deepcopy(fixture.ledger)
    reads = []

    def listener(directory, *, profile):
        assert (directory, profile) == (DIRECTORY, "private")
        reads.append("listener")
        return BINDING

    def ledger(directory, filename, limit):
        assert (directory, filename, limit) == (DIRECTORY, executor.LEDGER, executor.MAX_LEDGER)
        reads.append("ledger")
        return executor._json(fixture.ledger) + b"\n"

    def observe(*, profile):
        assert profile == "private"
        reads.append("nft")
        return (source, 39_502, live_action) if live_action else None

    def write(*_args, **_kwargs):
        pytest.fail("the read-only status action attempted a write")

    monkeypatch.setattr(executor, "_locked", lambda: nullcontext(DIRECTORY))
    monkeypatch.setattr(executor, "_listener", listener)
    monkeypatch.setattr(executor, "_read", ledger)
    monkeypatch.setattr(executor, "_save", write)
    monkeypatch.setattr(executor.ssh_fixture_nft, "observe", observe)
    for operation in ("initialize", "add", "remove"):
        monkeypatch.setattr(executor.ssh_fixture_nft, operation, write)
    monkeypatch.setattr(
        sys,
        "argv",
        ["ssh_fixture", "--profile", "private", "status-readonly", "--action-id", IDENTIFIER],
    )
    assert executor.main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "action_id": IDENTIFIER,
        "status": status,
        "remaining_ms": remaining,
    }
    assert captured.err == ""
    assert fixture.ledger == before
    assert reads == ["listener", "ledger"] + ([] if phase == "revoked" else ["nft"])

    fixture.ledger["binding"] = [*BINDING[:-1], BINDING[-1] + 1]
    reads.clear()
    assert executor.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "" and IDENTIFIER not in captured.err
    assert reads == ["listener", "ledger"]
