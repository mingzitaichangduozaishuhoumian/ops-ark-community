"""Production ten-store archive fidelity for owned synthetic task-watch history.

The ordinary-file archive adapter makes no ACL or age claim. No deployment,
configuration loader, real credential, network, model or worker is activated.
"""

import sqlite3
from contextlib import closing, contextmanager
from datetime import timedelta
from threading import Event
from types import SimpleNamespace

import pytest
import test_defense_store as core
from test_defense_recheck_backup import (
    _action,
    _archive_roundtrip,
    _directory,
    _image,
    archive,
    transfer,
)
from test_defense_recheck_store import declaration, passing_result

from opsark.automation_store import AutomationStore, ModeChange
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_store import DefenseConflict, DefenseStore
from opsark.defense_task_watch import DefenseTaskWatcher
from opsark.defense_task_watch_store import DefenseTaskWatchStore
from opsark.security_store import SecurityStore


@contextmanager
def no_activation():
    attempts = []

    def forbidden(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("A data-only restore cannot activate a transport or worker")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("socket.socket", forbidden)
        patch.setattr("paramiko.SSHClient.connect", forbidden)
        patch.setattr("httpx.Client.send", forbidden)
        patch.setattr("httpx.AsyncClient.send", forbidden)
        patch.setattr("subprocess.Popen", forbidden)
        patch.setattr("threading.Thread.start", forbidden)
        yield
    assert attempts == []


def base_images(path):
    catalog, rows = _image(path)
    return (
        [row for row in catalog if not row[1].startswith("defense_task_watch")],
        {name: value for name, value in rows.items() if not name.startswith("defense_task_watch")},
    )


@pytest.fixture(scope="module")
def preserved_watch(tmp_path_factory, request):
    root = _directory(tmp_path_factory.mktemp("newfake-task-watch-archive") / "owned")
    source = _directory(root / "source")
    mode = AutomationStore(
        source / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
    )
    mode.change_mode(ModeChange(mode=Mode.assisted, expected_revision=0))
    security = source / "security.sqlite3"
    SecurityStore(security)
    base = DefenseStore(security)
    rechecks = DefenseRecheckStore(base)
    originals = []
    for name in ("known", "outage", "unfinished"):
        transaction, profile = _action(base, rechecks, "newfake-watch-" + name, "semi")
        originals.append((transaction, profile))
    # An actual sealed v2 result is also present; watch table restoration cannot
    # substitute for preserving the original approval and observation references.
    original = originals[0][0]
    run = rechecks.create(
        declaration(base, original, "7" * 32), now=core.NOW + timedelta(seconds=3)
    )
    recheck_claim = rechecks.claim(
        run.declaration.run_ref, owner="newfake-old-recheck", now=core.NOW + timedelta(seconds=3)
    )
    assert recheck_claim is not None
    result = passing_result(base, rechecks, original, recheck_claim)
    rechecks.finish(recheck_claim, result)
    retained_run = rechecks.get(run.declaration.run_ref)
    for transaction, _ in originals:
        base.record_unavailable(
            transaction.rid,
            "apply",
            context=transaction.context,
            now=core.NOW + timedelta(seconds=8),
        )
        assert base.latched(transaction.context.host_id, transaction.context.defense_scope)
    mode.change_mode(ModeChange(mode=Mode.manual, expected_revision=1))
    mode_status = mode.status()

    watch = DefenseTaskWatchStore(base)
    hosts = tuple(transaction.context.host_id for transaction, _ in originals)
    old_lease = watch.acquire("newfake-old-watch-owner", now=core.NOW + timedelta(seconds=9))
    assert old_lease is not None
    watch.discover(old_lease, hosts, now=core.NOW + timedelta(seconds=9))
    known = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=9))
    watch.finish(
        old_lease, known, "active", interval_seconds=30, now=core.NOW + timedelta(seconds=10)
    )
    outage = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=11))
    watch.finish(
        old_lease, outage, "unavailable", interval_seconds=30, now=core.NOW + timedelta(seconds=12)
    )
    events = watch.events()["events"]
    acknowledged = watch.ack(
        events[1]["event_ref"], confirm_ack=True, now=core.NOW + timedelta(seconds=13)
    )
    unfinished = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=14))
    assert unfinished.request_id == originals[2][0].rid
    known_again = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=41))
    assert known_again.request_id == known.request_id and known_again.attempt == 2
    watch.finish(
        old_lease, known_again, "expired", interval_seconds=30, now=core.NOW + timedelta(seconds=42)
    )
    outage_again = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=73))
    assert outage_again.request_id == outage.request_id and outage_again.attempt == 2
    watch.finish(
        old_lease,
        outage_again,
        "unavailable",
        interval_seconds=30,
        now=core.NOW + timedelta(seconds=74),
    )
    for name in set(transfer.DATABASES) - {"security.sqlite3", "automation.sqlite3"}:
        with closing(sqlite3.connect(source / name)) as db, db:
            db.execute("CREATE TABLE newfake_marker(id TEXT PRIMARY KEY,value BLOB NOT NULL)")
            db.execute("INSERT INTO newfake_marker VALUES(?,?)", (name, name.encode()))

    # Keep the connection alive after checkpoint. The next committed original-RID
    # follow-up claim must exist only in WAL, not in a copied main database file.
    witness = sqlite3.connect(security)
    request.addfinalizer(witness.close)
    assert witness.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    witness.execute("PRAGMA wal_autocheckpoint=0")
    wal_claim = watch.claim_due(old_lease, hosts, now=core.NOW + timedelta(seconds=105))
    assert wal_claim.request_id == unfinished.request_id and wal_claim.attempt == 2
    assert (source / "security.sqlite3-wal").stat().st_size > 0
    with closing(sqlite3.connect(security.as_uri() + "?immutable=1", uri=True)) as main_only:
        assert (
            main_only.execute(
                "SELECT 1 FROM defense_task_watch_attempts_v1 WHERE claim_ref=?",
                (wal_claim.claim_ref,),
            ).fetchone()
            is None
        )

    before = {name: _image(source / name) for name in transfer.DATABASES}
    immutable = base_images(security)
    with no_activation():
        snapshot = root / "snapshot"
        manifest = transfer.snapshot(source, snapshot)
        assert len(manifest["databases"]) == 10
        assert set(manifest["databases"]) == set(transfer.DATABASES) == set(archive.DATABASES)
        assert {name: _image(snapshot / name) for name in transfer.DATABASES} == before
        extracted = _archive_roundtrip(snapshot, _directory(root / "extracted"))
        assert transfer.verify_snapshot(extracted)["database_count"] == 10
        for name in (*transfer.DATABASES, "manifest.json"):
            assert (extracted / name).read_bytes() == (snapshot / name).read_bytes()
        rehearsed = root / "rehearsed"
        assert transfer.rehearse(extracted, rehearsed)["database_count"] == 10
        assert {name: _image(rehearsed / name) for name in transfer.DATABASES} == before
    return SimpleNamespace(
        root=root,
        source=source,
        snapshot=snapshot,
        extracted=extracted,
        rehearsed=rehearsed,
        before=before,
        immutable=immutable,
        originals=originals,
        old_lease=old_lease,
        unfinished=unfinished,
        wal_claim=wal_claim,
        events=watch.events(),
        acknowledged=acknowledged,
        mode_status=mode_status,
        retained_run=retained_run,
        hosts=hosts,
    )


def test_watch_ten_store_archive_preserves_wal_claims_budget_ack_and_rowids(preserved_watch):
    h = preserved_watch
    with no_activation():
        base = DefenseStore(h.rehearsed / "security.sqlite3")
        watch = DefenseTaskWatchStore(base)
        rechecks = DefenseRecheckStore(base)
        mode = AutomationStore(
            h.rehearsed / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
        )
        disabled = DefenseTaskWatcher(
            SimpleNamespace(store=base, targets={}, stopped=Event()), watch, (), enabled=False
        )
        assert not disabled.start() and not disabled.tick()["queried"]
        assert not disabled.status()["enabled"] and not disabled.status()["running"]
        assert watch.events() == h.events
        assert (
            watch.ack(h.acknowledged["event_ref"], now=core.NOW + timedelta(seconds=106))
            == h.acknowledged
        )
        assert watch.acquire("newfake-restart", now=core.NOW + timedelta(seconds=106)) is None
        assert not watch.discovery_incomplete(h.hosts)
        assert rechecks.get(h.retained_run.declaration.run_ref) == h.retained_run
        assert mode.status() == h.mode_status
        for transaction, profile in h.originals:
            assert base.transaction(transaction.rid).query_required
            assert base.latched(transaction.context.host_id, transaction.context.defense_scope)
            assert rechecks.action_profile(transaction.rid) == profile
        with base._connection() as db:
            row = db.execute(
                "SELECT * FROM defense_task_watches_v1 WHERE rid=?", (h.wal_claim.request_id,)
            ).fetchone()
            assert row["claim_ref"] == h.wal_claim.claim_ref
            assert row["attempts"] == row["daily_attempts"] == 2
            assert row["charged_day"] == core.NOW.date().isoformat()
            assert (
                db.execute(
                    "SELECT finished_at FROM defense_task_watch_attempts_v1 WHERE claim_ref=?",
                    (h.unfinished.claim_ref,),
                ).fetchone()[0]
                is None
            )
            indexes = {row[1] for row in db.execute("PRAGMA index_list(defense_requests)")}
            assert "defense_task_watch_apply_cursor_v1" in indexes
        assert {name: _image(h.rehearsed / name) for name in transfer.DATABASES} == h.before


def test_restored_old_claim_owner_cannot_commit_or_reset_usage_or_replay_sender(preserved_watch):
    h = preserved_watch
    with no_activation():
        replica = h.root / "separate-rehearsal"
        assert transfer.rehearse(h.extracted, replica)["database_count"] == 10
        base = DefenseStore(replica / "security.sqlite3")
        watch = DefenseTaskWatchStore(base)
        before = base_images(base.path)
        now = core.NOW + timedelta(seconds=130)
        with pytest.raises(DefenseConflict):
            watch.finish(h.old_lease, h.wal_claim, "active", interval_seconds=30, now=now)
        fresh = watch.acquire("newfake-explicit-follow-up-owner", now=now)
        assert fresh is not None and fresh.epoch > h.old_lease.epoch
        claim = watch.claim_due(fresh, h.hosts, now=now)
        assert claim.request_id == h.wal_claim.request_id
        assert claim.attempt == h.wal_claim.attempt + 1
        with base._connection() as db:
            row = db.execute(
                "SELECT attempts,daily_attempts FROM defense_task_watches_v1 WHERE rid=?",
                (claim.request_id,),
            ).fetchone()
            assert tuple(row) == (3, 3)
        original = next(tx for tx, _ in h.originals if tx.rid == claim.request_id)
        assert (
            base.begin_sendable(
                original.rid,
                "apply",
                context=original.context,
                owner="newfake-recovered-sender",
                now=now,
            )
            is None
        )
        assert base_images(base.path) == before == h.immutable
        mode = AutomationStore(
            replica / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
        )
        assert mode.status() == h.mode_status
        for transaction, _ in h.originals:
            assert base.latched(transaction.context.host_id, transaction.context.defense_scope)
