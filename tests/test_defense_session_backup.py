"""Production ten-store session recovery, using only owned synthetic ledger facts.

This is stores-v1 snapshot/archive/rehearsal acceptance, not a new age claim.
The restore path never opens credentials, starts an app, a thread or a transport.
"""

import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from test_defense_api import NOW
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_recheck_backup import (
    _action,
    _archive_roundtrip,
    _directory,
    _image,
    archive,
    transfer,
)
from test_defense_session_mutation_fence import ai_phase, ai_result, new_action, prepare_request
from test_defense_session_store import admission, old_image
from test_defense_session_store import no_network_or_provider as no_network_or_provider
from test_defense_session_store import session as session
from test_defense_task_watch_backup import no_activation

from opsark.automation_store import AutomationStore
from opsark.config import Settings
from opsark.defense_models import ActionBody, DefenseCall, DefenseRequest
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_session_store import DefenseSessionStore
from opsark.defense_store import DefenseConflict, DefenseStore
from opsark.security_store import SecurityStore


def _prepared(s):
    base = s.h.store
    ai_admission, selected, options = ai_phase(s)
    permit = base.begin_ai_usage(
        s.declaration.cursor_rid, session_admission=ai_admission, **options
    )
    result = ai_result(s, selected, permit)
    base.save_ai_result(result, session_admission=ai_admission, now=NOW)
    s.store.advance(ai_admission, next_phase="analysis_ready", now=NOW)
    s.store.advance(admission(s, "analysis_ready"), next_phase="preparing", now=NOW)
    sa = admission(s, "preparing")
    action = new_action(s, sa)
    request = prepare_request(s, action)
    base.save_request(action.rid, request, session_admission=sa, now=NOW)
    usage = s.h.service._usage(action, s.h.service.policy.execution)
    assert base.begin_sendable(
        action.rid,
        "prepare",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    reply = s.h.root(s.h.target, DefenseCall(request), "control").reply
    assert base.record_reply(
        action.rid, "prepare", reply, context=action.context, session_admission=sa, now=NOW
    ).accepted
    s.store.advance(sa, next_phase="prepared", now=NOW)
    return action, usage, permit, result


def _other_stores_and_old_history(s):
    source = s.h.store.path.parent
    SecurityStore(s.h.store.path)
    rechecks = DefenseRecheckStore(s.h.store)
    legacy, profile = _action(s.h.store, rechecks, "newfake-session-legacy-peer", "semi")
    s.h.store.record_unavailable(legacy.rid, "apply", context=legacy.context, now=NOW)
    assert s.h.store.approval_record(legacy.rid) is not None
    for name in set(transfer.DATABASES) - {"security.sqlite3", "automation.sqlite3"}:
        with closing(sqlite3.connect(source / name)) as db, db:
            db.execute("CREATE TABLE newfake_marker(id TEXT PRIMARY KEY,value BLOB NOT NULL)")
            db.execute("INSERT INTO newfake_marker VALUES(?,?)", (name, name.encode()))
    # The DB-only production snapshot must not load or activate this fake config.
    (source / ".env").write_text("OPSARK_DEFENSE_SESSION_ENABLED=true\n", encoding="ascii")
    return source, rechecks, legacy, profile


def _roundtrip(source):
    root = _directory(source.with_name(source.name + "-owned-backup-artifacts"))
    before = {name: _image(source / name) for name in transfer.DATABASES}
    with no_activation():
        snapshot = root / "snapshot"
        manifest = transfer.snapshot(source, snapshot)
        assert set(manifest["databases"]) == set(transfer.DATABASES) == set(archive.DATABASES)
        assert len(manifest["databases"]) == 10
        assert {name: _image(snapshot / name) for name in transfer.DATABASES} == before
        extracted = _archive_roundtrip(snapshot, _directory(root / "extracted"))
        assert transfer.verify_snapshot(extracted)["database_count"] == 10
        for name in (*transfer.DATABASES, "manifest.json"):
            assert (extracted / name).read_bytes() == (snapshot / name).read_bytes()
        restored = root / "restored"
        assert transfer.rehearse(extracted, restored)["database_count"] == 10
        assert {name: _image(restored / name) for name in transfer.DATABASES} == before
        assert not (restored / ".env").exists()
        assert not Settings(
            restored, "synthetic-restored-disabled-console-token"
        ).defense_session_enabled
    assert (source / ".env").read_text() == "OPSARK_DEFENSE_SESSION_ENABLED=true\n"
    return restored, before


def _checkpoint_witness(base):
    keeper = sqlite3.connect(base.path)
    assert keeper.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
    keeper.execute("PRAGMA wal_autocheckpoint=0")
    return keeper


def _reopen(s, directory, owner):
    base = DefenseStore(directory / "security.sqlite3")
    store = DefenseSessionStore(
        base, owner=owner, current_runtime=lambda _host: s.current[0], stopped=lambda: False
    )
    return base, store


def test_ten_store_restore_preserves_wal_unknown_session_and_all_canonical_records(session):
    s = session
    source, _, legacy, profile = _other_stores_and_old_history(s)
    action, usage, permit, result = _prepared(s)
    s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
    sa = admission(s, "applying")
    request = DefenseRequest(
        v=1,
        op="apply",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=ActionBody(manifest_sha256=s.h.store.manifest(action.rid).sha256, approval=None),
    )
    s.h.store.save_request(action.rid, request, session_admission=sa, now=NOW)
    assert s.h.store.begin_sendable(
        action.rid,
        "apply",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    # Keep the main file checkpointed while two new committed facts remain in WAL:
    # the unknown receiver record and the original session's terminal phase CAS.
    with closing(_checkpoint_witness(s.h.store)):
        s.h.store.record_unavailable(
            action.rid,
            "apply",
            context=action.context,
            session_admission=sa,
            now=NOW + timedelta(seconds=1),
        )
        retained = s.store.halt(
            s.declaration.session_ref, reason="result_unknown", now=NOW + timedelta(seconds=2)
        )
        assert retained.phase == "reconciliation_only"
        assert (source / "security.sqlite3-wal").stat().st_size > 0
        with closing(sqlite3.connect(s.h.store.path.as_uri() + "?immutable=1", uri=True)) as main:
            assert main.execute("SELECT phase FROM defense_sessions_v1").fetchone()[0] == "applying"
            assert (
                main.execute(
                    "SELECT phase FROM defense_transactions WHERE rid=?", (action.rid,)
                ).fetchone()[0]
                == "apply_sendable"
            )
        mode = s.h.automation.status()
        ai = s.h.store.ai_permit(analysis_id=permit.analysis_id)
        old = old_image(s.h.store)
        rpc = tuple(s.h.root.sent)
        restored, images = _roundtrip(source)
    with no_activation():
        base, reopened = _reopen(s, restored, "newfake-restored-process")
        assert reopened.get(s.declaration.session_ref, now=NOW + timedelta(seconds=3)) == retained
        assert base.ai_permit(analysis_id=permit.analysis_id) == ai
        assert base.ai_result(permit.analysis_id) == result
        assert base.usage(permit.intent_key).state == "consumed"
        assert base.execution_usage(action.rid).state == "unknown"
        assert base.request_metadata(action.rid, "apply").dispatch_phase == "unknown"
        assert base.request_metadata(action.rid, "apply").reply_sha256 is None
        assert base.latched(action.context.host_id, action.context.defense_scope)
        assert base.latched(legacy.context.host_id, legacy.context.defense_scope)
        assert DefenseRecheckStore(base).action_profile(legacy.rid) == profile
        assert (
            AutomationStore(
                restored / "automation.sqlite3",
                s.h.automation.policy,
                supplemental_scope=s.h.automation.supplemental_scope,
            ).status()
            == mode
        )
        with base._write() as db, pytest.raises(DefenseConflict):
            reopened.atomic_assert(sa, db, now=NOW + timedelta(seconds=3))
        with pytest.raises(DefenseConflict):
            base.begin_sendable(
                action.rid,
                "apply",
                context=action.context,
                owner=action.owner,
                usage=usage,
                lease=s.lease,
                session_admission=sa,
                now=NOW + timedelta(seconds=3),
            )
        assert old_image(base) == old and tuple(s.h.root.sent) == rpc
        assert {name: _image(restored / name) for name in transfer.DATABASES} == images


def test_restored_same_owner_new_epoch_cannot_resume_wal_only_phase_or_pending_sender(session):
    s = session
    source, _, _, _ = _other_stores_and_old_history(s)
    action, usage, _, _ = _prepared(s)
    with closing(_checkpoint_witness(s.h.store)):
        s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
        sa = admission(s, "applying")
        request = DefenseRequest(
            v=1,
            op="apply",
            request_id=action.rid,
            scope_sha256=action.context.root_scope,
            body=ActionBody(manifest_sha256=s.h.store.manifest(action.rid).sha256, approval=None),
        )
        s.h.store.save_request(action.rid, request, session_admission=sa, now=NOW)
        assert (source / "security.sqlite3-wal").stat().st_size > 0
        with closing(sqlite3.connect(s.h.store.path.as_uri() + "?immutable=1", uri=True)) as main:
            assert main.execute("SELECT phase FROM defense_sessions_v1").fetchone()[0] == "prepared"
            assert (
                main.execute(
                    "SELECT 1 FROM defense_requests WHERE rid=? AND op='apply'", (action.rid,)
                ).fetchone()
                is None
            )
        original = s.store.get(s.declaration.session_ref, now=NOW)
        restored, images = _roundtrip(source)
    with no_activation():
        base, reopened = _reopen(s, restored, s.h.service.owner)
        assert reopened.get(s.declaration.session_ref, now=NOW) == original
        assert base.request_metadata(action.rid, "apply").dispatch_phase == "intent"
        assert base.execution_usage(action.rid).state == "reserved"
        with base._write() as db, pytest.raises(DefenseConflict):
            reopened.atomic_assert(sa, db, now=NOW)
        assert {name: _image(restored / name) for name in transfer.DATABASES} == images
        base.release_worker(s.lease, now=NOW + timedelta(seconds=3))
        fresh = base.acquire_worker(
            s.h.service.owner,
            expires_at=s.declaration.controller_deadline_at,
            now=NOW + timedelta(seconds=3),
        )
        assert fresh is not None and fresh.epoch > s.lease.epoch
        before = old_image(base)
        record = reopened.get(s.declaration.session_ref, now=NOW + timedelta(seconds=3))
        assert record.phase == "applying" and record.effective_phase == "reconciliation_only"
        with pytest.raises(DefenseConflict):
            reopened.admit(
                s.declaration.session_ref,
                fresh,
                expected_phase="applying",
                now=NOW + timedelta(seconds=3),
            )
        for token in (None, sa):
            with pytest.raises(DefenseConflict):
                base.begin_sendable(
                    action.rid,
                    "apply",
                    context=action.context,
                    owner=action.owner,
                    usage=usage,
                    lease=fresh,
                    session_admission=token,
                    now=NOW + timedelta(seconds=3),
                )
        assert old_image(base) == before
        assert base.execution_usage(action.rid).state == "reserved"
