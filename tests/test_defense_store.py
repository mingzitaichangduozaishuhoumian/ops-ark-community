"""Fake, temporary SQLite ledgers only; no host, key or deployed database access."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from threading import Barrier
from typing import cast

import pytest

from opsark.defense_models import (
    ActionBody,
    ArmBody,
    DefenseApproval,
    DefenseCandidate,
    DefenseReply,
    DefenseRequest,
    ModeBody,
    PrepareBody,
    QueryBody,
    canonical,
    digest,
    rebuild_manifest,
)
from opsark.defense_store import (
    AIAdviceAuthorization,
    AIResult,
    AliasMap,
    DefenseAlias,
    DefenseConflict,
    DefenseContext,
    DefenseQuotaExceeded,
    DefenseSource,
    DefenseStore,
    UsageClaim,
)
from opsark.security_store import SecurityStore

NOW = datetime(2026, 11, 6, 1, 0, tzinfo=UTC)
OWNER = "test-worker"


def stamp(seconds=0):
    return (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def context(**changes):
    values = {
        "host_id": "fake-host",
        "defense_scope": "1" * 64,
        "registry_scope": "2" * 64,
        "root_scope": "3" * 64,
        "policy_sha256": "4" * 64,
        "boot_ref": "5" * 64,
        "binding_ref": "6" * 64,
        "mode": "semi",
        "global_revision": 2,
        "wire_revision": 3,
        "epoch": 1,
    }
    values.update(changes)
    return DefenseContext.model_validate(values)


def create(store, kind="cursor", *, ctx=None, cursor=None, now=NOW, deadline=120):
    return store.create_transaction(
        kind=kind,
        context=ctx or context(),
        owner=OWNER,
        deadline_at=stamp(deadline),
        cursor_rid=cursor,
        now=now,
    )


def test_two_independent_workers_share_original_observation_rid(tmp_path):
    path = tmp_path / "security.sqlite3"
    stores = (DefenseStore(path), DefenseStore(path))
    barrier = Barrier(2)

    def begin(index):
        barrier.wait(timeout=5)
        return stores[index].create_transaction(
            kind="cursor",
            context=context(),
            owner=f"worker-{index}",
            deadline_at=stamp(120),
            observation_key="a" * 64,
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = tuple(workers.map(begin, (0, 1)))
    assert first == second
    assert len(stores[0].transactions()) == 1
    # A repeated click cannot mint a replacement identity even after this cursor's deadline.
    again = stores[1].create_transaction(
        kind="cursor",
        context=context(),
        owner="new-worker",
        deadline_at=stamp(241),
        observation_key="a" * 64,
        now=NOW + timedelta(seconds=121),
    )
    assert again == first


def arm(store, *, ctx=None, now=NOW, deadline=120):
    transaction = create(store, ctx=ctx, now=now, deadline=deadline)
    request = DefenseRequest(
        v=1,
        op="arm",
        request_id=transaction.rid,
        scope_sha256=transaction.context.root_scope,
        body=ArmBody(
            observation_grant_ref="a" * 32, policy_sha256=transaction.context.policy_sha256
        ),
    )
    store.save_request(transaction.rid, request)
    return transaction, request


def reply(transaction, op, state, *, changes=None):
    ctx = transaction.context
    values = {
        "v": 1,
        "op": op,
        "request_id": transaction.rid,
        "scope_sha256": ctx.root_scope,
        "policy_sha256": ctx.policy_sha256,
        "boot_ref": ctx.boot_ref,
        "binding_ref": ctx.binding_ref,
        "mode": ctx.mode,
        "mode_revision": ctx.wire_revision,
        "state": state,
        "action_id": None,
        "cursor_id": None,
        "manifest_sha256": None,
        "deadline_at": None,
        "remaining_ms": None,
        "reason_code": "ok",
        "candidates": (),
    }
    if transaction.kind == "cursor" and state not in {"not_found", "rejected"}:
        values.update(cursor_id="a" * 32, deadline_at=transaction.deadline_at)
        if state == "expired":
            values["reason_code"] = "cursor_expired"
    if transaction.kind == "action" and state not in {"not_found", "rejected"}:
        values.update(
            action_id="b" * 32, cursor_id="a" * 32, manifest_sha256="0" * 64, deadline_at=stamp(90)
        )
        if state == "active":
            values["remaining_ms"] = 50000
    values.update(changes or {})
    return DefenseReply.model_validate(values)


def sync_mode(store, ctx=None):
    transaction = create(store, "mode", ctx=ctx)
    ctx = transaction.context
    store.register_mode_pending(transaction.rid, now=NOW)
    request = DefenseRequest(
        v=1,
        op="mode_sync",
        request_id=transaction.rid,
        scope_sha256=ctx.root_scope,
        body=ModeBody(
            mode=ctx.mode, mode_revision=ctx.wire_revision, policy_sha256=ctx.policy_sha256
        ),
    )
    store.save_request(transaction.rid, request)
    assert store.begin_sendable(transaction.rid, "mode_sync", context=ctx, owner=OWNER, now=NOW)
    store.record_reply(
        transaction.rid,
        "mode_sync",
        reply(transaction, "mode_sync", "synced"),
        context=ctx,
        now=NOW,
    )
    assert store.mode_ack(ctx).status == "pending"
    store.record_reply(
        transaction.rid, "query", reply(transaction, "query", "synced"), context=ctx, now=NOW
    )
    assert store.mode_ack(ctx).status == "confirmed"
    return transaction


def prepare(store, *, key="c" * 64, ctx=None, send=True, now=NOW, deadline=120):
    cursor, _ = arm(store, ctx=ctx, now=now, deadline=deadline)
    assert store.begin_sendable(cursor.rid, "arm", context=cursor.context, owner=OWNER, now=now)
    cursor_receipt = reply(
        cursor,
        "query",
        "armed",
        changes={
            "candidates": (
                DefenseCandidate(
                    source_ref="d" * 32,
                    source_alias="fixture-a",
                    classification="eligible",
                    distinct_failure_ports=5,
                    evidence_sha256="7" * 64,
                ),
            )
        },
    )
    store.record_reply(cursor.rid, "query", cursor_receipt, context=cursor.context, now=now)
    transaction = create(store, "action", ctx=ctx, cursor=cursor.rid, now=now, deadline=deadline)
    ctx = transaction.context
    request = DefenseRequest(
        v=1,
        op="prepare",
        request_id=transaction.rid,
        scope_sha256=ctx.root_scope,
        body=PrepareBody(
            cursor_id="a" * 32,
            source_ref="d" * 32,
            evidence_sha256="7" * 64,
            policy_sha256=ctx.policy_sha256,
            mode=ctx.mode,
            mode_revision=ctx.wire_revision,
            controller_grant_ref="e" * 32,
            root_grant_ref="f" * 32,
        ),
    )
    usage = UsageClaim(
        intent_key=key, kind="execution", grant_ref="e" * 32, max_per_day=10, max_total=100
    )
    store.save_request(transaction.rid, request)
    if send:
        assert store.begin_sendable(
            transaction.rid, "prepare", context=ctx, owner=OWNER, usage=usage, now=now
        )
        receipt = reply(transaction, "prepare", "ready")
        manifest = rebuild_manifest(request, receipt)
        receipt = receipt.model_copy(update={"manifest_sha256": manifest.sha256})
        assert store.record_reply(
            transaction.rid, "prepare", receipt, context=ctx, now=now
        ).accepted
    return transaction, request, usage


def action_reply(store, transaction, state, *, now=NOW, changes=None):
    manifest = store.manifest(transaction.rid)
    values = {"manifest_sha256": manifest.sha256}
    values.update(changes or {})
    return store.record_reply(
        transaction.rid,
        "query",
        reply(transaction, "query", state, changes=values),
        context=transaction.context,
        now=now,
    )


def approval(store, transaction, purpose="apply", *, expires=60):
    declaration = DefenseApproval(
        approval_id=("9" if purpose == "apply" else "8") * 32,
        purpose=purpose,
        request_id=transaction.rid,
        manifest_sha256=store.manifest(transaction.rid).sha256,
        approved_at=stamp(),
        expires_at=stamp(expires),
    )
    store.save_approval(
        transaction.rid,
        declaration,
        context=transaction.context,
        controller_grant_ref="e" * 32,
        root_grant_ref="f" * 32,
        now=NOW,
    )
    return declaration


def test_two_connections_at_most_one_send_permit(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    transaction, _ = arm(store)
    barrier = Barrier(2)

    def claim():
        other = DefenseStore(path)
        barrier.wait()
        return other.begin_sendable(
            transaction.rid, "arm", context=transaction.context, owner=OWNER, now=NOW
        )

    with ThreadPoolExecutor(max_workers=2) as workers:
        permits = list(workers.map(lambda _: claim(), range(2)))
    assert sum(item is not None for item in permits) == 1
    assert store.request_metadata(transaction.rid, "arm").dispatch_phase == "sendable"
    assert store.transaction(transaction.rid).query_required


def test_failed_sendable_commit_never_returns_permission_or_charges(tmp_path, monkeypatch):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, usage = prepare(store, send=False)

    def fail(_):
        raise sqlite3.OperationalError("injected commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_commit", fail)
        with pytest.raises(sqlite3.OperationalError):
            store.begin_sendable(
                transaction.rid,
                "prepare",
                context=transaction.context,
                owner=OWNER,
                usage=usage,
                now=NOW,
            )
    assert store.request_metadata(transaction.rid, "prepare").dispatch_phase == "intent"
    with pytest.raises(DefenseConflict):
        store.usage(usage.intent_key)
    assert store.begin_sendable(
        transaction.rid, "prepare", context=transaction.context, owner=OWNER, usage=usage, now=NOW
    )


def test_original_request_is_immutable_even_after_query(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    transaction, request = arm(store)
    metadata = store.save_request(transaction.rid, request)
    changed = request.model_copy(
        update={
            "body": ArmBody(
                observation_grant_ref="b" * 32, policy_sha256=transaction.context.policy_sha256
            )
        }
    )
    with pytest.raises(DefenseConflict, match="immutable"):
        store.save_request(transaction.rid, changed)
    assert store.begin_sendable(
        transaction.rid, "arm", context=transaction.context, owner=OWNER, now=NOW
    )
    receipt = reply(transaction, "arm", "armed")
    store.record_reply(transaction.rid, "arm", receipt, context=transaction.context, now=NOW)
    first_hash = store.request_metadata(transaction.rid, "arm").reply_sha256
    store.record_reply(
        transaction.rid,
        "query",
        reply(transaction, "query", "expired"),
        context=transaction.context,
        now=NOW + timedelta(seconds=130),
    )
    assert store.request_metadata(transaction.rid, "arm").reply_sha256 == first_hash
    assert store.request_metadata(transaction.rid, "arm").request_sha256 == metadata.request_sha256
    assert not hasattr(metadata, "request_bytes")


def test_same_cursor_two_workers_get_original_rid(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    cursor, _ = arm(store)
    barrier = Barrier(2)

    def claim():
        other = DefenseStore(path)
        barrier.wait()
        return create(other, "action", cursor=cursor.rid).rid

    with ThreadPoolExecutor(max_workers=2) as workers:
        rids = list(workers.map(lambda _: claim(), range(2)))
    assert rids[0] == rids[1]


def test_unknown_restart_only_queries_original_rid_and_keeps_reservation(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    sync_mode(store)
    transaction, _, usage = prepare(store)
    confirmed = store.last_confirmed(transaction.rid)
    store.record_unavailable(transaction.rid, "prepare", now=NOW)
    recovered = DefenseStore(path)
    assert (
        recovered.begin_sendable(
            transaction.rid,
            "prepare",
            context=transaction.context,
            owner=OWNER,
            usage=usage,
            now=NOW,
        )
        is None
    )
    call = recovered.query_call(transaction.rid)
    assert call.request.op == "query" and call.request.request_id == transaction.rid
    assert call.prepare_request is not None
    assert call.prepare_request.request_id == transaction.rid
    assert recovered.last_confirmed(transaction.rid) == confirmed
    assert recovered.usage(usage.intent_key).state == "unknown"
    assert recovered.latched(transaction.context.host_id, transaction.context.defense_scope)


@pytest.mark.parametrize(
    "change",
    [
        {"epoch": 2},
        {"binding_ref": "8" * 64},
        {"policy_sha256": "8" * 64},
        {"global_revision": 3, "wire_revision": 4},
    ],
)
def test_dispatch_rechecks_exact_context(tmp_path, change):
    store = DefenseStore(tmp_path / "security.sqlite3")
    transaction, _ = arm(store)
    with pytest.raises(DefenseConflict):
        store.begin_sendable(
            transaction.rid, "arm", context=context(**change), owner=OWNER, now=NOW
        )
    with pytest.raises(DefenseConflict):
        store.begin_sendable(
            transaction.rid, "arm", context=transaction.context, owner="different-worker", now=NOW
        )
    with pytest.raises(DefenseConflict):
        store.begin_sendable(
            transaction.rid,
            "arm",
            context=transaction.context,
            owner=OWNER,
            now=NOW + timedelta(seconds=120),
        )


def test_approval_exact_binding_expiry_and_independent_revoke_op(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, usage = prepare(store)
    declaration = approval(store, transaction)
    with pytest.raises(DefenseConflict, match="cannot be replaced"):
        store.save_approval(
            transaction.rid,
            declaration.model_copy(update={"approval_id": "7" * 32}),
            context=transaction.context,
            controller_grant_ref="e" * 32,
            root_grant_ref="f" * 32,
            now=NOW,
        )
    apply = DefenseRequest(
        v=1,
        op="apply",
        request_id=transaction.rid,
        scope_sha256=transaction.context.root_scope,
        body=ActionBody(manifest_sha256=declaration.manifest_sha256, approval=declaration),
    )
    store.save_request(transaction.rid, apply)
    with pytest.raises(DefenseConflict, match="stale"):
        store.begin_sendable(
            transaction.rid,
            "apply",
            context=transaction.context,
            owner=OWNER,
            usage=usage,
            now=NOW + timedelta(seconds=61),
        )
    assert store.begin_sendable(
        transaction.rid, "apply", context=transaction.context, owner=OWNER, usage=usage, now=NOW
    )
    assert (
        store.begin_sendable(
            transaction.rid, "apply", context=transaction.context, owner=OWNER, usage=usage, now=NOW
        )
        is None
    )
    assert store.usage(usage.intent_key).state == "consumed"
    revoke_declaration = approval(store, transaction, "revoke")
    store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="revoke",
            request_id=transaction.rid,
            scope_sha256=transaction.context.root_scope,
            body=ActionBody(
                manifest_sha256=declaration.manifest_sha256, approval=revoke_declaration
            ),
        ),
    )
    assert store.begin_sendable(
        transaction.rid, "revoke", context=transaction.context, owner=OWNER, now=NOW
    )
    assert store.request_metadata(transaction.rid, "apply").dispatch_phase == "sendable"
    assert store.request_metadata(transaction.rid, "revoke").dispatch_phase == "sendable"


def test_mode_ack_requires_query_exact_rid_revision_and_current_context(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    mode = sync_mode(store)
    newer = context(global_revision=3, wire_revision=4, epoch=2)
    pending = create(store, "mode", ctx=newer)
    store.register_mode_pending(pending.rid, now=NOW)
    old = reply(mode, "query", "synced")
    result = store.record_reply(mode.rid, "query", old, context=mode.context, now=NOW)
    assert result.accepted
    newer_ack = store.mode_ack(newer)
    assert newer_ack is not None and newer_ack.status == "pending"
    wrong = reply(mode, "query", "synced", changes={"request_id": "1" * 32})
    assert not store.record_reply(mode.rid, "query", wrong, context=mode.context, now=NOW).accepted
    older_ack = store.mode_ack(mode.context)
    assert older_ack is not None and older_ack.status == "unknown"


def test_observations_keep_last_fact_ttl_and_terminal_regressions_latch(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, _ = prepare(store)
    assert action_reply(store, transaction, "active").accepted
    active = store.last_confirmed(transaction.rid)
    assert not action_reply(store, transaction, "active", changes={"remaining_ms": 50001}).accepted
    assert store.last_confirmed(transaction.rid) == active
    assert action_reply(store, transaction, "expired").accepted
    expired = store.last_confirmed(transaction.rid)
    assert not action_reply(store, transaction, "active").accepted
    assert store.last_confirmed(transaction.rid) == expired
    store.record_unavailable(transaction.rid, "query", now=NOW + timedelta(days=1))
    assert store.last_confirmed(transaction.rid) == expired
    assert len(store.observations(transaction.rid)) == 6
    assert store.transaction(transaction.rid).phase == "unknown"


def test_security_store_existing_schema_rows_and_monitor_lease_untouched(tmp_path):
    path = tmp_path / "security.sqlite3"
    SecurityStore(path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("INSERT INTO monitor_lease VALUES(1,?,?)", ("legacy-owner", 123456.0))
        db.execute(
            "INSERT INTO observations VALUES(?,?,?,?,?,?)",
            ("old-id", "fake-host", "1" * 64, 1.0, "{}", "old-hash"),
        )
        before = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        old_rows = db.execute("SELECT * FROM observations").fetchall()
    store = DefenseStore(path)
    lease = store.acquire_worker(OWNER, expires_at=stamp(60), now=NOW)
    assert lease is not None
    with closing(sqlite3.connect(path)) as db, db:
        for name, sql in before:
            assert (
                db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
                == sql
            )
        assert db.execute("SELECT * FROM observations").fetchall() == old_rows
        assert db.execute("SELECT * FROM monitor_lease").fetchall() == [
            (1, "legacy-owner", 123456.0)
        ]
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_worker_epochs_are_fenced_and_do_not_delete_history(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    first = store.acquire_worker(OWNER, expires_at=stamp(10), now=NOW)
    assert first is not None
    assert store.acquire_worker("other", expires_at=stamp(10), now=NOW) is None
    second = store.acquire_worker("other", expires_at=stamp(60), now=NOW + timedelta(seconds=11))
    assert second is not None and second.epoch == first.epoch + 1
    store.release_worker(first, now=NOW + timedelta(seconds=12))
    transaction, _ = arm(store)
    with pytest.raises(DefenseConflict, match="lease"):
        store.begin_sendable(
            transaction.rid,
            "arm",
            context=transaction.context,
            owner=OWNER,
            lease=first,
            now=NOW + timedelta(seconds=12),
        )


def test_ai_stable_intent_keeps_cost_across_restart_grant_change_and_unknown(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    sync_mode(store)
    cursor, _ = arm(store)
    ctx = cursor.context
    assert store.begin_sendable(cursor.rid, "arm", context=ctx, owner=OWNER, now=NOW)
    candidates = (
        DefenseCandidate(
            source_ref="c" * 32,
            source_alias="fixture-a",
            classification="eligible",
            distinct_failure_ports=5,
            evidence_sha256="d" * 64,
        ),
    )
    cursor_reply = reply(cursor, "query", "armed", changes={"candidates": candidates})
    receipt = store.record_reply(cursor.rid, "query", cursor_reply, context=ctx, now=NOW)
    assert receipt.receipt_sha256 is not None
    source = DefenseSource(
        v=1,
        host_scope="a" * 64,
        defense_scope=ctx.defense_scope,
        root_scope=ctx.root_scope,
        policy_sha256=ctx.policy_sha256,
        boot_ref=ctx.boot_ref,
        binding_ref=ctx.binding_ref,
        cursor_rid=cursor.rid,
        observed_at=stamp(),
        cursor_deadline_at=stamp(120),
        root_reply_sha256=receipt.receipt_sha256,
        candidates=candidates,
    )
    store.save_source(
        "e" * 64,
        source,
        alias_map=AliasMap(
            aliases=(
                DefenseAlias(
                    candidate_alias="candidate-1",
                    evidence_alias="evidence-1",
                    source_ref="c" * 32,
                    evidence_sha256="d" * 64,
                ),
            )
        ),
    )
    usage = UsageClaim(
        intent_key="f" * 64,
        kind="ai",
        grant_ref="a" * 32,
        max_per_day=1,
        max_total=2,
        provider_fingerprint="b" * 64,
    )
    permit = store.begin_ai_usage(
        cursor.rid,
        source_key="e" * 64,
        context=ctx,
        owner=OWNER,
        usage=usage,
        analysis_id="c" * 32,
        input_digest="d" * 64,
        now=NOW,
    )
    with pytest.raises(DefenseQuotaExceeded):
        store.begin_ai_usage(
            cursor.rid,
            source_key="e" * 64,
            context=ctx,
            owner=OWNER,
            usage=usage.model_copy(update={"intent_key": "0" * 64}),
            analysis_id="d" * 32,
            input_digest="d" * 64,
            now=NOW,
        )
    store.save_ai_result(
        AIResult(
            analysis_id=permit.analysis_id,
            intent_key=usage.intent_key,
            input_digest=permit.input_digest,
            provider_fingerprint=permit.provider_fingerprint,
            status="unknown",
            proof_sha256=None,
            decision=None,
            source_ref=None,
            evidence_sha256=None,
            reason_code=None,
        )
    )
    recovered = DefenseStore(path)
    with pytest.raises(DefenseConflict):
        recovered.begin_ai_usage(
            cursor.rid,
            source_key="e" * 64,
            context=ctx,
            owner=OWNER,
            usage=usage.model_copy(update={"grant_ref": "b" * 32}),
            analysis_id="d" * 32,
            input_digest="d" * 64,
            now=NOW,
        )
    with pytest.raises(DefenseConflict):
        recovered.begin_ai_usage(
            cursor.rid,
            source_key="e" * 64,
            context=ctx,
            owner=OWNER,
            usage=usage.model_copy(update={"intent_key": "0" * 64}),
            analysis_id="d" * 32,
            input_digest="d" * 64,
            now=NOW,
        )
    assert recovered.usage(usage.intent_key).state == "unknown"
    assert recovered.latched(ctx.host_id, ctx.defense_scope)


def test_corrupted_request_hash_never_dispatches(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    transaction, _ = arm(store)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE defense_requests SET request_sha256=?", ("0" * 64,))
    with pytest.raises(DefenseConflict, match="integrity"):
        store.begin_sendable(
            transaction.rid, "arm", context=transaction.context, owner=OWNER, now=NOW
        )
    assert canonical(store.transaction(transaction.rid))


def test_execution_day_and_total_reservations_survive_unknown_and_calendar_change(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    first, _, base = prepare(store, send=False)
    limits = base.model_copy(update={"max_per_day": 1, "max_total": 2})
    assert store.begin_sendable(
        first.rid, "prepare", context=first.context, owner=OWNER, usage=limits, now=NOW
    )
    # A rejected/unknown result retains its original daily and total reservation.
    store.record_unavailable(first.rid, "prepare", now=NOW)
    second_context = context(host_id="fake-host-2")
    sync_mode(store, second_context)
    second, _, _ = prepare(store, ctx=second_context, send=False)
    second_usage = limits.model_copy(update={"intent_key": "d" * 64})
    with pytest.raises(DefenseQuotaExceeded):
        store.begin_sendable(
            second.rid, "prepare", context=second_context, owner=OWNER, usage=second_usage, now=NOW
        )
    tomorrow = NOW + timedelta(days=1)
    second, _, _ = prepare(
        store, ctx=second_context, send=False, now=tomorrow, deadline=86400 + 120
    )
    assert store.begin_sendable(
        second.rid, "prepare", context=second_context, owner=OWNER, usage=second_usage, now=tomorrow
    )
    third_context = context(host_id="fake-host-3")
    sync_mode(store, third_context)
    third, _, _ = prepare(
        store, ctx=third_context, send=False, now=NOW + timedelta(days=2), deadline=172800 + 120
    )
    with pytest.raises(DefenseQuotaExceeded):
        store.begin_sendable(
            third.rid,
            "prepare",
            context=third_context,
            owner=OWNER,
            usage=limits.model_copy(update={"intent_key": "e" * 64}),
            now=NOW + timedelta(days=2),
        )
    assert store.usage(limits.intent_key).charged_day == "2026-11-06"
    assert store.usage(second_usage.intent_key).charged_day == "2026-11-07"
    assert store.usage(limits.intent_key).state == "unknown"


def test_prepare_requires_exact_confirmed_source_and_manual_never_dispatches(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    cursor, _ = arm(store)
    transaction = create(store, "action", cursor=cursor.rid)
    request = DefenseRequest(
        v=1,
        op="prepare",
        request_id=transaction.rid,
        scope_sha256=transaction.context.root_scope,
        body=PrepareBody(
            cursor_id="a" * 32,
            source_ref="d" * 32,
            evidence_sha256="7" * 64,
            policy_sha256=transaction.context.policy_sha256,
            mode="semi",
            mode_revision=3,
            controller_grant_ref="e" * 32,
            root_grant_ref="f" * 32,
        ),
    )
    with pytest.raises(DefenseConflict, match="confirmed cursor source"):
        store.save_request(transaction.rid, request)
    manual = context(mode="manual")
    cursor, _ = arm(store, ctx=manual)
    # Query and an explicit arm remain possible in manual mode; action grants do not.
    assert store.begin_sendable(cursor.rid, "arm", context=manual, owner=OWNER, now=NOW)
    query_body = store.query_call(cursor.rid).request.body
    assert isinstance(query_body, QueryBody) and query_body.kind == "cursor"
    assert digest(store.transaction(cursor.rid))


def test_approval_cannot_exceed_manifest_deadline_or_change_manifest(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, _ = prepare(store)
    declaration = DefenseApproval(
        approval_id="1" * 32,
        purpose="apply",
        request_id=transaction.rid,
        manifest_sha256=store.manifest(transaction.rid).sha256,
        approved_at=stamp(),
        expires_at=stamp(91),
    )
    with pytest.raises(DefenseConflict):
        store.save_approval(
            transaction.rid,
            declaration,
            context=transaction.context,
            controller_grant_ref="e" * 32,
            root_grant_ref="f" * 32,
            now=NOW,
        )
    with pytest.raises(DefenseConflict):
        store.save_approval(
            transaction.rid,
            declaration.model_copy(update={"expires_at": stamp(60), "manifest_sha256": "0" * 64}),
            context=transaction.context,
            controller_grant_ref="e" * 32,
            root_grant_ref="f" * 32,
            now=NOW,
        )


def test_wrong_binding_and_stale_query_preserve_last_confirmed(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, _ = prepare(store)
    confirmed = store.last_confirmed(transaction.rid)
    mismatch = action_reply(store, transaction, "active", changes={"binding_ref": "0" * 64})
    assert mismatch.reason == "binding_changed"
    assert store.last_confirmed(transaction.rid) == confirmed
    assert action_reply(store, transaction, "active", now=NOW + timedelta(seconds=10)).accepted
    stale = action_reply(store, transaction, "active", now=NOW + timedelta(seconds=9))
    assert stale.reason == "stale"
    latest = store.last_confirmed(transaction.rid)
    assert latest is not None and latest.observed_at == stamp(10).replace("Z", ".000000Z")
    assert store.latched(transaction.context.host_id, transaction.context.defense_scope)


def test_cursor_terminal_cannot_revive_or_change_root_cursor_binding(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    cursor, _ = arm(store)
    assert store.begin_sendable(cursor.rid, "arm", context=cursor.context, owner=OWNER, now=NOW)
    store.record_reply(
        cursor.rid, "arm", reply(cursor, "arm", "armed"), context=cursor.context, now=NOW
    )
    different = reply(cursor, "query", "armed", changes={"cursor_id": "b" * 32})
    result = store.record_reply(cursor.rid, "query", different, context=cursor.context, now=NOW)
    assert not result.accepted and result.reason == "binding_changed"
    assert store.record_reply(
        cursor.rid, "query", reply(cursor, "query", "expired"), context=cursor.context, now=NOW
    ).accepted
    result = store.record_reply(
        cursor.rid, "query", reply(cursor, "query", "armed"), context=cursor.context, now=NOW
    )
    assert not result.accepted and result.reason == "terminal_regression"


def test_corrupted_mode_ack_cannot_admit_prepare(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    sync_mode(store)
    transaction, _, usage = prepare(store, send=False)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE defense_mode_ack SET receipt_sha256=?", ("0" * 64,))
    with pytest.raises(DefenseConflict, match="acknowledgement integrity"):
        store.begin_sendable(
            transaction.rid,
            "prepare",
            context=transaction.context,
            owner=OWNER,
            usage=usage,
            now=NOW,
        )
    with pytest.raises(DefenseConflict):
        store.usage(usage.intent_key)


def test_apply_confirmation_usage_and_sendable_share_failed_commit(tmp_path, monkeypatch):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    sync_mode(store)
    transaction, _, usage = prepare(store)
    declaration = approval(store, transaction)
    store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="apply",
            request_id=transaction.rid,
            scope_sha256=transaction.context.root_scope,
            body=ActionBody(manifest_sha256=declaration.manifest_sha256, approval=declaration),
        ),
    )

    def fail(_):
        raise sqlite3.OperationalError("injected confirmation commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_commit", fail)
        with pytest.raises(sqlite3.OperationalError):
            store.begin_sendable(
                transaction.rid,
                "apply",
                context=transaction.context,
                owner=OWNER,
                usage=usage,
                now=NOW,
            )
    assert store.usage(usage.intent_key).state == "reserved"
    assert store.request_metadata(transaction.rid, "apply").dispatch_phase == "intent"
    with closing(sqlite3.connect(path)) as db, db:
        assert db.execute(
            "SELECT dispatch_state,used_at FROM defense_authorizations"
        ).fetchone() == (
            "recorded",
            None,
        )
    assert store.begin_sendable(
        transaction.rid, "apply", context=transaction.context, owner=OWNER, usage=usage, now=NOW
    )


def late_active(store):
    """Original admission ends at120; apply at89 can stay active until149."""
    transaction, _, usage = prepare(store)
    declaration = DefenseApproval(
        approval_id="2" * 32,
        purpose="apply",
        request_id=transaction.rid,
        manifest_sha256=store.manifest(transaction.rid).sha256,
        approved_at=stamp(89),
        expires_at=stamp(90),
    )
    store.save_approval(
        transaction.rid,
        declaration,
        context=transaction.context,
        controller_grant_ref="e" * 32,
        root_grant_ref="f" * 32,
        now=NOW + timedelta(seconds=89),
    )
    store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="apply",
            request_id=transaction.rid,
            scope_sha256=transaction.context.root_scope,
            body=ActionBody(manifest_sha256=declaration.manifest_sha256, approval=declaration),
        ),
    )
    assert store.begin_sendable(
        transaction.rid,
        "apply",
        context=transaction.context,
        owner=OWNER,
        usage=usage,
        now=NOW + timedelta(seconds=89),
    )
    receipt = reply(
        transaction,
        "apply",
        "active",
        changes={
            "manifest_sha256": declaration.manifest_sha256,
            "remaining_ms": 60000,
        },
    )
    assert store.record_reply(
        transaction.rid,
        "apply",
        receipt,
        context=transaction.context,
        now=NOW + timedelta(seconds=89),
    ).accepted
    assert action_reply(
        store,
        transaction,
        "active",
        changes={"remaining_ms": 28000},
        now=NOW + timedelta(seconds=121),
    ).accepted
    return transaction, usage


def save_late_revoke(store, transaction, ctx):
    declaration = DefenseApproval(
        approval_id="3" * 32,
        purpose="revoke",
        request_id=transaction.rid,
        manifest_sha256=store.manifest(transaction.rid).sha256,
        approved_at=stamp(121),
        expires_at=stamp(130),
    )
    store.save_approval(
        transaction.rid,
        declaration,
        context=ctx,
        controller_grant_ref="e" * 32,
        root_grant_ref="f" * 32,
        now=NOW + timedelta(seconds=121),
    )
    store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="revoke",
            request_id=transaction.rid,
            scope_sha256=transaction.context.root_scope,
            body=ActionBody(manifest_sha256=declaration.manifest_sha256, approval=declaration),
        ),
    )
    return declaration


def test_active_late_revoke_uses_new_confirmation_not_old_deadline(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, usage = late_active(store)
    original = store.transaction(transaction.rid)
    save_late_revoke(store, transaction, transaction.context)
    permit = store.begin_sendable(
        transaction.rid,
        "revoke",
        context=transaction.context,
        owner=OWNER,
        now=NOW + timedelta(seconds=121),
    )
    assert permit is not None
    assert store.revoke_admission(transaction.rid) == transaction.context
    assert store.transaction(transaction.rid).context == original.context
    assert store.transaction(transaction.rid).deadline_at == original.deadline_at
    assert store.manifest(transaction.rid).deadline_at == stamp(90)
    assert store.usage(usage.intent_key).state == "consumed"
    assert (
        store.begin_sendable(
            transaction.rid,
            "revoke",
            context=transaction.context,
            owner=OWNER,
            now=NOW + timedelta(seconds=122),
        )
        is None
    )


@pytest.mark.parametrize("mode", ["semi", "auto"])
def test_historical_query_and_revoke_after_current_mode_revision_change(tmp_path, mode):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, usage = late_active(store)
    current = context(mode=mode, global_revision=3, wire_revision=4, epoch=2)
    sync_mode(store, current)
    historical = reply(
        transaction,
        "query",
        "active",
        changes={
            "remaining_ms": 27000,
            "manifest_sha256": store.manifest(transaction.rid).sha256,
        },
    )
    assert store.record_reply(
        transaction.rid, "query", historical, context=current, now=NOW + timedelta(seconds=122)
    ).accepted
    save_late_revoke(store, transaction, current)
    permit = store.begin_sendable(
        transaction.rid, "revoke", context=current, owner=OWNER, now=NOW + timedelta(seconds=122)
    )
    assert permit is not None and permit.epoch == current.epoch
    assert store.transaction(transaction.rid).context == transaction.context
    assert store.revoke_admission(transaction.rid) == current
    revoked = reply(
        transaction,
        "revoke",
        "revoked",
        changes={
            "manifest_sha256": store.manifest(transaction.rid).sha256,
        },
    )
    assert store.record_reply(
        transaction.rid, "revoke", revoked, context=current, now=NOW + timedelta(seconds=123)
    ).accepted
    assert store.usage(usage.intent_key).state == "consumed"


def test_late_revoke_failed_commit_and_expired_confirmation_never_grant_send(tmp_path, monkeypatch):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    sync_mode(store)
    transaction, usage = late_active(store)
    save_late_revoke(store, transaction, transaction.context)

    def fail(_):
        raise sqlite3.OperationalError("injected revoke commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_commit", fail)
        with pytest.raises(sqlite3.OperationalError):
            store.begin_sendable(
                transaction.rid,
                "revoke",
                context=transaction.context,
                owner=OWNER,
                now=NOW + timedelta(seconds=121),
            )
    assert store.revoke_admission(transaction.rid) is None
    assert store.request_metadata(transaction.rid, "revoke").dispatch_phase == "intent"
    with closing(sqlite3.connect(path)) as db, db:
        assert db.execute(
            "SELECT dispatch_state FROM defense_authorizations WHERE purpose='revoke'"
        ).fetchone() == ("recorded",)
    with pytest.raises(DefenseConflict, match="stale"):
        store.begin_sendable(
            transaction.rid,
            "revoke",
            context=transaction.context,
            owner=OWNER,
            now=NOW + timedelta(seconds=130),
        )
    assert store.revoke_admission(transaction.rid) is None
    assert store.usage(usage.intent_key).state == "consumed"


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "manual"},
        {"boot_ref": "7" * 64},
        {"binding_ref": "7" * 64},
        {"root_scope": "7" * 64},
        {"policy_sha256": "7" * 64},
        {"host_id": "other"},
        {"defense_scope": "7" * 64},
        {"registry_scope": "7" * 64},
    ],
)
def test_revoke_cannot_rebind_identity_or_authorize_manual(tmp_path, change):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, _ = prepare(store)
    with pytest.raises(DefenseConflict):
        save_late_revoke(store, transaction, context(**change))


def test_same_revision_new_generation_reuses_mode_rid_with_fresh_query_only(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    original = sync_mode(store)
    current = context(epoch=2)
    assert store.mode_rid(current) == original.rid
    pending = store.register_mode_pending(
        original.rid, context=current, now=NOW + timedelta(seconds=121)
    )
    assert pending.context == current and pending.status == "pending"
    assert store.transaction(original.rid).context == original.context
    assert (
        store.begin_sendable(
            original.rid,
            "mode_sync",
            context=original.context,
            owner=OWNER,
            now=NOW + timedelta(seconds=121),
        )
        is None
    )
    receipt = reply(original, "query", "synced")  # byte-identical across both generations
    old = store.record_reply(
        original.rid, "query", receipt, context=original.context, now=NOW + timedelta(seconds=122)
    )
    assert old.reason == "stale" and not old.accepted
    current_pending = store.mode_ack(current)
    assert current_pending is not None and current_pending.status == "pending"
    assert store.record_reply(
        original.rid, "query", receipt, context=current, now=NOW + timedelta(seconds=123)
    ).accepted
    confirmed = store.mode_ack(current)
    assert confirmed is not None and confirmed.status == "confirmed"
    assert not store.latched(current.host_id, current.defense_scope)
    old = store.record_reply(
        original.rid, "query", receipt, context=original.context, now=NOW + timedelta(seconds=124)
    )
    assert old.reason == "stale" and store.mode_ack(current) == confirmed
    store.record_unavailable(
        original.rid, "query", context=original.context, now=NOW + timedelta(seconds=125)
    )
    assert store.mode_ack(current) == confirmed
    assert not store.latched(current.host_id, current.defense_scope)
    assert len(store.mode_ack_history(original.rid)) == 4
    with pytest.raises(DefenseConflict, match="generation is stale"):
        store.register_mode_pending(original.rid, context=original.context, now=NOW)
    assert DefenseStore(path).mode_ack(current) == confirmed


def test_ready_expired_cannot_revive_even_after_unknown_query(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, _ = prepare(store)
    assert action_reply(
        store,
        transaction,
        "ready_expired",
        changes={
            "reason_code": "cursor_expired",
        },
        now=NOW + timedelta(seconds=91),
    ).accepted
    confirmed = store.last_confirmed(transaction.rid)
    store.record_unavailable(transaction.rid, "query", now=NOW + timedelta(seconds=92))
    result = action_reply(store, transaction, "ready", now=NOW + timedelta(seconds=93))
    assert not result.accepted and result.reason == "terminal_regression"
    assert store.last_confirmed(transaction.rid) == confirmed
    assert confirmed is not None and confirmed.state == "ready"
    assert store.transaction(transaction.rid).phase == "unknown"
    assert store.latched(transaction.context.host_id, transaction.context.defense_scope)


def test_new_revoke_admission_cannot_authorize_original_prepare_or_apply(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    sync_mode(store)
    transaction, _, usage = prepare(store)
    current = context(global_revision=3, wire_revision=4, epoch=2)
    sync_mode(store, current)
    declaration = approval(store, transaction)
    store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="apply",
            request_id=transaction.rid,
            scope_sha256=transaction.context.root_scope,
            body=ActionBody(manifest_sha256=declaration.manifest_sha256, approval=declaration),
        ),
    )
    with pytest.raises(DefenseConflict, match="epoch changed"):
        store.begin_sendable(
            transaction.rid, "apply", context=current, owner=OWNER, usage=usage, now=NOW
        )
    pending, _, reservation = prepare(store, key="b" * 64, send=False)
    with pytest.raises(DefenseConflict, match="epoch changed"):
        store.begin_sendable(
            pending.rid, "prepare", context=current, owner=OWNER, usage=reservation, now=NOW
        )
    assert store.usage(usage.intent_key).state == "reserved"
    with pytest.raises(DefenseConflict):
        store.usage(reservation.intent_key)


def test_new_generation_ack_commit_failure_and_fresh_receipt_provenance(tmp_path, monkeypatch):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    mode = sync_mode(store)
    current = context(epoch=2)
    store.register_mode_pending(mode.rid, context=current, now=NOW)

    def fail(_):
        raise sqlite3.OperationalError("injected fresh mode query commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_commit", fail)
        with pytest.raises(sqlite3.OperationalError):
            store.record_reply(
                mode.rid, "query", reply(mode, "query", "synced"), context=current, now=NOW
            )
    pending = store.mode_ack(current)
    assert pending is not None and pending.status == "pending"
    # Even byte-identical old receipts are insufficient provenance for epoch2.
    old = store.mode_ack_history(mode.rid)[1]
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(
            "UPDATE defense_mode_ack SET status='confirmed',receipt_sha256=?,checked_at=?",
            (old.receipt_sha256, old.checked_at),
        )
    with pytest.raises(DefenseConflict, match="acknowledgement integrity"):
        store.mode_ack(current)


def test_service_reads_list_metadata_recover_intent_and_keep_latest_accepted(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    first, original = arm(store)
    second, _ = arm(store, ctx=context(host_id="other-host"))
    assert store.transactions(limit=1)[0].rid == second.rid
    assert tuple(item.rid for item in store.transactions("fake-host")) == (first.rid,)
    assert store.transactions("missing-host") == ()
    assert store.request(first.rid, "arm") == original
    assert store.latest_reply(first.rid) is None
    assert store.begin_sendable(first.rid, "arm", context=first.context, owner=OWNER, now=NOW)
    accepted = reply(first, "arm", "armed")
    store.record_reply(first.rid, "arm", accepted, context=first.context, now=NOW)
    store.record_unavailable(first.rid, "query", now=NOW + timedelta(seconds=1))
    assert store.latest_reply(first.rid) == accepted
    assert not hasattr(store.request(first.rid, "arm"), "request_bytes")
    for invalid in (True, 0, -1, 1001, "1"):
        with pytest.raises(ValueError):
            store.transactions(limit=cast(int, invalid))
    with pytest.raises(ValueError):
        store.transactions("fake host")


def test_service_read_interfaces_reject_corrupted_binding_or_hash(tmp_path):
    path = tmp_path / "security.sqlite3"
    store = DefenseStore(path)
    transaction, _ = arm(store)
    assert store.begin_sendable(
        transaction.rid, "arm", context=transaction.context, owner=OWNER, now=NOW
    )
    store.record_reply(
        transaction.rid,
        "arm",
        reply(transaction, "arm", "armed"),
        context=transaction.context,
        now=NOW,
    )
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE defense_observations SET receipt_sha256=?", ("0" * 64,))
        db.execute("UPDATE defense_requests SET request_sha256=?", ("0" * 64,))
    with pytest.raises(DefenseConflict, match="integrity"):
        store.latest_reply(transaction.rid)
    with pytest.raises(DefenseConflict, match="integrity"):
        store.request(transaction.rid, "arm")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE defense_transactions SET context_sha256=?", ("0" * 64,))
    with pytest.raises(DefenseConflict, match="integrity"):
        store.transactions()


def test_manual_ai_cost_requires_durable_advice_and_closed_source_reads(tmp_path):
    store = DefenseStore(tmp_path / "security.sqlite3")
    cursor, _ = arm(store, ctx=context(mode="manual"))
    ctx = cursor.context
    assert store.begin_sendable(cursor.rid, "arm", context=ctx, owner=OWNER, now=NOW)
    candidates = (
        DefenseCandidate(
            source_ref="c" * 32,
            source_alias="fixture-a",
            classification="eligible",
            distinct_failure_ports=5,
            evidence_sha256="d" * 64,
        ),
    )
    root = reply(cursor, "query", "armed", changes={"candidates": candidates})
    store.record_reply(cursor.rid, "query", root, context=ctx, now=NOW)
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    aliases = AliasMap(
        aliases=(
            DefenseAlias(
                candidate_alias="candidate-1",
                evidence_alias="evidence-1",
                source_ref="c" * 32,
                evidence_sha256="d" * 64,
            ),
        )
    )
    store.save_source("e" * 64, source, alias_map=aliases)
    usage = UsageClaim(
        intent_key="f" * 64,
        kind="ai",
        grant_ref="a" * 32,
        max_per_day=1,
        max_total=1,
        provider_fingerprint="b" * 64,
    )
    arguments = {
        "source_key": "e" * 64,
        "context": ctx,
        "owner": OWNER,
        "usage": usage,
        "analysis_id": "c" * 32,
        "input_digest": "d" * 64,
        "now": NOW,
    }
    with pytest.raises(DefenseConflict):
        store.begin_ai_usage(cursor.rid, advice_authorization=None, **arguments)
    authority = AIAdviceAuthorization(
        context_sha256=digest(ctx),
        consent_sha256="9" * 64,
        provider_fingerprint="b" * 64,
        confirmed_at=stamp(),
    )
    permit = store.begin_ai_usage(cursor.rid, advice_authorization=authority, **arguments)
    assert permit.advice_authorization == authority
    assert store.source("e" * 64) == (source, aliases)
    assert store.source_reply("e" * 64) == root
    assert store.ai_permit(analysis_id=permit.analysis_id) == permit
    assert store.ai_permit(intent_key=permit.intent_key) == permit
    assert store.ai_result(permit.analysis_id) is None
    assert store.unfinished_ai(ctx.host_id, ctx.defense_scope)
    assert not store.unfinished_ai(
        ctx.host_id, ctx.defense_scope, except_analysis_id=permit.analysis_id
    )
    assert store.mode_ack(ctx) is None
    empty = AliasMap(aliases=())
    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute(
            "UPDATE defense_sources SET alias_map=?,alias_sha256=? WHERE source_key=?",
            (canonical(empty), digest(empty), "e" * 64),
        )
    with pytest.raises(DefenseConflict):
        store.ai_permit(analysis_id=permit.analysis_id)


def test_controller_bounds_rederive_original_ledger_and_never_reset_after_query_or_restart(
    tmp_path,
):
    store = DefenseStore(tmp_path / "security.sqlite3")
    cursor, _ = arm(store)
    assert store.begin_sendable(cursor.rid, "arm", context=cursor.context, owner=OWNER, now=NOW)
    candidate = DefenseCandidate(
        source_ref="c" * 32,
        source_alias="fixture-a",
        classification="eligible",
        distinct_failure_ports=5,
        evidence_sha256="d" * 64,
    )
    root = reply(cursor, "query", "armed", changes={"candidates": (candidate,)})
    observed = NOW + timedelta(seconds=14.382)
    store.record_reply(cursor.rid, "query", root, context=cursor.context, now=observed)
    original = store.cursor_source(cursor.rid, host_scope="a" * 64)
    bounds = store.source_time_bounds(original)
    bounds.require(original, context=cursor.context, now=observed)
    later = NOW + timedelta(seconds=119)
    store.record_reply(cursor.rid, "query", root, context=cursor.context, now=later)
    refreshed = store.cursor_source(cursor.rid, host_scope="a" * 64)
    restarted = DefenseStore(store.path)
    refreshed_bounds = restarted.source_time_bounds(refreshed)
    assert refreshed_bounds._data.created_at == bounds._data.created_at == cursor.created_at
    assert refreshed_bounds._data.deadline_at == bounds._data.deadline_at == cursor.deadline_at
    refreshed_bounds.require(refreshed, now=later)
    with pytest.raises(DefenseConflict):
        refreshed_bounds.require(refreshed, now=NOW + timedelta(seconds=120))
    with pytest.raises(DefenseConflict):
        bounds.require(refreshed, now=later)
    # A shorter processing delay or a new observation never creates a fresh 30s budget.
    assert store.transaction(cursor.rid).deadline_at == cursor.deadline_at


@pytest.mark.parametrize("metadata", ["extended", "created_after_observation", "receipt_missing"])
def test_controller_bounds_never_fill_missing_or_invalid_original_time_metadata(tmp_path, metadata):
    store = DefenseStore(tmp_path / "security.sqlite3")
    cursor, _ = arm(store)
    assert store.begin_sendable(cursor.rid, "arm", context=cursor.context, owner=OWNER, now=NOW)
    root = reply(cursor, "query", "armed")
    observed = NOW + timedelta(seconds=14)
    store.record_reply(cursor.rid, "query", root, context=cursor.context, now=observed)
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    bounds = store.source_time_bounds(source)
    with closing(sqlite3.connect(store.path)) as connection, connection:
        if metadata == "extended":
            connection.execute(
                "UPDATE defense_transactions SET deadline_at=? WHERE rid=?",
                (stamp(121), cursor.rid),
            )
        elif metadata == "created_after_observation":
            connection.execute(
                "UPDATE defense_transactions SET created_at=? WHERE rid=?", (stamp(15), cursor.rid)
            )
        else:
            connection.execute("DELETE FROM defense_observations WHERE rid=?", (cursor.rid,))
    with pytest.raises(DefenseConflict):
        bounds.require(source, now=observed)
    with pytest.raises(DefenseConflict):
        store.source_time_bounds(source)
