"""Exact worker lease CAS in temporary SQLite only; never sends a request."""

import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from test_defense_api import NOW, ready, stamp
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.defense_models import ActionBody, DefenseApproval, DefenseRequest
from opsark.defense_store import DefenseConflict, DefenseStore


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def reject(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("Lease tests cannot access any network")

    monkeypatch.setattr(socket.socket, "connect", reject)
    yield
    assert not attempts


def at(seconds):
    return stamp(NOW + timedelta(seconds=seconds))


def lease_store(tmp_path):
    base = DefenseStore(tmp_path / "security.sqlite3")
    lease = base.acquire_worker("worker-a", expires_at=at(30), now=NOW)
    assert lease is not None
    return base, lease


def test_assert_worker_is_select_only_and_can_use_existing_write_transaction(tmp_path):
    base, lease = lease_store(tmp_path)
    assert base.assert_worker(lease, now=NOW) is None
    with base._write() as db:
        changes = db.total_changes
        assert base.assert_worker(lease, now=NOW, connection=db) is None
        assert db.total_changes == changes
    with base._connection() as db, pytest.raises(DefenseConflict):
        base.assert_worker(lease, now=NOW, connection=db)
    with sqlite3.connect(base.path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert base.assert_worker(lease, now=NOW, connection=db) is None
    with sqlite3.connect(tmp_path / "unrelated.sqlite3") as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(DefenseConflict):
            base.assert_worker(lease, now=NOW, connection=db)


@pytest.mark.parametrize(
    "field,value", [("owner", "worker-b"), ("epoch", 1), ("expires_at", "other")]
)
def test_assert_worker_requires_exact_owner_epoch_and_expiry(tmp_path, field, value):
    base, lease = lease_store(tmp_path)
    if field == "expires_at":
        value = at(31)
    changed = lease.model_copy(update={field: value})
    with pytest.raises(DefenseConflict):
        base.assert_worker(changed, now=NOW)
    base.assert_worker(lease, now=NOW)


def test_renewal_preserves_epoch_but_old_copy_cannot_assert_or_release_it(tmp_path):
    base, old = lease_store(tmp_path)
    current = base.renew_worker(old, expires_at=at(60), deadline_at=at(120), now=NOW)
    assert current.owner == old.owner and current.epoch == old.epoch
    assert current.expires_at == at(60)
    with pytest.raises(DefenseConflict):
        base.assert_worker(old, now=NOW)
    base.release_worker(old, now=NOW)
    base.assert_worker(current, now=NOW)
    with pytest.raises(DefenseConflict):
        base.renew_worker(old, expires_at=at(90), now=NOW)
    base.release_worker(current, now=NOW)
    with pytest.raises(DefenseConflict):
        base.assert_worker(current, now=NOW)
    with pytest.raises(DefenseConflict):
        base.renew_worker(current, expires_at=at(90), now=NOW)
    next_lease = base.acquire_worker(old.owner, expires_at=at(90), now=NOW)
    assert next_lease is not None and next_lease.epoch == old.epoch + 1
    base.release_worker(current, now=NOW)
    base.assert_worker(next_lease, now=NOW)


def test_two_independent_renewers_have_one_compare_and_swap_winner(tmp_path):
    first, old = lease_store(tmp_path)
    stores = (first, DefenseStore(first.path))
    barrier = Barrier(2)

    def renew(index):
        barrier.wait(timeout=3)
        try:
            return stores[index].renew_worker(old, expires_at=at(60 + index), now=NOW)
        except DefenseConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(renew, (0, 1)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    stores[0].assert_worker(winners[0], now=NOW)
    assert winners[0].epoch == old.epoch


@pytest.mark.parametrize("seconds", [30, 31, 120])
def test_expired_lease_cannot_be_renewed_or_revived_by_release(tmp_path, seconds):
    base, lease = lease_store(tmp_path)
    current_time = NOW + timedelta(seconds=seconds)
    with pytest.raises(DefenseConflict):
        base.assert_worker(lease, now=current_time)
    with pytest.raises(DefenseConflict):
        base.renew_worker(lease, expires_at=at(seconds + 60), now=current_time)
    base.release_worker(lease, now=current_time)
    with base._connection() as db:
        assert (
            db.execute("SELECT expires_at FROM defense_worker_lease").fetchone()[0]
            == lease.expires_at
        )
    fresh = base.acquire_worker("worker-b", expires_at=at(seconds + 90), now=current_time)
    assert fresh is not None and fresh.epoch == lease.epoch + 1


@pytest.mark.parametrize(
    "seconds,deadline", [(0, None), (29, None), (30, None), (301, None), (121, 120)]
)
def test_renewal_rejects_nonextension_lifetime_overflow_and_original_deadline(
    tmp_path, seconds, deadline
):
    base, lease = lease_store(tmp_path)
    with pytest.raises(DefenseConflict):
        base.renew_worker(
            lease,
            expires_at=at(seconds),
            deadline_at=None if deadline is None else at(deadline),
            now=NOW,
        )
    base.assert_worker(lease, now=NOW)


def test_renewal_accepts_exact_300_second_and_original_deadline_boundaries(tmp_path):
    base, lease = lease_store(tmp_path)
    boundary = base.renew_worker(lease, expires_at=at(300), now=NOW)
    base.assert_worker(boundary, now=NOW)
    base.release_worker(boundary, now=NOW)
    lease = base.acquire_worker("worker-a", expires_at=at(30), now=NOW)
    assert lease is not None
    boundary = base.renew_worker(lease, expires_at=at(120), deadline_at=at(120), now=NOW)
    base.assert_worker(boundary, now=NOW)


def unsubmitted_apply(h):
    revision, _, _, value = ready(h)
    action = h.store.transaction(value["request_id"])
    manifest = h.store.manifest(action.rid)
    approval = DefenseApproval(
        approval_id="9" * 32,
        purpose="apply",
        request_id=action.rid,
        manifest_sha256=manifest.sha256,
        approved_at=stamp(NOW),
        expires_at=at(60),
    )
    grant = h.service.policy.execution
    h.store.save_approval(
        action.rid,
        approval,
        context=action.context,
        controller_grant_ref=grant.grant_ref,
        root_grant_ref=grant.root_grant_refs["fixture"],
        now=NOW,
    )
    request = DefenseRequest(
        v=1,
        op="apply",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=ActionBody(manifest_sha256=manifest.sha256, approval=approval),
    )
    h.store.save_request(action.rid, request)
    return action, h.service._usage(action, grant), revision


def test_stale_sendable_lease_does_not_consume_approval_or_execution_reservation(harness):
    h = harness
    action, usage, _ = unsubmitted_apply(h)
    lease = h.store.acquire_worker(action.owner, expires_at=at(30), now=NOW)
    assert lease is not None
    fresh = h.store.renew_worker(lease, expires_at=at(60), deadline_at=action.deadline_at, now=NOW)
    before = (
        h.store.execution_usage(action.rid),
        h.store.approval_record(action.rid),
        h.store.request_metadata(action.rid, "apply"),
        tuple(h.root.sent),
    )
    with pytest.raises(DefenseConflict):
        h.store.begin_sendable(
            action.rid,
            "apply",
            context=action.context,
            owner=action.owner,
            usage=usage,
            lease=lease,
            now=NOW,
        )
    assert (
        h.store.execution_usage(action.rid),
        h.store.approval_record(action.rid),
        h.store.request_metadata(action.rid, "apply"),
        tuple(h.root.sent),
    ) == before
    permit = h.store.begin_sendable(
        action.rid,
        "apply",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=fresh,
        now=NOW,
    )
    assert permit is not None and permit.epoch == action.context.epoch
    assert h.store.execution_usage(action.rid).state == "consumed"
    assert h.store.approval_record(action.rid).dispatch_state == "used"
    assert tuple(h.root.sent) == before[-1]


def test_none_lease_keeps_existing_explicit_dispatch_path(harness):
    h = harness
    action, usage, _ = unsubmitted_apply(h)
    assert h.store.acquire_worker("other-worker", expires_at=at(60), now=NOW)
    permit = h.store.begin_sendable(
        action.rid,
        "apply",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=None,
        now=NOW,
    )
    assert permit is not None


def test_sendable_owner_must_match_even_with_an_otherwise_valid_lease(harness):
    h = harness
    action, usage, _ = unsubmitted_apply(h)
    lease = h.store.acquire_worker("different-owner", expires_at=at(60), now=NOW)
    assert lease is not None
    before = h.store.execution_usage(action.rid), h.store.approval_record(action.rid)
    with pytest.raises(DefenseConflict):
        h.store.begin_sendable(
            action.rid,
            "apply",
            context=action.context,
            owner=action.owner,
            usage=usage,
            lease=lease,
            now=NOW,
        )
    assert (h.store.execution_usage(action.rid), h.store.approval_record(action.rid)) == before
