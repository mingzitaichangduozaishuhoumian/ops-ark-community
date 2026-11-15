"""Original-task following: fake Root, real ledgers, no model or real network."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from threading import Event

import pytest
from test_defense_api import apply, ready
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.automation_store import ModeChange
from opsark.control_modes import Mode
from opsark.defense_models import digest
from opsark.defense_store import DefenseConflict
from opsark.defense_task_watch import DefenseTaskWatcher
from opsark.defense_task_watch_store import DefenseTaskWatchStore


def watch(h, *, enabled=True):
    return DefenseTaskWatcher(
        h.service,
        DefenseTaskWatchStore(h.store),
        ("fixture",),
        30,
        clock=lambda: h.clock[0],
        enabled=enabled,
    )


def original_images(h):
    with closing(sqlite3.connect(h.store.path)) as db, db:
        return {
            table: db.execute("SELECT rowid,* FROM " + table).fetchall()  # noqa: S608 -- fixed tables only.
            for table in (
                "defense_requests",
                "defense_authorizations",
                "defense_usage",
                "defense_observation_intents",
                "defense_ai_intents",
            )
        }


def observations(h):
    with closing(sqlite3.connect(h.store.path)) as db, db:
        return db.execute("SELECT rowid,* FROM defense_observations ORDER BY rowid").fetchall()


def active_action(h, *, lost=False):
    revision, _, _, action = ready(h)
    if lost:
        h.root.lose = "apply"
        result = apply(h, revision, action)
        assert result["query_required"] and result["current_result"] is None
    else:
        apply(h, revision, action)
    return action["request_id"]


def test_disabled_never_runs_or_sends(harness):
    h = harness
    rid = active_action(h)
    w = watch(h, enabled=False)
    before, mode = tuple(h.root.sent), h.automation.status()
    assert not w.start() and w.tick() == {"queried": False, "state": None}
    assert w.status()["reason_code"] == "disabled"
    assert w.status()["counts"] == {"tasks": 0, "pending": 0, "alerts": 0, "unread": 0}
    assert tuple(h.root.sent) == before and h.automation.status() == mode
    assert h.store.transaction(rid).phase == "active"


def test_manual_following_dedup_ack_expiry_and_restart_keep_originals(harness):
    h = harness
    rid = active_action(h, lost=True)
    h.coordinator.change_mode(ModeChange(mode=Mode.manual, expected_revision=1))
    w = watch(h)
    before, mode, sent = original_images(h), h.automation.status(), tuple(h.root.sent)
    assert w.tick()["state"] == "active"
    assert h.root.sent[len(sent) :] == [("query", rid)]
    first = w.store.events()["events"][0]
    assert first["state"] == "active" and len(first["task_reference_sha256"]) == 64
    ack = w.store.ack(first["event_ref"], confirm_ack=True, now=h.clock[0])
    assert w.store.ack(first["event_ref"], now=h.clock[0] + timedelta(seconds=1)) == ack
    assert w.store.counts()["unread"] == 0
    assert not w.tick()["queried"]
    h.clock[0] += timedelta(seconds=30)
    assert w.tick()["state"] == "active"
    assert len(w.store.events()["events"]) == 1
    h.clock[0] += timedelta(seconds=31)
    h.root.records[rid]["state"] = "expired"
    assert w.tick()["state"] == "expired"
    assert [e["state"] for e in w.store.events()["events"]] == ["active", "expired"]
    restarted = watch(h)
    assert not restarted.tick()["queried"]
    assert original_images(h) == before and h.automation.status() == mode
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_unavailable_backoff_survives_restart_then_confirms_expiry(harness):
    h = harness
    rid = active_action(h)
    w = watch(h)
    h.root.lose = "query"
    assert w.tick()["state"] == "unavailable"
    sent = tuple(h.root.sent)
    restarted = watch(h)
    h.clock[0] += timedelta(seconds=59)
    assert not restarted.tick()["queried"] and tuple(h.root.sent) == sent
    h.clock[0] += timedelta(seconds=1)
    h.root.records[rid]["state"] = "expired"
    assert restarted.tick()["state"] == "expired"
    assert [e["state"] for e in restarted.store.events()["events"]] == ["unavailable", "expired"]


def test_prepare_without_apply_is_not_watched_and_late_apply_is_discovered(harness):
    h = harness
    revision, _, _, action = ready(h)
    w = watch(h)
    assert not w.tick()["queried"] and w.store.counts()["tasks"] == 0
    apply(h, revision, action)
    assert w.tick()["state"] == "active"
    assert w.store.events()["events"][0]["request_id"] == action["request_id"]


def test_discovery_advances_over_other_allowlists_without_losing_their_history(harness):
    h = harness
    rid = active_action(h)
    store = watch(h).store
    lease = store.acquire("discovery-owner", now=h.clock[0])
    assert store.discover(lease, ("another-registered-host",), now=h.clock[0]) == 1
    assert store.counts()["tasks"] == 0
    scope = digest({"host_ids": ("another-registered-host",), "kind": "original-apply-query/v1"})
    with h.store._connection() as db:
        cursor = db.execute(
            "SELECT after_sequence FROM defense_task_watch_discovery_v1 WHERE scope_sha256=?",
            (scope,),
        ).fetchone()[0]
        assert (
            cursor
            == db.execute(
                "SELECT rowid FROM defense_requests WHERE rid=? AND op='apply'", (rid,)
            ).fetchone()[0]
        )
    assert store.discover(lease, ("another-registered-host",), now=h.clock[0]) == 0
    # A different explicit allowlist gets its own cursor, rather than silently
    # losing this old original apply to the other deployment's scan position.
    assert store.discover(lease, ("fixture",), now=h.clock[0]) == 1
    assert store.counts()["tasks"] == 1


def test_discovery_backlog_is_visible_until_current_scope_cursor_catches_up(harness):
    h = harness
    active_action(h)
    w = watch(h)
    # No event yet cannot masquerade as a completed initial history pass.
    assert w.status()["counts"]["alerts"] == 0
    assert w.status()["discovery_incomplete"] is True
    w.tick()
    assert w.status()["discovery_incomplete"] is False
    disabled = watch(h, enabled=False)
    assert disabled.status()["discovery_incomplete"] is False
    assert disabled.status()["reason_code"] == "disabled"


def test_ready_query_during_apply_dispatch_does_not_lose_later_unknown(harness, monkeypatch):
    h = harness
    revision, _, _, action = ready(h)
    rid = action["request_id"]
    w = watch(h)
    dispatch = h.service._dispatch

    def query_before_sender(transaction, request, context, permit):
        if request.op == "apply":
            assert w.tick()["state"] == "ready"
        return dispatch(transaction, request, context, permit)

    monkeypatch.setattr(h.service, "_dispatch", query_before_sender)
    h.root.lose = "apply"
    result = apply(h, revision, action)
    assert result["query_required"] and result["phase"] == "unknown"
    assert w.store.counts()["pending"] == 1
    h.clock[0] += timedelta(seconds=31)
    sent = tuple(h.root.sent)
    assert w.tick()["state"] == "active"
    assert h.root.sent[len(sent) :] == [("query", rid)]
    assert [row["state"] for row in w.store.events()["events"]] == ["ready", "active"]
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_final_admission_rejects_expired_owner_without_base_observation(harness):
    h = harness
    active_action(h)
    w = watch(h)
    before, sent, leases = observations(h), tuple(h.root.sent), []

    def lose_owner():
        h.clock[0] += timedelta(seconds=121)
        leases.append(w.store.acquire("replacement-worker", now=h.clock[0]))

    h.root.before_admit = lose_owner
    assert not w.tick()["queried"]
    assert observations(h) == before and tuple(h.root.sent) == sent
    assert w.store.events()["events"] == [] and leases[0] is not None
    # The stale worker's finally release cannot erase the replacement lease.
    assert w.store.acquire("third-worker", now=h.clock[0]) is None


def test_atomic_base_commit_fence_rejects_owner_change_after_last_checkpoint(harness, monkeypatch):
    h = harness
    active_action(h)
    w = watch(h)
    before = observations(h)
    original = h.store.record_reply

    def replace_before_sql(*args, **kwargs):
        if args[1] == "query":
            h.clock[0] += timedelta(seconds=121)
            assert w.store.acquire("replacement-before-commit", now=h.clock[0]) is not None
        return original(*args, **kwargs)

    monkeypatch.setattr(h.store, "record_reply", replace_before_sql)
    assert not w.tick()["queried"]
    assert observations(h) == before and w.store.events()["events"] == []


def test_stop_at_final_admit_does_not_send_or_create_unavailable(harness):
    h = harness
    active_action(h)
    w = watch(h)
    before, sent = observations(h), tuple(h.root.sent)
    h.root.before_admit = lambda: w.stop(timeout=0)
    assert not w.tick()["queried"]
    assert observations(h) == before and tuple(h.root.sent) == sent
    assert w.status()["reason_code"] == "stopped"


def test_public_pin_change_at_final_admit_is_reported_without_unavailable(harness):
    h = harness
    active_action(h)
    w = watch(h)
    before, sent = observations(h), tuple(h.root.sent)
    h.root.before_admit = lambda: h.target.readonly.known_hosts_file.write_bytes(
        b"synthetic replaced public pin\n"
    )
    assert w.tick() == {"queried": False, "state": "registration_changed"}
    assert observations(h) == before and tuple(h.root.sent) == sent
    assert w.store.events()["events"][0]["state"] == "registration_changed"


def test_store_failure_is_fixed_status_without_transport_or_exception_text(harness, monkeypatch):
    h = harness
    active_action(h)
    w = watch(h)
    sent = tuple(h.root.sent)

    def broken(*_args, **_kwargs):
        raise sqlite3.OperationalError("synthetic private error must not escape")

    monkeypatch.setattr(w.store, "discover", broken)
    assert w.tick() == {"queried": False, "state": None}
    assert tuple(h.root.sent) == sent
    status = w.status()
    assert status["reason_code"] == "store_unavailable"
    assert "synthetic private" not in str(status)


@pytest.mark.parametrize("change", ["pin", "retired"])
def test_registration_change_reports_locally_without_root_call(harness, change):
    h = harness
    active_action(h)
    w = watch(h)
    before, sent = observations(h), tuple(h.root.sent)
    if change == "pin":
        h.target.readonly.known_hosts_file.write_bytes(b"untrusted synthetic changed pin\n")
    else:
        h.service.targets.clear()
    assert w.tick() == {"queried": False, "state": "registration_changed"}
    assert observations(h) == before and tuple(h.root.sent) == sent
    assert w.store.events()["events"][0]["state"] == "registration_changed"
    assert not w.tick()["queried"]


def test_lease_renewal_and_result_cas_preserve_old_claim(harness):
    h = harness
    active_action(h)
    store = watch(h).store
    first = store.acquire("owner-a", now=h.clock[0])
    store.discover(first, ("fixture",), now=h.clock[0])
    claim = store.claim_due(first, ("fixture",), now=h.clock[0])
    h.clock[0] += timedelta(seconds=1)
    renewed = store.renew(first, now=h.clock[0])
    with pytest.raises(DefenseConflict):
        store.assert_claim(first, claim, now=h.clock[0])
    store.release(first, now=h.clock[0])
    store.assert_claim(renewed, claim, now=h.clock[0])
    assert store.acquire("owner-b", now=h.clock[0]) is None
    h.clock[0] += timedelta(seconds=121)
    second = store.acquire("owner-b", now=h.clock[0])
    assert second.epoch > first.epoch
    with pytest.raises(DefenseConflict):
        store.finish(renewed, claim, "expired", interval_seconds=30, now=h.clock[0])
    replacement = store.claim_due(second, ("fixture",), now=h.clock[0])
    assert replacement.attempt == claim.attempt + 1 and replacement.claim_ref != claim.claim_ref
    with h.store._connection() as db:
        assert (
            db.execute(
                "SELECT finished_at FROM defense_task_watch_attempts_v1 WHERE claim_ref=?",
                (claim.claim_ref,),
            ).fetchone()[0]
            is None
        )


def test_budget_and_event_capacity_stop_without_deleting_history(harness, monkeypatch):
    h = harness
    active_action(h)
    w = watch(h)
    monkeypatch.setattr("opsark.defense_task_watch_store.MAX_EVENTS", 2)
    assert w.tick()["state"] == "active"
    first = w.store.events()["events"][0]
    h.clock[0] += timedelta(seconds=30)
    sent = tuple(h.root.sent)
    assert not w.tick()["queried"] and tuple(h.root.sent) == sent
    rows = w.store.events()["events"]
    assert rows[0] == first and [r["state"] for r in rows] == ["active", "capacity_limit"]
    assert w.store.counts()["pending"] == 0


def test_daily_and_total_query_budget_are_durable(harness, monkeypatch):
    h = harness
    active_action(h)
    w = watch(h)
    monkeypatch.setattr("opsark.defense_task_watch_store.MAX_DAILY_ATTEMPTS", 1)
    monkeypatch.setattr("opsark.defense_task_watch_store.MAX_ATTEMPTS", 2)
    h.root.lose = "query"
    assert w.tick()["state"] == "unavailable"
    h.clock[0] += timedelta(seconds=60)
    sent = tuple(h.root.sent)
    assert not w.tick()["queried"] and tuple(h.root.sent) == sent
    assert w.store.events()["events"][-1]["state"] == "daily_limit"
    h.clock[0] = h.clock[0].replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    h.root.lose = "query"
    restarted = watch(h)
    assert restarted.tick()["state"] == "unavailable"
    h.clock[0] += timedelta(seconds=120)
    sent = tuple(h.root.sent)
    assert not restarted.tick()["queried"] and tuple(h.root.sent) == sent
    assert restarted.store.events()["events"][-1]["state"] == "attempt_limit"


def test_only_one_worker_queries_and_thread_stop_is_bounded(harness):
    h = harness
    active_action(h)
    first, second = watch(h), watch(h)
    entered, release = Event(), Event()

    def block():
        entered.set()
        assert release.wait(5)

    h.root.before_admit = block
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(first.tick)
        assert entered.wait(5)
        sent = tuple(h.root.sent)
        assert not second.tick()["queried"] and tuple(h.root.sent) == sent
        release.set()
        assert running.result(timeout=5)["state"] == "active"
    assert first.start()
    assert first.stop(timeout=5)
    assert not first.status()["running"]


@pytest.mark.parametrize("value", [False, 1, "yes", None])
def test_ack_requires_exact_confirmation_and_does_not_change_authority(harness, value):
    h = harness
    active_action(h)
    w = watch(h)
    w.tick()
    event = w.store.events()["events"][0]
    original, mode = original_images(h), h.automation.status()
    with pytest.raises(DefenseConflict):
        w.store.ack(event["event_ref"], confirm_ack=value, now=h.clock[0])
    assert original_images(h) == original and h.automation.status() == mode


def test_event_pagination_is_stable_and_summary_fields_are_fixed(harness):
    h = harness
    rid = active_action(h)
    w = watch(h)
    w.tick()
    h.clock[0] += timedelta(seconds=30)
    h.root.records[rid]["state"] = "expired"
    w.tick()
    first = w.store.events(limit=1)
    second = w.store.events(after_sequence=first["next_after_sequence"], limit=1)
    assert first["events"][0]["state"] == "active" and second["events"][0]["state"] == "expired"
    assert second["next_after_sequence"] is None
    assert set(first["events"][0]) == {
        "event_ref",
        "sequence",
        "task_reference_sha256",
        "host_id",
        "request_id",
        "state",
        "observed_at",
        "acknowledged_at",
    }
