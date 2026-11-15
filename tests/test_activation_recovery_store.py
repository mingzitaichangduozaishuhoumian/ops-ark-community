"""Durability, evidence bounds and exact-cause transactions for the new ledger."""

import copy
import json
import sqlite3
from datetime import timedelta

import pytest
from test_activation_recovery_controller import (
    HOST,
    RECOVERY,
    prepare,
    quotas,
    sealed,
    submit,
)
from test_activation_recovery_controller import activation as activation
from test_activation_recovery_controller import env as env
from test_activation_recovery_controller import recovered_activation as recovered_activation

from opsark import activation_recovery_store as ledger
from opsark.automatic_store import canonical, digest


def saved_args(record):
    return {
        "scope_hash": record["scope_hash"],
        "controller_policy_digest": record["controller_policy_digest"],
        "original_job": record["original_job"],
        "original_activation": record["original_activation"],
        "latch": record["latch_before"],
    }


def test_identity_cannot_be_overwritten_or_auto_approved(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    record = r.store.get(HOST, RECOVERY)
    usage, latch = quotas(r), r.e.auto.latch(HOST)
    changed = saved_args(record)
    changed["controller_policy_digest"] = "c" * 64
    with pytest.raises(ValueError, match="immutable"):
        r.store.save_plan(HOST, plan, **changed, now=r.e.clock)
    assert r.store.get(HOST, RECOVERY) == record
    assert quotas(r) == usage and r.e.auto.latch(HOST) == latch


def test_new_identity_and_fact_budgets_never_evict_history(recovered_activation, monkeypatch):
    r = recovered_activation
    prepare(r)
    record = r.store.get(HOST, RECOVERY)
    original = r.store.list()
    second = copy.deepcopy(record["plan"])
    second["recovery_id"] = "c" * 32
    sealed(second, "recovery_digest")
    monkeypatch.setattr(ledger, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="full"):
        r.store.save_plan(HOST, second, **saved_args(record), now=r.e.clock)
    monkeypatch.setattr(ledger, "MAX_RECORDS", 1000)
    second["verification"]["large_fact"] = "x" * ledger.MAX_RECORD_BYTES
    sealed(second, "recovery_digest")
    with pytest.raises(ValueError, match="budget"):
        r.store.save_plan(HOST, second, **saved_args(record), now=r.e.clock)
    assert r.store.list() == original and r.e.auto.latch(HOST)


def test_durable_intent_budget_failure_rolls_back_before_transport(
    recovered_activation, monkeypatch
):
    r = recovered_activation
    plan = prepare(r)
    usage = quotas(r)
    monkeypatch.setattr(ledger, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(ValueError, match="full"):
        r.store.begin_submission(
            HOST, RECOVERY, plan["recovery_digest"], plan["mode_revision"], now=r.e.clock
        )
    assert r.store.get(HOST, RECOVERY)["status"] == "prepared"
    assert not any(call["op"] == "activation_recovery_submit" for call in r.calls)
    assert quotas(r) == usage and r.e.auto.latch(HOST)


def test_two_previews_cannot_create_parallel_unresolved_approvals(recovered_activation):
    r = recovered_activation
    first = prepare(r)
    r.next_id = "c" * 32
    second = prepare(r)
    r.store.begin_submission(
        HOST, first["recovery_id"], first["recovery_digest"], first["mode_revision"], now=r.e.clock
    )
    with pytest.raises(ValueError, match="unresolved"):
        r.store.begin_submission(
            HOST,
            second["recovery_id"],
            second["recovery_digest"],
            second["mode_revision"],
            now=r.e.clock,
        )
    assert r.store.get(HOST, second["recovery_id"])["status"] == "prepared"
    assert r.e.auto.latch(HOST)


@pytest.mark.parametrize("race", ["unavailable", "different_snapshot", "old_snapshot"])
def test_release_requires_same_fresh_current_remote_row(recovered_activation, race):
    r = recovered_activation
    plan = prepare(r)
    r.loss = True
    assert submit(r, plan)["status"] == "unknown"
    receipt = r.receipts[RECOVERY]
    fresh = r.e.service.refresh_automatic_status(HOST)
    target = r.e.service.target(HOST)
    if race == "unavailable":
        r.e.auto.mark_remote_unavailable(
            HOST, fresh["scope_hash"], target.policy_digest, now=r.e.clock
        )
    elif race == "different_snapshot":
        r.e.root_safety["updated_at"] = (r.e.clock + timedelta(seconds=1)).isoformat()
        r.e.service.refresh_automatic_status(HOST)
    else:
        r.e.clock += timedelta(seconds=61)
    with pytest.raises(ValueError, match="fresh"):
        r.store.complete(HOST, RECOVERY, receipt, fresh, now=r.e.clock)
    assert r.store.get(HOST, RECOVERY)["local_released"] is False
    assert r.e.auto.latch(HOST)


def test_cached_immutable_anchor_and_list_limit_fail_closed(recovered_activation):
    r = recovered_activation
    prepare(r)
    for value in [0, True, 1001]:
        with pytest.raises(ValueError, match="budget"):
            r.store.list(limit=value)
    with sqlite3.connect(r.store.path) as connection:
        row = connection.execute("SELECT payload FROM activation_recoveries").fetchone()
        value = json.loads(row[0])
        value["original_activation"]["activation_id"] = "d" * 32
        connection.execute("UPDATE activation_recoveries SET payload=?", (canonical(value),))
    with pytest.raises(ValueError, match="binding"):
        r.store.get(HOST, RECOVERY)
    assert r.e.auto.latch(HOST)


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("corruption", ["orphan", "bad_receipt", "wrong_activation"])
def test_late_root_snapshot_requires_intact_new_source_even_with_inactive_fallback(
    recovered_activation, fallback, corruption
):
    r = recovered_activation
    plan = prepare(r)
    original_pause = copy.deepcopy(r.e.root_safety)
    assert submit(r, plan)["local_released"]
    with sqlite3.connect(r.store.path) as connection:
        if fallback:
            connection.execute("DELETE FROM automatic_resolved_causes")
        if corruption == "orphan":
            connection.execute("DELETE FROM activation_recoveries")
        else:
            value = json.loads(
                connection.execute("SELECT payload FROM activation_recoveries").fetchone()[0]
            )
            if corruption == "bad_receipt":
                value["receipt"]["verification"]["fresh_ssh"]["passed"] = False
                sealed(value["receipt"], "receipt_digest")
                # Keep both lookup aliases consistent, so receipt facts must be checked.
                receipt_digest = value["receipt"]["receipt_digest"]
                connection.execute(
                    "UPDATE automatic_resolved_causes SET receipt_digest=?", (receipt_digest,)
                )
                latch = json.loads(
                    connection.execute("SELECT payload FROM automatic_latches").fetchone()[0]
                )
                latch["resolution"]["receipt_digest"] = receipt_digest
                connection.execute("UPDATE automatic_latches SET payload=?", (canonical(latch),))
            else:
                value["original_activation"]["result"]["verification"]["fresh_ssh"]["passed"] = (
                    False
                )
            connection.execute("UPDATE activation_recoveries SET payload=?", (canonical(value),))
    r.e.root_safety = original_pause
    remote = r.e.service.refresh_automatic_status(HOST)
    assert remote["status"] == "available" and remote["remote"]["safety"]["paused"]
    assert r.e.auto.latch(HOST)["remote_safety"] == original_pause


def test_corrupt_cause_index_cannot_use_otherwise_valid_inactive_fallback(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    original_pause = copy.deepcopy(r.e.root_safety)
    assert submit(r, plan)["local_released"]
    with sqlite3.connect(r.store.path) as connection:
        connection.execute("UPDATE automatic_resolved_causes SET receipt_digest=?", ("f" * 64,))
    r.e.root_safety = original_pause
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST)["remote_safety"] == original_pause


def test_genuine_new_inactive_fallback_and_new_pause_are_distinct(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    original_pause = copy.deepcopy(r.e.root_safety)
    assert submit(r, plan)["local_released"]
    with sqlite3.connect(r.store.path) as connection:
        connection.execute("DELETE FROM automatic_resolved_causes")
    r.e.root_safety = copy.deepcopy(original_pause)
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST) is None
    r.e.root_safety["updated_at"] = (r.e.clock + timedelta(seconds=1)).isoformat()
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST)["remote_safety"] == r.e.root_safety
    current = r.e.auto.latch(HOST)
    r.e.root_safety = original_pause
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST) == current


def test_saved_root_receipt_unknown_can_suppress_only_old_snapshot_without_local_release(
    recovered_activation,
):
    r = recovered_activation
    plan = prepare(r)
    original_pause = copy.deepcopy(r.e.root_safety)
    r.loss = True
    assert submit(r, plan)["status"] == "unknown"
    before = r.e.auto.latch(HOST)
    r.store.outcome(
        HOST,
        RECOVERY,
        "unknown",
        receipt=r.receipts[RECOVERY],
        detail="Root receipt persisted; local fresh-state read not yet complete",
        now=r.e.clock,
    )
    r.e.root_safety = original_pause
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST) == before
    assert r.store.get(HOST, RECOVERY)["local_released"] is False


@pytest.mark.parametrize(
    "authorization,status", [("assisted", "installed_restart_pending"), ("automatic", "failed")]
)
def test_resealed_historical_source_cannot_change_original_parent_kind(
    recovered_activation, authorization, status
):
    r = recovered_activation
    prepare(r)
    value = r.store.get(HOST, RECOVERY)
    value["original_job"].update(authorization=authorization, status=status)
    value["job_digest"] = digest(value["original_job"])
    value["plan"]["job_digest"] = value["job_digest"]
    value["original_activation"]["original_job"] = copy.deepcopy(value["original_job"])
    value["original_activation"]["job_digest"] = value["job_digest"]
    with pytest.raises(ValueError, match="source binding"):
        ledger.verified_source(value)


@pytest.mark.parametrize("mutation", ["missing_ledger", "extra_field", "bad_ledger_digest"])
def test_resealed_source_still_requires_fixed_native_schema(recovered_activation, mutation):
    r = recovered_activation
    plan = prepare(r)
    original_pause = copy.deepcopy(r.e.root_safety)
    assert submit(r, plan)["local_released"]
    with sqlite3.connect(r.store.path) as connection:
        value = json.loads(
            connection.execute("SELECT payload FROM activation_recoveries").fetchone()[0]
        )
        if mutation == "missing_ledger":
            del value["plan"]["ledger_digest"]
            del value["receipt"]["ledger_digest"]
        elif mutation == "extra_field":
            value["plan"]["unexpected_anchor"] = "a" * 64
            value["receipt"]["unexpected_anchor"] = "a" * 64
        else:
            value["plan"]["ledger_digest"] = "invalid"
            value["receipt"]["ledger_digest"] = "invalid"
        sealed(value["plan"], "recovery_digest")
        value["recovery_digest"] = value["plan"]["recovery_digest"]
        value["receipt"]["recovery_digest"] = value["recovery_digest"]
        value["receipt"]["plan"] = copy.deepcopy(value["plan"])
        sealed(value["receipt"], "receipt_digest")
        connection.execute(
            "UPDATE activation_recoveries SET payload=?,anchor_digest=?",
            (canonical(value), ledger._anchor(value)),
        )
        receipt_digest = value["receipt"]["receipt_digest"]
        connection.execute(
            "UPDATE automatic_resolved_causes SET receipt_digest=?", (receipt_digest,)
        )
        latch = json.loads(
            connection.execute("SELECT payload FROM automatic_latches").fetchone()[0]
        )
        latch["resolution"]["receipt_digest"] = receipt_digest
        connection.execute("UPDATE automatic_latches SET payload=?", (canonical(latch),))
    r.e.root_safety = original_pause
    r.e.service.refresh_automatic_status(HOST)
    assert r.e.auto.latch(HOST)["remote_safety"] == original_pause
