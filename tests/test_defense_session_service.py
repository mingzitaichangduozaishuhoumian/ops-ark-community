"""Service-to-transport session fencing with synthetic ledgers and FakeRoot only."""

from datetime import timedelta

import pytest
from test_defense_api import EVIDENCE, NOW, SOURCE, PrepareRequest, stamp
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_store import admission, old_image
from test_defense_session_store import no_network_or_provider as no_network_or_provider
from test_defense_session_store import session as session

from opsark.defense_client import UnknownDefenseResult
from opsark.defense_store import DefenseConflict


def start(s):
    s.store.declare(s.declaration, now=NOW)
    s.store.advance(admission(s, "declared"), next_phase="observing", now=NOW)
    s.store.select_source(
        admission(s, "observing"), s.declaration.source, SOURCE, EVIDENCE, now=NOW
    )
    s.store.advance(admission(s, "observing"), next_phase="preparing", now=NOW)
    budgets = []
    root = s.h.root

    def bounded(target, call, role, *, admit=None, timeout=28):
        assert 0 < timeout <= 30
        budgets.append((call.request.op, timeout))
        return root(target, call, role, admit=admit)

    s.h.service.invoker = bounded
    return budgets


def prepare(s):
    return s.h.service.prepare(
        "fixture",
        PrepareRequest(
            cursor_request_id=s.declaration.cursor_rid,
            source_ref=SOURCE,
            expected_evidence_sha256=EVIDENCE,
            expected_mode_revision=s.declaration.runtime.context.global_revision,
        ),
        session_admission=admission(s, "preparing"),
        worker_lease=s.lease,
        rpc_timeout=10,
    )


def applying(s):
    action = prepare(s)
    assert action["phase"] == "ready"
    s.store.advance(admission(s, "preparing"), next_phase="prepared", now=NOW)
    s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
    return action


def apply(s, action):
    return s.h.service.automatic_apply(
        "fixture",
        action["request_id"],
        expected_mode_revision=s.declaration.runtime.context.global_revision,
        session_admission=admission(s, "applying"),
        worker_lease=s.lease,
        rpc_timeout=10,
    )


def test_session_service_prepares_and_applies_once_with_short_rpc_budget(session):
    s = session
    budgets = start(s)
    action = applying(s)
    result = apply(s, action)
    assert result["phase"] == "active" and not result["query_required"]
    s.store.advance(admission(s, "applying"), next_phase="confirmed", now=NOW)
    final = s.store.advance(admission(s, "confirmed"), next_phase="completed", now=NOW)
    assert final.business_verdict == "pending" and final.phase == "completed"
    assert budgets == [("query", 10), ("prepare", 10), ("apply", 10)]
    assert sum(op == "apply" for op, _ in s.h.root.sent) == 1
    assert s.h.store.execution_usage(action["request_id"]).state == "consumed"
    assert s.h.store.approval_record(action["request_id"], "apply") is None


def test_unfenced_public_prepare_cannot_take_the_bound_cursor(session):
    s = session
    start(s)
    image, sent = old_image(s.h.store), tuple(s.h.root.sent)
    with pytest.raises(DefenseConflict):
        s.h.service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=s.declaration.cursor_rid,
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=s.declaration.runtime.context.global_revision,
            ),
        )
    assert old_image(s.h.store) == image and tuple(s.h.root.sent) == sent


def test_session_lost_at_internal_query_admission_never_creates_action(session):
    s = session
    start(s)
    sent = tuple(s.h.root.sent)

    def lose():
        s.h.store.release_worker(s.lease, now=NOW)

    s.h.root.before_admit = lose
    with pytest.raises(DefenseConflict):
        prepare(s)
    assert tuple(s.h.root.sent) == sent
    assert not [row for row in s.h.store.transactions() if row.kind == "action"]


def test_lease_loss_before_apply_exec_keeps_consumed_intent_and_only_queries(session):
    s = session
    start(s)
    action = applying(s)
    applying_admission = admission(s, "applying")

    def lose():
        s.h.store.release_worker(s.lease, now=NOW)

    s.h.root.before_admit = lose
    with pytest.raises(DefenseConflict):
        apply(s, action)
    rid = action["request_id"]
    assert s.h.store.request_metadata(rid, "apply").dispatch_phase == "sendable"
    assert s.h.store.request_metadata(rid, "apply").reply_sha256 is None
    assert s.h.store.execution_usage(rid).state == "consumed"
    assert sum(op == "apply" for op, _ in s.h.root.sent) == 0
    before = len(s.h.root.sent)
    newer = s.h.store.acquire_worker(
        s.h.service.owner, expires_at=stamp(NOW + timedelta(seconds=110)), now=NOW
    )
    assert newer is not None and newer.epoch > s.lease.epoch
    with pytest.raises(DefenseConflict):
        s.store.assert_live(applying_admission, now=NOW)
    retained = s.h.service.automatic_apply(
        "fixture", rid, expected_mode_revision=s.declaration.runtime.context.global_revision
    )
    assert retained["request_id"] == rid
    assert s.h.root.sent[before:] == [("query", rid)]
    assert sum(op == "apply" for op, _ in s.h.root.sent) == 0


def test_reply_from_lost_owner_cannot_replace_sendable_with_confirmed(session):
    s = session
    start(s)
    action = applying(s)
    root = s.h.root

    def late(target, call, role, *, admit=None, timeout=28):
        result = root(target, call, role, admit=admit)
        s.h.store.release_worker(s.lease, now=NOW)
        return result

    s.h.service.invoker = late
    with pytest.raises(DefenseConflict):
        apply(s, action)
    rid = action["request_id"]
    assert s.h.store.request_metadata(rid, "apply").reply_sha256 is None
    assert not [row for row in s.h.store.observations(rid) if row.op == "apply"]
    assert sum(op == "apply" for op, _ in root.sent) == 1
    # The physical operation may have happened; a separate readonly query can
    # confirm it, without fabricating the missing direct operation receipt.
    s.h.service.invoker = root
    assert s.h.service.query("fixture", rid)["phase"] == "active"
    assert s.h.store.execution_usage(rid).state == "consumed"


def test_lease_lost_between_exec_and_stdin_is_not_hidden_by_client_normalization(session):
    s = session
    start(s)
    action = applying(s)
    root, stages = s.h.root, []

    def split_transport(target, call, role, *, admit=None, timeout=28):
        assert admit is not None
        admit()
        stages.append("exec")
        s.h.store.release_worker(s.lease, now=NOW)
        try:
            admit()
        except Exception:
            raise UnknownDefenseResult(call.request.request_id) from None
        stages.append("stdin")
        return root(target, call, role, admit=admit)

    s.h.service.invoker = split_transport
    with pytest.raises(DefenseConflict):
        apply(s, action)
    rid = action["request_id"]
    assert stages == ["exec"] and ("apply", rid) not in root.sent
    assert not [row for row in s.h.store.observations(rid) if row.op == "apply"]
    assert s.h.store.request_metadata(rid, "apply").dispatch_phase == "sendable"
    assert s.h.store.execution_usage(rid).state == "consumed"


def test_atomic_receipt_fence_rejects_loss_after_service_precommit_checkpoint(session, monkeypatch):
    s = session
    start(s)
    action = applying(s)
    record = s.h.store.record_reply

    def lose_before_receiver(rid, op, *args, **kwargs):
        if op == "apply":
            s.h.store.release_worker(s.lease, now=NOW)
        return record(rid, op, *args, **kwargs)

    monkeypatch.setattr(s.h.store, "record_reply", lose_before_receiver)
    with pytest.raises(DefenseConflict):
        apply(s, action)
    rid = action["request_id"]
    assert s.h.root.sent.count(("apply", rid)) == 1
    assert not [row for row in s.h.store.observations(rid) if row.op == "apply"]
    assert s.h.store.request_metadata(rid, "apply").reply_sha256 is None
    assert s.h.store.execution_usage(rid).state == "consumed"


@pytest.mark.parametrize("value", [0, -1, True, 31, float("nan"), float("inf")])
def test_session_rpc_budget_is_bounded_before_any_transport(session, value):
    s = session
    start(s)
    before = tuple(s.h.root.sent)
    with pytest.raises(DefenseConflict):
        s.h.service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=s.declaration.cursor_rid,
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=s.declaration.runtime.context.global_revision,
            ),
            session_admission=admission(s, "preparing"),
            worker_lease=s.lease,
            rpc_timeout=value,
        )
    assert tuple(s.h.root.sent) == before
