"""Elapsed-time source refreshes retain one original session and paid proof."""

import json
import sqlite3
from datetime import timedelta

import httpx
import pytest
from test_defense_ai import OUTPUT, wire
from test_defense_session_coordinator import (
    REF,
    cost_counts,
    start,
)
from test_defense_session_coordinator import (
    harness as harness,
)
from test_defense_session_coordinator import (
    keyset as keyset,
)
from test_defense_session_coordinator import (
    no_real_transport as no_real_transport,
)
from test_defense_session_coordinator import (
    scene as scene,
)
from test_defense_session_coordinator import (
    target as target,
)

from opsark.automation_store import ModeChange
from opsark.control_modes import Mode
from opsark.defense_api import PrepareRequest
from opsark.defense_models import DefenseCandidate, digest
from opsark.defense_store import DefenseConflict


def advance(s, seconds=5.01):
    s.clock[0] += timedelta(seconds=seconds)
    return s.coordinator.tick(REF)


def slow_rpc(s, monkeypatch, *, seconds=9.99, after=None):
    original = s.service.invoker

    def invoke(target, call, role, *, admit=None, timeout=28):
        s.clock[0] += timedelta(seconds=seconds)
        result = original(target, call, role, admit=admit, timeout=timeout)
        if after is not None:
            after(call)
        return result

    monkeypatch.setattr(s.service, "invoker", invoke)


def paid_analysis(s, monkeypatch, *, seconds=19.99):
    def response(_request):
        s.clock[0] += timedelta(seconds=seconds)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(OUTPUT)},
                    }
                ]
            },
        )

    calls = wire(monkeypatch, s.provider_state, handler=response)
    start(s)
    assert s.coordinator.tick(REF).phase == "analyzing"
    assert advance(s).phase == "analysis_ready"
    return calls


def test_elapsed_ai_and_rpc_refresh_complete_without_repricing(scene, monkeypatch):
    s = scene(requires_ai=True)
    calls = paid_analysis(s, monkeypatch)
    selected = s.coordinator.get(REF).selection
    paid = s.coordinator.get(REF).ai_intent
    proof = s.store.ai_result(paid.analysis_id)
    deadline = s.store.transaction(s.cursor).deadline_at
    before_refresh = len(s.root.sent)
    slow_rpc(s, monkeypatch)
    record = advance(s)
    for _ in range(6):
        if record.phase == "completed":
            break
        record = advance(s)
    assert record.phase == record.effective_phase == "completed"
    assert record.selection == selected and record.ai_intent == paid
    assert s.store.ai_result(paid.analysis_id) == proof
    assert record.declaration.controller_deadline_at == deadline
    assert record.business_verdict == "pending"
    assert len(calls) == 1 and cost_counts(s) == (("ai", 1), ("execution", 1))
    assert sum(op == "arm" for op, _ in s.root.sent) == 1
    assert sum(op == "prepare" for op, _ in s.root.sent) == 1
    assert sum(op == "apply" for op, _ in s.root.sent) == 1
    assert {rid for op, rid in s.root.sent[before_refresh:] if op == "query"} <= {s.cursor}


def test_elapsed_rule_rpc_and_confirmation_keep_fresh_source(scene, monkeypatch):
    s = scene()
    start(s)
    assert s.coordinator.tick(REF).phase == "preparing"
    slow_rpc(s, monkeypatch)
    record = advance(s)
    for _ in range(6):
        if record.phase == "completed":
            break
        record = advance(s)
    assert record.phase == "completed"
    assert cost_counts(s) == (("execution", 1),)
    assert sum(op == "prepare" for op, _ in s.root.sent) == 1
    assert sum(op == "apply" for op, _ in s.root.sent) == 1


def test_refresh_permit_cannot_bypass_ordinary_thirty_second_fence(scene):
    s = scene()
    start(s)
    assert s.coordinator.tick(REF).phase == "preparing"
    s.clock[0] += timedelta(seconds=31)
    lease = s.coordinator._leases[REF]
    permit = s.coordinator.store.admit_refresh(
        REF, lease, expected_phase="preparing", now=s.clock[0]
    )
    s.coordinator.store.assert_refresh(permit, now=s.clock[0])
    with pytest.raises(DefenseConflict):
        s.coordinator.store.assert_live(permit, now=s.clock[0])
    with pytest.raises(DefenseConflict):
        s.coordinator.store.advance(permit, next_phase="prepared", now=s.clock[0])
    selected = s.coordinator.get(REF).selection
    sent = tuple(s.root.sent)
    with pytest.raises(DefenseConflict):
        s.service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=s.cursor,
                source_ref=selected.source_ref,
                expected_evidence_sha256=selected.evidence_sha256,
                expected_mode_revision=s.revision,
            ),
            session_admission=permit,
            worker_lease=lease,
            rpc_timeout=10,
        )
    assert tuple(s.root.sent) == sent
    assert cost_counts(s) == ()


@pytest.mark.parametrize("change", ["candidate", "evidence", "unavailable"])
def test_refresh_reply_must_match_all_original_evidence(scene, monkeypatch, change):
    s = scene(requires_ai=True)
    calls = paid_analysis(s, monkeypatch)
    original = s.root.reply

    def reply(request):
        result = original(request)
        if request.op == "query" and request.request_id == s.cursor:
            candidates = list(result.candidates)
            candidate = candidates[0]
            candidates[0] = (
                candidate.model_copy(update={"evidence_sha256": "f" * 64})
                if change == "evidence"
                else DefenseCandidate(
                    source_ref=candidate.source_ref,
                    source_alias=candidate.source_alias,
                    classification="insufficient",
                    distinct_failure_ports=0,
                    evidence_sha256=None,
                )
            )
            result = result.model_copy(update={"candidates": tuple(candidates)})
        return result

    if change == "unavailable":
        s.root.lose = "query"
    else:
        monkeypatch.setattr(s.root, "reply", reply)
    record = advance(s, 6)
    assert record.phase == "reconciliation_only" and len(calls) == 1
    assert cost_counts(s) == (("ai", 1),)
    assert not any(op in {"prepare", "apply"} for op, _ in s.root.sent)


@pytest.mark.parametrize("change", ["epoch", "stop", "mode", "grant", "expired"])
def test_refresh_receiver_rechecks_original_authority(scene, monkeypatch, change):
    s = scene(requires_ai=True)
    calls = paid_analysis(s, monkeypatch)
    before = s.coordinator.get(REF)
    original_selection = digest(before.selection)
    fired = []

    def mutate(call):
        if call.request.op != "query" or fired:
            return
        fired.append(True)
        if change == "epoch":
            lease = s.coordinator._leases[REF]
            s.store.release_worker(lease, now=s.clock[0])
            s.store.acquire_worker(s.service.owner, expires_at=lease.expires_at, now=s.clock[0])
        elif change == "stop":
            s.coordinator.stop(REF)
        elif change == "mode":
            s.mode.change_mode(ModeChange(mode=Mode.manual, expected_revision=s.revision))
        elif change == "grant":
            s.service.policy = s.service.policy.model_copy(
                update={
                    "execution": s.service.policy.execution.model_copy(
                        update={"grant_ref": "7" * 32}
                    )
                }
            )
        else:
            s.clock[0] += timedelta(seconds=120)

    slow_rpc(s, monkeypatch, seconds=0, after=mutate)
    record = advance(s, 6)
    assert fired and record.effective_phase == "reconciliation_only"
    assert digest(record.selection) == original_selection
    assert record.ai_intent == before.ai_intent and len(calls) == 1
    assert cost_counts(s) == (("ai", 1),)
    assert not any(op in {"prepare", "apply"} for op, _ in s.root.sent)
    with sqlite3.connect(s.store.path) as db:
        assert db.execute("SELECT count(*) FROM defense_session_actions_v1").fetchone()[0] == 0


def test_old_ai_selection_cannot_charge_after_its_fresh_window(scene, monkeypatch):
    s = scene(requires_ai=True)
    calls = wire(monkeypatch, s.provider_state)
    start(s)
    assert s.coordinator.tick(REF).phase == "analyzing"
    record = advance(s, 26)
    assert record.phase == "stopped" and record.stop_reason == "proof_changed"
    assert not calls and cost_counts(s) == ()
