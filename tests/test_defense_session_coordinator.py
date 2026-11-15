"""Explicit one-window coordination; tmp-only Root and provider transports."""

import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from threading import Lock
from types import SimpleNamespace

import httpx
import pytest
from test_defense_ai import OUTPUT, wire
from test_defense_api import ArmRequest, FakeRoot, defense_service_scope, policy
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark import ai_provider
from opsark.automation_store import AutomationStore, ModeChange
from opsark.config import Settings
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_ai import DefenseAIService
from opsark.defense_api import DefenseService
from opsark.defense_models import DefenseCandidate
from opsark.defense_policy import DefenseAIConsent
from opsark.defense_session import DefenseSessionCoordinator
from opsark.defense_store import DefenseConflict, DefenseStore
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope

REF = "8" * 32


@pytest.fixture(autouse=True)
def no_real_transport(monkeypatch):
    import paramiko

    attempted = []

    def deny(*_args, **_kwargs):
        attempted.append(True)
        raise AssertionError("Coordinator tests only use synthetic transports")

    async def deny_async(*args, **kwargs):
        return deny(*args, **kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", deny)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_async)
    yield
    assert not attempted


@pytest.fixture
def scene(harness, tmp_path):
    def build(*, requires_ai=False):
        settings = Settings(
            tmp_path,
            "synthetic-coordinator-console-key-only",
            ai_base_url="https://synthetic-coordinator-provider.invalid/v1"
            if requires_ai
            else None,
            ai_key="synthetic-coordinator-provider-key-only" if requires_ai else None,
            ai_model="synthetic-coordinator-model" if requires_ai else None,
        )
        consent = DefenseAIConsent(
            enabled=requires_ai,
            provider_fingerprint=ai_provider.provider_fingerprint(settings)
            if requires_ai
            else None,
            requires_ai=requires_ai,
        )
        deployment = policy(harness.target, ai=consent.model_dump(mode="json"))
        scope = defense_service_scope({"fixture": harness.target}, deployment)
        assert scope is not None
        participant = ModeParticipant("ssh-defense", scope, lambda _: False)
        automation = AutomationStore(
            tmp_path / "coordinator-automation.sqlite3",
            ControlPolicy(),
            supplemental_scope=supplemental_scope((participant,)),
        )
        store = DefenseStore(tmp_path / "coordinator-security.sqlite3")
        root = FakeRoot(harness.target, lambda: harness.clock[0])
        budgets = []

        def invoke(target, call, role, *, admit=None, timeout=28):
            assert 0 < timeout <= 30
            budgets.append((call.request.op, timeout))
            return root(target, call, role, admit=admit)

        service = DefenseService(
            settings,
            {"fixture": harness.target},
            store,
            automation,
            policy=deployment,
            mode_lock=Lock(),
            invoker=invoke,
            clock=lambda: harness.clock[0],
        )
        channel = service.participant()
        assert channel is not None
        mode = ModeCoordinator(automation, service.mode_lock, (channel,))
        service.coordinator = mode
        provider_state = {"settings": settings}
        ai = DefenseAIService(
            store,
            lambda: provider_state["settings"],
            current_snapshot=service.ai_snapshot,
            validate_admission=service.validate_ai_admission,
            now=service.clock,
        )
        service.ai_service = ai
        changed = mode.change_mode(ModeChange(mode=Mode.automatic, expected_revision=0))
        cursor = service.arm(
            "fixture", ArmRequest(expected_mode_revision=changed["revision"], confirm_arm=True)
        )
        coordinator = DefenseSessionCoordinator(service)
        return SimpleNamespace(
            service=service,
            root=root,
            mode=mode,
            store=store,
            automation=automation,
            coordinator=coordinator,
            cursor=cursor["request_id"],
            revision=changed["revision"],
            clock=harness.clock,
            budgets=budgets,
            provider_state=provider_state,
            ai=ai,
        )

    return build


def start(s, reference=REF):
    return s.coordinator.start(
        "fixture", s.cursor, expected_mode_revision=s.revision, session_ref=reference
    )


def finish(s, *, limit=10):
    result = s.coordinator.get(REF)
    for _ in range(limit):
        result = s.coordinator.tick(REF)
        if result.effective_phase in {"completed", "stopped", "expired", "reconciliation_only"}:
            break
    return result


def cost_counts(s):
    with closing(sqlite3.connect(s.store.path)) as db, db:
        return tuple(
            db.execute(
                "SELECT kind,count(*) FROM defense_usage GROUP BY kind ORDER BY kind"
            ).fetchall()
        )


def test_deterministic_one_action_and_duplicate_ticks_never_repeat(scene):
    s = scene()
    initial = start(s)
    deadline = s.store.transaction(s.cursor).deadline_at
    sent = tuple(s.root.sent)
    assert start(s) == initial and tuple(s.root.sent) == sent
    final = finish(s)
    assert final.phase == final.effective_phase == "completed"
    assert final.business_verdict == "pending" and final.ai_intent is None
    assert final.declaration.controller_deadline_at == deadline
    assert sum(op == "arm" for op, _ in s.root.sent) == 1
    assert sum(op == "prepare" for op, _ in s.root.sent) == 1
    assert sum(op == "apply" for op, _ in s.root.sent) == 1
    assert cost_counts(s) == (("execution", 1),)
    sent = tuple(s.root.sent)
    assert s.coordinator.tick(REF) == final and tuple(s.root.sent) == sent
    assert s.coordinator.status()["continuous_execution"] is False
    assert all(timeout == 10 for op, timeout in s.budgets if op in {"prepare", "apply"})


def test_empty_cursor_waits_for_candidate_in_same_original_window(scene, monkeypatch):
    s = scene()
    available = [False]
    reply = s.root.reply

    def candidate_state(request):
        result = reply(request)
        if request.request_id == s.cursor and request.op == "query" and not available[0]:
            return result.model_copy(
                update={
                    "candidates": tuple(
                        DefenseCandidate(
                            source_ref=c.source_ref,
                            source_alias=c.source_alias,
                            classification="insufficient",
                            distinct_failure_ports=0,
                            evidence_sha256=None,
                        )
                        for c in result.candidates
                    )
                }
            )
        return result

    monkeypatch.setattr(s.root, "reply", candidate_state)
    initial = start(s)
    assert initial.phase == "observing" and initial.selection is None
    first_sent = tuple(s.root.sent)
    assert s.coordinator.tick(REF).selection is None and tuple(s.root.sent) == first_sent
    available[0] = True
    s.clock[0] += timedelta(seconds=5)
    selected = s.coordinator.tick(REF)
    assert selected.selection is not None and selected.phase == "preparing"
    assert selected.declaration.controller_deadline_at == initial.declaration.controller_deadline_at
    assert finish(s).phase == "completed"


def test_ai_proposal_has_single_fee_and_original_gates_then_one_action(scene, monkeypatch):
    s = scene(requires_ai=True)
    calls = wire(monkeypatch, s.provider_state)
    start(s)
    final = finish(s)
    assert final.phase == "completed" and final.business_verdict == "pending"
    assert len(calls) == 1 and set(calls[0].extensions["timeout"].values()) == {20}
    assert cost_counts(s) == (("ai", 1), ("execution", 1))
    assert sum(op == "apply" for op, _ in s.root.sent) == 1
    assert s.coordinator.tick(REF).phase == "completed" and len(calls) == 1


@pytest.mark.parametrize("kind", ["no_action", "unknown"])
def test_ai_nonproposal_never_falls_back_or_reprices(scene, monkeypatch, kind):
    s = scene(requires_ai=True)
    if kind == "unknown":

        def unknown(request):
            raise httpx.ReadTimeout("Synthetic unknown provider", request=request)

        calls = wire(monkeypatch, s.provider_state, handler=unknown)
    else:
        calls = wire(
            monkeypatch,
            s.provider_state,
            output=OUTPUT
            | {
                "decision": "no_action",
                "candidate_alias": None,
                "evidence_aliases": [],
                "reason_code": "no_match",
            },
        )
    start(s)
    final = finish(s)
    assert final.effective_phase == "reconciliation_only"
    assert len(calls) == 1 and cost_counts(s) == (("ai", 1),)
    assert not any(op in {"prepare", "apply"} for op, _ in s.root.sent)
    s.coordinator.tick(REF)
    assert len(calls) == 1 and cost_counts(s) == (("ai", 1),)


def test_budget_stops_before_ai_fee_or_execution_reservation(scene, monkeypatch):
    s = scene(requires_ai=True)
    calls = wire(monkeypatch, s.provider_state)
    initial = start(s)
    s.coordinator.tick(REF)  # select once and enter analyzing while evidence is fresh
    s.clock[0] += timedelta(seconds=70)
    final = s.coordinator.tick(REF)
    assert final.stop_reason == "budget_insufficient" and final.effective_phase == "stopped"
    assert not calls and cost_counts(s) == ()
    assert final.declaration.controller_deadline_at == initial.declaration.controller_deadline_at


@pytest.mark.parametrize("change", ["mode", "lease", "stop"])
def test_mutation_admission_changes_stop_without_execution(scene, change):
    s = scene()
    start(s)
    s.coordinator.tick(REF)  # preparing, no execution reservation yet
    if change == "mode":
        s.mode.change_mode(ModeChange(mode=Mode.manual, expected_revision=s.revision))
    elif change == "lease":
        old = s.coordinator._leases[REF]
        s.store.release_worker(old, now=s.clock[0])
        s.store.acquire_worker(s.service.owner, expires_at=old.expires_at, now=s.clock[0])
    else:
        s.coordinator.stop(REF)
    final = s.coordinator.tick(REF)
    assert final.effective_phase in {"stopped", "reconciliation_only"}
    assert not any(op in {"prepare", "apply"} for op, _ in s.root.sent)
    assert cost_counts(s) == ()


@pytest.mark.parametrize("lost", ["prepare", "apply"])
def test_unknown_original_operation_only_reconciles_same_identity(scene, lost):
    s = scene()
    start(s)
    s.root.lose = lost
    final = finish(s)
    assert final.phase == "reconciliation_only" and final.action is not None
    before = tuple(s.root.sent)
    s.coordinator.tick(REF)
    assert tuple(s.root.sent) == before
    s.coordinator.reconcile(REF)
    assert s.root.sent[len(before) :] == [("query", final.action.rid)]
    assert sum(op == lost for op, _ in s.root.sent) == 1
    assert sum(op == "arm" for op, _ in s.root.sent) == 1


def test_new_boot_can_read_and_query_but_never_resume_old_session(scene):
    s = scene()
    start(s)
    s.coordinator.tick(REF)
    prepared = s.coordinator.tick(REF)
    assert prepared.phase == "prepared"
    restarted = DefenseService(
        s.service.settings,
        s.service.targets,
        DefenseStore(s.store.path),
        s.automation,
        coordinator=s.mode,
        policy=s.service.policy,
        invoker=s.service.invoker,
        clock=s.service.clock,
    )
    second = DefenseSessionCoordinator(restarted)
    before, costs = tuple(s.root.sent), cost_counts(s)
    assert second.get(REF).effective_phase == "reconciliation_only"
    assert second.tick(REF).effective_phase == "reconciliation_only"
    assert tuple(s.root.sent) == before and cost_counts(s) == costs
    with pytest.raises(DefenseConflict):
        second.stop(REF)
    assert tuple(s.root.sent) == before and cost_counts(s) == costs
    second.reconcile(REF)
    assert s.root.sent[len(before) :] == [("query", prepared.action.rid)]
    assert sum(op == "apply" for op, _ in s.root.sent) == 0


def test_bound_cursor_cannot_start_a_different_session_or_new_epoch(scene):
    s = scene()
    start(s)
    before = tuple(s.root.sent)
    with pytest.raises(DefenseConflict):
        start(s, "9" * 32)
    old = s.coordinator._leases[REF]
    s.store.release_worker(old, now=s.clock[0])
    s.store.acquire_worker(s.service.owner, expires_at=old.expires_at, now=s.clock[0])
    assert start(s).effective_phase == "reconciliation_only"
    assert s.coordinator.tick(REF).effective_phase == "reconciliation_only"
    assert tuple(s.root.sent) == before


def test_duplicate_coordinator_can_only_read_existing_guard(scene):
    s = scene()
    second = DefenseSessionCoordinator(s.service)
    assert second.status()["mutation_owner"] is False
    before = tuple(s.root.sent)
    with pytest.raises(DefenseConflict):
        second.start("fixture", s.cursor, expected_mode_revision=s.revision, session_ref=REF)
    assert tuple(s.root.sent) == before and not second.owned_session_refs()
    initial = start(s)
    assert second.get(REF) == initial
    assert second.tick(REF).effective_phase == "reconciliation_only"
    assert s.coordinator.owned_session_refs() == (REF,)


def test_stop_during_provider_call_is_immediate_and_late_result_cannot_execute(scene, monkeypatch):
    s = scene(requires_ai=True)

    def stop_then_reply(request):
        s.coordinator.stop(REF)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(OUTPUT),
                        },
                    }
                ]
            },
        )

    calls = wire(monkeypatch, s.provider_state, handler=stop_then_reply)
    start(s)
    final = finish(s)
    assert final.effective_phase == "reconciliation_only" and len(calls) == 1
    assert not s.coordinator.owned_session_refs()
    assert cost_counts(s) == (("ai", 1),)
    assert not any(op in {"prepare", "apply"} for op, _ in s.root.sent)
    with closing(sqlite3.connect(s.store.path)) as db, db:
        assert db.execute("SELECT count(*) FROM defense_ai_results").fetchone()[0] == 0


def test_history_listing_is_readonly_bound_and_keyset_paged(scene):
    s = scene()
    record = start(s)
    sent, counts = tuple(s.root.sent), cost_counts(s)
    page = s.coordinator.list("fixture", limit=1)
    assert len(page["sessions"]) == 1
    row = page["sessions"][0]
    assert row["sequence"] > 0 and row["record"] == record
    assert page["next_after_sequence"] is None
    assert s.coordinator.list("fixture", after_sequence=row["sequence"])["sessions"] == []
    assert s.coordinator.list("another-host")["sessions"] == []
    for arguments in ({"after_sequence": -1}, {"after_sequence": True}, {"limit": 21}):
        with pytest.raises(DefenseConflict):
            s.coordinator.list("fixture", **arguments)
    assert tuple(s.root.sent) == sent and cost_counts(s) == counts


def test_explicit_reconcile_can_retry_unavailable_original_query(scene):
    s = scene()
    start(s)
    s.root.lose = "apply"
    record = finish(s)
    assert record.phase == "reconciliation_only" and record.action is not None
    rid = record.action.rid
    original = s.store.request(rid, "apply").wire_bytes()
    before, costs = len(s.root.sent), cost_counts(s)
    s.root.lose = "query"
    s.coordinator.reconcile(REF)
    assert s.root.sent[before:] == [("query", rid)]
    assert s.store.transaction(rid).query_required
    before = len(s.root.sent)
    s.coordinator.reconcile(REF)
    assert s.root.sent[before:] == [("query", rid)]
    assert not s.store.transaction(rid).query_required
    assert s.store.transaction(rid).phase == "active"
    assert s.store.request(rid, "apply").wire_bytes() == original
    assert cost_counts(s) == costs and sum(op == "apply" for op, _ in s.root.sent) == 1


def test_explicit_reconcile_refreshes_after_a_previously_confirmed_action_expires(scene):
    s = scene()
    start(s)
    s.root.lose = "apply"
    record = finish(s)
    assert record.action is not None
    rid = record.action.rid
    s.coordinator.reconcile(REF)
    old = s.store.latest_observation(rid)
    assert old is not None and old.reply is not None and old.reply.state == "active"
    costs = cost_counts(s)
    # FakeRoot's expiry is advanced explicitly; this is not a native kernel
    # timer experiment. A new caller query must still replace the old fact.
    s.clock[0] += timedelta(seconds=61)
    s.root.records[rid]["state"] = "expired"
    before = len(s.root.sent)
    s.coordinator.reconcile(REF)
    latest = s.store.latest_observation(rid)
    assert s.root.sent[before:] == [("query", rid)]
    assert latest is not None and latest.sequence > old.sequence
    assert latest.observation.accepted and latest.reply is not None
    assert latest.reply.state == "expired" and s.store.transaction(rid).phase == "expired"
    assert cost_counts(s) == costs and sum(op == "apply" for op, _ in s.root.sent) == 1
