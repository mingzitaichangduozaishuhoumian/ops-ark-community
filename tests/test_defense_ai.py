"""Real ledger/serializer/provider boundary with newfake data and MockTransport only."""

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from threading import Lock, Thread
from typing import TypedDict

import httpx
import pytest
from test_defense_api import FakeRoot, policy
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_store import NOW, OWNER, arm, context, reply, sync_mode

from opsark import ai_provider
from opsark.ai_egress import AIEgressBlocked, guard_request
from opsark.config import ANTHROPIC_BASE_URL, Settings
from opsark.defense_ai import (
    AI_BUDGET_REF,
    DefenseAIAdmission,
    DefenseAIBlocked,
    DefenseAIService,
    DefenseAISnapshot,
    project_egress,
    request_body,
    validate_source,
)
from opsark.defense_models import DefenseCandidate, canonical, digest, utc
from opsark.defense_policy import DefenseAIConsent
from opsark.defense_store import (
    MAX_DEADLINE_DISPLACEMENT_SECONDS,
    ControllerTimeBounds,
    DefenseConflict,
    DefenseStore,
)

OUTPUT = {
    "v": 1,
    "decision": "propose_defense",
    "candidate_alias": "candidate-1",
    "evidence_aliases": ["evidence-1"],
    "reason_code": "evidence_sufficient",
}


class DefenseAITestState(TypedDict):
    settings: Settings
    snapshot: DefenseAISnapshot
    admissions: list[DefenseAIAdmission]


def environment(
    tmp_path,
    *,
    mode="semi",
    provider="openai",
    root_deadline_seconds=120,
    observed_seconds=0,
):
    store = DefenseStore(tmp_path / "security.sqlite3")
    ctx = context(mode=mode)
    if mode != "manual":
        sync_mode(store, ctx)
    cursor, _ = arm(store, ctx=ctx)
    assert store.begin_sendable(cursor.rid, "arm", context=ctx, owner=OWNER, now=NOW)
    candidates = (
        DefenseCandidate(
            source_ref="c" * 32,
            source_alias="fixture-a",
            classification="eligible",
            distinct_failure_ports=5,
            evidence_sha256="d" * 64,
        ),
        DefenseCandidate(
            source_ref="b" * 32,
            source_alias="fixture-b",
            classification="success_seen",
            distinct_failure_ports=2,
            evidence_sha256=None,
        ),
    )
    observed = NOW + timedelta(seconds=observed_seconds)
    root_reply = reply(
        cursor,
        "query",
        "armed",
        changes={
            "candidates": candidates,
            "deadline_at": (NOW + timedelta(seconds=root_deadline_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
        },
    )
    assert store.record_reply(cursor.rid, "query", root_reply, context=ctx, now=observed).accepted
    settings = (
        Settings(
            data_dir=tmp_path,
            token="newfake-console-canary-unique",
            ai_key="newfake-provider-canary-unique",
            ai_base_url="https://newfake.example/v1",
            ai_model="newfake-model",
            ai_provider=provider,
        )
        if provider == "openai"
        else Settings(
            data_dir=tmp_path,
            token="newfake-console-canary-unique",
            ai_key="newfake-provider-canary-unique",
            ai_base_url=ANTHROPIC_BASE_URL,
            ai_model="newfake-claude",
            ai_provider="anthropic",
            ai_response_format="json_prompt",
        )
    )
    state: DefenseAITestState = {
        "settings": settings,
        "snapshot": DefenseAISnapshot(
            context=ctx,
            host_scope="a" * 64,
            enabled=True,
            mode_sync_complete=mode != "manual",
            stopping=False,
            sync_generation=ctx.epoch,
            consent=DefenseAIConsent(
                enabled=True,
                provider_fingerprint=ai_provider.provider_fingerprint(settings),
                max_analyses_per_day=4,
                max_total_analyses=8,
                requires_ai=True,
            ),
        ),
        "admissions": [],
    }

    def admit(value: DefenseAIAdmission) -> None:
        state["admissions"].append(value)

    service = DefenseAIService(
        store,
        lambda: state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=admit,
        now=lambda: observed,
    )
    return store, cursor, root_reply, state, service


def wire(monkeypatch, state, *, output=None, handler=None):
    calls = []
    original = httpx.AsyncClient

    def respond(request):
        calls.append(request)
        if handler:
            return handler(request)
        text = json.dumps(OUTPUT if output is None else output)
        if state["settings"].ai_provider == "anthropic":
            return httpx.Response(
                200,
                json={
                    "type": "message",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "content": [{"type": "text", "text": text}],
                },
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": text},
                    }
                ]
            },
        )

    monkeypatch.setattr(
        ai_provider.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(respond), **kw),
    )
    return calls


def analyze(service, cursor, *, automatic=False):
    preview = service.preview(cursor.context.host_id, cursor.rid, "c" * 32)
    return service.analyze(
        cursor.context.host_id,
        cursor.rid,
        "c" * 32,
        expected_input_digest=preview["input_digest"],
        expected_mode_revision=preview["mode_revision"],
        confirm_ai=not automatic,
        automatic=automatic,
    )


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_actual_wire_contains_only_aliases_enums_counts_and_fixed_ttl(
    tmp_path, monkeypatch, provider
):
    store, cursor, root_reply, state, service = environment(tmp_path, provider=provider)
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    assert result["status"] == "completed"
    assert result["decision"] == "propose_defense"
    assert result["actions_executable"] is False
    assert len(calls) == 1
    body = json.loads(calls[0].content)
    messages = body["messages"]
    summary = json.loads(messages[-1]["content"])
    assert summary == {
        "v": 1,
        "omitted_candidate_count": 1,
        "candidates": [
            {
                "candidate_alias": "candidate-1",
                "evidence_alias": "evidence-1",
                "classification": "eligible",
                "distinct_failure_ports": 5,
                "ttl_seconds": 60,
            }
        ],
    }
    raw = calls[0].content.decode()
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    for value in (
        cursor.rid,
        "c" * 32,
        "d" * 64,
        "fixture-a",
        "fixture-b",
        source.host_scope,
        source.defense_scope,
        source.root_scope,
        source.boot_ref,
        source.binding_ref,
        state["settings"].token,
        state["settings"].ai_key,
    ):
        assert value not in raw
    assert service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert service.validate_proof(
        cursor.context.host_id, cursor.rid, "c" * 32, result["proof_sha256"]
    )
    assert store.transaction(cursor.rid).kind == "cursor"
    assert all(t.kind != "action" for t in store.transactions(host_id=cursor.context.host_id))


@pytest.mark.parametrize(
    "field,value",
    [
        ("rawSQL", "SELECT token FROM secrets"),
        ("token", "newfake-secret"),
        ("log", "198.18.241.3 newfake-user"),
        ("unknown", "harmless"),
    ],
)
def test_complete_source_unknown_and_secret_keys_block_before_projection(tmp_path, field, value):
    store, cursor, root_reply, state, service = environment(tmp_path)
    source = store.cursor_source(cursor.rid, host_scope="a" * 64).model_dump(mode="json")
    source[field] = value
    with pytest.raises(AIEgressBlocked):
        project_egress(source, root_reply, "c" * 32, state["settings"])
    preview = service.preview(cursor.context.host_id, cursor.rid, "c" * 32)
    assert preview["actions_executable"] is False


@pytest.mark.parametrize("mutation", ["root_extra", "source_extra", "bool", "root_id", "secret"])
def test_full_source_root_schema_and_guard_are_required(tmp_path, mutation):
    store, cursor, root_reply, state, _ = environment(tmp_path)
    source = store.cursor_source(cursor.rid, host_scope="a" * 64).model_dump(mode="json")
    root = root_reply.model_dump(mode="json")
    if mutation == "root_extra":
        root["rawdb"] = "SQLite format 3"
    elif mutation == "source_extra":
        source["candidates"][1]["log"] = "newfake hidden log"
    elif mutation == "bool":
        source["candidates"][0]["distinct_failure_ports"] = True
    elif mutation == "root_id":
        root["request_id"] = "f" * 32
    else:
        state["settings"] = replace(state["settings"], token="c" * 32)
    with pytest.raises(AIEgressBlocked):
        validate_source(source, root, state["settings"])


@pytest.mark.parametrize("extra", ["shell", "ttl", "ip", "authorization", "source_ref"])
def test_model_extra_fields_are_failed_durable_and_not_resent(tmp_path, monkeypatch, extra):
    store, cursor, _, state, service = environment(tmp_path)
    calls = wire(monkeypatch, state, output={**OUTPUT, extra: "newfake-canary"})
    result = analyze(service, cursor)
    assert result["status"] == "failed" and result["proof_sha256"] is None
    recovered = DefenseAIService(
        DefenseStore(store.path),
        state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=lambda _: None,
        now=lambda: NOW,
    )
    assert recovered.get(cursor.context.host_id, result["analysis_id"]) == result
    assert analyze(recovered, cursor) == result
    assert len(calls) == 1
    assert not recovered.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)


@pytest.mark.parametrize(
    "change", ["mode", "generation", "consent", "provider", "registry", "stop", "source"]
)
def test_final_guard_after_cost_intent_cancels_with_zero_http(tmp_path, monkeypatch, change):
    store, cursor, root_reply, state, service = environment(tmp_path, mode="auto")
    calls = wire(monkeypatch, state)
    original = store.begin_ai_usage

    def reserve(*args, **kwargs):
        permit = original(*args, **kwargs)
        snapshot = state["snapshot"]
        if change == "mode":
            state["snapshot"] = snapshot.model_copy(
                update={"context": snapshot.context.model_copy(update={"mode": "manual"})}
            )
        elif change == "generation":
            state["snapshot"] = snapshot.model_copy(
                update={
                    "context": snapshot.context.model_copy(update={"epoch": 2}),
                    "sync_generation": 2,
                }
            )
        elif change == "consent":
            state["snapshot"] = snapshot.model_copy(
                update={"consent": snapshot.consent.model_copy(update={"enabled": False})}
            )
        elif change == "provider":
            state["settings"] = replace(state["settings"], ai_model="newfake-changed-model")
        elif change == "registry":
            state["snapshot"] = snapshot.model_copy(
                update={"context": snapshot.context.model_copy(update={"registry_scope": "9" * 64})}
            )
        elif change == "stop":
            state["snapshot"] = snapshot.model_copy(update={"stopping": True})
        else:
            candidate = root_reply.candidates[0].model_copy(update={"distinct_failure_ports": 6})
            changed = root_reply.model_copy(update={"candidates": (candidate,)})
            assert store.record_reply(
                cursor.rid, "query", changed, context=cursor.context, now=NOW
            ).accepted
        return permit

    monkeypatch.setattr(store, "begin_ai_usage", reserve)
    result = analyze(service, cursor, automatic=True)
    assert result["status"] == "stale"
    assert calls == []
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert store.usage(permit.intent_key).state == "unknown"
    assert store.transaction(cursor.rid).kind == "cursor"


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_boundary_rejects_tampered_prompt_format_and_unlisted_fields(tmp_path, provider):
    store, cursor, root_reply, state, _ = environment(tmp_path, provider=provider)
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    summary, _ = project_egress(source, root_reply, "c" * 32, state["settings"])
    body = request_body(summary, state["settings"])
    body["max_tokens"] = 256
    assert guard_request(body, state["settings"], "ssh_defense")
    for mutation in ("prompt", "format", "input", "extra"):
        changed = json.loads(json.dumps(body))
        if mutation == "prompt":
            changed["messages"][0]["content"] += " newfake injection"
        elif mutation == "format":
            changed["response_format"] = {"type": "text"}
        elif mutation == "input":
            content = json.loads(changed["messages"][1]["content"])
            content["root_rid"] = cursor.rid
            changed["messages"][1]["content"] = json.dumps(content)
        else:
            changed["metadata"] = {"source": "newfake"}
        with pytest.raises(AIEgressBlocked):
            guard_request(changed, state["settings"], "ssh_defense")


def test_manual_explicit_advice_has_independent_consent_and_no_execution_proof(
    tmp_path, monkeypatch
):
    store, cursor, _, state, service = environment(tmp_path, mode="manual")
    calls = wire(monkeypatch, state)
    with pytest.raises(DefenseAIBlocked):
        analyze(service, cursor, automatic=True)
    assert calls == []
    result = analyze(service, cursor)
    assert result["status"] == "completed" and len(calls) == 1
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert permit.advice_authorization.context_sha256 == digest(cursor.context)
    assert permit.advice_authorization.consent_sha256 == digest(state["snapshot"].consent)
    assert store.mode_ack(cursor.context) is None
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert all(t.kind != "action" for t in store.transactions())


@pytest.mark.parametrize("mode", ["manual", "semi", "auto"])
def test_every_mode_requires_separate_ai_fee_permission(tmp_path, monkeypatch, mode):
    store, cursor, _, state, service = environment(tmp_path, mode=mode)
    calls = wire(monkeypatch, state)
    state["snapshot"] = state["snapshot"].model_copy(
        update={"consent": state["snapshot"].consent.model_copy(update={"enabled": False})}
    )
    with pytest.raises(DefenseAIBlocked):
        analyze(service, cursor, automatic=mode == "auto")
    assert calls == []
    assert store.ai_permit(analysis_id="0" * 32) is None


def test_same_evidence_new_cursor_ref_observation_and_grant_do_not_rebill(tmp_path, monkeypatch):
    store, cursor, _, state, service = environment(tmp_path)
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    new_cursor, _ = arm(store, ctx=cursor.context)
    assert store.begin_sendable(new_cursor.rid, "arm", context=cursor.context, owner=OWNER, now=NOW)
    candidate = DefenseCandidate(
        source_ref="e" * 32,
        source_alias="fixture-a",
        classification="eligible",
        distinct_failure_ports=9,
        evidence_sha256="d" * 64,
    )
    receipt = reply(
        new_cursor,
        "query",
        "armed",
        changes={
            "candidates": (candidate,),
            "cursor_id": "9" * 32,
        },
    )
    assert store.record_reply(
        new_cursor.rid, "query", receipt, context=cursor.context, now=NOW
    ).accepted
    preview = service.preview(cursor.context.host_id, new_cursor.rid, "e" * 32)
    repeated = service.analyze(
        cursor.context.host_id,
        new_cursor.rid,
        "e" * 32,
        expected_input_digest=preview["input_digest"],
        expected_mode_revision=preview["mode_revision"],
        confirm_ai=True,
    )
    assert repeated == result and len(calls) == 1
    assert not service.validate_proposal(cursor.context, new_cursor.rid, "e" * 32, "d" * 64)
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert store.usage(permit.intent_key).grant_ref == AI_BUDGET_REF


def test_unknown_restart_reuses_original_analysis_and_cost_without_http(tmp_path, monkeypatch):
    store, cursor, _, state, service = environment(tmp_path)

    def timeout(request):
        raise httpx.ReadTimeout("newfake timeout", request=request)

    calls = wire(monkeypatch, state, handler=timeout)
    result = analyze(service, cursor)
    assert result["status"] == "unknown" and len(calls) == 1
    restarted = DefenseAIService(
        DefenseStore(store.path),
        state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=lambda _: None,
        now=lambda: NOW,
    )
    assert analyze(restarted, cursor) == result and len(calls) == 1
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert store.usage(permit.intent_key).state == "unknown"
    assert not restarted.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)


@pytest.mark.parametrize(
    "decision,reason",
    [
        ("collect_more", "evidence_gap"),
        ("review_access", "access_review"),
        ("no_action", "no_match"),
    ],
)
def test_nonproposals_are_durable_stop_without_fallback(tmp_path, monkeypatch, decision, reason):
    _, cursor, _, state, service = environment(tmp_path, mode="auto")
    calls = wire(
        monkeypatch,
        state,
        output={
            "v": 1,
            "decision": decision,
            "candidate_alias": None,
            "evidence_aliases": [],
            "reason_code": reason,
        },
    )
    result = analyze(service, cursor, automatic=True)
    assert result["status"] == "completed" and result["proof_sha256"] is None
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert analyze(service, cursor, automatic=True) == result and len(calls) == 1


@pytest.mark.parametrize("corruption", ["source", "alias", "permit", "result"])
def test_read_interfaces_verify_hash_and_closed_binding(tmp_path, monkeypatch, corruption):
    store, cursor, _, state, service = environment(tmp_path)
    wire(monkeypatch, state)
    result = analyze(service, cursor)
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    table, column, identity, key = {
        "source": ("defense_sources", "typed_source", "source_key", permit.source_key),
        "alias": ("defense_sources", "alias_map", "source_key", permit.source_key),
        "permit": ("defense_ai_intents", "typed_permit", "analysis_id", permit.analysis_id),
        "result": ("defense_ai_results", "typed_result", "analysis_id", permit.analysis_id),
    }[corruption]
    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute(
            f"UPDATE {table} SET {column}=? WHERE {identity}=?",  # noqa: S608 -- fixed test map.
            (b"{}", key),
        )
    with pytest.raises(DefenseConflict):
        service.get(cursor.context.host_id, result["analysis_id"])
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)


def test_crash_after_durable_intent_never_replays_and_fences_new_evidence(tmp_path, monkeypatch):
    store, cursor, root_reply, state, service = environment(tmp_path)
    calls = wire(monkeypatch, state)
    original = ai_provider.request_document

    def crash(*args, **kwargs):
        raise SystemExit("newfake process crash before transport")

    monkeypatch.setattr(ai_provider, "request_document", crash)
    with pytest.raises(SystemExit):
        analyze(service, cursor)
    monkeypatch.setattr(ai_provider, "request_document", original)
    assert store.unfinished_ai(cursor.context.host_id, cursor.context.defense_scope)
    # A new registry binding must not remove the old host's pending-cost fence.
    assert store.unfinished_ai(cursor.context.host_id, "9" * 64)
    restarted = DefenseAIService(
        DefenseStore(store.path),
        state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=lambda _: None,
        now=lambda: NOW,
    )
    retained = analyze(restarted, cursor)
    assert retained["status"] == "unknown" and calls == []
    candidate = root_reply.candidates[0].model_copy(update={"evidence_sha256": "e" * 64})
    assert store.record_reply(
        cursor.rid,
        "query",
        root_reply.model_copy(update={"candidates": (candidate,)}),
        context=cursor.context,
        now=NOW,
    ).accepted
    with pytest.raises(DefenseAIBlocked):
        analyze(restarted, cursor)
    assert calls == []


def test_identical_fresh_query_retains_proof_but_changed_evidence_stops(tmp_path, monkeypatch):
    store, cursor, root_reply, state, service = environment(tmp_path)
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    refreshed_at = NOW + timedelta(seconds=1)
    service.now = lambda: refreshed_at
    assert store.record_reply(
        cursor.rid, "query", root_reply, context=cursor.context, now=refreshed_at
    ).accepted
    assert service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert (
        service.get(cursor.context.host_id, result["analysis_id"])["proof_sha256"]
        == result["proof_sha256"]
    )
    candidate = root_reply.candidates[0].model_copy(update={"distinct_failure_ports": 6})
    assert store.record_reply(
        cursor.rid,
        "query",
        root_reply.model_copy(update={"candidates": (candidate,)}),
        context=cursor.context,
        now=refreshed_at,
    ).accepted
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert len(calls) == 1


def test_change_after_transport_preserves_cost_but_invalidates_proposal(tmp_path, monkeypatch):
    store, cursor, _, state, service = environment(tmp_path, mode="auto")

    def change_after_sent(_request):
        state["snapshot"] = state["snapshot"].model_copy(update={"stopping": True})
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(OUTPUT)},
                    }
                ]
            },
        )

    calls = wire(monkeypatch, state, handler=change_after_sent)
    result = analyze(service, cursor, automatic=True)
    assert len(calls) == 1 and result["status"] == "stale"
    assert result["proof_sha256"] is None
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert store.usage(permit.intent_key).state == "unknown"
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)


@pytest.mark.parametrize("deadline_displacement", [-30, 0, 23.786, 30])
def test_real_service_callbacks_share_plain_lock_and_proof_never_submits_root(
    tmp_path,
    monkeypatch,
    target,
    deadline_displacement,
):
    from test_defense_api import NOW as SERVICE_NOW

    from opsark.automation_store import AutomationStore, ModeChange
    from opsark.control_modes import ControlPolicy, Mode
    from opsark.defense_api import ArmRequest, DefenseService, PrepareRequest, defense_service_scope
    from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope

    settings = Settings(
        data_dir=tmp_path,
        token="newfake-integrated-console-canary",
        ai_key="newfake-integrated-provider-canary",
        ai_base_url="https://newfake.example/v1",
        ai_model="newfake-integrated-model",
    )
    consent = DefenseAIConsent(
        enabled=True,
        provider_fingerprint=ai_provider.provider_fingerprint(settings),
        max_analyses_per_day=2,
        max_total_analyses=4,
        requires_ai=True,
    )
    deployment = policy(target, ai=consent.model_dump(mode="json"))
    scope = defense_service_scope({"fixture": target}, deployment)
    assert scope is not None
    participant = ModeParticipant("ssh-defense", scope, lambda _: False)
    automation = AutomationStore(
        tmp_path / "mode.sqlite3",
        ControlPolicy(),
        supplemental_scope=supplemental_scope((participant,)),
    )
    store, mode_lock = DefenseStore(tmp_path / "security.sqlite3"), Lock()
    clock = [SERVICE_NOW]
    root = FakeRoot(target, lambda: clock[0] + timedelta(seconds=deadline_displacement))
    controller = DefenseService(
        settings,
        {"fixture": target},
        store,
        automation,
        policy=deployment,
        mode_lock=mode_lock,
        invoker=root,
        clock=lambda: clock[0],
    )
    controller_participant = controller.participant()
    assert controller_participant is not None
    coordinator = ModeCoordinator(automation, mode_lock, (controller_participant,))
    controller.coordinator = coordinator
    service = DefenseAIService(
        store,
        settings,
        current_snapshot=controller.ai_snapshot,
        validate_admission=controller.validate_ai_admission,
        now=controller.clock,
    )
    controller.ai_service = service
    revision = coordinator.change_mode(ModeChange(mode=Mode.automatic, expected_revision=0))[
        "revision"
    ]
    armed = controller.arm("fixture", ArmRequest(expected_mode_revision=revision, confirm_arm=True))
    rid = armed["request_id"]
    clock[0] += timedelta(seconds=14.382)
    controller.query("fixture", rid)

    def unlocked_transport(_request):
        assert mode_lock.acquire(blocking=False), "provider transport ran under the mode lock"
        mode_lock.release()
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(OUTPUT)},
                    }
                ]
            },
        )

    calls = wire(monkeypatch, {"settings": settings}, handler=unlocked_transport)
    preview = service.preview("fixture", rid, "c" * 32)
    result = service.analyze(
        "fixture",
        rid,
        "c" * 32,
        expected_input_digest=preview["input_digest"],
        expected_mode_revision=revision,
        automatic=True,
    )
    assert result["status"] == "completed" and len(calls) == 1
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in root.sent)
    outcomes = []

    def check_while_locked():
        try:
            with mode_lock:
                controller._ai(store.transaction(rid).context, rid, "c" * 32, "d" * 64)
            outcomes.append(True)
        except BaseException as error:
            outcomes.append(error)

    thread = Thread(target=check_while_locked, daemon=True)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive(), "local proof callback attempted to reenter the plain mode lock"
    assert outcomes == [True]
    clock[0] = SERVICE_NOW + timedelta(seconds=110)
    action = controller.prepare(
        "fixture",
        PrepareRequest(
            cursor_request_id=rid,
            source_ref="c" * 32,
            expected_evidence_sha256="d" * 64,
            expected_mode_revision=revision,
        ),
    )
    assert action["phase"] == "ready"
    assert store.transaction(action["request_id"]).deadline_at == store.transaction(rid).deadline_at
    assert utc(store.manifest(action["request_id"]).deadline_at) == (
        utc(store.transaction(rid).deadline_at) + timedelta(seconds=deadline_displacement)
    )
    controller.query("fixture", rid)
    attached = store.latest_reply(rid)
    assert attached is not None and attached.state == "attached"
    assert service.validate_proposal(store.transaction(rid).context, rid, "c" * 32, "d" * 64)
    active = controller.automatic_apply(
        "fixture", action["request_id"], expected_mode_revision=revision
    )
    assert active["phase"] == "active"
    assert len(calls) == 1
    assert [op for op, _ in root.sent].count("apply") == 1


def test_provider_rotation_uses_same_independent_ai_budget(tmp_path, monkeypatch):
    store, cursor, _, state, service = environment(tmp_path)
    state["snapshot"] = state["snapshot"].model_copy(
        update={
            "consent": state["snapshot"].consent.model_copy(
                update={
                    "max_analyses_per_day": 1,
                    "max_total_analyses": 1,
                }
            )
        }
    )
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    state["settings"] = replace(
        state["settings"],
        ai_provider="anthropic",
        ai_base_url=ANTHROPIC_BASE_URL,
        ai_model="newfake-rotated-claude",
        ai_response_format="json_prompt",
    )
    state["snapshot"] = state["snapshot"].model_copy(
        update={
            "consent": state["snapshot"].consent.model_copy(
                update={
                    "provider_fingerprint": ai_provider.provider_fingerprint(state["settings"]),
                }
            )
        }
    )
    with pytest.raises(DefenseConflict):
        analyze(service, cursor)
    assert len(calls) == 1
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    assert store.usage(permit.intent_key).grant_ref == AI_BUDGET_REF


def test_relative_cross_host_deadlines_use_original_local_window_not_150_seconds(
    tmp_path, monkeypatch
):
    store, cursor, root_reply, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    local = store.transaction(cursor.rid)
    assert (utc(source.cursor_deadline_at) - utc(source.observed_at)).total_seconds() == 129.404
    assert (utc(local.deadline_at) - utc(source.observed_at)).total_seconds() == 105.618
    assert (utc(source.cursor_deadline_at) - utc(local.deadline_at)).total_seconds() == 23.786
    assert (utc(source.observed_at) - utc(local.created_at)).total_seconds() == 14.382
    original = canonical(source)
    root_raw = canonical(root_reply) + b"\n"
    assert hashlib.sha256(root_raw).hexdigest() == source.root_reply_sha256
    with pytest.raises(AIEgressBlocked):
        project_egress(source, root_reply, "c" * 32, state["settings"])
    bounds = store.source_time_bounds(source)
    summary, _ = project_egress(
        source,
        root_reply,
        "c" * 32,
        state["settings"],
        controller_bounds=bounds,
    )
    assert summary["candidates"][0]["ttl_seconds"] == 60
    assert canonical(source) == original and canonical(bounds.root_reply) + b"\n" == root_raw
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    assert result["status"] == "completed" and len(calls) == 1
    assert service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    permit = store.ai_permit(analysis_id=result["analysis_id"])
    with closing(sqlite3.connect(store.path)) as connection, connection:
        saved = connection.execute(
            "SELECT typed_source FROM defense_sources WHERE source_key=?", (permit.source_key,)
        ).fetchone()[0]
    assert saved == original
    # Root's wire deadline remains later, but local 120 seconds is a hard stop.
    service.now = lambda: NOW + timedelta(seconds=120)
    with pytest.raises(DefenseConflict):
        service.preview(cursor.context.host_id, cursor.rid, "c" * 32)
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert service.get(cursor.context.host_id, result["analysis_id"]) == result
    assert len(calls) == 1


@pytest.mark.parametrize("displacement", [-30, 30])
def test_exact_deadline_displacement_boundaries_allow_trusted_ledger_only(
    tmp_path, monkeypatch, displacement
):
    observed = 105 if displacement < 0 else 14.382
    store, cursor, root_reply, state, service = environment(
        tmp_path,
        root_deadline_seconds=120 + displacement,
        observed_seconds=observed,
    )
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    assert MAX_DEADLINE_DISPLACEMENT_SECONDS == 30
    bounds = store.source_time_bounds(source)
    bounds.require(source, context=cursor.context, now=service.now())
    with pytest.raises(AIEgressBlocked):
        validate_source(source, root_reply, state["settings"])
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    assert result["status"] == "completed" and len(calls) == 1
    assert service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)


@pytest.mark.parametrize("displacement", [-30.000001, 30.000001, -300, 300])
def test_over_budget_never_opens_http_or_cost_intent(tmp_path, monkeypatch, displacement):
    store, cursor, _, state, service = environment(
        tmp_path,
        root_deadline_seconds=120 + displacement,
        observed_seconds=14.382,
    )
    calls = wire(monkeypatch, state)
    with pytest.raises(DefenseConflict):
        analyze(service, cursor)
    assert calls == []
    assert store.ai_permit(analysis_id="0" * 32) is None
    with closing(sqlite3.connect(store.path)) as connection, connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM defense_usage WHERE kind='ai'").fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("local_now", [14.381999, 120, 120.000001])
def test_future_observation_rollback_and_local_expiry_never_use_root_extra_time(
    tmp_path, monkeypatch, local_now
):
    _, cursor, _, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    service.now = lambda: NOW + timedelta(seconds=local_now)
    calls = wire(monkeypatch, state)
    with pytest.raises(DefenseConflict):
        analyze(service, cursor)
    assert calls == []


@pytest.mark.parametrize("tamper", ["unissued", "data", "source", "context", "root"])
def test_controller_bounds_cannot_be_forged_or_rebound(tmp_path, tamper):
    store, cursor, root_reply, state, _ = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    source = store.cursor_source(cursor.rid, host_scope="a" * 64)
    bounds = store.source_time_bounds(source)
    if tamper == "unissued":
        bounds = ControllerTimeBounds()
    elif tamper == "data":
        object.__setattr__(
            bounds, "_data", bounds._data.model_copy(update={"deadline_at": "2026-11-06T01:03:00Z"})
        )
    elif tamper == "source":
        source = source.model_copy(update={"observed_at": "2026-11-06T01:00:15Z"})
    elif tamper == "root":
        object.__setattr__(
            bounds, "root_reply", root_reply.model_copy(update={"request_id": "f" * 32})
        )
    else:
        with pytest.raises(DefenseConflict):
            bounds.require(source, context=cursor.context.model_copy(update={"epoch": 2}))
        return
    with pytest.raises(AIEgressBlocked):
        validate_source(source, root_reply, state["settings"], controller_bounds=bounds)


@pytest.mark.parametrize("stage", ["cost_commit", "final_guard"])
@pytest.mark.parametrize("local_now", [14.381999, 120])
def test_local_time_rechecked_at_cost_commit_and_final_dispatch(
    tmp_path, monkeypatch, stage, local_now
):
    store, cursor, _, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    calls = wire(monkeypatch, state)
    method = "save_source" if stage == "cost_commit" else "begin_ai_usage"
    original = getattr(store, method)

    def change_clock(*args, **kwargs):
        result = original(*args, **kwargs)
        service.now = lambda: NOW + timedelta(seconds=local_now)
        return result

    monkeypatch.setattr(store, method, change_clock)
    if stage == "cost_commit":
        with pytest.raises(DefenseConflict):
            analyze(service, cursor)
    else:
        result = analyze(service, cursor)
        assert result["status"] == "stale"
        assert service.get(cursor.context.host_id, result["analysis_id"]) == result
    assert calls == []
    with closing(sqlite3.connect(store.path)) as connection, connection:
        assert connection.execute("SELECT COUNT(*) FROM defense_usage WHERE kind='ai'").fetchone()[
            0
        ] == (0 if stage == "cost_commit" else 1)


def test_changed_evidence_between_source_retention_and_cost_commit_charges_nothing(
    tmp_path, monkeypatch
):
    store, cursor, root_reply, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    calls = wire(monkeypatch, state)
    original = store.save_source

    def retain_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        candidate = root_reply.candidates[0].model_copy(update={"evidence_sha256": "e" * 64})
        assert store.record_reply(
            cursor.rid,
            "query",
            root_reply.model_copy(update={"candidates": (candidate,)}),
            context=cursor.context,
            now=service.now(),
        ).accepted
        return result

    monkeypatch.setattr(store, "save_source", retain_then_change)
    with pytest.raises(DefenseConflict):
        analyze(service, cursor)
    assert calls == []
    with closing(sqlite3.connect(store.path)) as connection, connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM defense_usage WHERE kind='ai'").fetchone()[0]
            == 0
        )


def test_unknown_historical_source_and_cost_remain_readable_after_local_expiry(
    tmp_path, monkeypatch
):
    store, cursor, _, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )

    def timeout(request):
        raise httpx.ReadTimeout("newfake deadline test timeout", request=request)

    calls = wire(monkeypatch, state, handler=timeout)
    result = analyze(service, cursor)
    assert result["status"] == "unknown"
    with closing(sqlite3.connect(store.path)) as connection, connection:
        before = connection.execute("SELECT * FROM defense_sources").fetchall()
        original_intents = connection.execute("SELECT * FROM defense_ai_intents").fetchall()
        original_usage = connection.execute("SELECT * FROM defense_usage").fetchall()
    recovered_store = DefenseStore(store.path)
    restarted = DefenseAIService(
        recovered_store,
        state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=lambda _: None,
        now=lambda: NOW + timedelta(seconds=121),
    )
    assert restarted.get(cursor.context.host_id, result["analysis_id"]) == result
    permit = recovered_store.ai_permit(analysis_id=result["analysis_id"])
    assert permit is not None
    original_source, _ = recovered_store.source(permit.source_key)
    original_reply = recovered_store.source_reply(permit.source_key)
    assert (
        hashlib.sha256(canonical(original_reply) + b"\n").hexdigest()
        == original_source.root_reply_sha256
    )
    with pytest.raises(DefenseConflict):
        analyze(restarted, cursor)
    assert not restarted.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    with closing(sqlite3.connect(store.path)) as connection, connection:
        assert connection.execute("SELECT * FROM defense_sources").fetchall() == before
        assert connection.execute("SELECT * FROM defense_ai_intents").fetchall() == original_intents
        assert connection.execute("SELECT * FROM defense_usage").fetchall() == original_usage
    assert recovered_store.usage(permit.intent_key).state == "unknown"
    assert len(calls) == 1


def test_rollback_above_observation_but_before_durable_cost_invalidates_proof(
    tmp_path, monkeypatch
):
    _, cursor, _, state, service = environment(
        tmp_path,
        root_deadline_seconds=143.786,
        observed_seconds=14.382,
    )
    service.now = lambda: NOW + timedelta(seconds=50)
    calls = wire(monkeypatch, state)
    result = analyze(service, cursor)
    assert result["status"] == "completed"
    service.now = lambda: NOW + timedelta(seconds=40)
    assert not service.validate_proposal(cursor.context, cursor.rid, "c" * 32, "d" * 64)
    assert service.get(cursor.context.host_id, result["analysis_id"]) == result
    assert len(calls) == 1
