"""Session AI uses only tmp ledgers, synthetic configuration and MockTransport."""

import sqlite3
from contextlib import closing
from types import SimpleNamespace
from typing import TypedDict

import httpx
import pytest
from test_defense_ai import OUTPUT, wire
from test_defense_api import EVIDENCE, NOW, SOURCE
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_store import admission, observing
from test_defense_session_store import session as session

from opsark import ai_provider
from opsark.config import Settings
from opsark.defense_ai import DefenseAIBlocked, DefenseAIService, DefenseAISnapshot
from opsark.defense_models import canonical
from opsark.defense_policy import DefenseAIConsent
from opsark.defense_store import DefenseConflict, DefenseStore


class AIState(TypedDict):
    settings: Settings
    snapshot: DefenseAISnapshot


@pytest.fixture(autouse=True)
def no_real_transport(monkeypatch):
    import paramiko

    attempts = []

    def reject(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("Only synthetic transports are allowed")

    async def reject_async(*args, **kwargs):
        return reject(*args, **kwargs)

    # Windows asyncio uses an actual loopback socketpair internally. Provider
    # transports and SSH are fenced directly; MockTransport remains available.
    monkeypatch.setattr(paramiko.SSHClient, "connect", reject)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", reject)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", reject_async)
    yield
    assert not attempts


@pytest.fixture
def environment(session):
    s = session
    settings = Settings(
        s.h.service.settings.data_dir,
        "synthetic-session-console-key-only",
        ai_base_url="https://synthetic-session-provider.invalid/v1",
        ai_key="synthetic-session-provider-key-only",
        ai_model="synthetic-session-model",
    )
    fingerprint = ai_provider.provider_fingerprint(settings)
    runtime = s.current[0].model_copy(
        update={"requires_ai": True, "provider_fingerprint": fingerprint}
    )
    s.current[0] = runtime
    s.declaration = s.declaration.model_copy(update={"runtime": runtime})
    _, selection = observing(s)
    s.store.advance(admission(s, "observing"), next_phase="analyzing", now=NOW)
    session_admission = admission(s, "analyzing")
    snapshot = DefenseAISnapshot(
        context=runtime.context,
        host_scope=runtime.host_scope,
        enabled=True,
        mode_sync_complete=True,
        stopping=False,
        sync_generation=runtime.context.epoch,
        consent=DefenseAIConsent(
            enabled=True,
            provider_fingerprint=fingerprint,
            max_analyses_per_day=4,
            max_total_analyses=8,
            requires_ai=True,
        ),
    )
    state: AIState = {"settings": settings, "snapshot": snapshot}
    admissions = []
    service = DefenseAIService(
        s.h.store,
        lambda: state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=lambda value: admissions.append(value),
        now=lambda: s.h.clock[0],
    )
    return SimpleNamespace(
        session=s,
        service=service,
        state=state,
        settings=settings,
        selection=selection,
        admission=session_admission,
        controller_admissions=admissions,
    )


def invoke(e, **changes):
    preview = e.service.preview("fixture", e.session.declaration.cursor_rid, SOURCE)
    options = {
        "expected_input_digest": preview["input_digest"],
        "expected_mode_revision": preview["mode_revision"],
        "automatic": True,
        "session_admission": e.admission,
        "timeout_seconds": 20,
    }
    options.update(changes)
    return e.service.analyze("fixture", e.session.declaration.cursor_rid, SOURCE, **options)


def ai_rows(e):
    with closing(sqlite3.connect(e.session.h.store.path)) as db, db:
        return db.execute("SELECT count(*) FROM defense_ai_intents").fetchone()[0]


def test_session_ai_once_keeps_original_proof_and_alias_boundary(environment, monkeypatch):
    e = environment
    calls = wire(monkeypatch, e.state)
    result = invoke(e)
    assert result["status"] == "completed" and len(calls) == 1
    assert result["actions_executable"] is False
    assert set(calls[0].extensions["timeout"].values()) == {20}
    assert e.service.validate_proposal(
        e.session.declaration.runtime.context,
        e.session.declaration.cursor_rid,
        SOURCE,
        EVIDENCE,
    )
    record = e.session.store.get(e.session.declaration.session_ref, now=NOW)
    permit = e.session.h.store.ai_permit(analysis_id=result["analysis_id"])
    assert record.ai_intent is not None and record.ai_intent.analysis_id == permit.analysis_id
    assert record.ai_intent.input_digest == permit.input_digest
    assert result["proof_sha256"] == DefenseAIService._proof(
        e.session.h.store.ai_result(result["analysis_id"]),
        permit,
        e.selection.source,
        e.session.declaration.runtime.context,
    )
    body = calls[0].content
    assert SOURCE.encode() not in body and e.session.declaration.cursor_rid.encode() not in body
    assert e.settings.token.encode() not in body and e.settings.ai_key.encode() not in body
    before = canonical(permit)
    assert invoke(e) == result and ai_rows(e) == 1 and len(calls) == 1
    assert canonical(e.session.h.store.ai_permit(analysis_id=result["analysis_id"])) == before


def test_bound_cursor_cannot_use_public_ai_cost_path_without_admission(environment, monkeypatch):
    e = environment
    calls = wire(monkeypatch, e.state)
    with pytest.raises(DefenseConflict):
        invoke(e, session_admission=None, timeout_seconds=30)
    assert ai_rows(e) == 0 and calls == []


@pytest.mark.parametrize("change", ["stop", "mode", "lease_epoch"])
def test_session_loss_before_cost_does_not_charge_or_dispatch(environment, monkeypatch, change):
    e, s = environment, environment.session
    calls = wire(monkeypatch, e.state)
    if change == "stop":
        s.stopped[0] = True
    elif change == "mode":
        s.current[0] = s.current[0].model_copy(update={"mode_sync_complete": False})
        e.state["snapshot"] = e.state["snapshot"].model_copy(update={"mode_sync_complete": False})
    else:
        s.h.store.release_worker(s.lease, now=NOW)
        newer = s.h.store.acquire_worker(s.h.service.owner, expires_at=s.lease.expires_at, now=NOW)
        assert newer is not None and newer.epoch > s.lease.epoch
    with pytest.raises(DefenseConflict):
        invoke(e)
    assert ai_rows(e) == 0 and calls == []


@pytest.mark.parametrize("stage", ["after_cost", "before_send", "after_response"])
@pytest.mark.parametrize("change", ["stop", "mode", "lease_epoch"])
def test_late_session_callback_never_writes_completed_or_stale_result(
    environment, monkeypatch, stage, change
):
    e, s = environment, environment.session

    def lose_authority():
        if change == "stop":
            s.stopped[0] = True
        elif change == "mode":
            s.current[0] = s.current[0].model_copy(update={"mode_sync_complete": False})
            e.state["snapshot"] = e.state["snapshot"].model_copy(
                update={"mode_sync_complete": False}
            )
        else:
            s.h.store.release_worker(s.lease, now=NOW)
            newer = s.h.store.acquire_worker(
                s.h.service.owner, expires_at=s.lease.expires_at, now=NOW
            )
            assert newer is not None and newer.epoch > s.lease.epoch

    def respond(_request):
        lose_authority()
        import json

        return httpx.Response(
            200,
            json={
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(OUTPUT)}}]
            },
        )

    calls = wire(monkeypatch, e.state, handler=respond if stage == "after_response" else None)
    if stage == "before_send":
        factory = ai_provider.httpx.AsyncClient

        def construct_then_revoke(**kwargs):
            client = factory(**kwargs)
            lose_authority()
            return client

        monkeypatch.setattr(ai_provider.httpx, "AsyncClient", construct_then_revoke)
    original = s.h.store.begin_ai_usage
    charged = []

    def after_cost(*args, **kwargs):
        permit = original(*args, **kwargs)
        charged.append(permit)
        if stage == "after_cost":
            lose_authority()
        return permit

    monkeypatch.setattr(s.h.store, "begin_ai_usage", after_cost)
    with pytest.raises(DefenseConflict):
        invoke(e)
    assert len(charged) == 1 and len(calls) == int(stage == "after_response")
    permit = charged[0]
    assert s.h.store.ai_result(permit.analysis_id) is None
    assert s.h.store.usage(permit.intent_key).state == "consumed"
    assert s.h.store.ai_permit(analysis_id=permit.analysis_id) == permit
    history = e.service.get("fixture", permit.analysis_id)
    assert history["status"] == "unknown" and history["proof_sha256"] is None
    assert invoke(e) == history and len(calls) == int(stage == "after_response")
    assert ai_rows(e) == 1


def test_input_projection_rejects_unknown_content_before_session_cost(environment, monkeypatch):
    e = environment
    calls = wire(monkeypatch, e.state)
    original = e.service._source

    def classified_source(*args, **kwargs):
        source = original(*args, **kwargs)
        return {**source.model_dump(mode="json"), "rawdb": "FAKE_PRIVATE_DATABASE_BODY"}

    monkeypatch.setattr(e.service, "_source", classified_source)
    with pytest.raises(ValueError):
        invoke(e)
    assert ai_rows(e) == 0 and calls == []


def test_final_hook_rejects_session_halted_after_admit_before_current_read(
    environment, monkeypatch
):
    e, s = environment, environment.session
    calls = wire(monkeypatch, e.state)
    factory, read = ai_provider.httpx.AsyncClient, s.store.get
    armed = False
    halted = []

    def construct(**kwargs):
        nonlocal armed
        client = factory(**kwargs)
        armed = True
        return client

    def halt_then_read(*args, **kwargs):
        if armed and not halted:
            s.store.halt(s.declaration.session_ref, reason="requested", now=NOW)
            halted.append(True)
        return read(*args, **kwargs)

    monkeypatch.setattr(ai_provider.httpx, "AsyncClient", construct)
    monkeypatch.setattr(s.store, "get", halt_then_read)
    with pytest.raises(DefenseConflict):
        invoke(e)
    assert halted == [True] and not calls and ai_rows(e) == 1
    with closing(sqlite3.connect(s.h.store.path)) as db, db:
        assert db.execute("SELECT count(*) FROM defense_ai_results").fetchone()[0] == 0


def test_unknown_session_analysis_is_historical_only_and_keeps_single_cost(
    environment, monkeypatch
):
    e = environment

    def unknown(request):
        raise httpx.ReadTimeout("Synthetic unknown provider result", request=request)

    calls = wire(monkeypatch, e.state, handler=unknown)
    result = invoke(e)
    assert result["status"] == "unknown" and result["proof_sha256"] is None
    permit = e.session.h.store.ai_permit(analysis_id=result["analysis_id"])
    assert e.session.h.store.usage(permit.intent_key).state == "unknown"
    assert invoke(e) == result and len(calls) == 1 and ai_rows(e) == 1
    assert e.session.h.store.ai_permit(analysis_id=result["analysis_id"]) == permit


def test_historical_analysis_readable_from_new_boot_without_dispatch(environment, monkeypatch):
    e = environment
    calls = wire(monkeypatch, e.state)
    result = invoke(e)
    newer = DefenseAIService(
        DefenseStore(e.session.h.store.path),
        e.settings,
        current_snapshot=lambda _: e.state["snapshot"],
        validate_admission=lambda _: None,
        now=lambda: NOW,
    )
    preview = newer.preview("fixture", e.session.declaration.cursor_rid, SOURCE)
    returned = newer.analyze(
        "fixture",
        e.session.declaration.cursor_rid,
        SOURCE,
        expected_input_digest=preview["input_digest"],
        expected_mode_revision=preview["mode_revision"],
        automatic=True,
    )
    assert returned == result and len(calls) == 1


@pytest.mark.parametrize("timeout", [0, -1, 31, float("nan"), True])
def test_session_timeout_is_bounded_before_any_new_cost(environment, monkeypatch, timeout):
    e = environment
    calls = wire(monkeypatch, e.state)
    with pytest.raises(DefenseAIBlocked):
        invoke(e, timeout_seconds=timeout)
    assert ai_rows(e) == 0 and calls == []


def test_legacy_custom_budget_cannot_be_used_without_session(environment, monkeypatch):
    e = environment
    calls = wire(monkeypatch, e.state)
    with pytest.raises(DefenseAIBlocked):
        invoke(e, session_admission=None, timeout_seconds=20)
    assert ai_rows(e) == 0 and calls == []
