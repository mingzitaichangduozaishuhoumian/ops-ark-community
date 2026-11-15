"""Automatic consent is rechecked at the real, whitelist-only provider boundary."""

import copy
import json
import sys
from dataclasses import replace
from datetime import timedelta
from threading import Event, Lock, Thread
from types import SimpleNamespace

import httpx
import pytest
from test_automatic_ai import gated as gated
from test_automatic_ai import require
from test_automatic_monitor import HOST
from test_vulnerability_ai import document
from test_vulnerability_ai_service import env as env

from opsark import ai_provider
from opsark import vulnerability_ai_focus as focus
from opsark.automation_store import ModeChange
from opsark.control_modes import ControlPolicy
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant
from opsark.vulnerability_ai_api import AnalysisRequest


def proposal(summary):
    candidate = summary["candidate_catalog"][0]
    finding = summary["findings"][0]
    evidence = candidate["evidence_refs"]
    return document(
        {
            "summary": "供应商证据支持核对固定候选。",
            "uncertainty": ["整体覆盖仍不完整。"],
            "evidence_refs": evidence + ["coverage-1"],
            "finding_analyses": [
                {
                    "finding_ref": finding["finding_ref"],
                    "priority": "planned",
                    "reason_codes": ["vendor_confirmed_affected", "candidate_available"],
                    "rationale": "已有供应商证据和可用候选。",
                    "evidence_refs": evidence,
                }
            ],
            "proposals": [
                {
                    "candidate_id": candidate["candidate_id"],
                    "rationale": "需要继续核对原生计划。",
                    "evidence_refs": evidence,
                }
            ],
            "actions_executable": False,
        }
    )


@pytest.fixture
def dispatch(gated, monkeypatch):
    # Replace the service fixture's provider stand-in with the actual serializer.
    monkeypatch.setitem(sys.modules, "opsark.ai_provider", ai_provider)
    gated.service.focus_analyzer = focus.analyze
    state = SimpleNamespace(env=gated, requests=[], on_request=None, success=False)

    def receive(request):
        assert request.method == "POST"
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer " + gated.settings.ai_key
        payload = json.loads(request.content)
        summary = json.loads(payload["messages"][1]["content"])
        focus.validate_egress(summary)
        text = request.content.decode()
        assert all(
            private not in text
            for private in (
                gated.settings.token,
                gated.settings.ai_key,
                HOST,
                gated.candidate["id"],
                gated.scan["scan_id"],
            )
        )
        state.requests.append(request)
        if state.on_request is not None:
            state.on_request()
        if state.success:
            return httpx.Response(200, json=proposal(summary))
        return httpx.Response(503, json={"error": {"type": "synthetic_unavailable"}})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        ai_provider.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(receive), **kwargs),
    )
    return state


def no_native_work(e):
    assert all(row["op"] == "set_mode" for row in e.root_calls)
    assert not e.patches.list_jobs()


def attach_shared_mode(e):
    def apt(snapshot):
        e.native.synchronize_mode_targets({"mode": snapshot.mode, "revision": snapshot.revision})
        return True

    coordinator = ModeCoordinator(
        e.modes, Lock(), (ModeParticipant("ubuntu-apt", e.modes.driver_scope, apt),)
    )
    e.native.mode_coordinator = coordinator
    return coordinator


def test_shared_admission_lock_blocks_automatic_post_without_holding_legacy_rpc_lock(dispatch):
    e = dispatch.env
    coordinator = attach_shared_mode(e)
    with coordinator.mode_lock:
        assert not e.native.mode_lock.locked()
        assert require(e) is None
    assert not dispatch.requests
    assert e.auto.ai_requests()[0]["status"] == "stale"
    assert require(e) is None and not dispatch.requests
    no_native_work(e)


def test_shared_coordinator_manual_cas_during_reserved_ai_intent_never_posts(dispatch, monkeypatch):
    e = dispatch.env
    coordinator = attach_shared_mode(e)
    reserved, pending, release = Event(), Event(), Event()
    errors = []
    invoke, reserve = e.native.invoker, e.auto.begin_ai_request

    def blocked_ack(target, request, **kwargs):
        if request["op"] == "set_mode" and request["mode"] == "manual":
            assert not coordinator.mode_lock.locked()
            assert not e.native.mode_lock.locked()
            pending.set()
            assert release.wait(5)
        return invoke(target, request, **kwargs)

    def reservation(**kwargs):
        result = reserve(**kwargs)
        reserved.set()
        assert pending.wait(5)
        assert e.modes.status()["mode"] == "manual"
        assert not e.modes.status()["mode_sync_complete"]
        return result

    def manual():
        try:
            assert reserved.wait(5)
            e.native.change_mode(
                ModeChange(mode="manual", expected_revision=e.modes.status()["revision"])
            )
        except Exception as error:
            errors.append(error)

    monkeypatch.setattr(e.native, "invoker", blocked_ack)
    monkeypatch.setattr(e.auto, "begin_ai_request", reservation)
    worker = Thread(target=manual, daemon=True)
    worker.start()
    try:
        assert require(e) is None and not dispatch.requests
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and not errors
    assert e.auto.ai_requests()[0]["status"] == "stale"
    no_native_work(e)


def mutate(e, change):
    if change == "manual":
        e.native.change_mode(
            ModeChange(mode="manual", expected_revision=e.modes.status()["revision"])
        )
    elif change == "pending":
        e.modes.mark_sync_pending(e.modes.status()["revision"])
    elif change == "stopping":
        e.gate.is_stopping = lambda: True
    elif change == "provider":
        e.service.settings = replace(e.settings, ai_model="different-synthetic-model")
    elif change == "input":
        # Keep scan_id and apt_state_digest: the complete original input still matters.
        source = copy.deepcopy(e.patches.latest_scan(HOST))
        source["gaps"] = ["provider_failure"]
        e.patches.save_scan(HOST, source)
    elif change == "consent":
        value = e.policy.model_dump(mode="json")
        value["automatic_ai"]["enabled"] = False
        e.modes.policy = ControlPolicy.model_validate(value)
    elif change == "expiry":
        e.now += timedelta(hours=2)
    else:
        raise AssertionError("Unknown test mutation")


def test_stable_automatic_uses_one_real_serialized_request_and_never_retries(dispatch):
    e = dispatch.env
    assert require(e) is None and require(e) is None
    assert len(dispatch.requests) == len(e.auto.ai_requests()) == 1
    assert e.auto.ai_requests()[0]["status"] == "failed"
    assert e.auto.ai_quotas(HOST, e.policy.automatic.grant_id, now=e.now)["total_used"] == 1
    no_native_work(e)


def test_mode_sync_pending_before_admission_never_reserves_or_posts(dispatch):
    e = dispatch.env
    e.modes.mark_sync_pending(e.modes.status()["revision"])
    assert require(e) is None
    assert not dispatch.requests and not e.auto.ai_requests()
    no_native_work(e)


@pytest.mark.parametrize("seam", ["automatic_intent", "analysis_begin", "serialized"])
@pytest.mark.parametrize(
    "change", ["manual", "pending", "stopping", "provider", "input", "consent", "expiry"]
)
def test_changes_before_transport_do_not_post_or_rearm_intent(dispatch, monkeypatch, seam, change):
    e = dispatch.env
    reached = []
    if seam == "serialized":
        original = ai_provider.guard_request

        def before_dispatch(*args, **kwargs):
            result = original(*args, **kwargs)
            reached.append(True)
            mutate(e, change)
            return result

        monkeypatch.setattr(ai_provider, "guard_request", before_dispatch)
    else:
        store = e.auto if seam == "automatic_intent" else e.service.store
        method = "begin_ai_request" if seam == "automatic_intent" else "begin"
        original = getattr(store, method)

        def before_dispatch(*args, **kwargs):
            result = original(*args, **kwargs)
            reached.append(True)
            mutate(e, change)
            return result

        monkeypatch.setattr(store, method, before_dispatch)
    assert require(e) is None
    assert reached == [True] and not dispatch.requests
    intents = e.auto.ai_requests()
    assert len(intents) == 1
    assert intents[0]["status"] in {"failed", "stale", "unknown"}
    assert require(e) is None
    assert not dispatch.requests and len(e.auto.ai_requests()) == 1
    no_native_work(e)


def test_real_concurrent_mode_change_holds_mode_lock_without_allowing_new_post(
    dispatch, monkeypatch
):
    e = dispatch.env
    reserved, pending, release = Event(), Event(), Event()
    errors = []
    original_invoker = e.native.invoker
    original_reservation = e.auto.begin_ai_request

    def hold_native_ack(target, request, **kwargs):
        if request["op"] == "set_mode" and request["mode"] == "manual":
            pending.set()
            assert release.wait(5), "Native acknowledgment barrier timed out"
        return original_invoker(target, request, **kwargs)

    def after_durable_intent(**kwargs):
        result = original_reservation(**kwargs)
        reserved.set()
        assert pending.wait(5), "Mode change did not enter real native sync"
        assert e.native.mode_lock.locked()
        assert e.modes.status()["mode"] == "manual"
        assert e.modes.status()["mode_sync_complete"] is False
        return result

    def change_mode():
        try:
            assert reserved.wait(5), "No durable AI intent"
            mutate(e, "manual")
        except BaseException as error:
            errors.append(type(error).__name__)

    monkeypatch.setattr(e.native, "invoker", hold_native_ack)
    monkeypatch.setattr(e.auto, "begin_ai_request", after_durable_intent)
    worker = Thread(target=change_mode, daemon=True)
    worker.start()
    try:
        assert require(e) is None
        assert not dispatch.requests
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and not errors
    assert len(e.auto.ai_requests()) == 1
    assert require(e) is None and not dispatch.requests
    no_native_work(e)


def test_already_admitted_request_is_not_replayed_after_mode_changes(dispatch):
    e = dispatch.env
    dispatch.success = True

    def after_transport_admission():
        # A completed mode change from the transport callback proves the sender
        # does not retain mode_lock over provider I/O.
        assert not e.native.mode_lock.locked()
        mutate(e, "manual")

    dispatch.on_request = after_transport_admission
    assert require(e) is None
    assert len(dispatch.requests) == 1
    assert e.auto.ai_requests()[0]["status"] == "stale"
    assert require(e) is None and len(dispatch.requests) == 1
    no_native_work(e)


def test_blocked_automatic_context_does_not_disable_explicit_manual_advice(dispatch, monkeypatch):
    e = dispatch.env
    original = e.service.store.begin

    def revoke_after_analysis_begins(*args, **kwargs):
        result = original(*args, **kwargs)
        mutate(e, "manual")
        return result

    monkeypatch.setattr(e.service.store, "begin", revoke_after_analysis_begins)
    assert require(e) is None and not dispatch.requests
    monkeypatch.setattr(e.service.store, "begin", original)
    catalog = e.service.preview(HOST)["catalog"]
    selection = {"kind": "single_candidate", "candidate_id": catalog[0]["candidate_id"]}
    preview = e.service.preview(HOST, selection=selection)
    result = e.service.analyze(
        AnalysisRequest(
            host_id=HOST,
            analysis_id="7" * 32,
            expected_input_digest=preview["input_digest"],
            confirm_send=True,
            selection=selection,
        )
    )
    assert result["status"] == "failed" and len(dispatch.requests) == 1
    assert len(e.auto.ai_requests()) == 1
    no_native_work(e)
