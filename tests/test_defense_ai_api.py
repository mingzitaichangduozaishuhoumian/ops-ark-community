"""Real application/HTTP/ledger boundaries; synthetic identities and MockTransport only."""

import json
import sqlite3
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from test_defense_api import EVIDENCE, NOW, SOURCE, FakeRoot, policy
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark import ai_provider
from opsark.ai_egress import AIEgressBlocked
from opsark.baselines import scope_for
from opsark.config import Settings
from opsark.defense_ai import DefenseAIBlocked, intent_key
from opsark.defense_ai_api import register_defense_ai_routes
from opsark.defense_client import DefenseClientError
from opsark.defense_store import DefenseConflict

TOKEN = "newfake-ai-http-console-token-only"
OUTPUT = {
    "v": 1,
    "decision": "propose_defense",
    "candidate_alias": "candidate-1",
    "evidence_aliases": ["evidence-1"],
    "reason_code": "evidence_sufficient",
}


@pytest.fixture
def assembled(tmp_path, monkeypatch, target, main_module):
    def create(*, consent=True, token=TOKEN):
        settings = Settings(
            data_dir=tmp_path / "newfake-http-data",
            token=token,
            ai_key="newfake-ai-http-provider-token-only",
            ai_base_url="https://newfake-ai.example/v1",
            ai_model="newfake-http-model",
        )
        deployment = policy(
            target,
            ai={
                "enabled": consent,
                "provider_fingerprint": ai_provider.provider_fingerprint(settings),
                "max_analyses_per_day": 2,
                "max_total_analyses": 2,
                "requires_ai": True,
            },
        )
        monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": target.host})
        monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
        monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": target})
        monkeypatch.setattr(main_module, "load_defense_policy", lambda _: deployment)
        app = main_module.create_app(settings)
        clock = [NOW]
        root = FakeRoot(target, lambda: clock[0])
        service, ai = app.state.defense_service, app.state.defense_ai_service
        service.invoker, service.clock, ai.now = root, lambda: clock[0], lambda: clock[0]
        client = TestClient(app, headers={"Authorization": "Bearer " + token})
        response = client.post(
            "/api/hosts/fixture/ssh-defense/arm",
            json={"expected_mode_revision": 0, "confirm_arm": True},
        )
        assert response.status_code == 200
        cursor_rid = response.json()["request_id"]
        assert (
            client.post(
                f"/api/hosts/fixture/ssh-defense/transactions/{cursor_rid}/query", json={}
            ).status_code
            == 200
        )
        return SimpleNamespace(
            app=app,
            client=client,
            root=root,
            service=service,
            ai=ai,
            store=service.store,
            settings=settings,
            clock=clock,
            cursor_rid=cursor_rid,
            preview_url="/api/hosts/fixture/ssh-defense/ai/preview",
            analyze_url="/api/hosts/fixture/ssh-defense/ai/analyses",
        )

    return create


def preview(h):
    return h.client.get(
        h.preview_url, params={"cursor_request_id": h.cursor_rid, "source_ref": SOURCE}
    )


def request_body(h):
    response = preview(h)
    assert response.status_code == 200, response.text
    value = response.json()
    return {
        "cursor_request_id": h.cursor_rid,
        "source_ref": SOURCE,
        "expected_input_digest": value["input_digest"],
        "expected_mode_revision": value["mode_revision"],
        "confirm_send": True,
    }


def provider(monkeypatch, *, fail=False):
    requests = []
    original = httpx.AsyncClient

    def respond(request):
        requests.append(request)
        if fail:
            raise httpx.ReadTimeout("newfake-sensitive-provider-error", request=request)
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

    monkeypatch.setattr(
        ai_provider.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(respond), **kw),
    )
    return requests


@pytest.mark.parametrize("endpoint", ["preview", "analyze", "get"])
def test_real_routes_reject_anonymous_before_source_or_provider(assembled, monkeypatch, endpoint):
    h = assembled()
    calls = provider(monkeypatch)
    body = request_body(h)

    def forbidden(*_args, **_kwargs):
        pytest.fail("anonymous request reached the AI service")

    for operation in ("preview", "analyze", "get"):
        monkeypatch.setattr(h.ai, operation, forbidden)
    anonymous = TestClient(h.app)
    if endpoint == "preview":
        response = anonymous.get(
            h.preview_url, params={"cursor_request_id": h.cursor_rid, "source_ref": SOURCE}
        )
    elif endpoint == "analyze":
        response = anonymous.post(h.analyze_url, json=body)
    else:
        response = anonymous.get(h.analyze_url + "/" + "a" * 32)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert not calls
    assert not any(transaction.kind == "action" for transaction in h.store.transactions())


@pytest.mark.parametrize("confirmation", [False, 1, 0, "true", None])
def test_confirm_send_must_be_the_true_boolean(assembled, monkeypatch, confirmation):
    h = assembled()
    calls = provider(monkeypatch)
    body = request_body(h) | {"confirm_send": confirmation}
    response = h.client.post(h.analyze_url, json=body)
    assert response.status_code == 422
    assert not calls and not h.store.unfinished_ai(
        "fixture", h.service._context("fixture").defense_scope
    )


@pytest.mark.parametrize(
    "change",
    [
        {"expected_mode_revision": True},
        {"expected_mode_revision": "0"},
        {"expected_mode_revision": -1},
        {"expected_input_digest": "bad-digest-canary"},
        {"cursor_request_id": 123},
        {"source_ref": "wrong-reference-canary"},
        {"command": "sensitive-extra-command-canary"},
        {"api_key": "sensitive-extra-key-canary"},
    ],
)
def test_analysis_body_is_strict_and_validation_does_not_reflect_input(
    assembled, monkeypatch, change
):
    h = assembled()
    calls = provider(monkeypatch)
    response = h.client.post(h.analyze_url, json=request_body(h) | change)
    assert response.status_code == 422 and not calls
    for value in change.values():
        if type(value) is str:
            assert value not in response.text


@pytest.mark.parametrize(
    "path,params",
    [
        ("preview", {"cursor_request_id": "invalid-cursor-canary", "source_ref": SOURCE}),
        (
            "preview",
            {"cursor_request_id": "a" * 32, "source_ref": SOURCE, "command": "query-extra-canary"},
        ),
        ("get", {}),
        ("host", {"cursor_request_id": "a" * 32, "source_ref": SOURCE}),
    ],
)
def test_preview_query_and_analysis_path_references_are_typed(assembled, path, params):
    h = assembled()
    url = (
        h.preview_url
        if path == "preview"
        else (
            "/api/hosts/invalid$host-canary/ssh-defense/ai/preview"
            if path == "host"
            else h.analyze_url + "/invalid-analysis-canary"
        )
    )
    response = h.client.get(url, params=params)
    assert response.status_code == 422
    assert "canary" not in response.text


def test_manual_confirmed_analysis_is_advice_only_and_wire_is_allowlisted(assembled, monkeypatch):
    h = assembled()
    calls = provider(monkeypatch)
    before = list(h.root.sent)
    response = h.client.post(h.analyze_url, json=request_body(h))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "completed" and result["decision"] == "propose_defense"
    assert result["actions_executable"] is False and len(calls) == 1
    assert h.root.sent == before
    assert h.app.state.mode_coordinator.status()["mode"] == "manual"
    assert not h.app.state.patch_service.targets and not h.service.automation.policy.enabled
    assert all(transaction.kind == "cursor" for transaction in h.store.transactions())
    permit = h.store.ai_permit(analysis_id=result["analysis_id"])
    assert permit.advice_authorization is not None
    assert h.store.usage(permit.intent_key).kind == "ai"
    assert h.store.usage(permit.intent_key).state == "consumed"
    assert not h.ai.validate_proposal(h.service._context("fixture"), h.cursor_rid, SOURCE, EVIDENCE)
    assert h.client.get(h.analyze_url + "/" + result["analysis_id"]).json() == result
    assert response.headers["cache-control"] == "no-store"
    raw = calls[0].content.decode()
    for private in (
        h.cursor_rid,
        SOURCE,
        EVIDENCE,
        "fixture-a",
        "fixture-b",
        h.settings.token,
        h.settings.ai_key,
        h.service._context("fixture").root_scope,
    ):
        assert private not in raw
    body = json.loads(calls[0].content)
    projected = json.loads(body["messages"][-1]["content"])
    assert projected["candidates"][0]["candidate_alias"] == "candidate-1"
    assert projected["candidates"][0]["ttl_seconds"] == 60
    assert (
        h.client.post(
            "/api/hosts/fixture/ssh-defense/prepare",
            json={
                "cursor_request_id": h.cursor_rid,
                "source_ref": SOURCE,
                "expected_evidence_sha256": EVIDENCE,
                "expected_mode_revision": 0,
            },
        ).status_code
        == 409
    )
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)


@pytest.mark.parametrize(
    "failure", ["source", "expired_source", "consent", "privacy", "digest", "revision"]
)
def test_source_consent_and_privacy_fail_closed_without_provider_or_leaks(
    assembled, monkeypatch, failure
):
    h = assembled(consent=failure != "consent", token=EVIDENCE if failure == "privacy" else TOKEN)
    calls = provider(monkeypatch)
    if failure == "privacy":
        response = preview(h)
    else:
        body = request_body(h)
        if failure == "source":
            body["source_ref"] = "0" * 32
        elif failure == "expired_source":
            h.clock[0] += timedelta(seconds=121)
        elif failure == "digest":
            body["expected_input_digest"] = "0" * 64
        elif failure == "revision":
            body["expected_mode_revision"] = 1
        response = h.client.post(h.analyze_url, json=body)
    assert response.status_code == 409, response.text
    assert not calls
    for value in (h.settings.token, h.settings.ai_key, h.cursor_rid, SOURCE, EVIDENCE):
        assert value not in response.text
    source = h.store.cursor_source(
        h.cursor_rid, host_scope=scope_for(h.service.targets["fixture"].host.public)
    )
    assert (
        h.store.ai_permit(
            intent_key=intent_key(source, SOURCE, ai_provider.provider_fingerprint(h.settings))
        )
        is None
    )
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)


def test_unknown_analysis_and_restart_preserve_one_cost_intent_without_replay(
    assembled, monkeypatch, main_module
):
    h = assembled()
    calls = provider(monkeypatch, fail=True)
    body = request_body(h)
    response = h.client.post(h.analyze_url, json=body)
    assert response.status_code == 200, response.text
    retained = response.json()
    assert retained["status"] == "unknown" and retained["proof_sha256"] is None
    assert retained["actions_executable"] is False and len(calls) == 1
    assert "newfake-sensitive-provider-error" not in response.text
    assert h.client.post(h.analyze_url, json=body).json() == retained
    assert h.client.get(h.analyze_url + "/" + retained["analysis_id"]).json() == retained
    restarted = main_module.create_app(h.settings)
    restarted.state.defense_service.clock = lambda: NOW
    restarted.state.defense_ai_service.now = lambda: NOW
    restarted.state.defense_service.invoker = lambda *_args, **_kwargs: pytest.fail("Root replay")
    client = TestClient(restarted, headers={"Authorization": "Bearer " + h.settings.token})
    assert client.get(h.analyze_url + "/" + retained["analysis_id"]).json() == retained
    assert client.post(h.analyze_url, json=body).json() == retained
    assert len(calls) == 1
    permit = h.store.ai_permit(analysis_id=retained["analysis_id"])
    assert h.store.usage(permit.intent_key).state == "unknown"
    assert h.store.latched("fixture", h.service._context("fixture").defense_scope)
    assert all(transaction.kind == "cursor" for transaction in h.store.transactions())


@pytest.mark.parametrize(
    "exception,status",
    [
        (DefenseAIBlocked("scope-secret-canary"), 409),
        (DefenseConflict("ledger-secret-canary"), 409),
        (ValueError("source-secret-canary"), 409),
        (AIEgressBlocked("sensitive_content"), 409),
        (DefenseClientError("target_invalid"), 503),
        (sqlite3.OperationalError("database-secret-canary"), 503),
        (OSError("private-path-secret-canary"), 503),
    ],
)
def test_route_error_mapping_is_fixed_and_never_reflects_exceptions(
    assembled, monkeypatch, exception, status
):
    h = assembled()
    calls = provider(monkeypatch)

    def fail(*_args, **_kwargs):
        raise exception

    monkeypatch.setattr(h.ai, "preview", fail)
    response = preview(h)
    assert response.status_code == status
    assert "canary" not in response.text and "target_invalid" not in response.text
    assert not calls


def test_changed_synthetic_role_key_maps_to_safe_conflict(assembled, monkeypatch):
    h = assembled()
    calls = provider(monkeypatch)
    body = request_body(h)
    # Only the newly generated fixture identity is modified; never deployment keys.
    h.service.targets["fixture"].readonly.key_file.write_text("newfake-replaced-key-canary")
    response = h.client.post(h.analyze_url, json=body)
    assert response.status_code == 409
    assert "newfake-replaced-key-canary" not in response.text
    assert not calls


def test_standalone_registration_preserves_auth_and_sanitized_validation():
    called = []

    def authorize():
        raise HTTPException(status_code=401, detail="newfake-auth-required")

    service = SimpleNamespace(
        preview=lambda *_: called.append("preview"),
        analyze=lambda *_: called.append("analyze"),
        get=lambda *_: called.append("get"),
    )
    protected = FastAPI()
    register_defense_ai_routes(protected, service, [Depends(authorize)])
    assert (
        TestClient(protected)
        .get("/api/hosts/fixture/ssh-defense/ai/analyses/" + "a" * 32)
        .status_code
        == 401
    )
    assert not called
    standalone = FastAPI()
    register_defense_ai_routes(standalone, service, [])
    response = TestClient(standalone).post(
        "/api/hosts/fixture/ssh-defense/ai/analyses", json={"secret": "standalone-secret-canary"}
    )
    assert response.status_code == 422 and "standalone-secret-canary" not in response.text
    assert not called


def test_cross_origin_and_query_token_are_rejected_before_analysis(assembled, monkeypatch):
    h = assembled()
    calls = provider(monkeypatch)
    body = request_body(h)
    assert (
        h.client.post(
            h.analyze_url, json=body, headers={"Origin": "https://newfake-other.example"}
        ).status_code
        == 403
    )
    assert (
        h.client.get(
            h.preview_url,
            params={
                "cursor_request_id": h.cursor_rid,
                "source_ref": SOURCE,
                "token": "query-secret-canary",
            },
        ).status_code
        == 400
    )
    assert not calls
