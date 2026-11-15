"""Frozen fake exit matrix, never deployment credentials, SSH or real providers.

The 80 core cases distinguish source engines/projection from the final provider
gate. Additional cases exercise existing vulnerability API and automatic
services. Full SSH API/session coverage is recorded in its separate matrix.
A successful synthetic wire control precedes each core rejection.
"""

import copy
import json
import sqlite3
import sys
from contextlib import closing
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from test_ai import report as diagnosis_report
from test_automatic_ai import gated as gated
from test_automatic_ai import require as require_automatic
from test_defense_ai import OUTPUT
from test_defense_ai import analyze as analyze_defense
from test_defense_ai import environment as defense_environment
from test_security_ai import alert as security_alert
from test_security_ai import output as security_output
from test_vulnerability_ai import catalog as catalog
from test_vulnerability_ai import scan as scan
from test_vulnerability_ai_service import env as env

from opsark import ai, ai_provider, security_ai
from opsark import vulnerability_ai as vulnerability
from opsark import vulnerability_ai_focus as focus
from opsark.ai_egress import AIEgressBlocked
from opsark.config import ANTHROPIC_BASE_URL, Settings
from opsark.defense_ai import project_egress as project_defense_source
from opsark.models import Finding
from opsark.vulnerability_ai_api import register_vulnerability_ai_routes

ROUTES = ("diagnosis", "security", "vulnerability", "focused", "ssh_defense")
KINDS = ("key_token", "pem", "database", "unclassified_field")
ADAPTERS = ("openai", "anthropic")
LAYERS = ("source", "final_body")
TAIL = "synthetic-unprojected-matrix-tail-only"
PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "c3ludGhldGljLW1hdHJpeC1jYW5hcnktbm90LWEta2V5\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
DATABASE = "-- PostgreSQL database dump\nCOPY fake_rows(value) FROM stdin;\nfake-only\n\\.\n"


@pytest.fixture(autouse=True)
def no_real_transport(monkeypatch):
    import paramiko

    attempts = []

    def deny(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("The release matrix permits MockTransport only")

    async def deny_async(*args, **kwargs):
        return deny(*args, **kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", deny)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", deny)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", deny_async)
    yield
    assert attempts == []


def configured(path, adapter):
    return Settings(
        path,
        "synthetic-release-console-token-only",
        ai_key="synthetic-release-provider-token-only",
        ai_model="synthetic-release-model",
        ai_base_url=ANTHROPIC_BASE_URL
        if adapter == "anthropic"
        else "https://synthetic-provider.invalid/v1",
        ai_provider=adapter,
        ai_response_format="json_prompt" if adapter == "anthropic" else "json_object",
    )


def adapter_settings(value, adapter):
    return replace(
        value,
        ai_provider=adapter,
        ai_base_url=ANTHROPIC_BASE_URL
        if adapter == "anthropic"
        else "https://synthetic-provider.invalid/v1",
        ai_response_format="json_prompt" if adapter == "anthropic" else "json_object",
        ai_token_limit_parameter="max_tokens",
        ai_thinking_mode="provider_default",
    )


def canary(kind, settings):
    return {
        "key_token": settings.ai_key,
        "pem": PEM,
        "database": DATABASE,
        "unclassified_field": "matrix-unclassified-value",
    }[kind]


def payload(route, summary):
    if route == "diagnosis":
        return {"summary": "合成证据需要复核。", "evidence_ids": [summary["evidence"][0]["id"]]}
    if route == "security":
        return security_output(evidence_ids=[summary["events"][0]["id"]])
    if route == "ssh_defense":
        return OUTPUT
    finding = summary["findings"][0]
    candidate = summary["candidate_catalog"][0]
    return {
        "summary": "受控实验需要人工核对候选。",
        "uncertainty": ["覆盖仍不完整。"],
        "evidence_refs": [finding["evidence_ref"], "coverage-1"],
        "finding_analyses": [],
        "proposals": [
            {
                "candidate_id": candidate["candidate_id"],
                "rationale": "建议核对受控实验候选。",
                "evidence_refs": [finding["evidence_ref"]],
            }
        ],
        "actions_executable": False,
    }


@pytest.fixture
def wire(monkeypatch):
    calls = []
    active = {"route": None, "adapter": None}
    original = httpx.AsyncClient

    def respond(request):
        calls.append(request)
        body = json.loads(request.content)
        native = active["adapter"] == "anthropic"
        assert request.url.path == ("/v1/messages" if native else "/v1/chat/completions")
        summary = json.loads(body["messages"][0 if native else 1]["content"])
        text = json.dumps(payload(active["route"], summary), ensure_ascii=False)
        if native:
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
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": text}}
                ]
            },
        )

    monkeypatch.setattr(
        ai_provider.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs),
    )
    return SimpleNamespace(calls=calls, active=active)


def build(route, adapter, path, scan, catalog):
    path.mkdir(parents=True, exist_ok=True)
    settings = configured(path, adapter)
    if route == "diagnosis":
        source = diagnosis_report()
        source.facts.extend(copy.deepcopy(source.facts[0]) for _ in range(15))
        source.facts.append(Finding(text=source.facts[0].text, evidence_ids=["E-1"]))

        def run():
            return ai.explain(source, settings)

        summary = ai.explanation_input(source)
        body = {
            "model": settings.ai_model,
            "messages": [
                {"role": "system", "content": ai.egress_system(summary)},
                {"role": "user", "content": json.dumps(summary)},
            ],
        }
        if (fmt := ai.egress_format(settings)) is not None:
            body["response_format"] = fmt
    elif route == "security":
        source = security_alert()
        source["events"] = [
            {**copy.deepcopy(source["events"][0]), "id": f"{index:064x}"} for index in range(1, 26)
        ]
        source["events"][-1]["raw_matrix_tail"] = TAIL

        def run():
            return security_ai.analyze_alert(source, settings)

        summary = security_ai.analysis_input(source)
        body = {
            "model": settings.ai_model,
            "messages": [
                {"role": "system", "content": security_ai.egress_system(summary)},
                {"role": "user", "content": json.dumps(summary)},
            ],
        }
        if (fmt := security_ai.egress_format(settings)) is not None:
            body["response_format"] = fmt
    elif route in {"vulnerability", "focused"}:
        source, candidates = copy.deepcopy(scan), copy.deepcopy(catalog)
        source["packages"][0].pop("private_apt_uri", None)
        source["gaps"] = source["gaps"][:2]
        first = copy.deepcopy(source["findings"][0])
        source["findings"] = [first] + [
            {**copy.deepcopy(first), "finding_id": f"{index:064x}"} for index in range(1, 43)
        ]
        source["findings"][-1]["raw_matrix_tail"] = TAIL
        source["coverage"]["evaluated_finding_count"] = len(source["findings"])
        selection = {"kind": "single_candidate", "candidate_id": candidates[0]["candidate_id"]}
        engine = focus if route == "focused" else vulnerability
        options = {"selection": selection} if route == "focused" else {}

        def run():
            return engine.analyze(source, candidates, settings, **options)

        reduced = engine.analysis_input(
            source, candidates, **({"selection": selection} if route == "focused" else {})
        )
        summary, _aliases = vulnerability.project_egress(reduced)
        body = engine.request_body(summary, settings)
    else:
        store, cursor, _reply, state, service = defense_environment(path, provider=adapter)
        settings = state["settings"]
        preview = service.preview(cursor.context.host_id, cursor.rid, "c" * 32)
        summary = preview["input"]
        from opsark.defense_ai import request_body

        body = request_body(summary, settings)

        def run():
            return analyze_defense(service, cursor)

        source = service._source(cursor.context.host_id, cursor.rid, state["snapshot"], settings)
        return SimpleNamespace(
            route=route,
            settings=settings,
            source=source,
            run=run,
            body=body,
            service=service,
            store=store,
            cursor=cursor,
            preview=preview,
            root_reply=_reply,
        )
    return SimpleNamespace(route=route, settings=settings, source=source, run=run, body=body)


def poison_source(case, kind, monkeypatch):
    value = canary(kind, case.settings)
    if case.route == "diagnosis":
        case.source.facts[-1].text = value
    elif case.route == "security":
        case.source["events"][-1]["raw_matrix_tail"] = value
        if kind == "unclassified_field":
            case.source["events"][-1]["path_class"] = value
    elif case.route in {"vulnerability", "focused"}:
        case.source["findings"][-1]["raw_matrix_tail"] = value
        if kind == "unclassified_field":
            case.source["findings"][-1]["affected"] = value
    else:
        data = case.source.model_dump(mode="json")
        data["candidates"][-1]["unclassified_matrix_tail"] = value
        case.source = data


def poison_body(body, kind, settings):
    result = copy.deepcopy(body)
    summary = json.loads(result["messages"][1]["content"])
    summary["unclassified_matrix_field"] = canary(kind, settings)
    result["messages"][1]["content"] = json.dumps(summary)
    return result


def status(value):
    return value.status if hasattr(value, "status") else value["status"]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("layer", LAYERS)
def test_existing_route_rejects_whole_canary_with_zero_dispatch_delta(
    route, adapter, kind, layer, tmp_path, scan, catalog, wire, monkeypatch, record_property
):
    for name, value in {
        "route": route,
        "adapter": adapter,
        "canary": kind,
        "layer": layer,
        "coverage": ("source_projection_only" if route == "ssh_defense" else "source_engine")
        if layer == "source"
        else "final_transport_only",
    }.items():
        record_property(name, value)
    wire.active.update(route=route, adapter=adapter)
    good = build(route, adapter, tmp_path / "positive", scan, catalog)
    assert ai_provider.provider_status(good.settings)["configured"] is True
    assert status(good.run()) == "completed" and len(wire.calls) == 1
    assert TAIL not in wire.calls[0].content.decode()
    bad = build(route, adapter, tmp_path / "negative", scan, catalog)
    baseline = len(wire.calls)
    if layer == "final_body":
        body = poison_body(bad.body, kind, bad.settings)
        for _ in range(2):
            with pytest.raises(AIEgressBlocked):
                ai_provider.request_document(body, bad.settings, route=route)
            assert len(wire.calls) == baseline
    else:
        poison_source(bad, kind, monkeypatch)
        for _ in range(2):
            if route == "ssh_defense":
                with pytest.raises(AIEgressBlocked):
                    project_defense_source(bad.source, bad.root_reply, "c" * 32, bad.settings)
                with closing(sqlite3.connect(bad.store.path)) as db, db:
                    assert (
                        db.execute("SELECT count(*) FROM defense_usage WHERE kind='ai'").fetchone()[
                            0
                        ]
                        == 0
                    )
            else:
                assert status(bad.run()) == "failed"
            assert len(wire.calls) == baseline


@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("route", ["vulnerability", "focused"])
def test_existing_manual_api_final_body_canary_never_reaches_provider(
    adapter, kind, route, env, monkeypatch, wire, record_property
):
    for key, value in {
        "coverage": "complete_manual_analysis_api",
        "layer": "final_body",
        "route": route,
        "adapter": adapter,
        "canary": kind,
    }.items():
        record_property(key, value)
    monkeypatch.setitem(sys.modules, "opsark.ai_provider", ai_provider)
    env.service.settings = adapter_settings(env.settings, adapter)
    env.service.analyzer, env.service.focus_analyzer = vulnerability.analyze, focus.analyze
    wire.active.update(route=route, adapter=adapter)
    host = next(iter(env.native.targets))
    selection = (
        {
            "kind": "single_candidate",
            "candidate_id": env.service.preview(host)["catalog"][0]["candidate_id"],
        }
        if route == "focused"
        else None
    )
    preview = env.service.preview(host, selection=selection)
    app = FastAPI()

    def authorize(request: Request):
        if request.headers.get("Authorization") != "Bearer " + env.settings.token:
            raise HTTPException(401, "synthetic authorization required")

    register_vulnerability_ai_routes(app, env.service, [Depends(authorize)])
    with TestClient(app, headers={"Authorization": "Bearer " + env.settings.token}) as client:
        body = {
            "host_id": host,
            "analysis_id": "1" * 32,
            "expected_input_digest": preview["input_digest"],
            "confirm_send": True,
        }
        if selection is not None:
            body["selection"] = selection
        control = client.post("/api/vulnerability-ai/analyses", json=body)
        assert (
            control.status_code == 200
            and control.json()["status"] == "completed"
            and len(wire.calls) == 1
        )
        original = ai_provider.request_document

        def poisoned(request, configured, **kwargs):
            return original(poison_body(request, kind, configured), configured, **kwargs)

        monkeypatch.setattr(ai_provider, "request_document", poisoned)
        body["analysis_id"] = "2" * 32
        blocked = client.post("/api/vulnerability-ai/analyses", json=body)
        assert blocked.status_code == 200 and blocked.json()["status"] == "failed"
        assert blocked.json()["result"]["failure_kind"] == "ai_egress_blocked"
        assert len(wire.calls) == 1
        assert client.post("/api/vulnerability-ai/analyses", json=body).json() == blocked.json()
        assert len(wire.calls) == 1


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("layer", LAYERS)
def test_existing_automatic_service_preserves_single_budget_and_never_retries_canary(
    kind, layer, gated, monkeypatch, wire, record_property
):
    for key, value in {
        "coverage": "automatic_service_openai",
        "route": "focused",
        "adapter": "openai",
        "canary": kind,
        "layer": layer,
    }.items():
        record_property(key, value)
    monkeypatch.setitem(sys.modules, "opsark.ai_provider", ai_provider)
    gated.service.focus_analyzer = focus.analyze
    wire.active.update(route="focused", adapter="openai")
    preview = gated.service.preview(gated.candidate["host_id"])
    assert preview["configured"] is True and wire.calls == []
    if layer == "source":
        bad = copy.deepcopy(gated.scan)
        bad["unprojected_matrix_tail"] = canary(kind, gated.settings)
        if kind == "unclassified_field":
            bad["findings"][0]["affected"] = canary(kind, gated.settings)
        gated.patches.save_scan(gated.candidate["host_id"], bad)
        gated.scan = bad
    else:
        original = ai_provider.request_document

        def poisoned(body, configured, **kwargs):
            return original(poison_body(body, kind, configured), configured, **kwargs)

        monkeypatch.setattr(ai_provider, "request_document", poisoned)
    assert require_automatic(gated) is None and wire.calls == []
    assert require_automatic(gated) is None and wire.calls == []
    assert len(gated.auto.ai_requests()) == (0 if layer == "source" else 1)
    assert all(call["op"] == "set_mode" for call in gated.root_calls)
