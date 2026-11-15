"""SSH manual HTTP route and explicit-session AI service privacy matrix.

Only temporary synthetic sources/configuration, in-memory Root and MockTransport
are used. Each negative has an independent successful control. This is a new
targeted matrix, not full-main/browser/worker, native SSH or full-product proof.
"""

import copy
import hashlib
import json
import socket
import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import paramiko
import pytest
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from test_defense_ai import OUTPUT
from test_defense_ai import environment as manual_environment
from test_defense_api import NOW, SOURCE
from test_defense_api import harness as harness_factory
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_store import admission, observing
from test_defense_session_store import session as session_factory

from opsark import ai_provider, defense_ai
from opsark.ai_egress import AIEgressBlocked
from opsark.config import ANTHROPIC_BASE_URL, Settings
from opsark.defense_ai import DefenseAIService, DefenseAISnapshot
from opsark.defense_ai_api import register_defense_ai_routes
from opsark.defense_models import canonical
from opsark.defense_policy import DefenseAIConsent

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "src/opsark/ai_egress.py",
    "src/opsark/ai_provider.py",
    "src/opsark/defense_ai.py",
    "src/opsark/defense_ai_api.py",
    "src/opsark/defense_store.py",
    "src/opsark/defense_session_store.py",
    "src/opsark/defense_session_models.py",
)
PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "c3ludGhldGljLWZpeHR1cmUtbm90LWtleS1tYXRlcmlhbA==\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
DB_DUMP = (
    "-- PostgreSQL database dump\nCOPY public.fake_records (id, value) FROM stdin;\n"
    "1\tfake-db-export-only\n\\.\n"
)
CANARIES = {
    "key_token": {"api_key": "ssh-matrix-fake-key-only", "token": "ssh-matrix-fake-token-only"},
    "pem": PEM,
    "database_text": DB_DUMP,
    "unclassified": {"unrecognized_classification": "ordinary-but-unclassified"},
}


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def rows(store):
    with closing(sqlite3.connect(store.path)) as db, db:
        return {
            "ai_rows": db.execute("SELECT count(*) FROM defense_ai_intents").fetchone()[0],
            "ai_results": db.execute("SELECT count(*) FROM defense_ai_results").fetchone()[0],
            "actions": db.execute(
                "SELECT count(*) FROM defense_transactions WHERE kind='action'"
            ).fetchone()[0],
            "usage": db.execute(
                "SELECT kind,state,count(*) FROM defense_usage "
                "GROUP BY kind,state ORDER BY kind,state"
            ).fetchall(),
        }


@pytest.fixture(autouse=True)
def evidence(monkeypatch, tmp_path, request):
    before = hashes()
    state: dict[str, Any] = {
        "schema": "opsark-ai-egress-ssh-entry-case/v1",
        "completed": False,
        "test_scope": "targeted_manual_http_route_and_explicit_session_ai_service",
        "full_product_suite": False,
        "native_ssh_or_real_provider_verified": False,
        "real_transport_attempts": {
            "httpx_sync": 0,
            "httpx_async": 0,
            "paramiko_connect": 0,
            "socket_create_connection": 0,
        },
        "source_before": before,
    }

    def reject(kind):
        def fail(*_args, **_kwargs):
            state["real_transport_attempts"][kind] += 1
            raise AssertionError("SSH matrix permits only synthetic transports")

        return fail

    async def fail_async(*_args, **_kwargs):
        state["real_transport_attempts"]["httpx_async"] += 1
        raise AssertionError("SSH matrix permits only MockTransport")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", reject("httpx_sync"))
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fail_async)
    monkeypatch.setattr(paramiko.SSHClient, "connect", reject("paramiko_connect"))
    # Do not replace socket.socket.connect: Windows asyncio uses its own
    # loopback socketpair. The provider path is independently fenced above.
    monkeypatch.setattr(socket, "create_connection", reject("socket_create_connection"))
    yield state
    after = hashes()
    state["source_after"] = after
    state["source_unchanged"] = before == after
    state["case_id_sha256"] = hashlib.sha256(request.node.nodeid.encode()).hexdigest()
    with (tmp_path / "ssh-egress.safe.json").open("x", encoding="ascii") as output:
        output.write(json.dumps(state, sort_keys=True, indent=2) + "\n")
    assert before == after
    assert all(value == 0 for value in state["real_transport_attempts"].values())


def configured(directory, provider):
    if provider == "anthropic":
        return Settings(
            directory,
            "synthetic-ssh-entry-console-token-only",
            ai_key="synthetic-ssh-entry-provider-key-only",
            ai_model="synthetic-ssh-entry-model",
            ai_provider="anthropic",
            ai_base_url=ANTHROPIC_BASE_URL,
            ai_response_format="json_prompt",
        )
    return Settings(
        directory,
        "synthetic-ssh-entry-console-token-only",
        ai_key="synthetic-ssh-entry-provider-key-only",
        ai_model="synthetic-ssh-entry-model",
        ai_provider="openai",
        ai_base_url="https://ssh-matrix-provider.invalid/v1",
    )


def manual_scene(directory, provider):
    store, cursor, _reply, state, service = manual_environment(
        directory, mode="manual", provider=provider
    )
    app = FastAPI()

    def authenticated(authorization: str | None = Header(default=None)):
        if authorization != "Bearer " + state["settings"].token:
            raise HTTPException(401, "Synthetic console authentication required")

    register_defense_ai_routes(app, service, [Depends(authenticated)])
    client = TestClient(app, headers={"Authorization": "Bearer " + state["settings"].token})
    prefix = "/api/hosts/" + cursor.context.host_id + "/ssh-defense/ai"
    return SimpleNamespace(
        store=store,
        cursor=cursor.rid,
        host=cursor.context.host_id,
        state=state,
        service=service,
        client=client,
        prefix=prefix,
        admission=None,
    )


def session_scene(directory, provider, target):
    # Reuse the existing synthetic Root/mode/cursor and real opaque session
    # admission factory, before it declares a provider-bound AI intent.
    h = cast(Any, harness_factory).__wrapped__(directory, target)
    s = cast(Any, session_factory).__wrapped__(h)
    settings = configured(directory, provider)
    fingerprint = ai_provider.provider_fingerprint(settings)
    runtime = s.current[0].model_copy(
        update={"requires_ai": True, "provider_fingerprint": fingerprint}
    )
    s.current[0] = runtime
    s.declaration = s.declaration.model_copy(update={"runtime": runtime})
    observing(s)
    s.store.advance(admission(s, "observing"), next_phase="analyzing", now=NOW)
    token = admission(s, "analyzing")
    state: dict[str, Any] = {
        "settings": settings,
        "snapshot": DefenseAISnapshot(
            context=runtime.context,
            host_scope=runtime.host_scope,
            enabled=True,
            mode_sync_complete=True,
            stopping=False,
            sync_generation=runtime.context.epoch,
            consent=DefenseAIConsent(
                enabled=True,
                requires_ai=True,
                provider_fingerprint=fingerprint,
                max_analyses_per_day=4,
                max_total_analyses=8,
            ),
        ),
    }
    calls = []
    service = DefenseAIService(
        h.store,
        lambda: state["settings"],
        current_snapshot=lambda _: state["snapshot"],
        validate_admission=calls.append,
        now=lambda: h.clock[0],
    )
    return SimpleNamespace(
        store=h.store,
        cursor=s.declaration.cursor_rid,
        host="fixture",
        state=state,
        service=service,
        client=None,
        admission=token,
        root=h.root,
    )


def preview(scene):
    if scene.client is not None:
        response = scene.client.get(
            scene.prefix + "/preview",
            params={"cursor_request_id": scene.cursor, "source_ref": SOURCE},
        )
        assert response.status_code == 200
        return response.json()
    return scene.service.preview(scene.host, scene.cursor, SOURCE)


def analyze(scene, expected):
    if scene.client is not None:
        response = scene.client.post(
            scene.prefix + "/analyses",
            json={
                "cursor_request_id": scene.cursor,
                "source_ref": SOURCE,
                "expected_input_digest": expected["input_digest"],
                "expected_mode_revision": expected["mode_revision"],
                "confirm_send": True,
            },
        )
        return response.status_code, response.json()
    result = scene.service.analyze(
        scene.host,
        scene.cursor,
        SOURCE,
        expected_input_digest=expected["input_digest"],
        expected_mode_revision=expected["mode_revision"],
        automatic=True,
        session_admission=scene.admission,
        timeout_seconds=20,
    )
    return None, result


def wire(monkeypatch, provider):
    captured = []
    original = httpx.AsyncClient

    def respond(request):
        captured.append(request)
        assert request.method == "POST"
        assert request.url.path == (
            "/v1/messages" if provider == "anthropic" else "/v1/chat/completions"
        )
        body = json.loads(request.content)
        summary = json.loads(body["messages"][-1]["content"])
        assert set(summary) == {"v", "candidates", "omitted_candidate_count"}
        assert set(summary["candidates"][0]) == {
            "candidate_alias",
            "evidence_alias",
            "classification",
            "distinct_failure_ports",
            "ttl_seconds",
        }
        text = json.dumps(OUTPUT)
        return httpx.Response(
            200,
            json=(
                {
                    "type": "message",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "content": [{"type": "text", "text": text}],
                }
                if provider == "anthropic"
                else {
                    "choices": [
                        {"finish_reason": "stop", "message": {"role": "assistant", "content": text}}
                    ]
                }
            ),
        )

    monkeypatch.setattr(
        ai_provider.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs),
    )
    return captured


@pytest.mark.parametrize("entry", ["manual_api", "session_service"])
@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize("stage", ["source", "final_body"])
@pytest.mark.parametrize("category", list(CANARIES))
def test_ssh_entry_rejects_contamination_after_independent_live_control(
    tmp_path, target, monkeypatch, evidence, entry, provider, stage, category
):
    make = (
        (lambda path: manual_scene(path, provider))
        if entry == "manual_api"
        else (lambda path: session_scene(path, provider, target))
    )
    control, blocked = make(tmp_path / "positive-ledger"), make(tmp_path / "negative-ledger")
    captured = wire(monkeypatch, provider)
    status, result = analyze(control, preview(control))
    assert status in (None, 200) and result["status"] == "completed"
    assert result["decision"] == "propose_defense" and result["actions_executable"] is False
    assert len(captured) == 1
    assert rows(control.store)["ai_rows"] == 1 and rows(control.store)["actions"] == 0
    expected = preview(blocked)
    assert rows(blocked.store)["ai_rows"] == 0
    payload = copy.deepcopy(CANARIES[category])
    hits = []
    if stage == "source":
        original_source, original_bounds = blocked.service._source, blocked.store.source_time_bounds

        def source(*args, **kwargs):
            value = original_source(*args, **kwargs).model_dump(mode="json")
            # The omitted candidate is deliberately contaminated: projection
            # cannot discard unclassified or sensitive upstream content first.
            value["candidates"][-1]["unclassified_matrix_payload"] = payload
            return value

        def bounds(value, *args, **kwargs):
            try:
                return original_bounds(value, *args, **kwargs)
            except ValueError:
                if type(value) is dict:
                    hits.append("strict_source_schema")
                raise

        monkeypatch.setattr(blocked.service, "_source", source)
        monkeypatch.setattr(blocked.store, "source_time_bounds", bounds)
        if entry == "manual_api":
            rejected_status, rejected = analyze(blocked, expected)
            assert rejected_status == 409  # actual source refusal, not auth 401.
            assert "detail" in rejected
        else:
            with pytest.raises(ValueError):
                analyze(blocked, expected)
        assert hits == ["strict_source_schema"]
        assert rows(blocked.store) == {"ai_rows": 0, "ai_results": 0, "actions": 0, "usage": []}
        gate, blocked_status = "strict_source_schema", "source_rejected"
    else:
        original_body, original_guard = defense_ai.request_body, ai_provider.guard_request

        def body(*args, **kwargs):
            value = original_body(*args, **kwargs)
            value = copy.deepcopy(value)
            summary = json.loads(value["messages"][-1]["content"])
            summary["candidates"][-1]["unclassified_matrix_payload"] = payload
            value["messages"][-1]["content"] = canonical(summary).decode()
            return value

        def guard(*args, **kwargs):
            try:
                return original_guard(*args, **kwargs)
            except AIEgressBlocked as error:
                hits.append(error.code)
                raise

        monkeypatch.setattr(defense_ai, "request_body", body)
        monkeypatch.setattr(ai_provider, "guard_request", guard)
        rejected_status, rejected = analyze(blocked, expected)
        assert rejected_status in (None, 200) and rejected["status"] == "failed"
        assert rejected["proof_sha256"] is None and rejected["actions_executable"] is False
        assert len(hits) == 1 and hits[0] in {"sensitive_content", "unclassified_payload"}
        assert rows(blocked.store) == {
            "ai_rows": 1,
            "ai_results": 1,
            "actions": 0,
            "usage": [("ai", "unknown", 1)],
        }
        assert analyze(blocked, expected)[1] == rejected
        assert len(hits) == 1  # original failed intent read back; no replay/cost reset.
        assert rows(blocked.store)["usage"] == [("ai", "unknown", 1)]
        gate, blocked_status = "final_request_egress", "failed"
    assert len(captured) == 1
    assert rows(blocked.store)["actions"] == 0
    raw = captured[0].content.decode()
    for scene in (control, blocked):
        assert (
            scene.state["settings"].token not in raw and scene.state["settings"].ai_key not in raw
        )
        assert scene.cursor not in raw
    evidence.update(
        completed=True,
        entry=entry,
        provider=provider,
        stage=stage,
        category=category,
        layer="manual_analysis_http_route_service"
        if entry == "manual_api"
        else "explicit_session_ai_service",
        control_mock_wires=1,
        blocked_model_wire_increment=0,
        actual_gate=gate,
        gate_rejections=1,
        blocked_status=blocked_status,
        budget=rows(blocked.store),
        control_body_sha256=hashlib.sha256(captured[0].content).hexdigest(),
    )
