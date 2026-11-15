"""Provider compatibility, private credentials and one-attempt cost boundaries."""

import asyncio
import json
import os
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from opsark import ai_provider as provider
from opsark import vulnerability_ai
from opsark.ai_egress import AIEgressBlocked
from opsark.config import Settings, load_settings
from opsark.main import create_app


def settings(tmp_path, **fields):
    return Settings(
        data_dir=tmp_path,
        token="console-test-value-" * 3,
        ai_base_url="https://provider.example/v1",
        ai_model="configured-model",
        **({"ai_key": "provider-fixture-value"} | fields),
    )


def wire(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        provider.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(handler), **kw),
    )


def body(config):
    source = {
        "schema_version": 1,
        "scan_id": "a" * 32,
        "coverage": {"status": "unavailable"},
        "findings": [],
    }
    summary, _aliases = vulnerability_ai.project_egress(vulnerability_ai.analysis_input(source, []))
    return vulnerability_ai.request_body(summary, config)


def test_one_bounded_request_has_only_configured_key_and_no_automatic_retry(tmp_path, monkeypatch):
    calls = []

    def reply(request):
        calls.append(request)
        assert request.url == "https://provider.example/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer provider-fixture-value"
        sent = json.loads(request.content)
        assert sent["max_tokens"] == 2048
        assert "max_completion_tokens" not in sent and "tools" not in sent
        return httpx.Response(200, json={"choices": []})

    wire(monkeypatch, reply)
    config = settings(tmp_path)
    assert provider.request_document(body(config), config, route="vulnerability") == {"choices": []}
    assert len(calls) == 1


def test_gemini_compatible_endpoint_uses_the_same_egress_gate(tmp_path, monkeypatch):
    calls = []
    config = replace(
        settings(tmp_path, ai_response_format="json_prompt"),
        ai_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        ai_model="gemini-test-fixture",
    )

    def reply(request):
        calls.append(request)
        assert request.url.path == "/v1beta/openai/chat/completions"
        assert request.headers["authorization"] == "Bearer provider-fixture-value"
        assert json.loads(request.content)["model"] == "gemini-test-fixture"
        assert config.token.encode() not in request.content
        return httpx.Response(200, json={"choices": []})

    wire(monkeypatch, reply)
    approved = body(config)
    assert provider.request_document(approved, config, route="vulnerability") == {"choices": []}
    with pytest.raises(AIEgressBlocked):
        provider.request_document(
            {**approved, "metadata": {"private_token": config.token}}, config, route="vulnerability"
        )
    assert len(calls) == 1


def test_output_budget_parameter_is_explicit_and_prompt_mode_omits_format(tmp_path, monkeypatch):
    calls = []

    def reply(request):
        calls.append(request)
        sent = json.loads(request.content)
        assert sent["max_completion_tokens"] == 1000
        assert "max_tokens" not in sent and "response_format" not in sent
        return httpx.Response(200, json={"choices": []})

    wire(monkeypatch, reply)
    config = settings(
        tmp_path,
        ai_response_format="json_prompt",
        ai_token_limit_parameter="max_completion_tokens",
    )
    value = body(config) | {"max_tokens": 1000}
    provider.request_document(
        value,
        config,
        route="vulnerability",
    )
    with pytest.raises(AIEgressBlocked):
        provider.request_document(
            value | {"response_format": {"type": "json_object"}},
            config,
            route="vulnerability",
        )
    assert len(calls) == 1


@pytest.mark.parametrize("mode", ["provider_default", "enabled", "disabled"])
def test_only_explicit_config_controls_provider_thinking_without_changing_model(
    tmp_path, monkeypatch, mode
):
    calls = []

    def reply(request):
        sent = json.loads(request.content)
        calls.append(sent)
        assert sent["model"] == "configured-model"
        assert sent["max_tokens"] == 2048
        if mode == "provider_default":
            assert "thinking" not in sent
        else:
            assert sent["thinking"] == {"type": mode}
        return httpx.Response(200, json={"choices": []})

    wire(monkeypatch, reply)
    value = settings(tmp_path, ai_thinking_mode=mode)
    provider.request_document(body(value), value, route="vulnerability")
    with pytest.raises(AIEgressBlocked):
        provider.request_document(
            body(value) | {"thinking": {"type": mode}},
            value,
            route="vulnerability",
        )
    assert len(calls) == 1
    assert provider.provider_status(value)["thinking_mode"] == mode
    assert provider.provider_fingerprint(value) != provider.provider_fingerprint(
        replace(value, ai_thinking_mode="enabled" if mode == "disabled" else "disabled")
    )


@pytest.mark.parametrize("code", [301, 307, 400, 401, 403, 429, 500])
def test_http_failures_and_redirects_never_replay_or_leak(tmp_path, monkeypatch, code):
    calls = []

    def reply(request):
        calls.append(request)
        return httpx.Response(
            code,
            headers={"location": "https://other.example/credential-trap"},
            json={"private": "provider-fixture-value"},
        )

    wire(monkeypatch, reply)
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderError) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert "provider-fixture-value" not in str(caught.value)
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["timeout", "connection"])
def test_transport_loss_has_unknown_result_and_single_attempt(tmp_path, monkeypatch, kind):
    calls = []

    def reply(request):
        calls.append(request)
        cls = httpx.ReadTimeout if kind == "timeout" else httpx.ConnectError
        raise cls("sensitive provider error", request=request)

    wire(monkeypatch, reply)
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderRequestUnknown) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert "sensitive" not in str(caught.value) and len(calls) == 1


def test_total_deadline_bounds_slow_first_response(tmp_path, monkeypatch):
    calls = []

    async def reply(request):
        calls.append(request)
        await asyncio.sleep(0.1)
        return httpx.Response(200, json={})

    wire(monkeypatch, reply)
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderRequestUnknown):
        provider.request_document(body(config), config, route="vulnerability", timeout_seconds=0.01)
    assert len(calls) == 1


@pytest.mark.parametrize("raw", [b'{"choices":[],"choices":[]}', b'{"x":NaN}', b"[]"])
def test_response_is_strict_single_json_object(tmp_path, monkeypatch, raw):
    wire(monkeypatch, lambda _: httpx.Response(200, content=raw))
    config = settings(tmp_path)
    with pytest.raises(ValueError):
        provider.request_document(body(config), config, route="vulnerability")


def test_response_and_request_size_budgets(tmp_path, monkeypatch):
    wire(monkeypatch, lambda _: httpx.Response(200, content=b"x" * 1025))
    config = settings(tmp_path)
    with pytest.raises(ValueError):
        provider.request_document(
            body(config), config, route="vulnerability", max_response_bytes=1024
        )
    wire(monkeypatch, lambda _: pytest.fail("Oversized request must not be sent"))
    with pytest.raises(ValueError):
        provider.request_document(
            body(config) | {"extra": "x" * 70_000}, config, route="vulnerability"
        )


@pytest.mark.parametrize("route", ["unknown", "diagnosis", "vulnerability"])
def test_provider_never_sends_a_noncanonical_body(tmp_path, monkeypatch, route):
    wire(monkeypatch, lambda _: pytest.fail("Noncanonical request must not be sent"))
    config = settings(tmp_path)
    request = body(config)
    request["messages"][0]["content"] += "private unclassified suffix"
    with pytest.raises(AIEgressBlocked) as caught:
        provider.request_document(request, config, route=route)
    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    "model",
    [
        "namespace/provider-fixture-value:tag",
        "namespace/console-test-value-console-test-value-console-test-value-:tag",
        "namespace/model label",
        "namespace/model?options=true",
        "namespace/abc12345:tag",
    ],
)
def test_unsafe_configured_model_is_disabled_without_echo_or_wire(tmp_path, monkeypatch, model):
    wire(monkeypatch, lambda _: pytest.fail("Unsafe model label must not be sent"))
    config = replace(settings(tmp_path), ai_model=model)
    if model == "namespace/abc12345:tag":
        config = replace(config, token="ａｂｃ１２３４５")
    public = provider.provider_status(config)
    assert public["configured"] is False and public["model_name"] is None
    with pytest.raises(provider.ProviderError) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert model not in str(caught.value) + json.dumps(public)


def test_file_key_can_be_provisioned_later_and_rotated_without_api_echo(tmp_path):
    path = tmp_path / "provider-key"
    value = settings(tmp_path, ai_key=None, ai_key_file=path)
    assert provider.provider_status(value)["configured"] is False
    path.write_text("first-private-provider-value\n")
    path.chmod(0o600)
    assert provider.provider_status(value)["configured"] is True
    assert provider.resolve_ai_settings(value).ai_key == "first-private-provider-value"
    assert value.ai_key is None
    path.write_text("second-private-provider-value\n")
    assert provider.resolve_ai_settings(value).ai_key == "second-private-provider-value"
    unsafe_model = replace(value, ai_model="namespace/second-private-provider-value:tag")
    assert provider.provider_status(unsafe_model)["model_name"] is None
    compatible_model = replace(value, ai_model="namespace/model:tag+fp16")
    assert provider.provider_status(compatible_model)["model_name"] == compatible_model.ai_model
    assert provider.provider_fingerprint(value) == provider.provider_fingerprint(
        replace(value, ai_key_file=None, ai_key="other-private-value")
    )
    published = json.dumps(provider.provider_status(value))
    assert str(path) not in published and "private-provider-value" not in published


@pytest.mark.parametrize("value", ["", "x\ny", "x\ry", "x\x00y", "x" * 8193])
def test_invalid_secret_file_is_disabled_without_exposing_content(tmp_path, value):
    path = tmp_path / "provider-key"
    path.write_text(value)
    path.chmod(0o600)
    public = provider.provider_status(settings(tmp_path, ai_key=None, ai_key_file=path))
    assert public["configured"] is False and "credential" in public["missing"]


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX credential metadata")
def test_unsafe_permissions_symlink_hardlink_and_fifo_are_not_credentials(tmp_path):
    path = tmp_path / "provider-key"
    path.write_text("private-file-value")
    path.chmod(0o644)
    assert not provider.provider_status(settings(tmp_path, ai_key=None, ai_key_file=path))[
        "configured"
    ]
    path.chmod(0o600)
    linked = tmp_path / "linked"
    linked.symlink_to(path)
    assert not provider.provider_status(settings(tmp_path, ai_key=None, ai_key_file=linked))[
        "configured"
    ]
    hard = tmp_path / "hard"
    os.link(path, hard)
    assert not provider.provider_status(settings(tmp_path, ai_key=None, ai_key_file=path))[
        "configured"
    ]
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    assert not provider.provider_status(settings(tmp_path, ai_key=None, ai_key_file=fifo))[
        "configured"
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"finish_reason": "length"},
        {"tool_calls": [{}]},
        {"function_call": {"name": "shell"}},
        {"content": None},
        {"role": "system"},
    ],
)
def test_completion_must_be_finished_text_without_tools(change):
    document = {
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}]
    }
    if "finish_reason" in change:
        document["choices"][0].update(change)
    else:
        document["choices"][0]["message"].update(change)
    with pytest.raises(provider.ProviderError):
        provider.completion_text(document)


def test_refusal_is_explicit_and_no_payload_is_exposed():
    with pytest.raises(provider.ProviderRefusal):
        provider.completion_text(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": None, "refusal": "private refusal body"},
                    }
                ]
            }
        )


def test_ai_status_and_capabilities_are_authenticated_and_dynamic(tmp_path):
    path = tmp_path / "provider-key"
    cfg = settings(tmp_path, ai_key=None, ai_key_file=path)
    app = create_app(cfg)
    client = TestClient(app)
    auth = {"Authorization": "Bearer " + cfg.token}
    assert client.get("/api/ai/status").status_code == 401
    assert client.get("/api/capabilities", headers=auth).json()["model_configured"] is False
    path.write_text("later-private-provider-value")
    path.chmod(0o600)
    assert client.get("/api/ai/status", headers=auth).json()["configured"] is True
    response = client.get("/api/capabilities", headers=auth)
    assert (
        response.json()["model_configured"] is True and response.json()["vulnerability_ai"] is True
    )
    assert "later-private-provider-value" not in response.text


def test_environment_key_reference_may_be_unprovisioned_but_incomplete_metadata_is_rejected(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("OPSARK_AI_KEY", raising=False)
    monkeypatch.setenv("OPSARK_AI_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("OPSARK_AI_MODEL", "configured-model")
    monkeypatch.setenv("OPSARK_AI_KEY_FILE", str(tmp_path / "future-key"))
    cfg = load_settings()
    assert cfg.ai_key is None and not provider.provider_status(cfg)["configured"]
    monkeypatch.setenv("OPSARK_AI_KEY", "second-secret-source")
    with pytest.raises(ValueError):
        load_settings()
