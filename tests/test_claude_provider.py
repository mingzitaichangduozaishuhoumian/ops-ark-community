"""Native Claude uses the same egress and one-attempt transport boundaries."""

import hashlib
import json
import sys
from dataclasses import replace

import httpx
import pytest
from test_ai_provider import body, wire
from test_ai_provider import settings as openai_settings
from test_vulnerability_ai import output
from test_vulnerability_ai_service import HOST
from test_vulnerability_ai_service import env as native_service_fixture
from test_vulnerability_ai_service import request as analysis_request

from opsark import ai_provider as provider
from opsark import vulnerability_ai
from opsark.ai_egress import AIEgressBlocked
from opsark.config import ANTHROPIC_BASE_URL, load_settings
from opsark.vulnerability_evidence import verify_source

service_env = native_service_fixture


def settings(tmp_path):
    return replace(
        openai_settings(tmp_path),
        ai_provider="anthropic",
        ai_base_url=ANTHROPIC_BASE_URL,
        ai_model="claude-fixture",
        ai_response_format="json_prompt",
    )


def reply(**fields):
    return {
        "id": "private-provider-request-id",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": json.dumps(output()), "citations": None}],
        "model": "claude-fixture",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": 40, "private": "upstream metadata"},
        **fields,
    }


def test_native_analysis_sends_the_approved_summary_and_archives_its_binding(
    tmp_path, monkeypatch, service_env
):
    config = settings(tmp_path)
    service = service_env.service
    service.settings = config
    service.analyzer = vulnerability_ai.analyze
    monkeypatch.setitem(sys.modules, "opsark.ai_provider", provider)
    calls = []

    def send(request):
        calls.append(request)
        assert request.method == "POST" and str(request.url) == ANTHROPIC_BASE_URL + "/messages"
        assert request.headers["x-api-key"] == config.ai_key
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert "authorization" not in request.headers
        assert config.token not in str(request.headers)
        sent = json.loads(request.content)
        assert set(sent) == {"model", "max_tokens", "system", "messages"}
        assert sent["model"] == config.ai_model and sent["max_tokens"] == 2048
        assert len(sent["messages"]) == 1 and sent["messages"][0]["role"] == "user"
        summary = json.loads(sent["messages"][0]["content"])
        vulnerability_ai.validate_egress(summary)
        assert summary == service.preview(HOST)["model_input"]
        assert sent["system"] == vulnerability_ai.egress_system(summary)
        for local_value in (config.ai_key, config.token, "libbrotli1", "1.1.0-2build2"):
            assert local_value.encode() not in request.content
        return httpx.Response(200, json=reply())

    wire(monkeypatch, send)
    preview = service.preview(HOST)
    assert preview["provider_kind"] == "anthropic"
    record = service.analyze(analysis_request(service_env))
    assert record["status"] == "completed" and len(calls) == 1
    result = record["result"]
    assert result["provider_response"]["usage"] == {
        "prompt_tokens": 100,
        "completion_tokens": 40,
        "total_tokens": 140,
    }
    assert record["proposals"][0]["candidate_id"] == "candidate-1"
    source = service.store.get_source(HOST, record["analysis_id"])["source"]
    assert source["provider"]["provider_kind"] == "anthropic"
    assert source["provider"] == provider.provider_binding_fields(config)
    assert verify_source(source)["valid"] is True
    without_native_marker = {**source, "provider": dict(source["provider"])}
    without_native_marker["provider"].pop("provider_kind")
    assert verify_source(without_native_marker)["valid"] is False
    serialized = json.dumps(record)
    for absent in (config.ai_key, config.token, "private-provider-request-id", "upstream metadata"):
        assert absent not in serialized


@pytest.mark.parametrize(
    "changes",
    [
        {"ai_base_url": "https://api.anthropic.com.evil.invalid/v1"},
        {"ai_base_url": "https://api.anthropic.com:443/v1"},
        {"ai_base_url": "https://api.anthropic.com/v1/"},
        {"ai_base_url": "https://api.anthropic.com@evil.invalid/v1"},
        {"ai_base_url": "http://api.anthropic.com/v1"},
        {"ai_base_url": "http://127.0.0.1/v1"},
        {"ai_base_url": "https://api.anthropic.com/v1?option=1"},
        {"ai_response_format": "json_object"},
        {"ai_response_format": "json_schema"},
        {"ai_token_limit_parameter": "max_completion_tokens"},
        {"ai_thinking_mode": "enabled"},
        {"ai_thinking_mode": "disabled"},
        {"ai_provider": "claude"},
    ],
)
def test_incompatible_native_configuration_is_rejected(tmp_path, changes):
    with pytest.raises(ValueError):
        replace(settings(tmp_path), **changes)


def test_environment_explicitly_selects_native_interface(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OPSARK_TOKEN", "synthetic-console-token-for-env-config")
    monkeypatch.setenv("OPSARK_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("OPSARK_AI_BASE_URL", ANTHROPIC_BASE_URL)
    monkeypatch.setenv("OPSARK_AI_MODEL", "claude-fixture")
    monkeypatch.setenv("OPSARK_AI_KEY", "fixture-claude-key")
    monkeypatch.setenv("OPSARK_AI_TOKEN_LIMIT_PARAMETER", "max_tokens")
    monkeypatch.setenv("OPSARK_AI_THINKING_MODE", "provider_default")
    monkeypatch.delenv("OPSARK_AI_KEY_FILE", raising=False)
    monkeypatch.delenv("OPSARK_AI_RESPONSE_FORMAT", raising=False)
    with pytest.raises(ValueError):
        load_settings()
    monkeypatch.setenv("OPSARK_AI_RESPONSE_FORMAT", "json_prompt")
    assert load_settings().ai_provider == "anthropic"
    monkeypatch.delenv("OPSARK_AI_PROVIDER")
    assert load_settings().ai_provider == "openai"


def test_provider_binding_keeps_existing_openai_digest_and_distinguishes_native(tmp_path):
    native = settings(tmp_path)
    legacy = replace(native, ai_provider="openai")
    fields = provider.provider_binding_fields(legacy)
    assert set(fields) == {
        "base_url",
        "model",
        "response_format",
        "token_limit_parameter",
        "max_output_tokens",
        "thinking_mode",
    }
    old_digest = hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert provider.provider_fingerprint(legacy) == old_digest
    assert provider.provider_fingerprint(native) != old_digest
    assert provider.provider_status(native)["provider_kind"] == "anthropic"


@pytest.mark.parametrize("kind", ["secret", "unknown_field", "system_override", "console_as_key"])
def test_native_conversion_cannot_bypass_existing_egress(tmp_path, monkeypatch, kind):
    wire(monkeypatch, lambda _: pytest.fail("Rejected request contacted provider"))
    config = settings(tmp_path)
    request = body(config)
    if kind == "system_override":
        request["messages"][0]["content"] += " extra untrusted instruction"
    elif kind == "console_as_key":
        config = replace(config, ai_key=config.token)
    else:
        summary = json.loads(request["messages"][1]["content"])
        summary["extra"] = config.token if kind == "secret" else "unclassified marker"
        request["messages"][1]["content"] = json.dumps(summary)
    with pytest.raises(AIEgressBlocked) as caught:
        provider.request_document(request, config, route="vulnerability")
    assert config.token not in str(caught.value)


@pytest.mark.parametrize(
    "response",
    [
        reply(stop_reason="tool_use"),
        reply(stop_reason="pause_turn"),
        reply(stop_reason="stop_sequence"),
        reply(content=[{"type": "tool_use", "input": {"secret": "private provider text"}}]),
        reply(content=[{"type": "thinking", "thinking": "private provider text"}]),
        reply(
            content=[{"type": "text", "text": "{}", "citations": [{"text": "private citation"}]}]
        ),
        reply(role="user"),
        reply(type="error", error={"message": "private upstream error"}),
    ],
)
def test_native_nontext_or_nonfinal_responses_fail_closed(tmp_path, monkeypatch, response):
    wire(monkeypatch, lambda _: httpx.Response(200, json=response))
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderResponseInvalid) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert caught.value.code == "provider_object_invalid" and "private" not in str(caught.value)


@pytest.mark.parametrize(
    "response",
    [
        reply(stop_reason="refusal"),
        reply(stop_details={"type": "refusal", "explanation": "private upstream refusal"}),
    ],
)
def test_native_refusal_has_no_upstream_text(tmp_path, monkeypatch, response):
    wire(monkeypatch, lambda _: httpx.Response(200, json=response))
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderRefusal) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert "private" not in str(caught.value)


def test_native_truncation_drops_partial_text_and_bounds_billing(tmp_path, monkeypatch):
    response = reply(
        stop_reason="max_tokens",
        content=[{"type": "text", "text": "private unfinished text"}],
        usage={"input_tokens": 81, "output_tokens": 9_000_000, "private": "ignored"},
    )
    wire(monkeypatch, lambda _: httpx.Response(200, json=response))
    config = settings(tmp_path)
    document = provider.request_document(body(config), config, route="vulnerability")
    assert "private" not in json.dumps(document)
    assert provider.response_metadata(document, config)["finish_reason"] == "length"
    assert document["usage"] == {"prompt_tokens": 81}
    with pytest.raises(provider.ProviderError):
        provider.completion_text(document)


@pytest.mark.parametrize("status", [307, 401, 429, 529])
def test_native_http_error_is_single_attempt_and_never_forwards_key(tmp_path, monkeypatch, status):
    calls = []

    def send(request):
        calls.append(request)
        return httpx.Response(
            status,
            headers={"location": "https://third-party.invalid/messages"},
            json={"error": "private upstream error"},
        )

    wire(monkeypatch, send)
    config = settings(tmp_path)
    with pytest.raises(provider.ProviderRejected) as caught:
        provider.request_document(body(config), config, route="vulnerability")
    assert caught.value.status_code == status and len(calls) == 1
    assert "private" not in str(caught.value)
