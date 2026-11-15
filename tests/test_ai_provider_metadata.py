"""Response diagnostics must not turn untrusted envelope fields into secret output."""

import json

import pytest
from test_ai_provider import settings

from opsark.ai_provider import response_metadata


def envelope(model="returned-model", finish_reason="stop"):
    return {
        "model": model,
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {
                    "content": "中文 JSON",
                    "reasoning_content": "private-fixture-reasoning",
                },
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
    }


@pytest.mark.parametrize("secret_field", ["ai_key", "token"])
@pytest.mark.parametrize("template", ["{}", "prefix-{}", "{}-suffix", "prefix-{}-suffix"])
def test_returned_model_never_exposes_known_secret_substrings(tmp_path, secret_field, template):
    configured = settings(tmp_path)
    secret = getattr(configured, secret_field)
    result = response_metadata(envelope(model=template.format(secret)), configured)
    assert result["returned_model"] is None
    assert secret not in json.dumps(result)
    assert result["finish_reason"] == "stop"
    assert result["usage"]["total_tokens"] == 300


@pytest.mark.parametrize("character", ["\x00", "\t", "\n", "\r", "\x1f", "\x7f"])
def test_returned_model_omits_control_characters(tmp_path, character):
    result = response_metadata(envelope(model=f"model{character}suffix"), settings(tmp_path))
    assert result["returned_model"] is None
    assert result["finish_reason"] == "stop"


@pytest.mark.parametrize("reason", [[], {}, ["length"], {"value": "stop"}, None, 1, True, "new"])
def test_malformed_finish_reason_preserves_safe_diagnostics(tmp_path, reason):
    result = response_metadata(envelope(finish_reason=reason), settings(tmp_path))
    assert result["finish_reason"] == "unknown"
    assert result["returned_model"] == "returned-model"
    assert result["content_bytes"] == len("中文 JSON".encode())
    assert result["usage"]["total_tokens"] == 300
    assert "private-fixture-reasoning" not in json.dumps(result)


@pytest.mark.parametrize(
    "reason", ["stop", "length", "content_filter", "tool_calls", "function_call"]
)
def test_supported_finish_reasons_remain_available_for_analysis(tmp_path, reason):
    result = response_metadata(envelope(finish_reason=reason), settings(tmp_path))
    assert result["finish_reason"] == reason
    assert result["returned_model"] == "returned-model"
    assert result["reasoning_output_present"] is True
