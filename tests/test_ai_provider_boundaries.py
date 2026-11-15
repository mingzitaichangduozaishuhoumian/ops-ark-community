"""Independent public-readiness and legacy compatibility configuration checks."""

import json
from dataclasses import replace

import pytest
from test_ai_provider import settings
from test_security_ai import alert, output

from opsark import security_ai
from opsark.ai_provider import provider_status


@pytest.mark.parametrize("identifier", [" \n ", "model\x00suffix", "model\rsuffix"])
def test_nonprintable_or_empty_model_is_not_publicly_ready(tmp_path, identifier):
    public = provider_status(replace(settings(tmp_path), ai_model=identifier))
    assert public["configured"] is False
    assert public["model_name"] is None


def test_legacy_security_advice_never_returns_naked_known_provider_credential(
    tmp_path, monkeypatch
):
    configured = settings(tmp_path)

    def response(*_args, **_kwargs):
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(output(summary=configured.ai_key)),
                    },
                }
            ]
        }

    monkeypatch.setattr(security_ai, "request_document", response)
    result = security_ai.analyze_alert(alert(), configured)
    assert configured.ai_key not in json.dumps(result)
