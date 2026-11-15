"""Model-call consent is explicit and cannot manufacture Root authorization."""

import pytest
from pydantic import ValidationError
from test_automatic_policy import auto_policy, grant

from opsark.control_modes import AutomaticAIPolicy, ControlPolicy


def ai(**changes):
    return AutomaticAIPolicy.model_validate(
        {"enabled": True, "provider_fingerprint": "a" * 64} | changes
    )


def test_model_call_policy_defaults_do_not_enable_ai_or_execution():
    assert ControlPolicy().automatic_ai is None
    assert ControlPolicy().automatic is None
    value = AutomaticAIPolicy()
    assert value.enabled is False and value.provider_fingerprint is None
    assert value.max_analyses_per_day == value.max_total_analyses == 1
    assert auto_policy(automatic_ai=value).automatic_ai.enabled is False


def test_enabled_ai_requires_explicit_provider_and_independent_enabled_root_grant():
    with pytest.raises(ValidationError):
        AutomaticAIPolicy(enabled=True)
    with pytest.raises(ValidationError):
        ControlPolicy(enabled=True, automatic_ai=ai())
    with pytest.raises(ValidationError):
        auto_policy(grant(enabled=False), automatic_ai=ai())
    with pytest.raises(ValidationError):
        auto_policy(enabled=False, automatic_ai=ai())
    value = auto_policy(automatic_ai=ai())
    assert value.automatic == grant()
    assert value.automatic_ai.provider_fingerprint == "a" * 64
    assert value.host_ids == value.automatic.host_ids


@pytest.mark.parametrize("field", ["max_analyses_per_day", "max_total_analyses"])
@pytest.mark.parametrize("bad", [0, 6, -1, True, 1.0, "1", None])
def test_analysis_budgets_require_integers_in_the_bounded_range(field, bad):
    with pytest.raises(ValidationError):
        ai(**{field: bad})


@pytest.mark.parametrize("bad", ["", "A" * 64, "g" * 64, "a" * 63, b"a" * 64, True])
def test_provider_fingerprint_is_a_strict_digest(bad):
    with pytest.raises(ValidationError):
        ai(provider_fingerprint=bad)


def test_ai_policy_has_no_scope_override_and_roundtrips_without_creating_a_grant():
    with pytest.raises(ValidationError):
        ai(host_ids=["other-server"])
    value = auto_policy(automatic_ai=ai(max_analyses_per_day=5, max_total_analyses=5))
    assert ControlPolicy.model_validate_json(value.model_dump_json()) == value
    assert value.automatic.grant_digest == grant().grant_digest
    assert value.automatic_ai.max_total_analyses == 5
