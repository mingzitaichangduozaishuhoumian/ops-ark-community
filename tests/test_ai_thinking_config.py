"""Thinking behavior is an explicit deployment choice, with no inferred fallback."""

import pytest

from opsark import config
from opsark.config import Settings, load_settings


@pytest.fixture
def deployment_env(tmp_path, monkeypatch):
    environment = {
        "OPSARK_DATA_DIR": str(tmp_path),
        "OPSARK_TOKEN": "fixture-console-value-" * 3,
    }
    monkeypatch.setattr(config.os, "environ", environment)
    return environment


def test_thinking_defaults_to_provider_behavior(tmp_path, deployment_env):
    assert Settings(data_dir=tmp_path, token="fixture").ai_thinking_mode == "provider_default"
    assert load_settings().ai_thinking_mode == "provider_default"


@pytest.mark.parametrize("mode", ["provider_default", "enabled", "disabled"])
def test_explicit_thinking_modes_are_accepted(tmp_path, mode):
    assert (
        Settings(data_dir=tmp_path, token="fixture", ai_thinking_mode=mode).ai_thinking_mode == mode
    )


@pytest.mark.parametrize("mode", ["provider_default", "enabled", "disabled"])
def test_thinking_mode_loads_from_deployment_environment(deployment_env, mode):
    deployment_env["OPSARK_AI_THINKING_MODE"] = mode
    assert load_settings().ai_thinking_mode == mode


@pytest.mark.parametrize("mode", ["auto", "", True, 1, None, [], {}])
def test_invalid_or_non_string_thinking_modes_are_rejected(tmp_path, mode):
    with pytest.raises(ValueError, match="模型思考模式"):
        Settings(data_dir=tmp_path, token="fixture", ai_thinking_mode=mode)


@pytest.mark.parametrize("mode", ["auto", "", "Disabled", " disabled "])
def test_invalid_thinking_environment_does_not_silently_default(deployment_env, mode):
    deployment_env["OPSARK_AI_THINKING_MODE"] = mode
    with pytest.raises(ValueError, match="模型思考模式"):
        load_settings()
