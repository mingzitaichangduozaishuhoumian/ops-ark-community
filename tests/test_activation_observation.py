"""Activation observations have independent identities and cannot masquerade as verified jobs."""

from dataclasses import replace

import pytest
from test_vulnerability_monitor import setup

from opsark.patch_api import PatchService

HOST = "test-host"
ACTIVATION = "a" * 32
JOB = "b" * 32


def enqueue(env):
    return env.monitor.request_activation_rescan(
        HOST,
        ACTIVATION,
        JOB,
        expected_scope=PatchService._automatic_scope(env.service.targets[HOST]),
    )


def test_activation_rescan_is_durable_and_separate_from_patch_job(tmp_path):
    env = setup(tmp_path)
    first = enqueue(env)
    assert first["event_kind"] == "service_activation"
    assert first["activation_id"] == first["event_key"] == ACTIVATION
    assert first["original_job_id"] == JOB and first["job_id"] is None
    assert enqueue(env) == first
    env.monitor.poll_once()
    final = env.store.get_rescan(first["rescan_request_id"])
    assert final["status"] == "complete" and final["result_observation_id"]
    assert enqueue(env) == final and len(env.calls) == 1


def test_event_kind_collision_never_reuses_a_different_real_event(tmp_path):
    env = setup(tmp_path)
    enqueue(env)
    with pytest.raises(ValueError):
        env.store.request_rescan(HOST, env.monitor.scopes[HOST], ACTIVATION)
    with pytest.raises(ValueError):
        env.store.request_activation_rescan(HOST, env.monitor.scopes[HOST], ACTIVATION, "c" * 32)


def test_activation_cannot_take_the_identity_of_an_existing_patch_job(tmp_path):
    env = setup(tmp_path)
    env.store.request_rescan(HOST, env.monitor.scopes[HOST], ACTIVATION)
    with pytest.raises(ValueError):
        enqueue(env)


def test_original_activation_scope_cannot_follow_a_replaced_host(tmp_path):
    env = setup(tmp_path)
    expected = PatchService._automatic_scope(env.service.targets[HOST])
    changed = replace(env.service.targets[HOST], policy_digest="e" * 64)
    env.service.targets[HOST] = changed
    assert (
        env.monitor.request_activation_rescan(HOST, ACTIVATION, JOB, expected_scope=expected)
        is None
    )
