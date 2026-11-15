"""Independent timing, state-drift and pause identity recovery regressions."""

import copy
from datetime import timedelta

import pytest
from fastapi import HTTPException
from test_automatic_monitor import HOST, ROOT_POLICY
from test_automatic_service import env as env
from test_patch_agent import NOW
from test_patch_agent import remote as remote
from test_recovery_api import approve
from test_recovery_api import preview as controller_preview
from test_recovery_api import recovery as recovery
from test_root_recovery import commit, preview, write_job
from test_root_recovery import recovery_env as recovery_env

from opsark.automation_store import AutomationStore
from opsark.control_modes import ControlPolicy
from opsark.recovery_api import RecoveryPrepareRequest, RecoverySubmitRequest


def root_refusal(env, plan):
    try:
        return commit(env, plan)
    except env.core.Rejected:
        return {"status": "rejected"}


def test_root_cannot_publish_verified_completion_after_preview_expiry(recovery_env, monkeypatch):
    e = recovery_env
    plan = preview(e)
    clock = [NOW + timedelta(minutes=5, microseconds=-1)]
    monkeypatch.setattr(e.core, "now", lambda: clock[0])

    def cross_boundary(*_args):
        clock[0] = NOW + timedelta(minutes=5, milliseconds=1)
        return True

    monkeypatch.setattr(e.core, "fresh_ssh_connection", cross_boundary)
    result = root_refusal(e, plan)
    assert result["status"] != "verified", result.get("completed_at")


def test_root_cannot_ignore_package_state_drift_during_final_reconciliation(
    recovery_env, monkeypatch
):
    e = recovery_env
    plan = preview(e)

    def assessment_then_drift(**_kw):
        e.inventory["apt_state_digest"] = "9" * 64
        e.inventory["packages"][0]["installed_version"] = "8.5.0-2ubuntu10.9"
        return copy.deepcopy(e.assessment)

    monkeypatch.setattr(e.core, "scan_packages", assessment_then_drift)
    assert root_refusal(e, plan)["status"] != "verified"


def test_controller_cannot_accept_a_receipt_completed_after_original_expiry(recovery):
    state = recovery
    plan = controller_preview(state)

    def cross_boundary(value):
        state.env.clock += timedelta(minutes=5, seconds=1)
        value["completed_at"] = state.env.clock.isoformat()

    state.receipt_hook = cross_boundary
    result = approve(state, plan)
    assert result["status"] != "verified"
    assert state.env.auto.latch(state.env.job["host_id"])


def test_exact_receipt_cannot_cover_later_verified_revision_with_new_unsafe_history(recovery_env):
    e = recovery_env
    old = write_job(
        e,
        history=[
            {"status": "unknown", "at": NOW.isoformat()},
            {"status": "verified", "at": NOW.isoformat()},
        ],
    )
    assert e.agent.automatic_policy.safety_state()["paused"] is True
    receipt = commit(e, preview(e))
    assert receipt["status"] == "verified"
    assert e.agent.automatic_policy.safety_state()["paused"] is False
    updated = write_job(
        e,
        revision=9,
        history=old["history"]
        + [
            {"status": "unknown", "at": (NOW + timedelta(seconds=1)).isoformat()},
            {"status": "verified", "at": (NOW + timedelta(seconds=2)).isoformat()},
        ],
    )
    state = e.agent.automatic_policy.safety_state()
    assert state["paused"] and state["job_id"] == updated["job_id"]
    assert (updated["job_id"], updated["revision"], e.core.digest(updated)) not in (
        e.recovery.resolved_bindings()
    )


def test_old_resolved_root_snapshot_cannot_replace_a_new_active_pause(recovery):
    state, env = recovery, recovery.env
    env.root_safety = {
        "schema_version": 1,
        "paused": True,
        "reason": "automatic_job_unknown",
        "job_id": env.job["job_id"],
        "updated_at": env.clock.isoformat(),
    }
    env.service.refresh_automatic_status(HOST)
    stale = copy.deepcopy(env.auto.remote_state(HOST)["remote"])
    assert approve(state, controller_preview(state))["status"] == "verified"
    assert env.auto.latch(HOST) is None
    env.root_safety.update(
        paused=True,
        reason="automatic_job_unknown",
        job_id="4" * 32,
        updated_at=(env.clock + timedelta(seconds=1)).isoformat(),
    )
    env.service.refresh_automatic_status(HOST)
    current = env.auto.latch(HOST)
    assert current and current["job_id"] == "4" * 32
    env.auto.record_remote_safety(
        HOST,
        env.service._automatic_scope(env.service.targets[HOST]),
        ROOT_POLICY,
        {
            "schema_version": 1,
            "host_id": HOST,
            "policy_digest": ROOT_POLICY,
            "status": "automatic_status",
            **stale,
        },
        now=env.clock,
    )
    assert env.auto.latch(HOST) == current


@pytest.mark.parametrize("change", [{"enabled": False}, {"allowed_actions": (), "automatic": None}])
def test_recovery_respects_a_fresh_disabled_or_actionless_deployment_policy(recovery, change):
    state, current = recovery, recovery.env
    policy = ControlPolicy.model_validate(current.service.automation.policy.model_dump() | change)
    renewed = AutomationStore(
        current.service.automation.path,
        policy,
        driver_scope=current.service.automation.driver_scope,
    )
    current.service.automation = renewed
    current.automation = renewed
    mode = current.service.sync_mode()
    assert mode["mode"] == "manual" and mode["mode_sync_complete"]
    revision = mode["revision"]
    state.plan_hook = lambda value: value.update(mode_revision=revision)
    try:
        plan = state.service.prepare(
            RecoveryPrepareRequest(
                host_id=HOST,
                job_id=current.job["job_id"],
                expected_mode_revision=revision,
            )
        )
    except HTTPException as error:
        assert error.status_code == 403
        assert current.auto.latch(HOST)
        return
    result = state.service.submit(
        RecoverySubmitRequest(
            host_id=HOST,
            recovery_id=plan["recovery_id"],
            expected_recovery_digest=plan["recovery_digest"],
            expected_mode_revision=revision,
            confirm_recover=True,
        )
    )
    assert result["status"] != "verified"
    assert current.auto.latch(HOST)
