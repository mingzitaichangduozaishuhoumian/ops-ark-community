"""Native automatic entry points cannot bypass durable AI admission; no transports."""

import copy
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from test_automatic_monitor import HOST, finding
from test_automatic_service import env as env
from test_automatic_service import ops, prepare, reserved, submit

from opsark.automatic_monitor import AutomaticMonitor, scope_for_automatic
from opsark.automatic_store import digest
from opsark.automation_store import ModeChange
from opsark.config import Settings
from opsark.control_modes import ControlPolicy
from opsark.vulnerability_monitor import VulnerabilityMonitor
from opsark.vulnerability_store import VulnerabilityStore


def enable(e):
    data = e.automation.policy.model_dump(mode="json")
    data["automatic_ai"] = {
        "enabled": True,
        "provider_fingerprint": "c" * 64,
        "max_analyses_per_day": 1,
        "max_total_analyses": 1,
    }
    e.automation.policy = ControlPolicy.model_validate(data)
    scan = e.patches.latest_scan(HOST)
    scan["packages"][0]["candidate_sha256"] = "4" * 64
    e.patches.save_scan(HOST, scan)


def claim(e):
    grant = e.automation.policy.automatic
    return e.auto.claim_candidate(
        host_id=HOST,
        scope_hash=scope_for_automatic(e.service.targets[HOST]),
        finding_id=finding()["finding_id"],
        package="libbrotli1",
        current_version="1.1.0-2build2",
        candidate_version="1.1.0-2ubuntu0.1",
        grant_id=grant.grant_id,
        grant_digest=grant.grant_digest,
        scan_id=e.patches.latest_scan(HOST)["scan_id"],
        owner="5" * 32,
        now=e.clock,
    )


def model_reference(e, candidate):
    key = digest({"synthetic_ai_admission": candidate["id"]})
    request = e.auto.begin_ai_request(
        key,
        HOST,
        candidate["scope_hash"],
        candidate["id"],
        candidate["grant_id"],
        "c" * 64,
        "7" * 32,
        "8" * 64,
        "9" * 32,
        daily_limit=1,
        total_limit=1,
        now=e.clock,
    )
    reference = {
        "analysis_id": request["analysis_id"],
        "input_digest": request["input_digest"],
        "analysis_digest": "a" * 64,
        "proposal_id": "b" * 32,
        "candidate_id": "candidate-1",
        "provider_fingerprint": "c" * 64,
    }
    e.auto.finish_ai_request(
        key,
        "9" * 32,
        status="completed",
        result_ref=reference,
        detail="Synthetic validated admission; no external model.",
        now=e.clock,
    )
    return {"request_key": key, **reference}


class Gate:
    """Controlled validator: the real Store must still carry the exact bound reference."""

    def __init__(self, e, *, selected=True):
        self.e, self.selected = e, selected
        self.valid = True
        self.checks = 0

    def require_proposal(self, candidate, scan, policy, mode):
        return model_reference(self.e, candidate) if self.selected else None

    def validate_proof(self, candidate, scan, policy, mode, proof):
        self.checks += 1
        if not self.valid or not isinstance(proof, dict):
            return False
        current = self.e.auto.get(candidate["id"])
        request = self.e.auto.get_ai_request(proof["request_key"], now=self.e.clock)
        return (
            current.get("ai_proof") == proof
            and request["status"] == "completed"
            and request["result_ref"] == {k: v for k, v in proof.items() if k != "request_key"}
        )

    @staticmethod
    def status():
        return {"enabled": True, "requests": [], "alerts": [], "policy": {}}


def admitted(e):
    value = claim(e)
    proof = model_reference(e, value)
    assert e.auto.bind_ai_result(value["id"], value["owner"], proof, now=e.clock) is not None
    return value


@pytest.mark.parametrize("missing", ["gate", "candidate", "proof", "invalidated_proof"])
def test_native_prepare_fails_closed_before_rpc_without_durable_admission(env, missing):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = None if missing == "gate" else gate
    if missing in {"gate", "invalidated_proof"}:
        admitted(e)
    elif missing == "proof":
        claim(e)
    if missing == "invalidated_proof":
        gate.valid = False
    with pytest.raises(HTTPException) as caught:
        prepare(e)
    assert caught.value.status_code in {409, 503}
    assert ops(e, "prepare") == ops(e, "submit") == []


def test_preexisting_durable_install_intent_cannot_bypass_new_ai_requirement(env):
    e = env
    intent = reserved(e)
    enable(e)
    e.service.automatic_ai_gate = Gate(e)
    with pytest.raises(HTTPException) as caught:
        submit(e, intent)
    assert caught.value.status_code == 409
    assert ops(e, "submit") == []
    assert e.auto.get(intent["id"])["state"] == "submission_intent"


def test_native_plan_with_another_valid_sha_is_rejected_even_with_persisted_ai_proof(env):
    e = env
    enable(e)
    e.service.automatic_ai_gate = Gate(e)
    admitted(e)

    def wrong_sha(value):
        value["package_changes"][0]["sha256"] = "0" * 64
        return value

    e.prepare_hook = wrong_sha
    with pytest.raises(HTTPException) as caught:
        prepare(e)
    assert caught.value.status_code == 409
    assert len(ops(e, "prepare")) == 1 and ops(e, "submit") == []
    assert e.patches.get_plan(HOST, "1" * 32) is None


def test_ai_revocation_after_planning_stops_submit_despite_a_reserved_job_identity(env):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = gate
    candidate = admitted(e)
    plan = prepare(e)
    grant = e.automation.policy.automatic
    intent = e.auto.reserve_submission(
        candidate["id"],
        plan,
        e.automation.status()["revision"],
        daily_limit=grant.max_jobs_per_day,
        total_limit=grant.max_total_jobs,
        now=e.clock,
    )
    gate.valid = False
    with pytest.raises(HTTPException):
        submit(e, intent)
    assert ops(e, "submit") == []


@pytest.mark.parametrize("with_gate", [False, True])
def test_monitor_cannot_fall_back_to_native_planning_when_ai_is_missing_or_has_no_selection(
    env, with_gate
):
    e = env
    enable(e)
    gate = Gate(e, selected=False) if with_gate else None
    e.service.automatic_ai_gate = gate
    monitor = AutomaticMonitor(e.service, e.auto, now=lambda: e.clock, ai_gate=gate)
    monitor.poll_once()
    assert ops(e, "prepare") == ops(e, "submit") == []
    assert e.auto.list_attempts()[0]["state"] == "deferred"
    assert any(a["kind"] == "blocked" for a in e.auto.ai_alerts())


def test_monitor_persists_ai_binding_before_native_flow_and_reconciles_terminal_result(env):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = gate
    monitor = AutomaticMonitor(e.service, e.auto, now=lambda: e.clock, ai_gate=gate)
    rescans = set()
    monitor.vulnerability_monitor = SimpleNamespace(
        request_rescan=lambda host, job, *, expected_scope: rescans.add((host, job, expected_scope))
    )
    monitor.poll_once()
    assert len(ops(e, "prepare")) == len(ops(e, "submit")) == 1
    candidate = e.auto.list_attempts()[0]
    assert candidate["ai_proof"] and candidate["state"] == "tracking"
    assert gate.checks >= 3
    assert len(e.auto.ai_requests()) == 1
    e.job.update(status="verified", revision=2)
    e.service.job_status(HOST, candidate["job_id"])
    e.service.change_mode(
        ModeChange(mode="manual", expected_revision=e.automation.status()["revision"])
    )
    monitor.poll_once()
    monitor.poll_once()
    assert rescans == {(HOST, candidate["job_id"], candidate["scope_hash"])}
    assert len([a for a in e.auto.ai_alerts() if a["kind"] == "repair_verified"]) == 1
    assert len(ops(e, "submit")) == 1


def test_monitor_stop_before_execution_does_not_consume_or_dispatch_ai_budget(env):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = gate
    monitor = AutomaticMonitor(e.service, e.auto, now=lambda: e.clock, ai_gate=gate)
    monitor.owner = "5" * 32
    candidate = claim(e)
    policy, mode = e.automation.policy, e.automation.status()
    state = monitor._gate(HOST, policy, mode, e.clock)
    monitor.stop_event.set()
    monitor._execute(candidate, e.patches.latest_scan(HOST), policy, mode, state)
    assert e.auto.ai_requests() == []
    assert ops(e, "prepare") == ops(e, "submit") == []


@pytest.mark.parametrize("change", ["address", "policy", "removed"])
def test_old_verified_ai_job_keeps_alert_without_rescanning_reused_host_identity(env, change):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = gate
    monitor = AutomaticMonitor(e.service, e.auto, now=lambda: e.clock, ai_gate=gate)
    monitor.poll_once()
    candidate = e.auto.list_attempts()[0]
    e.job.update(status="verified", revision=2)
    e.service.job_status(HOST, candidate["job_id"])
    old_target = e.service.targets[HOST]
    if change == "policy":
        e.service.targets[HOST] = replace(old_target, policy_digest="e" * 64)
    elif change == "address":
        e.service.targets[HOST] = replace(
            old_target,
            host=replace(
                old_target.host,
                public=old_target.host.public.model_copy(update={"address": "192.0.2.20"}),
            ),
        )
    watch = VulnerabilityMonitor(
        Settings(
            data_dir=e.auto.path.parent,
            token="x" * 40,
            vulnerability_scan_enabled=True,
            vulnerability_scan_host_ids=(HOST,),
        ),
        e.service,
        VulnerabilityStore(e.auto.path.parent / "watch.db"),
        now=lambda: e.clock,
    )
    if change == "removed":
        del e.service.targets[HOST]
    monitor.vulnerability_monitor = watch
    for _ in range(2):
        monitor._ai_outcomes()
    assert len([a for a in e.auto.ai_alerts() if a["kind"] == "repair_verified"]) == 1
    assert not watch.store.rescans_due(HOST, watch.scopes[HOST], now=e.clock)
    assert len(ops(e, "submit")) == 1


@pytest.mark.parametrize("change", ["mode", "window", "proof"])
def test_native_prepare_rechecks_authority_after_slow_root_planning(env, change):
    e = env
    enable(e)
    gate = Gate(e)
    e.service.automatic_ai_gate = gate
    admitted(e)

    def changed(value):
        if change == "mode":
            e.service.change_mode(
                ModeChange(mode="manual", expected_revision=e.automation.status()["revision"])
            )
        elif change == "window":
            e.clock += timedelta(hours=2)
        else:
            gate.valid = False
        return copy.deepcopy(value)

    e.prepare_hook = changed
    with pytest.raises(HTTPException):
        prepare(e)
    assert len(ops(e, "prepare")) == 1 and ops(e, "submit") == []
