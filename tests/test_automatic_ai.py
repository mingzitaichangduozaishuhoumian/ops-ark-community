"""Real durable model budgets and analysis records gate native candidates; no network."""

import copy
from dataclasses import replace
from datetime import timedelta

import pytest
from test_automatic_monitor import HOST, ROOT_POLICY, scope_for_automatic
from test_vulnerability_ai_service import env as env

from opsark.automatic_ai import AutomaticAIGate
from opsark.automatic_store import AutomaticStore, candidate_identity
from opsark.automation_store import AutomationStore, ModeChange
from opsark.control_modes import ControlPolicy
from opsark.patch_api import targets_scope
from opsark.vulnerability_ai_store import VulnerabilityAIStore


@pytest.fixture
def gated(env, tmp_path):
    e = env
    binding = e.service.preview(HOST)["provider_binding"]
    e.policy = ControlPolicy.model_validate(
        {
            "enabled": True,
            "host_ids": [HOST],
            "allowed_actions": ["os_security_upgrade"],
            "allowed_packages": ["libbrotli1"],
            "allow_service_restart": True,
            "automatic": {
                "enabled": True,
                "grant_id": "f" * 32,
                "issued_at": (e.now - timedelta(minutes=1)).isoformat(),
                "expires_at": (e.now + timedelta(hours=1)).isoformat(),
                "host_ids": [HOST],
                "allowed_packages": ["libbrotli1"],
                "allowed_advisories": ["USN-8956-1"],
                "target_policy_digests": {HOST: ROOT_POLICY},
                "maintenance_windows": [
                    {"weekdays": list(range(7)), "start_minute": 0, "end_minute": 1440}
                ],
                "allowed_risk_levels": ["medium"],
                "allow_service_restart": True,
            },
            "automatic_ai": {
                "enabled": True,
                "provider_fingerprint": binding,
                "max_analyses_per_day": 1,
                "max_total_analyses": 1,
            },
        }
    )
    e.modes = AutomationStore(
        tmp_path / "ai-mode.sqlite3", e.policy, driver_scope=targets_scope(e.native.targets)
    )
    e.native.automation = e.modes
    e.native.change_mode(ModeChange(mode="automatic", expected_revision=0))
    e.auto = AutomaticStore(tmp_path / "ai-automatic.sqlite3")
    e.native.automatic_store = e.auto
    e.gate = AutomaticAIGate(e.service, e.auto, now=lambda: e.now)
    e.scan = e.patches.latest_scan(HOST)
    grant = e.policy.automatic
    e.candidate = e.auto.claim_candidate(
        host_id=HOST,
        scope_hash=scope_for_automatic(e.native.targets[HOST]),
        finding_id=e.scan["findings"][0]["finding_id"],
        package="libbrotli1",
        current_version="1.1.0-2build2",
        candidate_version="1.1.0-2ubuntu0.1",
        grant_id=grant.grant_id,
        grant_digest=grant.grant_digest,
        scan_id=e.scan["scan_id"],
        owner="c" * 32,
        now=e.now,
    )
    return e


def require(e, gate=None):
    return (gate or e.gate).require_proposal(e.candidate, e.scan, e.policy, e.modes.status())


def test_one_real_analysis_record_and_budget_survive_reopen_and_never_prepare_or_submit(gated):
    e = gated
    proof = require(e)
    assert proof is not None
    assert set(proof) == {
        "request_key",
        "analysis_id",
        "input_digest",
        "analysis_digest",
        "proposal_id",
        "candidate_id",
        "provider_fingerprint",
    }
    assert e.model_calls == 1
    original = e.auto.get_ai_request(proof["request_key"], now=e.now)
    assert original["status"] == "completed"
    assert original["scope_hash"] == e.candidate["scope_hash"]
    bound = e.auto.bind_ai_result(e.candidate["id"], e.candidate["owner"], proof, now=e.now)
    assert bound is not None and bound["ai_proof"] == proof
    assert original["result_ref"] == {k: v for k, v in proof.items() if k != "request_key"}
    e.service.store = VulnerabilityAIStore(e.audit.path)
    reopened = AutomaticStore(e.auto.path)
    new_gate = AutomaticAIGate(e.service, reopened, now=lambda: e.now)
    assert require(e, new_gate) == proof
    assert e.model_calls == 1
    assert reopened.ai_quotas(HOST, e.policy.automatic.grant_id, now=e.now) == {
        "daily_used": 1,
        "total_used": 1,
    }
    assert all(c["op"] == "set_mode" for c in e.root_calls)
    assert e.gate.validate_proof(e.candidate, e.scan, e.policy, e.modes.status(), proof)


@pytest.mark.parametrize("state", ["failed", "unknown", "refused", "disabled"])
def test_noncompletion_consumes_one_intent_and_never_falls_back_or_retries(gated, state):
    e = gated
    analyze = e.service.focus_analyzer

    def fail(*args, **kwargs):
        result = analyze(*args, **kwargs)
        result.update(status=state, proposals=[])
        return result

    e.service.focus_analyzer = fail
    assert require(e) is None
    assert require(e) is None
    assert e.model_calls == 1
    assert len(e.auto.ai_requests()) == 1
    request = e.auto.ai_requests()[0]
    assert request["status"] == ("failed" if state == "disabled" else state)
    assert e.auto.ai_quotas(HOST, e.policy.automatic.grant_id, now=e.now)["total_used"] == 1
    assert not any(c["op"] in {"prepare", "submit"} for c in e.root_calls)


def test_empty_selection_is_persistent_no_proposal_not_native_fallback(gated):
    e = gated
    analyze = e.service.focus_analyzer

    def none(*args, **kwargs):
        result = analyze(*args, **kwargs)
        result["proposals"] = []
        return result

    e.service.focus_analyzer = none
    assert require(e) is None and require(e) is None
    assert e.model_calls == 1
    assert any(a["kind"] == "no_proposal" for a in e.auto.ai_alerts())


def test_transport_exception_keeps_fixed_id_and_never_exposes_provider_error(gated):
    e = gated
    calls = []

    def lost(body):
        calls.append(body.analysis_id)
        raise RuntimeError("private-upstream-body-api-key-fixture")

    e.service.analyze = lost
    assert require(e) is None and require(e) is None
    assert len(calls) == 1
    assert e.auto.ai_requests()[0]["status"] == "unknown"
    assert "private-upstream-body-api-key-fixture" not in str(e.gate.status())


@pytest.mark.parametrize(
    "change", ["manual", "unsynced", "expiry", "provider", "disabled_ai", "stale_scan"]
)
def test_no_dispatch_without_current_mode_consent_provider_and_evidence(gated, change):
    e = gated
    if change == "manual":
        e.native.change_mode(
            ModeChange(mode="manual", expected_revision=e.modes.status()["revision"])
        )
    elif change == "unsynced":
        e.modes.mark_sync_pending(e.modes.status()["revision"])
    elif change == "expiry":
        e.now += timedelta(hours=2)
    elif change == "provider":
        e.service.settings = replace(e.settings, ai_model="other-model")
    elif change == "disabled_ai":
        data = e.policy.model_dump(mode="json")
        data["automatic_ai"]["enabled"] = False
        e.policy = ControlPolicy.model_validate(data)
        e.modes.policy = e.policy
    else:
        e.now += timedelta(seconds=901)
    assert require(e) is None
    assert e.model_calls == 0 and e.auto.ai_requests() == []


def test_new_scan_identity_does_not_create_new_billable_attempt(gated):
    e = gated
    proof = require(e)
    newer = copy.deepcopy(e.scan)
    newer["scan_id"] = "9" * 32
    e.patches.save_scan(HOST, newer)
    e.scan = newer
    assert require(e) is None
    assert e.model_calls == 1 and len(e.auto.ai_requests()) == 1
    assert not e.gate.validate_proof(e.candidate, e.scan, e.policy, e.modes.status(), proof)


def test_new_root_grant_cannot_reset_same_request_identity(gated):
    e = gated
    require(e)
    data = e.policy.model_dump(mode="json")
    data["automatic"]["grant_id"] = "8" * 32
    data["automatic"]["grant_digest"] = ""
    e.policy = ControlPolicy.model_validate(data)
    e.modes.policy = e.policy
    e.candidate.update(
        grant_id=e.policy.automatic.grant_id, grant_digest=e.policy.automatic.grant_digest
    )
    assert require(e) is None
    assert e.model_calls == 1 and len(e.auto.ai_requests()) == 1


def test_atomic_model_budget_rejects_another_candidate(gated):
    e = gated
    require(e)
    newer = copy.deepcopy(e.scan)
    newer["packages"][0]["candidate_version"] = "1.1.0-2ubuntu0.2"
    e.patches.save_scan(HOST, newer)
    e.scan = newer
    e.candidate["candidate_version"] = "1.1.0-2ubuntu0.2"
    e.candidate["id"] = candidate_identity(
        HOST,
        e.candidate["scope_hash"],
        e.candidate["finding_id"],
        e.candidate["current_version"],
        e.candidate["candidate_version"],
    )
    assert require(e) is None
    assert e.model_calls == 1 and len(e.auto.ai_requests()) == 1


@pytest.mark.parametrize("mutation", ["approved", "analysis", "provider", "sha", "extra_command"])
def test_submission_revalidates_saved_request_analysis_and_candidate_not_boolean_approval(
    gated, mutation
):
    e = gated
    proof = require(e)
    assert proof is not None
    if mutation == "approved":
        proof = {"approved": True}
    elif mutation == "analysis":
        proof["analysis_digest"] = "9" * 64
    elif mutation == "provider":
        e.service.settings = replace(e.settings, ai_model="provider-changed")
    elif mutation == "sha":
        newer = copy.deepcopy(e.scan)
        newer["packages"][0]["candidate_sha256"] = "9" * 64
        e.patches.save_scan(HOST, newer)
        e.scan = newer
    else:
        proof["commands"] = ["untrusted-operation"]
    assert not e.gate.validate_proof(e.candidate, e.scan, e.policy, e.modes.status(), proof)
    assert e.model_calls == 1


def test_submission_intent_phase_keeps_valid_proof_but_mode_change_during_call_stops_work(gated):
    e = gated
    proof = require(e)
    e.candidate["state"] = "submission_intent"
    assert e.gate.validate_proof(e.candidate, e.scan, e.policy, e.modes.status(), proof)
    e.native.change_mode(ModeChange(mode="manual", expected_revision=e.modes.status()["revision"]))
    assert not e.gate.validate_proof(e.candidate, e.scan, e.policy, e.modes.status(), proof)


def test_mode_revocation_while_model_runs_preserves_cost_but_cannot_plan(gated):
    e = gated
    e.analyze_hook = lambda: e.native.change_mode(
        ModeChange(mode="manual", expected_revision=e.modes.status()["revision"])
    )
    assert require(e) is None
    assert e.model_calls == 1 and e.auto.ai_requests()[0]["status"] == "stale"


def test_status_exposes_persistent_acknowledgeable_alerts_without_request_owner(gated):
    e = gated
    require(e)
    status = e.gate.status()
    assert status["enabled"] and status["policy"] == e.policy.automatic_ai.model_dump(mode="json")
    assert status["requests"] and all("owner" not in r for r in status["requests"])
    assert {a["kind"] for a in status["alerts"]} == {"analysis_started", "analysis_completed"}
    e.auto.ack_ai_alert(status["alerts"][0]["id"], now=e.now)
    assert any(a["acknowledged"] is True for a in e.gate.status()["alerts"])


def test_expired_dispatch_intent_after_restart_is_only_queried_never_replayed(gated):
    e = gated
    calls = []

    def interrupted(body):
        calls.append(body.analysis_id)
        e.now += timedelta(seconds=121)
        raise RuntimeError("unknown remote result")

    e.service.analyze = interrupted
    assert require(e) is None
    restarted = AutomaticAIGate(e.service, AutomaticStore(e.auto.path), now=lambda: e.now)
    assert require(e, restarted) is None
    assert len(calls) == 1 and e.auto.ai_requests()[0]["status"] == "unknown"


def test_concurrent_gate_observes_reserved_intent_and_cannot_create_another_request(gated):
    e = gated
    other = AutomaticAIGate(e.service, AutomaticStore(e.auto.path), now=lambda: e.now)
    e.analyze_hook = lambda: require(e, other)
    assert require(e) is not None
    assert e.model_calls == 1 and len(e.auto.ai_requests()) == 1


def test_cached_admission_still_requires_a_durable_alert_before_native_work(gated, monkeypatch):
    e = gated
    proof = require(e)
    assert proof is not None

    def unavailable(*args, **kwargs):
        raise OSError("private storage failure")

    monkeypatch.setattr(e.auto, "emit_ai_alert", unavailable)
    assert require(e) is None
    assert e.model_calls == 1
