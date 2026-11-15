"""Root automatic authorization against private fixture files; no APT or SSH."""

import copy
from contextlib import nullcontext
from datetime import timedelta, timezone
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, NOW, load_module, request
from test_patch_agent import remote as remote


@pytest.fixture
def root_auto(remote, monkeypatch):
    core = remote.core
    module = load_module("automatic_policy", "automatic_policy.py", monkeypatch)
    monkeypatch.setattr(remote.agent, "automatic_policy", module)
    scan = load_module("scan", "scan.py", monkeypatch)
    monkeypatch.setattr(core, "load_scan_module", lambda: scan)
    monkeypatch.setattr(core, "lock", lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(
        core, "read_command", lambda *_args, **_kwargs: pytest.fail("No command execution allowed")
    )
    grant = {
        "schema_version": 1,
        "enabled": True,
        "grant_id": "e" * 32,
        "issued_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(hours=23, minutes=59)).isoformat(),
        "allowed_packages": ["curl"],
        "allowed_advisories": ["USN-99999-1"],
        "maintenance_windows": [
            {"weekdays": list(range(7)), "start_minute": 0, "end_minute": 1440}
        ],
        "max_jobs_per_day": 1,
        "max_total_jobs": 1,
        "allowed_risk_levels": ["medium"],
        "allow_service_restart": True,
    }
    remote.policy.update(automatic=grant, asset_kind="controlled_lab")
    plan = {
        "plan_id": "f" * 32,
        "plan_digest": "0" * 64,
        "mode_revision": 0,
        "package_changes": [copy.deepcopy(remote.change)],
        "finding": {**remote.finding, "finding_evidence_complete": True},
        "risk_level": "medium",
        "requires_service_restart": True,
        "requires_reboot": False,
        "evidence_complete": True,
        "transaction_complete_verified": True,
        "restart_impact_verified": True,
        "automatic_grant_id": grant["grant_id"],
        "automatic_grant_digest": core.digest(grant),
    }
    return SimpleNamespace(**vars(remote), module=module, grant=grant, plan=plan)


def rebind(root_auto):
    root_auto.plan["automatic_grant_id"] = root_auto.grant["grant_id"]
    root_auto.plan["automatic_grant_digest"] = root_auto.core.digest(root_auto.grant)


def saved_job(root_auto, *, job_id=JOB, **changes):
    job = {
        "schema_version": 1,
        "job_id": job_id,
        "authorization": "automatic",
        "automatic_grant_id": root_auto.grant["grant_id"],
        "automatic_grant_digest": root_auto.core.digest(root_auto.grant),
        "plan_id": root_auto.plan["plan_id"],
        "plan_digest": root_auto.plan["plan_digest"],
        "status": "queued",
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        **changes,
    }
    folder = root_auto.path / "jobs" / job_id
    folder.mkdir(exist_ok=True)
    root_auto.core.write_json(folder / "job.json", job)
    return job


def admission(root_auto, job_id=JOB):
    return {
        "kind": "automatic",
        "job_id": job_id,
        "plan_id": root_auto.plan["plan_id"],
        "plan_digest": root_auto.plan["plan_digest"],
        "mode_revision": 0,
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "automatic_grant_id": root_auto.grant["grant_id"],
        "automatic_grant_digest": root_auto.core.digest(root_auto.grant),
    }


def test_root_medium_restart_remains_medium_and_requires_explicit_grant(root_auto):
    assert root_auto.module.authorize(root_auto.plan, root_auto.policy) == root_auto.grant
    assert root_auto.plan["risk_level"] == "medium"
    assert root_auto.plan["requires_service_restart"] is True
    assert root_auto.commands == []
    root_auto.grant["allowed_risk_levels"] = ["low"]
    rebind(root_auto)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("where", ["absent", "grant_disabled", "policy_disabled"])
def test_no_implicit_root_automatic_authority(root_auto, where):
    if where == "absent":
        root_auto.policy.pop("automatic")
    elif where == "grant_disabled":
        root_auto.grant["enabled"] = False
    else:
        root_auto.policy["enabled"] = False
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("kind", ["expired", "future", "over_24h", "naive"])
def test_root_grant_lifetime_is_bounded_and_current(root_auto, kind):
    if kind == "expired":
        root_auto.grant.update(
            issued_at=(NOW - timedelta(hours=1)).isoformat(), expires_at=NOW.isoformat()
        )
    elif kind == "future":
        root_auto.grant.update(
            issued_at=(NOW + timedelta(seconds=1)).isoformat(),
            expires_at=(NOW + timedelta(hours=1)).isoformat(),
        )
    elif kind == "over_24h":
        root_auto.grant["expires_at"] = (NOW + timedelta(hours=24)).isoformat()
    else:
        root_auto.grant["expires_at"] = NOW.replace(tzinfo=None).isoformat()
    rebind(root_auto)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


def test_root_windows_use_starting_utc_weekday_and_exclusive_end(root_auto):
    # NOW is Wednesday. This window starts Sunday and continues into Monday.
    root_auto.grant["maintenance_windows"] = [
        {"weekdays": [6], "start_minute": 23 * 60, "end_minute": 60}
    ]
    sunday = NOW.replace(day=25, hour=23, minute=0)
    monday = NOW.replace(day=26, hour=0, minute=59)
    assert root_auto.module.maintenance_open(root_auto.grant, sunday)
    assert root_auto.module.maintenance_open(root_auto.grant, monday)
    assert root_auto.module.maintenance_open(
        root_auto.grant, monday.astimezone(timezone(timedelta(hours=8)))
    )
    assert not root_auto.module.maintenance_open(root_auto.grant, sunday - timedelta(minutes=1))
    assert not root_auto.module.maintenance_open(root_auto.grant, monday + timedelta(minutes=1))
    rebind(root_auto)
    with pytest.raises(root_auto.core.Rejected, match="window"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"enabled": "true"},
        {"allow_service_restart": 1},
        {"grant_id": "../../bad"},
        {"allowed_packages": []},
        {"allowed_packages": ["curl", "curl"]},
        {"allowed_packages": ["bash"]},
        {"allowed_advisories": ["CVE-2026-111497"]},
        {"allowed_advisories": ["USN-99999-1", "USN-99999-1"]},
        {"max_jobs_per_day": True},
        {"max_jobs_per_day": 0},
        {"max_total_jobs": "1"},
        {"max_total_jobs": 6},
        {"allowed_risk_levels": ["high"]},
        {"allowed_risk_levels": ["unknown"]},
        {"maintenance_windows": []},
        {"maintenance_windows": [{"weekdays": [2], "start_minute": 0, "end_minute": 0}]},
        {"maintenance_windows": [{"weekdays": [True], "start_minute": 0, "end_minute": 1440}]},
        {"maintenance_windows": [{"weekdays": [2, 2], "start_minute": 0, "end_minute": 1440}]},
        {"shell": "touch /tmp/never"},
    ],
)
def test_root_grant_schema_is_explicit_and_rejects_scope_extensions(root_auto, change):
    root_auto.grant.update(change)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.validate_grant(root_auto.policy)


@pytest.mark.parametrize(
    "field",
    [
        "evidence_complete",
        "transaction_complete_verified",
        "restart_impact_verified",
    ],
)
@pytest.mark.parametrize("unverified", [False, None, "true", 1])
def test_root_plan_proof_flags_require_exact_true(root_auto, field, unverified):
    root_auto.plan[field] = unverified
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize(
    "field", ["affected", "candidate_fixable", "vendor_evidence_fresh", "finding_evidence_complete"]
)
def test_root_finding_proofs_cannot_be_omitted(root_auto, field):
    root_auto.plan["finding"].pop(field)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize(
    "kind", ["package", "advisory", "two_packages", "high", "unknown", "reboot"]
)
def test_root_plan_must_match_exact_single_package_notice_and_risk(root_auto, kind):
    if kind == "package":
        root_auto.plan["package_changes"][0]["name"] = "curl; touch /tmp/never"
    elif kind == "advisory":
        root_auto.plan["finding"]["advisory"] = "USN-99999-2"
    elif kind == "two_packages":
        root_auto.plan["package_changes"].append({**root_auto.change, "name": "bash"})
    elif kind == "reboot":
        root_auto.plan["requires_reboot"] = True
    else:
        root_auto.plan["risk_level"] = kind
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)
    assert root_auto.commands == []


def test_root_service_restart_needs_both_explicit_permissions(root_auto):
    root_auto.grant["allow_service_restart"] = False
    rebind(root_auto)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("value", [None, "false", 0])
def test_unknown_restart_impact_is_not_accepted_by_restart_permission(root_auto, value):
    root_auto.plan["requires_service_restart"] = value
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("field", ["automatic_grant_id", "automatic_grant_digest"])
def test_new_root_grant_invalidates_prepared_plan(root_auto, field):
    root_auto.plan[field] = "0" * (32 if field.endswith("_id") else 64)
    with pytest.raises(root_auto.core.Rejected, match="different root grant"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("status", ["queued", "failed", "unknown", "verified"])
def test_root_quota_counts_all_persisted_automatic_intents(root_auto, status):
    saved_job(root_auto, status=status)
    assert root_auto.module.usage(root_auto.grant) == {"daily_used": 1, "total_used": 1}
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy, admission=True)


def test_daily_quota_is_host_wide_and_total_quota_is_per_grant(root_auto):
    saved_job(root_auto, automatic_grant_id="d" * 32)
    assert root_auto.module.usage(root_auto.grant) == {"daily_used": 1, "total_used": 0}
    with pytest.raises(root_auto.core.Rejected, match="quota"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy, admission=True)


def test_old_intent_still_spends_total_quota_but_not_todays(root_auto):
    saved_job(root_auto, created_at=(NOW - timedelta(days=1)).isoformat())
    assert root_auto.module.usage(root_auto.grant) == {"daily_used": 0, "total_used": 1}
    with pytest.raises(root_auto.core.Rejected, match="quota"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy, admission=True)


def test_worker_can_exclude_only_its_already_admitted_intent(root_auto):
    saved_job(root_auto)
    assert root_auto.module.usage(root_auto.grant, exclude_job_id=JOB) == {
        "daily_used": 0,
        "total_used": 0,
    }
    assert (
        root_auto.module.authorize(root_auto.plan, root_auto.policy, admission(root_auto))
        == root_auto.grant
    )
    with pytest.raises(root_auto.core.Rejected, match="quota"):
        root_auto.module.authorize(
            root_auto.plan, root_auto.policy, admission(root_auto), admission=True
        )


@pytest.mark.parametrize("field", ["kind", "automatic_grant_id", "automatic_grant_digest"])
def test_worker_admission_record_cannot_change_authorization(root_auto, field):
    saved_job(root_auto)
    approved = admission(root_auto)
    approved[field] = "assisted" if field == "kind" else "0" * 64
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy, approved)


@pytest.mark.parametrize(
    "status", sorted({"failed", "unknown", "verification_failed", "running_overdue"})
)
def test_automatic_failure_latches_across_new_grants_and_mode_changes(root_auto, status):
    saved_job(root_auto, status=status)
    initial = root_auto.module.safety_state()
    assert initial["paused"] is True
    assert initial["job_id"] == JOB
    root_auto.grant["grant_id"] = "d" * 32
    root_auto.core.write_json(root_auto.path / "mode.json", {"mode": "manual", "revision": 99})
    rebind(root_auto)
    assert root_auto.module.safety_state() == initial
    persisted = root_auto.core.read_json(root_auto.path / "automatic-state.json")
    assert persisted == initial
    with pytest.raises(root_auto.core.Rejected, match="paused"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


def test_unobserved_overdue_then_verified_history_still_persists_pause(root_auto):
    saved_job(
        root_auto,
        status="verified",
        history=[
            {"status": "queued", "at": NOW.isoformat()},
            {"status": "running_overdue", "at": NOW.isoformat()},
            {"status": "verifying", "at": NOW.isoformat()},
            {"status": "verified", "at": NOW.isoformat()},
        ],
    )
    state = root_auto.module.safety_state()
    assert state["paused"] is True
    assert state["reason"] == "automatic_job_running_overdue"
    assert state["job_id"] == JOB
    assert root_auto.core.read_json(root_auto.path / "automatic-state.json") == state
    # New policy/grant and subsequent successful status cannot erase the pause.
    root_auto.grant["grant_id"] = "d" * 32
    rebind(root_auto)
    assert root_auto.module.safety_state() == state
    with pytest.raises(root_auto.core.Rejected, match="paused"):
        root_auto.module.authorize(root_auto.plan, root_auto.policy)


@pytest.mark.parametrize("authorization", ["automatic", "assisted"])
def test_pending_transport_verification_blocks_another_transaction(root_auto, authorization):
    root_auto.grant.update(max_jobs_per_day=5, max_total_jobs=5)
    saved_job(root_auto, authorization=authorization, status="awaiting_transport_verification")
    new_request = request(
        root_auto,
        "submit",
        plan_id=root_auto.plan["plan_id"],
        plan_digest=root_auto.plan["plan_digest"],
        job_id="b" * 32,
        mode_revision=0,
    )
    with pytest.raises(root_auto.core.Rejected, match="active or uncertain"):
        root_auto.agent.submit(new_request, root_auto.policy)
    assert not (root_auto.path / "jobs" / ("b" * 32)).exists()
    assert root_auto.commands == []


@pytest.mark.parametrize("authorization", ["assisted", "legacy"])
def test_historical_assisted_failure_does_not_consume_automatic_quota_or_latch(
    root_auto, authorization
):
    job = saved_job(root_auto, authorization=authorization, status="failed")
    if authorization == "legacy":
        job.pop("authorization")
        root_auto.core.write_json(root_auto.path / "jobs" / JOB / "job.json", job)
    assert root_auto.module.safety_state()["paused"] is False
    assert root_auto.module.usage(root_auto.grant) == {"daily_used": 0, "total_used": 0}
    assert root_auto.module.authorize(root_auto.plan, root_auto.policy) == root_auto.grant


@pytest.mark.parametrize(
    "state",
    [
        [],
        {"schema_version": 1, "paused": "false"},
        {"schema_version": True, "paused": False},
        {"schema_version": 2, "paused": False},
    ],
)
def test_corrupt_persisted_safety_state_is_never_treated_as_unpaused(root_auto, state):
    root_auto.core.write_json(root_auto.path / "automatic-state.json", state)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.safety_state()


@pytest.mark.parametrize(
    "change",
    [
        {"job_id": "b" * 32},
        {"authorization": None},
        {"status": "not_a_known_status"},
        {"created_at": NOW.replace(tzinfo=None).isoformat()},
        {"automatic_grant_id": "../../unknown"},
    ],
)
def test_corrupt_automatic_ledger_cannot_appear_unused_or_safe(root_auto, change):
    job = saved_job(root_auto)
    job.update(change)
    root_auto.core.write_json(root_auto.path / "jobs" / JOB / "job.json", job)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.safety_state()
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.usage(root_auto.grant)


@pytest.mark.parametrize("field", ["authorization", "automatic_grant_id", "plan_id", "plan_digest"])
def test_worker_cannot_exclude_a_different_accepted_plan(root_auto, field):
    job = saved_job(root_auto)
    job[field] = (
        "assisted" if field == "authorization" else "b" * (64 if field == "plan_digest" else 32)
    )
    root_auto.core.write_json(root_auto.path / "jobs" / JOB / "job.json", job)
    with pytest.raises(root_auto.core.Rejected):
        root_auto.module.authorize(root_auto.plan, root_auto.policy, admission(root_auto))


def test_automatic_status_only_reads_local_state_without_executing_commands(root_auto):
    value = root_auto.module.status(root_auto.policy)
    assert value["enabled"] is True
    assert value["grant_digest"] == root_auto.core.digest(root_auto.grant)
    assert value["usage"] == {"daily_used": 0, "total_used": 0}
    assert value["safety"]["paused"] is False
    assert root_auto.commands == []


@pytest.mark.parametrize("field", ["shell", "command", "argv", "script"])
def test_automatic_channel_does_not_add_an_arbitrary_shell_rpc(root_auto, field):
    value = request(
        root_auto, "submit", plan_id="f" * 32, plan_digest="0" * 64, job_id=JOB, mode_revision=0
    )
    value[field] = "id"
    with pytest.raises(root_auto.core.Rejected):
        root_auto.agent.validate_request(value)
    assert root_auto.commands == []
