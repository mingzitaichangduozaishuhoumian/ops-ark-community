"""Exact activation-backed manual resolution must not promote the original install."""

import copy
import hashlib
import json
from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_patch_agent import JOB, NOW, load_module
from test_patch_agent import remote as remote
from test_patch_install_safety import bootstrap as bootstrap
from test_root_activation import BOOT, CTX, mode, preview, submit
from test_root_activation import activation_env as activation_env


def completed_activation(e, monkeypatch, *, authorization="automatic"):
    grant = {
        "schema_version": 1,
        "enabled": True,
        "grant_id": "b" * 32,
        "issued_at": (NOW - timedelta(hours=2)).isoformat(),
        "expires_at": (NOW - timedelta(hours=1)).isoformat(),
        "allowed_packages": ["libexpat1"],
        "allowed_advisories": [e.finding["advisory"]],
        "maintenance_windows": [
            {"weekdays": [NOW.weekday()], "start_minute": 0, "end_minute": 1440}
        ],
        "max_jobs_per_day": 1,
        "max_total_jobs": 1,
        "allowed_risk_levels": ["medium"],
        "allow_service_restart": True,
    }
    e.policy["automatic"] = grant
    plan = copy.deepcopy(e.patch_plan)
    plan["prepared_mode"] = authorization
    admitted = NOW - timedelta(minutes=90)
    plan.update(
        created_at=admitted.isoformat(), expires_at=(admitted + timedelta(minutes=30)).isoformat()
    )
    job = copy.deepcopy(e.job)
    job.update(authorization=authorization, mode_revision=0, created_at=admitted.isoformat())
    approval = {
        "kind": authorization,
        "job_id": JOB,
        "mode_revision": 0,
        "approved_at": admitted.isoformat(),
        "expires_at": (admitted + timedelta(minutes=10)).isoformat(),
    }
    if authorization == "automatic":
        for target in (plan, job, approval):
            target["automatic_grant_id"] = grant["grant_id"]
            target["automatic_grant_digest"] = e.core.digest(grant)
    else:
        e.core.write_json(
            e.path / "automatic-state.json",
            {
                "schema_version": 1,
                "paused": False,
                "reason": None,
                "job_id": None,
                "updated_at": NOW.isoformat(),
            },
        )
    plan["plan_digest"] = e.core.digest({k: v for k, v in plan.items() if k != "plan_digest"})
    job["plan_digest"] = approval["plan_digest"] = plan["plan_digest"]
    e.core.write_json(e.folder / "plan.json", plan)
    e.core.write_json(e.folder / "job.json", job)
    e.core.write_json(e.folder / "approval.json", approval)
    mode(e, "assisted", 0)
    prepared = preview(e)
    submit(e, prepared)
    local = e.module.run(prepared["activation_id"])
    assert local["status"] == "awaiting_transport_verification"
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: True)
    act = e.module.status(prepared["activation_id"], e.policy)
    assert act["status"] == "verified"
    mode(e, "manual", 1)
    ar = load_module("activation_recovery", "activation_recovery.py", monkeypatch)
    recovery = __import__("recovery")
    monkeypatch.setattr(
        recovery, "transport_challenge", lambda: {"boot_id": BOOT, "uptime_ticks": 1000}
    )
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: False)
    e.ar, e.act, e.original_job = ar, act, job
    return e


@pytest.fixture
def environment(activation_env, monkeypatch):
    return completed_activation(activation_env, monkeypatch)


def prepare(e):
    return e.ar.prepare(
        {
            "job_id": JOB,
            "activation_id": e.act["activation_id"],
            "mode_revision": 1,
            "context_digest": CTX,
        },
        e.policy,
    )


def approve(e, plan):
    return e.ar.submit(
        {
            key: plan[key]
            for key in ("recovery_id", "recovery_digest", "mode_revision", "context_digest")
        },
        e.policy,
    )


def originals(e):
    return {
        "job": (e.folder / "job.json").read_bytes(),
        "plan": (e.folder / "plan.json").read_bytes(),
        "manifest": (e.folder / "runtime-files-before.json").read_bytes(),
        "act": (e.path / "activations" / e.act["activation_id"] / "activation.json").read_bytes(),
    }


def test_preview_and_approval_preserve_install_activation_and_exhausted_usage(
    environment, monkeypatch
):
    e = environment
    before = originals(e)
    pause = (e.path / "automatic-state.json").read_bytes()
    auto = __import__("automatic_policy")
    used = auto.usage(e.policy["automatic"])
    plan = prepare(e)
    assert plan["eligible"] and plan["blockers"] == []
    assert set(plan) == e.ar.PLAN_FIELDS
    assert plan["root_safety_raw_sha256"] == hashlib.sha256(pause).hexdigest()
    assert plan["root_safety_before_raw"].encode() == pause
    assert originals(e) == before and (e.path / "automatic-state.json").read_bytes() == pause
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: True)
    receipt = approve(e, plan)
    assert set(receipt) == e.ar.RECEIPT_FIELDS and receipt["status"] == "verified"
    assert receipt["resolved_job"]["status"] == "installed_restart_pending"
    assert receipt["verified_activation"]["status"] == "verified"
    assert receipt["root_usage_before"] == receipt["root_usage_after"]
    assert originals(e) == before and e.state.restarts == ["dbus.service"]
    assert auto.safety_state()["paused"] is False
    assert auto.usage(e.policy["automatic"]) == used == {"daily_used": 1, "total_used": 1}
    assert e.core.read_json(e.path / "mode.json")["mode"] == "manual"
    assert e.policy["automatic"]["expires_at"] < NOW.isoformat()
    assert approve(e, plan) == receipt and e.ar.status(plan["recovery_id"]) == receipt


@pytest.mark.parametrize("state", ["missing", "unpaused", "different_job", "new_pause_time"])
def test_preview_does_not_create_or_broaden_existing_pause(environment, state):
    e = environment
    path = e.path / "automatic-state.json"
    if state == "missing":
        path.unlink()
    else:
        value = e.core.read_json(path)
        if state == "unpaused":
            value.update(paused=False, reason=None, job_id=None)
        elif state == "different_job":
            value["job_id"] = "c" * 32
        else:
            value["updated_at"] = (NOW + timedelta(seconds=1)).isoformat()
        e.core.write_json(path, value)
    before = path.read_bytes() if path.exists() else None
    plan = prepare(e)
    assert not plan["eligible"] and "exact_root_pause" in plan["blockers"]
    assert (path.read_bytes() if path.exists() else None) == before
    with pytest.raises(e.core.Rejected):
        approve(e, plan)


def test_assisted_original_is_not_an_automatic_cause(activation_env, monkeypatch):
    e = completed_activation(activation_env, monkeypatch, authorization="assisted")
    before = (e.path / "automatic-state.json").read_bytes()
    plan = prepare(e)
    assert not plan["eligible"] and "original_automatic_pending" in plan["blockers"]
    assert (e.path / "automatic-state.json").read_bytes() == before


@pytest.mark.parametrize("target", ["job", "activation", "plan", "approval", "restart", "manifest"])
def test_tampered_originals_never_authorize_resolution(environment, target):
    e = environment
    files = {
        "job": e.folder / "job.json",
        "manifest": e.folder / "runtime-files-before.json",
        "plan": e.folder / "plan.json",
        "approval": e.folder / "approval.json",
        "activation": e.path / "activations" / e.act["activation_id"] / "activation.json",
        "restart": e.path / "activations" / e.act["activation_id"] / "restart-intent.json",
    }
    value = e.core.read_json(files[target])
    value["unexpected"] = True
    e.core.write_json(files[target], value)
    with pytest.raises(e.core.Rejected):
        prepare(e)


def test_new_transport_is_required_and_rejection_does_not_release(environment):
    e = environment
    plan = prepare(e)
    before = (e.path / "automatic-state.json").read_bytes()
    receipt = approve(e, plan)
    assert receipt["status"] == "rejected" and "fresh_ssh" in receipt["blockers"]
    assert (e.path / "automatic-state.json").read_bytes() == before
    assert approve(e, plan) == receipt


@pytest.mark.parametrize("change", ["mode", "expiry", "pause", "context", "policy", "job"])
def test_stale_admission_does_not_even_record_an_approval(environment, monkeypatch, change):
    e = environment
    plan = prepare(e)
    if change == "mode":
        mode(e, "assisted", 2)
    elif change == "expiry":
        monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=5))
    elif change == "pause":
        value = e.core.read_json(e.path / "automatic-state.json")
        value["updated_at"] = (NOW + timedelta(seconds=1)).isoformat()
        e.core.write_json(e.path / "automatic-state.json", value)
    elif change == "context":
        plan = dict(plan, context_digest="f" * 64)
    elif change == "policy":
        e.policy["allowed_packages"] = []
    else:
        value = e.core.read_json(e.folder / "job.json")
        value["revision"] += 1
        e.core.write_json(e.folder / "job.json", value)
    with pytest.raises(e.core.Rejected):
        approve(e, plan)
    directory = e.path / "activation-recovery-submissions"
    assert not directory.exists() or not list(directory.iterdir())


def test_interrupted_admitted_approval_is_unknown_and_never_replayed(environment, monkeypatch):
    e = environment
    plan = prepare(e)

    def lost(*_args):
        raise RuntimeError("isolated failed observation")

    monkeypatch.setattr(e.ar, "_checks", lost)
    with pytest.raises(RuntimeError):
        approve(e, plan)
    value = e.ar.status(plan["recovery_id"])
    assert value["status"] == "unknown"
    assert approve(e, plan) == value
    with pytest.raises(e.core.Rejected):
        prepare(e)
    with pytest.raises(e.core.Rejected):
        e.core.assert_no_activation()
    assert e.core.read_json(e.path / "automatic-state.json")["paused"] is True


def test_late_same_pause_does_not_rearm_but_new_pause_and_other_bad_job_do(
    environment, monkeypatch
):
    e = environment
    pause = e.core.read_json(e.path / "automatic-state.json")
    plan = prepare(e)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    approve(e, plan)
    auto = __import__("automatic_policy")
    e.core.write_json(e.path / "automatic-state.json", pause)
    assert auto.safety_state()["paused"] is False
    newer = {**pause, "updated_at": (NOW + timedelta(seconds=1)).isoformat()}
    e.core.write_json(e.path / "automatic-state.json", newer)
    assert auto.safety_state() == newer
    e.core.write_json(
        e.path / "automatic-state.json",
        {
            "schema_version": 1,
            "paused": False,
            "reason": None,
            "job_id": None,
            "updated_at": NOW.isoformat(),
        },
    )
    other = "d" * 32
    folder = e.path / "jobs" / other
    folder.mkdir()
    e.core.write_json(
        folder / "job.json", {**e.original_job, "job_id": other, "status": "unknown", "revision": 1}
    )
    result = auto.safety_state()
    assert result["paused"] and result["job_id"] == other


def test_corrupt_receipt_or_missing_original_fails_closed_even_when_current_state_false(
    environment, monkeypatch
):
    e = environment
    plan = prepare(e)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    receipt = approve(e, plan)
    auto = __import__("automatic_policy")
    path = e.path / "activation-recovery-receipts" / (receipt["recovery_id"] + ".json")
    value = e.core.read_json(path)
    value["resolved_job"]["status"] = "verified"
    value["receipt_digest"] = e.core.digest(
        {k: v for k, v in value.items() if k != "receipt_digest"}
    )
    e.core.write_json(path, value)
    with pytest.raises(e.core.Rejected):
        auto.safety_state()
    e.core.write_json(path, receipt)
    (e.folder / "plan.json").unlink()
    with pytest.raises((e.core.Rejected, FileNotFoundError)):
        auto.safety_state()


def test_worker_and_native_locks_cover_approval_decision(environment, monkeypatch):
    e = environment
    held = []

    @contextmanager
    def native():
        held.append(True)
        try:
            yield
        finally:
            held.pop()

    monkeypatch.setattr(e.core, "native_package_locks", native)
    plan = prepare(e)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: bool(held))
    receipt = approve(e, plan)
    assert receipt["status"] == "verified" and not held


@pytest.mark.parametrize("drift", ["expiry", "process", "health", "runtime", "new_pause"])
def test_slow_supplier_observation_cannot_hide_changed_final_context(
    environment, monkeypatch, drift
):
    e = environment
    plan = prepare(e)
    before = (e.path / "automatic-state.json").read_bytes()
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)

    def supplier(**_kwargs):
        if drift == "expiry":
            monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=5))
        elif drift == "process":
            e.state.unit["main_process"]["pid"] += 1
        elif drift == "health":
            monkeypatch.setattr(
                e.core, "health", lambda _p: {"passed": False, "reboot_required": False}
            )
        elif drift == "runtime":
            e.state.runtime["outdated_process_count"] = 1
        else:
            state = e.core.read_json(e.path / "automatic-state.json")
            state["updated_at"] = (NOW + timedelta(seconds=1)).isoformat()
            e.core.write_json(e.path / "automatic-state.json", state)
        return copy.deepcopy(e.assessment)

    monkeypatch.setattr(e.core, "scan_packages", supplier)
    receipt = approve(e, plan)
    assert receipt["status"] == "rejected" and receipt["blockers"]
    if drift != "new_pause":
        assert (e.path / "automatic-state.json").read_bytes() == before
    else:
        assert (
            e.core.read_json(e.path / "automatic-state.json")["updated_at"]
            != (
                e.core.read_json(
                    e.path / "activation-recovery-plans" / (plan["recovery_id"] + ".json")
                )["root_safety_before"]["updated_at"]
            )
        )
    assert e.core.read_json(e.folder / "job.json")["status"] == "installed_restart_pending"


@pytest.mark.parametrize("slow_phase", ["final_ledger", "receipt_budget"])
def test_final_audit_io_cannot_backdate_approval_past_its_deadline(
    environment, monkeypatch, slow_phase
):
    e = environment
    plan = prepare(e)
    before = originals(e)
    pause = (e.path / "automatic-state.json").read_bytes()
    late = NOW + timedelta(minutes=6)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: True)
    if slow_phase == "final_ledger":
        settled = e.ar._settled
        calls = []

        def delayed_settled(job_id):
            value = settled(job_id)
            calls.append(job_id)
            if len(calls) == 2:  # Submit observation, followed by final ledger check.
                monkeypatch.setattr(e.core, "now", lambda: late)
            return value

        monkeypatch.setattr(e.ar, "_settled", delayed_settled)
    else:
        folder = e.ar._folder

        def delayed_retention(name, *, create=False):
            value = folder(name, create=create)
            if name == "activation-recovery-receipts" and create:
                monkeypatch.setattr(e.core, "now", lambda: late)
            return value

        monkeypatch.setattr(e.ar, "_folder", delayed_retention)
    receipt = approve(e, plan)
    assert receipt["status"] == "rejected" and "plan_valid" in receipt["blockers"]
    assert receipt["completed_at"] == late.isoformat()
    assert receipt["completed_at"] > plan["expires_at"]
    assert receipt["resolved_job"] is receipt["verified_activation"] is None
    assert originals(e) == before and (e.path / "automatic-state.json").read_bytes() == pause
    assert e.ar.status(plan["recovery_id"]) == receipt


@pytest.mark.parametrize("drift", ["process", "health", "runtime"])
@pytest.mark.parametrize("audit", ["settled", "usage", "ledger", "retention"])
def test_final_live_service_proof_follows_all_slow_audit_reads(
    environment, monkeypatch, drift, audit
):
    e = environment
    plan = prepare(e)
    before = originals(e)
    pause = (e.path / "automatic-state.json").read_bytes()
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: True)

    def change_live_state():
        if drift == "process":
            e.state.unit["main_process"]["pid"] += 1
        elif drift == "health":
            monkeypatch.setattr(
                e.core, "health", lambda _p: {"passed": False, "reboot_required": False}
            )
        else:
            e.state.runtime["outdated_process_count"] = 1

    if audit == "settled":
        settled = e.ar._settled
        calls = []

        def slow_settled(job_id):
            value = settled(job_id)
            calls.append(job_id)
            if len(calls) == 2:
                change_live_state()
            return value

        monkeypatch.setattr(e.ar, "_settled", slow_settled)
    elif audit in {"usage", "ledger"}:
        name = "_usage" if audit == "usage" else "_ledger_digest"
        operation = getattr(e.ar, name)

        def slow_audit(*args):
            value = operation(*args)
            change_live_state()
            return value

        monkeypatch.setattr(e.ar, name, slow_audit)
    else:
        folder = e.ar._folder

        def slow_retention(name, *, create=False):
            value = folder(name, create=create)
            if name == "activation-recovery-receipts" and create:
                change_live_state()
            return value

        monkeypatch.setattr(e.ar, "_folder", slow_retention)
    receipt = approve(e, plan)
    expected = {
        "process": "activation_process_current",
        "health": "registered_health",
        "runtime": "runtime_complete",
    }[drift]
    assert receipt["status"] == "rejected" and expected in receipt["blockers"]
    assert originals(e) == before and (e.path / "automatic-state.json").read_bytes() == pause
    assert receipt["resolved_job"] is receipt["verified_activation"] is None


def test_historical_activation_survives_reviewed_source_upgrade_without_new_rights(
    environment, monkeypatch
):
    e = environment
    before = originals(e)
    old_policy = e.act["policy_digest"]
    e.policy["driver_source_digest"] = "2" * 64
    e.policy["automatic"] = None
    e.policy["activation"]["enabled"] = False
    mode(e, "manual", 2)
    plan = e.ar.prepare(
        {
            "job_id": JOB,
            "activation_id": e.act["activation_id"],
            "mode_revision": 2,
            "context_digest": CTX,
        },
        e.policy,
    )
    assert (
        plan["eligible"]
        and plan["policy_digest"] != old_policy
        and plan["root_usage_before"] is None
    )
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    receipt = approve(e, plan)
    assert (
        receipt["status"] == "verified"
        and receipt["root_usage_before"] is receipt["root_usage_after"] is None
    )
    assert originals(e) == before and e.policy["activation"]["enabled"] is False


@pytest.mark.parametrize(
    "field", ["process", "runtime", "health", "version", "usage", "fresh_ssh", "resolved_job"]
)
def test_resealed_false_receipt_is_not_a_resolution(environment, monkeypatch, field):
    e = environment
    plan = prepare(e)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: True)
    value = copy.deepcopy(approve(e, plan))
    if field == "process":
        value["verification"]["activation_process"]["observed"]["pid"] += 1
    elif field == "runtime":
        value["verification"]["runtime"]["outdated_process_count"] = 1
    elif field == "health":
        value["verification"]["health"]["reboot_required"] = True
    elif field == "version":
        value["verification"]["exact_package_version"]["observed"] = "9.9"
    elif field == "usage":
        value["root_usage_after"]["usage"]["total_used"] = 0
    elif field == "fresh_ssh":
        value["verification"]["fresh_ssh"]["passed"] = False
    else:
        value["resolved_job"]["status"] = "verified"
    value["receipt_digest"] = e.core.digest(
        {k: v for k, v in value.items() if k != "receipt_digest"}
    )
    with pytest.raises(e.core.Rejected):
        e.ar.validate_receipt(value)


def test_another_unresolved_install_blocks_preview_without_mutating_originals(environment):
    e = environment
    before = originals(e)
    pause = (e.path / "automatic-state.json").read_bytes()
    other = "e" * 32
    folder = e.path / "jobs" / other
    folder.mkdir()
    e.core.write_json(folder / "job.json", {**e.original_job, "job_id": other, "status": "unknown"})
    value = prepare(e)
    assert not value["eligible"] and "ledger_settled" in value["blockers"]
    assert originals(e) == before and (e.path / "automatic-state.json").read_bytes() == pause


@pytest.mark.parametrize("fault", ["intent_digest", "intent_mode", "missing_plan"])
def test_receipt_cannot_release_or_allow_new_mutations_after_audit_pair_is_lost(
    environment, monkeypatch, fault
):
    e = environment
    plan = prepare(e)
    monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_args: True)
    receipt = approve(e, plan)
    if fault == "missing_plan":
        (e.path / "activation-recovery-plans" / (plan["recovery_id"] + ".json")).unlink()
    else:
        path = e.path / "activation-recovery-submissions" / (plan["recovery_id"] + ".json")
        intent = e.core.read_json(path)
        if fault == "intent_digest":
            intent["recovery_digest"] = "1" * 64
        else:
            intent["mode_revision"] += 1
        e.core.write_json(path, intent)
    with pytest.raises((e.core.Rejected, FileNotFoundError)):
        e.core.assert_no_activation()
    with pytest.raises((e.core.Rejected, FileNotFoundError)):
        __import__("automatic_policy").safety_state()
    assert receipt["status"] == "verified"


@pytest.mark.parametrize(
    "fault", [None, "rejected", "missing", "unknown", "digest", "context", "mode", "extra"]
)
def test_upgrade_requires_a_terminal_matching_recovery_intent_receipt(bootstrap, fault):
    installer = bootstrap.module
    identifier = "e" * 32
    intent = {
        "recovery_id": identifier,
        "recovery_digest": "a" * 64,
        "mode_revision": 1,
        "context_digest": CTX,
        "approved_at": NOW.isoformat(),
    }
    receipt = {
        "schema_version": 1,
        "kind": "activation_recovery",
        "recovery_id": identifier,
        "recovery_digest": intent["recovery_digest"],
        "mode_revision": 1,
        "context_digest": CTX,
        "status": "rejected" if fault == "rejected" else "verified",
    }
    if fault == "unknown":
        receipt["status"] = "unknown"
    if fault == "context":
        receipt["context_digest"] = "b" * 64
    if fault == "mode":
        receipt["mode_revision"] = 2
    if fault == "extra":
        intent["unexpected"] = True
    receipt["receipt_digest"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()
    if fault == "digest":
        receipt["receipt_digest"] = "b" * 64
    for name, value in (
        ("activation-recovery-submissions", intent),
        ("activation-recovery-receipts", receipt),
    ):
        folder = bootstrap.state / name
        folder.mkdir()
        if name.endswith("receipts") and fault == "missing":
            continue
        (folder / (identifier + ".json")).write_text(json.dumps(value))
    if fault in {None, "rejected"}:
        installer.reject_unfinished_jobs()
    else:
        with pytest.raises(ValueError):
            installer.reject_unfinished_jobs()
