"""A verified activation is evidence for one new approval, never a generic reset."""

import copy
import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from test_activation_controller import (
    ACTIVATION,
    SOURCE,
)
from test_activation_controller import (
    activation as activation,
)
from test_activation_controller import (
    prepare as prepare_activation,
)
from test_activation_controller import (
    submit as submit_activation,
)
from test_automatic_monitor import HOST, ROOT_POLICY
from test_automatic_service import env as env

from opsark.activation_recovery_api import (
    ANCHORS,
    FINAL_CHECKS,
    IDENTITY,
    PLAN_FIELDS,
    REQUIRED_CHECKS,
    ActivationRecoveryPrepareRequest,
    ActivationRecoveryService,
    ActivationRecoverySubmitRequest,
    register_activation_recovery_routes,
)
from opsark.activation_recovery_store import ActivationRecoveryStore
from opsark.automatic_store import canonical, digest, safety_digest
from opsark.automation_store import ModeChange
from opsark.patch_client import UnknownPatchResult

RECOVERY = "9" * 32


def sealed(value, field):
    value[field] = digest({key: item for key, item in value.items() if key != field})
    return value


@pytest.fixture
def recovered_activation(activation):
    a = activation
    e = a.e
    e.root_safety = {
        "schema_version": 1,
        "paused": True,
        "job_id": e.job["job_id"],
        "reason": "automatic_job_installed_restart_pending",
        "updated_at": e.clock.isoformat(),
    }
    e.root_usage = {"daily_used": 1, "total_used": 1}

    def plan_hook(plan):
        plan["original_safety_digest"] = digest(e.root_safety)
        plan["original_job_sha256"] = digest(e.job)

    a.plan_hook = plan_hook
    act = prepare_activation(a)
    submit_activation(a, act)
    a.root_status, a.root_revision = "verified", 6
    a.receipt_hook = lambda result: result["verification"]["new_process"].update(
        after={"pid": 81, "starttime_ticks": 500, "cgroup": "/system.slice/nginx.service"}
    )
    e.clock += timedelta(seconds=2)
    a.service.poll(HOST, ACTIVATION)
    assert a.store.get(HOST, ACTIVATION)["status"] == "verified"
    e.service.change_mode(
        ModeChange(mode="manual", expected_revision=e.automation.status()["revision"])
    )
    store = ActivationRecoveryStore(e.auto.path, automatic=e.auto)
    service = ActivationRecoveryService(e.service, a.service, store=store)
    original = e.service.invoker
    state = SimpleNamespace(
        a=a,
        e=e,
        service=service,
        store=store,
        calls=[],
        plans={},
        receipts={},
        plan_hook=None,
        receipt_hook=None,
        loss=False,
        status_unknown=False,
        after_submit=None,
        next_id=RECOVERY,
        force_rejected=False,
    )

    def invoke(target, request, timeout=75):
        op = request["op"]
        if not op.startswith("activation_recovery_"):
            return original(target, request, timeout)
        state.calls.append(copy.deepcopy(request))
        if op == "activation_recovery_prepare":
            saved = a.store.get(HOST, ACTIVATION)
            raw_job = copy.deepcopy(e.job)
            anchors = service._expected_anchors(raw_job, saved)
            value = dict.fromkeys(PLAN_FIELDS)
            remote = original(target, {"op": "automatic_status"}, timeout)
            value.update(
                schema_version=1,
                kind="activation_recovery",
                status="activation_recovery_prepared",
                host_id=HOST,
                policy_digest=target.policy_digest,
                driver_source_digest=SOURCE,
                recovery_id=state.next_id,
                job_id=e.job["job_id"],
                job_revision=e.job["revision"],
                job_digest=digest(raw_job),
                mode_revision=request["mode_revision"],
                context_digest=request["context_digest"],
                created_at=e.clock.isoformat(),
                expires_at=(e.clock + timedelta(minutes=5)).isoformat(),
                **anchors,
            )
            value.update(
                ledger_digest="a" * 64,
                eligible=True,
                checks=[
                    {"id": name, "status": "passed", "detail": "synthetic contract fixture"}
                    for name in sorted(REQUIRED_CHECKS)
                ],
                blockers=[],
                verification={
                    "exact_package_version": {
                        "passed": True,
                        "expected": saved["plan"]["candidate_version"],
                        "observed": saved["plan"]["candidate_version"],
                    },
                    "final_package_state": {
                        "passed": True,
                        "expected": saved["plan"]["candidate_version"],
                        "observed": saved["plan"]["candidate_version"],
                        "apt_configuration_safe": True,
                        "apt_state_digest": "b" * 64,
                    },
                    "health": {"passed": True, "reboot_required": False},
                    "runtime": {"status": "complete", "outdated_process_count": 0},
                    "activation_process": {
                        "passed": True,
                        "observed": saved["result"]["verification"]["new_process"]["after"],
                    },
                    "vendor_rescan": {"passed": True, "finding_id": "synthetic-finding"},
                },
                state_digest="b" * 64,
                root_safety_before=copy.deepcopy(e.root_safety),
                root_safety_digest=safety_digest(e.root_safety),
                root_safety_before_raw=canonical(e.root_safety),
                root_usage_before=None
                if remote["grant"] is None
                else {
                    "grant_id": remote["grant"]["grant_id"],
                    "grant_digest": remote["grant_digest"],
                    "usage": remote["usage"],
                },
                transport_challenge={"boot_id": "synthetic-boot", "uptime_ticks": 80},
            )
            if state.plan_hook:
                state.plan_hook(value)
            value = sealed(value, "recovery_digest")
            state.plans[value["recovery_id"]] = copy.deepcopy(value)
            return value
        if op == "activation_recovery_submit":
            plan = state.plans[request["recovery_id"]]
            checks = [
                {"id": name, "status": "passed", "detail": "synthetic contract fixture"}
                for name in sorted(REQUIRED_CHECKS | FINAL_CHECKS)
            ]
            if state.force_rejected:
                checks[0]["status"] = "failed"
            verification = copy.deepcopy(plan["verification"])
            verification["fresh_ssh"] = {"passed": True}
            verification["health"]["reboot_required"] = False
            verification["runtime"] = {"status": "complete", "outdated_process_count": 0}
            verification["fresh_ssh"].update(
                mechanism="sshd_connection_started_after_activation_recovery_preview",
                checked_at=e.clock.isoformat(),
            )
            after = {
                "schema_version": 1,
                "paused": False,
                "job_id": None,
                "reason": None,
                "updated_at": e.clock.isoformat(),
            }
            value = {key: copy.deepcopy(plan[key]) for key in IDENTITY | ANCHORS}
            value.update(
                status="rejected" if state.force_rejected else "verified",
                recovery_digest=plan["recovery_digest"],
                plan=copy.deepcopy(plan),
                completed_at=e.clock.isoformat(),
                checks=checks,
                blockers=[c["id"] for c in checks if c["status"] != "passed"],
                verification=verification,
                resolved_job=None
                if state.force_rejected
                else {
                    "job_id": plan["job_id"],
                    "revision": plan["job_revision"],
                    "job_digest": plan["job_digest"],
                    "status": "installed_restart_pending",
                },
                verified_activation=None
                if state.force_rejected
                else {
                    "activation_id": ACTIVATION,
                    "revision": 6,
                    "activation_digest": plan["activation_digest"],
                    "record_digest": plan["activation_record_digest"],
                    "status": "verified",
                },
                resolved_safety_digest=plan["root_safety_digest"],
                safety_before=copy.deepcopy(plan["root_safety_before"]),
                safety_after=copy.deepcopy(e.root_safety) if state.force_rejected else after,
                safety_after_digest=safety_digest(e.root_safety if state.force_rejected else after),
                root_usage_before=copy.deepcopy(plan["root_usage_before"]),
                root_usage_after=copy.deepcopy(plan["root_usage_before"]),
            )
            if state.receipt_hook:
                state.receipt_hook(value)
            value = sealed(value, "receipt_digest")
            state.receipts[value["recovery_id"]] = copy.deepcopy(value)
            if not state.force_rejected:
                e.root_safety = after
            if state.after_submit:
                state.after_submit()
            if state.loss:
                raise UnknownPatchResult(op, request["recovery_id"])
            return value
        assert op == "activation_recovery_status"
        if state.status_unknown:
            return {
                "schema_version": 1,
                "kind": "activation_recovery",
                "host_id": HOST,
                "policy_digest": ROOT_POLICY,
                "status": "unknown",
                "recovery_id": request["recovery_id"],
            }
        return copy.deepcopy(
            state.receipts.get(request["recovery_id"], state.plans[request["recovery_id"]])
        )

    e.service.invoker = invoke
    return state


def prepare(r):
    return r.service.prepare(
        ActivationRecoveryPrepareRequest(
            host_id=HOST,
            job_id=r.e.job["job_id"],
            activation_id=ACTIVATION,
            expected_mode_revision=r.e.automation.status()["revision"],
        )
    )


def submit(r, plan):
    return r.service.submit(
        ActivationRecoverySubmitRequest(
            host_id=HOST,
            recovery_id=plan["recovery_id"],
            expected_recovery_digest=plan["recovery_digest"],
            expected_mode_revision=plan["mode_revision"],
            confirm_recover=True,
        )
    )


def quotas(r):
    return r.e.auto.quotas(HOST, r.e.automation.policy.automatic.grant_id, now=r.e.clock)


def test_preview_separate_approval_release_preserves_originals_and_usage(recovered_activation):
    r = recovered_activation
    original = copy.deepcopy(r.e.job), copy.deepcopy(r.a.store.get(HOST, ACTIVATION)), quotas(r)
    plan = prepare(r)
    assert plan["kind"] == "activation_recovery" and r.e.auto.latch(HOST)
    before = list(r.calls)
    r.service.list()
    r.service.status(HOST, plan["recovery_id"])
    assert r.calls == before  # Prepared reads are pure cache.
    result = submit(r, plan)
    assert result["status"] == "verified" and result["local_released"] is True
    assert r.e.auto.latch(HOST) is None
    assert (r.e.job, r.a.store.get(HOST, ACTIVATION), quotas(r)) == original
    assert r.e.automation.status()["mode"] == "manual"
    assert submit(r, plan) == result
    assert [call["op"] for call in r.calls].count("activation_recovery_submit") == 1


def test_lost_receipt_queries_original_and_restart_does_not_resubmit(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    r.loss = True
    assert submit(r, plan)["status"] == "unknown" and r.e.auto.latch(HOST)
    r.service.store = ActivationRecoveryStore(r.e.auto.path, automatic=r.e.auto)
    result = r.service.status(HOST, plan["recovery_id"])
    assert result["status"] == "verified" and result["local_released"]
    assert [call["op"] for call in r.calls].count("activation_recovery_submit") == 1


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.e.job.update(authorization="assisted"),
        lambda r: r.e.job.update(status="failed"),
        lambda r: r.e.root_safety.update(paused=False, job_id=None, reason=None),
        lambda r: r.e.root_safety.update(reason="automatic_job_unknown"),
        lambda r: r.e.root_safety.update(job_id="a" * 32),
    ],
)
def test_wrong_parent_or_actual_pause_cannot_generate_approval(recovered_activation, change):
    r = recovered_activation
    change(r)
    with pytest.raises((HTTPException, ValueError)):
        prepare(r)
    assert r.store.list() == []
    assert not any(call["op"] == "activation_recovery_submit" for call in r.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("activation_digest", "c" * 64),
        ("job_digest", "d" * 64),
        ("root_safety_raw_sha256", "e" * 64),
        ("root_safety_digest", "f" * 64),
        ("activation_revision", True),
        ("kind", "recovery"),
    ],
)
def test_resealed_native_preview_cannot_change_saved_anchors(recovered_activation, field, value):
    r = recovered_activation
    r.plan_hook = lambda plan: plan.update({field: value})
    with pytest.raises(HTTPException):
        prepare(r)
    assert r.store.list() == [] and r.e.auto.latch(HOST)


def test_expiry_and_manual_revision_guard_before_transport(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    r.e.clock += timedelta(minutes=6)
    with pytest.raises(HTTPException):
        submit(r, plan)
    assert not any(c["op"] == "activation_recovery_submit" for c in r.calls)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt["verification"]["fresh_ssh"].update(passed=False),
        lambda receipt: receipt["verification"]["runtime"].update(outdated_process_count=1),
        lambda receipt: receipt["resolved_job"].update(status="verified"),
        lambda receipt: receipt["verified_activation"].update(revision=5),
        lambda receipt: receipt["checks"].pop(),
        lambda receipt: receipt["root_usage_after"]["usage"].update(total_used=0),
        lambda receipt: receipt["verification"]["activation_process"]["observed"].update(pid=99),
        lambda receipt: receipt["verification"]["vendor_rescan"].update(finding_id="other"),
        lambda receipt: receipt["verification"]["final_package_state"].update(observed="older"),
    ],
)
def test_resealed_receipt_bad_proof_never_releases_local_pause(recovered_activation, mutation):
    r = recovered_activation
    plan = prepare(r)
    r.receipt_hook = mutation
    result = submit(r, plan)
    assert result["status"] == "unknown" and not result["local_released"] and r.e.auto.latch(HOST)


def test_new_pause_after_root_decision_is_not_released(recovered_activation):
    r = recovered_activation
    plan = prepare(r)

    def newer():
        r.e.root_safety = {
            "schema_version": 1,
            "paused": True,
            "job_id": "a" * 32,
            "reason": "automatic_job_unknown",
            "updated_at": r.e.clock.isoformat(),
        }

    r.after_submit = newer
    result = submit(r, plan)
    assert result["status"] == "superseded" and not result["local_released"]
    assert r.e.auto.latch(HOST)["job_id"] == "a" * 32


def test_late_same_root_and_job_do_not_rearm_but_changed_job_does(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    old_root = copy.deepcopy(r.e.root_safety)
    assert submit(r, plan)["local_released"]
    r.e.auto.record_result(
        r.e.auto.get_by_job(HOST, r.e.job["job_id"])["id"],
        r.e.job,
        now=r.e.clock,
    )
    assert r.e.auto.latch(HOST) is None
    original = r.e.root_safety
    r.e.root_safety = old_root
    r.e.service.refresh_automatic_status(HOST)
    r.e.root_safety = original
    assert r.e.auto.latch(HOST) is None
    job = copy.deepcopy(r.e.job)
    job["revision"] += 1
    r.e.auto.record_result(r.e.auto.get_by_job(HOST, job["job_id"])["id"], job, now=r.e.clock)
    assert r.e.auto.latch(HOST)


@pytest.mark.parametrize(
    "corruption", ["orphan", "resolution_digest", "receipt_check", "malformed_check"]
)
def test_bad_resolution_evidence_cannot_suppress_a_real_pending_result(
    recovered_activation, corruption
):
    r = recovered_activation
    plan = prepare(r)
    assert submit(r, plan)["local_released"]
    with sqlite3.connect(r.e.auto.path) as connection:
        if corruption == "orphan":
            connection.execute("DELETE FROM activation_recoveries")
        elif corruption == "resolution_digest":
            connection.execute(
                "UPDATE activation_recovery_resolved_jobs SET receipt_digest=?", ("f" * 64,)
            )
        else:
            row = connection.execute("SELECT payload FROM activation_recoveries").fetchone()
            value = json.loads(row[0])
            if corruption == "malformed_check":
                value["receipt"]["checks"][0] = "malformed"
            else:
                value["receipt"]["checks"].pop()
            sealed(value["receipt"], "receipt_digest")
            connection.execute("UPDATE activation_recoveries SET payload=?", (canonical(value),))
    r.e.auto.record_result(
        r.e.auto.get_by_job(HOST, r.e.job["job_id"])["id"], r.e.job, now=r.e.clock
    )
    assert r.e.auto.latch(HOST)


def test_routes_protected_and_confirmation_required(recovered_activation):
    r = recovered_activation
    app = FastAPI()

    def denied():
        raise HTTPException(401, "fixture authentication required")

    register_activation_recovery_routes(app, r.service, [Depends(denied)])
    client = TestClient(app)
    assert client.get("/api/activation-recoveries").status_code == 401
    assert client.post("/api/activation-recoveries/plans", json={}).status_code == 401
    with pytest.raises(ValueError):
        ActivationRecoverySubmitRequest(
            host_id=HOST,
            recovery_id=RECOVERY,
            expected_recovery_digest="a" * 64,
            expected_mode_revision=1,
            confirm_recover=False,
        )


def test_mode_revision_drift_and_absent_local_latch_block_before_transport(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    with pytest.raises(HTTPException):
        r.service.submit(
            ActivationRecoverySubmitRequest(
                host_id=HOST,
                recovery_id=RECOVERY,
                expected_recovery_digest=plan["recovery_digest"],
                expected_mode_revision=plan["mode_revision"] + 1,
                confirm_recover=True,
            )
        )
    with sqlite3.connect(r.e.auto.path) as connection:
        connection.execute("UPDATE automatic_latches SET active=0")
    before = len(r.calls)
    with pytest.raises(HTTPException):
        prepare(r)
    assert len(r.calls) == before
    assert not any(call["op"] == "activation_recovery_submit" for call in r.calls)


def test_historical_activation_source_survives_root_upgrade_but_not_host_retarget(
    recovered_activation,
):
    r = recovered_activation
    target = r.e.service.target(HOST)
    r.e.service.targets[HOST] = replace(target, policy_digest="f" * 64)
    original = r.e.service.invoker

    def upgraded(remote, request, timeout=75):
        value = original(remote, request, timeout)
        if request["op"] == "automatic_status":
            value = {**value, "policy_digest": remote.policy_digest}
        return value

    r.e.service.invoker = upgraded
    plan = prepare(r)
    assert plan["policy_digest"] != r.a.store.get(HOST, ACTIVATION)["policy_digest"]
    assert submit(r, plan)["local_released"]


def test_reused_host_id_with_other_address_cannot_use_historical_activation(recovered_activation):
    r = recovered_activation
    target = r.e.service.target(HOST)
    r.e.service.targets[HOST] = replace(
        target,
        host=replace(
            target.host, public=target.host.public.model_copy(update={"address": "192.0.2.99"})
        ),
    )
    with pytest.raises(HTTPException):
        prepare(r)
    assert r.store.list() == [] and r.calls == []


@pytest.mark.parametrize("without_grant", [True, False])
def test_manual_reconciliation_never_needs_or_refunds_new_automatic_budget(
    recovered_activation, without_grant
):
    r = recovered_activation
    usage = quotas(r)
    if without_grant:
        r.e.root_status_hook = lambda value: {
            **value,
            "enabled": False,
            "grant": None,
            "grant_digest": None,
            "usage": {"daily_used": None, "total_used": None},
        }
    else:
        r.e.root_usage = {"daily_used": 2, "total_used": 2}
    plan = prepare(r)
    assert (plan["root_usage_before"] is None) is without_grant
    assert submit(r, plan)["local_released"]
    assert quotas(r) == usage


def test_definite_root_rejection_retains_pause_and_original_approval(recovered_activation):
    r = recovered_activation
    plan = prepare(r)
    r.force_rejected = True
    result = submit(r, plan)
    assert result["status"] == "rejected" and not result["local_released"]
    assert r.e.auto.latch(HOST)
    assert submit(r, plan) == result
    assert [call["op"] for call in r.calls].count("activation_recovery_submit") == 1
