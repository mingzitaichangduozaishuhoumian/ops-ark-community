"""Approved root reconciliation receipts cannot silently reset execution authority."""

import copy
import sqlite3
from contextlib import closing
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from test_automatic_monitor import HOST, ROOT_POLICY, target
from test_automatic_service import env as env
from test_automatic_service import reserved

from opsark.automatic_monitor import scope_for_automatic
from opsark.automatic_store import AutomaticStore, canonical, digest, safety_digest
from opsark.automation_store import ModeChange
from opsark.config import Settings
from opsark.main import create_app
from opsark.patch_client import UnknownPatchResult
from opsark.recovery_api import (
    REQUIRED_CHECKS,
    RecoveryPrepareRequest,
    RecoveryService,
    RecoverySubmitRequest,
)

RECOVERY = "7" * 32
SOURCE = "8" * 64
TOKEN = "fixture-recovery-console-token-long-enough"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def seal_plan(value):
    value["recovery_digest"] = digest({k: v for k, v in value.items() if k != "recovery_digest"})
    return value


def seal_receipt(value):
    value["receipt_digest"] = digest({k: v for k, v in value.items() if k != "receipt_digest"})
    return value


@pytest.fixture
def recovery(env):
    candidate = reserved(env)
    env.unknown = True
    result = env.service.auto_submit(
        HOST,
        candidate["plan_id"],
        candidate["plan_digest"],
        candidate["mode_revision"],
        candidate["grant_digest"],
        candidate["job_id"],
    )
    assert result["status"] == "unknown"
    env.job.update(
        status="verified",
        revision=7,
        install_exit_code=0,
        verification={"fresh_ssh": {"passed": True}},
    )
    env.service.job_status(HOST, candidate["job_id"])
    assert env.auto.latch(HOST)
    env.service.change_mode(ModeChange(mode="manual", expected_revision=1))
    original = env.service.invoker
    state = SimpleNamespace(
        env=env,
        candidate=candidate,
        service=RecoveryService(env.service),
        plans={},
        receipts={},
        calls=[],
        plan_hook=None,
        receipt_hook=None,
        lose_reply=False,
        ambiguous_reply=False,
        force_rejected=False,
        status_rejected=False,
        recovery_id=RECOVERY,
    )

    def invoke(target, request, timeout=75):
        op = request["op"]
        if not op.startswith("recovery_"):
            return original(target, request, timeout)
        state.calls.append(copy.deepcopy(request))
        if op == "recovery_prepare":
            value = {
                "schema_version": 1,
                "status": "recovery_prepared",
                "host_id": HOST,
                "policy_digest": target.policy_digest,
                "driver_source_digest": SOURCE,
                "recovery_id": state.recovery_id,
                "job_id": env.job["job_id"],
                "job_revision": env.job["revision"],
                "job_digest": digest(env.job),
                "mode_revision": 2,
                "context_digest": request["context_digest"],
                "created_at": env.clock.isoformat(),
                "expires_at": (env.clock + timedelta(minutes=5)).isoformat(),
                "eligible": True,
                "checks": [
                    {"id": key, "status": "passed", "detail": "fixture"}
                    for key in sorted(REQUIRED_CHECKS)
                ],
                "blockers": [],
                "root_safety_before": copy.deepcopy(env.root_safety),
                "root_safety_digest": safety_digest(env.root_safety),
                "state_digest": "9" * 64,
                "verification": {},
                "transport_challenge": {"boot_id": "boot", "uptime_ticks": 50},
            }
            if state.plan_hook:
                state.plan_hook(value)
            value = seal_plan(value)
            state.plans[value["recovery_id"]] = value
            return copy.deepcopy(value)
        if op == "recovery_submit":
            plan = state.plans[request["recovery_id"]]
            checks = copy.deepcopy(plan["checks"]) + [
                {"id": key, "status": "passed", "detail": "fixture"}
                for key in (
                    "prepared_eligible",
                    "plan_valid",
                    "job_unchanged",
                    "state_unchanged",
                    "pause_unchanged",
                    "fresh_ssh",
                    "final_ledger_settled",
                    "policy_unchanged",
                )
            ]
            if state.force_rejected:
                checks[-1]["status"] = "failed"
            after = {
                "schema_version": 1,
                "paused": False,
                "reason": None,
                "job_id": None,
                "updated_at": env.clock.isoformat(),
            }
            value = {
                key: plan[key]
                for key in (
                    "schema_version",
                    "host_id",
                    "policy_digest",
                    "driver_source_digest",
                    "recovery_id",
                    "recovery_digest",
                    "job_id",
                    "job_revision",
                    "job_digest",
                    "mode_revision",
                    "context_digest",
                    "created_at",
                    "expires_at",
                )
            }
            value.update(
                status="rejected" if state.force_rejected else "verified",
                completed_at=env.clock.isoformat(),
                checks=checks,
                blockers=[c["id"] for c in checks if c["status"] != "passed"],
                verification={"fresh_ssh": {"passed": not state.force_rejected}},
                verified_job=None
                if state.force_rejected
                else {
                    "job_id": plan["job_id"],
                    "revision": plan["job_revision"],
                    "job_digest": plan["job_digest"],
                    "status": "verified",
                },
                resolved_safety_digest=plan["root_safety_digest"],
                safety_before=copy.deepcopy(plan["root_safety_before"]),
                safety_after=after,
                safety_after_digest=safety_digest(after),
            )
            if state.receipt_hook:
                state.receipt_hook(value)
            value = seal_receipt(value)
            state.receipts[value["recovery_id"]] = value
            if not state.force_rejected:
                env.root_safety = after
            if state.lose_reply:
                raise UnknownPatchResult("recovery_submit", None)
            if state.ambiguous_reply:
                return {"ok": False, "error": "unverified_result"}
            return copy.deepcopy(value)
        if state.status_rejected:
            return {"ok": False, "error": "rejected"}
        return copy.deepcopy(
            state.receipts.get(request["recovery_id"], state.plans[request["recovery_id"]])
        )

    env.service.invoker = invoke
    return state


def preview(recovery):
    return recovery.service.prepare(
        RecoveryPrepareRequest(
            host_id=HOST, job_id=recovery.env.job["job_id"], expected_mode_revision=2
        )
    )


def approve(recovery, plan):
    return recovery.service.submit(
        RecoverySubmitRequest(
            host_id=HOST,
            recovery_id=plan["recovery_id"],
            expected_recovery_digest=plan["recovery_digest"],
            expected_mode_revision=2,
            confirm_recover=True,
        )
    )


def test_preview_is_not_a_release_and_success_keeps_all_authority_and_quota(recovery):
    env = recovery.env
    old = copy.deepcopy(env.auto.latch(HOST))
    quota = env.auto.quotas(HOST, env.automation.policy.automatic.grant_id)
    plan = preview(recovery)
    assert plan["eligible"] and plan["status"] == "recovery_prepared"
    assert env.auto.latch(HOST) == old
    result = approve(recovery, plan)
    assert result["status"] == "verified" and result["local_released"] is True
    assert env.auto.latch(HOST) is None and env.auto.latched_hosts() == []
    assert (
        result["latch_before"] == old and result["receipt"]["verified_job"]["status"] == "verified"
    )
    assert env.automation.status()["mode"] == "manual" and env.automation.status()["revision"] == 2
    assert env.auto.quotas(HOST, env.automation.policy.automatic.grant_id) == quota
    assert len(env.auto.list_attempts()) == len(env.patches.list_jobs()) == 1
    with closing(sqlite3.connect(env.auto.path)) as c:
        assert c.execute("SELECT COUNT(*) FROM automatic_latches").fetchone()[0] == 1
        archived = c.execute("SELECT payload FROM automatic_latch_history").fetchone()[0]
        assert archived == canonical(old)


@pytest.mark.parametrize("lost", ["lose_reply", "ambiguous_reply"])
def test_lost_recovery_ack_only_queries_original_id_across_store_restart(recovery, lost):
    plan = preview(recovery)
    setattr(recovery, lost, True)
    result = approve(recovery, plan)
    assert result["status"] == "unknown" and recovery.env.auto.latch(HOST)
    recovery.env.service.automatic_store = AutomaticStore(recovery.env.auto.path)
    restarted = RecoveryService(recovery.env.service)
    result = restarted.status(HOST, RECOVERY)
    assert result["status"] == "verified" and result["local_released"]
    assert [r["op"] for r in recovery.calls].count("recovery_submit") == 1
    assert [r["op"] for r in recovery.calls][-1] == "recovery_status"
    assert approve(recovery, plan)["status"] == "verified"
    assert [r["op"] for r in recovery.calls].count("recovery_submit") == 1


def test_original_receipt_can_be_reconciled_after_a_later_manual_revision(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    assert approve(recovery, plan)["status"] == "unknown"
    recovery.env.service.change_mode(ModeChange(mode="automatic", expected_revision=2))
    assert recovery.service.status(HOST, RECOVERY)["status"] == "unknown"
    assert recovery.env.auto.latch(HOST)
    recovery.env.service.change_mode(ModeChange(mode="manual", expected_revision=3))
    result = recovery.service.status(HOST, RECOVERY)
    assert result["status"] == "verified" and result["local_released"]
    assert result["mode_revision"] == 2
    assert recovery.env.automation.status()["revision"] == 4
    assert len([r for r in recovery.calls if r["op"] == "recovery_submit"]) == 1


def test_unknown_root_id_does_not_become_a_rejection_or_allow_a_new_plan(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    approve(recovery, plan)
    recovery.status_rejected = True
    assert recovery.service.status(HOST, RECOVERY)["status"] == "unknown"
    with pytest.raises(HTTPException, match="已有恢复结果"):
        preview(recovery)
    assert len([r for r in recovery.calls if r["op"] == "recovery_submit"]) == 1
    assert recovery.env.auto.latch(HOST)


def test_rejected_receipt_keeps_pause_and_is_not_retried(recovery):
    plan = preview(recovery)
    recovery.force_rejected = True
    result = approve(recovery, plan)
    assert result["status"] == "rejected" and not result["local_released"]
    assert recovery.env.auto.latch(HOST)
    assert approve(recovery, plan)["status"] == "rejected"
    assert len([r for r in recovery.calls if r["op"] == "recovery_submit"]) == 1


def test_mode_change_and_expiry_cannot_authorize_recovery(recovery):
    plan = preview(recovery)
    recovery.env.clock += timedelta(minutes=6)
    with pytest.raises(HTTPException):
        approve(recovery, plan)
    assert recovery.env.auto.latch(HOST) and not recovery.receipts
    recovery.env.service.change_mode(ModeChange(mode="automatic", expected_revision=2))
    with pytest.raises(HTTPException, match="当前手动模式"):
        preview(recovery)


def test_another_job_cannot_be_used_to_release_the_original_pause(recovery):
    with pytest.raises(HTTPException, match="原任务"):
        recovery.service.prepare(
            RecoveryPrepareRequest(host_id=HOST, job_id="0" * 32, expected_mode_revision=2)
        )
    assert not recovery.calls


def test_ineligible_preview_is_persisted_and_cannot_be_approved(recovery):
    def broken(value):
        value["eligible"] = False
        value["checks"] = [{"id": "original_job_verified", "status": "failed", "detail": "fixture"}]
        value["blockers"] = ["original_job_verified"]
        value["state_digest"] = None

    recovery.plan_hook = broken
    plan = preview(recovery)
    assert (
        not plan["eligible"]
        and recovery.env.auto.get_recovery(HOST, RECOVERY)["status"] == "prepared"
    )
    with pytest.raises(ValueError, match="ineligible"):
        approve(recovery, plan)
    assert recovery.env.auto.latch(HOST) and not recovery.receipts


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_digest", "0" * 64),
        ("job_digest", "0" * 64),
        ("job_revision", 8),
        ("mode_revision", 3),
        ("driver_source_digest", "invalid"),
        ("eligible", "true"),
        ("blockers", ["missing"]),
    ],
)
def test_preview_binding_changes_fail_closed(recovery, field, value):
    recovery.plan_hook = lambda plan: plan.update({field: value})
    with pytest.raises(HTTPException):
        preview(recovery)
    assert not recovery.env.auto.list_recoveries() and recovery.env.auto.latch(HOST)


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_digest", "0" * 64),
        ("job_digest", "0" * 64),
        ("job_revision", 8),
        ("driver_source_digest", "0" * 64),
        ("resolved_safety_digest", "0" * 64),
        ("verified_job", None),
        ("verification", {}),
    ],
)
def test_invalid_verified_receipt_never_releases_pause(recovery, field, value):
    plan = preview(recovery)
    recovery.receipt_hook = lambda receipt: receipt.update({field: value})
    result = approve(recovery, plan)
    assert result["status"] == "unknown" and not result["local_released"]
    assert recovery.env.auto.latch(HOST)


def test_changed_local_pause_cannot_be_released_by_an_old_approval(recovery):
    plan = preview(recovery)
    with recovery.env.auto._connection() as c:
        latch = recovery.env.auto.latch(HOST)
        latch["detail"] = "new evidence"
        c.execute(
            "UPDATE automatic_latches SET payload=? WHERE host_id=?", (canonical(latch), HOST)
        )
    with pytest.raises(ValueError, match="pause has changed"):
        approve(recovery, plan)
    assert not recovery.receipts


def test_root_only_late_snapshot_does_not_resurrect_resolved_cause_but_new_cause_does(recovery):
    env = recovery.env
    env.root_safety = {
        "schema_version": 1,
        "paused": True,
        "reason": "automatic_job_unknown",
        "job_id": env.job["job_id"],
        "updated_at": env.clock.isoformat(),
    }
    env.service.refresh_automatic_status(HOST)
    stale = env.auto.remote_state(HOST)["remote"]
    plan = preview(recovery)
    approve(recovery, plan)
    assert env.auto.latch(HOST) is None
    wrapped = {
        "schema_version": 1,
        "host_id": HOST,
        "policy_digest": ROOT_POLICY,
        "status": "automatic_status",
        **stale,
    }
    env.auto.record_remote_safety(
        HOST,
        env.service._automatic_scope(env.service.targets[HOST]),
        ROOT_POLICY,
        wrapped,
        now=env.clock,
    )
    assert env.auto.latch(HOST) is None
    wrapped["safety"]["updated_at"] = (env.clock + timedelta(seconds=1)).isoformat()
    env.auto.record_remote_safety(
        HOST,
        env.service._automatic_scope(env.service.targets[HOST]),
        ROOT_POLICY,
        wrapped,
        now=env.clock,
    )
    assert env.auto.latch(HOST) and env.auto.latch(HOST)["source"] == "remote_root"


def test_verified_receipt_outside_approval_ttl_is_never_accepted(recovery):
    plan = preview(recovery)

    def late(receipt):
        recovery.env.clock += timedelta(minutes=5, seconds=1)
        receipt["completed_at"] = recovery.env.clock.isoformat()

    recovery.receipt_hook = late
    result = approve(recovery, plan)
    assert result["status"] == "unknown" and not result["local_released"]
    assert recovery.env.auto.latch(HOST)


def test_changed_pause_supersedes_known_root_receipt_and_allows_fresh_preview(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    approve(recovery, plan)
    current = recovery.env.auto.latch(HOST)
    current["detail"] = "new cause evidence"
    with recovery.env.auto._connection() as c:
        c.execute(
            "UPDATE automatic_latches SET payload=? WHERE host_id=?", (canonical(current), HOST)
        )
    result = recovery.service.status(HOST, RECOVERY)
    assert result["status"] == "superseded" and not result["local_released"]
    assert result["receipt"]["status"] == "verified" and result["root_outcome"] == "verified"
    assert (
        recovery.env.auto.latch(HOST) == current
        and recovery.env.auto.pending_recovery(HOST) is None
    )
    recovery.recovery_id = "6" * 32
    assert preview(recovery)["recovery_id"] == "6" * 32
    assert len([r for r in recovery.calls if r["op"] == "recovery_submit"]) == 1


def test_changed_target_supersedes_old_unknown_without_claiming_root_rejected(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    approve(recovery, plan)
    recovery.env.service.targets[HOST] = target(policy="f" * 64)
    result = recovery.service.status(HOST, RECOVERY)
    assert result["status"] == "superseded" and result["root_outcome"] == "unknown"
    assert result["receipt"] is None and not result["local_released"]
    assert recovery.env.auto.latch(HOST) and recovery.env.auto.pending_recovery(HOST) is None
    assert not [r for r in recovery.calls if r["op"] == "recovery_status"]


def test_new_root_pause_survives_completion_of_an_old_root_recovery(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    approve(recovery, plan)
    recovery.env.root_safety = {
        "schema_version": 1,
        "paused": True,
        "reason": "automatic_job_failed",
        "job_id": "0" * 32,
        "updated_at": (recovery.env.clock + timedelta(seconds=1)).isoformat(),
    }
    result = recovery.service.status(HOST, RECOVERY)
    assert result["status"] == "superseded" and not result["local_released"]
    current = recovery.env.auto.latch(HOST)
    assert current["job_id"] == "0" * 32 and current["reason"] == "automatic_job_failed"
    assert result["latch_before"]["job_id"] != current["job_id"]
    assert recovery.env.auto.pending_recovery(HOST) is None


def test_new_bad_event_has_a_new_pause_identity_even_with_the_same_clock(recovery):
    plan = preview(recovery)
    original = recovery.env.auto.latch(HOST)
    approve(recovery, plan)
    recovery.env.auto.mark_unknown(recovery.candidate["id"], now=recovery.env.clock)
    current = recovery.env.auto.latch(HOST)
    assert current["generation"] != original["generation"] and digest(current) != digest(original)
    assert recovery.env.auto.get_recovery(HOST, RECOVERY)["local_released"]


def test_store_requires_a_post_receipt_fresh_safety_snapshot(recovery):
    plan = preview(recovery)
    recovery.lose_reply = True
    approve(recovery, plan)
    recovery.env.service.refresh_automatic_status(HOST)
    remote = recovery.env.auto.remote_state(HOST)
    remote["checked_at"] = (recovery.env.clock - timedelta(seconds=61)).isoformat()
    with pytest.raises(ValueError, match="fresh post-receipt"):
        recovery.env.auto.complete_recovery(
            HOST, RECOVERY, recovery.receipts[RECOVERY], remote, now=recovery.env.clock
        )
    assert recovery.env.auto.latch(HOST)


def test_eligible_plan_without_required_native_check_is_rejected(recovery):
    recovery.plan_hook = lambda value: value.update(
        checks=[c for c in value["checks"] if c["id"] != "runtime_complete"]
    )
    with pytest.raises(HTTPException):
        preview(recovery)
    assert recovery.env.auto.latch(HOST)


def test_historical_job_is_archived_before_root_binds_its_recovery_hash(recovery):
    env = recovery.env
    original = env.service.invoker
    order = []
    original_target = env.service.target(HOST)
    old_scope = scope_for_automatic(original_target)
    new_policy = "0" * 64
    env.service.targets = {HOST: target(policy=new_policy)}
    assert env.auto.latch(HOST)["scope_hash"] == old_scope

    def archived(target, request, timeout=75):
        order.append(request["op"])
        if request["op"] == "status" and env.job["policy_digest"] != target.policy_digest:
            env.job["execution_policy_digest"] = env.job["policy_digest"]
            env.job["policy_digest"] = target.policy_digest
            env.job["revision"] += 1
        return original(target, request, timeout)

    env.service.invoker = archived
    plan = preview(recovery)
    assert order[:3] == ["status", "recovery_prepare", "status"]
    assert plan["job_revision"] == 8 and plan["job_digest"] == digest(env.job)
    assert (
        env.job["execution_policy_digest"] == ROOT_POLICY and env.job["policy_digest"] == new_policy
    )
    stored = env.auto.get_recovery(HOST, RECOVERY)
    assert stored["latch_before"]["scope_hash"] == old_scope
    assert stored["scope_hash"] != stored["latch_before"]["scope_hash"]


def test_migration_preserves_old_pause_payload_and_makes_it_active(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "old.db"
    value = {"host_id": HOST, "job_id": "0" * 32, "reason": "unknown", "scope_hash": "a" * 64}
    with closing(sqlite3.connect(path)) as c, c:
        c.execute("CREATE TABLE automatic_latches(host_id TEXT PRIMARY KEY,payload TEXT NOT NULL)")
        c.execute("INSERT INTO automatic_latches VALUES(?,?)", (HOST, canonical(value)))
    path.chmod(0o600)
    migrated = AutomaticStore(path)
    assert migrated.latch(HOST) == value and migrated.latched_hosts() == [value]
    with closing(sqlite3.connect(path)) as c:
        assert c.execute("SELECT payload,active FROM automatic_latches").fetchone() == (
            canonical(value),
            1,
        )


def test_pending_original_recovery_ids_cannot_be_hidden_by_newer_previews(tmp_path):
    tmp_path.chmod(0o700)
    store = AutomaticStore(tmp_path / "automatic.db")
    with store._connection() as connection:
        for index in range(107):
            status = "unknown" if index == 0 else "submission_intent" if index == 1 else "prepared"
            stamp = (
                "2026-10-28T11:00:00+00:00"
                if index == 0
                else "2026-10-28T10:00:00+00:00"
                if index == 1
                else f"2026-10-29T12:00:{index % 60:02d}+00:00"
            )
            store._write_recovery(
                connection,
                {
                    "host_id": HOST,
                    "recovery_id": f"{index:032x}",
                    "status": status,
                    "created_at": stamp,
                    "updated_at": stamp,
                },
            )
    limited = store.list_recoveries(limit=2)
    assert [item["status"] for item in limited] == ["unknown", "submission_intent"]
    assert [item["recovery_id"] for item in limited] == ["0" * 32, "0" * 31 + "1"]
    assert store.list_recoveries()[:2] == limited


def test_recovery_routes_are_protected_and_require_exact_human_confirmation(recovery, tmp_path):
    app = create_app(Settings(token=TOKEN, data_dir=tmp_path / "app"))
    app.state.recovery_service.service = recovery.env.service
    client = TestClient(app)
    assert client.get("/api/automatic/recoveries").status_code == 401
    assert client.get("/api/capabilities", headers=AUTH).json()["automatic_recovery"] is True
    body = {"host_id": HOST, "job_id": recovery.env.job["job_id"], "expected_mode_revision": 2}
    assert client.post("/api/automatic/recovery-plans", json=body).status_code == 401
    assert (
        client.post(
            "/api/automatic/recovery-plans",
            json=body,
            headers=AUTH | {"Origin": "https://other.invalid"},
        ).status_code
        == 403
    )
    plan = client.post("/api/automatic/recovery-plans", json=body, headers=AUTH).json()
    approval = {
        "host_id": HOST,
        "recovery_id": RECOVERY,
        "expected_recovery_digest": plan["recovery_digest"],
        "expected_mode_revision": 2,
    }
    for bad in (False, "true", 1):
        assert (
            client.post(
                "/api/automatic/recoveries", json=approval | {"confirm_recover": bad}, headers=AUTH
            ).status_code
            == 422
        )
    result = client.post(
        "/api/automatic/recoveries", json=approval | {"confirm_recover": True}, headers=AUTH
    )
    assert result.status_code == 200 and result.json()["local_released"] is True
    assert len(client.get("/api/automatic/recoveries", headers=AUTH).json()) == 1
    assert (
        client.get(f"/api/automatic/recoveries/{HOST}/{RECOVERY}", headers=AUTH).json()["status"]
        == "verified"
    )
