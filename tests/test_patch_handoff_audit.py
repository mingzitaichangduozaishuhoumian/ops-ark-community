"""Controller-owned handoff evidence stays separate from native patch receipts."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from test_automatic_service import env as env
from test_automatic_service import ops, reserved, submit

from opsark import patch_store
from opsark.automation_store import AutomationStore, ModeChange
from opsark.baselines import scope_for
from opsark.config import HostConfig
from opsark.control_modes import ControlPolicy
from opsark.models import HostPublic
from opsark.patch_api import PatchService, SubmitRequest, targets_scope
from opsark.patch_client import PatchTarget, UnknownPatchResult
from opsark.patch_store import PatchStore

HOST = "host-a"
JOB = "e" * 32
PLAN = "c" * 32
POLICY = "a" * 64
PLAN_DIGEST = "d" * 64
SCOPE = "7" * 64
MODE_REVISION = 1
AUDIT_BINDING = {"host_scope": SCOPE, "policy_digest": POLICY, "authorization": "assisted"}
CURRENT_BINDING = {"current_host_scope": SCOPE, "current_policy_digest": POLICY}


def register(store, job_id=JOB):
    return store.register_submission(
        HOST, job_id, PLAN, PLAN_DIGEST, MODE_REVISION, **AUDIT_BINDING
    )


def native(**updates):
    return {
        "schema_version": 1,
        "host_id": HOST,
        "job_id": JOB,
        "policy_digest": POLICY,
        "execution_policy_digest": POLICY,
        "plan_id": PLAN,
        "plan_digest": PLAN_DIGEST,
        "mode_revision": MODE_REVISION,
        "authorization": "assisted",
        "status": "queued",
        "revision": 1,
        **updates,
    }


def test_approval_and_unknown_survive_reopen_without_rewriting_native_payload(tmp_path):
    path = tmp_path / "patches.sqlite3"
    store = PatchStore(path)
    assert register(store)
    approval = store.get_handoff_audit(HOST, JOB)
    assert approval == {
        "host_id": HOST,
        "job_id": JOB,
        **AUDIT_BINDING,
        "plan_id": PLAN,
        "plan_digest": PLAN_DIGEST,
        "mode_revision": MODE_REVISION,
        "approved_at": store.get_job(HOST, JOB)["received_at"],
        "unknown_at": None,
        "reconciled_at": None,
        "reconciled_revision": None,
    }
    assert not register(store)
    assert store.get_handoff_audit(HOST, JOB) == approval
    store.mark_unknown(HOST, JOB, PLAN)
    store = PatchStore(path)
    unknown = store.get_handoff_audit(HOST, JOB)
    assert unknown["approved_at"] <= unknown["unknown_at"]
    store.mark_unknown(HOST, JOB, PLAN)
    assert store.get_handoff_audit(HOST, JOB) == unknown

    # The same well-formed bytes are sufficient only on the original status path.
    payload = native(revision=2)
    store.save_job(HOST, payload)
    assert store.get_handoff_audit(HOST, JOB) == unknown
    store.save_job(HOST, payload, from_status=True, **CURRENT_BINDING)
    reconciled = store.get_handoff_audit(HOST, JOB)
    assert reconciled["unknown_at"] <= reconciled["reconciled_at"]
    assert reconciled["reconciled_revision"] == 2
    with store._connection() as connection:
        saved = connection.execute("SELECT payload FROM patch_jobs").fetchone()["payload"]
    assert json.loads(saved) == payload
    store.save_job(HOST, native(revision=3), from_status=True, **CURRENT_BINDING)
    assert store.get_handoff_audit(HOST, JOB) == reconciled


def test_new_unknown_requires_new_status_lookup(tmp_path):
    store = PatchStore(tmp_path / "patches.sqlite3")
    assert register(store)
    store.mark_unknown(HOST, JOB, PLAN)
    store.save_job(HOST, native(revision=2), from_status=True, **CURRENT_BINDING)
    prior = store.get_handoff_audit(HOST, JOB)
    assert prior["reconciled_revision"] == 2

    store.mark_unknown(HOST, JOB, PLAN)
    pending = store.get_handoff_audit(HOST, JOB)
    assert pending["unknown_at"] >= prior["reconciled_at"]
    assert pending["reconciled_at"] is None
    assert pending["reconciled_revision"] is None
    store.save_job(HOST, native(revision=3))
    assert store.get_handoff_audit(HOST, JOB) == pending
    store.save_job(HOST, native(revision=3), from_status=True, **CURRENT_BINDING)
    assert store.get_handoff_audit(HOST, JOB)["reconciled_revision"] == 3


@pytest.mark.parametrize(
    "changes,binding",
    [
        ({"schema_version": True}, CURRENT_BINDING),
        ({"schema_version": 2}, CURRENT_BINDING),
        ({"host_id": None}, CURRENT_BINDING),
        ({"plan_id": "b" * 32}, CURRENT_BINDING),
        ({"plan_digest": "f" * 64}, CURRENT_BINDING),
        ({"mode_revision": True}, CURRENT_BINDING),
        ({"mode_revision": 2}, CURRENT_BINDING),
        ({"authorization": "automatic"}, CURRENT_BINDING),
        ({"policy_digest": "b" * 64}, CURRENT_BINDING),
        ({"execution_policy_digest": "b" * 64}, CURRENT_BINDING),
        ({"revision": None}, CURRENT_BINDING),
        ({"revision": 0}, CURRENT_BINDING),
        ({"status": "unknown"}, CURRENT_BINDING),
        ({"transport_unknown": True}, CURRENT_BINDING),
        ({"remote_job_created": False}, CURRENT_BINDING),
        ({"source": "remote_rpc_rejection"}, CURRENT_BINDING),
        ({"error": "synthetic rejection"}, CURRENT_BINDING),
        ({"received_at": "controller-only metadata"}, CURRENT_BINDING),
        ({}, CURRENT_BINDING | {"current_host_scope": "8" * 64}),
        ({}, CURRENT_BINDING | {"current_policy_digest": "b" * 64}),
    ],
)
def test_wrong_receipt_cannot_resolve_handoff(tmp_path, changes, binding):
    store = PatchStore(tmp_path / "patches.sqlite3")
    assert register(store)
    store.mark_unknown(HOST, JOB, PLAN)
    payload = native(**changes)
    if changes.get("host_id", HOST) is None:
        payload.pop("host_id")
    store.save_job(HOST, payload, from_status=True, **binding)
    audit = store.get_handoff_audit(HOST, JOB)
    assert audit["unknown_at"] is not None
    assert audit["reconciled_at"] is None and audit["reconciled_revision"] is None


def test_older_revision_does_not_resolve_and_unobserved_intent_is_not_a_loss(tmp_path):
    store = PatchStore(tmp_path / "patches.sqlite3")
    assert register(store)
    store.save_job(HOST, native(revision=7), from_status=True, **CURRENT_BINDING)
    assert store.get_handoff_audit(HOST, JOB)["unknown_at"] is None
    assert store.get_handoff_audit(HOST, JOB)["reconciled_at"] is None
    store.mark_unknown(HOST, JOB, PLAN)
    old = store.save_job(HOST, native(revision=6), from_status=True, **CURRENT_BINDING)
    assert old["status"] == "unknown"
    assert store.get_handoff_audit(HOST, JOB)["reconciled_at"] is None
    store.save_job(HOST, native(revision=7), from_status=True, **CURRENT_BINDING)
    assert store.get_handoff_audit(HOST, JOB)["reconciled_revision"] == 7


def test_legacy_identity_remains_without_approval_audit(tmp_path):
    store = PatchStore(tmp_path / "patches.sqlite3")
    assert store.register_submission(HOST, JOB, PLAN, PLAN_DIGEST, MODE_REVISION)
    assert not register(store)
    store.mark_unknown(HOST, JOB, PLAN)
    store.save_job(HOST, native(), from_status=True, **CURRENT_BINDING)
    assert store.get_handoff_audit(HOST, JOB) is None


def test_audit_and_submit_intent_are_one_transaction(tmp_path):
    store = PatchStore(tmp_path / "patches.sqlite3")
    with store._connection() as connection:
        connection.execute(
            "CREATE TRIGGER test_fail BEFORE INSERT ON patch_handoff_audit "
            "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="blocked"):
        register(store)
    assert store.get_job(HOST, JOB) is None
    assert store.get_handoff_audit(HOST, JOB) is None


def test_job_retention_removes_the_sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_store, "MAX_JOBS", 1)
    store = PatchStore(tmp_path / "patches.sqlite3")
    assert register(store)
    store.save_job(HOST, native(status="verified"))
    other = "2" * 32
    assert register(store, other)
    store.mark_unknown(HOST, other, PLAN)
    assert store.get_job(HOST, JOB) is None
    assert store.get_handoff_audit(HOST, JOB) is None
    assert store.get_handoff_audit(HOST, other)["unknown_at"] is not None


def test_assisted_entry_records_approval_before_lost_submit_then_queries_original(tmp_path):
    host = HostConfig(
        HostPublic(id=HOST, name="fixture", address="192.0.2.30", source="ssh"),
        tmp_path / "readonly",
        tmp_path / "known-hosts",
    )
    targets = {HOST: PatchTarget(host, tmp_path / "repair", POLICY)}
    policy = ControlPolicy(
        enabled=True,
        host_ids=(HOST,),
        allowed_actions=("os_security_upgrade",),
        allowed_packages=("demo",),
    )
    store = PatchStore(tmp_path / "patches.sqlite3")
    automation = AutomationStore(
        tmp_path / "mode.sqlite3", policy, driver_scope=targets_scope(targets)
    )
    service = PatchService(targets, store, automation)
    calls = []

    def invoke(_target, request, timeout=75):
        calls.append(request)
        if request["op"] == "set_mode":
            return {"mode": request["mode"], "revision": request["revision"]}
        if request["op"] == "submit":
            audit = store.get_handoff_audit(HOST, JOB)
            assert audit["approved_at"] is not None and audit["unknown_at"] is None
            raise UnknownPatchResult("submit", JOB)
        assert request["op"] == "status" and request["job_id"] == JOB
        return native(revision=2, status="applying")

    service.invoker = invoke
    service.change_mode(ModeChange(mode="assisted", expected_revision=0))
    store.save_plan(
        HOST,
        {
            "schema_version": 1,
            "host_id": HOST,
            "policy_digest": POLICY,
            "mode_revision": MODE_REVISION,
            "plan_id": PLAN,
            "plan_digest": PLAN_DIGEST,
            "action": "os_security_upgrade",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
            "package_changes": [{"name": "demo"}],
            "requires_service_restart": False,
            "requires_reboot": False,
            "restart_assessment": "none",
        },
    )
    submitted = service.submit(
        SubmitRequest(
            host_id=HOST,
            job_id=JOB,
            plan_id=PLAN,
            expected_plan_digest=PLAN_DIGEST,
            expected_mode_revision=MODE_REVISION,
            confirm_execute=True,
        )
    )
    assert submitted.status_code == 202
    assert json.loads(submitted.body)["status"] == "unknown"
    audit = store.get_handoff_audit(HOST, JOB)
    assert audit["host_scope"] == scope_for(host.public)
    assert audit["authorization"] == "assisted" and audit["unknown_at"] is not None
    assert audit["reconciled_at"] is None

    assert service.job_status(HOST, JOB)["status"] == "applying"
    final = store.get_handoff_audit(HOST, JOB)
    assert final["reconciled_revision"] == 2
    assert [call["job_id"] for call in calls if call["op"] == "submit"] == [JOB]
    assert [call["job_id"] for call in calls if call["op"] == "status"] == [JOB]


def test_automatic_route_tracks_its_existing_grant_without_changing_budget(env):
    candidate = reserved(env)
    quotas = env.auto.quotas(candidate["host_id"], candidate["grant_id"], now=env.clock)
    assert quotas["total_used"] == 1
    env.unknown = True
    result = submit(env, candidate)
    assert result["status"] == "unknown"
    host_id, job_id = result["host_id"], result["job_id"]
    target = env.service.targets[host_id]
    audit = env.patches.get_handoff_audit(host_id, job_id)
    assert audit["authorization"] == "automatic"
    assert audit["host_scope"] == scope_for(target.host.public)
    assert audit["policy_digest"] == target.policy_digest
    assert audit["unknown_at"] is not None and audit["reconciled_at"] is None
    env.job.update(status="applying", revision=2)
    assert env.service.job_status(host_id, job_id)["status"] == "applying"
    assert env.patches.get_handoff_audit(host_id, job_id)["reconciled_revision"] == 2
    assert len(ops(env, "submit")) == 1
    assert env.auto.quotas(host_id, candidate["grant_id"], now=env.clock) == quotas
