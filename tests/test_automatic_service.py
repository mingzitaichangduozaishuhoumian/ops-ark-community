import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from test_automatic_monitor import HOST, ROOT_POLICY, finding, plan, policy, scan, target
from test_patch_agent import remote as remote
from test_root_automatic import root_auto as root_auto

from opsark.automatic_monitor import AutomaticMonitor, scope_for_automatic
from opsark.automatic_store import AutomaticStore
from opsark.automation_store import AutomationStore, ModeChange
from opsark.baselines import scope_for
from opsark.control_modes import AutomaticGrant, ControlPolicy
from opsark.patch_api import ModeSynchronizationError, PatchService, PrepareRequest, targets_scope
from opsark.patch_client import PatchClientError, UnknownPatchResult
from opsark.patch_store import PatchStore


def seal(value):
    content = {
        key: item for key, item in value.items() if key not in {"plan_digest", "received_at"}
    }
    value["plan_digest"] = hashlib.sha256(
        json.dumps(
            content,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    return value


@pytest.fixture
def env(tmp_path):
    at = datetime.now(UTC)
    local = policy(max_jobs_per_day=1, max_total_jobs=1).model_dump(mode="json")
    local["automatic"].pop("grant_digest")
    local["automatic"].update(
        issued_at=(at - timedelta(minutes=1)).isoformat(),
        expires_at=(at + timedelta(hours=1)).isoformat(),
    )
    configured = ControlPolicy.model_validate(local)
    targets = {HOST: target()}
    patches = PatchStore(tmp_path / "patch.db")
    auto = AutomaticStore(tmp_path / "auto.db")
    automation = AutomationStore(
        tmp_path / "mode.db", configured, driver_scope=targets_scope(targets)
    )
    service = PatchService(targets, patches, automation)
    service.automatic_store = auto
    state = SimpleNamespace(
        service=service,
        patches=patches,
        auto=auto,
        automation=automation,
        clock=at,
        calls=[],
        modes={},
        job=None,
        prepare_hook=None,
        submit_hook=None,
        failed_hosts=set(),
        unknown=False,
        root_safety={
            "schema_version": 1,
            "paused": False,
            "reason": None,
            "job_id": None,
            "updated_at": at.isoformat(),
        },
        root_usage={"daily_used": 0, "total_used": 0},
        root_status_hook=None,
    )
    service.now = lambda: state.clock
    patches.save_scan(HOST, scan(at))

    def invoke(remote_target, request, timeout=75):
        host = remote_target.host.public.id
        state.calls.append((host, copy.deepcopy(request)))
        if host in state.failed_hosts:
            raise PatchClientError("synthetic unreachable server")
        if request["op"] == "set_mode":
            state.modes[host] = (request["mode"], request["revision"])
            return {"mode": request["mode"], "revision": request["revision"]}
        if request["op"] == "prepare":
            mode, revision = state.modes[host]
            assert mode == "automatic" and revision == request["mode_revision"]
            value = plan(state.clock, revision)
            value["restart_assessment"] = "possible"
            value["automatic_grant_digest"] = service._root_grant_digest(configured.automatic)
            if state.prepare_hook:
                value = state.prepare_hook(value)
            return seal(value)
        if request["op"] == "automatic_status":
            value = {
                "schema_version": 1,
                "host_id": host,
                "policy_digest": ROOT_POLICY,
                "status": "automatic_status",
                "enabled": True,
                "maintenance_open": True,
                "grant": configured.automatic.model_dump(
                    mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
                ),
                "grant_digest": service._root_grant_digest(configured.automatic),
                "safety": copy.deepcopy(state.root_safety),
                "usage": dict(state.root_usage),
            }
            return state.root_status_hook(value) if state.root_status_hook else value
        if request["op"] == "submit":
            assert set(request) == {
                "schema_version",
                "op",
                "policy_digest",
                "job_id",
                "plan_id",
                "plan_digest",
                "mode_revision",
            }
            state.job = {
                "schema_version": 1,
                "host_id": host,
                "policy_digest": ROOT_POLICY,
                "job_id": request["job_id"],
                "plan_id": request["plan_id"],
                "plan_digest": request["plan_digest"],
                "mode_revision": request["mode_revision"],
                "authorization": "automatic",
                "automatic_grant_id": configured.automatic.grant_id,
                "automatic_grant_digest": service._root_grant_digest(configured.automatic),
                "status": "queued",
                "revision": 1,
            }
            if state.unknown:
                raise UnknownPatchResult("submit", request["job_id"])
            if state.submit_hook:
                return state.submit_hook(copy.deepcopy(state.job))
            return copy.deepcopy(state.job)
        if request["op"] == "status":
            if state.job is None:
                return {"ok": False, "error": "not found"}
            assert request["job_id"] == state.job["job_id"]
            return copy.deepcopy(state.job)
        raise AssertionError("Unexpected operation")

    service.invoker = invoke
    service.change_mode(ModeChange(mode="automatic", expected_revision=0))
    service.refresh_automatic_status(HOST)
    return state


def ops(env, op):
    return [request for _host, request in env.calls if request["op"] == op]


def prepare(env):
    return env.service.auto_prepare(
        HOST,
        finding()["finding_id"],
        env.automation.status()["revision"],
        env.automation.policy.automatic.grant_digest,
    )


def reserved(env):
    concrete_plan = prepare(env)
    grant = env.automation.policy.automatic
    value = env.auto.claim_candidate(
        host_id=HOST,
        scope_hash=scope_for_automatic(env.service.targets[HOST]),
        finding_id=finding()["finding_id"],
        package="libbrotli1",
        current_version="1.1.0-2build2",
        candidate_version="1.1.0-2ubuntu0.1",
        grant_id=grant.grant_id,
        grant_digest=grant.grant_digest,
        scan_id="d" * 32,
        owner="5" * 32,
        now=env.clock,
    )
    return env.auto.reserve_submission(
        value["id"],
        concrete_plan,
        env.automation.status()["revision"],
        daily_limit=1,
        total_limit=1,
        now=env.clock,
    )


def submit(env, value):
    return env.service.auto_submit(
        HOST,
        value["plan_id"],
        value["plan_digest"],
        value["mode_revision"],
        value["grant_digest"],
        value["job_id"],
    )


def test_real_service_monitor_closes_one_job_and_excludes_its_own_reserved_quota(env):
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    assert len(ops(env, "prepare")) == len(ops(env, "submit")) == 1
    attempt = env.auto.list_attempts()[0]
    assert attempt["status"] == "queued" and env.auto.latch(HOST) is None
    assert env.auto.quotas(HOST, "f" * 32, now=env.clock)["total_used"] == 1
    monitor.poll_once()
    assert len(ops(env, "submit")) == 1


def test_remote_full_digest_and_domain_projection_are_separate(env):
    result = prepare(env)
    assert result["plan_digest"] == seal(copy.deepcopy(result))["plan_digest"]
    assert result["automatic_grant_digest"] != env.automation.policy.automatic.grant_digest
    value = reserved(env)
    assert submit(env, value)["status"] == "queued"


def test_exact_utc_z_root_grant_projection_is_required(env):
    def different_timestamp_digest(value):
        grant = env.automation.policy.automatic.model_dump(
            mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
        )
        grant["issued_at"] = grant["issued_at"].replace("Z", "+00:00")
        value["automatic_grant_digest"] = hashlib.sha256(
            json.dumps(grant, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return value

    env.prepare_hook = different_timestamp_digest
    with pytest.raises(HTTPException):
        prepare(env)
    assert ops(env, "submit") == []


def test_full_root_digest_is_checked_before_a_plan_can_be_persisted(env):
    original = env.service.invoker

    def tampered(target, request, timeout=75):
        result = original(target, request, timeout)
        if request["op"] == "prepare":
            result["risk_level"] = "low"
        return result

    env.service.invoker = tampered
    with pytest.raises(HTTPException):
        prepare(env)
    assert env.patches.get_plan(HOST, "1" * 32) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("evidence_complete", False),
        ("transaction_complete_verified", False),
        ("restart_impact_verified", False),
        ("requires_reboot", True),
        ("requires_service_restart", None),
        ("risk_level", "low"),
        ("prepared_mode", "assisted"),
        ("automatic_grant_id", "6" * 32),
        ("state_digest", "6" * 64),
        ("health_before", {"passed": False}),
    ],
)
def test_valid_full_digest_cannot_replace_independent_policy_checks(env, field, value):
    env.prepare_hook = lambda concrete: concrete | {field: value}
    with pytest.raises(HTTPException):
        prepare(env)
    assert ops(env, "submit") == []


@pytest.mark.parametrize(
    "field",
    [
        "vendor_security_origin_verified",
        "candidate_contains_fixed_verified",
        "candidate_is_upgrade_verified",
        "current_is_affected_verified",
    ],
)
def test_package_proof_cannot_be_omitted_even_in_a_valid_root_full_digest(env, field):
    def missing(value):
        value["package_changes"][0].pop(field)
        return value

    env.prepare_hook = missing
    with pytest.raises(HTTPException):
        prepare(env)


@pytest.mark.parametrize("change", ["mode", "expiry", "grant", "target", "scan", "latch"])
def test_submission_rechecks_current_authority_after_plan_and_intent(env, change):
    value = reserved(env)
    if change == "mode":
        env.service.change_mode(ModeChange(mode="manual", expected_revision=value["mode_revision"]))
    elif change == "expiry":
        env.clock += timedelta(hours=2)
    elif change == "grant":
        data = env.automation.policy.model_dump()
        data["automatic"]["grant_digest"] = ""
        data["automatic"]["grant_id"] = "6" * 32
        env.automation.policy = ControlPolicy.model_validate(data)
    elif change == "target":
        env.service.targets[HOST] = target(address="192.0.2.11")
    elif change == "scan":
        env.patches.save_scan(HOST, scan(env.clock, scan_id="6" * 32))
    else:
        env.auto.mark_unknown(value["id"], now=env.clock)
    with pytest.raises(HTTPException):
        submit(env, value)
    assert ops(env, "submit") == []


def test_no_durable_intent_cannot_submit_a_prepared_plan(env):
    result = prepare(env)
    with pytest.raises(HTTPException):
        env.service.auto_submit(
            HOST,
            result["plan_id"],
            result["plan_digest"],
            result["mode_revision"],
            env.automation.policy.automatic.grant_digest,
            "6" * 32,
        )
    assert ops(env, "submit") == []


def test_unknown_submission_latches_immediately_then_only_reads_original_id(env):
    value = reserved(env)
    env.unknown = True
    first = submit(env, value)
    assert first["status"] == "unknown" and env.auto.latch(HOST) is not None
    second = submit(env, value)
    assert second["job_id"] == value["job_id"] and second["status"] == "queued"
    assert len(ops(env, "submit")) == len(ops(env, "status")) == 1
    assert env.auto.latch(HOST) is not None


def test_restart_with_patch_intent_before_transport_can_only_read_never_send(env):
    value = reserved(env)
    env.patches.register_submission(
        HOST,
        value["job_id"],
        value["plan_id"],
        value["plan_digest"],
        value["mode_revision"],
        host_scope=scope_for(env.service.targets[HOST].host.public),
        policy_digest=ROOT_POLICY,
        authorization="automatic",
    )
    result = submit(env, value)
    assert result["status"] == "unknown"
    assert "notification_count" not in result
    assert env.patches.get_handoff_audit(HOST, value["job_id"])["unknown_at"] is None
    assert ops(env, "submit") == [] and len(ops(env, "status")) == 1
    assert env.auto.get(value["id"])["state"] == "submission_intent"
    assert env.auto.latch(HOST) is None
    AutomaticMonitor(env.service, env.auto, now=lambda: env.clock).poll_once()
    assert env.auto.latch(HOST)["job_id"] == value["job_id"]
    assert ops(env, "submit") == []


@pytest.mark.parametrize("acknowledgment", ["normal", "lost", "malformed", "rejected"])
def test_early_status_read_preserves_live_submit_and_newer_job_receipt(env, acknowledgment):
    entered, release = Event(), Event()
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)

    def hold_original(ack):
        entered.set()
        assert release.wait(10)
        if acknowledgment == "lost":
            raise UnknownPatchResult("submit", ack["job_id"])
        if acknowledgment == "malformed":
            return ack | {"schema_version": True}
        if acknowledgment == "rejected":
            return {"ok": False, "error": "rejected"}
        return ack

    env.submit_hook = hold_original
    thread = Thread(target=monitor.poll_once, daemon=True)
    thread.start()
    try:
        assert entered.wait(10)
        job_id = env.job["job_id"]
        attempt = env.auto.get_by_job(HOST, job_id)
        assert attempt["state"] == "submission_intent"
        assert not env.auto.claim_monitor("6" * 32, now=env.clock)
        env.job = env.job | {"status": "verified", "revision": 2}
        assert env.service.job_status(HOST, job_id)["status"] == "verified"
        assert env.patches.get_job(HOST, job_id)["notification_count"] == 1
        assert env.auto.get(attempt["id"]) == attempt
        assert env.auto.latch(HOST) is None
        assert env.patches.get_handoff_audit(HOST, job_id)["unknown_at"] is None
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    final = env.auto.get(attempt["id"])
    assert (final["status"], final["remote_revision"]) == ("verified", 2)
    assert env.auto.latch(HOST) is None
    audit = env.patches.get_handoff_audit(HOST, job_id)
    if acknowledgment in {"normal", "rejected"}:
        assert audit["unknown_at"] is None
        assert audit["reconciled_at"] is None
    else:
        assert audit["approved_at"] <= audit["unknown_at"] == audit["reconciled_at"]
        assert audit["reconciled_revision"] == 2
    duplicate = env.service.job_status(HOST, job_id)
    assert duplicate["status"] == "verified"
    assert duplicate["notification_count"] == 1 and duplicate["notification_due"] is False
    assert env.patches.get_handoff_audit(HOST, job_id) == audit
    assert len(ops(env, "status")) == 2
    assert len(ops(env, "prepare")) == len(ops(env, "submit")) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"plan_id": "9" * 32},
        {"policy_digest": "9" * 64},
        {"execution_policy_digest": "9" * 64},
        {"automatic_grant_id": "9" * 32},
        {"automatic_grant_digest": "9" * 64},
    ],
)
def test_mismatched_early_status_never_replaces_the_patch_intent(env, change):
    class ProcessLost(BaseException):
        pass

    def lose_process(_ack):
        raise ProcessLost()

    env.submit_hook = lose_process
    with pytest.raises(ProcessLost):
        AutomaticMonitor(env.service, env.auto, now=lambda: env.clock).poll_once()
    job_id = env.job["job_id"]
    intent = env.patches.get_job(HOST, job_id)
    env.job = env.job | {"status": "verified", "revision": 2} | change
    with pytest.raises(PatchClientError):
        env.service.job_status(HOST, job_id)
    assert env.patches.get_job(HOST, job_id) == intent
    assert env.auto.get_by_job(HOST, job_id)["state"] == "submission_intent"
    assert env.auto.latch(HOST) is None
    assert env.patches.get_handoff_audit(HOST, job_id)["unknown_at"] is None


def test_historical_status_binds_original_execution_policy_after_rotation(env):
    value = reserved(env)
    assert submit(env, value)["status"] == "queued"
    job_id = value["job_id"]
    new_policy = "9" * 64
    env.service.targets = {HOST: target(policy=new_policy)}
    env.job = env.job | {
        "policy_digest": new_policy,
        "execution_policy_digest": ROOT_POLICY,
        "status": "verified",
        "revision": 2,
    }
    assert env.service.job_status(HOST, job_id)["status"] == "verified"
    assert env.auto.get(value["id"])["remote_revision"] == 2
    env.service.targets = {HOST: target(policy=new_policy, address="192.0.2.22")}
    env.job = env.job | {"revision": 3}
    with pytest.raises(PatchClientError):
        env.service.job_status(HOST, job_id)
    assert env.patches.get_job(HOST, job_id)["revision"] == 2


def test_original_grant_binding_survives_plan_retention(env, monkeypatch):
    value = reserved(env)
    assert submit(env, value)["status"] == "queued"
    job_id = value["job_id"]
    valid = env.job | {"status": "verified", "revision": 2}
    monkeypatch.setattr(env.patches, "get_plan", lambda *_: None)
    assert env.auto.get(value["id"])["root_grant_digest"] == valid["automatic_grant_digest"]
    assert "root_grant_digest" not in AutomaticMonitor(env.service, env.auto).status()["jobs"][0]
    env.job = valid | {"automatic_grant_digest": "9" * 64}
    with pytest.raises(PatchClientError):
        env.service.job_status(HOST, job_id)
    assert env.patches.get_job(HOST, job_id)["status"] == "queued"
    env.job = valid
    assert env.service.job_status(HOST, job_id)["status"] == "verified"


@pytest.mark.parametrize("source", ["status", "original_submit"])
def test_unbound_higher_cached_revision_cannot_win_over_a_valid_original(env, source):
    value = reserved(env)
    job_id = value["job_id"]

    def seed_legacy_cache(ack):
        # This recreates a row retained from a controller that did not validate
        # original root grant provenance before writing the status cache.
        env.patches.save_job(
            HOST,
            ack | {"status": "verified", "revision": 9, "automatic_grant_digest": "9" * 64},
        )
        return ack | {"revision": 2}

    if source == "original_submit":
        env.submit_hook = seed_legacy_cache
        with pytest.raises(PatchClientError):
            submit(env, value)
        assert env.auto.get(value["id"])["state"] == "submission_intent"
    else:
        assert submit(env, value)["status"] == "queued"
        env.job = seed_legacy_cache(env.job)
        with pytest.raises(PatchClientError):
            env.service.job_status(HOST, job_id)
        assert env.auto.get(value["id"])["remote_revision"] == 1
        assert env.auto.get(value["id"])["status"] == "queued"
    assert env.patches.get_job(HOST, job_id)["revision"] == 9
    assert env.service.checked_cached_automatic_job(value) is None
    assert len(ops(env, "submit")) == 1


def test_legacy_cache_needs_independent_grant_proof_to_settle_recovery(env, monkeypatch):
    class ProcessLost(BaseException):
        pass

    def lose_process(_ack):
        raise ProcessLost()

    original = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    env.submit_hook = lose_process
    with pytest.raises(ProcessLost):
        original.poll_once()
    job_id = env.job["job_id"]
    candidate = env.auto.get_by_job(HOST, job_id)
    candidate.pop("root_grant_digest")
    with env.auto._connection() as connection:
        env.auto._write(connection, candidate)
    trusted_plan = env.patches.get_plan(HOST, candidate["plan_id"])
    monkeypatch.setattr(env.patches, "get_plan", lambda *_: None)
    valid = env.job | {"status": "verified", "revision": 2}
    env.job = valid
    with pytest.raises(PatchClientError):
        env.service.job_status(HOST, job_id)
    # A pre-upgrade cache might already contain a structurally native result.
    # It cannot serve as its own original root grant proof after plan eviction.
    env.patches.save_job(HOST, valid)
    assert env.service.checked_cached_automatic_job(candidate) is None
    env.clock += timedelta(seconds=180)
    replacement = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    replacement.poll_once()
    assert env.auto.latch(HOST)["job_id"] == job_id
    assert env.auto.get(candidate["id"])["status"] == "unknown"
    assert env.patches.get_job(HOST, job_id)["status"] == "verified"
    monkeypatch.setattr(env.patches, "get_plan", lambda *_: trusted_plan)
    replacement.poll_once()
    assert env.auto.get(candidate["id"])["status"] == "verified"
    assert env.auto.latch(HOST)["job_id"] == job_id
    assert len(ops(env, "prepare")) == len(ops(env, "submit")) == 1


def test_failed_automatic_follow_cannot_overwrite_concurrent_verified_status(env):
    value = reserved(env)
    env.unknown = True
    assert submit(env, value)["status"] == "unknown"
    job_id = value["job_id"]
    entered, release = Event(), Event()
    invoker = env.service.invoker
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    original_latch = env.auto.latch(HOST)

    def ordered_rpc(target_value, request, *, timeout):
        if request["op"] == "status" and not entered.is_set():
            entered.set()
            assert release.wait(10)
            raise PatchClientError("synthetic status read lost")
        return invoker(target_value, request, timeout=timeout)

    env.service.invoker = ordered_rpc
    thread = Thread(target=monitor.poll_once, daemon=True)
    thread.start()
    try:
        assert entered.wait(10)
        env.job = env.job | {"status": "verified", "revision": 2}
        assert env.service.job_status(HOST, job_id)["status"] == "verified"
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert env.auto.get(value["id"])["status"] == "verified"
    assert env.auto.latch(HOST) == original_latch
    assert len(ops(env, "submit")) == 1


def test_status_cached_before_crash_lease_acquisition_cannot_consume_intent(env):
    class ProcessLost(BaseException):
        pass

    original = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)

    def lose_process(_ack):
        raise ProcessLost()

    env.submit_hook = lose_process
    with pytest.raises(ProcessLost):
        original.poll_once()
    job_id = env.job["job_id"]
    attempt = env.auto.get_by_job(HOST, job_id)
    assert attempt["state"] == "submission_intent"

    # The plain status reader observes the job while the old monitor's durable
    # lease still excludes the replacement owner, as after a process crash.
    reopened = AutomaticStore(env.auto.path)
    env.service.automatic_store = reopened
    env.service.store = PatchStore(env.patches.path)
    replacement = AutomaticMonitor(env.service, reopened, now=lambda: env.clock)
    env.job = env.job | {"status": "verified", "revision": 2}
    assert env.service.job_status(HOST, job_id)["status"] == "verified"
    assert reopened.get(attempt["id"]) == attempt
    assert not reopened.reconcile_submission_intent(attempt["id"], replacement.owner, now=env.clock)
    replacement.poll_once()
    assert reopened.latch(HOST) is None
    assert len(ops(env, "status")) == 1
    store_receipt = reopened.record_result
    pauses_at_record = []

    def record_result(*args, **kwargs):
        pauses_at_record.append(reopened.latch(HOST))
        return store_receipt(*args, **kwargs)

    reopened.record_result = record_result
    env.clock += timedelta(seconds=180)
    replacement.poll_once()
    reconciled = reopened.get(attempt["id"])
    assert (reconciled["status"], reconciled["remote_revision"]) == ("verified", 2)
    latch = reopened.latch(HOST)
    assert latch["job_id"] == job_id and latch["candidate_id"] == attempt["id"]
    assert latch["reason"] == "unknown"
    assert pauses_at_record == [latch]
    assert env.service.store.get_handoff_audit(HOST, job_id)["unknown_at"] is None
    assert env.service.store.get_job(HOST, job_id)["notification_count"] == 1
    replacement.poll_once()
    assert reopened.latch(HOST) == latch
    assert len(ops(env, "prepare")) == len(ops(env, "submit")) == len(ops(env, "status")) == 1


@pytest.mark.parametrize(
    "update",
    [
        {"authorization": "assisted"},
        {"automatic_grant_digest": "6" * 64},
        {"plan_id": "6" * 32},
        {"mode_revision": True},
        {"revision": True},
        {"schema_version": True},
    ],
)
def test_untrusted_job_response_becomes_unknown_without_retry_and_latches(env, update):
    value = reserved(env)
    env.submit_hook = lambda result: result | update
    result = submit(env, value)
    assert result["status"] == "unknown" and env.auto.latch(HOST) is not None
    assert len(ops(env, "submit")) == 1


def test_explicit_remote_rejection_is_dict_and_persistently_pauses_auto(env):
    value = reserved(env)
    env.submit_hook = lambda _result: {"ok": False, "error": "rejected"}
    result = submit(env, value)
    assert isinstance(result, dict) and result["status"] == "rejected"
    assert result["remote_job_created"] is False and env.auto.latch(HOST) is not None


def test_overdue_task_keeps_tracking_original_job_and_persists_safety_pause(env):
    value = reserved(env)
    assert submit(env, value)["status"] == "queued"
    env.job.update(status="running_overdue", revision=2)
    env.service.job_status(HOST, value["job_id"])
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    assert env.auto.latch(HOST)["reason"] == "running_overdue"
    assert env.auto.active_attempts()[0]["status"] == "running_overdue"
    assert len(ops(env, "submit")) == 1


def test_automatic_sync_ignores_ungranted_offline_host_but_manual_revokes_every_host(env):
    env.service.targets = {"offline": target("offline"), HOST: target(), "last": target("last")}
    env.failed_hosts = {"offline"}
    env.calls.clear()
    assert env.service.sync_mode()["mode_sync_complete"] is True
    assert [host for host, _request in env.calls] == [HOST]
    env.calls.clear()
    with pytest.raises(ModeSynchronizationError):
        env.service.change_mode(ModeChange(mode="manual", expected_revision=1))
    assert [host for host, _request in env.calls] == [HOST, "offline", "last"]
    assert env.automation.status()["mode"] == "manual"
    assert env.automation.status()["mode_sync_complete"] is False


def test_public_automatic_planning_cannot_bypass_internal_path(env):
    with pytest.raises(HTTPException) as failure:
        env.service.prepare(PrepareRequest(host_id=HOST, finding_id=finding()["finding_id"]))
    assert failure.value.status_code == 409 and ops(env, "prepare") == []


def test_mode_can_be_revoked_during_internal_prepare_without_accepting_returned_plan(env):
    def stop(value):
        env.service.change_mode(ModeChange(mode="manual", expected_revision=1))
        return value

    env.prepare_hook = stop
    with pytest.raises(HTTPException):
        prepare(env)
    assert env.automation.status()["mode"] == "manual" and ops(env, "submit") == []


def test_without_grant_automatic_mode_is_saved_without_rpc_or_execution(tmp_path):
    targets = {HOST: target()}
    policy = ControlPolicy(
        enabled=True,
        host_ids=(HOST,),
        allowed_actions=("os_security_upgrade",),
        allowed_packages=("libbrotli1",),
    )
    mode = AutomationStore(tmp_path / "mode.db", policy, driver_scope=targets_scope(targets))
    service = PatchService(targets, PatchStore(tmp_path / "patch.db"), mode)
    service.invoker = lambda *_args, **_kwargs: pytest.fail(
        "No grant must not synchronize auto mode"
    )
    selected = service.change_mode(ModeChange(mode="automatic", expected_revision=0))
    assert selected["mode_sync_complete"] is True and selected["execution_available"] is False
    assert selected["supported_execution_modes"] == ["assisted"]


def test_supported_auto_mode_requires_current_grant_and_controller_ledger(env):
    assert env.service.status()["supported_execution_modes"] == ["assisted", "automatic"]
    env.service.automatic_store = None
    assert env.service.status()["supported_execution_modes"] == ["assisted"]
    assert env.service.status()["execution_available"] is False


def test_actual_root_validator_and_digest_accept_the_model_dump_projection(root_auto):
    local_grant = AutomaticGrant.model_validate(
        root_auto.grant
        | {
            "host_ids": [root_auto.policy["host_id"]],
            "target_policy_digests": {root_auto.policy["host_id"]: ROOT_POLICY},
        }
    )
    normalized = local_grant.model_dump(
        mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
    )
    root_auto.grant.clear()
    root_auto.grant.update(normalized)
    validated = root_auto.module.validate_grant(root_auto.policy)
    assert validated["issued_at"].endswith("Z")
    assert root_auto.core.digest(validated) == PatchService._root_grant_digest(local_grant)
    root_auto.plan["automatic_grant_digest"] = PatchService._root_grant_digest(local_grant)
    assert root_auto.module.authorize(root_auto.plan, root_auto.policy) == normalized


def test_remote_only_historical_pause_is_persisted_without_a_controller_job(env):
    env.root_safety.update(paused=True, reason="automatic_job_running_overdue", job_id="8" * 32)
    env.service.refresh_automatic_status(HOST)
    pause = env.auto.latch(HOST)
    assert pause["source"] == "remote_root" and pause["job_id"] == "8" * 32
    assert pause["reason"] == "automatic_job_running_overdue"
    assert env.auto.list_attempts() == []
    env.root_safety.update(paused=False, reason=None, job_id=None)
    env.service.refresh_automatic_status(HOST)
    assert AutomaticStore(env.auto.path).latch(HOST) == pause
    with pytest.raises(HTTPException):
        prepare(env)
    assert ops(env, "prepare") == []


def test_background_reads_root_safety_in_manual_mode_and_get_status_never_uses_ssh(env):
    env.service.targets["not-granted"] = target("not-granted")
    env.service.change_mode(ModeChange(mode="manual", expected_revision=1))
    env.clock += timedelta(seconds=31)
    env.root_safety.update(paused=True, reason="automatic_job_unknown", job_id="8" * 32)
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    root_reads = [host for host, request in env.calls if request["op"] == "automatic_status"]
    assert root_reads == [HOST, HOST]
    total = len(env.calls)
    monitor.status()
    monitor.status()
    env.service.status()
    assert len(env.calls) == total
    host = next(item for item in monitor.status()["hosts"] if item["host_id"] == HOST)
    assert host["state"] == "latched" and host["remote_status"]["status"] == "available"
    assert host["latch"]["remote_safety"]["job_id"] == "8" * 32


def test_stale_remote_cache_blocks_independent_service_admission_until_background_refresh(env):
    env.clock += timedelta(seconds=61)
    with pytest.raises(HTTPException):
        prepare(env)
    assert ops(env, "prepare") == []
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    assert len(ops(env, "prepare")) == len(ops(env, "submit")) == 1


@pytest.mark.parametrize("kind", ["transport", "binding", "usage_unknown", "grant_mismatch"])
def test_unknown_foreign_or_failed_root_status_blocks_new_jobs_without_assuming_zero(env, kind):
    def unavailable(value):
        if kind == "transport":
            raise PatchClientError("Synthetic unavailable root status")
        if kind == "binding":
            value["host_id"] = "other"
        elif kind == "usage_unknown":
            value["usage"]["daily_used"] = None
        else:
            value["grant"]["grant_id"] = "8" * 32
            value["grant_digest"] = hashlib.sha256(
                json.dumps(value["grant"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        return value

    env.root_status_hook = unavailable
    env.clock += timedelta(seconds=31)
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    assert ops(env, "prepare") == ops(env, "submit") == []
    assert monitor.status()["hosts"][0]["state"] == "error"
    with pytest.raises(HTTPException):
        prepare(env)


def test_root_usage_exhaustion_cannot_be_hidden_by_empty_local_ledger(env):
    env.root_usage.update(daily_used=1, total_used=1)
    env.service.refresh_automatic_status(HOST)
    monitor = AutomaticMonitor(env.service, env.auto, now=lambda: env.clock)
    monitor.poll_once()
    state = monitor.status()["hosts"][0]
    assert state["state"] == "quota_exhausted" and state["quota"]["total_used"] == 1
    assert env.auto.quotas(HOST, "f" * 32, now=env.clock)["total_used"] == 0
    with pytest.raises(HTTPException):
        prepare(env)
    assert ops(env, "prepare") == ops(env, "submit") == []
