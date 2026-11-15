"""Local durable activation admission and native receipt contracts; no server/model calls."""

import copy
import json
import sqlite3
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from test_automatic_monitor import HOST, ROOT_POLICY, target
from test_automatic_service import env as env
from test_automatic_service import reserved

from opsark.activation_api import (
    PLAN_FIELDS,
    RECORD_FIELDS,
    REQUIRED_CHECKS,
    ActivationPrepareRequest,
    ActivationService,
    ActivationSubmitRequest,
    register_activation_routes,
)
from opsark.activation_evidence import build_evidence
from opsark.activation_monitor import ActivationMonitor
from opsark.activation_store import ActivationStore
from opsark.automatic_store import digest
from opsark.automation_store import AutomationStore, ModeChange
from opsark.control_modes import ControlPolicy
from opsark.patch_api import targets_scope
from opsark.patch_client import UnknownPatchResult

ACTIVATION = "7" * 32
SOURCE = "8" * 64


def seal(value, field):
    value[field] = digest({k: v for k, v in value.items() if k != field})
    return value


@pytest.fixture
def activation(env):
    candidate = reserved(env)
    env.unknown = True
    env.service.auto_submit(
        HOST,
        candidate["plan_id"],
        candidate["plan_digest"],
        candidate["mode_revision"],
        candidate["grant_digest"],
        candidate["job_id"],
    )
    env.job.update(
        status="installed_restart_pending",
        revision=7,
        install_exit_code=0,
        verification={
            "fresh_ssh": {"passed": True},
            "runtime": {"status": "complete", "outdated_process_count": 1},
        },
    )
    env.service.job_status(HOST, candidate["job_id"])
    configured = env.automation.policy.model_dump(mode="json")
    configured["service_activation"] = {
        "enabled": True,
        "host_ids": [HOST],
        "allowed_units": ["nginx.service"],
        "allowed_packages": ["libbrotli1"],
        "allow_critical_units": [],
        "max_services_per_activation": 1,
    }
    env.automation = AutomationStore(
        env.automation.path,
        ControlPolicy.model_validate(configured),
        driver_scope=targets_scope(env.service.targets),
    )
    env.service.automation = env.automation
    env.service.change_mode(
        ModeChange(mode="assisted", expected_revision=env.automation.status()["revision"])
    )
    store = ActivationStore(env.patches.path)
    service = ActivationService(env.service, store)
    state = SimpleNamespace(
        e=env,
        candidate=candidate,
        service=service,
        store=store,
        calls=[],
        plans={},
        results={},
        submit_loss=False,
        plan_hook=None,
        receipt_hook=None,
        root_status="queued",
        root_revision=1,
    )
    original = env.service.invoker

    def invoke(remote, request, timeout=75):
        op = request["op"]
        if not op.startswith("activation_"):
            return original(remote, request, timeout)
        state.calls.append(copy.deepcopy(request))
        if op == "activation_prepare":
            mode = env.automation.status()
            plan = dict.fromkeys(PLAN_FIELDS)
            plan.update(
                schema_version=1,
                status="activation_prepared",
                activation_id=ACTIVATION,
                host_id=HOST,
                evidence_origin="controlled_lab",
                action="service_activation",
                policy_digest=ROOT_POLICY,
                driver_source_digest=SOURCE,
                mode_revision=mode["revision"],
                prepared_mode=mode["mode"],
                context_digest=request["context_digest"],
                job_id=env.job["job_id"],
                job_revision=7,
                job_digest=digest(env.job),
                original_job_status="installed_restart_pending",
                original_job_sha256="1" * 64,
                original_plan_id=env.job["plan_id"],
                original_plan_digest=env.job["plan_digest"],
                original_plan_sha256="2" * 64,
                runtime_manifest_sha256="3" * 64,
                original_safety_digest="4" * 64,
                original_safety_present=True,
                package="libbrotli1",
                architecture="amd64",
                candidate_version="1.1.0-2ubuntu0.1",
                unit="nginx.service",
                unit_evidence={"unit": "nginx.service", "fragment_sha256": "5" * 64},
                processes=[{"pid": 50, "starttime": 200, "cgroup": "/system.slice/nginx.service"}],
                state_digest="6" * 64,
                boot_id="synthetic-boot",
                created_at=env.clock.isoformat(),
                expires_at=(env.clock + timedelta(minutes=5)).isoformat(),
                eligible=True,
                checks=[{"id": name, "status": "passed"} for name in sorted(REQUIRED_CHECKS)],
                blockers=[],
                requires_reboot=False,
                original_job_will_not_be_modified=True,
                effective_result="pending_approval",
            )
            if state.plan_hook:
                state.plan_hook(plan)
            state.plans[ACTIVATION] = seal(plan, "activation_digest")
            return copy.deepcopy(plan)
        if op == "activation_submit":
            plan = state.plans[request["activation_id"]]
            result = dict.fromkeys(RECORD_FIELDS)
            result.update(
                {
                    k: plan[k]
                    for k in RECORD_FIELDS & PLAN_FIELDS
                    if k not in {"status", "created_at", "updated_at", "effective_result"}
                }
            )
            result.update(
                status="queued",
                revision=1,
                created_at=env.clock.isoformat(),
                updated_at=env.clock.isoformat(),
                approved_at=env.clock.isoformat(),
                plan=copy.deepcopy(plan),
                original_job_unchanged=True,
                original_safety_unchanged=True,
                effective_result="activation_queued",
                detail="Synthetic queued action.",
            )
            result["approval_digest"] = digest(
                {
                    key: result[key]
                    for key in (
                        "activation_id",
                        "activation_digest",
                        "context_digest",
                        "mode_revision",
                        "approved_at",
                        "expires_at",
                    )
                }
            )
            state.results[ACTIVATION] = seal(result, "record_digest")
            if state.submit_loss:
                raise UnknownPatchResult(op)
            return copy.deepcopy(result)
        assert op == "activation_status"
        result = copy.deepcopy(state.results[request["activation_id"]])
        result.update(
            status=state.root_status, revision=state.root_revision, updated_at=env.clock.isoformat()
        )
        if state.root_status == "verified":
            intent = {
                "activation_id": ACTIVATION,
                "activation_digest": result["activation_digest"],
                "unit": result["unit"],
                "argv": ["/usr/bin/systemctl", "restart", result["unit"]],
                "boot_id": result["boot_id"],
            }
            result.update(
                effective_result="activation_verified",
                completed_at=env.clock.isoformat(),
                locally_verified_at=env.clock.isoformat(),
                locally_verified_uptime_ticks=60,
                local_result="verified",
                restart_evidence={
                    "intent_digest": digest(intent),
                    "intent": intent,
                    "result": {
                        "intent_digest": digest(intent),
                        "result": {"exit_code": 0, "result_unknown": False},
                    },
                },
                verification={
                    **{
                        name: {"passed": True}
                        for name in (
                            "new_process",
                            "exact_package_version",
                            "vendor_rescan",
                            "health",
                            "fresh_ssh",
                        )
                    },
                    "runtime": {"status": "complete", "outdated_process_count": 0},
                },
            )
            result["verification"]["health"]["reboot_required"] = False
            result["verification"]["fresh_ssh"].update(
                checked_at=env.clock.isoformat(),
                mechanism="sshd_connection_started_after_activation_verification",
            )
        if state.receipt_hook:
            state.receipt_hook(result)
        return seal(result, "record_digest")

    env.service.invoker = invoke
    return state


def prepare(a):
    return a.service.prepare(
        ActivationPrepareRequest(
            host_id=HOST,
            job_id=a.e.job["job_id"],
            expected_mode_revision=a.e.automation.status()["revision"],
        )
    )


def submit(a, record):
    return a.service.submit(
        ActivationSubmitRequest(
            host_id=HOST,
            activation_id=record["activation_id"],
            expected_activation_digest=record["activation_digest"],
            expected_mode_revision=record["plan"]["mode_revision"],
            confirm_activate=True,
        )
    )


def test_preview_and_cached_gets_never_restart_or_query_original_again(activation):
    a = activation
    record = prepare(a)
    assert record["status"] == "prepared" and record["plan"]["unit"] == "nginx.service"
    before = a.e.patches.path.read_bytes(), list(a.calls)
    assert a.service.get(HOST, ACTIVATION)["status"] == "prepared"
    assert a.service.list()["records"][0]["original_patch_status"] == "installed_restart_pending"
    assert (a.e.patches.path.read_bytes(), a.calls) == before
    assert [r["op"] for r in a.calls] == ["activation_prepare"]


def test_preview_uses_retained_original_receipt_without_legacy_status_refresh(
    activation, monkeypatch
):
    a = activation

    def denied(*_args, **_kwargs):
        pytest.fail("Activation preview must never refresh or rewrite the original patch receipt")

    monkeypatch.setattr(a.e.service, "job_status", denied)
    before = a.e.patches.get_job(HOST, a.e.job["job_id"])
    record = prepare(a)
    assert record["original_job"]["revision"] == before["revision"]
    assert record["job_digest"] == digest(a.e.job)
    assert a.e.patches.get_job(HOST, a.e.job["job_id"]) == before
    assert [call["op"] for call in a.calls] == ["activation_prepare"]


def test_preview_rejects_missing_original_cache_without_querying_root(activation, monkeypatch):
    a = activation

    def denied(*_args, **_kwargs):
        pytest.fail("A missing original receipt must not trigger a legacy Root status refresh")

    monkeypatch.setattr(a.e.service, "job_status", denied)
    with sqlite3.connect(a.e.patches.path) as connection:
        connection.execute(
            "DELETE FROM patch_jobs WHERE host_id=? AND job_id=?", (HOST, a.e.job["job_id"])
        )
    with pytest.raises(HTTPException) as caught:
        prepare(a)
    assert caught.value.status_code == 409
    assert not a.calls


def test_fractional_future_preview_waits_for_actual_clock_without_extending_expiry(
    activation, monkeypatch
):
    a = activation
    created = a.e.clock + timedelta(milliseconds=335)
    expires = created + timedelta(minutes=5)
    a.plan_hook = lambda p: p.update(created_at=created.isoformat(), expires_at=expires.isoformat())
    waits = []

    def advance(seconds):
        waits.append(seconds)
        a.e.clock += timedelta(seconds=seconds)

    monkeypatch.setattr("opsark.activation_api.time.sleep", advance)
    record = prepare(a)
    assert waits == [0.335]
    assert a.e.clock == created
    assert record["plan"]["expires_at"] == expires.isoformat()
    assert [call["op"] for call in a.calls] == ["activation_prepare"]


@pytest.mark.parametrize("advance", [False, True])
def test_wait_never_accepts_a_still_future_or_now_expired_plan(activation, monkeypatch, advance):
    a = activation
    created = a.e.clock + timedelta(milliseconds=335)
    expires = created + timedelta(milliseconds=100)
    a.plan_hook = lambda p: p.update(created_at=created.isoformat(), expires_at=expires.isoformat())
    waits = []

    def wait(seconds):
        waits.append(seconds)
        if advance:
            a.e.clock = expires

    monkeypatch.setattr("opsark.activation_api.time.sleep", wait)
    with pytest.raises(HTTPException) as caught:
        prepare(a)
    assert caught.value.status_code == 409
    assert waits == [0.335] and a.store.list() == []
    assert not any(call["op"] == "activation_submit" for call in a.calls)


def test_larger_future_preview_is_rejected_without_wait_or_submission(activation, monkeypatch):
    a = activation
    created = a.e.clock + timedelta(seconds=2)
    a.plan_hook = lambda p: p.update(
        created_at=created.isoformat(), expires_at=(created + timedelta(minutes=5)).isoformat()
    )
    monkeypatch.setattr(
        "opsark.activation_api.time.sleep", lambda _: pytest.fail("Unbounded clock wait")
    )
    with pytest.raises(HTTPException):
        prepare(a)
    assert a.store.list() == []
    assert not any(call["op"] == "activation_submit" for call in a.calls)


@pytest.mark.parametrize("field,value", [("job_revision", 8), ("job_digest", "0" * 64)])
def test_preview_rejects_native_original_revision_or_digest_drift(activation, field, value):
    a = activation
    a.plan_hook = lambda plan: plan.update({field: value})
    with pytest.raises(HTTPException) as caught:
        prepare(a)
    assert caught.value.status_code == 409
    assert a.store.list() == []


def test_assisted_submit_poll_and_restart_preserve_original_job_and_latch(activation):
    a = activation
    original_job, original_latch = copy.deepcopy(a.e.job), copy.deepcopy(a.e.auto.latch(HOST))
    record = prepare(a)
    assert submit(a, record)["status"] == "queued"
    assert submit(a, record)["status"] == "queued"
    a.root_status, a.root_revision = "verified", 4
    a.e.clock += timedelta(seconds=3)
    monitor = ActivationMonitor(a.service)
    monitor.poll_once()
    monitor.stop()
    assert a.service.get(HOST, ACTIVATION)["effective_status"] == "activation_verified"
    assert a.store.get(HOST, ACTIVATION)["notification_count"] == 1
    a.service.store = ActivationStore(a.e.patches.path)
    ActivationMonitor(a.service).poll_once()
    assert a.e.job == original_job and a.e.auto.latch(HOST) == original_latch
    assert [r["op"] for r in a.calls].count("activation_submit") == 1


def test_unknown_submit_only_polls_original_id_even_after_mode_revocation(activation):
    a = activation
    record = prepare(a)
    a.submit_loss = True
    assert submit(a, record)["status"] == "unknown"
    a.e.service.change_mode(
        ModeChange(mode="manual", expected_revision=record["plan"]["mode_revision"])
    )
    before = len(a.calls)
    assert submit(a, record)["status"] == "unknown" and len(a.calls) == before
    a.root_status, a.root_revision = "verified", 4
    a.e.clock += timedelta(seconds=1)
    ActivationMonitor(a.service).poll_once()
    assert a.service.get(HOST, ACTIVATION)["status"] == "verified"
    assert len([r for r in a.calls if r["op"] == "activation_submit"]) == 1
    assert all(
        r.get("activation_id") == ACTIVATION for r in a.calls if r["op"] != "activation_prepare"
    )


def test_manual_preview_is_not_executable_without_new_assisted_preview(activation):
    a = activation
    a.e.service.change_mode(
        ModeChange(mode="manual", expected_revision=a.e.automation.status()["revision"])
    )
    record = prepare(a)
    with pytest.raises(HTTPException) as caught:
        submit(a, record)
    assert caught.value.status_code == 409
    assert not any(r["op"] == "activation_submit" for r in a.calls)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(eligible=True, checks=[{"id": "fake", "status": "passed"}]),
        lambda p: p.update(unit="ssh.service"),
        lambda p: p.update(unit="dbus.service"),
        lambda p: p.update(unit="nginx.service;reboot"),
        lambda p: p.update(job_revision=True),
        lambda p: p.update(original_job_will_not_be_modified=False),
        lambda p: p.update(requires_reboot=True),
        lambda p: p.update(expires_at="2099-01-01T00:00:00+00:00"),
        lambda p: p.update(job_digest="0" * 64),
        lambda p: p.update(context_digest="0" * 64),
    ],
)
def test_untrusted_or_widened_plan_never_enters_local_approval(activation, change):
    a = activation
    a.plan_hook = change
    with pytest.raises(HTTPException):
        prepare(a)
    assert a.store.list() == []
    assert not any(r["op"] == "activation_submit" for r in a.calls)


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(unit="other.service"),
        lambda r: r.update(job_revision=True),
        lambda r: r.update(mode_revision=True),
        lambda r: r.update(original_job_unchanged=False),
        lambda r: r.update(original_safety_unchanged=False),
        lambda r: r["verification"]["fresh_ssh"].update(passed=False),
        lambda r: r["verification"]["runtime"].update(outdated_process_count=1),
        lambda r: r["verification"].update(health=None),
        lambda r: r["verification"].update(fresh_ssh="private-malformed-message"),
        lambda r: r.update(restart_evidence=[]),
        lambda r: r.update(extra="private-raw-body"),
    ],
)
def test_forged_receipt_is_unknown_not_effective_verified(activation, change):
    a = activation
    record = prepare(a)
    submit(a, record)
    a.root_status, a.root_revision = "verified", 4
    a.receipt_hook = change
    a.e.clock += timedelta(seconds=1)
    ActivationMonitor(a.service).poll_once()
    result = a.service.get(HOST, ACTIVATION)
    assert result["status"] == "unknown" and result["effective_status"] != "activation_verified"
    assert "private-raw-body" not in str(result)
    assert a.e.job["status"] == "installed_restart_pending"


def test_reused_host_label_never_contacts_replacement_or_calls_observation(activation):
    a = activation
    record = prepare(a)
    submit(a, record)
    a.e.service.targets[HOST] = target(address="192.0.2.55")
    calls = len(a.calls)
    observed = []
    ActivationMonitor(a.service, on_verified=lambda r: observed.append(r)).poll_once()
    assert a.service.get(HOST, ACTIVATION)["stale"]
    assert len(a.calls) == calls and not observed


def test_verified_observation_callback_recovers_after_controller_restart_once(activation):
    a = activation
    record = prepare(a)
    submit(a, record)
    a.root_status, a.root_revision = "verified", 4
    a.service.poll(HOST, ACTIVATION)
    called = []

    def observed(value):
        called.append(value["activation_id"])
        return {
            "activation_id": ACTIVATION,
            "original_job_id": value["job_id"],
            "host_id": HOST,
            "rescan_request_id": "a" * 32,
            "event_key": ACTIVATION,
            "scope_hash": "b" * 64,
        }

    monitor = ActivationMonitor(a.service, on_verified=observed)
    monitor.poll_once()
    monitor.poll_once()
    monitor.stop()
    assert called == [ACTIVATION]
    assert a.store.get(HOST, ACTIVATION)["rescan_reference"]["event_key"] == ACTIVATION


def test_evidence_is_read_only_and_does_not_need_current_target(activation, monkeypatch):
    a = activation
    record = prepare(a)
    submit(a, record)
    a.root_status, a.root_revision = "verified", 4
    a.service.poll(HOST, ACTIVATION)
    before = a.e.patches.path.read_bytes(), list(a.calls)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Evidence must not resolve current target, model or transport")

    monkeypatch.setattr(a.service.service, "target", forbidden)
    monkeypatch.setattr(a.service, "_root", forbidden)
    monkeypatch.setattr(a.service, "_policy", forbidden)
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    assert bundle["original_patch_status"] == "installed_restart_pending"
    assert bundle["activation_record"]["status"] == "verified"
    assert bundle["evidence_status"] == "incomplete"  # Read-only observation is not attached yet.
    assert bundle["bundle_digest"] == digest(
        {k: v for k, v in bundle.items() if k != "bundle_digest"}
    )
    assert (a.e.patches.path.read_bytes(), a.calls) == before


def test_all_activation_routes_require_authentication(activation):
    def deny():
        raise HTTPException(401, "Protected")

    app = FastAPI()
    register_activation_routes(app, activation.service, [Depends(deny)])
    client = TestClient(app)
    for method, path in (
        ("get", ""),
        ("post", ""),
        ("post", "/plans"),
        ("get", f"/{HOST}/{ACTIVATION}"),
        ("get", f"/{HOST}/{ACTIVATION}/evidence"),
        ("post", f"/{HOST}/{ACTIVATION}/acknowledge"),
    ):
        assert getattr(client, method)("/api/service-activations" + path).status_code == 401


def test_mutated_plan_payload_cannot_change_immutable_anchor(activation):
    a = activation
    prepare(a)
    with sqlite3.connect(a.e.patches.path) as connection:
        row = connection.execute("SELECT payload FROM service_activation_records").fetchone()
        value = json.loads(row[0])
        value["plan"]["unit"] = "other.service"
        connection.execute("UPDATE service_activation_records SET payload=?", (json.dumps(value),))
    with pytest.raises(ValueError, match="inconsistent"):
        a.store.get(HOST, ACTIVATION)
