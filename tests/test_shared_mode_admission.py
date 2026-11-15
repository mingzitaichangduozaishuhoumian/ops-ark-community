"""Shared mode changes and durable local intents have one short admission boundary."""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread, current_thread
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from test_activation_controller import activation as activation
from test_activation_controller import prepare as prepare_activation
from test_activation_controller import submit as submit_activation
from test_activation_recovery_controller import prepare as prepare_activation_recovery
from test_activation_recovery_controller import recovered_activation as recovered_activation
from test_activation_recovery_controller import submit as submit_activation_recovery
from test_automatic_monitor import HOST
from test_automatic_service import env as env
from test_automatic_service import reserved
from test_automatic_service import submit as submit_automatic
from test_recovery_api import approve, preview
from test_recovery_api import recovery as recovery

from opsark.automation_store import AutomationStore, ModeChange
from opsark.config import HostConfig
from opsark.control_modes import ControlPolicy
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope
from opsark.models import HostPublic
from opsark.patch_api import PatchService, SubmitRequest, targets_scope
from opsark.patch_client import PatchClientError
from opsark.patch_store import PatchStore


def attach_coordinator(e):
    def apt(snapshot):
        e.service.synchronize_mode_targets({"mode": snapshot.mode, "revision": snapshot.revision})
        return True

    coordinator = ModeCoordinator(
        e.automation,
        Lock(),
        (ModeParticipant("ubuntu-apt", e.automation.driver_scope, apt),),
    )
    e.service.mode_coordinator = coordinator
    coordinator.sync_mode()
    return coordinator


@pytest.fixture
def shared_assisted(tmp_path):
    """All identity references are synthetic; the invoker never opens a key or socket."""
    from opsark.patch_client import PatchTarget

    host = HostConfig(
        HostPublic(id="host-a", name="synthetic", address="192.0.2.30", source="ssh"),
        tmp_path / "readonly.key",
        tmp_path / "known_hosts",
    )
    target = PatchTarget(host, tmp_path / "repair.key", "a" * 64)
    policy = ControlPolicy(
        enabled=True,
        host_ids=["host-a"],
        allowed_actions=["os_security_upgrade"],
        allowed_packages=["demo"],
        max_packages_per_job=1,
    )
    driver_scope = targets_scope({"host-a": target})
    assert driver_scope is not None
    calls, remote = [], {"mode": "manual", "revision": 0}
    participant_scope = supplemental_scope(
        (ModeParticipant("ssh-defense", "2" * 64, lambda _: True),)
    )
    automation = AutomationStore(
        tmp_path / "mode.sqlite3",
        policy,
        driver_scope=driver_scope,
        supplemental_scope=participant_scope,
    )
    patches = PatchStore(tmp_path / "patches.sqlite3")
    patch = PatchService({"host-a": target}, patches, automation)

    def invoke(target, request, timeout=75):
        calls.append(request.copy())
        if request["op"] == "set_mode":
            if request["revision"] < remote["revision"]:
                raise PatchClientError("synthetic stale revision")
            remote.update(mode=request["mode"], revision=request["revision"])
            return remote.copy()
        assert request["op"] == "submit"
        assert remote == {"mode": "assisted", "revision": request["mode_revision"]}
        return {
            "host_id": "host-a",
            "job_id": request["job_id"],
            "plan_id": request["plan_id"],
            "plan_digest": request["plan_digest"],
            "status": "queued",
            "revision": 1,
        }

    patch.invoker = invoke

    def apt(snapshot):
        patch.synchronize_mode_targets({"mode": snapshot.mode, "revision": snapshot.revision})
        return True

    coordinator = ModeCoordinator(
        automation,
        Lock(),
        (
            ModeParticipant("ubuntu-apt", driver_scope, apt),
            ModeParticipant("ssh-defense", "2" * 64, lambda _: True),
        ),
    )
    patch.mode_coordinator = coordinator
    coordinator.change_mode(ModeChange(mode="assisted", expected_revision=0))
    body = SubmitRequest(
        host_id="host-a",
        plan_id="c" * 32,
        expected_plan_digest="d" * 64,
        expected_mode_revision=1,
        confirm_execute=True,
        job_id="e" * 32,
    )
    patches.save_plan(
        "host-a",
        {
            "schema_version": 1,
            "host_id": "host-a",
            "plan_id": body.plan_id,
            "plan_digest": body.expected_plan_digest,
            "policy_digest": target.policy_digest,
            "mode_revision": 1,
            "action": "os_security_upgrade",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
            "package_changes": [{"name": "demo", "current_version": "1", "candidate_version": "2"}],
            "requires_service_restart": False,
            "requires_reboot": False,
            "restart_assessment": "none",
        },
    )
    return SimpleNamespace(
        service=patch,
        automation=automation,
        patches=patches,
        coordinator=coordinator,
        calls=calls,
        body=body,
    )


def case_for(request, kind, *, uncertain=False):
    if kind == "assisted":
        e = request.getfixturevalue("shared_assisted")

        def action():
            return e.service.submit(e.body)

        def pending():
            return e.patches.get_job("host-a", e.body.job_id) is None

        calls, operation, stop = e.calls, "submit", "manual"
    elif kind == "automatic":
        e = request.getfixturevalue("env")
        attach_coordinator(e)
        candidate = reserved(e)
        e.unknown = uncertain

        def action():
            return submit_automatic(e, candidate)

        def pending():
            return e.patches.get_job(HOST, candidate["job_id"]) is None

        calls, operation, stop = e.calls, "submit", "manual"
    elif kind == "activation":
        a = request.getfixturevalue("activation")
        e = a.e
        attach_coordinator(e)
        record = prepare_activation(a)

        def action():
            return submit_activation(a, record)

        def pending():
            return a.store.get(HOST, record["activation_id"])["status"] == "prepared"

        calls, operation, stop = a.calls, "activation_submit", "manual"
    elif kind == "recovery":
        r = request.getfixturevalue("recovery")
        e = r.env
        attach_coordinator(e)
        record = preview(r)
        r.lose_reply = uncertain

        def action():
            return approve(r, record)

        def pending():
            return r.service.store.get_recovery(HOST, record["recovery_id"])["status"] == "prepared"

        calls, operation, stop = r.calls, "recovery_submit", "assisted"
    else:
        r = request.getfixturevalue("recovered_activation")
        e = r.e
        attach_coordinator(e)
        record = prepare_activation_recovery(r)
        r.loss = uncertain

        def action():
            return submit_activation_recovery(r, record)

        def pending():
            return r.store.get(HOST, record["recovery_id"])["status"] == "prepared"

        calls, operation, stop = r.calls, "activation_recovery_submit", "assisted"

    def sent():
        return sum(
            (value[1] if isinstance(value, tuple) else value)["op"] == operation for value in calls
        )

    return SimpleNamespace(e=e, action=action, pending=pending, sent=sent, stop=stop)


KINDS = ["assisted", "automatic", "activation", "recovery", "activation_recovery"]


@pytest.mark.parametrize("kind", KINDS)
def test_mode_committed_before_admission_rejects_every_new_intent(request, monkeypatch, kind):
    case = case_for(request, kind)
    patch = case.e.service
    entered, release = Event(), Event()
    errors = []
    original = patch.local_admission

    @contextmanager
    def wait_before_admission():
        entered.set()
        assert release.wait(5)
        with original():
            yield

    monkeypatch.setattr(patch, "local_admission", wait_before_admission)

    def submit():
        try:
            case.action()
        except Exception as error:
            errors.append(error)

    before = case.sent()
    worker = Thread(target=submit, daemon=True)
    worker.start()
    try:
        assert entered.wait(5)
        coordinator = patch.mode_coordinator
        status = case.e.automation.status()
        coordinator.change_mode(ModeChange(mode=case.stop, expected_revision=status["revision"]))
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], HTTPException)
    assert errors[0].status_code == 409
    assert case.pending() and case.sent() == before


def test_authorization_through_intent_precedes_manual_but_rpc_does_not_block_it(
    shared_assisted, monkeypatch
):
    e = shared_assisted
    captured, release_check, rpc_entered, release_rpc, stopping, stopped = (
        Event() for _ in range(6)
    )
    results, errors = [], []
    original_status, original_invoke = e.automation.status, e.service.invoker

    def status():
        value = original_status()
        if current_thread().name == "shared-mode-submit" and not captured.is_set():
            captured.set()
            assert e.coordinator.mode_lock.locked()
            assert release_check.wait(5)
        return value

    def invoke(target, request, **kwargs):
        if request["op"] == "set_mode" and request["mode"] == "manual":
            assert rpc_entered.wait(5)
        if request["op"] == "submit":
            # Admission is durable before mode changes can proceed. Only this
            # already admitted RPC retains the legacy transaction lock.
            assert e.patches.get_job("host-a", e.body.job_id) is not None
            value = original_invoke(target, request, **kwargs)
            rpc_entered.set()
            assert release_rpc.wait(5)
            return value
        return original_invoke(target, request, **kwargs)

    monkeypatch.setattr(e.automation, "status", status)
    monkeypatch.setattr(e.service, "invoker", invoke)

    def submit():
        try:
            results.append(e.service.submit(e.body))
        except Exception as error:
            errors.append(error)

    def manual():
        stopping.set()
        try:
            e.service.change_mode(ModeChange(mode="manual", expected_revision=1))
            stopped.set()
        except Exception as error:
            errors.append(error)

    worker = Thread(target=submit, name="shared-mode-submit", daemon=True)
    stopper = Thread(target=manual, daemon=True)
    worker.start()
    try:
        assert captured.wait(5)
        stopper.start()
        assert stopping.wait(5)
        assert original_status()["mode"] == "assisted"
        assert e.patches.get_job("host-a", e.body.job_id) is None
        release_check.set()
        assert rpc_entered.wait(5)
        assert stopped.wait(5), "An admitted RPC must not delay the local manual change"
        assert original_status()["mode"] == "manual"
        assert e.service.mode_lock.locked()
    finally:
        release_check.set()
        release_rpc.set()
        worker.join(timeout=5)
        if stopper.ident is not None:
            stopper.join(timeout=5)
    assert not worker.is_alive() and not stopper.is_alive() and not errors
    assert results[0]["status"] == "queued"


@pytest.mark.parametrize(
    ("kind", "uncertain"),
    [(kind, False) for kind in KINDS]
    + [(kind, True) for kind in ["automatic", "recovery", "activation_recovery"]],
)
def test_execution_and_duplicate_reads_never_hold_shared_lock_over_rpc(
    request, monkeypatch, kind, uncertain
):
    case = case_for(request, kind, uncertain=uncertain)
    patch = case.e.service
    lock = patch.mode_coordinator.mode_lock
    original = patch.invoker
    observed = []

    def invoke(target, body, **kwargs):
        assert lock.acquire(blocking=False), body["op"]
        lock.release()
        observed.append(body["op"])
        return original(target, body, **kwargs)

    monkeypatch.setattr(patch, "invoker", invoke)
    case.action()
    case.action()
    assert observed and case.sent() == 1
    if uncertain:
        assert {"status", "recovery_status", "activation_recovery_status"} & set(observed)


@pytest.mark.parametrize("kind", ["recovery", "activation_recovery"])
def test_recovery_rechecks_mode_after_network_before_releasing_local_pause(
    request, monkeypatch, kind
):
    case = case_for(request, kind)
    patch = case.e.service
    original = patch.invoker
    drifted = []

    def invoke(target, body, **kwargs):
        value = original(target, body, **kwargs)
        if body["op"] == "automatic_status" and not drifted:
            drifted.append(True)
            patch.change_mode(
                ModeChange(
                    mode="assisted", expected_revision=case.e.automation.status()["revision"]
                )
            )
        return value

    monkeypatch.setattr(patch, "invoker", invoke)
    result = case.action()
    assert drifted and result["status"] == "unknown"
    assert case.e.auto.latch(HOST) is not None
    assert not result.get("local_released", False)


def test_absent_coordinator_preserves_legacy_admission_and_rejects_reused_rpc_lock(env):
    e = env
    before = e.automation.scope, e.automation.status()["revision"]
    assert e.service.admission_lock is e.service.mode_lock
    with e.service.mode_lock, e.service.local_admission():
        assert e.service.mode_coordinator is None
    assert (e.automation.scope, e.automation.status()["revision"]) == before
    coordinator = attach_coordinator(e)
    assert e.service.admission_lock is coordinator.mode_lock
    coordinator.mode_lock = e.service.mode_lock
    with pytest.raises(ValueError, match="旧 RPC 执行锁"):
        _ = e.service.admission_lock
    with pytest.raises(ValueError, match="旧 RPC 执行锁"):
        e.service.local_admission()
