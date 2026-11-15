from threading import Event

from opsark.automation_store import AutomationStore
from opsark.config import HostConfig
from opsark.control_modes import ControlPolicy
from opsark.models import HostPublic
from opsark.patch_api import PatchService
from opsark.patch_client import PatchClientError, PatchTarget
from opsark.patch_monitor import PatchMonitor
from opsark.patch_store import PatchStore

JOB = "a" * 32


def service(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    automation = AutomationStore(
        tmp_path / "mode.db", ControlPolicy(enabled=True), driver_scope="f" * 64
    )
    public = HostPublic(id="host-a", name="Test host", address="192.0.2.6", source="ssh")
    host = HostConfig(public, tmp_path / "readonly", tmp_path / "known_hosts")
    target = PatchTarget(host, tmp_path / "repair", "e" * 64)
    return PatchService({"host-a": target}, store, automation)


def test_monitor_only_syncs_and_queries_original_registered_jobs(tmp_path):
    value = service(tmp_path)
    calls = []
    phase = ["awaiting_transport_verification", "verified"]

    def fake(_target, request, timeout=75):
        calls.append(request)
        if request["op"] == "set_mode":
            return {"mode": request["mode"], "revision": request["revision"]}
        return {"job_id": JOB, "status": phase.pop(0), "revision": len(calls)}

    value.invoker = fake
    value.store.save_job("host-a", {"job_id": JOB, "status": "queued", "revision": 0})
    value.store.save_job("not-registered", {"job_id": "b" * 32, "status": "queued"})
    monitor = PatchMonitor(value)
    monitor.poll_once()
    assert value.store.get_job("host-a", JOB)["status"] == "awaiting_transport_verification"
    monitor.poll_once()
    completed = value.store.get_job("host-a", JOB)
    assert completed["status"] == "verified" and completed["notification_count"] == 1
    monitor.poll_once()
    assert [request["op"] for request in calls] == ["set_mode", "status", "status"]
    assert all(request.get("job_id", JOB) == JOB for request in calls)


def test_lease_prevents_two_background_pollers(tmp_path):
    value = service(tmp_path)
    value.invoker = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("unexpected RPC")
    )
    other = "b" * 32
    assert value.store.claim_monitor(other)
    monitor = PatchMonitor(value)
    monitor.poll_once()
    assert value.automation.status()["mode_sync_complete"] is False
    value.store.release_monitor(other)
    assert value.store.claim_monitor(monitor.owner)
    monitor.stop()
    assert value.store.claim_monitor(other)


def test_read_failure_preserves_unknown_without_any_resubmit(tmp_path):
    value = service(tmp_path)
    value.automation.finish_sync(0)
    value.store.mark_unknown("host-a", JOB, "c" * 32)
    calls = []

    def fail(_target, request, timeout=75):
        calls.append(request["op"])
        raise PatchClientError("synthetic offline target")

    value.invoker = fail
    monitor = PatchMonitor(value)
    monitor.poll_once()
    assert calls == ["status"]
    assert value.store.get_job("host-a", JOB)["status"] == "unknown"
    assert monitor.last_error and "不会重新提交" in monitor.last_error


def test_lifecycle_stops_waiting_thread_and_does_not_submit(tmp_path):
    value = service(tmp_path)
    value.automation.finish_sync(0)
    value.store.save_job("host-a", {"job_id": JOB, "status": "queued"})
    received = Event()

    def query(_target, request, timeout=75):
        assert request["op"] == "status"
        received.set()
        return {"job_id": JOB, "status": "verified", "revision": 1}

    value.invoker = query
    monitor = PatchMonitor(value)
    monitor.start()
    assert received.wait(1)
    monitor.stop()
    assert monitor.thread is not None and not monitor.thread.is_alive()
