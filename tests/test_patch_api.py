import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from opsark import main, patch_api
from opsark.automation_store import AutomationStore, ModeChange
from opsark.config import HostConfig, Settings, load_patch_targets, load_settings
from opsark.control_modes import ControlPolicy
from opsark.models import HostPublic
from opsark.patch_client import PatchClientError, UnknownPatchResult

TOKEN = "synthetic-patch-api-console-token"
POLICY = "a" * 64
FINDING = "b" * 64
PLAN = "c" * 32
DIGEST = "d" * 64
JOB = "e" * 32
HEADERS = {"Authorization": "Bearer " + TOKEN}


class Remote:
    def __init__(self):
        self.calls = []
        self.mode = "manual"
        self.revision = 0
        self.fail_sync = False
        self.unknown_submit = False
        self.job = None
        self.scan_entered = threading.Event()
        self.scan_release = threading.Event()
        self.hold_scan = False
        self.expired = False

    def plan(self):
        return {
            "schema_version": 1,
            "host_id": "host-a",
            "plan_id": PLAN,
            "plan_digest": DIGEST,
            "policy_digest": POLICY,
            "mode_revision": self.revision,
            "action": "os_security_upgrade",
            "expires_at": (
                datetime.now(UTC) + timedelta(minutes=-1 if self.expired else 20)
            ).isoformat(),
            "package_changes": [{"name": "demo", "current_version": "1", "candidate_version": "2"}],
            "requires_service_restart": True,
            "requires_reboot": False,
            "restart_assessment": "possible",
            "risk_level": "medium",
        }

    def __call__(self, target, request, timeout=75):
        self.calls.append(copy.deepcopy(request))
        assert target.host.public.id == "host-a"
        assert request["policy_digest"] == POLICY
        if request["op"] == "set_mode":
            if self.fail_sync:
                raise PatchClientError("synthetic sync failure")
            self.mode, self.revision = request["mode"], request["revision"]
            return {"mode": self.mode, "revision": self.revision}
        if request["op"] == "scan":
            self.scan_entered.set()
            if self.hold_scan:
                assert self.scan_release.wait(3)
            return {
                "host_id": "host-a",
                "coverage": "complete",
                "findings": [{"finding_id": FINDING}],
            }
        if request["op"] == "prepare":
            assert request["finding_id"] == FINDING and request["mode_revision"] == self.revision
            return self.plan()
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
            self.job = {
                "host_id": "host-a",
                "job_id": request["job_id"],
                "plan_id": request["plan_id"],
                "plan_digest": request["plan_digest"],
                "status": "queued",
                "revision": 1,
            }
            if self.unknown_submit:
                raise UnknownPatchResult("submit", request["job_id"])
            return copy.deepcopy(self.job)
        if request["op"] == "status":
            assert request["job_id"] == JOB
            return copy.deepcopy(self.job)
        raise AssertionError("Unexpected operation")


@pytest.fixture
def configured(tmp_path, monkeypatch):
    readonly = tmp_path / "readonly.key"
    repair = tmp_path / "repair.key"
    known = tmp_path / "known_hosts"
    readonly.write_text("synthetic readonly credential")
    repair.write_text("synthetic repair credential")
    known.write_text("synthetic trusted host records")
    host = HostConfig(
        HostPublic(
            id="host-a",
            name="synthetic host",
            address="192.0.2.30",
            source="ssh",
            trusted_hosts_digest=hashlib.sha256(known.read_bytes()).hexdigest(),
        ),
        readonly,
        known,
    )
    inventory = tmp_path / "patch-targets.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "targets": {"host-a": {"key_file": str(repair), "policy_digest": POLICY}},
            }
        )
    )
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "enabled": True,
                "host_ids": ["host-a"],
                "allowed_actions": ["os_security_upgrade"],
                "allowed_packages": ["demo"],
                "max_packages_per_job": 1,
                "allow_service_restart": True,
            }
        )
    )
    settings = Settings(
        data_dir=tmp_path / "data",
        token=TOKEN,
        patch_inventory_path=inventory,
        automation_policy_path=policy_file,
    )
    remote = Remote()
    monkeypatch.setattr(main, "load_hosts", lambda _: {"host-a": host})
    monkeypatch.setattr(patch_api, "invoke", remote)
    app = main.create_app(settings)
    return TestClient(app), app, remote, settings, host


def mode(client, value="assisted"):
    current = client.get("/api/automation", headers=HEADERS).json()
    return client.put(
        "/api/automation",
        headers=HEADERS,
        json={"mode": value, "expected_revision": current["revision"]},
    )


def prepare(client):
    return client.post(
        "/api/remediation/plans", headers=HEADERS, json={"host_id": "host-a", "finding_id": FINDING}
    )


def submit_body(revision=1, **changes):
    return {
        "host_id": "host-a",
        "plan_id": PLAN,
        "expected_plan_digest": DIGEST,
        "expected_mode_revision": revision,
        "confirm_execute": True,
        "job_id": JOB,
    } | changes


def test_no_driver_is_explicit_and_new_routes_require_auth(tmp_path):
    client = TestClient(main.create_app(Settings(data_dir=tmp_path, token=TOKEN)))
    assert client.get("/api/remediation").status_code == 401
    assert client.post("/api/remediation/scans", json={"host_id": "x"}).status_code == 401
    status = client.get("/api/remediation", headers=HEADERS).json()
    assert status["configured"] is False and status["execution_available"] is False
    assert status["supported_execution_modes"] == []
    assert (
        client.get("/api/capabilities", headers=HEADERS).json()["vulnerability_remediation"] is True
    )


def test_scan_persists_without_changing_mode_or_creating_jobs(configured):
    client, app, remote, _, _ = configured
    response = client.post("/api/remediation/scans", headers=HEADERS, json={"host_id": "host-a"})
    assert response.status_code == 200
    assert [call["op"] for call in remote.calls] == ["scan"]
    status = client.get("/api/remediation", headers=HEADERS).json()
    assert status["hosts"][0]["scan"]["coverage"] == "complete"
    assert status["jobs"] == [] and app.state.automation_store.status()["mode"] == "manual"


def test_real_driver_resets_old_mode_and_requires_root_sync_before_availability(tmp_path):
    path = tmp_path / "automation.db"
    policy = ControlPolicy(enabled=True)
    old = AutomationStore(path, policy)
    old.change_mode(ModeChange(mode="automatic", expected_revision=0))
    active = AutomationStore(path, policy, driver_scope="f" * 64)
    status = active.status()
    assert status["mode"] == "manual" and status["revision"] == 2
    assert status["execution_available"] is False
    active.finish_sync(2)
    assert active.status()["execution_available"] is True
    assert active.status()["supported_execution_modes"] == ["assisted"]
    assert AutomationStore(path, policy, driver_scope="e" * 64).status()["mode"] == "manual"


def test_assisted_plan_approval_submit_and_fresh_status_closed_loop(configured):
    client, app, remote, _, _ = configured
    selected = mode(client)
    assert selected.status_code == 200 and selected.json()["mode_sync_complete"] is True
    response = prepare(client)
    assert response.status_code == 200 and response.json()["plan_id"] == PLAN
    result = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body())
    assert result.status_code == 200 and result.json()["status"] == "queued"
    duplicate = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body())
    assert duplicate.status_code == 202
    assert sum(call["op"] == "submit" for call in remote.calls) == 1
    remote.job.update(status="verified", revision=2)
    checked = client.get(f"/api/remediation/jobs/host-a/{JOB}", headers=HEADERS)
    assert checked.status_code == 200 and checked.json()["status"] == "verified"
    assert checked.json()["notification_due"] is True
    again = client.get(f"/api/remediation/jobs/host-a/{JOB}", headers=HEADERS)
    assert again.json()["notification_due"] is False and again.json()["notification_count"] == 1
    assert app.state.patch_store.list_jobs()[0]["status"] == "verified"


@pytest.mark.parametrize("chosen", ["manual", "automatic"])
def test_only_assisted_can_submit_even_if_another_mode_was_saved(configured, chosen):
    client, _, remote, _, _ = configured
    selected = mode(client, chosen)
    assert selected.status_code == 200
    assert prepare(client).status_code == (409 if chosen == "automatic" else 200)
    response = client.post(
        "/api/remediation/jobs", headers=HEADERS, json=submit_body(selected.json()["revision"])
    )
    assert response.status_code == 409
    assert not any(call["op"] == "submit" for call in remote.calls)


def test_lost_submit_is_durable_unknown_and_original_job_is_queried(configured):
    client, app, remote, _, _ = configured
    assert mode(client).status_code == 200 and prepare(client).status_code == 200
    remote.unknown_submit = True
    response = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body())
    assert response.status_code == 202 and response.json()["status"] == "unknown"
    assert response.json()["job_id"] == JOB
    assert app.state.patch_store.get_job("host-a", JOB)["transport_unknown"] is True
    assert (
        client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body()).status_code == 202
    )
    assert sum(call["op"] == "submit" for call in remote.calls) == 1
    remote.job.update(status="awaiting_transport_verification", revision=2)
    assert (
        client.get(f"/api/remediation/jobs/host-a/{JOB}", headers=HEADERS).json()["status"]
        == "awaiting_transport_verification"
    )
    remote.job.update(status="reboot_pending", revision=3)
    assert (
        client.get(f"/api/remediation/jobs/host-a/{JOB}", headers=HEADERS).json()["status"]
        == "reboot_pending"
    )


def test_mode_sync_failure_blocks_new_jobs_and_manual_choice_stops_locally(configured):
    client, app, remote, _, _ = configured
    remote.fail_sync = True
    response = mode(client)
    assert response.status_code == 503
    status = client.get("/api/automation", headers=HEADERS).json()
    assert status["mode"] == "assisted" and status["mode_sync_complete"] is False
    assert status["execution_available"] is False
    assert (
        client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body()).status_code == 409
    )
    assert mode(client, "manual").status_code == 503
    pending = app.state.automation_store.status()
    assert pending["mode"] == "manual" and not pending["mode_sync_complete"]
    remote.fail_sync = False
    before_sync = len(remote.calls)
    response = mode(client, "manual")
    assert response.status_code == 200
    synchronized = response.json()
    assert synchronized["mode_sync_complete"] is True
    assert synchronized["mode"] == pending["mode"]
    assert synchronized["revision"] == pending["revision"]
    assert synchronized["policy"] == pending["policy"]
    assert [call["op"] for call in remote.calls[before_sync:]] == ["set_mode"]


@pytest.mark.parametrize(
    "changes",
    [
        {"confirm_execute": False},
        {"confirm_execute": 1},
        {"command": "apt-get upgrade"},
        {"expected_mode_revision": True},
        {"job_id": "../job"},
    ],
)
def test_approval_schema_rejects_implicit_or_extra_authority(configured, changes):
    client, _, remote, _, _ = configured
    response = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body(**changes))
    assert response.status_code == 422 and remote.calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"expected_mode_revision": 0},
        {"expected_plan_digest": "0" * 64},
    ],
)
def test_changed_approval_cannot_execute(configured, changes):
    client, _, remote, _, _ = configured
    assert mode(client).status_code == 200 and prepare(client).status_code == 200
    assert (
        client.post(
            "/api/remediation/jobs", headers=HEADERS, json=submit_body(**changes)
        ).status_code
        == 409
    )
    assert not any(call["op"] == "submit" for call in remote.calls)


def test_local_package_and_restart_permissions_cannot_be_bypassed(configured):
    client, app, remote, _, _ = configured
    assert mode(client).status_code == 200 and prepare(client).status_code == 200
    original = app.state.automation_store.policy
    for changes in (
        {"allowed_packages": ("other",)},
        {"allow_service_restart": False},
        {"enabled": False},
        {"host_ids": ()},
        {"allowed_actions": ()},
    ):
        app.state.automation_store.policy = ControlPolicy.model_validate(
            original.model_dump() | changes
        )
        assert (
            client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body()).status_code
            == 403
        )
    assert not any(call["op"] == "submit" for call in remote.calls)


def test_expired_plan_is_not_saved_as_executable(configured):
    client, app, remote, _, _ = configured
    assert mode(client).status_code == 200
    remote.expired = True
    assert prepare(client).status_code == 409
    assert app.state.patch_store.get_plan("host-a", PLAN) is None


def test_scan_does_not_block_switching_mode(configured):
    client, _, remote, _, _ = configured
    remote.hold_scan = True
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(
            client.post, "/api/remediation/scans", headers=HEADERS, json={"host_id": "host-a"}
        )
        assert remote.scan_entered.wait(1)
        try:
            assert mode(client).status_code == 200
            assert not pending.done()
        finally:
            remote.scan_release.set()
        assert pending.result(timeout=2).status_code == 200


def test_config_uses_only_registered_hosts_absolute_distinct_keys_and_env(configured, monkeypatch):
    _, _, _, settings, host = configured
    assert load_patch_targets(settings, {"host-a": host})["host-a"].host is host
    monkeypatch.setenv("OPSARK_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("OPSARK_PATCH_INVENTORY", str(settings.patch_inventory_path))
    assert load_settings().patch_inventory_path == settings.patch_inventory_path
    good = json.loads(settings.patch_inventory_path.read_text())
    for invalid in (
        {"schema_version": True, "targets": {}},
        {"schema_version": 1, "targets": {"unknown": good["targets"]["host-a"]}},
        {
            "schema_version": 1,
            "targets": {"host-a": {"key_file": "relative", "policy_digest": POLICY}},
        },
        {
            "schema_version": 1,
            "targets": {"host-a": {"key_file": str(host.key_file), "policy_digest": POLICY}},
        },
        {
            "schema_version": 1,
            "targets": {"host-a": good["targets"]["host-a"] | {"address": "other"}},
        },
    ):
        settings.patch_inventory_path.write_text(json.dumps(invalid))
        with pytest.raises(ValueError):
            load_patch_targets(settings, {"host-a": host})


def test_remediation_cross_origin_and_unknown_host_are_rejected(configured):
    client, _, remote, _, _ = configured
    response = client.post(
        "/api/remediation/scans",
        json={"host_id": "host-a"},
        headers=HEADERS | {"Origin": "https://untrusted.invalid"},
    )
    assert response.status_code == 403
    assert (
        client.post(
            "/api/remediation/scans", headers=HEADERS, json={"host_id": "unknown"}
        ).status_code
        == 404
    )
    assert remote.calls == []


def test_explicit_remote_refusal_closes_intent_without_claiming_installation(configured):
    client, app, remote, _, _ = configured
    assert mode(client).status_code == 200 and prepare(client).status_code == 200
    original = remote.__call__

    def busy(target, request, timeout=75):
        if request["op"] == "submit":
            return {"status": "busy"}
        return original(target, request, timeout)

    app.state.patch_service.invoker = busy
    response = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body())
    assert response.status_code == 409
    assert response.json()["status"] == "rejected"
    assert response.json()["remote_job_created"] is False
    assert app.state.patch_store.pollable_jobs() == []


def test_unresolved_intent_is_queried_after_service_restart_without_resubmit(configured):
    client, app, remote, _, _ = configured
    assert mode(client).status_code == 200 and prepare(client).status_code == 200
    store = app.state.patch_store
    assert store.register_submission("host-a", JOB, PLAN, DIGEST, 1)
    result = client.post("/api/remediation/jobs", headers=HEADERS, json=submit_body())
    assert result.status_code == 202 and result.json()["status"] == "unknown"
    assert not any(call["op"] == "submit" for call in remote.calls)
