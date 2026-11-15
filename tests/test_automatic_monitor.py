from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from opsark.automatic_monitor import AutomaticMonitor, scope_for_automatic
from opsark.automatic_store import AutomaticStore
from opsark.config import HostConfig
from opsark.control_modes import ControlPolicy
from opsark.models import HostPublic
from opsark.patch_api import PatchService
from opsark.patch_client import PatchTarget
from opsark.patch_store import PatchStore

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)
HOST = "server-a"
ROOT_POLICY = "a" * 64


def target(host=HOST, policy=ROOT_POLICY, address="192.0.2.10"):
    config = HostConfig(
        HostPublic(id=host, name=host, address=address, source="ssh"),
        Path("readonly"),
        Path("known"),
    )
    return PatchTarget(config, Path("repair"), policy)


def finding(**updates):
    return {
        "finding_id": "b" * 64,
        "package": "libbrotli1",
        "architecture": "amd64",
        "advisory": "USN-8956-1",
        "cve": "CVE-2026-111497",
        "current_version": "1.1.0-2build2",
        "fixed_binary_version": "1.1.0-2ubuntu0.1",
        "affected": True,
        "candidate_fixable": True,
        "vendor_evidence_fresh": True,
        "finding_evidence_complete": True,
        "vendor_record_digest": "c" * 64,
        "evidence_urls": ["https://ubuntu.com/security/notices/USN-8956-1"],
        **updates,
    }


def scan(now=NOW, **updates):
    return {
        "schema_version": 1,
        "scan_id": "d" * 32,
        "host_id": HOST,
        "collected_at": now.isoformat(),
        "policy_digest": ROOT_POLICY,
        "apt_state_digest": "e" * 64,
        "apt_configuration_safe": True,
        "coverage": {"status": "partial", "all_installed_cves_checked": False},
        "findings": [finding()],
        "packages": [
            {
                "name": "libbrotli1",
                "architecture": "amd64",
                "installed_version": "1.1.0-2build2",
                "candidate_version": "1.1.0-2ubuntu0.1",
            }
        ],
        **updates,
    }


def policy(**grant_updates):
    return ControlPolicy.model_validate(
        {
            "enabled": True,
            "host_ids": [HOST],
            "allowed_actions": ["os_security_upgrade"],
            "allowed_packages": ["libbrotli1"],
            "allow_service_restart": True,
            "automatic": {
                "enabled": True,
                "grant_id": "f" * 32,
                "issued_at": (NOW - timedelta(minutes=1)).isoformat(),
                "expires_at": (NOW + timedelta(hours=1)).isoformat(),
                "host_ids": [HOST],
                "allowed_packages": ["libbrotli1"],
                "allowed_advisories": ["USN-8956-1"],
                "target_policy_digests": {HOST: ROOT_POLICY},
                "maintenance_windows": [
                    {"weekdays": list(range(7)), "start_minute": 0, "end_minute": 1440}
                ],
                "allowed_risk_levels": ["medium"],
                "allow_service_restart": True,
                "max_jobs_per_day": 2,
                "max_total_jobs": 2,
                **grant_updates,
            },
        }
    )


def plan(now=NOW, revision=3):
    return {
        "schema_version": 1,
        "host_id": HOST,
        "plan_id": "1" * 32,
        "plan_digest": "2" * 64,
        "policy_digest": ROOT_POLICY,
        "mode_revision": revision,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "state_digest": "e" * 64,
        "prepared_mode": "automatic",
        "automatic_grant_id": "f" * 32,
        "automatic_grant_digest": "3" * 64,
        "action": "os_security_upgrade",
        "risk_level": "medium",
        "requires_reboot": False,
        "requires_service_restart": True,
        "health_before": {"passed": True},
        "evidence_complete": True,
        "transaction_complete_verified": True,
        "restart_impact_verified": True,
        "finding": finding(),
        "package_changes": [
            {
                "name": "libbrotli1",
                "architecture": "amd64",
                "current_version": "1.1.0-2build2",
                "candidate_version": "1.1.0-2ubuntu0.1",
                "fixed_version": "1.1.0-2ubuntu0.1",
                "sha256": "4" * 64,
                "vendor_security_origin_verified": True,
                "candidate_contains_fixed_verified": True,
                "candidate_is_upgrade_verified": True,
                "current_is_affected_verified": True,
            }
        ],
    }


def setup(tmp_path):
    clock, calls = [NOW], []
    mode = {"mode": "automatic", "revision": 3, "mode_sync_complete": True}
    auto = AutomaticStore(tmp_path / "automatic.db")
    patches = PatchStore(tmp_path / "patch.db")
    patches.save_scan(HOST, scan())
    automation = SimpleNamespace(policy=policy(), status=lambda: dict(mode))
    service = SimpleNamespace(targets={HOST: target()}, automation=automation, store=patches)
    env = SimpleNamespace(
        clock=clock,
        calls=calls,
        mode=mode,
        store=auto,
        patches=patches,
        service=service,
        prepare_hook=None,
        submit_hook=None,
        read_hook=None,
        remote_hook=None,
        remote_reads=[],
    )

    def prepare(host_id, finding_id, revision, grant_digest):
        calls.append(("prepare", host_id, finding_id, revision, grant_digest))
        value = plan(clock[0], revision)
        if env.prepare_hook:
            return env.prepare_hook(value)
        return value

    def submit(host_id, plan_id, plan_digest, revision, grant_digest, job_id):
        calls.append(("submit", host_id, job_id))
        authorized = auto.authorize_intent(
            host_id,
            job_id,
            plan_id,
            plan_digest,
            revision,
            automation.policy.automatic.grant_id,
            grant_digest,
            now=clock[0],
        )
        assert authorized["candidate"]["state"] == "submission_intent"
        assert patches.register_submission(host_id, job_id, plan_id, plan_digest, revision)
        if env.submit_hook:
            return env.submit_hook(host_id, job_id, plan_id)
        return patches.save_job(
            host_id, {"job_id": job_id, "plan_id": plan_id, "status": "queued", "revision": 1}
        )

    def read(host_id, job_id):
        calls.append(("read", host_id, job_id))
        if env.read_hook:
            return env.read_hook(host_id, job_id)
        previous = patches.get_job(host_id, job_id)
        return patches.save_job(
            host_id,
            {"job_id": job_id, "plan_id": previous["plan_id"], "status": "verified", "revision": 2},
        )

    service.auto_prepare, service.auto_submit, service.job_status = prepare, submit, read
    service.checked_cached_automatic_job = lambda candidate: patches.get_job(
        candidate["host_id"], candidate["job_id"]
    )

    def root_safety(host_id):
        env.remote_reads.append(host_id)
        grant = automation.policy.automatic
        root_grant = grant.model_dump(
            mode="json", exclude={"host_ids", "target_policy_digests", "grant_digest"}
        )
        value = {
            "schema_version": 1,
            "host_id": host_id,
            "policy_digest": service.targets[host_id].policy_digest,
            "status": "automatic_status",
            "enabled": grant.enabled,
            "grant": root_grant,
            "grant_digest": PatchService._root_grant_digest(grant),
            "maintenance_open": True,
            "usage": {"daily_used": 0, "total_used": 0},
            "safety": {
                "schema_version": 1,
                "paused": False,
                "reason": None,
                "job_id": None,
                "updated_at": clock[0].isoformat(),
            },
        }
        if env.remote_hook:
            value = env.remote_hook(value)
        return auto.record_remote_safety(
            host_id,
            scope_for_automatic(service.targets[host_id]),
            service.targets[host_id].policy_digest,
            value,
            now=clock[0],
        )

    service.refresh_automatic_status = root_safety
    env.monitor = AutomaticMonitor(service, auto, now=lambda: clock[0])
    return env


def phases(env):
    return [call[0] for call in env.calls]


def test_fresh_partial_scan_can_submit_one_exact_patch_with_intent_before_transport(tmp_path):
    env = setup(tmp_path)
    env.monitor.poll_once()
    assert phases(env) == ["prepare", "submit"]
    value = env.store.list_attempts()[0]
    assert value["state"] == "tracking" and value["status"] == "queued"
    assert value["candidate_version"] == "1.1.0-2ubuntu0.1"
    for _ in range(4):
        env.monitor.poll_once()
    assert phases(env) == ["prepare", "submit"]
    assert env.store.quotas(HOST, "f" * 32, now=NOW)["total_used"] == 1


@pytest.mark.parametrize("mode", ["manual", "assisted"])
def test_selecting_other_modes_never_prepares_or_submits(tmp_path, mode):
    env = setup(tmp_path)
    env.mode["mode"] = mode
    env.monitor.poll_once()
    assert env.calls == [] and env.monitor.status()["hosts"][0]["state"] == "manual"


@pytest.mark.parametrize(
    "scan_update",
    [
        {"collected_at": (NOW - timedelta(seconds=901)).isoformat()},
        {"collected_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"collected_at": "2026-10-28"},
        {"policy_digest": "0" * 64},
        {"apt_configuration_safe": False},
        {"coverage": {}},
        {"coverage": {"status": "unavailable"}},
        {"scan_id": "bad"},
        {"packages": []},
        {"schema_version": True},
        {"apt_state_digest": None},
    ],
)
def test_stale_unknown_or_mismatched_scan_never_enters_planning(tmp_path, scan_update):
    env = setup(tmp_path)
    env.patches.save_scan(HOST, scan(**scan_update))
    env.monitor.poll_once()
    assert env.calls == [] and env.store.list_attempts() == []


@pytest.mark.parametrize(
    "update",
    [
        {"affected": None},
        {"affected": False},
        {"affected": 1},
        {"candidate_fixable": "true"},
        {"vendor_evidence_fresh": False},
        {"finding_evidence_complete": False},
        {"vendor_record_digest": None},
        {"advisory": "CVE-2026-111497"},
        {"package": "other"},
        {"fixed_binary_version": None},
        {"evidence_urls": []},
    ],
)
def test_only_explicit_complete_vendor_affected_evidence_is_eligible(tmp_path, update):
    env = setup(tmp_path)
    env.patches.save_scan(HOST, scan(findings=[finding(**update)]))
    env.monitor.poll_once()
    assert env.calls == []


@pytest.mark.parametrize(
    "update",
    [
        {"requires_reboot": True},
        {"requires_service_restart": "false"},
        {"evidence_complete": False},
        {"transaction_complete_verified": False},
        {"restart_impact_verified": False},
        {"risk_level": "low"},
        {"prepared_mode": "assisted"},
        {"mode_revision": True},
        {"automatic_grant_id": "5" * 32},
        {"plan_digest": None},
        {"expires_at": (NOW + timedelta(minutes=31)).isoformat()},
        {"state_digest": "5" * 64},
        {"health_before": {"passed": False}},
    ],
)
def test_changed_or_incomplete_plan_is_deferred_and_cannot_install(tmp_path, update):
    env = setup(tmp_path)
    env.prepare_hook = lambda value: value | update
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]
    assert env.store.list_attempts()[0]["state"] == "deferred"
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]


def test_state_drift_requires_new_scan_and_new_plan_before_original_candidate_can_submit(tmp_path):
    env = setup(tmp_path)

    def rejected(_plan):
        raise HTTPException(409, "state changed")

    env.prepare_hook = rejected
    env.monitor.poll_once()
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]
    env.prepare_hook = None
    env.patches.save_scan(HOST, scan(scan_id="6" * 32))
    env.monitor.poll_once()
    assert phases(env) == ["prepare", "prepare", "submit"]


def test_mode_revision_or_expiry_changing_during_prepare_cannot_be_submitted(tmp_path):
    env = setup(tmp_path)

    def mode_changed(value):
        env.mode.update(mode="manual", revision=4)
        return value

    env.prepare_hook = mode_changed
    env.monitor.poll_once()
    assert phases(env) == ["prepare"] and env.store.list_attempts()[0]["state"] == "deferred"


@pytest.mark.parametrize(
    "key",
    [
        "vendor_security_origin_verified",
        "candidate_contains_fixed_verified",
        "candidate_is_upgrade_verified",
        "current_is_affected_verified",
    ],
)
def test_no_candidate_verification_flag_is_optional_in_automatic_mode(tmp_path, key):
    env = setup(tmp_path)

    def unproven(value):
        value["package_changes"][0][key] = False
        return value

    env.prepare_hook = unproven
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]


@pytest.mark.parametrize("change", ["scan_replaced", "scan_expired", "candidate_changed"])
def test_evidence_changed_while_preparing_cannot_enter_submission_intent(tmp_path, change):
    env = setup(tmp_path)

    def changed(value):
        if change == "scan_replaced":
            env.patches.save_scan(HOST, scan(scan_id="8" * 32))
        elif change == "scan_expired":
            env.clock[0] += timedelta(seconds=901)
        else:
            value["package_changes"][0]["candidate_version"] = "1.1.0-2ubuntu0.2"
        return value

    env.prepare_hook = changed
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]
    assert env.store.list_attempts()[0]["state"] == "deferred"


def test_transport_unknown_latches_then_reads_original_id_without_resubmit_across_restart(tmp_path):
    env = setup(tmp_path)

    def lost(*_args):
        raise OSError("lost transport and potentially secret exception text")

    env.submit_hook = lost
    env.monitor.poll_once()
    first = env.store.list_attempts()[0]
    assert env.store.latch(HOST) is not None and first["status"] == "unknown"
    env.monitor.stop()
    restarted = AutomaticMonitor(env.service, AutomaticStore(env.store.path), now=lambda: NOW)
    restarted.poll_once()
    assert phases(env) == ["prepare", "submit", "read"]
    assert env.calls[-1][2] == first["job_id"]
    assert env.store.get(first["id"])["status"] == "verified"
    assert restarted.status()["hosts"][0]["state"] == "latched"
    assert "secret" not in str(restarted.status())


def test_crash_after_durable_intent_before_any_send_does_not_install_on_restart(tmp_path):
    env = setup(tmp_path)

    class Crash(BaseException):
        pass

    def crashed(*_args):
        raise Crash()

    env.service.auto_submit = crashed
    with pytest.raises(Crash):
        env.monitor.poll_once()
    first = env.store.list_attempts()[0]
    assert (
        first["state"] == "submission_intent" and env.patches.get_job(HOST, first["job_id"]) is None
    )
    env.monitor.stop()

    def not_found(host, job):
        raise HTTPException(404, "not found")

    env.read_hook = not_found
    restarted = AutomaticMonitor(env.service, env.store, now=lambda: NOW)
    restarted.poll_once()
    assert phases(env) == ["prepare", "read"]
    assert env.store.latch(HOST)["job_id"] == first["job_id"]


def test_active_assisted_task_blocks_new_auto_but_old_assisted_rejection_does_not_latch(tmp_path):
    env = setup(tmp_path)
    env.patches.save_job(
        HOST, {"job_id": "7" * 32, "plan_id": "8" * 32, "status": "applying", "revision": 1}
    )
    env.monitor.poll_once()
    assert env.calls == []
    env.patches.save_job(
        HOST, {"job_id": "7" * 32, "plan_id": "8" * 32, "status": "rejected", "revision": 2}
    )
    env.monitor.poll_once()
    assert phases(env) == ["prepare", "submit"] and env.store.latch(HOST) is None


def test_bound_target_change_and_unsynced_mode_block_before_prepare(tmp_path):
    env = setup(tmp_path)
    env.mode["mode_sync_complete"] = False
    env.monitor.poll_once()
    assert env.calls == []
    env.mode["mode_sync_complete"] = True
    env.service.targets[HOST] = target(policy="8" * 64)
    env.monitor.poll_once()
    assert env.calls == [] and env.monitor.status()["hosts"][0]["state"] == "disabled"


@pytest.mark.parametrize(
    "grant_update,state",
    [
        ({"enabled": False}, "disabled"),
        ({"expires_at": NOW.isoformat()}, "expired"),
        (
            {
                "maintenance_windows": [
                    {"weekdays": list(range(7)), "start_minute": 0, "end_minute": 60}
                ]
            },
            "outside_window",
        ),
    ],
)
def test_grant_window_and_expiration_are_checked_before_prepare(tmp_path, grant_update, state):
    env = setup(tmp_path)
    env.service.automation.policy = policy(**grant_update)
    env.monitor.poll_once()
    assert env.calls == [] and env.monitor.status()["hosts"][0]["state"] == state


def test_disabled_status_shape_is_stable_and_does_not_poll_or_install(tmp_path):
    env = setup(tmp_path)
    env.service.automation.policy = ControlPolicy()
    env.monitor.poll_once()
    value = env.monitor.status()
    assert value["enabled"] is False and value["mode_revision"] == 3
    assert value["mode_sync_complete"] is True and value["notification_channel"] == "console"
    assert value["grants"] == value["latched_hosts"] == value["jobs"] == []
    assert value["hosts"][0]["quota"]["daily_used"] is None and env.calls == []


def test_stop_during_preparation_never_submits_the_completed_plan(tmp_path):
    env = setup(tmp_path)

    def stop(value):
        env.monitor.stop_event.set()
        return value

    env.prepare_hook = stop
    env.monitor.poll_once()
    assert phases(env) == ["prepare"]
    assert env.store.list_attempts()[0]["submitted_day"] is None
    assert env.store.list_attempts()[0]["state"] == "deferred"


def test_source_identity_change_does_not_clear_safety_latch(tmp_path):
    env = setup(tmp_path)
    env.submit_hook = lambda host, job, plan_id: {
        "host_id": host,
        "job_id": job,
        "plan_id": plan_id,
        "status": "verification_failed",
        "revision": 1,
    }
    env.monitor.poll_once()
    old = scope_for_automatic(env.service.targets[HOST])
    env.service.targets[HOST] = target(address="192.0.2.11")
    env.monitor.poll_once()
    value = env.monitor.status()
    assert value["hosts"][0]["scope_hash"] != old
    assert value["hosts"][0]["state"] == "latched" and len(phases(env)) == 2
    env.service.targets.clear()
    assert env.monitor.status()["hosts"] == [] and len(env.monitor.status()["latched_hosts"]) == 1
