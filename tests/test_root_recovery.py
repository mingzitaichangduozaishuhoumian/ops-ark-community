"""Exact manual recovery receipts without APT, SSH, service changes or real root files."""

import copy
import hashlib
import json
from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, NOW, STATE, load_module, prepare
from test_patch_agent import remote as remote

CTX = "d" * 64


@pytest.fixture
def recovery_env(remote, monkeypatch):
    core = remote.core
    scan = load_module("scan", "scan.py", monkeypatch)
    monkeypatch.setattr(core, "load_scan_module", lambda: scan)
    monkeypatch.setattr(core, "lock", lambda *_a, **_kw: nullcontext())
    remote.policy["driver_source_digest"] = "1" * 64
    latest = core.read_json(remote.path / "latest-scan.json")
    latest["driver_source_digest"] = remote.policy["driver_source_digest"]
    core.write_json(remote.path / "latest-scan.json", latest)
    mode = core.read_json(remote.path / "mode.json")
    mode["policy_digest"] = core.policy_digest(remote.policy)
    core.write_json(remote.path / "mode.json", mode)
    plan = prepare(remote)
    folder = remote.path / "jobs" / JOB
    folder.mkdir()
    core.write_json(folder / "plan.json", plan)
    manifest = {
        "schema_version": 1,
        "job_id": JOB,
        "package": "curl",
        "architecture": "amd64",
        "version": remote.change["current_version"],
        "paths": ["/usr/bin/curl"],
    }
    core.write_json(folder / "runtime-files-before.json", manifest)
    job = {
        "schema_version": 1,
        "job_id": JOB,
        "host_id": remote.policy["host_id"],
        "authorization": "automatic",
        "automatic_grant_id": "e" * 32,
        "plan_id": plan["plan_id"],
        "plan_digest": plan["plan_digest"],
        "status": "verified",
        "revision": 7,
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "history": [
            {"status": "queued", "at": NOW.isoformat()},
            {"status": "verified", "at": NOW.isoformat()},
        ],
        "install_exit_code": 0,
        "verification": {"fresh_ssh": {"passed": True}},
        "runtime_files_before_sha256": core.digest(manifest),
    }
    core.write_json(folder / "job.json", job)
    mode["mode"] = "manual"
    core.write_json(remote.path / "mode.json", mode)
    remote.inventory["packages"] = [
        {
            "name": "curl",
            "architecture": "amd64",
            "installed_version": remote.change["candidate_version"],
        }
    ]
    load_module("transaction_hook", "transaction_hook.py", monkeypatch)
    worker = load_module("worker", "worker.py", monkeypatch)
    calls = []
    monkeypatch.setattr(worker, "package_files", lambda _p: ["/usr/bin/curl"])
    monkeypatch.setattr(
        worker,
        "runtime_maps",
        lambda paths: (
            calls.append(paths) or {"status": "complete", "outdated_process_count": 0, "gaps": []}
        ),
    )
    health = {
        "passed": True,
        "dpkg_healthy": True,
        "services": [{"service": "ssh.service", "active": True}],
        "http": [{"id": "lab", "passed": True, "status": 200}],
        "reboot_required": False,
    }
    monkeypatch.setattr(core, "health", lambda _p: copy.deepcopy(health))
    assessment = {
        "scan_id": "2" * 32,
        "findings": [
            {
                **remote.finding,
                "affected": False,
                "vendor_evidence_fresh": True,
                "finding_evidence_complete": True,
            }
        ],
        "coverage": {"status": "partial", "all_installed_cves_checked": False},
        "gaps": ["usn_recent_or_requested_window_only"],
    }
    monkeypatch.setattr(core, "scan_packages", lambda **_kw: copy.deepcopy(assessment))
    monkeypatch.setattr(core, "fresh_ssh_connection", lambda *_args: True)
    monkeypatch.setattr(
        core, "read_command", lambda *_a, **_kw: pytest.fail("No external command is allowed")
    )
    monkeypatch.setenv("SUDO_USER", "opsark-repair")
    recovery = load_module("recovery", "recovery.py", monkeypatch)
    monkeypatch.setattr(
        recovery, "transport_challenge", lambda: {"boot_id": "fixture-boot", "uptime_ticks": 100}
    )
    return SimpleNamespace(
        **vars(remote),
        recovery=recovery,
        worker=worker,
        folder=folder,
        job=job,
        plan=plan,
        health=health,
        assessment=assessment,
        calls=calls,
    )


def preview(env):
    return env.recovery.prepare(
        {"job_id": JOB, "mode_revision": 0, "context_digest": CTX}, env.policy
    )


def commit(env, plan):
    return env.recovery.submit(
        {k: plan[k] for k in ("recovery_id", "recovery_digest", "mode_revision", "context_digest")},
        env.policy,
    )


def write_job(env, **fields):
    job = env.core.read_json(env.folder / "job.json")
    job.update(fields)
    env.core.write_json(env.folder / "job.json", job)
    return job


def test_manual_recovery_of_controller_only_pause_has_complete_immutable_proof(recovery_env):
    e = recovery_env
    before = (e.folder / "job.json").read_bytes()
    plan = preview(e)
    assert plan["eligible"] and plan["blockers"] == []
    assert plan["context_digest"] == CTX and plan["state_digest"] == STATE
    assert plan["root_safety_before"]["paused"] is False
    assert (
        e.core.digest({k: v for k, v in plan.items() if k != "recovery_digest"})
        == plan["recovery_digest"]
    )
    result = commit(e, plan)
    assert result["status"] == "verified" and result["blockers"] == []
    assert result["verified_job"] == {
        "job_id": JOB,
        "revision": 7,
        "job_digest": e.core.digest(e.job),
        "status": "verified",
    }
    assert e.recovery.validate_receipt(result) == result
    assert e.recovery.status(plan["recovery_id"]) == result
    assert result["resolved_safety_digest"] == plan["root_safety_digest"]
    assert result["safety_after_digest"] == e.recovery.safety_digest(
        e.agent.automatic_policy.safety_state()
    )
    assert (e.folder / "job.json").read_bytes() == before
    assert e.agent.mode_state()["mode"] == "manual"
    assert e.agent.automatic_policy.usage({"grant_id": "e" * 32}) == {
        "daily_used": 1,
        "total_used": 1,
    }
    assert len(list((e.path / "jobs").iterdir())) == 1


def test_root_pause_history_survives_and_exact_approved_job_no_longer_relatches(recovery_env):
    e = recovery_env
    job = write_job(
        e,
        history=[
            {"status": "running_overdue", "at": NOW.isoformat()},
            {"status": "verified", "at": NOW.isoformat()},
        ],
    )
    paused = e.agent.automatic_policy.safety_state()
    assert paused["paused"] and paused["job_id"] == JOB
    result = commit(e, preview(e))
    assert result["status"] == "verified" and result["safety_before"] == paused
    assert e.core.read_json(e.folder / "job.json") == job
    assert e.core.read_json(e.path / "automatic-state.json")["paused"] is False
    assert e.agent.automatic_policy.safety_state()["paused"] is False
    assert e.agent.automatic_policy.safety_state()["paused"] is False
    write_job(e, status="unknown", revision=8)
    new = e.agent.automatic_policy.safety_state()
    assert new["paused"] and new["reason"] == "automatic_job_unknown"


def test_false_safety_digest_is_stable_without_weakening_real_pause_binding(recovery_env):
    e = recovery_env
    old = e.agent.automatic_policy.safety_state()
    new = old | {"updated_at": (NOW + timedelta(seconds=1)).isoformat()}
    assert e.recovery.safety_digest(old) == e.recovery.safety_digest(new)
    paused = old | {"paused": True, "job_id": JOB, "reason": "automatic_job_unknown"}
    assert e.recovery.safety_digest(paused) != e.recovery.safety_digest(
        paused | {"updated_at": new["updated_at"]}
    )


@pytest.mark.parametrize(
    "status",
    [
        "unknown",
        "failed",
        "rejected",
        "verification_failed",
        "reboot_pending",
        "installed_restart_pending",
        "applying",
        "awaiting_transport_verification",
    ],
)
def test_unverified_original_task_is_ineligible_and_cannot_be_marked_verified(recovery_env, status):
    e = recovery_env
    before = write_job(e, status=status)
    plan = preview(e)
    assert plan["eligible"] is False and "original_job_verified" in plan["blockers"]
    with pytest.raises(e.core.Rejected, match="ineligible"):
        commit(e, plan)
    assert e.core.read_json(e.folder / "job.json") == before
    assert len(list((e.path / "jobs").iterdir())) == 1


@pytest.mark.parametrize(
    "kind",
    [
        "missing_manifest",
        "manifest_digest",
        "manifest_package",
        "manifest_version",
        "manifest_path",
        "wrong_version",
        "unsafe_apt",
        "reboot",
        "health",
        "runtime_incomplete",
        "runtime_old",
        "affected",
        "vendor_stale",
        "vendor_incomplete",
        "vendor_absent",
        "prior_ssh",
        "install_exit",
    ],
)
def test_current_evidence_must_pass_and_cannot_be_bypassed_by_confirmation(
    recovery_env, monkeypatch, kind
):
    e = recovery_env
    if kind == "missing_manifest":
        (e.folder / "runtime-files-before.json").unlink()
    elif kind == "manifest_digest":
        write_job(e, runtime_files_before_sha256="0" * 64)
    elif kind.startswith("manifest_"):
        value = e.core.read_json(e.folder / "runtime-files-before.json")
        value[
            {
                "manifest_package": "package",
                "manifest_version": "version",
                "manifest_path": "paths",
            }[kind]
        ] = ["/usr/lib/../../etc/passwd"] if kind == "manifest_path" else "different"
        e.core.write_json(e.folder / "runtime-files-before.json", value)
        write_job(e, runtime_files_before_sha256=e.core.digest(value))
    elif kind == "wrong_version":
        e.inventory["packages"][0]["installed_version"] = e.change["current_version"]
    elif kind == "unsafe_apt":
        e.inventory["apt_configuration_safe"] = False
    elif kind == "reboot":
        e.health["reboot_required"] = True
    elif kind == "health":
        e.health["passed"] = False
    elif kind.startswith("runtime_"):
        monkeypatch.setattr(
            e.worker,
            "runtime_maps",
            lambda _p: {
                "status": "incomplete" if kind == "runtime_incomplete" else "complete",
                "outdated_process_count": 1 if kind == "runtime_old" else 0,
            },
        )
    elif kind == "affected":
        e.assessment["findings"][0]["affected"] = True
    elif kind == "vendor_stale":
        e.assessment["findings"][0]["vendor_evidence_fresh"] = False
    elif kind == "vendor_incomplete":
        e.assessment["findings"][0]["finding_evidence_complete"] = False
    elif kind == "vendor_absent":
        e.assessment["findings"] = []
    elif kind == "prior_ssh":
        write_job(e, verification={"fresh_ssh": {"passed": False}})
    elif kind == "install_exit":
        write_job(e, install_exit_code=1)
    plan = preview(e)
    assert plan["eligible"] is False and plan["blockers"]
    with pytest.raises(e.core.Rejected, match="ineligible"):
        commit(e, plan)


def test_old_and_new_package_paths_both_reach_current_runtime_inspection(recovery_env, monkeypatch):
    e = recovery_env
    manifest = e.core.read_json(e.folder / "runtime-files-before.json")
    manifest["paths"] = ["/usr/lib/old-version.so"]
    e.core.write_json(e.folder / "runtime-files-before.json", manifest)
    write_job(e, runtime_files_before_sha256=e.core.digest(manifest))
    monkeypatch.setattr(e.worker, "package_files", lambda _p: ["/usr/lib/new-version.so"])
    assert preview(e)["eligible"] is True
    assert e.calls[-1] == ["/usr/lib/old-version.so", "/usr/lib/new-version.so"]


@pytest.mark.parametrize(
    "kind",
    [
        "unknown",
        "failed",
        "verified_bad_history",
        "assisted_applying",
        "assisted_rejected_install_log",
    ],
)
def test_any_other_unreconciled_transaction_blocks_recovery(recovery_env, kind):
    e = recovery_env
    other = dict(e.job, job_id="b" * 32)
    if kind.startswith("assisted_"):
        other["authorization"] = "assisted"
        other["status"] = "applying" if kind == "assisted_applying" else "rejected"
    else:
        other["status"] = "verified" if kind == "verified_bad_history" else kind
    if kind == "verified_bad_history":
        other["history"] = [{"status": "unknown"}, {"status": "verified"}]
    folder = e.path / "jobs" / other["job_id"]
    folder.mkdir()
    if kind == "assisted_rejected_install_log":
        other.pop("install_exit_code")
        other["history"] = [{"status": "rejected"}]
        (folder / "install.log").write_text("installation may have started")
    e.core.write_json(folder / "job.json", other)
    assert "ledger_settled" in preview(e)["blockers"]


def test_legacy_assisted_rejection_before_installation_does_not_block_forever(recovery_env):
    e = recovery_env
    folder = e.path / "jobs" / ("b" * 32)
    folder.mkdir()
    e.core.write_json(
        folder / "job.json",
        {
            "job_id": "b" * 32,
            "status": "rejected",
            "history": [{"status": "preflight"}, {"status": "rejected"}],
        },
    )
    assert preview(e)["eligible"] is True


@pytest.mark.parametrize("mode", ["assisted", "automatic"])
def test_preview_and_confirmation_require_manual_mode(recovery_env, mode):
    e = recovery_env
    plan = preview(e)
    state = e.core.read_json(e.path / "mode.json")
    state["mode"] = mode
    e.core.write_json(e.path / "mode.json", state)
    with pytest.raises(e.core.Rejected, match="manual"):
        preview(e)
    with pytest.raises(e.core.Rejected, match="manual"):
        commit(e, plan)


@pytest.mark.parametrize("field", ["recovery_digest", "context_digest", "mode_revision"])
def test_approval_must_match_exact_preview(recovery_env, field):
    e = recovery_env
    plan = preview(e)
    changed = dict(plan)
    changed[field] = 1 if field == "mode_revision" else "0" * 64
    with pytest.raises(e.core.Rejected, match="exact"):
        commit(e, changed)
    assert not (e.path / "recovery-receipts").exists()


@pytest.mark.parametrize(
    "kind", ["expired", "job_revision", "apt_state", "old_ssh", "missing_ssh_user"]
)
def test_changed_commit_conditions_leave_an_idempotent_rejected_receipt(
    recovery_env, monkeypatch, kind
):
    e = recovery_env
    plan = preview(e)
    if kind == "expired":
        monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=6))
    elif kind == "job_revision":
        write_job(e, revision=8)
    elif kind == "apt_state":
        e.inventory["apt_state_digest"] = "9" * 64
    elif kind == "old_ssh":
        monkeypatch.setattr(e.core, "fresh_ssh_connection", lambda *_a: False)
    else:
        monkeypatch.delenv("SUDO_USER")
    result = commit(e, plan)
    assert result["status"] == "rejected" and result["blockers"]
    assert e.recovery.status(plan["recovery_id"]) == result
    assert commit(e, plan) == result


def test_retry_after_verified_receipt_only_reads_original_even_if_mode_changed(
    recovery_env, monkeypatch
):
    e = recovery_env
    plan = preview(e)
    result = commit(e, plan)
    before = (e.path / "recovery-receipts" / (plan["recovery_id"] + ".json")).read_bytes()
    state = e.core.read_json(e.path / "mode.json")
    state["mode"] = "automatic"
    e.core.write_json(e.path / "mode.json", state)
    monkeypatch.setattr(
        e.recovery,
        "_reconcile",
        lambda *_a: pytest.fail("Idempotent result cannot re-run recovery"),
    )
    assert commit(e, plan) == result
    assert (e.path / "recovery-receipts" / (plan["recovery_id"] + ".json")).read_bytes() == before


def test_prepared_status_is_not_a_verified_receipt(recovery_env):
    e = recovery_env
    plan = preview(e)
    assert e.recovery.status(plan["recovery_id"])["status"] == "recovery_prepared"
    with pytest.raises(e.core.Rejected):
        e.recovery.validate_receipt(plan)


def test_unknown_id_has_no_successful_receipt(recovery_env):
    with pytest.raises(FileNotFoundError):
        recovery_env.recovery.status("f" * 32)


def test_tampered_resolution_cannot_suppress_an_old_bad_history(recovery_env):
    e = recovery_env
    write_job(e, history=[{"status": "unknown"}, {"status": "verified"}])
    plan = preview(e)
    result = commit(e, plan)
    path = e.path / "recovery-receipts" / (plan["recovery_id"] + ".json")
    result["job_digest"] = "0" * 64
    e.core.write_json(path, result)
    with pytest.raises(e.core.Rejected, match="digest"):
        e.agent.automatic_policy.safety_state()


def test_manual_confirmation_does_not_change_installed_job_or_quota_files(recovery_env):
    e = recovery_env
    before = hashlib.sha256((e.folder / "job.json").read_bytes()).hexdigest()
    mode = (e.path / "mode.json").read_bytes()
    policy = json.dumps(e.policy, sort_keys=True)
    result = commit(e, preview(e))
    assert result["status"] == "verified"
    assert hashlib.sha256((e.folder / "job.json").read_bytes()).hexdigest() == before
    assert (e.path / "mode.json").read_bytes() == mode
    assert json.dumps(e.policy, sort_keys=True) == policy


@pytest.mark.parametrize("other", [False, True])
def test_unsettled_preview_never_takes_installer_lock_or_probes_live_apt(
    recovery_env, monkeypatch, other
):
    e = recovery_env
    if other:
        folder = e.path / "jobs" / ("b" * 32)
        folder.mkdir()
        e.core.write_json(folder / "job.json", dict(e.job, job_id="b" * 32, status="queued"))
    else:
        write_job(e, status="queued")
    before = {p.name: (p / "job.json").read_bytes() for p in (e.path / "jobs").iterdir()}
    locks = []
    monkeypatch.setattr(e.core, "lock", lambda name, **_kw: locks.append(name) or nullcontext())
    for name in ("inventory", "health", "scan_packages"):
        monkeypatch.setattr(
            e.core,
            name,
            lambda *_a, **_kw: pytest.fail(
                "Unsettled preview must not inspect an installing package manager"
            ),
        )
    plan = preview(e)
    assert plan["eligible"] is False
    assert "worker" not in locks
    with pytest.raises(e.core.Rejected, match="ineligible"):
        commit(e, plan)
    assert "worker" not in locks
    assert {p.name: (p / "job.json").read_bytes() for p in (e.path / "jobs").iterdir()} == before


def test_manifest_is_parsed_from_the_same_bytes_whose_digest_was_checked(recovery_env, monkeypatch):
    e = recovery_env
    monkeypatch.setattr(
        e.core,
        "read_json",
        lambda *_a, **_kw: pytest.fail("Manifest path must not be re-read after its digest check"),
    )
    assert e.recovery.runtime_files(e.job, e.change) == ["/usr/bin/curl"]


@pytest.mark.parametrize(
    "operation,fields",
    [
        ("recovery_prepare", {"job_id": JOB, "mode_revision": 0, "context_digest": CTX}),
        (
            "recovery_submit",
            {
                "recovery_id": "f" * 32,
                "recovery_digest": "a" * 64,
                "mode_revision": 0,
                "context_digest": CTX,
            },
        ),
        ("recovery_status", {"recovery_id": "f" * 32}),
    ],
)
def test_recovery_rpc_has_an_exact_bounded_schema(recovery_env, operation, fields):
    e = recovery_env
    value = {"schema_version": 1, "op": operation, "policy_digest": "9" * 64, **fields}
    assert e.agent.validate_request(value) == value
    for changed in (
        value | {"command": "apt-get upgrade"},
        value | {"schema_version": True},
        value | {"recovery_id": "../../other"},
    ):
        with pytest.raises(e.core.Rejected):
            e.agent.validate_request(changed)


@pytest.mark.parametrize(
    "kind", ["before_created", "on_expiry", "after_expiry", "long_ttl", "zero_ttl"]
)
def test_verified_resolution_receipt_requires_a_bounded_valid_completion_time(recovery_env, kind):
    e = recovery_env
    receipt = commit(e, preview(e))
    if kind == "before_created":
        receipt["completed_at"] = (NOW - timedelta(microseconds=1)).isoformat()
    elif kind == "on_expiry":
        receipt["completed_at"] = receipt["expires_at"]
    elif kind == "after_expiry":
        receipt["completed_at"] = (NOW + timedelta(minutes=5, microseconds=1)).isoformat()
    elif kind == "long_ttl":
        receipt["expires_at"] = (NOW + timedelta(minutes=5, microseconds=1)).isoformat()
    else:
        receipt["expires_at"] = receipt["created_at"]
    receipt["receipt_digest"] = e.core.digest(
        {k: v for k, v in receipt.items() if k != "receipt_digest"}
    )
    with pytest.raises(e.core.Rejected, match="validity"):
        e.recovery.validate_receipt(receipt)


def test_expired_rejected_recovery_receipt_remains_valid_audit_evidence(recovery_env, monkeypatch):
    e = recovery_env
    plan = preview(e)
    monkeypatch.setattr(e.core, "now", lambda: NOW + timedelta(minutes=6))
    receipt = commit(e, plan)
    assert receipt["status"] == "rejected" and "plan_valid" in receipt["blockers"]
    assert e.recovery.validate_receipt(receipt) == receipt
