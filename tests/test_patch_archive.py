"""Historical patch results remain readable without replaying their installation."""

import copy
from datetime import timedelta

import pytest
from test_patch_agent import JOB, NOW, prepare, request, submission
from test_patch_agent import remote as remote


def submitted(remote):
    """Use the existing RPC fixture, including its mocked systemd launch."""
    remote.policy["driver_source_digest"] = "1" * 64
    mode_path = remote.path / "mode.json"
    mode = remote.core.read_json(mode_path)
    mode["policy_digest"] = remote.core.policy_digest(remote.policy)
    remote.core.write_json(mode_path, mode)
    scan_path = remote.path / "latest-scan.json"
    scan = remote.core.read_json(scan_path)
    scan["driver_source_digest"] = remote.policy["driver_source_digest"]
    remote.core.write_json(scan_path, scan)
    plan = prepare(remote)
    job = remote.agent.submit(submission(remote, plan), remote.policy)
    return plan, job


def terminal_job(remote, status, *, legacy=False):
    plan, _job = submitted(remote)
    verification = {
        "exact_package_version": {"passed": status == "verified", "version": "8.5.0-2ubuntu10.6"},
        "fresh_ssh": {"passed": status == "verified", "checked_at": NOW.isoformat()},
        "http": {"passed": status == "verified", "detail": "Original recorded business result"},
    }
    value = remote.core.update_job(
        JOB,
        status,
        verification=verification,
        completed_at=NOW.isoformat(),
        detail="Original recorded result; no action belongs to an archive read.",
    )
    if legacy:
        value.pop("execution_policy_digest")
        remote.core.write_json(remote.path / "jobs" / JOB / "job.json", value)
    return plan, copy.deepcopy(value)


def change_scope(remote, kind):
    if kind == "code":
        remote.policy["driver_source_digest"] = "2" * 64
    else:
        # A package allowed for the old action need not remain allowed to read its result.
        remote.policy["allowed_packages"] = ["other-approved-package"]
    return remote.core.policy_digest(remote.policy)


def forbid_execution(remote, monkeypatch):
    monkeypatch.setattr(
        remote.agent, "submit", lambda *_args, **_kwargs: pytest.fail("Archive reads cannot submit")
    )
    monkeypatch.setattr(
        remote.core,
        "read_command",
        lambda *_args, **_kwargs: pytest.fail(
            "Archive reads cannot launch units or package commands"
        ),
    )


def test_new_job_records_its_original_execution_scope(remote):
    plan, job = submitted(remote)
    assert job["execution_policy_digest"] == plan["policy_digest"]
    assert job["policy_digest"] == job["execution_policy_digest"]
    saved = remote.core.read_json(remote.path / "jobs" / JOB / "job.json")
    assert saved["execution_policy_digest"] == plan["policy_digest"]
    assert saved["status"] == "queued" and saved["revision"] == 1
    assert len(remote.commands) == 1


@pytest.mark.parametrize(
    "status,scope_kind,legacy",
    [
        ("rejected", "policy", False),
        ("verified", "code", False),
        ("rejected", "code", True),
        ("verified", "policy", True),
        ("reboot_pending", "policy", False),
        ("installed_restart_pending", "code", False),
        ("installed_restart_pending", "policy", True),
    ],
)
def test_terminal_scope_rebind_preserves_original_plan_and_result(
    remote, monkeypatch, status, scope_kind, legacy
):
    plan, original = terminal_job(remote, status, legacy=legacy)
    original_policy = original["policy_digest"]
    artifacts = {
        name: (remote.path / "jobs" / JOB / name).read_bytes()
        for name in ("plan.json", "approval.json")
    }
    commands = copy.deepcopy(remote.commands)
    current_policy = change_scope(remote, scope_kind)
    assert current_policy != original_policy
    # A historical result must remain readable even after its old approval has expired.
    monkeypatch.setattr(remote.core, "now", lambda: NOW + timedelta(days=1))
    forbid_execution(remote, monkeypatch)

    if status == "installed_restart_pending":
        # Activation binds the original raw pending ledger. A scope change must
        # not rewrite its revision or policy merely to answer an archive query.
        path = remote.path / "jobs" / JOB / "job.json"
        original_raw = path.read_bytes()
        for read in (
            lambda: remote.agent.status(JOB, remote.policy),
            lambda: remote.agent.dispatch(request(remote, "status", job_id=JOB)),
        ):
            with pytest.raises(remote.core.Rejected, match="preserved"):
                read()
            assert path.read_bytes() == original_raw
        for name, content in artifacts.items():
            assert (remote.path / "jobs" / JOB / name).read_bytes() == content
        assert remote.commands == commands
        return

    archived = remote.agent.status(JOB, remote.policy)
    assert archived["status"] == status
    assert archived["policy_digest"] == current_policy
    assert archived["execution_policy_digest"] == original_policy
    assert archived["revision"] == original["revision"] + 1
    assert "installation was not repeated" in archived["archival_note"]
    for key in (
        "job_id",
        "plan_id",
        "plan_digest",
        "mode_revision",
        "created_at",
        "completed_at",
        "verification",
        "detail",
    ):
        assert archived[key] == original[key]
    assert archived["plan_digest"] == plan["plan_digest"]
    assert archived["history"][: len(original["history"])] == original["history"]
    for name, content in artifacts.items():
        assert (remote.path / "jobs" / JOB / name).read_bytes() == content
    assert remote.commands == commands

    snapshot = (remote.path / "jobs" / JOB / "job.json").read_bytes()
    again = remote.agent.status(JOB, remote.policy)
    via_rpc = remote.agent.dispatch(request(remote, "status", job_id=JOB))
    assert again == archived
    assert via_rpc["policy_digest"] == current_policy
    assert via_rpc["execution_policy_digest"] == original_policy
    assert via_rpc["revision"] == archived["revision"]
    assert (remote.path / "jobs" / JOB / "job.json").read_bytes() == snapshot
    assert remote.commands == commands


def test_repeated_policy_rotations_keep_the_first_execution_scope(remote, monkeypatch):
    _plan, original = terminal_job(remote, "verified")
    forbid_execution(remote, monkeypatch)
    first_scope = change_scope(remote, "code")
    first = remote.agent.status(JOB, remote.policy)
    remote.policy["allowed_packages"] = []
    second_scope = remote.core.policy_digest(remote.policy)
    assert second_scope != first_scope
    second = remote.agent.status(JOB, remote.policy)
    assert second["status"] == "verified"
    assert second["policy_digest"] == second_scope
    assert second["execution_policy_digest"] == original["policy_digest"]
    assert second["plan_digest"] == original["plan_digest"]
    assert second["verification"] == original["verification"]
    assert second["revision"] == first["revision"] + 1


@pytest.mark.parametrize(
    "status",
    [
        "queued",
        "preflight",
        "downloading",
        "applying",
        "verifying",
        "running_overdue",
        "unknown",
        "awaiting_transport_verification",
    ],
)
def test_nonterminal_or_unknown_scope_is_not_archived_as_a_completed_job(
    remote, monkeypatch, status
):
    plan, job = submitted(remote)
    if status == "awaiting_transport_verification":
        job = remote.core.update_job(
            JOB,
            status,
            locally_verified_at=NOW.isoformat(),
            locally_verified_uptime_ticks=100,
            boot_id="synthetic-boot",
            local_result="verified",
            verification={"fresh_ssh": {"passed": False}},
        )
    else:
        job = remote.core.update_job(JOB, status)
    original = copy.deepcopy(job)
    snapshot = (remote.path / "jobs" / JOB / "job.json").read_bytes()
    current_policy = change_scope(remote, "code")
    monkeypatch.delenv("SUDO_USER", raising=False)
    forbid_execution(remote, monkeypatch)
    result = remote.agent.status(JOB, remote.policy)
    assert result["status"] == status
    assert result["revision"] == original["revision"]
    assert result["policy_digest"] != current_policy
    assert result["policy_digest"] == original["policy_digest"]
    assert result["execution_policy_digest"] == plan["policy_digest"]
    assert "archival_note" not in result
    assert (remote.path / "jobs" / JOB / "job.json").read_bytes() == snapshot


def test_archive_read_cannot_reassign_result_to_a_different_host(remote, monkeypatch):
    terminal_job(remote, "verified")
    snapshot = (remote.path / "jobs" / JOB / "job.json").read_bytes()
    remote.policy["host_id"] = "different-host"
    forbid_execution(remote, monkeypatch)
    with pytest.raises(remote.core.Rejected, match="different host"):
        remote.agent.status(JOB, remote.policy)
    assert (remote.path / "jobs" / JOB / "job.json").read_bytes() == snapshot
