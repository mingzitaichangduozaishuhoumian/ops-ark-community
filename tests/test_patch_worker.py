"""Persistent patch jobs never replay unknown installs or kill an install on budget."""

import copy
import hashlib
import os
import signal
from datetime import timedelta
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, NOW, ROOT, STATE, load_module, prepare
from test_patch_agent import remote as remote


@pytest.fixture
def worker_env(remote, monkeypatch):
    hook = load_module("transaction_hook", "transaction_hook.py", monkeypatch)
    worker = load_module("worker", "worker.py", monkeypatch)
    plan = prepare(remote)
    folder = remote.path / "jobs" / JOB
    folder.mkdir()
    job = {
        "job_id": JOB,
        "host_id": remote.policy["host_id"],
        "plan_id": plan["plan_id"],
        "plan_digest": plan["plan_digest"],
        "status": "queued",
        "revision": 1,
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "history": [],
    }
    remote.core.write_json(folder / "job.json", job)
    remote.core.write_json(
        folder / "approval.json",
        {
            "plan_digest": plan["plan_digest"],
            "mode_revision": 0,
            "approved_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        },
    )
    calls = []
    archive = PurePosixPath("/var/cache/apt/archives/curl_fixture_amd64.deb")
    monkeypatch.setattr(worker, "package_files", lambda _package: ["/usr/bin/curl"])
    monkeypatch.setattr(worker, "backup_metadata", lambda _path: calls.append("backup_metadata"))
    monkeypatch.setattr(worker, "archive_for", lambda _change: archive)
    real_verify, real_run_apt = worker.verify, worker.run_apt

    def run_apt(job_id, change, *, download=False):
        calls.append("download" if download else "install")
        if not download:
            data = (folder / "expected-transaction.json").read_bytes()
            remote.core.write_json(
                folder / "hook-passed.json",
                {
                    "job_id": job_id,
                    "expected_sha256": hashlib.sha256(data).hexdigest(),
                    "transaction_sha256": "f" * 64,
                    "checked_at": NOW.isoformat(),
                },
            )
        return 0

    def verify(*_args):
        calls.append("verify")
        return remote.core.update_job(
            JOB, "awaiting_transport_verification", local_result="verified"
        )

    def no_real_process(*_args, **_kwargs):
        pytest.fail("These tests must never start a real package manager or subprocess")

    monkeypatch.setattr(worker, "run_apt", run_apt)
    real_check_control = worker.check_candidate_control
    monkeypatch.setattr(worker, "check_candidate_control", lambda _archive: None)
    monkeypatch.setattr(worker, "verify", verify)
    monkeypatch.setattr(worker.subprocess, "Popen", no_real_process)
    return SimpleNamespace(
        remote=remote,
        core=remote.core,
        agent=remote.agent,
        worker=worker,
        hook=hook,
        plan=plan,
        job=job,
        folder=folder,
        calls=calls,
        archive=archive,
        real_verify=real_verify,
        real_run_apt=real_run_apt,
        real_check_control=real_check_control,
    )


@pytest.mark.parametrize("output", ['{"has_conffiles":true}', "{}", '{"has_conffiles":"false"}'])
def test_candidate_declared_conffiles_require_separate_support(worker_env, monkeypatch, output):
    monkeypatch.setattr(worker_env.core, "read_command", lambda *_args, **_kwargs: (0, output))
    with pytest.raises(worker_env.core.Rejected):
        worker_env.real_check_control(worker_env.archive)


def test_candidate_without_declared_conffiles_is_accepted(worker_env, monkeypatch):
    monkeypatch.setattr(
        worker_env.core, "read_command", lambda *_args, **_kwargs: (0, '{"has_conffiles":false}')
    )
    worker_env.real_check_control(worker_env.archive)


def test_exact_fixed_apt_arguments_refuse_unapproved_installs(worker_env):
    env = worker_env
    args = env.worker.apt_arguments(env.remote.change, job_id=JOB)
    assert args[0] == "/usr/bin/apt-get"
    assert args[-2:] == ["install", "curl:amd64=8.5.0-2ubuntu10.6"]
    assert {"--only-upgrade", "--no-remove", "--no-install-recommends"} <= set(args)
    for guard in (
        "APT::Get::AllowUnauthenticated=false",
        "Acquire::AllowInsecureRepositories=false",
        "Acquire::AllowDowngradeToInsecureRepositories=false",
        "Acquire::Check-Valid-Until=true",
        "Acquire::Check-Date=true",
        "APT::Get::allow-Downgrades=false",
        "APT::Get::allow-Change-Held-Packages=false",
        "DPkg::Tools::Options::/usr/bin/python3::Version=3",
        "DPkg::Tools::Options::/usr/bin/python3::InfoFD=0",
    ):
        assert guard in args
    assert (
        "DPkg::Pre-Install-Pkgs::=/usr/bin/python3 -I "
        "/usr/local/libexec/opsark-patch/pre_install.py " + JOB in args
    )
    assert not {
        "--allow-unauthenticated",
        "--allow-downgrades",
        "--allow-change-held-packages",
        "--force-yes",
    } & set(args)
    download = env.worker.apt_arguments(env.remote.change, download=True, job_id=JOB)
    assert "--download-only" in download
    assert not any("Pre-Install-Pkgs" in value for value in download)


@pytest.mark.parametrize(
    "change",
    [
        {"name": "curl;id"},
        {"candidate_version": "--allow-unauthenticated"},
        {"architecture": "amd64;id"},
        {"architecture": "i386"},
    ],
)
def test_apt_arguments_cannot_accept_shell_text_versions_or_foreign_arch(worker_env, change):
    with pytest.raises(worker_env.core.Rejected):
        worker_env.worker.apt_arguments(worker_env.remote.change | change, job_id=JOB)


def test_worker_expected_transaction_covers_unpack_configure_and_archive_hash(worker_env):
    env = worker_env
    expected = env.worker.expected_transaction(JOB, env.remote.change, env.archive)
    value = env.hook.parse_expected(env.core.canonical(expected), JOB)
    assert [item["action"] for item in value["actions"]] == ["unpack", "configure"]
    assert value["actions"][0]["sha256"] == env.remote.change["sha256"]
    assert value["actions"][1]["deb_path"] is None
    observed = []
    for item in value["actions"]:
        observed.append(item | {"sha256": None})
    assert (
        len(env.hook.verify_transaction(value, observed, lambda _path: env.remote.change["sha256"]))
        == 64
    )
    with pytest.raises(env.hook.HookError):
        env.hook.verify_transaction(value, observed[:1], lambda _path: env.remote.change["sha256"])


@pytest.mark.parametrize(
    "status",
    [
        "preflight",
        "downloading",
        "applying",
        "running_overdue",
        "verifying",
        "awaiting_transport_verification",
        "unknown",
        "failed",
        "verified",
    ],
)
def test_worker_never_replays_a_nonqueued_job(worker_env, status):
    env = worker_env
    env.core.update_job(JOB, status)
    before = env.core.read_json(env.folder / "job.json")
    env.worker.run(JOB)
    assert env.calls == []
    assert env.core.read_json(env.folder / "job.json") == before


def test_successful_worker_proves_hook_before_local_verification_and_waits_for_transport(
    worker_env,
):
    env = worker_env
    env.worker.run(JOB)
    value = env.core.read_json(env.folder / "job.json")
    assert env.calls == ["backup_metadata", "download", "install", "verify"]
    assert value["status"] == "awaiting_transport_verification"
    assert (
        value["hook_receipt"]["expected_sha256"]
        == hashlib.sha256((env.folder / "expected-transaction.json").read_bytes()).hexdigest()
    )
    assert value["install_exit_code"] == 0
    assert [event["status"] for event in value["history"]] == [
        "preflight",
        "downloading",
        "applying",
        "verifying",
        "awaiting_transport_verification",
    ]


@pytest.mark.parametrize("phase", ["preflight", "before_install"])
def test_state_drift_blocks_installation_without_replaying_a_different_plan(
    worker_env, monkeypatch, phase
):
    env = worker_env
    count = 0

    def inventory():
        nonlocal count
        count += 1
        return {"apt_state_digest": "0" * 64 if phase == "preflight" or count > 1 else STATE}

    monkeypatch.setattr(env.core, "inventory", inventory)
    with pytest.raises(env.core.Rejected):
        env.worker.run(JOB)
    assert "install" not in env.calls


def test_dependency_resolution_drift_blocks_even_the_download(worker_env, monkeypatch):
    env = worker_env
    monkeypatch.setattr(
        env.core, "resolve_change", lambda *_args: env.remote.change | {"sha256": "0" * 64}
    )
    with pytest.raises(env.core.Rejected, match="Dependency"):
        env.worker.run(JOB)
    assert env.calls == []


def test_failed_download_never_enters_install(worker_env, monkeypatch):
    env = worker_env
    monkeypatch.setattr(
        env.worker,
        "run_apt",
        lambda *_args, **kwargs: 100 if kwargs.get("download") else pytest.fail("Must not install"),
    )
    with pytest.raises(env.core.Rejected, match="download"):
        env.worker.run(JOB)
    assert env.core.read_json(env.folder / "job.json")["status"] == "downloading"


def test_install_exit_failure_does_not_claim_verified(worker_env, monkeypatch):
    env = worker_env
    monkeypatch.setattr(
        env.worker, "run_apt", lambda *_args, **kwargs: 0 if kwargs.get("download") else 100
    )
    env.worker.run(JOB)
    value = env.core.read_json(env.folder / "job.json")
    assert value["status"] == "failed"
    assert value["install_exit_code"] == 100
    assert "verify" not in env.calls


def test_prior_receipt_blocks_replay_before_install(worker_env):
    env = worker_env
    env.core.write_json(env.folder / "hook-passed.json", {"old_receipt": True})
    with pytest.raises(env.core.Rejected, match="prior hook receipt"):
        env.worker.run(JOB)
    assert "install" not in env.calls


def test_missing_hook_receipt_cannot_be_treated_as_success(worker_env, monkeypatch):
    env = worker_env
    monkeypatch.setattr(env.worker, "run_apt", lambda *_args, **_kwargs: 0)
    with pytest.raises(FileNotFoundError):
        env.worker.run(JOB)
    assert env.core.read_json(env.folder / "job.json")["status"] == "applying"
    assert "verify" not in env.calls


@pytest.mark.parametrize("status", ["unknown", "verified"])
def test_worker_lock_failure_does_not_relabel_an_old_uncertain_or_completed_job(
    worker_env, monkeypatch, status
):
    env = worker_env
    env.core.update_job(JOB, status)
    monkeypatch.setattr(
        env.core, "lock", lambda _name: (_ for _ in ()).throw(env.core.Rejected("Worker lock busy"))
    )
    monkeypatch.setattr(env.worker.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(env.worker.os, "umask", lambda _mode: 0)
    monkeypatch.setattr(env.worker.sys, "argv", ["worker.py", JOB])
    assert env.worker.main() == 1
    assert env.core.read_json(env.folder / "job.json")["status"] == status
    assert env.calls == []


def test_unexpected_error_after_commit_point_becomes_unknown_not_rejected(worker_env, monkeypatch):
    env = worker_env

    def crash(_job):
        env.core.update_job(JOB, "applying", worker_pid=os.getpid())
        raise OSError("Lost observation of the real process")

    monkeypatch.setattr(env.worker, "run", crash)
    monkeypatch.setattr(env.worker.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(env.worker.os, "umask", lambda _mode: 0)
    monkeypatch.setattr(env.worker.sys, "argv", ["worker.py", JOB])
    assert env.worker.main() == 1
    assert env.core.read_json(env.folder / "job.json")["status"] == "unknown"


@pytest.mark.parametrize(
    "condition,local_result",
    [
        ("healthy", "verified"),
        ("wrong_version", "verification_failed"),
        ("still_affected", "verification_failed"),
        ("stale_vendor", "verification_failed"),
        ("missing_finding", "verification_failed"),
        ("health_failed", "verification_failed"),
        ("runtime_incomplete", "verification_failed"),
        ("old_process", "installed_restart_pending"),
        ("reboot", "reboot_pending"),
    ],
)
def test_verification_requires_exact_fix_rescan_runtime_health_and_then_new_ssh(
    worker_env, monkeypatch, condition, local_result
):
    env = worker_env
    installed = env.remote.change["candidate_version"] if condition != "wrong_version" else "1.0"
    monkeypatch.setattr(
        env.core,
        "inventory",
        lambda: {
            "packages": [{"name": "curl", "architecture": "amd64", "installed_version": installed}]
        },
    )
    monkeypatch.setattr(
        env.core,
        "health",
        lambda _policy: {
            "passed": condition != "health_failed",
            "reboot_required": condition == "reboot",
        },
    )
    runtime = {
        "status": "incomplete" if condition == "runtime_incomplete" else "complete",
        "outdated_process_count": int(condition == "old_process"),
        "gaps": [],
    }
    monkeypatch.setattr(env.worker, "runtime_maps", lambda _files: copy.deepcopy(runtime))
    rescan = {
        "scan_id": "9" * 32,
        "coverage": {"scope": "selected_vendor_advisory"},
        "gaps": [],
        "findings": []
        if condition == "missing_finding"
        else [
            {
                "finding_id": env.remote.finding["finding_id"],
                "affected": condition == "still_affected",
                "vendor_evidence_fresh": condition != "stale_vendor",
            }
        ],
    }
    monkeypatch.setattr(env.core, "scan_packages", lambda **_kwargs: copy.deepcopy(rescan))
    monkeypatch.setattr(env.core, "uptime_ticks", lambda: 12345)
    real_path = Path
    monkeypatch.setattr(
        env.worker,
        "Path",
        lambda value: (
            SimpleNamespace(read_text=lambda: "fixture-boot")
            if str(value) == "/proc/sys/kernel/random/boot_id"
            else real_path(value)
        ),
    )
    value = env.real_verify(JOB, env.plan, env.remote.policy, ["/usr/bin/curl"])
    assert value["status"] == "awaiting_transport_verification"
    assert value["local_result"] == local_result
    assert value["verification"]["fresh_ssh"]["passed"] is False
    assert value["locally_verified_uptime_ticks"] == 12345
    assert value["boot_id"] == "fixture-boot"


def test_systemd_service_does_not_automatically_stop_the_dpkg_group():
    text = (ROOT / "deploy/vulnerability/opsark-patch@.service").read_text()
    assert "KillMode=mixed" in text or "KillMode=process" in text
    assert "TimeoutStopSec=infinity" in text
    assert "RuntimeMaxSec=infinity" in text
    assert "Restart=no" in text
    assert "ExitType=cgroup" in text


@pytest.mark.parametrize(
    "condition,accepted",
    [
        ("applying", True),
        ("running_overdue", True),
        ("queued", False),
        ("state_drift", False),
        ("unsafe_configuration", False),
        ("expired_approval", False),
        ("mode_changed", False),
        ("resolver_rejected", False),
    ],
)
def test_inside_apt_commit_hook_rechecks_authorization_before_transaction_validation(
    worker_env, monkeypatch, condition, accepted
):
    env = worker_env
    pre_install = load_module("pre_install", "pre_install.py", monkeypatch)
    status = condition if condition in {"applying", "running_overdue", "queued"} else "applying"
    env.core.update_job(JOB, status)
    if condition == "state_drift":
        env.remote.inventory["apt_state_digest"] = "0" * 64
    if condition == "unsafe_configuration":
        env.remote.inventory["apt_configuration_safe"] = False
    if condition == "expired_approval":
        approval = env.core.read_json(env.folder / "approval.json")
        approval["expires_at"] = NOW.isoformat()
        env.core.write_json(env.folder / "approval.json", approval)
    if condition == "mode_changed":
        mode = env.core.read_json(env.remote.path / "mode.json")
        mode["mode"] = "manual"
        env.core.write_json(env.remote.path / "mode.json", mode)
    if condition == "resolver_rejected":
        monkeypatch.setattr(
            env.core,
            "resolve_change",
            lambda *_args: (_ for _ in ()).throw(env.core.Rejected("Solver changed")),
        )
    final_checks = []
    monkeypatch.setattr(env.hook, "main", lambda: final_checks.append("transaction") or 0)
    monkeypatch.setattr(pre_install.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(pre_install.sys, "argv", ["pre_install.py", JOB])
    monkeypatch.setattr(pre_install.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(pre_install.signal, "signal", lambda *_args: signal.SIG_DFL)
    monkeypatch.setattr(pre_install.signal, "alarm", lambda _seconds: 0, raising=False)
    assert pre_install.main() == (0 if accepted else 1)
    assert final_checks == (["transaction"] if accepted else [])


@pytest.mark.skipif(os.name != "posix", reason="POSIX selector and process-group contract")
def test_install_overdue_or_log_budget_exhaustion_never_kills_apt(worker_env, monkeypatch):
    env = worker_env
    chunks = [b"x" * 8192 for _ in range(130)] + [b""]
    state = {"code": None, "waited": False}

    class Pipe:
        def close(self):
            pass

        def read(self, _size):
            return chunks.pop(0) if chunks else b""

    pipe = Pipe()

    class Process:
        pid = 500
        stdout = pipe

        def poll(self):
            return state["code"]

        def wait(self):
            state.update(code=0, waited=True)
            return 0

    class Selector:
        def __enter__(self):
            self.active = True
            return self

        def __exit__(self, *_args):
            return False

        def register(self, *_args):
            pass

        def get_map(self):
            return {1: True} if self.active else {}

        def select(self, _timeout):
            return [(SimpleNamespace(fd=42, fileobj=pipe), 1)]

        def unregister(self, _file):
            self.active = False

    monkeypatch.setattr(env.worker.subprocess, "Popen", lambda argv, **kwargs: Process())
    monkeypatch.setattr(env.worker.selectors, "DefaultSelector", Selector)
    ticks = iter([0, *([301] * 140)])
    monkeypatch.setattr(env.worker.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(env.worker.signal, "signal", lambda *_args: signal.SIG_DFL)
    monkeypatch.setattr(env.worker.os, "read", lambda _fd, _size: chunks.pop(0))
    monkeypatch.setattr(
        env.worker.os, "killpg", lambda *_args: pytest.fail("An install must not be killed")
    )
    assert env.real_run_apt(JOB, env.remote.change) == 0
    assert (env.folder / "install.log").stat().st_size == 1_048_576
    assert not chunks and state["waited"]
    assert env.core.read_json(env.folder / "job.json")["status"] == "running_overdue"
