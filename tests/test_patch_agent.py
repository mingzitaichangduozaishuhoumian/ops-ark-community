"""Remote patch authorization and durable intent, without root or package changes."""

import copy
import importlib.util
import json
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
JOB = "a" * 32
FINDING = "b" * 64
STATE = "c" * 64


def load_module(name, filename, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/vulnerability" / filename)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def remote(tmp_path, monkeypatch):
    # Imported remote scripts change sys.path for their fixed Linux installation.
    monkeypatch.setattr(sys, "path", list(sys.path))
    core = load_module("core", "core.py", monkeypatch)
    load_module("automatic_policy", "automatic_policy.py", monkeypatch)
    agent = load_module("agent", "agent.py", monkeypatch)
    (tmp_path / "plans").mkdir()
    (tmp_path / "jobs").mkdir()
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(core, "now", lambda: NOW)
    monkeypatch.setattr(core, "directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(core, "lock", lambda _name: nullcontext())
    monkeypatch.setattr(core, "read_bytes", lambda path, *_args, **_kwargs: Path(path).read_bytes())
    monkeypatch.setattr(core, "read_json", lambda path, *_args: json.loads(Path(path).read_bytes()))
    monkeypatch.setattr(
        core, "write_json", lambda path, value: Path(path).write_bytes(core.canonical(value))
    )
    policy = {
        "enabled": True,
        "allow_service_restart": True,
        "allow_reboot": False,
        "host_id": "test-host",
        "allowed_packages": ["curl"],
        "max_packages": 1,
    }
    change = {
        "name": "curl",
        "architecture": "amd64",
        "current_version": "8.5.0-2ubuntu10.5",
        "candidate_version": "8.5.0-2ubuntu10.6",
        "fixed_version": "8.5.0-2ubuntu10.6",
        "sha256": "d" * 64,
        "old_multiarch": "no",
        "new_multiarch": "no",
        "candidate_filename": "curl.deb",
    }
    finding = {
        "finding_id": FINDING,
        "advisory": "USN-99999-1",
        "package": "curl",
        "affected": True,
        "candidate_fixable": True,
        "vendor_evidence_fresh": True,
        "fixed_binary_version": change["fixed_version"],
    }
    inventory = {"apt_state_digest": STATE, "apt_configuration_safe": True, "packages": []}
    baseline = {"passed": True, "reboot_required": False}
    commands = []
    monkeypatch.setattr(core, "load_policy", lambda: copy.deepcopy(policy))
    monkeypatch.setattr(core, "inventory", lambda: copy.deepcopy(inventory))
    monkeypatch.setattr(core, "resolve_change", lambda *_args: copy.deepcopy(change))
    monkeypatch.setattr(core, "health", lambda _policy: copy.deepcopy(baseline))
    monkeypatch.setattr(
        core, "read_command", lambda argv, **_kwargs: commands.append(argv) or (0, "")
    )

    def update(job_id, status, **fields):
        path = tmp_path / "jobs" / job_id / "job.json"
        value = json.loads(path.read_bytes())
        value.update(fields)
        value.update(status=status, revision=value.get("revision", 0) + 1, updated_at=core.stamp())
        value.setdefault("history", []).append({"status": status, "at": core.stamp()})
        core.write_json(path, value)
        return value

    monkeypatch.setattr(core, "update_job", update)
    core.write_json(
        tmp_path / "mode.json",
        {
            "mode": "assisted",
            "revision": 0,
            "policy_digest": core.policy_digest(policy),
            "updated_at": core.stamp(),
        },
    )
    core.write_json(
        tmp_path / "latest-scan.json",
        {
            "collected_at": core.stamp(),
            "apt_state_digest": STATE,
            "coverage": {"scope": "fixture-only"},
            "findings": [finding],
        },
    )
    return SimpleNamespace(
        core=core,
        agent=agent,
        path=tmp_path,
        policy=policy,
        change=change,
        finding=finding,
        inventory=inventory,
        baseline=baseline,
        commands=commands,
    )


def request(remote, op="scan", **fields):
    return {
        "schema_version": 1,
        "op": op,
        "policy_digest": remote.core.policy_digest(remote.policy),
        **fields,
    }


def prepare(remote):
    return remote.agent.prepare(
        request(remote, "prepare", finding_id=FINDING, mode_revision=0), remote.policy
    )


def submission(remote, plan, **fields):
    return (
        request(
            remote,
            "submit",
            plan_id=plan["plan_id"],
            plan_digest=plan["plan_digest"],
            job_id=JOB,
            mode_revision=plan["mode_revision"],
        )
        | fields
    )


@pytest.mark.parametrize(
    "op,fields",
    [
        ("scan", {}),
        ("jobs", {}),
        ("prepare", {"finding_id": FINDING, "mode_revision": 0}),
        (
            "submit",
            {"plan_id": "e" * 32, "plan_digest": "f" * 64, "job_id": JOB, "mode_revision": 0},
        ),
        ("status", {"job_id": JOB}),
        ("set_mode", {"mode": "assisted", "revision": 1}),
    ],
)
def test_rpc_accepts_only_the_documented_structured_contract(remote, op, fields):
    value = request(remote, op, **fields)
    assert remote.agent.validate_request(value) == value


@pytest.mark.parametrize(
    "change",
    [
        {"op": "shell"},
        {"schema_version": True},
        {"schema_version": 2},
        {"policy_digest": "wrong"},
        {"command": "apt-get upgrade"},
        {"host_id": "unregistered"},
        {"argv": ["sh", "-c", "id"]},
        {"environment": {"APT_CONFIG": "/untrusted/apt.conf"}},
    ],
)
def test_rpc_cannot_supply_commands_targets_options_or_weak_schema(remote, change):
    with pytest.raises(remote.core.Rejected):
        remote.agent.validate_request(request(remote) | change)


@pytest.mark.parametrize(
    "change",
    [
        {"job_id": "../" + JOB},
        {"job_id": JOB.upper()},
        {"plan_digest": "f" * 63},
        {"mode_revision": True},
        {"mode_revision": "0"},
        {"mode_revision": -1},
        {"mode_revision": 2**53},
    ],
)
def test_submit_id_and_revision_fields_are_not_coerced(remote, change):
    value = (
        request(
            remote, "submit", plan_id="e" * 32, plan_digest="f" * 64, job_id=JOB, mode_revision=0
        )
        | change
    )
    with pytest.raises(remote.core.Rejected):
        remote.agent.validate_request(value)


def test_prepare_and_load_bind_the_full_plan_and_reject_content_drift(remote):
    plan = prepare(remote)
    assert plan["risk_level"] == "medium"
    assert plan["restart_assessment"] == "possible"
    assert remote.agent.load_plan(plan["plan_id"]) == plan
    path = remote.path / "plans" / (plan["plan_id"] + ".json")
    plan["package_changes"][0]["candidate_version"] = "99.0"
    remote.core.write_json(path, plan)
    with pytest.raises(remote.core.Rejected, match="binding"):
        remote.agent.load_plan(plan["plan_id"])


def test_prepare_rejects_scan_collected_by_a_different_driver_source(remote):
    data = remote.core.read_json(remote.path / "latest-scan.json")
    data["driver_source_digest"] = "9" * 64
    remote.core.write_json(remote.path / "latest-scan.json", data)
    with pytest.raises(remote.core.Rejected, match="Scan implementation changed"):
        prepare(remote)
    assert not list((remote.path / "plans").iterdir())
    assert remote.commands == []


@pytest.mark.parametrize("flag", ["affected", "candidate_fixable", "vendor_evidence_fresh"])
def test_prepare_rejects_missing_vendor_or_affected_evidence(remote, flag):
    data = remote.core.read_json(remote.path / "latest-scan.json")
    data["findings"][0][flag] = False
    remote.core.write_json(remote.path / "latest-scan.json", data)
    with pytest.raises(remote.core.Rejected):
        prepare(remote)
    assert not list((remote.path / "plans").iterdir())


@pytest.mark.parametrize("offset", [-901, 1])
def test_prepare_rejects_old_or_future_scan_timestamps(remote, offset):
    data = remote.core.read_json(remote.path / "latest-scan.json")
    data["collected_at"] = (NOW + timedelta(seconds=offset)).isoformat()
    remote.core.write_json(remote.path / "latest-scan.json", data)
    with pytest.raises(remote.core.Rejected, match="stale"):
        prepare(remote)


def test_prepare_rejects_repository_drift_and_unhealthy_baseline(remote):
    remote.inventory["apt_state_digest"] = "0" * 64
    with pytest.raises(remote.core.Rejected, match="state changed"):
        prepare(remote)
    remote.inventory["apt_state_digest"] = STATE
    remote.baseline["passed"] = False
    with pytest.raises(remote.core.Rejected, match="health"):
        prepare(remote)


@pytest.mark.parametrize("mode", ["manual", "automatic"])
def test_assisted_plan_cannot_cross_into_another_mode(remote, mode):
    plan = prepare(remote)
    data = remote.core.read_json(remote.path / "mode.json")
    data["mode"] = mode
    remote.core.write_json(remote.path / "mode.json", data)
    with pytest.raises(remote.core.Rejected, match="mode"):
        remote.agent.validate_authorization(plan, remote.policy)


def test_real_clock_progress_does_not_extend_plan_beyond_thirty_minutes(remote, monkeypatch):
    ticks = iter(NOW + timedelta(microseconds=i) for i in range(100))
    monkeypatch.setattr(remote.core, "now", lambda: next(ticks))
    plan = prepare(remote)
    assert datetime.fromisoformat(plan["expires_at"]) - datetime.fromisoformat(
        plan["created_at"]
    ) == timedelta(minutes=30)


@pytest.mark.parametrize(
    "kind", ["disabled", "host", "expired", "scope", "restart", "mode_revision"]
)
def test_approval_cannot_override_policy_identity_time_scope_or_mode(remote, kind):
    plan = prepare(remote)
    policy = copy.deepcopy(remote.policy)
    if kind == "disabled":
        policy["enabled"] = False
    elif kind == "host":
        plan["host_id"] = "other-host"
    elif kind == "expired":
        plan["expires_at"] = NOW.isoformat()
    elif kind == "scope":
        policy["allowed_packages"] = []
    elif kind == "restart":
        policy["allow_service_restart"] = False
    else:
        plan["mode_revision"] = 1
    with pytest.raises(remote.core.Rejected):
        remote.agent.validate_authorization(plan, policy)


@pytest.mark.parametrize(
    "change",
    [
        {"plan_digest": "0" * 64},
        {"mode_revision": 1},
        {"expires_at": NOW.isoformat()},
        {"approved_at": (NOW + timedelta(seconds=1)).isoformat()},
    ],
)
def test_specific_approval_is_bound_and_short_lived(remote, change):
    plan = prepare(remote)
    approval = {
        "plan_digest": plan["plan_digest"],
        "mode_revision": 0,
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    } | change
    with pytest.raises(remote.core.Rejected):
        remote.agent.validate_authorization(plan, remote.policy, approval)


def test_submission_persists_intent_before_start_and_duplicate_does_not_restart(
    remote, monkeypatch
):
    plan = prepare(remote)

    def start(argv, **_kwargs):
        assert (remote.path / "jobs" / JOB / "job.json").is_file()
        assert (remote.path / "jobs" / JOB / "approval.json").is_file()
        remote.commands.append(argv)
        return 0, ""

    monkeypatch.setattr(remote.core, "read_command", start)
    first = remote.agent.submit(submission(remote, plan), remote.policy)
    duplicate = remote.agent.submit(submission(remote, plan), remote.policy)
    assert first == duplicate
    assert len(remote.commands) == 1
    assert remote.commands[0] == [
        "/usr/bin/systemctl",
        "start",
        "--no-block",
        "opsark-patch@" + JOB + ".service",
    ]
    approval = remote.core.read_json(remote.path / "jobs" / JOB / "approval.json")
    assert remote.core.aware(approval["expires_at"]) == NOW + timedelta(minutes=10)


def test_existing_job_id_cannot_be_rebound_to_a_different_plan(remote):
    plan = prepare(remote)
    remote.agent.submit(submission(remote, plan), remote.policy)
    with pytest.raises(remote.core.Rejected, match="already bound"):
        remote.agent.submit(submission(remote, plan, plan_digest="0" * 64), remote.policy)
    assert len(remote.commands) == 1


@pytest.mark.parametrize("status", ["queued", "applying", "unknown"])
def test_new_job_is_blocked_by_active_or_uncertain_transaction(remote, status):
    plan = prepare(remote)
    remote.agent.submit(submission(remote, plan), remote.policy)
    remote.core.update_job(JOB, status)
    with pytest.raises(remote.core.Rejected, match="reconciliation"):
        remote.agent.submit(submission(remote, plan, job_id="1" * 32), remote.policy)
    assert len(remote.commands) == 1


def test_rpc_lost_start_ack_returns_the_original_durable_job(remote, monkeypatch, capsys):
    plan = prepare(remote)
    value = submission(remote, plan)
    monkeypatch.setattr(remote.agent, "read_request", lambda: value)
    monkeypatch.setattr(remote.agent.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(remote.agent.os, "umask", lambda _value: 0)
    monkeypatch.setattr(remote.agent.sys, "argv", ["agent.py"])
    monkeypatch.setattr(
        remote.core,
        "read_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            TimeoutError("Lost unit-start acknowledgement")
        ),
    )
    assert remote.agent.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["job_id"] == JOB
    assert result["plan_digest"] == plan["plan_digest"]
    assert result["status"] == "queued"
    assert len(list((remote.path / "jobs").iterdir())) == 1


def awaiting_job(remote, *, age=1):
    folder = remote.path / "jobs" / JOB
    folder.mkdir()
    value = {
        "job_id": JOB,
        "host_id": remote.policy["host_id"],
        "status": "awaiting_transport_verification",
        "revision": 4,
        "updated_at": NOW.isoformat(),
        "local_result": "verified",
        "locally_verified_at": (NOW - timedelta(seconds=age)).isoformat(),
        "locally_verified_uptime_ticks": 100,
        "boot_id": "boot-fixture",
        "verification": {"fresh_ssh": {"passed": False}},
    }
    remote.core.write_json(folder / "job.json", value)
    return value


def test_local_success_waits_for_a_new_dedicated_ssh_connection(remote, monkeypatch):
    awaiting_job(remote)
    monkeypatch.setattr(remote.core, "fresh_ssh_connection", lambda *_args: True)
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert remote.agent.status(JOB, remote.policy)["status"] == "awaiting_transport_verification"
    monkeypatch.setenv("SUDO_USER", "opsark-repair")
    monkeypatch.setattr(remote.core, "fresh_ssh_connection", lambda *_args: False)
    assert remote.agent.status(JOB, remote.policy)["status"] == "awaiting_transport_verification"
    monkeypatch.setattr(
        remote.core,
        "fresh_ssh_connection",
        lambda ticks, boot: ticks == 100 and boot == "boot-fixture",
    )
    result = remote.agent.status(JOB, remote.policy)
    assert result["status"] == "verified"
    assert result["verification"]["fresh_ssh"]["passed"] is True


@pytest.mark.parametrize("age", [301, 86400, -1])
def test_fresh_ssh_cannot_promote_stale_or_future_local_verification(remote, monkeypatch, age):
    awaiting_job(remote, age=age)
    monkeypatch.setenv("SUDO_USER", "opsark-repair")
    monkeypatch.setattr(remote.core, "fresh_ssh_connection", lambda *_args: True)
    result = remote.agent.status(JOB, remote.policy)
    assert result["status"] != "verified"


@pytest.mark.parametrize("connection_tick,expected", [(99, False), (100, False), (101, True)])
def test_fresh_ssh_uses_the_connection_ancestor_start_time(
    remote, monkeypatch, connection_tick, expected
):
    def proc_stat(pid, parent, tick):
        fields = ["S", str(parent), *(["0"] * 17), str(tick)]
        return str(pid) + " (name with ) spaces) " + " ".join(fields)

    texts = {
        "/proc/sys/kernel/random/boot_id": "fixture-boot\n",
        "/proc/50/stat": proc_stat(50, 40, 110),
        "/proc/40/stat": proc_stat(40, 1, connection_tick),
    }
    executables = {"/proc/50/exe": "/usr/bin/sudo", "/proc/40/exe": "/usr/sbin/sshd"}
    monkeypatch.setattr(
        remote.core, "Path", lambda path: SimpleNamespace(read_text=lambda: texts[str(path)])
    )
    monkeypatch.setattr(remote.core.os, "getppid", lambda: 50)
    monkeypatch.setattr(remote.core.os, "readlink", lambda path: executables[str(path)])
    assert remote.core.fresh_ssh_connection(100, "fixture-boot") is expected
    assert remote.core.fresh_ssh_connection(100, "a different boot") is False


@pytest.mark.parametrize("kind", ["duplicate", "oversized", "deadline"])
def test_rpc_stdin_is_bounded_and_duplicate_keys_are_rejected(remote, monkeypatch, kind):
    wire = remote.core.canonical(request(remote))
    if kind == "duplicate":
        wire = wire.replace(b'"op":"scan"', b'"op":"scan","op":"submit"')
    elif kind == "oversized":
        wire = b" " * 8193
    chunks = [wire, b""]

    class Selector:
        def __enter__(self):
            self.active = True
            return self

        def __exit__(self, *_args):
            return False

        def register(self, *_args):
            pass

        def get_map(self):
            return {0: True} if self.active else {}

        def select(self, _timeout):
            return [(SimpleNamespace(fd=0, fileobj=0), 1)]

        def unregister(self, _file):
            self.active = False

    monkeypatch.setattr(remote.agent.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(remote.agent.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(remote.agent.os, "read", lambda _fd, _size: chunks.pop(0))
    ticks = iter([0, *([11 if kind == "deadline" else 1] * 5)])
    monkeypatch.setattr(remote.agent.time, "monotonic", lambda: next(ticks))
    with pytest.raises(remote.core.Rejected):
        remote.agent.read_request()


def test_remote_policy_digest_is_checked_before_dispatching_even_a_scan(remote, monkeypatch):
    monkeypatch.setattr(
        remote.core, "scan_packages", lambda: pytest.fail("Must not scan a mismatched policy")
    )
    with pytest.raises(remote.core.Rejected, match="binding changed"):
        remote.agent.dispatch(request(remote) | {"policy_digest": "0" * 64})


def test_mode_updates_are_monotonic_and_idempotent(remote):
    initial = remote.agent.set_mode({"mode": "assisted", "revision": 0}, remote.policy)
    assert initial["status"] == "mode_saved"
    changed = remote.agent.set_mode({"mode": "manual", "revision": 1}, remote.policy)
    assert changed["revision"] == 1
    assert remote.agent.set_mode({"mode": "manual", "revision": 1}, remote.policy) == changed
    for value in ({"mode": "assisted", "revision": 0}, {"mode": "automatic", "revision": 1}):
        with pytest.raises(remote.core.Rejected):
            remote.agent.set_mode(value, remote.policy)


def test_policy_change_invalidates_the_saved_remote_mode(remote):
    remote.policy["allowed_packages"] = ["other-package"]
    with pytest.raises(remote.core.Rejected, match="invalidated"):
        remote.agent.mode_state()


@pytest.mark.parametrize("kind", ["malformed", "unreadable", "cycle"])
def test_fresh_ssh_fails_closed_on_unreadable_or_malformed_process_ancestry(
    remote, monkeypatch, kind
):
    def text(path):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return "boot"
        if kind == "unreadable":
            raise PermissionError("Process metadata not readable")
        if kind == "malformed":
            return "not a stat record"
        return "50 (cycle) " + " ".join(["S", "50", *(["0"] * 17), "101"])

    monkeypatch.setattr(
        remote.core, "Path", lambda path: SimpleNamespace(read_text=lambda: text(path))
    )
    monkeypatch.setattr(remote.core.os, "getppid", lambda: 50)
    monkeypatch.setattr(remote.core.os, "readlink", lambda _path: "/usr/bin/sudo")
    assert remote.core.fresh_ssh_connection(100, "boot") is False
