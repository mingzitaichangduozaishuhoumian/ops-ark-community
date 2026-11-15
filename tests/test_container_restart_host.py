"""Exercise the host protocol with a disposable private Linux journal and fake Docker."""

import copy
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from deploy.container import restart_action as action
from deploy.container import restart_runtime as runtime
from deploy.container import restart_ssh_entry as entry

NOW = datetime(2026, 11, 13, 12, tzinfo=UTC)
PID = "a" * 32
CID = "b" * 64
IMAGE = "sha256:" + "c" * 64
APPROVAL = "d" * 32
BEFORE = {
    "daemon": "1" * 64,
    "boot": "2" * 64,
    "mounts": "3" * 64,
    "pid": 121,
    "birth": 100,
    "created_ns": 1000,
    "started_ns": 2000,
}
AFTER = BEFORE | {"pid": 122, "birth": 101, "started_ns": 3000}
POLICY = {
    "schema_version": 1,
    "enabled": True,
    "mode": "assisted",
    "mode_revision": 7,
    "expires_at": "2026-11-13T14:00:00Z",
    "container_id": CID,
    "image_id": IMAGE,
    "compose_project": None,
    "compose_service": None,
}


class Lab:
    def __init__(self, directory, monkeypatch):
        self.directory = directory
        self.policy = POLICY.copy()
        self.clock = NOW
        self.state = BEFORE.copy()
        self.calls = []
        self.disconnect = False
        self.hide_after = False
        self.last_capture = None
        self.write_policy()
        monkeypatch.setattr(action, "STATE", directory)
        monkeypatch.setattr(action, "now", lambda: self.clock)
        monkeypatch.setattr(runtime, "capture", self.capture)
        monkeypatch.setattr(runtime, "restart", self.restart)

    def write_policy(self):
        path = self.directory / "policy.json"
        path.write_bytes(action.canonical(self.policy) + b"\n")
        path.chmod(0o600)

    def capture(self, policy):
        self.last_capture = policy
        if self.calls and self.hide_after:
            raise OSError("synthetic interrupted observation")
        return copy.deepcopy(self.state)

    def restart(self, identifier):
        expected = action.action_id(PID)
        assert identifier == CID and (self.directory / expected / "intent.json").exists()
        self.calls.append(identifier)
        self.state = AFTER.copy()
        if self.disconnect:
            raise OSError("synthetic lost acknowledgement")

    def request(self, operation, **kwargs):
        return action.dispatch(
            action.parse_request(
                action.canonical(
                    {
                        "schema_version": 1,
                        "op": operation,
                        "policy_digest": kwargs.pop("policy_digest", action.digest(self.policy)),
                        **kwargs,
                    }
                )
            )
        )

    def plan(self, identifier=PID):
        return self.request("prepare", plan_id=identifier, mode_revision=7)

    def call(self, operation, plan, **kwargs):
        return self.request(
            operation,
            policy_digest=plan["policy_digest"],
            **(
                {key: plan[key] for key in action.BINDING}
                if operation in {"submit", "reconcile_status"}
                else {"action_id": plan["action_id"]}
            ),
            **kwargs,
        )


@pytest.fixture
def lab(monkeypatch):
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("requires actual Linux root-only directory and fsync")
    with TemporaryDirectory(dir="/root", prefix=".opsark-container-test-") as folder:
        yield Lab(Path(folder), monkeypatch)


def test_exact_prepare_and_one_restart_with_old_history_after_policy_rotation(lab):
    plan = lab.plan()
    assert plan["status"] == "ready" and plan["container_id"] == CID
    assert lab.plan() == plan
    verified = lab.call("submit", plan, approval_id=APPROVAL)
    assert verified["status"] == "verified" and verified["reason"] is None
    assert lab.call("submit", plan, approval_id=APPROVAL) == verified
    assert lab.call("submit", plan, approval_id="e" * 32)["reason"] == "conflict"
    assert lab.calls == [CID]
    (lab.directory / "policy.json").unlink()
    lab.last_capture = None
    assert lab.call("status", plan) == lab.call("observe", plan) == verified
    assert lab.last_capture is None


def test_unacknowledged_restart_remains_unknown_and_no_replay(lab):
    plan = lab.plan()
    lab.disconnect = True
    original = lab.call("submit", plan, approval_id=APPROVAL)
    assert original["status"] == "unknown"
    assert lab.call("status", plan) == lab.call("observe", plan) == original
    assert lab.call("submit", plan, approval_id=APPROVAL) == original
    assert lab.plan("e" * 32)["reason"] == "conflict"
    assert lab.calls == [CID]


def test_durable_ack_allows_verified_observation_without_rewriting_original(lab):
    plan = lab.plan()
    lab.hide_after = True
    original = lab.call("submit", plan, approval_id=APPROVAL)
    assert original["status"] == "unknown" and original["reconciliation_status"] is None
    result = lab.directory / plan["action_id"] / "result.json"
    previous = result.read_bytes()
    lab.hide_after = False
    observed = lab.call("observe", plan)
    assert observed == original | {"reconciliation_status": "verified"}
    assert lab.call("status", plan) == lab.call("submit", plan, approval_id=APPROVAL) == observed
    assert result.read_bytes() == previous and lab.calls == [CID]


def test_expiry_closure_cannot_reopen_after_wall_clock_moves(lab):
    plan = lab.plan()
    assert lab.call("reconcile_status", plan)["status"] == "missing"
    lab.clock += timedelta(minutes=6)
    absent = lab.call("reconcile_status", plan)
    assert absent["status"] == "not_started" and absent["plan_digest"] == plan["plan_digest"]
    lab.clock = NOW
    assert lab.call("reconcile_status", plan) == absent
    assert lab.call("submit", plan, approval_id=APPROVAL)["reason"] == "expired"
    assert lab.calls == []


def test_preimage_change_and_policy_modes_refuse_before_restart(lab):
    plan = lab.plan()
    lab.state["mounts"] = "5" * 64
    assert lab.call("submit", plan, approval_id=APPROVAL)["reason"] == "scope_changed"
    assert lab.calls == []
    lab.policy["mode"] = "automatic"
    lab.write_policy()
    assert lab.plan("e" * 32)["reason"] == "policy_refused"


def test_visible_ack_is_synchronized_before_runtime_reconciliation(lab, monkeypatch):
    plan = lab.plan()
    lab.hide_after = True
    prior = lab.call("submit", plan, approval_id=APPROVAL)
    lab.hide_after = False
    child_info = (lab.directory / plan["action_id"]).stat()
    fsync = os.fsync

    def interrupted(fd):
        if os.path.samestat(os.fstat(fd), child_info):
            raise OSError("synthetic directory fsync interruption")
        fsync(fd)

    with monkeypatch.context() as failure:
        failure.setattr(os, "fsync", interrupted)
        assert lab.call("observe", plan)["reconciliation_status"] is None
    assert lab.call("observe", plan) == prior | {"reconciliation_status": "verified"}


def test_untrusted_journal_entry_refuses_execution(lab):
    plan = lab.plan()
    (lab.directory / plan["action_id"] / "intent.json").symlink_to(lab.directory / "policy.json")
    assert lab.call("submit", plan, approval_id=APPROVAL)["status"] == "unknown"
    assert lab.calls == []


def test_canonical_roles_and_argv_projection(monkeypatch):
    commands = []
    row = {
        "id": CID,
        "image": IMAGE,
        "created": "2026-11-13T00:00:00.1Z",
        "start": "2026-11-13T00:00:01.123456789Z",
        "pid": 22,
        "status": "running",
        "running": True,
        "paused": False,
        "restarting": False,
        "dead": False,
        "auto_remove": False,
        "restart_policy": "no",
        "project": "",
        "service": "",
        "mounts": [
            {"Type": "volume", "Destination": "/test", "RW": True, "Name": "synthetic"},
        ],
    }

    def docker(args, *_):
        commands.append(args)
        if args[0] == "info":
            return runtime.canonical(
                {"id": "synthetic", "os": "linux", "security": [], "storage": "overlay2"}
            )
        if args[:2] == ("container", "inspect"):
            return runtime.canonical(row)
        return CID.encode("ascii") + b"\n"

    monkeypatch.setattr(runtime, "socket_witness", lambda: [1, 2, 3, 4])
    monkeypatch.setattr(runtime, "boot_digest", lambda: "1" * 64)
    monkeypatch.setattr(runtime, "birth", lambda _: 22)
    monkeypatch.setattr(runtime, "command", docker)
    assert set(runtime.capture(POLICY)) == action.WITNESS
    with pytest.raises(runtime.Refused):
        runtime.capture(POLICY | {"compose_project": "test", "compose_service": "web"})
    row.update(project="test", service="web")
    assert (
        set(runtime.capture(POLICY | {"compose_project": "test", "compose_service": "web"}))
        == action.WITNESS
    )
    for changes in ({"paused": True}, {"auto_remove": True}, {"restart_policy": "always"}):
        values = row.copy()
        row.update(changes)
        with pytest.raises(runtime.Refused):
            runtime.capture(POLICY | {"compose_project": "test", "compose_service": "web"})
        row.update(values)
    runtime.restart(CID)
    assert commands[-1] == ("container", "restart", "--timeout", "10", CID)
    assert all("logs" not in call and ".Config.Env" not in " ".join(call) for call in commands)
    with pytest.raises(runtime.Refused):
        runtime.restart("short")


def test_wire_rejects_unknown_fields_and_unrelated_operations():
    base = {
        "schema_version": 1,
        "op": "prepare",
        "policy_digest": action.digest(POLICY),
        "plan_id": PID,
        "mode_revision": 7,
    }
    for changes in ({"command": "anything"}, {"op": "exec"}, {"mode_revision": True}):
        with pytest.raises(runtime.Refused):
            action.parse_request(action.canonical(base | changes))


def test_ssh_adapter_accepts_only_fixed_sudo_command(monkeypatch):
    seen = []
    monkeypatch.setattr(sys, "argv", ["entry"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(os, "execve", lambda *values: seen.append(values))
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "sftp")
    assert entry.main() == 126 and not seen
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", entry.COMMAND)
    assert entry.main() == 126
    assert seen == [
        (
            "/usr/bin/sudo",
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/python3",
                "-I",
                "-B",
                "/usr/local/lib/opsark-container-restart/restart_action.py",
            ],
            {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    ]
