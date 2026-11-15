"""Bootstrap serialization with the root RPC and worker, without system changes."""

import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, load_module


@pytest.fixture
def bootstrap(tmp_path, monkeypatch):
    # The installer runs on Linux; this fixture does not need a host account API.
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace())
    module = load_module("patch_install_safety", "install.py", monkeypatch)
    state = tmp_path / "state"
    state.mkdir()
    (state / "jobs").mkdir()
    marker = tmp_path / "marker.json"
    marker.write_text(json.dumps({"owner": "opsark-patch/v1"}))

    class PrivateState:
        def __truediv__(self, child):
            return state / child

        def exists(self):
            return state.exists()

        def lstat(self):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)

    events = []
    opened = {}
    held = set()
    faults = {"blocked": None, "mode": 0o600, "links": 1, "owner": 0}
    original_open, original_close, original_fstat = os.open, os.close, os.fstat

    def open_file(path, flags, mode=0o777, **kwargs):
        fd = original_open(path, flags, mode, **kwargs)
        if Path(path).parent == state and Path(path).suffix == ".lock":
            opened[fd] = Path(path).stem
            events.append(("open", opened[fd]))
        return fd

    def close_file(fd):
        if fd in opened:
            events.append(("close", opened[fd]))
            held.discard(opened[fd])
        return original_close(fd)

    def metadata(fd):
        if fd not in opened:
            return original_fstat(fd)
        return SimpleNamespace(
            st_mode=stat.S_IFREG | faults["mode"],
            st_uid=faults["owner"],
            st_nlink=faults["links"],
        )

    def flock(fd, flags):
        assert flags == 3  # LOCK_EX | LOCK_NB, without waiting for or killing a worker.
        name = opened[fd]
        events.append(("lock", name))
        if faults["blocked"] == name:
            raise BlockingIOError("fixture lock busy")
        held.add(name)

    monkeypatch.setattr(module, "STATE", PrivateState())
    monkeypatch.setattr(module, "MARKER", marker)
    monkeypatch.setattr(module, "secure_dir", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "owned_file", lambda path, *_args: path.read_bytes())
    monkeypatch.setattr(module, "run", lambda _args: pytest.fail("No system command allowed"))
    monkeypatch.setattr(module.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(module.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    monkeypatch.setattr(module.os, "open", open_file)
    monkeypatch.setattr(module.os, "close", close_file)
    monkeypatch.setattr(module.os, "fstat", metadata)
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=flock))
    return SimpleNamespace(
        module=module,
        state=state,
        marker=marker,
        events=events,
        held=held,
        faults=faults,
    )


def test_upgrade_holds_rpc_then_worker_locks_through_the_entire_install(bootstrap, monkeypatch):
    def install_locked(_policy, _key):
        assert bootstrap.held == {"rpc", "worker"}
        bootstrap.events.append(("write", "reviewed_source_policy_mode_marker"))
        return {"installed": True}

    monkeypatch.setattr(bootstrap.module, "install_locked", install_locked)
    assert bootstrap.module.install("policy-fixture", "key-fixture") == {"installed": True}
    assert bootstrap.events == [
        ("open", "rpc"),
        ("lock", "rpc"),
        ("open", "worker"),
        ("lock", "worker"),
        ("write", "reviewed_source_policy_mode_marker"),
        ("close", "worker"),
        ("close", "rpc"),
    ]
    assert not bootstrap.held


@pytest.mark.parametrize("name", ["rpc", "worker"])
def test_upgrade_refuses_busy_root_lock_without_touching_code(bootstrap, monkeypatch, name):
    bootstrap.faults["blocked"] = name
    monkeypatch.setattr(
        bootstrap.module, "install_locked", lambda *_args: pytest.fail("Must not replace code")
    )
    with pytest.raises(ValueError, match="active repair"):
        bootstrap.module.install("policy-fixture", "key-fixture")
    assert not bootstrap.held


@pytest.mark.parametrize(
    "status",
    [
        "queued",
        "preflight",
        "downloading",
        "applying",
        "verifying",
        "running_overdue",
        "awaiting_transport_verification",
        "unknown",
    ],
)
def test_active_job_is_rechecked_after_both_locks_and_preserved(bootstrap, monkeypatch, status):
    folder = bootstrap.state / "jobs" / JOB
    folder.mkdir()
    record = json.dumps({"job_id": JOB, "status": status}).encode()
    job_path = folder / "job.json"
    job_path.write_bytes(record)

    def install_locked(_policy, _key):
        assert bootstrap.held == {"rpc", "worker"}
        bootstrap.module.reject_unfinished_jobs()
        pytest.fail("Must not install over an unfinished job")

    monkeypatch.setattr(bootstrap.module, "install_locked", install_locked)
    with pytest.raises(ValueError, match="active or uncertain"):
        bootstrap.module.install("policy-fixture", "key-fixture")
    assert job_path.read_bytes() == record
    assert not bootstrap.held


def test_job_created_before_lock_acquisition_is_not_missed(bootstrap, monkeypatch):
    def install_locked(_policy, _key):
        # Models admission just before the installer obtained the RPC lock.
        folder = bootstrap.state / "jobs" / JOB
        folder.mkdir()
        (folder / "job.json").write_text(json.dumps({"status": "queued"}))
        bootstrap.module.reject_unfinished_jobs()
        pytest.fail("The queued intent must prevent replacement")

    monkeypatch.setattr(bootstrap.module, "install_locked", install_locked)
    with pytest.raises(ValueError, match="active or uncertain"):
        bootstrap.module.install("policy-fixture", "key-fixture")


@pytest.mark.parametrize("status", ["verified", "failed", "rejected", "verification_failed"])
def test_terminal_job_records_survive_a_permitted_upgrade(bootstrap, status):
    folder = bootstrap.state / "jobs" / JOB
    folder.mkdir()
    record = json.dumps({"job_id": JOB, "status": status}).encode()
    job_path = folder / "job.json"
    job_path.write_bytes(record)
    with bootstrap.module.upgrade_locks():
        bootstrap.module.reject_unfinished_jobs()
        assert bootstrap.held == {"rpc", "worker"}
    assert job_path.read_bytes() == record


@pytest.mark.parametrize("fault,value", [("mode", 0o644), ("links", 2), ("owner", 1000)])
def test_untrusted_lock_inode_prevents_upgrade(bootstrap, fault, value):
    bootstrap.faults[fault] = value
    with (
        pytest.raises(ValueError, match="Untrusted repair upgrade lock"),
        bootstrap.module.upgrade_locks(),
    ):
        pytest.fail("Untrusted lock must not be used")
    assert not bootstrap.held


def test_install_error_releases_both_locks_without_hiding_error(bootstrap, monkeypatch):
    def fail_install(*_args):
        raise ValueError("fixture policy rejected")

    monkeypatch.setattr(bootstrap.module, "install_locked", fail_install)
    with pytest.raises(ValueError, match="fixture policy rejected"):
        bootstrap.module.install("policy-fixture", "key-fixture")
    assert not bootstrap.held


def test_interrupted_first_bootstrap_without_state_can_resume(bootstrap, monkeypatch):
    (bootstrap.state / "jobs").rmdir()
    bootstrap.state.rmdir()
    monkeypatch.setattr(bootstrap.module, "install_locked", lambda *_args: {"resumed": True})
    assert bootstrap.module.install("policy-fixture", "key-fixture") == {"resumed": True}
    assert bootstrap.events == []


@pytest.mark.parametrize(
    "enabled,grant,expected",
    [
        (True, None, ["assisted"]),
        (True, {"enabled": False}, ["assisted"]),
        (False, {"enabled": True}, ["assisted"]),
        (True, {"enabled": True}, ["assisted", "automatic"]),
    ],
)
def test_install_summary_matches_validated_root_automatic_capability(
    bootstrap, enabled, grant, expected
):
    policy = {"enabled": enabled, "automatic": grant}
    assert bootstrap.module.supported_execution_modes(policy) == expected
