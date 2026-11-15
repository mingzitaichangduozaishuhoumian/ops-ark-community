"""A queried historical pending installation must stay byte-identical for activation."""

import pytest
from test_patch_agent import JOB
from test_patch_agent import remote as remote


def test_changed_driver_scope_status_never_rewrites_pending_parent(remote):
    folder = remote.path / "jobs" / JOB
    folder.mkdir()
    value = {
        "schema_version": 1,
        "job_id": JOB,
        "host_id": remote.policy["host_id"],
        "policy_digest": "f" * 64,
        "status": "installed_restart_pending",
        "revision": 7,
    }
    remote.core.write_json(folder / "job.json", value)
    before = (folder / "job.json").read_bytes()
    with pytest.raises(remote.core.Rejected, match="preserved"):
        remote.agent.status(JOB, remote.policy)
    assert (folder / "job.json").read_bytes() == before


def test_current_scope_status_keeps_the_same_pending_parent(remote):
    folder = remote.path / "jobs" / JOB
    folder.mkdir()
    value = {
        "schema_version": 1,
        "job_id": JOB,
        "host_id": remote.policy["host_id"],
        "policy_digest": remote.core.policy_digest(remote.policy),
        "status": "installed_restart_pending",
        "revision": 7,
    }
    remote.core.write_json(folder / "job.json", value)
    before = (folder / "job.json").read_bytes()
    assert remote.agent.status(JOB, remote.policy) == value
    assert (folder / "job.json").read_bytes() == before
