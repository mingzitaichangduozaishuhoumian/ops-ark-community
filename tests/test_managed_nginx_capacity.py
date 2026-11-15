"""Exercise Nginx preview retirement with native file publication and journal locking."""

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from deploy.nginx import action_journal as journal
from deploy.nginx import config_snapshot as snapshot
from deploy.nginx import managed_action as action
from deploy.nginx import managed_context as context

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Actual Linux ownership, directory fsync and advisory lock",
)

NOW = datetime(2026, 11, 13, tzinfo=UTC)
POLICY = "f" * 64
OLD, NEW = b"synthetic old upstream\n", b"synthetic new upstream\n"


class Workspace:
    def __init__(self, directory):
        self.root = directory / "state"
        self.plans = self.root / "plans"
        self.backups = self.root / "backups"
        self.actions = self.root / "actions"
        for item in (self.root, self.plans, self.backups, self.actions):
            item.mkdir(mode=0o700)
        config = directory / "etc/nginx/conf.d"
        config.mkdir(mode=0o700, parents=True)
        machine = directory / "machine-id"
        machine.write_bytes(b"1" * 32)
        self.policy = snapshot.SnapshotPolicy(directory, config, machine, 0)
        self.live = config / "target.conf"
        self.live.write_bytes(OLD)

    def backup(self, identifier):
        path = self.backups / identifier
        snapshot.capture(self.live, context.digest(OLD), path, policy=self.policy)
        return snapshot._backup(path, self.policy)

    def plan(self, identifier, *, expires=NOW, restore=None):
        original = restore if restore is not None else identifier
        if restore is None:
            data, manifest, digest = self.backup(original)
        else:
            data, manifest, digest = snapshot._backup(self.backups / original, self.policy)
        source, candidate = (OLD, NEW) if restore is None else (NEW, OLD)
        kind = "apply" if restore is None else "restore"
        view = {
            "schema_version": 1,
            "status": "ready",
            "syntax": "passed",
            "plan_id": identifier,
            "action": kind,
            "action_id": journal.action_id(identifier, kind),
            "policy_digest": POLICY,
            "mode_revision": 2,
            "source_sha256": context.digest(source),
            "candidate_sha256": context.digest(candidate),
            "backup_sha256": context.digest(data),
            "context_sha256": "d" * 64,
            "expires_at": expires.isoformat(),
            "affected_site_ids": ["target"],
            "upstream_before": "127.0.0.1:18081" if restore is None else "127.0.0.1:18082",
            "upstream_after": "127.0.0.1:18082" if restore is None else "127.0.0.1:18081",
            "original_action_id": None if restore is None else journal.action_id(restore),
        }
        private = {
            "machine_sha256": manifest["machine_sha256"],
            "master_sha256": "a" * 64,
            "source_identity": manifest["source_identity"],
            "backup_plan_id": original,
            "backup_manifest_sha256": digest,
            "non_target_context_sha256": "c" * 64,
            "startup_sha256": "b" * 64,
        }
        view["plan_digest"] = action._plan_digest(view, private)
        snapshot._publish(
            self.plans / identifier,
            "candidate.conf",
            candidate,
            {"view": view, "private": private},
            lambda: None,
            self.policy,
        )
        return view

    def prune(self, now=NOW):
        with action._journal().locked() as tx:
            action._reclaim_previews(tx, now)


@pytest.fixture
def workspace(monkeypatch):
    with TemporaryDirectory(prefix=".opsark-nginx-capacity-", dir="/root") as folder:
        lab = Workspace(Path(folder))
        monkeypatch.setattr(context, "PRIVATE_ROOT", lab.root)
        monkeypatch.setattr(snapshot, "DEFAULT_POLICY", lab.policy)
        yield lab


def request(operation, identifier, **fields):
    return {
        "schema_version": 1,
        "op": operation,
        "policy_digest": POLICY,
        "plan_id": identifier,
        **fields,
    }


def action_request(operation, view, **fields):
    binding = {key: view[key] for key in ("action_id", "plan_digest", "mode_revision")}
    return request(operation, view["plan_id"], **binding, **fields)


def test_new_preview_reclaims_full_expired_capacity_and_preserves_original_query(
    workspace, monkeypatch
):
    plans = {f"{index:032x}": workspace.plan(f"{index:032x}") for index in range(24)}
    orphan = "c" * 32
    # A previous backup can publish before its plan, including when plans are at capacity.
    workspace.backup(orphan)
    fresh = "f" * 32
    with pytest.raises(context.Refused, match="busy"):
        action._plan_capacity(fresh, restore=False)
    action._plan_capacity(fresh, restore=True)

    class AtDeadline:
        @staticmethod
        def now(_zone):
            return NOW

    monkeypatch.setattr(action, "datetime", AtDeadline)
    monkeypatch.setattr(
        context, "active_policy", lambda _: SimpleNamespace(policy_digest=POLICY, expires_at=NOW)
    )

    def graph(_policy):
        # The action must reach the ordinary graph gate after reclaiming capacity.
        raise context.Refused("business_unconfirmed")

    monkeypatch.setattr(context, "capture_graph", graph)
    response = action.dispatch(request("prepare", fresh, mode_revision=2))
    assert response["reason"] == "business_unconfirmed"
    assert {p.name for p in workspace.plans.iterdir()} == {action._RETIRED}
    assert not list(workspace.backups.iterdir()) and not list(workspace.actions.iterdir())
    archive = workspace.plans / action._RETIRED
    assert {p.name for p in archive.iterdir()} == {identifier + ".json" for identifier in plans}
    for identifier, view in plans.items():
        assert action.dispatch(request("plan_status", identifier)) == view
    action._plan_capacity(fresh, restore=False)


def test_retirement_preserves_unknown_and_verified_actions_and_restore_references(workspace):
    unknown, verified, restore, pending = ("1" * 32, "2" * 32, "3" * 32, "4" * 32)
    referenced, reference = "5" * 32, "6" * 32
    unknown_view = workspace.plan(unknown)
    verified_view = workspace.plan(verified)
    workspace.plan(restore, expires=NOW + timedelta(seconds=30), restore=verified)
    workspace.plan(pending, expires=NOW + timedelta(seconds=30))
    workspace.plan(referenced)
    workspace.plan(reference, expires=NOW + timedelta(seconds=30), restore=referenced)
    with action._journal().locked() as tx:
        for view in (unknown_view, verified_view):
            tx.begin(
                view["plan_id"],
                "apply",
                "a" * 32,
                view["plan_digest"],
                view["source_sha256"],
                view["candidate_sha256"],
            )
        identity = snapshot._signature(workspace.live.stat())
        identity["size"] = len(NEW)
        tx.publish(verified_view["action_id"], identity, "a" * 64)
        tx.finish(verified_view["action_id"], "verified")
        before = {p.name: p.read_bytes() for p in workspace.actions.iterdir()}
    workspace.prune()
    assert {p.name for p in workspace.plans.iterdir()} == {
        unknown,
        verified,
        restore,
        pending,
        referenced,
        reference,
    }
    assert {p.name for p in workspace.backups.iterdir()} == {unknown, verified, pending, referenced}
    assert {p.name: p.read_bytes() for p in workspace.actions.iterdir()} == before
    assert (
        action.dispatch(
            {"op": "status", "policy_digest": POLICY, "action_id": unknown_view["action_id"]}
        )["status"]
        == "unknown"
    )
    assert (
        action.dispatch(
            {"op": "status", "policy_digest": POLICY, "action_id": verified_view["action_id"]}
        )["status"]
        == "verified"
    )


def test_restore_uses_reserved_slots_without_requiring_unrelated_backup_cleanup(
    workspace, monkeypatch
):
    for index in range(24):
        workspace.plan(f"{index:032x}")
    unexpected = workspace.backups / ("e" * 32)
    unexpected.symlink_to(workspace.live)
    monkeypatch.setattr(
        context, "active_policy", lambda _: SimpleNamespace(policy_digest=POLICY, expires_at=NOW)
    )

    def graph(_policy):
        raise context.Refused("business_unconfirmed")

    monkeypatch.setattr(context, "capture_graph", graph)
    response = action.dispatch(
        request("rollback_prepare", "f" * 32, mode_revision=2, original_action_id="a" * 64)
    )
    assert response["reason"] == "business_unconfirmed"
    assert unexpected.is_symlink()


def test_archived_plan_proves_no_start_and_blocks_stale_approval_after_clock_rollback(
    workspace, monkeypatch
):
    identifier = "a" * 32
    view = workspace.plan(identifier)
    active = action._load_plan(identifier)
    assert active is not None and not active.retired
    workspace.prune()

    class Earlier:
        @staticmethod
        def now(_zone):
            return NOW - timedelta(minutes=5)

    monkeypatch.setattr(action, "datetime", Earlier)
    outcome = action.dispatch(action_request("reconcile_status", view))
    assert (outcome["status"], outcome["reason"], outcome["plan_id"]) == (
        "not_started",
        "expired",
        identifier,
    )
    delayed = action_request("submit", view, approval_id="b" * 32)
    with pytest.raises(context.Refused, match="expired"):
        action._submit(delayed, active)
    assert action.dispatch(delayed)["reason"] == "expired"
    assert not list(workspace.actions.iterdir())
    assert action.dispatch(request("plan_status", identifier)) == view


def test_resume_after_archive_is_durable_but_before_active_bundle_moves(workspace, monkeypatch):
    identifier = "a" * 32
    view = workspace.plan(identifier)

    def interrupted(*_args, **_kwargs):
        raise OSError("fixture interruption after archive")

    with monkeypatch.context() as step:
        step.setattr(action, "_stage_reclaim", interrupted)
        with pytest.raises(journal.JournalError, match="journal is unavailable"):
            workspace.prune()
    assert (workspace.plans / identifier).is_dir()
    assert (workspace.backups / identifier).is_dir()
    assert action.dispatch(request("plan_status", identifier)) == view
    workspace.prune(NOW - timedelta(minutes=5))
    assert not (workspace.plans / identifier).exists()
    assert not (workspace.backups / identifier).exists()
    assert action.dispatch(request("plan_status", identifier)) == view


def test_visible_archive_requires_fsync_before_expiry_proof(workspace, monkeypatch):
    identifier = "a" * 32
    view = workspace.plan(identifier)
    archive = workspace.plans / action._RETIRED
    record = archive / (identifier + ".json")
    fsync = os.fsync

    class Earlier:
        @staticmethod
        def now(_zone):
            return NOW - timedelta(minutes=5)

    def fail_archive_sync(fd):
        if record.is_file() and os.path.samestat(os.fstat(fd), archive.stat()):
            raise OSError("fixture interruption before archive fsync")
        fsync(fd)

    def refuse_policy_read(_digest):
        pytest.fail("Retirement closure must precede any live policy read")

    monkeypatch.setattr(context, "active_policy", refuse_policy_read)
    with monkeypatch.context() as interrupted:
        interrupted.setattr(os, "fsync", fail_archive_sync)
        with pytest.raises(journal.JournalError, match="journal is unavailable"):
            workspace.prune()
        assert record.is_file() and (workspace.plans / identifier).is_dir()

        interrupted.setattr(action, "datetime", Earlier)
        reconcile = action_request("reconcile_status", view)
        submit = action_request("submit", view, approval_id="b" * 32)
        for query in (reconcile, submit):
            receipt = action.dispatch(query)
            assert (receipt["status"], receipt["reason"], receipt["plan_id"]) == (
                "unknown",
                "operation_unconfirmed",
                identifier,
            )
        assert not list(workspace.actions.iterdir())

    synchronized = []
    directories = [workspace.root, workspace.plans, archive]
    stats = [directory.stat() for directory in directories]

    def track_sync(fd):
        fsync(fd)
        info = os.fstat(fd)
        synchronized.extend(
            path
            for path, expected in zip(directories, stats, strict=True)
            if os.path.samestat(info, expected)
        )

    monkeypatch.setattr(action, "datetime", Earlier)
    monkeypatch.setattr(os, "fsync", track_sync)
    receipt = action.dispatch(reconcile)
    assert (receipt["status"], receipt["reason"]) == ("not_started", "expired")
    assert synchronized[-len(directories) :] == directories
    assert action.dispatch(submit)["reason"] == "expired"
    assert not list(workspace.actions.iterdir())


@pytest.mark.parametrize("kind", ["plans", "backups"])
def test_resume_retirement_after_interruption_between_member_removals(workspace, monkeypatch, kind):
    identifier = "a" * 32
    view = workspace.plan(identifier)
    reclaim = action._reclaim_directory

    def interrupted(scope, parent, plan_id, *, unpublished):
        if scope != kind:
            return reclaim(scope, parent, plan_id, unpublished=unpublished)
        staged = workspace.root / scope / (action._RETIRING + plan_id)
        member = "candidate.conf" if scope == "plans" else snapshot._CONFIG
        (staged / member).unlink()
        raise OSError("fixture interruption")

    with monkeypatch.context() as step:
        step.setattr(action, "_reclaim_directory", interrupted)
        with pytest.raises(journal.JournalError, match="journal is unavailable"):
            workspace.prune()
    assert (workspace.root / kind / (action._RETIRING + identifier)).is_dir()
    assert action.dispatch(request("plan_status", identifier)) == view
    workspace.prune()
    assert not list(workspace.backups.iterdir())
    assert {p.name for p in workspace.plans.iterdir()} == {action._RETIRED}


def test_interrupted_unpublished_plan_and_backup_are_reclaimed_but_links_are_refused(workspace):
    identifier = "a" * 32
    pending_plan = workspace.plans / identifier
    pending_backup = workspace.backups / identifier
    for bundle, member in ((pending_plan, "candidate.conf"), (pending_backup, snapshot._CONFIG)):
        bundle.mkdir(mode=0o700)
        for name in (member, snapshot._PENDING_MANIFEST):
            artifact = bundle / name
            artifact.touch(mode=0o600)
    workspace.prune()
    assert not pending_plan.exists() and not pending_backup.exists()
    assert action.dispatch(request("plan_status", identifier))["status"] == "missing"

    pending_backup.mkdir(mode=0o700)
    (pending_backup / snapshot._CONFIG).symlink_to(workspace.live)
    with pytest.raises(context.Refused):
        workspace.prune()
    assert (pending_backup / snapshot._CONFIG).is_symlink()
    assert workspace.live.read_bytes() == OLD
