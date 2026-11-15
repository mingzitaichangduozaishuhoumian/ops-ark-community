"""Execute one approved change to a private Nginx fixture, with an immutable receipt."""

import hmac
import os
import re
import secrets
from collections.abc import Callable
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path

from deploy.nginx import action_journal, config_snapshot

TARGET_NAME = "opsark-isolated-restore-fixture.conf"
WORKSPACE_MARKER = "opsark-isolated-fixture"
WORKSPACE_MARKER_CONTENT = b"opsark-nginx-fixture-v1\n"
WORKSPACE_NAME = re.compile(r"opsark-nginx-fixture-[0-9a-f]{12,32}\Z")
ORIGINAL = b"""server {
    listen 127.0.0.1:18087;
    server_name target.opsark.invalid;
    location = /healthz { default_type text/plain; return 200 "opsark-original"; }
}
"""
CANDIDATE = ORIGINAL.replace(b"opsark-original", b"opsark-candidate")
_ORIGINAL_DIGEST = config_snapshot._sha(ORIGINAL)
CANDIDATE_DIGEST = config_snapshot._sha(CANDIDATE)
_JOURNAL = "actions"
_PROTECTED_ROOTS = tuple(Path("/") / part for part in ("etc", "dev", "proc", "sys", "run", "usr"))
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
_WORKSPACE_PATH = re.compile(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z")


def _check_mounts(workspace: Path) -> None:
    # Bind mounts can alias a live config tree without using symlinks.
    seen: dict[tuple[str, str], int] = {}
    ancestors: list[tuple[str, str]] = []
    with Path("/proc/self/mountinfo").open(encoding="utf-8", errors="surrogateescape") as mounts:
        for line in mounts:
            fields = line.split()
            if len(fields) < 6:
                raise config_snapshot.SnapshotError("Fixture mount scope is unavailable")
            name = _MOUNT_ESCAPE.sub(lambda match: chr(int(match[1], 8)), fields[4])
            mount = Path(name)
            if mount.is_relative_to(workspace):
                raise config_snapshot.SnapshotError("Fixture workspace must not contain mounts")
            source = fields[2], fields[3]
            seen[source] = seen.get(source, 0) + 1
            if mount != Path("/") and workspace.is_relative_to(mount):
                ancestors.append(source)
    if any(root != "/" or seen[(device, root)] > 1 for device, root in ancestors):
        raise config_snapshot.SnapshotError("Fixture must not be below a mounted alias")


def fixture_policy(workspace: Path) -> config_snapshot.SnapshotPolicy:
    """Require an explicitly marked, root-owned workspace outside real service paths."""
    config_snapshot._check_runtime(config_snapshot.DEFAULT_POLICY)
    config_snapshot._absolute(workspace)
    if not _WORKSPACE_PATH.fullmatch(os.fspath(workspace)) or any(
        workspace.is_relative_to(p) for p in _PROTECTED_ROOTS
    ):
        raise config_snapshot.SnapshotError("A separate private fixture workspace is required")
    policy = config_snapshot.SnapshotPolicy(
        workspace, workspace / "etc/nginx/conf.d", workspace / "etc/machine-id", 0
    )
    try:
        # Walk all ancestors from / before accepting the workspace as a policy anchor.
        with config_snapshot._directory(
            workspace, config_snapshot.DEFAULT_POLICY, private=True
        ) as directory:
            marker, _identity = config_snapshot._read(
                directory, WORKSPACE_MARKER, len(WORKSPACE_MARKER_CONTENT), policy, private=True
            )
        if marker != WORKSPACE_MARKER_CONTENT:
            raise config_snapshot.SnapshotError("Explicit fixture marker is required")
        _check_mounts(workspace)
        machine = config_snapshot._machine(policy)
        host_machine = None
        with suppress(OSError, config_snapshot.SnapshotError):
            host_machine = config_snapshot._machine(config_snapshot.DEFAULT_POLICY)
        if machine == host_machine:
            raise config_snapshot.SnapshotError("Fixture must use a separate machine identity")
        with config_snapshot._directory(policy.config_directory, policy):
            pass
    except OSError as error:
        raise config_snapshot.SnapshotError("Fixture workspace could not be verified") from error
    return policy


def _read_approval(approval: Path, policy: config_snapshot.SnapshotPolicy):
    try:
        receipt, approved, expires = config_snapshot._approval(approval, policy)
        if receipt["machine_sha256"] != config_snapshot._machine(policy):
            raise config_snapshot.SnapshotError("Approval belongs to a different fixture")
        _outside_journal(policy, approval, Path(receipt["plan_path"]))
    except (OSError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise config_snapshot.SnapshotError("Fixture approval could not be verified") from error
    return receipt, approved, expires


def _outside_journal(policy: config_snapshot.SnapshotPolicy, *paths: Path) -> None:
    journal = policy.anchor / _JOURNAL
    if any(path.is_relative_to(journal) or journal.is_relative_to(path) for path in paths):
        raise config_snapshot.SnapshotError("Fixture inputs must be separate from the journal")


def action_id_for_approval(workspace: Path, approval: Path) -> str:
    """Return the lookup ID without requiring a still-active approval."""
    receipt, _, _ = _read_approval(approval, fixture_policy(workspace))
    return action_journal.action_id(receipt["plan_id"], "apply")


def _observation(
    proof: action_journal.ActionReceipt, policy: config_snapshot.SnapshotPolicy
) -> dict:
    disk_status = "unavailable"
    try:
        with config_snapshot._directory(policy.config_directory, policy) as directory:
            data, _identity = config_snapshot._read(directory, TARGET_NAME, 1024, policy)
        disk_status = (
            "preimage" if data == ORIGINAL else "candidate" if data == CANDIDATE else "drift"
        )
    except (OSError, config_snapshot.SnapshotError):
        pass
    return {**proof, "disk_status": disk_status}


def inspect_action(workspace: Path, action_id: str) -> dict:
    """Read the original action and observe disk without writing or calling Nginx."""
    policy = fixture_policy(workspace)
    proof = action_journal.ActionJournal(workspace / _JOURNAL).status(action_id)
    return _missing(action_id) if proof is None else _observation(proof, policy)


def _missing(action_id: str) -> dict:
    return {
        "schema_version": 1,
        "action": "apply",
        "action_id": action_id,
        "status": "missing",
        "disk_status": "unavailable",
    }


def _reviewed_plan(
    approval: Path,
    receipt: dict,
    policy: config_snapshot.SnapshotPolicy,
    now,
    context_reader: Callable[[], str] | None,
):
    actual, approved, expires = _read_approval(approval, policy)
    current = config_snapshot._read_clock(now)
    if actual != receipt or not approved <= current < expires:
        raise config_snapshot.SnapshotError("Fixture approval changed or expired")
    status, plan, candidate = config_snapshot._plan_state(
        Path(receipt["plan_path"]), policy, current, context_reader=context_reader
    )
    if (
        status != "ready"
        or plan is None
        or candidate != CANDIDATE
        or plan.get("context_sha256") != receipt.get("context_sha256")
        or config_snapshot._sealed_manifest_sha256(plan) != receipt["plan_manifest_sha256"]
        or any(
            plan[field] != receipt[field]
            for field in ("plan_id", "machine_sha256", "candidate_sha256", "expires_at")
        )
        or datetime.fromisoformat(plan["created_at"]) > approved
        or plan["source_name"] != TARGET_NAME
        or plan["source_sha256"] != _ORIGINAL_DIGEST
    ):
        raise config_snapshot.SnapshotError("Reviewed fixture configuration is not ready")
    _outside_journal(policy, Path(plan["backup_path"]))
    return plan


def _require_preimage(directory: int, policy: config_snapshot.SnapshotPolicy, plan: dict) -> None:
    data, identity = config_snapshot._read(directory, TARGET_NAME, 1024, policy)
    if data != ORIGINAL or identity != plan["source_identity"]:
        raise config_snapshot.SnapshotError("Fixture source changed before publication")
    _require_current_directory(directory, policy)


def _require_current_directory(directory: int, policy: config_snapshot.SnapshotPolicy) -> None:
    with config_snapshot._directory(policy.config_directory, policy) as current:
        parent, latest = os.fstat(directory), os.fstat(current)
        if (parent.st_dev, parent.st_ino) != (latest.st_dev, latest.st_ino):
            raise config_snapshot.SnapshotError("Fixture directory changed during execution")


@contextmanager
def _stage(directory: int, name: str, identity: dict, data: bytes = CANDIDATE):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    staged = os.fstat(fd)
    inode = staged.st_dev, staged.st_ino
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(fd, identity["uid"], identity["gid"])
            os.fchmod(fd, identity["mode"])
            handle.write(data)
            handle.flush()
            os.fsync(fd)
        yield inode
    finally:
        with suppress(FileNotFoundError):
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == inode:
                os.unlink(name, dir_fd=directory)


def _require_candidate(
    directory: int,
    policy: config_snapshot.SnapshotPolicy,
    inode: tuple[int, int],
    prior: dict,
    name: str = TARGET_NAME,
) -> dict:
    data, identity = config_snapshot._read(directory, name, 1024, policy)
    if (
        data != CANDIDATE
        or (identity["dev"], identity["ino"]) != inode
        or any(identity[field] != prior[field] for field in ("uid", "gid", "mode"))
    ):
        raise config_snapshot.SnapshotError("Fixture candidate could not be verified")
    _require_current_directory(directory, policy)
    return identity


def _require_publication(
    directory: int,
    policy: config_snapshot.SnapshotPolicy,
    disk_identity: dict,
    data: bytes = CANDIDATE,
) -> None:
    current, identity = config_snapshot._read(directory, TARGET_NAME, 1024, policy)
    if current != data or identity != disk_identity:
        raise config_snapshot.SnapshotError("Fixture differs from its recorded publication")
    _require_current_directory(directory, policy)


def _runtime_digest(runtime_fingerprint: Callable[[], str]) -> str:
    try:
        digest = runtime_fingerprint()
    except Exception as error:
        raise config_snapshot.SnapshotError("Isolated runtime could not be verified") from error
    if not config_snapshot._digest(digest):
        raise config_snapshot.SnapshotError("Isolated runtime could not be verified")
    return digest


def _require_runtime(runtime_fingerprint: Callable[[], str], expected: str) -> None:
    if not hmac.compare_digest(_runtime_digest(runtime_fingerprint), expected):
        raise config_snapshot.SnapshotError("Isolated runtime changed during observation")


def apply_fixture(
    workspace: Path,
    approval: Path,
    expected_approval_id: str,
    expected_candidate_sha256: str,
    *,
    confirm: bool = False,
    preflight: Callable[[], bool] | None = None,
    reload_and_verify: Callable[[], bool],
    runtime_fingerprint: Callable[[], str] | None = None,
    context_reader: Callable[[], str] | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict:
    """Apply one exact fixture under its local lock; a prior intent never repeats work."""
    policy = fixture_policy(workspace)
    if (
        confirm is not True
        or not isinstance(expected_approval_id, str)
        or not config_snapshot._PLAN_ID.fullmatch(expected_approval_id)
        or not isinstance(expected_candidate_sha256, str)
        or expected_candidate_sha256 != CANDIDATE_DIGEST
        or not callable(reload_and_verify)
        or (preflight is not None and not callable(preflight))
        or (runtime_fingerprint is not None and not callable(runtime_fingerprint))
    ):
        raise config_snapshot.SnapshotError("Exact fixture approval and confirmation are required")
    receipt, approved_at, expires = _read_approval(approval, policy)
    if not hmac.compare_digest(
        expected_approval_id, receipt["approval_id"]
    ) or not hmac.compare_digest(expected_candidate_sha256, receipt["candidate_sha256"]):
        raise config_snapshot.SnapshotError("Fixture approval does not match the reviewed values")
    journal = action_journal.ActionJournal(workspace / _JOURNAL)
    action_id = action_journal.action_id(receipt["plan_id"], "apply")
    with journal.locked() as tx:
        prior = tx.status(action_id)
        if prior is not None:
            return _observation(prior, policy)
        if tx.has_action("apply"):
            raise config_snapshot.SnapshotError("Fixture already has an original apply action")
        started = config_snapshot._read_clock(now)
        plan = _reviewed_plan(approval, receipt, policy, started, context_reader)
        if runtime_fingerprint is not None and preflight is None:
            raise config_snapshot.SnapshotError("A bound fixture runtime requires preflight")
        runtime_sha256 = (
            _runtime_digest(runtime_fingerprint) if runtime_fingerprint is not None else None
        )

        def require_bound_runtime() -> None:
            if runtime_fingerprint is not None and runtime_sha256 is not None:
                _require_runtime(runtime_fingerprint, runtime_sha256)

        if preflight is not None:
            try:
                ready = preflight()
            except Exception as error:
                raise config_snapshot.SnapshotError("Isolated runtime preflight failed") from error
            if ready is not True:
                raise config_snapshot.SnapshotError("Isolated runtime preflight failed")
        require_bound_runtime()
        if _reviewed_plan(approval, receipt, policy, now, context_reader) != plan:
            raise config_snapshot.SnapshotError("Fixture plan changed before execution")
        with config_snapshot._directory(policy.config_directory, policy) as directory:
            _require_preimage(directory, policy, plan)
            temp = ".opsark-fixture-" + secrets.token_hex(16) + ".stage"
            with _stage(directory, temp, plan["source_identity"]) as inode:
                tx.begin(
                    receipt["plan_id"],
                    "apply",
                    receipt["approval_id"],
                    receipt["plan_manifest_sha256"],
                    _ORIGINAL_DIGEST,
                    CANDIDATE_DIGEST,
                )
                try:
                    require_bound_runtime()
                    if _reviewed_plan(approval, receipt, policy, now, context_reader) != plan:
                        raise config_snapshot.SnapshotError(
                            "Fixture plan changed before publication"
                        )
                    _check_mounts(workspace)
                    _require_preimage(directory, policy, plan)
                    _require_candidate(directory, policy, inode, plan["source_identity"], temp)
                    if not max(started, approved_at) <= config_snapshot._read_clock(now) < expires:
                        raise config_snapshot.SnapshotError(
                            "Fixture approval expired before writing"
                        )
                    os.replace(temp, TARGET_NAME, src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                    published = _require_candidate(
                        directory, policy, inode, plan["source_identity"]
                    )
                    publication = None
                    if runtime_sha256 is not None:
                        require_bound_runtime()
                        _require_publication(directory, policy, published)
                        publication = tx.publish(action_id, published, runtime_sha256)
                    verified = reload_and_verify() is True
                    if verified:
                        require_bound_runtime()
                        _require_publication(directory, policy, published)
                        if publication is not None and tx.publication(action_id) != publication:
                            raise config_snapshot.SnapshotError("Fixture publication changed")
                    outcome = "verified" if verified else "unknown"
                except Exception:
                    # Intent is already durable; never infer failure or replay after uncertainty.
                    outcome = "unknown"
                proof = tx.finish(action_id, outcome)
    return _observation(proof, policy)


def reconcile_fixture(
    workspace: Path,
    action_id: str,
    *,
    runtime_fingerprint: Callable[[], str],
    verify_candidate: Callable[[], bool],
) -> dict:
    """Record independent observation for a published apply, without repeating it."""
    policy = fixture_policy(workspace)
    if not callable(runtime_fingerprint) or not callable(verify_candidate):
        raise config_snapshot.SnapshotError("Isolated runtime observation is required")
    journal = action_journal.ActionJournal(workspace / _JOURNAL)
    with journal.locked() as tx:
        proof = tx.status(action_id)
        if proof is None:
            return _missing(action_id)
        if (
            proof["action"] != "apply"
            or proof["status"] != "unknown"
            or proof.get("reconciliation_status") == "verified"
            or proof["source_sha256"] != _ORIGINAL_DIGEST
            or proof["candidate_sha256"] != CANDIDATE_DIGEST
        ):
            return _observation(proof, policy)
        publication = tx.publication(action_id)
        if publication is None:
            return _observation(proof, policy)
        try:
            with config_snapshot._directory(policy.config_directory, policy) as directory:
                disk_identity = publication["disk_identity"]
                runtime_sha256 = publication["runtime_sha256"]
                machine = config_snapshot._machine(policy)
                _require_publication(directory, policy, disk_identity)
                _require_runtime(runtime_fingerprint, runtime_sha256)
                if verify_candidate() is not True:
                    return _observation(proof, policy)
                _require_runtime(runtime_fingerprint, runtime_sha256)
                _check_mounts(workspace)
                if config_snapshot._machine(policy) != machine:
                    return _observation(proof, policy)
                _require_publication(directory, policy, disk_identity)
                if tx.publication(action_id) != publication or tx.status(action_id) != proof:
                    return _observation(proof, policy)
        except Exception:
            return _observation(proof, policy)
        proof = tx.reconcile(action_id)
    return _observation(proof, policy)
