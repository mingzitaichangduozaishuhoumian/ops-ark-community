"""Authorize and execute a separate, single-use restore in one isolated Nginx fixture."""

import hmac
import json
import os
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from deploy.nginx import action_journal, config_snapshot, fixture_action

_RECEIPT = "restore-approval.json"
_LIFETIME = timedelta(minutes=5)
_ORIGINAL_SHA256 = config_snapshot._sha(fixture_action.ORIGINAL)
_CANDIDATE_SHA256 = fixture_action.CANDIDATE_DIGEST
_FIELDS = {
    "schema_version",
    "approval_id",
    "original_action_id",
    "original_approval_path",
    "original_approval_sha256",
    "restore_action_id",
    "plan_id",
    "plan_sha256",
    "backup_manifest_sha256",
    "publication_sha256",
    "original_sha256",
    "candidate_sha256",
    "runtime_sha256",
    "machine_sha256",
    "image_sha256",
    "approved_at",
    "expires_at",
    "manifest_sha256",
}


@dataclass(frozen=True)
class _RestoreInput:
    metadata: dict
    disk_identity: dict
    plan: Path
    backup: Path
    original_approved_at: datetime
    context_sha256: str | None


def _check_separation(output: Path, policy: config_snapshot.SnapshotPolicy, *inputs: Path) -> None:
    config_snapshot._snapshot_path(output, policy)
    fixture_action._outside_journal(policy, output, *inputs)
    if any(path.is_relative_to(output) or output.is_relative_to(path) for path in inputs):
        raise config_snapshot.SnapshotError("Restore approval must be separate from its inputs")


def _restore_input(
    tx: action_journal._Transaction,
    action: str,
    original_approval: Path,
    policy: config_snapshot.SnapshotPolicy,
) -> _RestoreInput:
    status = tx.status(action)
    intent = tx.intent_binding(action)
    publication = tx.publication(action)
    if (
        status is None
        or intent is None
        or publication is None
        or status["action"] != "apply"
        or not (status["status"] == "verified" or status.get("reconciliation_status") == "verified")
    ):
        raise config_snapshot.SnapshotError("Restore needs a proven original application")

    receipt, approved_at, _expires = fixture_action._read_approval(original_approval, policy)
    plan_path = Path(receipt["plan_path"])
    plan, created, _plan_expires, candidate = config_snapshot._plan(plan_path, policy)
    if (
        intent["plan_id"] != receipt["plan_id"]
        or intent["approval_id"] != receipt["approval_id"]
        or intent["plan_sha256"] != receipt["plan_manifest_sha256"]
        or action_journal.action_id(plan["plan_id"], "apply") != action
        or config_snapshot._sealed_manifest_sha256(plan) != receipt["plan_manifest_sha256"]
        or any(
            plan[name] != receipt[name]
            for name in ("plan_id", "candidate_sha256", "machine_sha256", "expires_at")
        )
        or created > approved_at
        or plan["source_name"] != fixture_action.TARGET_NAME
        or plan["source_sha256"] != _ORIGINAL_SHA256
        or intent["source_sha256"] != _ORIGINAL_SHA256
        or intent["candidate_sha256"] != _CANDIDATE_SHA256
        or candidate != fixture_action.CANDIDATE
        or plan.get("context_sha256") != receipt.get("context_sha256")
    ):
        raise config_snapshot.SnapshotError("Restore input does not match the original approval")

    backup_path = Path(plan["backup_path"])
    fixture_action._outside_journal(policy, backup_path)
    original, backup, backup_sha = config_snapshot._backup(backup_path, policy)
    if (
        original != fixture_action.ORIGINAL
        or backup_sha != plan["backup_manifest_sha256"]
        or backup["content_sha256"] != _ORIGINAL_SHA256
        or any(
            backup[name] != plan[name]
            for name in ("source_name", "source_identity", "machine_sha256")
        )
        or any(
            publication["disk_identity"][name] != plan["source_identity"][name]
            for name in ("mode", "uid", "gid")
        )
    ):
        raise config_snapshot.SnapshotError("Restore backup does not match the original plan")

    metadata = {
        "original_action_id": action,
        "original_approval_path": str(original_approval),
        "original_approval_sha256": config_snapshot._sha(config_snapshot._json(receipt)),
        "restore_action_id": action_journal.action_id(plan["plan_id"], "restore"),
        "plan_id": plan["plan_id"],
        "plan_sha256": receipt["plan_manifest_sha256"],
        "backup_manifest_sha256": backup_sha,
        "publication_sha256": publication["publication_sha256"],
        "original_sha256": _ORIGINAL_SHA256,
        "candidate_sha256": _CANDIDATE_SHA256,
        "runtime_sha256": publication["runtime_sha256"],
        "machine_sha256": plan["machine_sha256"],
        "image_sha256": receipt["image_sha256"],
    }
    return _RestoreInput(
        metadata,
        publication["disk_identity"],
        plan_path,
        backup_path,
        approved_at,
        plan.get("context_sha256"),
    )


def _require_disk(
    directory: int,
    policy: config_snapshot.SnapshotPolicy,
    source: _RestoreInput,
) -> None:
    fixture_action._require_publication(directory, policy, source.disk_identity)


def _verify_current(
    source: _RestoreInput,
    policy: config_snapshot.SnapshotPolicy,
    runtime_fingerprint: Callable[[], str],
    verify_candidate: Callable[[], bool] | None = None,
    *,
    context_reader: Callable[[], str] | None = None,
) -> None:
    def require_context() -> None:
        actual = context_reader() if context_reader is not None else None
        if actual != source.context_sha256 or (context_reader is not None and actual is None):
            raise config_snapshot.SnapshotError("The reviewed restore context changed")

    with config_snapshot._directory(policy.config_directory, policy) as directory:
        require_context()
        _require_disk(directory, policy, source)
        if fixture_action._runtime_digest(runtime_fingerprint) != source.metadata["runtime_sha256"]:
            raise config_snapshot.SnapshotError("Restore runtime differs from the original")
        if verify_candidate is not None:
            try:
                healthy = verify_candidate()
            except Exception as error:
                raise config_snapshot.SnapshotError(
                    "Restore candidate verification failed"
                ) from error
            if (
                healthy is not True
                or fixture_action._runtime_digest(runtime_fingerprint)
                != source.metadata["runtime_sha256"]
            ):
                raise config_snapshot.SnapshotError("Restore candidate verification failed")
        _require_disk(directory, policy, source)
        require_context()


def _safe_proof(status: str, receipt: dict | None = None) -> dict:
    proof = {"schema_version": 1, "approval_status": status}
    if receipt is not None:
        for key in (
            "approval_id",
            "original_action_id",
            "restore_action_id",
            "original_sha256",
            "candidate_sha256",
            "image_sha256",
            "expires_at",
        ):
            proof[key] = receipt[key]
    return proof


def approve_restore(
    workspace: Path,
    original_action_id: str,
    original_approval: Path,
    expected_original_sha256: str,
    output: Path,
    *,
    runtime_fingerprint: Callable[[], str],
    verify_candidate: Callable[[], bool],
    context_reader: Callable[[], str] | None = None,
    syntax_check: Callable[[bytes, str], str] | None = None,
    confirm: bool = False,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict:
    """Approve restoring the exact original file after proving this candidate is live."""
    policy = fixture_action.fixture_policy(workspace)
    if (
        confirm is not True
        or expected_original_sha256 != _ORIGINAL_SHA256
        or not config_snapshot._digest(original_action_id)
        or not callable(verify_candidate)
        or not callable(runtime_fingerprint)
    ):
        raise config_snapshot.SnapshotError(
            "Explicit confirmation of the reviewed backup is required"
        )
    journal = action_journal.ActionJournal(workspace / "actions")
    try:
        with journal.locked() as tx:
            if tx.has_action("restore"):
                raise config_snapshot.SnapshotError("Fixture already has a restore intent")
            started = config_snapshot._read_clock(now)
            source = _restore_input(tx, original_action_id, original_approval, policy)
            if started < source.original_approved_at:
                raise config_snapshot.SnapshotError("Restore approval clock is unavailable")
            _check_separation(output, policy, original_approval, source.plan, source.backup)
            with config_snapshot._directory(output.parent, policy) as parent:
                try:
                    os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise config_snapshot.SnapshotError("Restore approval already exists")
            _verify_current(
                source, policy, runtime_fingerprint, verify_candidate, context_reader=context_reader
            )
            if (source.context_sha256 is None) != (syntax_check is None):
                raise config_snapshot.SnapshotError("A context-bound restore needs its validator")
            validator = syntax_check if syntax_check is not None else config_snapshot._docker_syntax
            if validator(fixture_action.ORIGINAL, source.metadata["image_sha256"]) != "passed":
                raise config_snapshot.SnapshotError(
                    "Isolated backup syntax validation did not pass"
                )
            approved_at = config_snapshot._read_clock(now)
            if approved_at < started:
                raise config_snapshot.SnapshotError("Restore approval clock moved backward")
            expires = approved_at + _LIFETIME

            def recheck() -> None:
                current = config_snapshot._read_clock(now)
                if (
                    not approved_at <= current < expires
                    or _restore_input(tx, original_action_id, original_approval, policy) != source
                ):
                    raise config_snapshot.SnapshotError("Restore inputs changed during approval")
                _verify_current(
                    source,
                    policy,
                    runtime_fingerprint,
                    verify_candidate,
                    context_reader=context_reader,
                )
                checked_at = config_snapshot._read_clock(now)
                if (
                    not current <= checked_at < expires
                    or _restore_input(tx, original_action_id, original_approval, policy) != source
                ):
                    raise config_snapshot.SnapshotError(
                        "Restore inputs changed during verification"
                    )

            receipt = {
                **source.metadata,
                "schema_version": 1,
                "approval_id": secrets.token_hex(16),
                "approved_at": approved_at.isoformat(),
                "expires_at": expires.isoformat(),
            }
            receipt["manifest_sha256"] = config_snapshot._sha(config_snapshot._json(receipt))
            config_snapshot._publish(
                output, None, None, receipt, recheck, policy, manifest_name=_RECEIPT
            )
    except config_snapshot.SnapshotError:
        raise
    except (
        OSError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        raise config_snapshot.SnapshotError(
            "Fixture restore approval could not be recorded"
        ) from error
    return _safe_proof("approved", receipt)


def _read_receipt(
    approval: Path, policy: config_snapshot.SnapshotPolicy
) -> tuple[dict, datetime, datetime]:
    config_snapshot._snapshot_path(approval, policy)
    with config_snapshot._directory(approval, policy, private=True) as directory:
        config_snapshot._members(directory, {_RECEIPT})
        raw, _ = config_snapshot._read(
            directory, _RECEIPT, config_snapshot.MAX_MANIFEST_BYTES, policy, private=True
        )
        config_snapshot._members(directory, {_RECEIPT})
    receipt = json.loads(raw, object_pairs_hook=config_snapshot._unique)
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _FIELDS
        or raw != config_snapshot._json(receipt) + b"\n"
    ):
        raise config_snapshot.SnapshotError("Invalid fixture restore receipt")
    manifest_sha = receipt.pop("manifest_sha256")
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or not isinstance(receipt["original_approval_path"], str)
        or not all(
            isinstance(receipt[name], str) and config_snapshot._PLAN_ID.fullmatch(receipt[name])
            for name in ("approval_id", "plan_id")
        )
        or not all(
            config_snapshot._digest(receipt[name])
            for name in (
                "original_action_id",
                "original_approval_sha256",
                "restore_action_id",
                "plan_sha256",
                "backup_manifest_sha256",
                "publication_sha256",
                "runtime_sha256",
                "machine_sha256",
            )
        )
        or receipt["original_action_id"] != action_journal.action_id(receipt["plan_id"], "apply")
        or receipt["restore_action_id"] != action_journal.action_id(receipt["plan_id"], "restore")
        or receipt["original_sha256"] != _ORIGINAL_SHA256
        or receipt["candidate_sha256"] != _CANDIDATE_SHA256
        or manifest_sha != config_snapshot._sha(config_snapshot._json(receipt))
    ):
        raise config_snapshot.SnapshotError("Invalid fixture restore receipt")
    config_snapshot._pinned_image(receipt["image_sha256"])
    _check_separation(approval, policy, Path(receipt["original_approval_path"]))
    approved_at = config_snapshot._clock(datetime.fromisoformat(receipt["approved_at"]))
    expires = config_snapshot._clock(datetime.fromisoformat(receipt["expires_at"]))
    if (
        approved_at.isoformat() != receipt["approved_at"]
        or expires.isoformat() != receipt["expires_at"]
        or expires - approved_at != _LIFETIME
    ):
        raise config_snapshot.SnapshotError("Invalid restore approval lifetime")
    return {**receipt, "manifest_sha256": manifest_sha}, approved_at, expires


def restore_action_id(workspace: Path, approval: Path) -> str:
    """Return the immutable restore lookup ID, even after approval expiry."""
    policy = fixture_action.fixture_policy(workspace)
    receipt, _, _ = _read_receipt(approval, policy)
    if receipt["machine_sha256"] != config_snapshot._machine(policy):
        raise config_snapshot.SnapshotError("Restore approval belongs to another fixture")
    return receipt["restore_action_id"]


def _require_binding(
    tx: action_journal._Transaction,
    approval: Path,
    receipt: dict,
    policy: config_snapshot.SnapshotPolicy,
    current: datetime,
) -> _RestoreInput:
    actual, approved_at, expires = _read_receipt(approval, policy)
    if actual != receipt or not approved_at <= current < expires:
        raise config_snapshot.SnapshotError("Restore approval changed or expired")
    original_approval = Path(receipt["original_approval_path"])
    source = _restore_input(tx, receipt["original_action_id"], original_approval, policy)
    _check_separation(approval, policy, original_approval, source.plan, source.backup)
    if (
        any(receipt[key] != value for key, value in source.metadata.items())
        or approved_at < source.original_approved_at
    ):
        raise config_snapshot.SnapshotError("Restore receipt does not match the original action")
    return source


def inspect_restore_approval(
    workspace: Path,
    approval: Path,
    *,
    runtime_fingerprint: Callable[[], str],
    verify_candidate: Callable[[], bool],
    context_reader: Callable[[], str] | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict:
    """Report current restore approval readiness without changing config or runtime."""
    policy = fixture_action.fixture_policy(workspace)
    try:
        receipt, approved_at, expires = _read_receipt(approval, policy)
        if receipt["machine_sha256"] != config_snapshot._machine(policy):
            raise config_snapshot.SnapshotError("Restore approval belongs to another fixture")
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        return _safe_proof("tampered")
    current = config_snapshot._read_clock(now)
    if current >= expires:
        return _safe_proof("expired", receipt)
    if current < approved_at:
        return _safe_proof("unavailable", receipt)
    journal = action_journal.ActionJournal(workspace / "actions")
    try:
        with journal.locked() as tx:
            if tx.has_action("restore"):
                return _safe_proof("consumed", receipt)
            source = _require_binding(tx, approval, receipt, policy, current)
            _verify_current(
                source, policy, runtime_fingerprint, verify_candidate, context_reader=context_reader
            )
            observed_at = config_snapshot._read_clock(now)
            if observed_at >= expires:
                return _safe_proof("expired", receipt)
            if (
                observed_at < current
                or _require_binding(tx, approval, receipt, policy, observed_at) != source
            ):
                return _safe_proof("unavailable", receipt)
    except config_snapshot.SnapshotError:
        return _safe_proof("drift", receipt)
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        return _safe_proof("unavailable", receipt)
    return _safe_proof("approved", receipt)


def _published_original(
    directory: int,
    inode: tuple[int, int],
    source: _RestoreInput,
    policy: config_snapshot.SnapshotPolicy,
    *,
    name: str = fixture_action.TARGET_NAME,
) -> dict:
    data, identity = config_snapshot._read(directory, name, 1024, policy)
    if (
        data != fixture_action.ORIGINAL
        or (identity["dev"], identity["ino"]) != inode
        or any(identity[key] != source.disk_identity[key] for key in ("mode", "uid", "gid"))
    ):
        raise config_snapshot.SnapshotError("Published restore file could not be verified")
    fixture_action._require_current_directory(directory, policy)
    return identity


def restore_fixture(
    workspace: Path,
    approval: Path,
    expected_approval_id: str,
    expected_original_sha256: str,
    *,
    runtime_fingerprint: Callable[[], str],
    verify_candidate: Callable[[], bool],
    reload_and_verify: Callable[[], bool],
    context_reader: Callable[[], str] | None = None,
    confirm: bool = False,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict:
    """Apply one independently approved restore; uncertainty permanently consumes its ID."""
    policy = fixture_action.fixture_policy(workspace)
    if (
        confirm is not True
        or expected_original_sha256 != _ORIGINAL_SHA256
        or not isinstance(expected_approval_id, str)
        or not config_snapshot._PLAN_ID.fullmatch(expected_approval_id)
        or not all(
            callable(callback)
            for callback in (runtime_fingerprint, verify_candidate, reload_and_verify)
        )
    ):
        raise config_snapshot.SnapshotError("Exact restore approval and confirmation are required")
    receipt, _, expires = _read_receipt(approval, policy)
    if not hmac.compare_digest(receipt["approval_id"], expected_approval_id) or receipt[
        "machine_sha256"
    ] != config_snapshot._machine(policy):
        raise config_snapshot.SnapshotError("Restore receipt does not match the reviewed values")
    action = receipt["restore_action_id"]
    journal = action_journal.ActionJournal(workspace / "actions")
    with journal.locked() as tx:
        prior = tx.status(action)
        if prior is not None:
            return fixture_action._observation(prior, policy)
        if tx.has_action("restore"):
            raise config_snapshot.SnapshotError("Fixture already has an original restore intent")
        started = config_snapshot._read_clock(now)
        source = _require_binding(tx, approval, receipt, policy, started)

        def recheck() -> None:
            current = config_snapshot._read_clock(now)
            if (
                current < started
                or _require_binding(tx, approval, receipt, policy, current) != source
            ):
                raise config_snapshot.SnapshotError("Restore proof changed during execution")
            _verify_current(source, policy, runtime_fingerprint, context_reader=context_reader)
            checked_at = config_snapshot._read_clock(now)
            if (
                checked_at < current
                or _require_binding(tx, approval, receipt, policy, checked_at) != source
            ):
                raise config_snapshot.SnapshotError("Restore proof changed during verification")

        _verify_current(
            source, policy, runtime_fingerprint, verify_candidate, context_reader=context_reader
        )
        recheck()
        with config_snapshot._directory(policy.config_directory, policy) as directory:
            fixture_action._check_mounts(workspace)
            _require_disk(directory, policy, source)
            name = ".opsark-fixture-restore-" + secrets.token_hex(16) + ".stage"
            with fixture_action._stage(
                directory, name, source.disk_identity, fixture_action.ORIGINAL
            ) as inode:
                tx.begin(
                    receipt["plan_id"],
                    "restore",
                    receipt["approval_id"],
                    receipt["plan_sha256"],
                    _CANDIDATE_SHA256,
                    _ORIGINAL_SHA256,
                )
                try:
                    recheck()
                    fixture_action._check_mounts(workspace)
                    _published_original(directory, inode, source, policy, name=name)
                    _require_disk(directory, policy, source)
                    if not started <= config_snapshot._read_clock(now) < expires:
                        raise config_snapshot.SnapshotError(
                            "Restore approval expired before writing"
                        )
                    os.replace(
                        name, fixture_action.TARGET_NAME, src_dir_fd=directory, dst_dir_fd=directory
                    )
                    os.fsync(directory)
                    published = _published_original(directory, inode, source, policy)
                    if (
                        fixture_action._runtime_digest(runtime_fingerprint)
                        != receipt["runtime_sha256"]
                    ):
                        raise config_snapshot.SnapshotError("Restore runtime changed after writing")
                    tx.publish(action, published, receipt["runtime_sha256"])
                    verified = (
                        reload_and_verify() is True
                        and fixture_action._runtime_digest(runtime_fingerprint)
                        == receipt["runtime_sha256"]
                        and _published_original(directory, inode, source, policy) == published
                    )
                    outcome = "verified" if verified else "unknown"
                except Exception:
                    outcome = "unknown"
                proof = tx.finish(action, outcome)
    return fixture_action._observation(proof, policy)
