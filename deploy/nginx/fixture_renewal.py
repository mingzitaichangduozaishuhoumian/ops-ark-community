"""Prepare a local, pending handoff for one renewed synthetic Nginx certificate."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from deploy.nginx import (
    action_journal,
    config_snapshot,
    fixture_action,
    fixture_context,
    fixture_context_syntax,
)

if TYPE_CHECKING:
    from deploy.nginx.fixture_runtime import FixtureRuntime

_RECEIPT = "renewal-pending.json"
_SEAL = "receipt_sha256"
_TARGET = fixture_context.CHAIN_HOSTS["target"]
_MINIMUM = timedelta(hours=1)
_TIMESTAMP = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z"
_OPENSSL_DATES = re.compile(rf"notBefore=({_TIMESTAMP})\nnotAfter=({_TIMESTAMP})\n", re.ASCII)
_PROOF_DIGESTS = (
    "handoff_id",
    "current_context_sha256",
    "candidate_context_sha256",
    "old_leaf_sha256",
    "new_leaf_sha256",
)
_PROOF_DATES = ("old_not_after", "new_not_after", "old_chain_not_after", "new_chain_not_after")


def candidate_workspace(workspace: Path) -> Path:
    """Derive the sole allowed candidate directory for the registered fixture."""
    config_snapshot._absolute(workspace)
    if not fixture_action.WORKSPACE_NAME.fullmatch(workspace.name):
        raise config_snapshot.SnapshotError("Invalid isolated workspace identifier")
    identifier = config_snapshot._sha(b"opsark-nginx-renewal-v1\0" + workspace.name.encode("ascii"))
    return workspace.with_name("opsark-nginx-fixture-" + identifier[:32])


def _require_same_trust(
    old: fixture_context.TLSChainMaterial, new: fixture_context.TLSChainMaterial
) -> None:
    if (
        old.root_pem_sha256 != new.root_pem_sha256
        or old.intermediate_sha256 != new.intermediate_sha256
        or old.leaf_sha256[_TARGET] == new.leaf_sha256[_TARGET]
        or any(
            old.chain_sha256[host] != new.chain_sha256[host]
            for role, host in fixture_context.CHAIN_HOSTS.items()
            if role != "target"
        )
    ):
        raise config_snapshot.SnapshotError("Only the target leaf may change in this handoff")


def _public_dates(pem: bytes, now: datetime) -> datetime:
    # The caller supplies only a validated, bounded, public certificate block.
    result = subprocess.run(
        ["/usr/bin/openssl", "x509", "-noout", "-dates", "-dateopt", "iso_8601"],
        input=pem,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=2,
        check=False,
    )
    try:
        match = (
            _OPENSSL_DATES.fullmatch(result.stdout.decode("ascii"))
            if result.returncode == 0 and len(result.stdout) <= 128
            else None
        )
        if match is None:
            raise ValueError
        start, end = (datetime.fromisoformat(value) for value in match.groups())
    except ValueError:
        raise config_snapshot.SnapshotError(
            "The public certificate dates could not be confirmed"
        ) from None
    if not start <= now < end:
        raise config_snapshot.SnapshotError("The public certificate is outside its validity period")
    return end


def _chain_dates(
    policy: config_snapshot.SnapshotPolicy,
    chain: fixture_context.TLSChainMaterial,
    now: datetime,
) -> tuple[datetime, datetime]:
    with config_snapshot._directory(policy.anchor / "tls", policy) as directory:
        root, root_identity = config_snapshot._read(
            directory, "root.pem", fixture_context._MAX_TLS_FILE_BYTES, policy
        )
        target, target_identity = config_snapshot._read(
            directory, "target-chain.pem", fixture_context._MAX_TLS_FILE_BYTES, policy
        )
    if (
        root_identity != chain.files["root.pem"]
        or target_identity != chain.files["target-chain.pem"]
        or config_snapshot._sha(root) != chain.root_pem_sha256
        or config_snapshot._sha(target) != chain.chain_sha256[_TARGET]
    ):
        raise config_snapshot.SnapshotError("The public certificate material changed")
    leaf, intermediate = fixture_context._certificate_blocks(target)
    leaf_end = _public_dates(leaf, now)
    return leaf_end, min(leaf_end, _public_dates(intermediate, now), _public_dates(root, now))


def _verify_dates(
    old: tuple[datetime, datetime], new: tuple[datetime, datetime], now: datetime
) -> None:
    if old[1] <= now or new[0] <= old[0] or new[1] <= old[1] or new[1] < now + _MINIMUM:
        raise config_snapshot.SnapshotError("The target renewal must extend the usable lifetime")


def _safe_proof(record: dict) -> dict:
    proof = record.get("proof")
    if (
        set(record) != {"proof", "binding_sha256"}
        or not config_snapshot._digest(record["binding_sha256"])
        or not isinstance(proof, dict)
        or set(proof) != {"schema_version", "status", *_PROOF_DIGESTS, *_PROOF_DATES}
        or type(proof["schema_version"]) is not int
        or proof["schema_version"] != 1
        or proof["status"] != "pending_approval"
        or any(not config_snapshot._digest(proof[key]) for key in _PROOF_DIGESTS)
        or any(
            not isinstance(proof[key], str)
            or re.fullmatch(_TIMESTAMP, proof[key], re.ASCII) is None
            for key in _PROOF_DATES
        )
    ):
        raise config_snapshot.SnapshotError("The renewal receipt is invalid")
    identity = {key: value for key, value in proof.items() if key != "handoff_id"}
    if proof["handoff_id"] != _handoff_id(identity, record["binding_sha256"]):
        raise config_snapshot.SnapshotError("The renewal receipt identity is invalid")
    return proof


def _handoff_id(proof: dict, binding: str) -> str:
    return config_snapshot._sha(
        config_snapshot._json(
            {"domain": "opsark-nginx-renewal-v1", "proof": proof, "binding_sha256": binding}
        )
    )


def _read_receipt(directory: int) -> dict | None:
    record = action_journal._record(directory, _RECEIPT, _SEAL)
    if record is not None:
        del record[_SEAL]
    return record


def inspect(workspace: Path) -> dict | None:
    """Read the historical pending receipt without contacting either process."""
    candidate_workspace(workspace)
    fixture_action.fixture_policy(workspace)
    with action_journal._directory(workspace) as directory:
        record = _read_receipt(directory)
    return _safe_proof(record) if record is not None else None


def prepare(
    current: FixtureRuntime, candidate: FixtureRuntime, *, expected_context_sha256: str
) -> dict:
    """Attest both isolated instances and durably record a handoff pending approval."""
    if (
        candidate.workspace != candidate_workspace(current.workspace)
        or current.container == candidate.container
        or current.image != candidate.image
        or not config_snapshot._digest(expected_context_sha256)
    ):
        raise config_snapshot.SnapshotError("The renewal workspaces or image do not match")
    with (
        action_journal.ActionJournal(current.workspace / "actions").locked(),
        action_journal.ActionJournal(candidate.workspace / "actions").locked(),
        action_journal._directory(current.workspace, durable=True) as directory,
    ):
        return _prepare_locked(current, candidate, expected_context_sha256, directory)


def _prepare_locked(
    current: FixtureRuntime, candidate: FixtureRuntime, expected_context_sha256: str, directory: int
) -> dict:
    old_context, new_context = current._context(), candidate._context()
    if (
        old_context is None
        or new_context is None
        or old_context.tls_chain is None
        or new_context.tls_chain is None
        or old_context.fingerprint != expected_context_sha256
        or old_context._machine_sha256 == new_context._machine_sha256
    ):
        raise config_snapshot.SnapshotError("The reviewed certificate context does not match")
    old, new = old_context.tls_chain, new_context.tls_chain
    _require_same_trust(old, new)
    old_site, new_site = current._site(), candidate._site()
    variants = {
        config_snapshot._sha(fixture_action.ORIGINAL): (fixture_action.ORIGINAL, b"original"),
        fixture_action.CANDIDATE_DIGEST: (fixture_action.CANDIDATE, b"candidate"),
    }
    if old_site[0] != new_site[0] or old_site[0] not in variants:
        raise config_snapshot.SnapshotError("Renewal must keep the reviewed site configuration")
    site_bytes, expected_response = variants[old_site[0]]
    old_runtime, new_runtime = current.fingerprint(), candidate.fingerprint()

    now = datetime.now(UTC)
    old_dates = _chain_dates(current.policy, old, now)
    new_dates = _chain_dates(candidate.policy, new, now)
    _verify_dates(old_dates, new_dates, now)
    binding = config_snapshot._sha(
        config_snapshot._json(
            {"current": (old_runtime, old_site), "candidate": (new_runtime, new_site)}
        )
    )
    proof = {
        "schema_version": 1,
        "status": "pending_approval",
        "current_context_sha256": old_context.fingerprint,
        "candidate_context_sha256": new_context.fingerprint,
        "old_leaf_sha256": old.leaf_sha256[_TARGET],
        "new_leaf_sha256": new.leaf_sha256[_TARGET],
        **{
            key: expiry.isoformat(sep=" ", timespec="seconds").replace("+00:00", "Z")
            for key, expiry in zip(
                _PROOF_DATES, (old_dates[0], new_dates[0], old_dates[1], new_dates[1]), strict=True
            )
        },
    }
    proof["handoff_id"] = _handoff_id(proof, binding)
    record = {"proof": proof, "binding_sha256": binding}
    existing = _read_receipt(directory)
    if existing is None:
        if (
            fixture_context_syntax.validate(
                site_bytes, candidate.image, tls_directory=candidate.workspace / "tls"
            )
            != "passed"
        ):
            raise config_snapshot.SnapshotError("The candidate syntax could not be confirmed")
    elif existing != record:
        raise config_snapshot.SnapshotError("A different renewal receipt already exists")

    if (
        not current.preflight(expected_response)
        or not candidate.preflight(expected_response)
        or current.fingerprint() != old_runtime
        or candidate.fingerprint() != new_runtime
        or current._site() != old_site
        or candidate._site() != new_site
        or current._context() != old_context
        or candidate._context() != new_context
    ):
        raise config_snapshot.SnapshotError("The original and candidate TLS runtimes must match")
    _verify_dates(old_dates, new_dates, datetime.now(UTC))
    with action_journal._directory(current.workspace) as latest:
        if not os.path.samestat(os.fstat(latest), os.fstat(directory)):
            raise config_snapshot.SnapshotError("The renewal workspace changed")
    if existing is None:
        action_journal._publish(directory, _RECEIPT, record, _SEAL)
    return proof
