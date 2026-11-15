"""Bounded operational receipts for original-task read-only following."""

from typing import Literal

from pydantic import Field

from opsark.defense_models import DefenseModel, Digest, Identifier, Timestamp
from opsark.defense_store import Epoch, Host, Owner

type WatchState = Literal[
    "active",
    "expired",
    "revoked",
    "ready",
    "ready_expired",
    "unknown",
    "not_found",
    "rejected",
    "unavailable",
    "registration_changed",
    "daily_limit",
    "attempt_limit",
    "capacity_limit",
]


class TaskWatchLease(DefenseModel):
    owner: Owner
    epoch: Epoch
    expires_at: Timestamp


class TaskWatchClaim(DefenseModel):
    claim_ref: Identifier
    host_id: Host
    request_id: Identifier
    defense_scope: Digest
    task_reference_sha256: Digest
    owner: Owner
    epoch: Epoch
    attempt: int = Field(ge=1, le=24)
    claimed_at: Timestamp
    expires_at: Timestamp


class TaskWatchEvent(DefenseModel):
    event_ref: Identifier
    sequence: int = Field(ge=1, le=2**63 - 1)
    task_reference_sha256: Digest
    host_id: Host
    request_id: Identifier
    state: WatchState
    observed_at: Timestamp
    acknowledged_at: Timestamp | None = None
