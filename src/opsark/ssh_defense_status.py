"""Query registered isolated defense actions without exposing execution commands."""

import json
import re
import shlex
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import AwareDatetime

from opsark.baselines import scope_for
from opsark.collector import collect_registered_receipts
from opsark.config import HostConfig
from opsark.models import CheckResult, StrictModel

Confirmed = Literal["active", "expired", "revoked"]
ActionStatus = Literal["active", "expired", "revoked", "unknown", "unavailable"]
_CONFIRMED = {"active", "expired", "revoked"}
_ID = re.compile(r"[0-9a-f]{32}\Z")


class DefenseObservation(StrictModel):
    status: Confirmed
    remaining_ms: int | None
    observed_at: AwareDatetime


class DefenseAction(StrictModel):
    action_id: str
    last_observed: DefenseObservation | None


class DefenseActions(StrictModel):
    host_id: str
    actions: list[DefenseAction]


class DefenseQuery(DefenseAction):
    host_id: str
    status: ActionStatus
    remaining_ms: int | None
    checked_at: AwareDatetime


def commands_for_defense_status(host: HostConfig) -> dict[str, str]:
    """Export an exact status command per administrator-registered fixture action."""
    ids = host.ssh_defense_action_ids
    public = host.public
    if not ids:
        return {}
    if (
        (public.source, public.username, public.address, public.port)
        != ("ssh", "opsark-readonly", "198.18.241.2", 22423)
        or not public.trusted_hosts_digest
        or len(ids) > 8
        or any(not isinstance(action, str) or not _ID.fullmatch(action) for action in ids)
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("Invalid isolated SSH defense registration")
    return {
        action: shlex.join(
            [
                "timeout",
                "-k",
                "1s",
                "5s",
                "/usr/bin/python3",
                "-I",
                "-B",
                "/usr/local/libexec/opsark-defense/deploy/defense/ssh_fixture.py",
                "--profile",
                "private",
                "status-readonly",
                "--action-id",
                action,
            ]
        )
        for action in ids
    }


def _unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("Repeated status field")
        values[key] = value
    return values


def _ttl_matches(status: str, remaining: object) -> bool:
    return (
        type(remaining) is int and 1 <= remaining <= 60_000
        if status == "active"
        else remaining is None
    )


def _parse(action_id: str, result: CheckResult | None) -> tuple[ActionStatus, int | None]:
    if (
        result is None
        or result.status != "ok"
        or result.exit_code != 0
        or result.truncated
        or result.stderr
        or not result.stdout.endswith("\n")
        or result.stdout.count("\n") != 1
        or len(result.stdout) > 256
    ):
        return "unavailable", None
    try:
        reply = json.loads(result.stdout, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        return "unavailable", None
    if not isinstance(reply, dict) or set(reply) != {"action_id", "status", "remaining_ms"}:
        return "unavailable", None
    status, remaining = reply["status"], reply["remaining_ms"]
    if (
        reply["action_id"] != action_id
        or status not in ("active", "expired", "revoked", "unknown")
        or not _ttl_matches(status, remaining)
    ):
        return "unavailable", None
    return cast(ActionStatus, status), remaining


class DefenseStatusStore:
    """Keep the latest confirmed observation in the existing security database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ssh_defense_observations (
                    host_id TEXT NOT NULL,
                    host_scope TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active','expired','revoked')),
                    remaining_ms INTEGER,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (host_id, host_scope, action_id),
                    CHECK (
                        (status='active' AND remaining_ms IS NOT NULL
                         AND remaining_ms BETWEEN 1 AND 60000)
                        OR (status!='active' AND remaining_ms IS NULL)
                    )
                )
                """
            )

    @staticmethod
    def _read(connection, key: tuple[str, str, str]) -> DefenseObservation | None:
        row = connection.execute(
            "SELECT status,remaining_ms,observed_at FROM ssh_defense_observations "
            "WHERE host_id=? AND host_scope=? AND action_id=?",
            key,
        ).fetchone()
        if row is None:
            return None
        status, remaining, observed = row
        if not _ttl_matches(status, remaining):
            raise ValueError("Invalid stored defense observation")
        return DefenseObservation(status=status, remaining_ms=remaining, observed_at=observed)

    @staticmethod
    def _key(host: HostConfig, action_id: str) -> tuple[str, str, str]:
        return host.public.id, scope_for(host.public), action_id

    def get(self, host: HostConfig, action_id: str) -> DefenseObservation | None:
        uri = self.path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            return self._read(connection, self._key(host, action_id))

    def confirm(self, host: HostConfig, action_id: str, current: DefenseObservation) -> bool:
        key = self._key(host, action_id)
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = self._read(connection, key)
            if previous is not None and (
                current.observed_at < previous.observed_at
                or (previous.status != "active" and current.status != previous.status)
                or (
                    current.remaining_ms is not None
                    and previous.remaining_ms is not None
                    and current.remaining_ms > previous.remaining_ms
                )
            ):
                return False
            connection.execute(
                """
                INSERT INTO ssh_defense_observations VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id,host_scope,action_id) DO UPDATE SET
                status=excluded.status, remaining_ms=excluded.remaining_ms,
                observed_at=excluded.observed_at
                """,
                (*key, current.status, current.remaining_ms, current.observed_at.isoformat()),
            )
        return True


def run_defense_status(host: HostConfig, action_id: str, store: DefenseStatusStore) -> DefenseQuery:
    command = commands_for_defense_status(host)[action_id]
    receipts = collect_registered_receipts(host, {action_id: command}, output_limit=256)
    status, remaining = _parse(action_id, receipts.get(action_id))
    checked = datetime.now(UTC)
    if status in _CONFIRMED and not store.confirm(
        host,
        action_id,
        DefenseObservation(
            status=cast(Confirmed, status), remaining_ms=remaining, observed_at=checked
        ),
    ):
        status, remaining = "unknown", None
    return DefenseQuery(
        host_id=host.public.id,
        action_id=action_id,
        status=status,
        remaining_ms=remaining,
        checked_at=checked,
        last_observed=store.get(host, action_id),
    )
