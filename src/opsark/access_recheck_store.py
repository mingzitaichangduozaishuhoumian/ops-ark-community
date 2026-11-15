"""Closed, report-bound access recovery receipts and their SQLite representation."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from opsark.baselines import matches_host_scope
from opsark.models import HostPublic, Report, StrictModel

type AccessOutcome = Literal["accepted", "failed", "pending"]
type ExternalObservation = Literal["matched", "unreachable", "unavailable"]
type AccessManagement = Literal["verified", "unavailable"]
type AccessCheckStatus = Literal["passed", "failed", "inconclusive", "uncovered"]
type AccessRecheckId = Annotated[str, Field(pattern=r"^ar-[0-9a-f]{32}$")]
type AccessReportId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
_REPORT_ID = TypeAdapter(AccessReportId)
_RECEIPT_ID = TypeAdapter(AccessRecheckId)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MISMATCH = "Access recheck evidence is inconsistent"
_DDL = (
    "CREATE TABLE access_recheck_profiles_v1 ("
    " report_id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, profile_sha256 TEXT NOT NULL )",
    "CREATE TABLE access_rechecks_v1 ("
    " id TEXT PRIMARY KEY NOT NULL,"
    " report_id TEXT NOT NULL REFERENCES access_recheck_profiles_v1(report_id),"
    " finished_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL, payload TEXT NOT NULL )",
    "CREATE INDEX access_rechecks_report_v1 ON access_rechecks_v1"
    " (report_id, finished_at DESC, id DESC)",
)


class AccessCheckResult(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    status: AccessCheckStatus


class AccessRecheck(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True, validate_default=True)

    id: AccessRecheckId
    report_id: AccessReportId
    finished_at: AwareDatetime
    management: AccessManagement
    external: ExternalObservation
    checks: list[AccessCheckResult] = Field(min_length=1, max_length=3)
    status: AccessOutcome

    @field_validator("finished_at")
    @classmethod
    def utc(cls, instant: datetime) -> datetime:
        return instant.astimezone(UTC)

    @model_validator(mode="after")
    def check_status(self) -> Self:
        if (
            len({check.id for check in self.checks}) != len(self.checks)
            or self.status != access_outcome(self.management, self.external, self.checks)
            or (
                self.management == "unavailable"
                and any(check.status == "passed" for check in self.checks)
            )
        ):
            raise ValueError(_MISMATCH)
        return self


def access_outcome(
    management: AccessManagement, external: ExternalObservation, checks: list[AccessCheckResult]
) -> AccessOutcome:
    if external == "unreachable" or any(check.status == "failed" for check in checks):
        return "failed"
    if (
        management == "verified"
        and external == "matched"
        and checks
        and all(check.status == "passed" for check in checks)
    ):
        return "accepted"
    return "pending"


def _need(ok) -> None:
    if not ok:
        raise ValueError(_MISMATCH)


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stamp(instant: datetime) -> str:
    return instant.astimezone(UTC).isoformat(timespec="microseconds")


def _decode(payload: object) -> AccessRecheck:
    if type(payload) is not str or not 0 < len(payload) <= 4096:
        raise ValueError(_MISMATCH)
    try:
        receipt = AccessRecheck.model_validate_json(payload, strict=True)
    except ValueError:
        raise ValueError(_MISMATCH) from None
    _need(receipt.model_dump_json() == payload)
    return receipt


def _schema(db: sqlite3.Connection, *, create: bool = False) -> bool:
    rows = db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name IN "
        "('access_recheck_profiles_v1','access_rechecks_v1','access_rechecks_report_v1')"
    ).fetchall()
    if not rows and create:
        for ddl in _DDL:
            db.execute(ddl)
        return True
    if not rows:
        return False
    expected = {
        ("table", "access_recheck_profiles_v1", "access_recheck_profiles_v1", _DDL[0]),
        ("table", "access_rechecks_v1", "access_rechecks_v1", _DDL[1]),
        ("index", "access_rechecks_report_v1", "access_rechecks_v1", _DDL[2]),
    }
    _need({tuple(row) for row in rows} == expected)
    return True


def _check_target(target: HostPublic | None, host_id: str, scope: object) -> None:
    _need(
        target is not None
        and target.source == "ssh"
        and target.id == host_id
        and target.trusted_hosts_digest is not None
        and type(scope) is str
        and _digest(scope)
        and matches_host_scope(target, scope)
    )


def capture_access_profile(db: sqlite3.Connection, report: Report, profile: str) -> None:
    """Seal the report's exact target scope in the caller's insertion transaction."""
    _REPORT_ID.validate_python(report.id, strict=True)
    _check_target(report.target, report.host_id, report.scope_hash)
    _need(report.source == "ssh" and report.created_at.utcoffset() is not None and _digest(profile))
    _schema(db, create=True)
    db.execute(
        "INSERT INTO access_recheck_profiles_v1 (report_id, host_scope, profile_sha256)"
        " VALUES (?, ?, ?)",
        (report.id, report.scope_hash, profile),
    )


def _profile(db: sqlite3.Connection, report_id: str) -> tuple[str, datetime] | None:
    _REPORT_ID.validate_python(report_id, strict=True)
    if not _schema(db):
        return None
    row = db.execute(
        "SELECT a.host_scope, a.profile_sha256, r.created_at,"
        " json_extract(r.payload,'$.id') AS report_id,"
        " json_extract(r.payload,'$.source') AS source,"
        " json_extract(r.payload,'$.host_id') AS host_id,"
        " json_extract(r.payload,'$.scope_hash') AS scope,"
        " json_extract(r.payload,'$.target') AS target FROM access_recheck_profiles_v1 AS a"
        " LEFT JOIN reports AS r ON r.id=a.report_id WHERE a.report_id=?",
        (report_id,),
    ).fetchone()
    if row is None:
        return None
    _need(
        row["report_id"] == report_id
        and row["source"] == "ssh"
        and row["host_scope"] == row["scope"]
        and _digest(row["profile_sha256"])
        and type(row["created_at"]) is str
        and type(row["target"]) is str
    )
    created = datetime.fromisoformat(row["created_at"])
    target = HostPublic.model_validate_json(row["target"])
    _need(created.utcoffset() == UTC.utcoffset(created))
    _check_target(target, row["host_id"], row["host_scope"])
    return row["profile_sha256"], created


def read_access_profile(db: sqlite3.Connection, report_id: str) -> str | None:
    result = _profile(db, report_id)
    return None if result is None else result[0]


def append_access_recheck(db: sqlite3.Connection, receipt: AccessRecheck, profile: str) -> None:
    _need(type(receipt) is AccessRecheck and _digest(profile))
    payload = receipt.model_dump_json(warnings=False)
    receipt = _decode(payload)
    original = _profile(db, receipt.report_id)
    _need(original is not None and original[0] == profile and receipt.finished_at > original[1])
    db.execute(
        "INSERT INTO access_rechecks_v1 (id, report_id, finished_at, payload_sha256, payload)"
        " VALUES (?, ?, ?, ?, ?)",
        (receipt.id, receipt.report_id, _stamp(receipt.finished_at), _hash(payload), payload),
    )


def read_access_rechecks(
    db: sqlite3.Connection, report_id: str, receipt_id: str | None = None
) -> list[AccessRecheck]:
    original = _profile(db, report_id)
    if original is None:
        return []
    query = (
        "SELECT id, report_id, finished_at, payload_sha256, payload"
        " FROM access_rechecks_v1 WHERE report_id=?"
    )
    if receipt_id is None:
        rows = db.execute(query + " ORDER BY finished_at DESC, id DESC LIMIT 20", (report_id,))
    else:
        _RECEIPT_ID.validate_python(receipt_id, strict=True)
        rows = db.execute(query + " AND id=?", (report_id, receipt_id))
    receipts = []
    for row in rows:
        receipt = _decode(row["payload"])
        _need(
            (receipt.id, receipt.report_id, _stamp(receipt.finished_at), _hash(row["payload"]))
            == (row["id"], row["report_id"], row["finished_at"], row["payload_sha256"])
            and receipt.finished_at > original[1]
        )
        receipts.append(receipt)
    return receipts
