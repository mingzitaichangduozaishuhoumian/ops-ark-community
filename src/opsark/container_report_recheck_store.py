"""Persist bodyless verification against the original container investigation."""

import hashlib
import re
import sqlite3
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from opsark.baselines import diagnostic_scope_for
from opsark.business_readiness import ReadinessStatus
from opsark.models import HostPublic, Report, StrictModel

type ReportId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
type RecheckId = Annotated[str, Field(pattern=r"^rr-[0-9a-f]{32}$")]
type RequestId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
type Management = Literal["verified", "unavailable"]
type Verdict = Literal["failed", "pending", "passed"]

_REQUEST_ID = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SCOPE_ERROR = "Container report recheck binding is inconsistent"
CAPACITY = 20
_PROFILES = "container_recheck_profiles_v1"
_RECHECKS = "container_rechecks_v1"
_INDEX = "container_rechecks_report_v1"
_DDL = (
    "CREATE TABLE container_recheck_profiles_v1 ("
    " report_id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, profile_sha256 TEXT NOT NULL )",
    "CREATE TABLE container_rechecks_v1 ("
    " id TEXT PRIMARY KEY NOT NULL,"
    " report_id TEXT NOT NULL REFERENCES container_recheck_profiles_v1(report_id),"
    " request_id TEXT NOT NULL, finished_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL,"
    " payload TEXT NOT NULL, UNIQUE(report_id, request_id) )",
    "CREATE INDEX container_rechecks_report_v1 ON container_rechecks_v1"
    " (report_id, finished_at DESC, id DESC)",
)


class RecheckCapacity(ValueError):
    """The report already has the maximum number of saved rechecks."""


def verdict(management: Management, checks: list[ReadinessStatus]) -> Verdict:
    if "failed" in checks:
        return "failed"
    if management == "verified" and checks and all(check == "passed" for check in checks):
        return "passed"
    return "pending"


class ContainerReportRecheck(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    id: RecheckId
    report_id: ReportId
    finished_at: AwareDatetime
    management: Management
    checks: list[ReadinessStatus] = Field(min_length=1, max_length=3)
    status: Verdict

    @field_validator("finished_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.status != verdict(self.management, self.checks) or (
            self.management == "unavailable"
            and any(check in {"passed", "failed"} for check in self.checks)
        ):
            raise ValueError(_SCOPE_ERROR)
        return self


def container_report_scope(report: Report) -> str | None:
    target = report.target
    if (
        report.source == "ssh"
        and report.scenario == "container_restart"
        and report.created_at.utcoffset() is not None
        and target is not None
        and target.id == report.host_id
        and target.source == "ssh"
        and target.trusted_hosts_digest is not None
        and diagnostic_scope_for(target) == report.scope_hash
    ):
        return report.scope_hash
    return None


def _schema(db: sqlite3.Connection, *, create: bool = False) -> bool:
    names = (_PROFILES, _RECHECKS, _INDEX)
    rows = db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'"
        " AND (lower(name) IN (?,?,?) OR lower(tbl_name) IN (?,?,?))",
        names + names,
    ).fetchall()
    if not rows:
        if create:
            for statement in _DDL:
                db.execute(statement)
        return create
    if {tuple(row) for row in rows} != {
        ("table", _PROFILES, _PROFILES, _DDL[0]),
        ("table", _RECHECKS, _RECHECKS, _DDL[1]),
        ("index", _INDEX, _RECHECKS, _DDL[2]),
    }:
        raise ValueError(_SCOPE_ERROR)
    return True


def capture_profile(db: sqlite3.Connection, report: Report, profile: str) -> None:
    scope = container_report_scope(report)
    if scope is None or not _DIGEST.fullmatch(profile):
        raise ValueError(_SCOPE_ERROR)
    _schema(db, create=True)
    db.execute(
        "INSERT INTO container_recheck_profiles_v1 (report_id,host_scope,profile_sha256)"
        " VALUES (?,?,?)",
        (report.id, scope, profile),
    )


def _profile(db: sqlite3.Connection, report_id: str) -> tuple[str, datetime] | None:
    if not _schema(db):
        return None
    row = db.execute(
        "SELECT p.host_scope,p.profile_sha256,r.created_at,"
        " json_extract(r.payload,'$.id') AS report_id,"
        " json_extract(r.payload,'$.created_at') AS captured,"
        " json_extract(r.payload,'$.source') AS source,"
        " json_extract(r.payload,'$.scenario') AS scenario,"
        " json_extract(r.payload,'$.host_id') AS host_id,"
        " json_extract(r.payload,'$.scope_hash') AS report_scope,"
        " json_extract(r.payload,'$.target') AS target"
        " FROM container_recheck_profiles_v1 p LEFT JOIN reports r ON r.id=p.report_id"
        " WHERE p.report_id=?",
        (report_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        if type(row["target"]) is not str or len(row["target"]) > 16384:
            raise ValueError
        target = HostPublic.model_validate_json(row["target"])
        created = datetime.fromisoformat(row["created_at"])
        if (
            row["report_id"] != report_id
            or row["source"] != "ssh"
            or row["scenario"] != "container_restart"
            or target.id != row["host_id"]
            or target.source != "ssh"
            or target.trusted_hosts_digest is None
            or diagnostic_scope_for(target) != row["host_scope"]
            or row["host_scope"] != row["report_scope"]
            or not _DIGEST.fullmatch(row["profile_sha256"])
            or created.utcoffset() != UTC.utcoffset(created)
            or created != datetime.fromisoformat(row["captured"])
        ):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise ValueError(_SCOPE_ERROR) from None
    return row["profile_sha256"], created


def read_profile(db: sqlite3.Connection, report_id: str) -> str | None:
    row = _profile(db, report_id)
    return row[0] if row is not None else None


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _seal(request_id: str, payload: str) -> str:
    raw = b"opsark-container-recheck/v1\0" + request_id.encode("ascii") + b"\0" + payload.encode()
    return hashlib.sha256(raw).hexdigest()


def _records(
    db: sqlite3.Connection, report_id: str, created: datetime
) -> dict[str, ContainerReportRecheck]:
    rows = db.execute(
        "SELECT id,report_id,request_id,finished_at,payload_sha256,payload"
        " FROM container_rechecks_v1 WHERE report_id=?"
        " ORDER BY finished_at DESC,id DESC LIMIT ?",
        (report_id, CAPACITY + 1),
    ).fetchall()
    if len(rows) > CAPACITY:
        raise ValueError(_SCOPE_ERROR)
    receipts = {}
    try:
        for row in rows:
            request_id, payload = row["request_id"], row["payload"]
            if (
                not _REQUEST_ID.fullmatch(request_id)
                or request_id in receipts
                or type(payload) is not str
                or not 0 < len(payload) <= 1024
            ):
                raise ValueError
            receipt = ContainerReportRecheck.model_validate_json(payload)
            if (
                receipt.model_dump_json() != payload
                or receipt.report_id != report_id
                or receipt.finished_at <= created
                or (
                    receipt.id,
                    receipt.report_id,
                    _stamp(receipt.finished_at),
                    _seal(request_id, payload),
                )
                != (row["id"], row["report_id"], row["finished_at"], row["payload_sha256"])
            ):
                raise ValueError
            receipts[request_id] = receipt
    except (TypeError, ValueError, OverflowError):
        raise ValueError(_SCOPE_ERROR) from None
    return receipts


def read_rechecks(db: sqlite3.Connection, report_id: str) -> dict[str, ContainerReportRecheck]:
    profile = _profile(db, report_id)
    return _records(db, report_id, profile[1]) if profile is not None else {}


def append_recheck(
    db: sqlite3.Connection, receipt: ContainerReportRecheck, profile: str, request_id: str
) -> ContainerReportRecheck:
    if not _REQUEST_ID.fullmatch(request_id):
        raise ValueError(_SCOPE_ERROR)
    original = _profile(db, receipt.report_id)
    if original is None or original[0] != profile or receipt.finished_at <= original[1]:
        raise ValueError(_SCOPE_ERROR)
    receipts = _records(db, receipt.report_id, original[1])
    if request_id in receipts:
        return receipts[request_id]
    if len(receipts) >= CAPACITY:
        raise RecheckCapacity
    payload = receipt.model_dump_json(warnings=False)
    ContainerReportRecheck.model_validate_json(payload)
    db.execute(
        "INSERT INTO container_rechecks_v1"
        " (id,report_id,request_id,finished_at,payload_sha256,payload) VALUES (?,?,?,?,?,?)",
        (
            receipt.id,
            receipt.report_id,
            request_id,
            _stamp(receipt.finished_at),
            _seal(request_id, payload),
            payload,
        ),
    )
    return receipt
