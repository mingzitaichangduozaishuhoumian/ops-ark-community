"""Immutable operator change statements linked to their original investigation."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import UTC, date, datetime
from typing import Annotated, Literal, Self
from uuid import uuid4

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from opsark.baselines import diagnostic_scope_for
from opsark.models import HostPublic, StrictModel

type ChangeRecordKind = Literal[
    "nginx_configuration",
    "compose_configuration",
    "image_update",
    "application_configuration",
    "service_restart",
    "unknown",
]
type ChangeRecordId = Annotated[str, Field(pattern=r"^cr-[0-9a-f]{32}$")]
type ChangeReportId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
type ChangeRequestId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
type ChangeScope = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

_REPORT_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
_RECORD_ID = re.compile(r"cr-[0-9a-f]{32}")
_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_MISMATCH = "Change record ledger is inconsistent"
_MAX_RECORDS = 20
_TABLE = "report_change_records_v1"
_INDEX = "report_change_records_report_v1"
_DDL = (
    "CREATE TABLE report_change_records_v1 ("
    " id TEXT PRIMARY KEY NOT NULL, report_id TEXT NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, request_id TEXT NOT NULL, recorded_at TEXT NOT NULL,"
    " payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, UNIQUE(report_id, request_id) )",
    "CREATE INDEX report_change_records_report_v1 ON report_change_records_v1"
    " (report_id, recorded_at DESC, id DESC)",
)


class ChangeRecordConflict(ValueError):
    def __init__(self, reason: Literal["request_conflict", "limit_reached"]) -> None:
        self.reason = reason
        super().__init__(reason)


class ChangeRecordScopeMismatch(ValueError):
    """Original report has no eligible matching diagnostic target."""


class ChangeRecordFutureInstant(ValueError):
    """Claimed instant is later than the control plane's recording time."""


class ClaimedAt(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    precision: Literal["unknown", "date", "instant"]
    value: str | None = Field(max_length=25)

    @model_validator(mode="before")
    @classmethod
    def normalize(cls, raw: object) -> object:
        if not isinstance(raw, dict) or set(raw) != {"precision", "value"}:
            return raw
        precision, value = raw["precision"], raw["value"]
        try:
            if precision == "unknown" and value is None:
                return raw
            if isinstance(value, str):
                if precision == "date" and _DATE.fullmatch(value):
                    date.fromisoformat(value)
                    return raw
                if precision == "instant" and _INSTANT.fullmatch(value):
                    instant = datetime.fromisoformat(value).astimezone(UTC)
                    return {
                        "precision": precision,
                        "value": instant.isoformat().replace("+00:00", "Z"),
                    }
        except (ValueError, OverflowError):
            pass
        raise ValueError("Invalid change claim time")


class ChangeRecordRequest(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    request_id: ChangeRequestId
    kind: ChangeRecordKind
    claimed_at: ClaimedAt


class ChangeRecord(StrictModel):
    model_config = ConfigDict(strict=True, frozen=True)

    id: ChangeRecordId
    report_id: ChangeReportId
    kind: ChangeRecordKind
    claimed_at: ClaimedAt
    recorded_at: AwareDatetime
    source: Literal["operator_statement"] = "operator_statement"

    @field_validator("recorded_at")
    @classmethod
    def utc(cls, instant: datetime) -> datetime:
        return instant.astimezone(UTC)

    @model_validator(mode="after")
    def check_claimed_time(self) -> Self:
        value = self.claimed_at.value
        if self.claimed_at.precision == "instant" and (
            value is None or datetime.fromisoformat(value) > self.recorded_at
        ):
            raise ValueError("Change claim time follows its recording time")
        return self


class _StoredChangeRecord(ChangeRecord):
    host_scope: ChangeScope
    request_id: ChangeRequestId

    def public(self) -> ChangeRecord:
        return ChangeRecord.model_validate(self.model_dump(exclude={"host_scope", "request_id"}))


def _schema(db: sqlite3.Connection, *, create: bool = False) -> bool:
    rows = db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' AND "
        "(lower(name) IN (?,?) OR lower(tbl_name) IN (?,?))",
        (_TABLE, _INDEX, _TABLE, _INDEX),
    ).fetchall()
    if not rows:
        if create:
            for statement in _DDL:
                db.execute(statement)
        return create
    if {tuple(row) for row in rows} != {
        ("table", _TABLE, _TABLE, _DDL[0]),
        ("index", _INDEX, _TABLE, _DDL[1]),
    }:
        raise ValueError(_MISMATCH)
    return True


def _parent(db: sqlite3.Connection, report_id: str) -> tuple[str, datetime]:
    row = db.execute(
        "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
        "json_extract(payload,'$.created_at') AS payload_time,"
        "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
        "json_extract(payload,'$.scope_hash') AS scope,"
        "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
        (report_id,),
    ).fetchone()
    if row is None:
        raise KeyError(report_id)
    if row["payload_id"] != report_id:
        raise ValueError(_MISMATCH)
    if row["source"] != "ssh" or row["target"] is None or row["scope"] is None:
        raise ChangeRecordScopeMismatch
    if type(row["target"]) is not str or len(row["target"]) > 16384:
        raise ValueError(_MISMATCH)
    try:
        target = HostPublic.model_validate_json(row["target"])
        created = datetime.fromisoformat(row["created_at"])
        captured = datetime.fromisoformat(row["payload_time"])
        scope = diagnostic_scope_for(target)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(_MISMATCH) from None
    if created.utcoffset() != UTC.utcoffset(created) or created != captured:
        raise ValueError(_MISMATCH)
    if (
        target.source != "ssh"
        or target.id != row["host"]
        or not _HOST_ID.fullmatch(target.id)
        or target.trusted_hosts_digest is None
        or row["scope"] != scope
    ):
        raise ChangeRecordScopeMismatch
    return scope, created


def _stamp(instant: datetime) -> str:
    return instant.isoformat(timespec="microseconds")


def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _stored_rows(db: sqlite3.Connection, report_id: str) -> list[_StoredChangeRecord]:
    rows = db.execute(
        "SELECT id,report_id,host_scope,request_id,recorded_at,payload,payload_sha256"
        " FROM report_change_records_v1 WHERE report_id=?"
        " ORDER BY recorded_at DESC,id DESC LIMIT 21",
        (report_id,),
    ).fetchall()
    if not rows:
        return []
    if len(rows) > _MAX_RECORDS:
        raise ValueError(_MISMATCH)
    try:
        scope, created = _parent(db, report_id)
    except (KeyError, ChangeRecordScopeMismatch):
        raise ValueError(_MISMATCH) from None
    records = []
    for row in rows:
        payload = row["payload"]
        if (
            type(payload) is not str
            or not 0 < len(payload) <= 4096
            or row["payload_sha256"] != _hash(payload)
        ):
            raise ValueError(_MISMATCH)
        try:
            record = _StoredChangeRecord.model_validate_json(payload)
        except (ValueError, OverflowError):
            raise ValueError(_MISMATCH) from None
        if (
            record.model_dump_json() != payload
            or (
                record.id,
                record.report_id,
                record.host_scope,
                record.request_id,
                _stamp(record.recorded_at),
            )
            != (
                row["id"],
                row["report_id"],
                row["host_scope"],
                row["request_id"],
                row["recorded_at"],
            )
            or record.host_scope != scope
            or record.recorded_at < created
        ):
            raise ValueError(_MISMATCH)
        records.append(record)
    return records


def append_change_record(
    db: sqlite3.Connection, report_id: str, host_scope: str, change: ChangeRecordRequest
) -> ChangeRecord:
    if not _REPORT_ID.fullmatch(report_id) or type(change) is not ChangeRecordRequest:
        raise ValueError(_MISMATCH)
    change = ChangeRecordRequest.model_validate_json(change.model_dump_json(warnings=False))
    scope, created = _parent(db, report_id)
    if scope != host_scope:
        raise ChangeRecordScopeMismatch
    records = _stored_rows(db, report_id) if _schema(db) else []
    for record in records:
        if record.request_id == change.request_id:
            if (record.kind, record.claimed_at) != (change.kind, change.claimed_at):
                raise ChangeRecordConflict("request_conflict")
            return record.public()
    if len(records) == _MAX_RECORDS:
        raise ChangeRecordConflict("limit_reached")
    now = datetime.now(UTC)
    value = change.claimed_at.value
    if (
        change.claimed_at.precision == "instant"
        and value is not None
        and datetime.fromisoformat(value) > now
    ):
        raise ChangeRecordFutureInstant
    if now < created:
        raise ValueError(_MISMATCH)
    record = _StoredChangeRecord(
        id="cr-" + uuid4().hex,
        report_id=report_id,
        kind=change.kind,
        claimed_at=change.claimed_at,
        recorded_at=now,
        host_scope=scope,
        request_id=change.request_id,
    )
    payload = record.model_dump_json()
    _schema(db, create=True)
    db.execute(
        "INSERT INTO report_change_records_v1"
        " (id,report_id,host_scope,request_id,recorded_at,payload,payload_sha256)"
        " VALUES (?,?,?,?,?,?,?)",
        (record.id, report_id, scope, record.request_id, _stamp(now), payload, _hash(payload)),
    )
    return record.public()


def read_change_records(
    db: sqlite3.Connection, report_id: str, record_id: str | None = None
) -> list[ChangeRecord]:
    if not _REPORT_ID.fullmatch(report_id) or (
        record_id is not None and not _RECORD_ID.fullmatch(record_id)
    ):
        raise ValueError(_MISMATCH)
    if not _schema(db):
        return []
    return [
        record.public() for record in _stored_rows(db, report_id) if record_id in {None, record.id}
    ]
