"""Keep private Compose equality markers alongside their original SSH reports."""

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from opsark.baselines import BaselineStore, diagnostic_scope_for
from opsark.compose_generation import GenerationComparison, _Witness, compare_generation
from opsark.models import BaselineInfo, HostPublic, Report, StrictModel
from opsark.storage import ReportStore

_TABLE = "compose_generation_witnesses_v1"
_DDL = (
    "CREATE TABLE compose_generation_witnesses_v1 ("
    " id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id) ON DELETE CASCADE,"
    " host_id TEXT NOT NULL, report_scope TEXT NOT NULL,"
    " observed_at TEXT NOT NULL, witness_sha256 TEXT NOT NULL, witness_json TEXT NOT NULL )"
)
_FIELDS = ("binding", "key_epoch", "container", "image", "configuration", "compose_version")
_REPORT_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_WINDOW = timedelta(seconds=120)
_REJECTED = "Compose generation evidence is inconsistent"
ChangeField = Literal["container", "image", "compose_configuration"]
ObservationStatus = Literal["no_baseline", "compared", "incomplete", "scope_changed"]
_CHANGE_FIELDS: tuple[ChangeField, ...] = ("container", "image", "compose_configuration")


class ObservedChange(StrictModel):
    field: ChangeField
    from_at: AwareDatetime
    to_at: AwareDatetime

    @field_validator("from_at", "to_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.from_at >= self.to_at:
            raise ValueError(_REJECTED)
        return self


class ChangeObservation(StrictModel):
    current_at: AwareDatetime | None = None
    baseline_status: ObservationStatus = "incomplete"
    changes: list[ObservedChange] = Field(default_factory=list, max_length=3)

    @field_validator("current_at")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def same_observation_pair(self) -> Self:
        if self.changes and (
            self.baseline_status in {"no_baseline", "scope_changed"}
            or len({row.field for row in self.changes}) != len(self.changes)
            or any(row.to_at != self.current_at for row in self.changes)
            or len({row.from_at for row in self.changes}) != 1
        ):
            raise ValueError(_REJECTED)
        return self


def _stamp(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError(_REJECTED)
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _payload(witness: _Witness) -> str:
    return json.dumps({field: getattr(witness, field) for field in _FIELDS}, separators=(",", ":"))


def _seal(*values: str) -> str:
    raw = json.dumps(values, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(b"opsark-compose-generation-storage/v1\0" + raw).hexdigest()


def _report(db: sqlite3.Connection, report_id: str) -> tuple[str, str, datetime] | None:
    if type(report_id) is not str or not _REPORT_ID.fullmatch(report_id):
        raise ValueError(_REJECTED)
    row = db.execute(
        "SELECT created_at, json_extract(payload,'$.id') AS payload_id, "
        "json_extract(payload,'$.created_at') AS payload_time, "
        "json_extract(payload,'$.host_id') AS host_id, json_extract(payload,'$.source') AS source, "
        "json_extract(payload,'$.scenario') AS scenario, "
        "json_extract(payload,'$.scope_hash') AS scope, "
        "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
        (report_id,),
    ).fetchone()
    if row is None:
        return None
    if (
        row["payload_id"] != report_id
        or row["source"] != "ssh"
        or row["scenario"] != "container_restart"
        or not _HOST_ID.fullmatch(row["host_id"] or "")
        or not _DIGEST.fullmatch(row["scope"] or "")
        or type(row["target"]) is not str
        or len(row["target"]) > 16_384
    ):
        raise ValueError(_REJECTED)
    try:
        target = HostPublic.model_validate_json(row["target"])
        created = datetime.fromisoformat(row["created_at"])
        payload_time = datetime.fromisoformat(row["payload_time"])
        if (
            target.id != row["host_id"]
            or target.source != "ssh"
            or target.username != "opsark-readonly"
            or target.trusted_hosts_digest is None
            or diagnostic_scope_for(target) != row["scope"]
            or _stamp(created) != _stamp(payload_time)
        ):
            raise ValueError(_REJECTED)
    except (ValueError, TypeError):
        raise ValueError(_REJECTED) from None
    return row["host_id"], row["scope"], created


def _has_schema(db: sqlite3.Connection) -> bool:
    row = db.execute("SELECT type, sql FROM sqlite_schema WHERE name=?", (_TABLE,)).fetchone()
    if row is None:
        return False
    if row["type"] != "table" or " ".join(row["sql"].split()) != _DDL:
        raise ValueError(_REJECTED)
    return True


def _load(
    db: sqlite3.Connection, report_id: str, report: tuple[str, str, datetime]
) -> _Witness | None:
    row = db.execute(
        "SELECT * FROM compose_generation_witnesses_v1 WHERE id=?", (report_id,)
    ).fetchone()
    if row is None:
        return None
    host, scope, created = report
    observed, payload = row["observed_at"], row["witness_json"]
    try:
        if (
            row["host_id"] != host
            or row["report_scope"] != scope
            or type(observed) is not str
            or len(observed) > 40
            or type(payload) is not str
            or not 0 < len(payload) <= 700
            or row["witness_sha256"] != _seal(report_id, host, scope, observed, payload)
        ):
            raise ValueError(_REJECTED)
        instant = datetime.fromisoformat(observed)
        witness = _Witness.model_validate({**json.loads(payload), "observed_at": instant})
        if (
            observed != _stamp(instant)
            or abs(instant - created) > _WINDOW
            or _payload(witness) != payload
            or (witness.configuration is None) != (witness.compose_version is None)
        ):
            raise ValueError(_REJECTED)
    except (TypeError, ValueError, RecursionError):
        raise ValueError(_REJECTED) from None
    return witness


def _valid_baseline(baseline: BaselineInfo | None) -> bool:
    return (
        baseline is not None
        and baseline.source == "ssh"
        and baseline.scenario == "container_restart"
        and baseline.created_at.utcoffset() is not None
    )


def _baseline_report(
    db: sqlite3.Connection, baseline: BaselineInfo, current: tuple[str, str, datetime]
) -> tuple[tuple[str, str, datetime] | None, Literal["incomplete", "scope_changed"]]:
    original = _report(db, baseline.report_id)
    if original is None:
        return None, "incomplete"
    if current[:2] != original[:2] or original[:2] != (baseline.host_id, baseline.scope_hash):
        return None, "scope_changed"
    if not original[2] <= baseline.created_at <= current[2] or original[2] >= current[2]:
        return None, "incomplete"
    return original, "incomplete"


def _observation_anchor(report: Report) -> datetime | None:
    """Reuse the collection time of successful evidence, if its original scope survives."""
    target = report.target
    if (
        report.source != "ssh"
        or target is None
        or target.source != "ssh"
        or target.id != report.host_id
        or target.trusted_hosts_digest is None
        or diagnostic_scope_for(target) != report.scope_hash
        or report.created_at.utcoffset() is None
    ):
        return None
    return max(
        (
            row.collected_at
            for row in report.evidence
            if row.source == "ssh"
            and row.target == report.host_id
            and row.status == "ok"
            and type(row.exit_code) is int
            and row.exit_code == 0
            and not row.truncated
            and row.collected_at.utcoffset() is not None
            and timedelta(0) <= report.created_at - row.collected_at <= _WINDOW
        ),
        default=None,
    )


class ComposeGenerationStore:
    """Attach one immutable, non-exportable witness to a saved investigation."""

    def __init__(self, reports: ReportStore) -> None:
        self._reports = reports

    def save(self, report_id: str, witness: _Witness) -> None:
        """Write once, accepting a retry only when it carries the original witness."""
        if type(witness) is not _Witness:
            raise ValueError(_REJECTED)
        try:
            witness = _Witness.model_validate(
                {
                    **{field: getattr(witness, field) for field in _FIELDS},
                    "observed_at": witness.observed_at,
                }
            )
        except (AttributeError, ValueError):
            raise ValueError(_REJECTED) from None
        observed = _stamp(witness.observed_at)
        payload = _payload(witness)
        with self._reports._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            report = _report(db, report_id)
            if report is None:
                raise ValueError(_REJECTED)
            host, scope, created = report
            if abs(witness.observed_at - created) > _WINDOW or (witness.configuration is None) != (
                witness.compose_version is None
            ):
                raise ValueError(_REJECTED)
            if not _has_schema(db):
                db.execute(_DDL)
            prior = _load(db, report_id, report)
            if prior is not None:
                if prior != witness:
                    raise ValueError(_REJECTED)
                return
            db.execute(
                "INSERT INTO compose_generation_witnesses_v1 "
                "(id,host_id,report_scope,observed_at,witness_sha256,witness_json) "
                "VALUES (?,?,?,?,?,?)",
                (
                    report_id,
                    host,
                    scope,
                    observed,
                    _seal(report_id, host, scope, observed, payload),
                    payload,
                ),
            )

    def compare_to_baseline(
        self, current_report_id: str, baseline: BaselineInfo | None
    ) -> GenerationComparison:
        """Read a pair tied to the caller's already validated observation baseline."""
        if baseline is None or not _valid_baseline(baseline):
            return GenerationComparison()
        with self._reports._connection() as db:
            db.execute("BEGIN")
            if not _has_schema(db):
                return GenerationComparison()
            current = _report(db, current_report_id)
            if current is None:
                return GenerationComparison()
            original, _ = _baseline_report(db, baseline, current)
            if original is None:
                return GenerationComparison()
            before, after = (
                _load(db, baseline.report_id, original),
                _load(db, current_report_id, current),
            )
            return compare_generation(before, after)

    def change_observation(
        self, report: Report, baseline: BaselineInfo | None, status: ObservationStatus
    ) -> ChangeObservation:
        current_at = _observation_anchor(report)
        current = (report.host_id, report.scope_hash, report.created_at)
        target = report.target
        if (
            report.source != "ssh"
            or report.scenario != "container_restart"
            or target is None
            or target.id != report.host_id
            or target.source != "ssh"
            or target.username != "opsark-readonly"
            or target.trusted_hosts_digest is None
            or diagnostic_scope_for(target) != report.scope_hash
            or report.created_at.utcoffset() is None
            or not _REPORT_ID.fullmatch(report.id)
        ):
            return ChangeObservation(current_at=current_at, baseline_status=status)
        with self._reports._connection() as db:
            db.execute("BEGIN")
            if not _has_schema(db):
                return ChangeObservation(current_at=current_at, baseline_status=status)
            # The controller resolved this immutable original report once. _load still
            # independently validates the matching private witness row and its seal.
            after = _load(db, report.id, current)
            if after is None:
                return ChangeObservation(current_at=current_at, baseline_status=status)
            current_at = after.observed_at
            if baseline is None or status in {"no_baseline", "scope_changed"}:
                return ChangeObservation(current_at=current_at, baseline_status=status)
            original, unavailable = _baseline_report(db, baseline, current)
            if original is None:
                return ChangeObservation(current_at=current_at, baseline_status=unavailable)
            before = _load(db, baseline.report_id, original)
            if before is None:
                return ChangeObservation(current_at=current_at)
            if (before.binding, before.key_epoch) != (after.binding, after.key_epoch):
                return ChangeObservation(current_at=current_at, baseline_status="scope_changed")
            compared = compare_generation(before, after)
            changes = [
                ObservedChange(field=field, from_at=before.observed_at, to_at=after.observed_at)
                for field in _CHANGE_FIELDS
                if getattr(compared, field) == "changed"
            ]
            return ChangeObservation(
                current_at=current_at,
                baseline_status="compared"
                if all(getattr(compared, field) != "unavailable" for field in _CHANGE_FIELDS)
                else "incomplete",
                changes=changes,
            )


def change_observation(
    report: Report, baseline_store: BaselineStore, generation_store: ComposeGenerationStore
) -> ChangeObservation:
    """Project paired observations for only the baseline already bound to this report."""
    reference = report.comparison
    if reference.status == "scope_changed":
        return generation_store.change_observation(report, None, "scope_changed")
    if reference.status == "no_baseline" and all(
        value is None
        for value in (
            reference.baseline_id,
            reference.baseline_report_id,
            reference.baseline_created_at,
        )
    ):
        return generation_store.change_observation(report, None, "no_baseline")
    baseline = None
    if (
        report.source == "ssh"
        and report.scenario == "container_restart"
        and reference.status in {"compared", "incomplete"}
        and reference.baseline_id is not None
        and reference.baseline_created_at is not None
        and reference.baseline_created_at.utcoffset() is not None
        and reference.baseline_report_id is not None
        and _REPORT_ID.fullmatch(reference.baseline_report_id)
        and reference.baseline_report_id != report.id
    ):
        found = baseline_store.for_report(reference.baseline_report_id)
        if (
            found is not None
            and _valid_baseline(found)
            and found.id == reference.baseline_id
            and found.report_id == reference.baseline_report_id
            and found.created_at == reference.baseline_created_at
        ):
            if found.host_id != report.host_id or found.scope_hash != report.scope_hash:
                return generation_store.change_observation(report, None, "scope_changed")
            baseline = found
    return generation_store.change_observation(report, baseline, "incomplete")
