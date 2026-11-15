"""Transactional SQLite storage for redacted reports and business recheck receipts."""

from __future__ import annotations

import builtins
import sqlite3
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from opsark.access_recheck_store import (
    AccessRecheck,
    append_access_recheck,
    capture_access_profile,
    read_access_profile,
    read_access_rechecks,
)
from opsark.baselines import report_target_matches_host_scope, scope_for
from opsark.change_record_store import (
    ChangeRecord,
    ChangeRecordRequest,
    append_change_record,
    read_change_records,
)
from opsark.container_report_recheck_store import (
    ContainerReportRecheck,
    append_recheck,
    capture_profile,
    read_profile,
    read_rechecks,
)
from opsark.models import AIExplanation, HostPublic, Report

if TYPE_CHECKING:
    from opsark.handoff_timeline import BusinessHandoffRecheck


_RECEIPT_ERROR = "Business handoff receipt is inconsistent"


def _parse_handoff_receipt(payload: object) -> BusinessHandoffRecheck:
    from opsark.handoff_timeline import BusinessHandoffRecheck

    if not isinstance(payload, str) or len(payload) > 4096:
        raise ValueError(_RECEIPT_ERROR)
    try:
        receipt = BusinessHandoffRecheck.model_validate_json(payload, strict=True)
    except ValidationError:
        raise ValueError(_RECEIPT_ERROR) from None
    if receipt.model_dump_json() != payload:
        raise ValueError(_RECEIPT_ERROR)
    return receipt


def _handoff_receipt_key(receipt: BusinessHandoffRecheck) -> tuple[str, str, str, str]:
    return (
        receipt.id,
        receipt.report_id,
        receipt.job_id,
        receipt.finished_at.astimezone(UTC).isoformat(timespec="microseconds"),
    )


def _read_handoff_receipt(row: sqlite3.Row) -> BusinessHandoffRecheck:
    receipt = _parse_handoff_receipt(row["payload"])
    if _handoff_receipt_key(receipt) != (
        row["id"],
        row["report_id"],
        row["job_id"],
        row["finished_at"],
    ):
        raise ValueError(_RECEIPT_ERROR)
    return receipt


class ReportStore:
    """Keep each report and its evidence as one validated document."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS reports_created_at ON reports(created_at DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS handoff_receipts (
                    id TEXT PRIMARY KEY NOT NULL,
                    report_id TEXT NOT NULL REFERENCES reports(id),
                    job_id TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS handoff_receipts_scope ON handoff_receipts"
                "(report_id, job_id, finished_at DESC, id DESC)"
            )
        if path.is_file():
            path.chmod(0o600)

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            with connection:
                yield connection
        finally:
            connection.close()

    def save(
        self,
        report: Report,
        *,
        access_profile: str | None = None,
        container_recheck_profile: str | None = None,
    ) -> None:
        """Insert a report; duplicate identifiers never overwrite prior evidence."""
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO reports (id, created_at, payload) VALUES (?, ?, ?)",
                (
                    report.id,
                    report.created_at.astimezone(UTC).isoformat(),
                    report.model_dump_json(),
                ),
            )
            if access_profile is not None:
                capture_access_profile(connection, report, access_profile)
            if container_recheck_profile is not None:
                capture_profile(connection, report, container_recheck_profile)

    def container_recheck_profile(self, report_id: str) -> str | None:
        with self._connection() as connection:
            connection.execute("BEGIN")
            return read_profile(connection, report_id)

    def container_rechecks(self, report_id: str) -> dict[str, ContainerReportRecheck]:
        with self._connection() as connection:
            connection.execute("BEGIN")
            return read_rechecks(connection, report_id)

    def save_container_recheck(
        self, receipt: ContainerReportRecheck, *, profile: str, request_id: str
    ) -> ContainerReportRecheck:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return append_recheck(connection, receipt, profile, request_id)

    def access_profile(self, report_id: str) -> str | None:
        with self._connection() as connection:
            return read_access_profile(connection, report_id)

    def save_access_recheck(self, receipt: AccessRecheck, *, profile: str) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            append_access_recheck(connection, receipt, profile)

    def access_rechecks(self, report_id: str) -> builtins.list[AccessRecheck]:
        with self._connection() as connection:
            return read_access_rechecks(connection, report_id)

    def get_access_recheck(self, report_id: str, receipt_id: str) -> AccessRecheck | None:
        with self._connection() as connection:
            rows = read_access_rechecks(connection, report_id, receipt_id)
        return rows[0] if rows else None

    def save_change_record(
        self, report_id: str, *, host_scope: str, change: ChangeRecordRequest
    ) -> ChangeRecord:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return append_change_record(connection, report_id, host_scope, change)

    def change_records(self, report_id: str) -> builtins.list[ChangeRecord]:
        with self._connection() as connection:
            connection.execute("BEGIN")
            return read_change_records(connection, report_id)

    def get_change_record(self, report_id: str, record_id: str) -> ChangeRecord | None:
        with self._connection() as connection:
            connection.execute("BEGIN")
            rows = read_change_records(connection, report_id, record_id)
        return rows[0] if rows else None

    def get(self, report_id: str) -> Report | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        return None if row is None else Report.model_validate_json(row["payload"])

    def list(self) -> builtins.list[dict[str, object]]:
        """Return at most the latest 100 reports, without log bodies."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM reports ORDER BY created_at DESC, id DESC LIMIT 100"
            ).fetchall()
        fields = {
            "id",
            "title",
            "host_id",
            "host_name",
            "scenario",
            "source",
            "created_at",
            "status",
            "summary",
        }
        return [
            Report.model_validate_json(row["payload"]).model_dump(mode="json", include=fields)
            for row in rows
        ]

    def handoff_rechecks(
        self, report: Report, *, after: datetime | None = None, host_scope: str | None = None
    ) -> Sequence[dict[str, str]]:
        """List local selection labels using captured target metadata, without reading evidence."""
        if report.source != "ssh" or not report.scope_hash or report.created_at.utcoffset() is None:
            return []
        if host_scope is None:
            host_scope = (
                scope_for(report.target) if report.target is not None else report.scope_hash
            )
        if not report_target_matches_host_scope(
            report.target, report.host_id, report.scope_hash, host_scope
        ):
            return []
        cutoff = max(report.created_at, after) if after is not None else report.created_at
        result = []
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id,created_at,json_extract(payload,'$.scope_hash') AS scope_hash,"
                "json_extract(payload,'$.target') AS target FROM reports WHERE created_at>? "
                "AND json_extract(payload,'$.source')='ssh' "
                "AND json_extract(payload,'$.host_id')=? "
                "AND json_extract(payload,'$.scenario')=? "
                "ORDER BY created_at DESC,id DESC",
                (
                    cutoff.astimezone(UTC).isoformat(),
                    report.host_id,
                    report.scenario,
                ),
            )
            for row in rows:
                try:
                    target = (
                        HostPublic.model_validate_json(row["target"])
                        if row["target"] is not None
                        else None
                    )
                except ValidationError:
                    continue
                if report_target_matches_host_scope(
                    target, report.host_id, row["scope_hash"], host_scope
                ):
                    result.append({"id": row["id"], "at": row["created_at"]})
                    if len(result) == 20:
                        break
        return result

    def save_handoff_receipt(self, receipt: BusinessHandoffRecheck) -> None:
        """Append a validated receipt without changing its original report."""
        payload = receipt.model_dump_json(warnings=False)
        key = _handoff_receipt_key(_parse_handoff_receipt(payload))
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO handoff_receipts (id, report_id, job_id, finished_at, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (*key, payload),
            )

    def get_handoff_receipt(
        self, report_id: str, job_id: str, receipt_id: str
    ) -> BusinessHandoffRecheck | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id, report_id, job_id, finished_at, payload FROM handoff_receipts "
                "WHERE report_id = ? AND job_id = ? AND id = ?",
                (report_id, job_id, receipt_id),
            ).fetchone()
        return None if row is None else _read_handoff_receipt(row)

    def handoff_receipts(
        self, report_id: str, job_id: str
    ) -> builtins.list[BusinessHandoffRecheck]:
        """List the latest 20 receipts for one original report and task."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, report_id, job_id, finished_at, payload FROM handoff_receipts "
                "WHERE report_id = ? AND job_id = ? ORDER BY finished_at DESC, id DESC LIMIT 20",
                (report_id, job_id),
            ).fetchall()
        return [_read_handoff_receipt(row) for row in rows]

    def has_handoff_receipts(self, report_id: str, job_id: str) -> bool:
        """Detect receipt history even if a stored payload cannot be read."""
        with self._connection() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM handoff_receipts WHERE report_id = ? AND job_id = ? LIMIT 1",
                    (report_id, job_id),
                ).fetchone()
                is not None
            )

    def set_ai(self, report_id: str, explanation: AIExplanation) -> Report | None:
        """Update interpretation atomically without touching the evidence or findings."""
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
            if row is None:
                return None
            report = Report.model_validate_json(row["payload"])
            report.ai = explanation
            connection.execute(
                "UPDATE reports SET payload = ? WHERE id = ?",
                (report.model_dump_json(), report_id),
            )
        return report
