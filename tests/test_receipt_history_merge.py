"""Offline union keeps business receipts bound to their original report IDs."""

import json
import sqlite3
from contextlib import closing
from datetime import UTC, timedelta, timezone

import pytest
from test_storage import make_receipt, make_report
from test_store_transfer import transfer

from opsark.storage import ReportStore


def make_store(directory, report_ids, *, receipts=(), modern=True):
    directory.mkdir(mode=0o700)
    path = directory / "reports.sqlite3"
    store = ReportStore(path)
    for report_id in report_ids:
        store.save(make_report(report_id))
    for receipt in receipts:
        store.save_handoff_receipt(receipt)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=DELETE")
        if not modern:
            connection.execute("DROP TABLE handoff_receipts")
    return path


def receipt_rows(path):
    with closing(sqlite3.connect(path)) as connection:
        has_receipts = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='handoff_receipts'"
        ).fetchone()
        if has_receipts is None:
            return None
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        return connection.execute(
            "SELECT id, report_id, job_id, finished_at, payload FROM handoff_receipts ORDER BY id"
        ).fetchall()


@pytest.mark.parametrize(
    "primary_new,extra_new", [(False, False), (False, True), (True, False), (True, True)]
)
def test_offline_merge_old_and_new_receipt_schema(tmp_path, primary_new, extra_new):
    first = make_receipt().model_copy(update={"report_id": "primary-original"})
    second = make_receipt(2).model_copy(
        update={
            "report_id": "supplemental-original",
            "finished_at": make_receipt(2).finished_at.astimezone(timezone(timedelta(hours=5))),
        }
    )
    primary = make_store(
        tmp_path / "primary",
        [first.report_id],
        modern=primary_new,
        receipts=[first] if primary_new else [],
    )
    extra = make_store(
        tmp_path / "extra",
        [second.report_id],
        modern=extra_new,
        receipts=[second] if extra_new else [],
    )
    with closing(sqlite3.connect(extra.parent / "patches.sqlite3")) as patch_db, patch_db:
        patch_db.execute("CREATE TABLE patch_handoff_audit (id TEXT NOT NULL)")
        patch_db.execute("INSERT INTO patch_handoff_audit VALUES ('fixture-approval')")
    before = {
        path: path.read_bytes() for path in (primary, extra, extra.parent / "patches.sqlite3")
    }
    destination = tmp_path / "merged"
    manifest = transfer.merge_report_baseline_snapshots(primary.parent, extra.parent, destination)
    assert manifest["status"] == "complete" and set(manifest["databases"]) == {"reports.sqlite3"}
    assert set(path.name for path in destination.iterdir()) == {"manifest.json", "reports.sqlite3"}
    merged = destination / "reports.sqlite3"
    assert receipt_rows(merged) == (
        (receipt_rows(primary) or []) + (receipt_rows(extra) or [])
        if primary_new or extra_new
        else None
    )
    assert all(path.read_bytes() == content for path, content in before.items())
    if primary_new or extra_new:
        opened = ReportStore(merged)
        assert opened.get(first.report_id) == make_report(first.report_id)
        assert opened.get(second.report_id) == make_report(second.report_id)
        for receipt, saved in ((first, primary_new), (second, extra_new)):
            assert opened.handoff_receipts(receipt.report_id, receipt.job_id) == (
                [receipt] if saved else []
            )


@pytest.mark.parametrize("changed", [False, True])
def test_shared_receipt_id_is_an_immutable_exact_row(tmp_path, changed):
    original = make_receipt()
    other = original.model_copy(update={"checks": ["failed"]}) if changed else original
    primary = make_store(tmp_path / "primary", [original.report_id], receipts=[original])
    extra = make_store(tmp_path / "extra", [other.report_id], receipts=[other])
    before = primary.read_bytes(), extra.read_bytes()
    destination = tmp_path / "merged"
    if changed:
        with pytest.raises(transfer.TransferError, match="same evidence ID"):
            transfer.merge_report_baseline_snapshots(primary.parent, extra.parent, destination)
        assert {path.name for path in destination.iterdir()} == {"manifest.json"}
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["status"] == "conflict"
        assert manifest["conflict"] == {
            "database": "reports.sqlite3",
            "table": "handoff_receipts",
            "id": original.id,
            "reason": "immutable_id_content_conflict",
        }
    else:
        transfer.merge_report_baseline_snapshots(primary.parent, extra.parent, destination)
        assert receipt_rows(destination / "reports.sqlite3") == receipt_rows(primary)
    assert (primary.read_bytes(), extra.read_bytes()) == before


@pytest.mark.parametrize(
    "hazard",
    [
        "wrong_fk",
        "wrong_report_binding",
        "wrong_job",
        "unknown_payload",
        "wrong_index",
        "trigger",
        "sqlite_prefix_trigger",
        "bad_timestamp",
        "unexpected_table",
    ],
)
def test_merge_refuses_invalid_receipt_or_unapproved_schema(tmp_path, hazard):
    receipt = make_receipt()
    primary = make_store(tmp_path / "primary", [receipt.report_id], modern=False)
    extra = make_store(
        tmp_path / "extra", [receipt.report_id, "another-original"], receipts=[receipt]
    )
    with closing(sqlite3.connect(extra)) as connection, connection:
        if hazard == "wrong_fk":
            connection.execute("UPDATE handoff_receipts SET report_id='missing-original'")
        elif hazard == "wrong_report_binding":
            connection.execute("UPDATE handoff_receipts SET report_id='another-original'")
        elif hazard == "wrong_job":
            connection.execute("UPDATE handoff_receipts SET job_id=?", ("f" * 32,))
        elif hazard == "unknown_payload":
            payload = json.loads(receipt.model_dump_json()) | {"raw": "private-fixture-marker"}
            connection.execute("UPDATE handoff_receipts SET payload=?", (json.dumps(payload),))
        elif hazard == "wrong_index":
            connection.execute("DROP INDEX handoff_receipts_scope")
            connection.execute(
                "CREATE INDEX handoff_receipts_scope ON handoff_receipts (report_id)"
            )
        elif hazard == "trigger":
            connection.execute(
                "CREATE TRIGGER alter_history AFTER INSERT ON handoff_receipts "
                "BEGIN DELETE FROM reports; END"
            )
        elif hazard == "sqlite_prefix_trigger":
            connection.execute(
                "CREATE TRIGGER sqliteXalter_history AFTER INSERT ON handoff_receipts "
                "BEGIN DELETE FROM reports; END"
            )
        elif hazard == "bad_timestamp":
            connection.execute(
                "UPDATE handoff_receipts SET finished_at=?",
                (receipt.finished_at.astimezone(UTC).isoformat(timespec="seconds"),),
            )
        else:
            connection.execute("CREATE TABLE private_rows (payload TEXT)")
    destination = tmp_path / "merged"
    before = primary.read_bytes(), extra.read_bytes()
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(primary.parent, extra.parent, destination)
    assert (primary.read_bytes(), extra.read_bytes()) == before
    assert {path.name for path in destination.iterdir()} == {"manifest.json"}
    assert "private-fixture-marker" not in (destination / "manifest.json").read_text(
        encoding="utf-8"
    )
