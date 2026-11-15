"""The original investigation and its operator statements retain independent identities."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

import pytest
from pydantic import ValidationError
from test_access_recheck_store import linked_report
from test_store_transfer import make_directory, transfer

from opsark.baselines import scope_for
from opsark.change_record_store import (
    ChangeRecordConflict,
    ChangeRecordFutureInstant,
    ChangeRecordRequest,
    ChangeRecordScopeMismatch,
    ClaimedAt,
)
from opsark.storage import ReportStore


def request(index=1, *, precision="unknown", value=None, kind="nginx_configuration"):
    return ChangeRecordRequest.model_validate(
        {
            "request_id": f"{index:032x}",
            "kind": kind,
            "claimed_at": {"precision": precision, "value": value},
        }
    )


def append(store, report, change=None):
    return store.save_change_record(
        report.id, host_scope=report.scope_hash, change=change or request()
    )


def test_concurrent_retry_keeps_original_report_and_exact_public_record(tmp_path):
    store = ReportStore(tmp_path / "reports.sqlite3")
    report, other = linked_report(), linked_report("other")
    store.save(report)
    store.save(other)
    assert store.change_records(report.id) == []
    with closing(sqlite3.connect(store.path)) as db:
        original = db.execute("SELECT payload FROM reports WHERE id=?", (report.id,)).fetchone()
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name=?", (transfer.CHANGE_TABLE,)
            ).fetchone()
            is None
        )

    ready = Barrier(2)

    def save(instant):
        ready.wait(timeout=5)
        return append(store, report, request(precision="instant", value=instant))

    with ThreadPoolExecutor(max_workers=2) as executor:
        left, right = executor.map(save, ["2026-10-25T23:30:00-01:00", "2026-10-26T00:30:00Z"])
    assert left == right
    assert left.claimed_at.value == "2026-10-26T00:30:00Z"
    assert set(left.model_dump()) == {
        "id",
        "report_id",
        "kind",
        "claimed_at",
        "recorded_at",
        "source",
    }
    assert left.source == "operator_statement"
    with pytest.raises(ChangeRecordConflict, match="request_conflict"):
        append(store, report)
    with closing(sqlite3.connect(store.path)) as db:
        assert (
            db.execute("SELECT payload FROM reports WHERE id=?", (report.id,)).fetchone()
            == original
        )

    reopened = ReportStore(store.path)
    assert reopened.get_change_record(other.id, left.id) is None
    assert reopened.get_change_record(report.id, left.id) == left
    assert reopened.change_records(report.id) == [left]


@pytest.mark.parametrize(
    "claimed",
    [
        {"precision": "unknown", "value": "unknown"},
        {"precision": "date", "value": "2026-02-29"},
        {"precision": "date", "value": "20261026"},
        {"precision": "instant", "value": "2026-10-26T00:30:00"},
        {"precision": "instant", "value": "2026-10-26T00:30:00.1Z"},
        {"precision": "instant", "value": "2026-10-26T00:30:00+00:99"},
        {"precision": "instant", "value": "0001-01-01T00:00:00+01:00"},
        {"precision": "unknown", "value": None, "text": "synthetic unsupported input"},
    ],
)
def test_claim_time_has_only_closed_valid_precision(claimed):
    with pytest.raises(ValidationError):
        ClaimedAt.model_validate(claimed)


def test_write_checks_scope_future_and_limit_without_losing_matching_retry(tmp_path):
    store = ReportStore(tmp_path / "reports.sqlite3")
    report = linked_report()
    with pytest.raises(KeyError):
        append(store, report)
    store.save(report)
    with pytest.raises(ChangeRecordScopeMismatch):
        store.save_change_record(report.id, host_scope="b" * 64, change=request())
    with pytest.raises(ChangeRecordFutureInstant):
        append(store, report, request(precision="instant", value="9999-10-26T00:30:00Z"))
    assert store.change_records(report.id) == []
    saved = [
        append(store, report, request(i, precision="date", value="2024-02-29"))
        for i in range(1, 21)
    ]
    assert [item.claimed_at.value for item in saved] == ["2024-02-29"] * 20
    with pytest.raises(ChangeRecordConflict, match="limit_reached"):
        append(store, report, request(21))
    assert append(store, report, request(1, precision="date", value="2024-02-29")) == saved[0]
    assert set(item.id for item in store.change_records(report.id)) == {item.id for item in saved}


def test_management_scope_alone_cannot_attach_a_diagnostic_record(tmp_path):
    store = ReportStore(tmp_path / "reports.sqlite3")
    report = linked_report()
    target = report.target.model_copy(update={"disk_reclaim_scope_digest": "e" * 64})
    legacy = report.model_copy(update={"target": target, "scope_hash": scope_for(target)})
    store.save(legacy)
    with pytest.raises(ChangeRecordScopeMismatch):
        append(store, legacy)
    assert store.change_records(legacy.id) == []


def complete_fixture(path, *, with_record):
    directory = make_directory(path)
    store = ReportStore(directory / "reports.sqlite3")
    report = linked_report()
    store.save(report)
    item = append(store, report) if with_record else None
    for name in set(transfer.DATABASES) - {"reports.sqlite3"}:
        with closing(sqlite3.connect(directory / name)) as db, db:
            db.execute("CREATE TABLE sample (id TEXT PRIMARY KEY)")
        (directory / name).chmod(0o600)
    return store, report, item


@pytest.mark.parametrize("with_record", [False, True])
def test_ten_store_cold_rehearsal_preserves_record_and_legacy_absence(tmp_path, with_record):
    store, report, item = complete_fixture(tmp_path / "source", with_record=with_record)
    baseline = hashlib.sha256(store.path.read_bytes()).hexdigest()
    snapshot, recovered = tmp_path / "snapshot", tmp_path / "recovered"
    transfer.snapshot(store.path.parent, snapshot, confirm_quiescent=True)
    transfer.verify_snapshot(snapshot)
    transfer.rehearse(snapshot, recovered)
    assert hashlib.sha256(store.path.read_bytes()).hexdigest() == baseline
    cold = ReportStore(recovered / "reports.sqlite3")
    assert cold.get(report.id) == report
    assert cold.change_records(report.id) == ([item] if item else [])


def test_merge_lazily_adds_records_repeats_same_record_and_refuses_request_collision(tmp_path):
    report = linked_report()
    primary, extra, conflicting = (
        ReportStore(make_directory(tmp_path / name) / "reports.sqlite3")
        for name in ("primary", "extra", "conflicting")
    )
    for store in (primary, extra, conflicting):
        store.save(report)
    item = append(extra, report)
    append(conflicting, report, request(kind="image_update"))
    first, second, refused = (tmp_path / name for name in ("first", "second", "refused"))
    transfer.merge_report_baseline_snapshots(primary.path.parent, extra.path.parent, first)
    transfer.merge_report_baseline_snapshots(first, extra.path.parent, second)
    assert ReportStore(second / "reports.sqlite3").change_records(report.id) == [item]
    with pytest.raises(transfer.TransferError, match="same change request"):
        transfer.merge_report_baseline_snapshots(second, conflicting.path.parent, refused)
    assert not (refused / "reports.sqlite3").exists()


def test_merge_cannot_exceed_per_report_limit_or_replace_same_record(tmp_path):
    report = linked_report()
    primary = ReportStore(make_directory(tmp_path / "primary") / "reports.sqlite3")
    extra = ReportStore(make_directory(tmp_path / "extra") / "reports.sqlite3")
    for store in (primary, extra):
        store.save(report)
    original = [append(primary, report, request(i)) for i in range(1, 21)]
    supplemental = append(extra, report, request(21))
    with pytest.raises(transfer.TransferError, match="per-report limit"):
        transfer.merge_report_baseline_snapshots(
            primary.path.parent, extra.path.parent, tmp_path / "cap-refused"
        )
    with closing(sqlite3.connect(extra.path)) as db, db:
        raw = db.execute("SELECT payload FROM report_change_records_v1").fetchone()[0]
        changed = json.loads(raw) | {"id": original[0].id}
        raw = json.dumps(changed, separators=(",", ":"))
        db.execute(
            "UPDATE report_change_records_v1 SET id=?,payload=?,payload_sha256=?",
            (original[0].id, raw, hashlib.sha256(raw.encode()).hexdigest()),
        )
    with pytest.raises(transfer.TransferError, match="same evidence ID"):
        transfer.merge_report_baseline_snapshots(
            primary.path.parent, extra.path.parent, tmp_path / "record-refused"
        )
    assert not (tmp_path / "cap-refused" / "reports.sqlite3").exists()
    assert not (tmp_path / "record-refused" / "reports.sqlite3").exists()
    assert primary.change_records(report.id) == list(reversed(original))
    changed_record = extra.get_change_record(report.id, original[0].id)
    assert changed_record is not None and changed_record.kind == supplemental.kind


@pytest.mark.parametrize("corruption", ["digest", "scope", "index", "content"])
def test_supplemental_history_corruption_is_refused_by_app_cold_and_merge(tmp_path, corruption):
    primary = ReportStore(make_directory(tmp_path / "primary") / "reports.sqlite3")
    other, report, item = complete_fixture(tmp_path / "candidate", with_record=True)
    primary.save(report)
    with closing(sqlite3.connect(other.path)) as db, db:
        if corruption == "index":
            db.execute("DROP INDEX report_change_records_report_v1")
            db.execute(
                "CREATE INDEX report_change_records_report_v1 ON report_change_records_v1(id)"
            )
        elif corruption == "digest":
            db.execute("UPDATE report_change_records_v1 SET payload_sha256=?", ("0" * 64,))
        else:
            raw = db.execute("SELECT payload FROM report_change_records_v1").fetchone()[0]
            payload = json.loads(raw)
            if corruption == "scope":
                payload["host_scope"] = "0" * 64
            else:
                payload["claimed_at"] = {"precision": "date", "value": "2026-02-29"}
            raw = json.dumps(payload, separators=(",", ":"))
            db.execute(
                "UPDATE report_change_records_v1 SET host_scope=?,payload=?,payload_sha256=?",
                (payload["host_scope"], raw, hashlib.sha256(raw.encode()).hexdigest()),
            )
    with pytest.raises(ValueError, match="inconsistent"):
        other.get_change_record(report.id, item.id)
    with pytest.raises(transfer.TransferError, match="[Cc]hange record"):
        transfer.snapshot(other.path.parent, tmp_path / "cold", confirm_quiescent=True)
    out = tmp_path / "merged"
    with pytest.raises(transfer.TransferError, match="[Cc]hange record"):
        transfer.merge_report_baseline_snapshots(primary.path.parent, other.path.parent, out)
    assert not (out / "reports.sqlite3").exists()
