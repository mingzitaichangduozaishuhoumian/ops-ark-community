"""Standalone cold transfer preserves container rechecks and validates bound history."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from test_compose_generation_store import close_offline
from test_compose_generation_store import report as ssh_report
from test_store_transfer import directory_digests, make_directory, transfer

from opsark.baselines import scope_for
from opsark.container_report_recheck_store import ContainerReportRecheck
from opsark.storage import ReportStore

EXPECTED_DDL = (
    "CREATE TABLE container_recheck_profiles_v1 ("
    " report_id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, profile_sha256 TEXT NOT NULL )",
    "CREATE TABLE container_rechecks_v1 ("
    " id TEXT PRIMARY KEY NOT NULL,"
    " report_id TEXT NOT NULL REFERENCES container_recheck_profiles_v1(report_id),"
    " request_id TEXT NOT NULL, finished_at TEXT NOT NULL,"
    " payload_sha256 TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(report_id, request_id) )",
    "CREATE INDEX container_rechecks_report_v1 ON container_rechecks_v1"
    " (report_id, finished_at DESC, id DESC)",
)


def make_database(path, report, *, profile=None, all_stores=False):
    directory = make_directory(path)
    store = ReportStore(directory / "reports.sqlite3")
    store.save(report)
    if profile is not None:
        with store._connection() as conn:
            for statement in EXPECTED_DDL:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO container_recheck_profiles_v1 VALUES (?,?,?)",
                (report.id, report.scope_hash, profile),
            )
    if all_stores:
        for name in set(transfer.DATABASES) - {"reports.sqlite3"}:
            with closing(sqlite3.connect(directory / name)) as conn, conn:
                if name == "baselines.sqlite3":
                    conn.execute("CREATE TABLE baselines (id TEXT PRIMARY KEY, payload TEXT)")
                else:
                    conn.execute("CREATE TABLE synthetic (id TEXT PRIMARY KEY)")
            (directory / name).chmod(0o600)
    return store


def insert(store, report, index=1, *, request=None, changes=None):
    at = report.created_at + timedelta(seconds=index)
    record = {
        "id": f"rr-{index:032x}",
        "report_id": report.id,
        "finished_at": at.isoformat().replace("+00:00", "Z"),
        "management": "verified",
        "checks": ["passed", "inconclusive"],
        "status": "pending",
    } | (changes or {})
    request = request or f"{index:032x}"
    payload = json.dumps(record, separators=(",", ":"))
    seal = hashlib.sha256(
        b"opsark-container-recheck/v1\0" + request.encode("ascii") + b"\0" + payload.encode()
    ).hexdigest()
    with store._connection() as conn:
        conn.execute(
            "INSERT INTO container_rechecks_v1 VALUES (?,?,?,?,?,?)",
            (
                record["id"],
                report.id,
                request,
                at.isoformat(timespec="microseconds"),
                seal,
                payload,
            ),
        )
    return record


def select_rechecks(path):
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute("SELECT payload FROM container_rechecks_v1 ORDER BY id").fetchall()


def test_fresh_ten_store_cold_restore_and_lazy_idempotent_merge(tmp_path):
    original = ssh_report("original", scope_change=True)
    old = make_database(tmp_path / "old", original, all_stores=True)
    new = make_database(tmp_path / "new", original, profile="d" * 64, all_stores=True)
    insert(new, original)
    insert(new, original, 2, changes={"checks": ["failed", "passed"], "status": "failed"})
    insert(new, original, 3, changes={"checks": ["passed"], "status": "passed"})
    insert(new, original, 4, changes={"management": "unavailable", "checks": ["uncovered"]})
    close_offline(old.path.parent, new.path.parent)
    before = directory_digests(new.path.parent)
    snapshot, receiver, legacy, merged, repeated = (
        tmp_path / name for name in ("snapshot", "receiver", "legacy", "merged", "repeated")
    )
    transfer.snapshot(new.path.parent, snapshot, confirm_quiescent=True)
    assert transfer.verify_snapshot(snapshot)["database_count"] == 10
    transfer.rehearse(snapshot, receiver)
    transfer.snapshot(old.path.parent, legacy, confirm_quiescent=True)
    assert transfer.verify_snapshot(legacy)["database_count"] == 10
    assert select_rechecks(receiver / "reports.sqlite3") == select_rechecks(new.path)
    transfer.merge_report_baseline_snapshots(old.path.parent, new.path.parent, merged)
    transfer.merge_report_baseline_snapshots(merged, new.path.parent, repeated)
    assert select_rechecks(repeated / "reports.sqlite3") == select_rechecks(new.path)
    assert directory_digests(new.path.parent) == before


def test_stock_store_and_standalone_transfer_share_exact_catalog_and_request_seal(tmp_path):
    original = ssh_report("stock", scope_change=True)
    source = make_database(tmp_path / "source", original, all_stores=True)
    actual = ssh_report("fresh-stock", scope_change=True)
    profile, request = "f" * 64, "1" * 32
    source.save(actual, container_recheck_profile=profile)
    item = ContainerReportRecheck(
        id="rr-" + "2" * 32,
        report_id=actual.id,
        finished_at=actual.created_at + timedelta(seconds=1),
        management="verified",
        checks=["passed"],
        status="passed",
    )
    source.save_container_recheck(item, profile=profile, request_id=request)
    snapshot, output = tmp_path / "snapshot", tmp_path / "restored"
    transfer.snapshot(source.path.parent, snapshot, confirm_quiescent=True)
    assert transfer.verify_snapshot(snapshot)["database_count"] == 10
    transfer.rehearse(snapshot, output)
    reopened = ReportStore(output / "reports.sqlite3")
    assert reopened.get(actual.id) == actual
    assert reopened.container_recheck_profile(actual.id) == profile
    assert reopened.container_rechecks(actual.id) == {request: item}
    assert reopened.container_rechecks(original.id) == {}


@pytest.mark.parametrize(
    "damage", ["catalog", "scope", "scenario", "request", "verdict", "nonevidence", "clock"]
)
def test_tampered_receipt_is_rejected_before_cold_or_merge_publication(tmp_path, damage):
    original = ssh_report("original", scope_change=True)
    report = original
    if damage == "scope":
        report = original.model_copy(update={"scope_hash": scope_for(original.target)})
    if damage == "scenario":
        report = original.model_copy(update={"scenario": "web_502"})
    source = make_database(tmp_path / "source", report, profile="a" * 64)
    primary = make_database(tmp_path / "primary", report)
    changes = {
        "verdict": {"status": "failed"},
        "nonevidence": {"management": "unavailable", "checks": ["failed"], "status": "failed"},
    }.get(damage)
    insert(source, report, index=0 if damage == "clock" else 1, changes=changes)
    with source._connection() as conn:
        if damage == "catalog":
            conn.execute("DROP INDEX container_rechecks_report_v1")
            conn.execute("CREATE INDEX container_rechecks_report_v1 ON container_rechecks_v1(id)")
        if damage == "request":
            conn.execute("UPDATE container_rechecks_v1 SET request_id=?", ("a" * 32,))
    with pytest.raises(transfer.TransferError, match="[Cc]ontainer recheck"):
        transfer.snapshot(source.path.parent, tmp_path / "snapshot", confirm_quiescent=True)
    with pytest.raises(transfer.TransferError, match="[Cc]ontainer recheck"):
        transfer.merge_report_baseline_snapshots(
            primary.path.parent, source.path.parent, tmp_path / "merge"
        )
    assert not (tmp_path / "snapshot/reports.sqlite3").exists()
    assert not (tmp_path / "merge/reports.sqlite3").exists()


@pytest.mark.parametrize("collision", ["profile", "request", "capacity"])
def test_merge_rejects_conflicts_without_replacing_either_original(tmp_path, collision):
    report = ssh_report("original")
    primary = make_database(tmp_path / "primary", report, profile="d" * 64)
    supplemental = make_database(
        tmp_path / "supplemental", report, profile=("a" if collision == "profile" else "d") * 64
    )
    for index in range(1, 21 if collision == "capacity" else 2):
        insert(primary, report, index)
    insert(supplemental, report, 21, request=f"{1:032x}" if collision == "request" else None)
    close_offline(primary.path.parent, supplemental.path.parent)
    before = (directory_digests(primary.path.parent), directory_digests(supplemental.path.parent))
    output = tmp_path / "merge"
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(
            primary.path.parent, supplemental.path.parent, output
        )
    assert not (output / "reports.sqlite3").exists()
    assert before == (
        directory_digests(primary.path.parent),
        directory_digests(supplemental.path.parent),
    )
