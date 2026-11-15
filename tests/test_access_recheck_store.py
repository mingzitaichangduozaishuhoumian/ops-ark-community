"""Access rechecks stay bound to their original report through storage and transfer."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_storage import make_report
from test_store_transfer import make_directory, transfer

from opsark.access_recheck_store import AccessCheckResult, AccessRecheck, access_outcome
from opsark.baselines import diagnostic_scope_for
from opsark.models import HostPublic
from opsark.storage import ReportStore

PROFILE = "b" * 64


def linked_report(identifier="original"):
    target = HostPublic(
        id="access-target",
        name="Synthetic target",
        address="192.0.2.18",
        source="ssh",
        trusted_hosts_digest="a" * 64,
    )
    return make_report(identifier).model_copy(
        update={
            "target": target,
            "host_id": target.id,
            "source": "ssh",
            "scope_hash": diagnostic_scope_for(target),
        }
    )


def receipt(
    report, suffix=1, *, offset=1, management="verified", external="matched", result="passed"
):
    checks = [AccessCheckResult(id="main", status=result)]
    return AccessRecheck(
        id=f"ar-{suffix:032x}",
        report_id=report.id,
        finished_at=report.created_at + timedelta(seconds=offset),
        management=management,
        external=external,
        checks=checks,
        status=access_outcome(management, external, checks),
    )


def test_capture_and_rechecks_preserve_original_report_after_reopen(tmp_path):
    report, other = linked_report(), linked_report("other")
    path = tmp_path / "reports.sqlite3"
    store = ReportStore(path)
    store.save(other)
    assert store.access_profile(other.id) is None and store.access_rechecks(other.id) == []
    store.save(report, access_profile=PROFILE)
    old = receipt(report, management="unavailable", result="inconclusive")
    current = receipt(report, 2, offset=2)
    store.save_access_recheck(old, profile=PROFILE)
    store.save_access_recheck(current, profile=PROFILE)
    opened = ReportStore(path)
    assert opened.get(report.id) == report and opened.access_profile(report.id) == PROFILE
    assert opened.get_access_recheck(report.id, old.id) == old
    assert opened.get_access_recheck(other.id, old.id) is None
    assert opened.access_rechecks(report.id) == [current, old]


def test_report_capture_and_receipt_identity_fail_closed(tmp_path):
    path = tmp_path / "reports.sqlite3"
    store = ReportStore(path)
    report = linked_report()
    with pytest.raises(ValueError):
        store.save(report, access_profile="x" * 64)
    assert store.get(report.id) is None
    wrong = report.model_copy(update={"scope_hash": "c" * 64})
    with pytest.raises(ValueError):
        store.save(wrong, access_profile=PROFILE)
    assert store.get(report.id) is None
    store.save(report, access_profile=PROFILE)
    with pytest.raises(ValueError):
        store.save_access_recheck(receipt(report), profile="e" * 64)
    with pytest.raises(ValueError):
        store.save_access_recheck(receipt(report, offset=0), profile=PROFILE)
    with pytest.raises(ValueError):
        store.save_access_recheck(receipt(linked_report("unrelated")), profile=PROFILE)
    assert store.access_rechecks(report.id) == []
    value = receipt(report)
    store.save_access_recheck(value, profile=PROFILE)
    with pytest.raises(sqlite3.IntegrityError):
        store.save_access_recheck(value, profile=PROFILE)
    assert store.access_rechecks(report.id) == [value]


@pytest.mark.parametrize(
    ("management", "external", "check", "verdict"),
    [
        ("verified", "matched", "passed", "accepted"),
        ("unavailable", "matched", "inconclusive", "pending"),
        ("unavailable", "unreachable", "inconclusive", "failed"),
        ("verified", "unavailable", "failed", "failed"),
        ("verified", "unavailable", "passed", "pending"),
    ],
)
def test_only_complete_fresh_observations_are_accepted(management, external, check, verdict):
    item = receipt(linked_report(), management=management, external=external, result=check)
    assert item.status == verdict
    wrong = "pending" if verdict != "pending" else "accepted"
    with pytest.raises(ValidationError):
        AccessRecheck.model_validate(item.model_dump() | {"status": wrong})


def test_recheck_history_is_bounded_but_old_receipts_are_selectable(tmp_path):
    report = linked_report()
    store = ReportStore(tmp_path / "reports.sqlite3")
    store.save(report, access_profile=PROFILE)
    for suffix in range(1, 22):
        store.save_access_recheck(receipt(report, suffix), profile=PROFILE)
    assert [row.id for row in store.access_rechecks(report.id)] == [
        f"ar-{suffix:032x}" for suffix in reversed(range(2, 22))
    ]
    assert store.get_access_recheck(report.id, f"ar-{1:032x}") == receipt(report)


def test_cold_and_merge_transfer_keep_scope_profile_and_history(tmp_path):
    report = linked_report()
    base = make_directory(tmp_path / "primary")
    extra = make_directory(tmp_path / "supplemental")
    ReportStore(base / "reports.sqlite3").save(report)
    store = ReportStore(extra / "reports.sqlite3")
    store.save(report, access_profile=PROFILE)
    item = receipt(report)
    store.save_access_recheck(item, profile=PROFILE)
    for name in transfer.DATABASES:
        if name != "reports.sqlite3":
            with closing(sqlite3.connect(extra / name)) as db, db:
                db.execute("CREATE TABLE sample (id TEXT PRIMARY KEY)")
            (extra / name).chmod(0o600)
    with closing(sqlite3.connect(base / "baselines.sqlite3")) as db, db:
        db.execute("CREATE TABLE baselines (id TEXT PRIMARY KEY, payload TEXT)")
    (base / "baselines.sqlite3").chmod(0o600)
    original = hashlib.sha256((extra / "reports.sqlite3").read_bytes()).hexdigest()
    cold, merged = tmp_path / "cold", tmp_path / "merged"
    transfer.snapshot(extra, cold, confirm_quiescent=True)
    transfer.verify_snapshot(cold)
    supplemental = make_directory(tmp_path / "supplemental-reports")
    detached = ReportStore(supplemental / "reports.sqlite3")
    detached.save(report, access_profile=PROFILE)
    detached.save_access_recheck(item, profile=PROFILE)
    transfer.merge_report_baseline_snapshots(base, supplemental, merged)
    assert hashlib.sha256((extra / "reports.sqlite3").read_bytes()).hexdigest() == original
    for folder in (cold, merged):
        reopened = ReportStore(folder / "reports.sqlite3")
        assert reopened.get(report.id) == report
        assert reopened.access_profile(report.id) == PROFILE
        assert reopened.get_access_recheck(report.id, item.id) == item


@pytest.mark.parametrize("changed", ["profile", "receipt", "index"])
def test_merge_refuses_profile_conflict_or_invalid_receipt_catalog(tmp_path, changed):
    report = linked_report()
    base = make_directory(tmp_path / "primary")
    extra = make_directory(tmp_path / "supplemental")
    primary = ReportStore(base / "reports.sqlite3")
    other = ReportStore(extra / "reports.sqlite3")
    primary.save(report, access_profile=PROFILE)
    other.save(report, access_profile="c" * 64 if changed == "profile" else PROFILE)
    item = receipt(report)
    other.save_access_recheck(item, profile=other.access_profile(report.id))
    with closing(sqlite3.connect(other.path)) as db, db:
        if changed == "receipt":
            raw = json.dumps(
                item.model_dump(mode="json") | {"status": "failed"}, separators=(",", ":")
            )
            db.execute(
                "UPDATE access_rechecks_v1 SET payload=?,payload_sha256=?",
                (raw, hashlib.sha256(raw.encode()).hexdigest()),
            )
        if changed == "index":
            db.execute("DROP INDEX access_rechecks_report_v1")
            db.execute("CREATE INDEX access_rechecks_report_v1 ON access_rechecks_v1(id)")
    out = tmp_path / "merged"
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(base, extra, out)
    assert not (out / "reports.sqlite3").exists()
    assert primary.access_profile(report.id) == PROFILE and primary.access_rechecks(report.id) == []
