import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from opsark.handoff_timeline import BusinessHandoffRecheck
from opsark.models import AIExplanation, Evidence, Finding, Report, Verification
from opsark.storage import ReportStore


def make_report(report_id: str = "report-1", offset: int = 0) -> Report:
    created = datetime(2026, 10, 26, 12, 0, tzinfo=UTC) + timedelta(seconds=offset)
    return Report(
        id=report_id,
        host_id="demo",
        host_name="演示主机",
        scenario="web_502",
        source="replay",
        created_at=created,
        status="needs_attention",
        title="上游不可用",
        summary="根据回放证据调查。",
        facts=[Finding(text="上游连接被拒绝。", evidence_ids=["e1"])],
        candidates=[Finding(text="上游服务可能不可用。", evidence_ids=["e1"])],
        missing=["没有历史配置。"],
        evidence=[
            Evidence(
                id="e1",
                check_id="nginx_errors",
                target="demo",
                source="replay",
                collected_at=created,
                status="ok",
                output="connection refused",
            )
        ],
        next_steps=["核实上游服务。"],
        verification=[Verification(name="站点恢复", detail="未执行任何处置或恢复检查。")],
    )


def test_report_survives_reopening_and_list_omits_log_bodies(tmp_path: Path) -> None:
    path = tmp_path / "reports.sqlite3"
    report = make_report()
    ReportStore(path).save(report)
    reopened = ReportStore(path)
    assert reopened.get(report.id) == report
    assert reopened.get("missing") is None
    summary = reopened.list()[0]
    assert summary["host_name"] == "演示主机"
    assert "evidence" not in summary
    assert "connection refused" not in str(summary)


def test_duplicate_identifier_does_not_replace_original_evidence(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    original = make_report()
    store.save(original)
    changed = original.model_copy(update={"summary": "replacement"})
    with pytest.raises(sqlite3.IntegrityError):
        store.save(changed)
    assert store.get(original.id) == original


def test_update_ai_preserves_evidence_and_findings(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    report = make_report()
    store.save(report)
    explanation = AIExplanation(
        status="completed", text="补充解释", evidence_ids=["e1"], model="test"
    )
    updated = store.set_ai(report.id, explanation)
    assert updated is not None
    assert updated.ai == explanation
    assert updated.model_dump(exclude={"ai"}) == report.model_dump(exclude={"ai"})
    assert store.get(report.id) == updated
    assert store.set_ai("missing", explanation) is None


def test_report_identifiers_are_sql_parameters(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    special = make_report("x'); DROP TABLE reports; --")
    store.save(special)
    assert store.get(special.id) == special
    assert store.get("' OR 1=1 --") is None
    store.save(make_report("normal"))
    assert len(store.list()) == 2


def test_list_is_newest_first_and_limited_to_100(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    for index in range(105):
        store.save(make_report(f"report-{index:03}", offset=index))
    result = store.list()
    assert len(result) == 100
    assert result[0]["id"] == "report-104"
    assert result[-1]["id"] == "report-005"


def make_receipt(index: int = 1, *, offset: int = 0) -> BusinessHandoffRecheck:
    at = datetime(2026, 10, 26, 12, 0, tzinfo=UTC) + timedelta(seconds=offset)
    return BusinessHandoffRecheck(
        id=f"br-{index:032x}",
        report_id="report-1",
        host_id="demo",
        job_id="a" * 32,
        host_scope="b" * 64,
        approval_digest="c" * 64,
        profile_digest="d" * 64,
        started_at=at,
        finished_at=at + timedelta(milliseconds=500),
        checks=["failed", "inconclusive", "passed"],
    )


def test_handoff_receipt_migrates_existing_store_and_is_scoped(tmp_path: Path) -> None:
    path = tmp_path / "reports.sqlite3"
    report = make_report()
    with closing(sqlite3.connect(path)) as database, database:
        database.execute(
            "CREATE TABLE reports (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, "
            "payload TEXT NOT NULL)"
        )
        database.execute(
            "INSERT INTO reports VALUES (?, ?, ?)",
            (report.id, report.created_at.isoformat(), report.model_dump_json()),
        )

    receipt = make_receipt()
    ReportStore(path).save_handoff_receipt(receipt)
    reopened = ReportStore(path)
    assert reopened.get(report.id) == report
    assert len(reopened.list()) == 1
    assert reopened.get_handoff_receipt(report.id, receipt.job_id, receipt.id) == receipt
    assert reopened.get_handoff_receipt("report-2", receipt.job_id, receipt.id) is None
    assert reopened.get_handoff_receipt(report.id, "e" * 32, receipt.id) is None
    assert reopened.get_handoff_receipt(report.id, receipt.job_id, "' OR 1=1 --") is None
    assert reopened.handoff_receipts(report.id, receipt.job_id) == [receipt]
    assert reopened.handoff_receipts("report-2", receipt.job_id) == []
    assert reopened.has_handoff_receipts(report.id, receipt.job_id)
    assert not reopened.has_handoff_receipts("report-2", receipt.job_id)
    assert not reopened.has_handoff_receipts(report.id, "e" * 32)
    with closing(sqlite3.connect(path)) as database:
        payload = database.execute("SELECT payload FROM handoff_receipts").fetchone()[0]
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
    assert json.loads(payload) == receipt.model_dump(mode="json")
    assert "connection refused" not in payload


def test_handoff_receipt_rejects_replacement_or_missing_report(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    receipt = make_receipt()
    with pytest.raises(sqlite3.IntegrityError):
        store.save_handoff_receipt(receipt)
    assert store.list() == []

    store.save(make_report())
    store.save_handoff_receipt(receipt)
    with pytest.raises(sqlite3.IntegrityError):
        store.save_handoff_receipt(receipt.model_copy(update={"checks": ["passed"]}))
    with pytest.raises(ValueError, match="receipt is inconsistent"):
        store.save_handoff_receipt(make_receipt(2).model_copy(update={"checks": ["body text"]}))
    assert store.handoff_receipts(receipt.report_id, receipt.job_id) == [receipt]


def test_handoff_receipts_newest_twenty_use_normalized_time(tmp_path: Path) -> None:
    store = ReportStore(tmp_path / "reports.sqlite3")
    store.save(make_report())
    rows = [make_receipt(index, offset=index // 2) for index in range(22)]
    east = timezone(timedelta(hours=8))
    rows[0] = rows[0].model_copy(
        update={
            "started_at": rows[0].started_at.astimezone(east),
            "finished_at": rows[0].finished_at.astimezone(east),
        }
    )
    for receipt in reversed(rows):
        store.save_handoff_receipt(receipt)
    store.save_handoff_receipt(make_receipt(23, offset=200).model_copy(update={"job_id": "e" * 32}))
    report_id, job_id = rows[0].report_id, rows[0].job_id
    assert store.handoff_receipts(report_id, job_id) == list(reversed(rows[2:]))
    assert store.get_handoff_receipt(report_id, job_id, rows[0].id) == rows[0]


@pytest.mark.parametrize("corruption", ["metadata", "wrong_job", "duplicate_key", "private_field"])
def test_handoff_receipt_corruption_fails_closed(tmp_path: Path, corruption: str) -> None:
    path = tmp_path / "reports.sqlite3"
    store = ReportStore(path)
    store.save(make_report())
    receipt = make_receipt()
    store.save_handoff_receipt(receipt)
    with closing(sqlite3.connect(path)) as database, database:
        if corruption == "metadata":
            database.execute(
                "UPDATE handoff_receipts SET finished_at = ? WHERE id = ?",
                ("2026-10-26T13:00:00.000000+00:00", receipt.id),
            )
        else:
            payload = receipt.model_dump_json()
            if corruption == "wrong_job":
                payload = receipt.model_copy(update={"job_id": "e" * 32}).model_dump_json()
            elif corruption == "duplicate_key":
                payload = '{"job_id":"bad",' + payload[1:]
            else:
                payload = '{"raw_response":"SYNTHETIC-PRIVATE",' + payload[1:]
            database.execute(
                "UPDATE handoff_receipts SET payload = ? WHERE id = ?", (payload, receipt.id)
            )
    assert store.has_handoff_receipts(receipt.report_id, receipt.job_id)
    with pytest.raises(ValueError, match="^Business handoff receipt is inconsistent$"):
        store.get_handoff_receipt(receipt.report_id, receipt.job_id, receipt.id)
    with pytest.raises(ValueError, match="^Business handoff receipt is inconsistent$"):
        store.handoff_receipts(receipt.report_id, receipt.job_id)
