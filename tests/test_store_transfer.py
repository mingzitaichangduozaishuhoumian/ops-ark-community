"""Real SQLite snapshots preserve WAL commits, immutable evidence and dedup state."""

import hashlib
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_storage import make_receipt, make_report

from opsark import action_handoff_recheck_store as actions
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.models import HostPublic
from opsark.storage import ReportStore

SPEC = importlib.util.spec_from_file_location(
    "opsark_store_transfer",
    Path(__file__).resolve().parents[1] / "deploy/observer/store_transfer.py",
)
assert SPEC is not None and SPEC.loader is not None
transfer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transfer)

REPORT_SCHEMA = (
    "CREATE TABLE reports(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,payload TEXT NOT NULL)"
)
BASELINE_SCHEMA = (
    "CREATE TABLE baselines(id TEXT PRIMARY KEY,report_id TEXT NOT NULL UNIQUE,"
    "source TEXT NOT NULL,host_id TEXT NOT NULL,scenario TEXT NOT NULL,"
    "created_at TEXT NOT NULL,payload TEXT NOT NULL)"
)


def make_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def make_reports(directory, rows=(), *, schema=REPORT_SCHEMA):
    path = directory / "reports.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(schema)
        connection.executemany("INSERT INTO reports VALUES(?,?,?)", rows)
    path.chmod(0o600)
    return path


def make_baselines(directory, rows=(), *, extra_column=False):
    path = directory / "baselines.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(BASELINE_SCHEMA)
        if extra_column:
            connection.execute("ALTER TABLE baselines ADD COLUMN new_metadata TEXT")
        else:
            connection.executemany("INSERT INTO baselines VALUES(?,?,?,?,?,?,?)", rows)
    path.chmod(0o600)
    return path


def rows(path, table):
    assert table in {
        "reports",
        "baselines",
        "events",
        "alerts",
        "alert_seen",
        "coverage_marks",
        "monitor_lease",
        "patch_jobs",
        "patch_submit_intents",
        "patch_monitor_lease",
        "handoff_receipts",
    }
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute("SELECT * FROM " + table).fetchall()  # noqa: S608 -- test allowlist


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_backup_includes_committed_rows_still_only_in_wal(tmp_path):
    source = make_directory(tmp_path / "source")
    path = source / "reports.sqlite3"
    with closing(sqlite3.connect(path)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(REPORT_SCHEMA)
        writer.execute("INSERT INTO reports VALUES(?,?,?)", ("r1", "2026-10-28", '{"id":"r1"}'))
        writer.commit()
        path.chmod(0o600)
        before = path.read_bytes()
        wal = Path(str(path) + "-wal")
        wal_before = wal.read_bytes()
        assert wal_before
        result = transfer.snapshot(source, tmp_path / "snapshot")
        assert result["databases"]["reports.sqlite3"]["tables"]["reports"]["rows"] == 1
        assert rows(tmp_path / "snapshot/reports.sqlite3", "reports")[0][0] == "r1"
        assert path.read_bytes() == before
        assert wal.read_bytes() == wal_before
    assert {p.name for p in (tmp_path / "snapshot").iterdir()} == {
        "reports.sqlite3",
        "manifest.json",
    }


def test_quiescent_cli_leaves_closed_wal_database_without_sidecars(tmp_path):
    source = make_directory(tmp_path / "source")
    original_row = ("r1", "2026-11-12", '{"id":"r1"}')
    path = make_reports(source, [original_row])
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    before = directory_digests(source)
    assert set(before) == {"reports.sqlite3"}

    output = tmp_path / "snapshot"
    result = subprocess.run(  # noqa: S603 -- local interpreter and fixed fixture paths.
        [
            sys.executable,
            "-I",
            "-B",
            transfer.__file__,
            "snapshot",
            str(source),
            str(output),
            "--confirm-quiescent",
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    assert json.loads(result.stdout)["databases"][path.name]["table_rows"]["reports"] == 1
    assert rows(output / path.name, "reports") == [original_row]
    assert directory_digests(source) == before


@pytest.mark.parametrize("keep_shm", [True, False])
def test_quiescent_snapshot_retains_commits_in_cold_uncheckpointed_wal(tmp_path, keep_shm):
    source = make_directory(tmp_path / "source")
    path = make_reports(source)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    base_digest = file_digest(path)
    # Exiting without SQLite close leaves real committed frames without a writer.
    script = """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute('INSERT INTO reports VALUES (?,?,?)', ('r1','2026-11-12','{}'))
connection.commit()
os._exit(0)
"""
    subprocess.run(  # noqa: S603 -- local interpreter and fixed synthetic SQLite program.
        [sys.executable, "-I", "-B", "-c", script, str(path)],
        capture_output=True,
        check=True,
        timeout=30,
    )
    assert file_digest(path) == base_digest
    wal = source / (path.name + "-wal")
    assert wal.stat().st_size > 0
    if not keep_shm:
        (source / (path.name + "-shm")).unlink()
    before = directory_digests(source)

    output = tmp_path / "snapshot"
    result = transfer.snapshot(source, output, confirm_quiescent=True)
    assert result["databases"][path.name]["tables"]["reports"]["rows"] == 1
    assert rows(output / path.name, "reports") == [("r1", "2026-11-12", "{}")]
    assert set(directory_digests(output)) == {path.name, "manifest.json"}
    assert directory_digests(source) == before


def test_quiescent_snapshot_refuses_even_empty_rollback_journal_before_output(tmp_path):
    source = make_directory(tmp_path / "source")
    path = make_reports(source)
    journal = source / (path.name + "-journal")
    journal.touch(mode=0o600)
    before = directory_digests(source)
    output = tmp_path / "snapshot"

    with pytest.raises(transfer.TransferError, match="rollback journal"):
        transfer.snapshot(source, output, confirm_quiescent=True)

    assert not output.exists()
    assert directory_digests(source) == before


@pytest.mark.parametrize(
    ("suffix", "reason"), [("-journal", "rollback journal"), ("-wal", "changed")]
)
def test_quiescent_snapshot_checks_source_again_before_publishing(
    tmp_path, monkeypatch, suffix, reason
):
    source = make_directory(tmp_path / "source")
    path = make_reports(source)
    output = tmp_path / "snapshot"
    backup = transfer._backup

    def changed_after_backup(original, stage, *, immutable):
        assert immutable
        backup(original, stage, immutable=immutable)
        (source / (path.name + suffix)).touch(mode=0o600)

    monkeypatch.setattr(transfer, "_backup", changed_after_backup)
    with pytest.raises(transfer.TransferError, match=reason):
        transfer.snapshot(source, output, confirm_quiescent=True)
    assert not any(output.iterdir())


def test_snapshot_whitelist_never_reads_tokens_env_or_unapproved_database(tmp_path):
    source = make_directory(tmp_path / "source")
    make_reports(source, [("r1", "day", '{"id":"r1","secret":"DO-NOT-EXPORT"}')])
    for name in ("access-token", ".env", "arbitrary.sqlite3"):
        (source / name).write_text("DO-NOT-READ")
    result = transfer.snapshot(source, tmp_path / "snapshot")
    encoded = json.dumps(result)
    assert "DO-NOT" not in encoded
    assert set(result["databases"]) == {"reports.sqlite3"}
    assert rows(tmp_path / "snapshot/reports.sqlite3", "reports")[0][2].endswith('"DO-NOT-EXPORT"}')


def test_existing_output_is_not_replaced(tmp_path):
    source = make_directory(tmp_path / "source")
    make_reports(source)
    output = make_directory(tmp_path / "output")
    existing = output / "reports.sqlite3"
    existing.write_text("previous deployment")
    with pytest.raises(transfer.TransferError, match="empty"):
        transfer.snapshot(source, output)
    assert existing.read_text() == "previous deployment"


@pytest.mark.parametrize("name", transfer.DATABASES)
def test_only_named_database_paths_are_considered(tmp_path, name):
    source = make_directory(tmp_path / "source")
    path = source / name
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE sample(id TEXT PRIMARY KEY)")
    path.chmod(0o600)
    result = transfer.snapshot(source, tmp_path / "snapshot")
    assert set(result["databases"]) == {name}


def test_merge_compares_payload_json_semantics_without_rewriting_authoritative_bytes(tmp_path):
    authoritative = make_directory(tmp_path / "authoritative")
    supplemental = make_directory(tmp_path / "supplemental")
    original = '{ "id": "r1", "action": {"executable":false}, "facts": [] }'
    make_reports(authoritative, [("r1", "day1", original)])
    make_reports(
        supplemental,
        [
            ("r1", "day1", '{"facts":[],"action":{"executable":false},"id":"r1"}'),
            ("r2", "day2", '{"id":"r2"}'),
        ],
    )
    make_baselines(authoritative, [("b1", "r1", "ssh", "host-a", "disk", "day1", '{"id":"b1"}')])
    make_baselines(
        supplemental,
        [
            ("b1", "r1", "ssh", "host-a", "disk", "day1", '{"id":"b1"}'),
            ("b2", "r2", "ssh", "host-a", "disk", "day2", '{"id":"b2"}'),
        ],
    )
    before = {
        p: file_digest(p)
        for directory in (authoritative, supplemental)
        for p in directory.iterdir()
    }
    manifest = transfer.merge_report_baseline_snapshots(
        authoritative, supplemental, tmp_path / "merged"
    )
    result = dict((r[0], r) for r in rows(tmp_path / "merged/reports.sqlite3", "reports"))
    assert result["r1"][2] == original
    assert set(result) == {"r1", "r2"}
    assert len(rows(tmp_path / "merged/baselines.sqlite3", "baselines")) == 2
    assert all(file_digest(path) == digest for path, digest in before.items())
    assert manifest["status"] == "complete"


@pytest.fixture
def action_merge(tmp_path, monkeypatch):
    primary = make_directory(tmp_path / "primary")
    extra = make_directory(tmp_path / "extra")
    now = datetime(2026, 5, 8, 10, tzinfo=UTC)
    host = HostPublic(
        id="test-host",
        name="Synthetic",
        address="192.0.2.2",
        source="ssh",
        disk_reclaim_scope_digest="e" * 64,
    )
    report = make_report().model_copy(
        update={
            "id": "report",
            "host_id": host.id,
            "source": "ssh",
            "created_at": now - timedelta(minutes=3),
            "target": host,
            "scope_hash": diagnostic_scope_for(host),
        }
    )
    binding = actions.ActionRecheckBinding(
        report_id=report.id,
        kind="nginx",
        plan_id="0" * 32,
        host_id=host.id,
        host_scope=scope_for(host),
        target_scope="a" * 64,
        approval_digest="b" * 64,
        execution_digest="c" * 64,
        profile_digest="d" * 64,
        configured_checks=3,
        execution_at=now - timedelta(minutes=1),
    )
    for folder in (primary, extra):
        ReportStore(folder / "reports.sqlite3").save(report)

    def register(folder, instant, checks):
        monkeypatch.setattr(actions, "_now", lambda: instant)
        store = actions.ActionHandoffRecheckStore(ReportStore(folder / "reports.sqlite3"))
        intent = store.start(binding)
        if checks is not None:
            store.finish(binding, intent.id, checks=checks)
        return intent.id

    return primary, extra, binding, now, register


@pytest.mark.parametrize("primary_has_action", [False, True])
def test_merge_action_rechecks_and_keep_newest_capture_first(
    tmp_path, action_merge, primary_has_action
):
    primary, extra, binding, now, register = action_merge
    primary_id = (
        register(primary, now, ("passed", "passed", "passed")) if primary_has_action else None
    )
    extra_id = register(extra, now - timedelta(seconds=10), ("passed", "failed", "uncovered"))
    unfinished = register(extra, now - timedelta(seconds=5), None)
    before = {
        path: file_digest(path) for directory in (primary, extra) for path in directory.iterdir()
    }
    manifest = transfer.merge_report_baseline_snapshots(primary, extra, tmp_path / "merged")
    merged = actions.ActionHandoffRecheckStore(ReportStore(tmp_path / "merged/reports.sqlite3"))
    failed = merged.get(binding, extra_id)
    assert failed is not None and failed.verdict == "failed"
    pending = merged.get(binding, unfinished)
    assert pending is not None and pending.result is None
    assert [run.intent.id for run in merged.list(binding)] == [
        item for item in (primary_id, unfinished, extra_id) if item is not None
    ]
    assert all(file_digest(path) == digest for path, digest in before.items())
    assert manifest["status"] == "complete"


def test_merge_action_conflict_cannot_replace_original(tmp_path, action_merge, monkeypatch):
    primary, extra, _, now, register = action_merge
    monkeypatch.setattr(actions.secrets, "token_hex", lambda _: "f" * 32)
    first = register(primary, now, ("passed", "passed", "passed"))
    assert register(extra, now, ("failed", "passed", "passed")) == first
    output = tmp_path / "merged"
    with pytest.raises(transfer.TransferError, match="same evidence ID"):
        transfer.merge_report_baseline_snapshots(primary, extra, output)
    assert not (output / "reports.sqlite3").exists()
    conflict = json.loads((output / "manifest.json").read_text())["conflict"]
    assert (
        conflict["table"] == transfer.ACTION_RESULTS
        and conflict["reason"] == "immutable_id_content_conflict"
    )


def test_merge_same_action_id_dedupes_with_different_local_sequences(tmp_path, action_merge):
    primary, extra, binding, now, register = action_merge
    register(primary, now - timedelta(seconds=1), None)
    original_id = register(primary, now, ("passed", "passed", "passed"))
    # A supplemental snapshot kept the exact intent but never recorded a result.
    with closing(sqlite3.connect(primary / "reports.sqlite3")) as source:
        original = source.execute(
            "SELECT id,report_id,kind,plan_id,binding_sha256,binding_json,started_at "
            "FROM action_handoff_recheck_intents_v1 WHERE id=?",
            (original_id,),
        ).fetchone()
    with closing(sqlite3.connect(extra / "reports.sqlite3")) as db, db:
        for statement in transfer.ACTION_DDL:
            db.execute(statement)
        db.execute(
            "INSERT INTO action_handoff_recheck_intents_v1 VALUES(1,?,?,?,?,?,?,?)",
            original,
        )
    transfer.merge_report_baseline_snapshots(primary, extra, tmp_path / "merged")
    merged = actions.ActionHandoffRecheckStore(ReportStore(tmp_path / "merged/reports.sqlite3"))
    result = merged.get(binding, original_id)
    assert result is not None and result.verdict == "passed" and len(merged.list(binding)) == 2


@pytest.mark.parametrize("secondary_has_current", [False, True])
def test_merge_legacy_action_catalog_adds_exact_history_index_only_to_output(
    tmp_path, action_merge, secondary_has_current
):
    primary, extra, binding, now, register = action_merge
    prior = register(primary, now - timedelta(seconds=10), None)
    with closing(sqlite3.connect(primary / "reports.sqlite3")) as db, db:
        db.execute("DROP INDEX action_handoff_recheck_original_v1")
    if secondary_has_current:
        latest = register(extra, now, ("passed", "passed", "passed"))
    else:
        (extra / "reports.sqlite3").unlink()
        latest = None
    before = file_digest(primary / "reports.sqlite3")
    output = tmp_path / "merged"
    transfer.merge_report_baseline_snapshots(primary, extra, output)
    with closing(transfer._connection(output / "reports.sqlite3")) as db:
        assert transfer._schema(db, "reports")[2] == "current"
    ledger = actions.ActionHandoffRecheckStore(ReportStore(output / "reports.sqlite3"))
    history = ledger.list_original(binding.report_id, binding.kind, binding.plan_id)
    assert [row.intent.id for row in history] == [item for item in (latest, prior) if item]
    assert file_digest(primary / "reports.sqlite3") == before


@pytest.mark.parametrize(
    "variant",
    [
        "altered_schema",
        "invalid_scope",
        "missing_result_table",
        "corrupt_result",
        "altered_history_index",
        "unknown_index",
    ],
)
def test_merge_action_admits_only_exact_schema_and_bound_rows(tmp_path, action_merge, variant):
    primary, extra, _, now, register = action_merge
    register(extra, now, ("passed", "passed", "passed"))
    with closing(sqlite3.connect(extra / "reports.sqlite3")) as db, db:
        if variant == "altered_schema":
            db.execute("ALTER TABLE action_handoff_recheck_intents_v1 ADD COLUMN extra TEXT")
        elif variant == "missing_result_table":
            db.execute("DROP TABLE action_handoff_recheck_results_v1")
        elif variant == "corrupt_result":
            db.execute("UPDATE action_handoff_recheck_results_v1 SET result_sha256='invalid'")
        elif variant == "altered_history_index":
            db.execute("DROP INDEX action_handoff_recheck_original_v1")
            db.execute(
                "CREATE INDEX action_handoff_recheck_original_v1 "
                "ON action_handoff_recheck_intents_v1 (plan_id, report_id)"
            )
        elif variant == "unknown_index":
            db.execute(
                "CREATE INDEX unexpected_action_index ON action_handoff_recheck_intents_v1 (kind)"
            )
        else:
            raw = db.execute(
                "SELECT binding_json FROM action_handoff_recheck_intents_v1"
            ).fetchone()[0]
            raw = json.dumps(json.loads(raw) | {"host_scope": "f" * 64}, separators=(",", ":"))
            db.execute(
                "UPDATE action_handoff_recheck_intents_v1 SET binding_json=?,binding_sha256=?",
                (raw, hashlib.sha256(raw.encode()).hexdigest()),
            )
    output = tmp_path / "merged"
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(primary, extra, output)
    assert not (output / "reports.sqlite3").exists()


@pytest.mark.parametrize(
    "payload",
    [
        '{"id":"r1","action":{"executable":true}}',
        '{"id":"r1","new_default":false}',
        '{"id":"r1","id":"r1"}',
    ],
)
def test_conflicting_or_ambiguous_id_never_overwrites_either_backup(tmp_path, payload):
    authoritative = make_directory(tmp_path / "authoritative")
    supplemental = make_directory(tmp_path / "supplemental")
    a = make_reports(authoritative, [("r1", "day", '{"id":"r1"}')])
    b = make_reports(supplemental, [("r1", "day", payload)])
    before = (a.read_bytes(), b.read_bytes())
    output = tmp_path / "merged"
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(authoritative, supplemental, output)
    assert (a.read_bytes(), b.read_bytes()) == before
    assert not (output / "reports.sqlite3").exists()
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["status"] == "conflict"
    assert "payload" not in json.dumps(manifest)


def test_extra_baseline_columns_refuse_merge_without_partial_report_publication(tmp_path):
    authoritative = make_directory(tmp_path / "authoritative")
    supplemental = make_directory(tmp_path / "supplemental")
    make_reports(authoritative, [("r1", "day", '{"id":"r1"}')])
    make_reports(supplemental, [("r2", "day", '{"id":"r2"}')])
    make_baselines(authoritative)
    make_baselines(supplemental, extra_column=True)
    with pytest.raises(transfer.TransferError, match="schemas differ"):
        transfer.merge_report_baseline_snapshots(authoritative, supplemental, tmp_path / "merged")
    assert not (tmp_path / "merged/reports.sqlite3").exists()
    assert not (tmp_path / "merged/baselines.sqlite3").exists()
    assert json.loads((tmp_path / "merged/manifest.json").read_text())["status"] == "conflict"


def test_unique_baseline_report_binding_conflict_is_not_ignored(tmp_path):
    authoritative = make_directory(tmp_path / "authoritative")
    supplemental = make_directory(tmp_path / "supplemental")
    make_reports(authoritative)
    make_reports(supplemental)
    make_baselines(authoritative, [("b1", "r1", "ssh", "host", "disk", "day", "{}")])
    make_baselines(supplemental, [("b2", "r1", "ssh", "host", "disk", "day", "{}")])
    with pytest.raises(sqlite3.IntegrityError):
        transfer.merge_report_baseline_snapshots(authoritative, supplemental, tmp_path / "merged")
    assert json.loads((tmp_path / "merged/manifest.json").read_text())["status"] == "conflict"


def test_lease_clear_changes_only_transport_copy_fixed_lease_tables(tmp_path):
    source = make_directory(tmp_path / "source")
    for filename in ("security.sqlite3", "web-security.sqlite3"):
        path = source / filename
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.executescript(
                "CREATE TABLE events(id TEXT PRIMARY KEY,cursor TEXT);"
                "CREATE TABLE alerts(id TEXT PRIMARY KEY,payload TEXT);"
                "CREATE TABLE alert_seen(alert_id TEXT,event_id TEXT,"
                "PRIMARY KEY(alert_id,event_id));"
                "CREATE TABLE coverage_marks(host_id TEXT PRIMARY KEY,covered_until INTEGER);"
                "CREATE TABLE monitor_lease(singleton INTEGER PRIMARY KEY,"
                "owner TEXT,expires_at REAL);"
            )
            connection.execute("INSERT INTO events VALUES('event-1','cursor-1')")
            connection.execute(
                "INSERT INTO alerts VALUES(?,?)",
                (
                    "a" * 64,
                    '{"status":"acknowledged","notification_count":1,"secret":"NEVER-PRINT"}',
                ),
            )
            connection.execute("INSERT INTO alert_seen VALUES(?,'event-1')", ("a" * 64,))
            connection.execute("INSERT INTO coverage_marks VALUES('host',12345)")
            connection.execute("INSERT INTO monitor_lease VALUES(1,'old-owner',99999)")
        path.chmod(0o600)
    patches = source / "patches.sqlite3"
    with closing(sqlite3.connect(patches)) as connection, connection:
        connection.executescript(
            "CREATE TABLE patch_jobs(host_id TEXT,job_id TEXT,status TEXT,revision INTEGER,"
            "payload TEXT,notification_count INTEGER,PRIMARY KEY(host_id,job_id));"
            "CREATE TABLE patch_submit_intents(host_id TEXT,job_id TEXT,payload TEXT,"
            "PRIMARY KEY(host_id,job_id));"
            "CREATE TABLE patch_monitor_lease(id INTEGER PRIMARY KEY,owner TEXT,expires_at REAL);"
        )
        connection.execute(
            "INSERT INTO patch_jobs VALUES(?,?,?,?,?,?)", ("host", "b" * 32, "verified", 7, "{}", 1)
        )
        connection.execute("INSERT INTO patch_submit_intents VALUES('host',?,'{}')", ("c" * 32,))
        connection.execute("INSERT INTO patch_monitor_lease VALUES(1,'old-owner',99999)")
    patches.chmod(0o600)
    before = {p: p.read_bytes() for p in source.iterdir()}
    snapshot = transfer.snapshot(source, tmp_path / "snapshot")
    manifest = transfer.clear_monitor_leases(tmp_path / "snapshot")
    assert manifest["cleared_lease_rows"] == {
        "security.sqlite3": 1,
        "web-security.sqlite3": 1,
        "patches.sqlite3": 1,
    }
    for name in ("security.sqlite3", "web-security.sqlite3"):
        assert rows(tmp_path / "snapshot" / name, "monitor_lease") == []
        for table in ("events", "alerts", "alert_seen", "coverage_marks"):
            assert rows(source / name, table) == rows(tmp_path / "snapshot" / name, table)
            assert (
                manifest["databases"][name]["tables"][table]
                == snapshot["databases"][name]["tables"][table]
            )
    assert rows(tmp_path / "snapshot/patches.sqlite3", "patch_monitor_lease") == []
    assert rows(source / "patches.sqlite3", "patch_jobs") == rows(
        tmp_path / "snapshot/patches.sqlite3", "patch_jobs"
    )
    assert rows(source / "patches.sqlite3", "patch_submit_intents") == rows(
        tmp_path / "snapshot/patches.sqlite3", "patch_submit_intents"
    )
    assert all(path.read_bytes() == content for path, content in before.items())
    assert "NEVER-PRINT" not in json.dumps(manifest)
    assert manifest["databases"]["patches.sqlite3"]["tables"]["patch_jobs"]["summaries"] == [
        {
            "id": "b" * 32,
            "host_id": "host",
            "status": "verified",
            "notification_count": 1,
            "revision": 7,
        }
    ]


def test_lease_clear_refuses_an_unmanifested_live_source(tmp_path):
    source = make_directory(tmp_path / "source")
    make_reports(source)
    with pytest.raises(FileNotFoundError):
        transfer.clear_monitor_leases(source)


def test_lease_clear_refuses_live_wal_with_a_forged_marker(tmp_path):
    live = make_directory(tmp_path / "live")
    path = live / "security.sqlite3"
    with closing(sqlite3.connect(path)) as writer:
        writer.executescript(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
            "CREATE TABLE monitor_lease(id INTEGER PRIMARY KEY,owner TEXT);"
            "INSERT INTO monitor_lease VALUES(1,'active-worker');"
        )
        path.chmod(0o600)
        marker = live / "manifest.json"
        marker.write_text('{"schema_version":1,"operation":"snapshot","status":"complete"}')
        marker.chmod(0o600)
        before = directory_digests(live)
        assert "security.sqlite3-wal" in before
        with pytest.raises(transfer.TransferError):
            transfer.clear_monitor_leases(live)
        assert directory_digests(live) == before
        assert writer.execute("SELECT owner FROM monitor_lease").fetchone() == ("active-worker",)


@pytest.mark.parametrize("drift", ["row", "manifest_rows", "unlisted_store", "sidecar"])
def test_lease_clear_refuses_stale_transport_before_any_write(tmp_path, drift):
    source = make_directory(tmp_path / "source")
    path = source / "security.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            "CREATE TABLE monitor_lease(id INTEGER PRIMARY KEY,owner TEXT);"
            "INSERT INTO monitor_lease VALUES(1,'first-worker');"
        )
    path.chmod(0o600)
    copy = tmp_path / "copy"
    transfer.snapshot(source, copy)
    if drift == "row":
        with closing(sqlite3.connect(copy / path.name)) as connection, connection:
            connection.execute("UPDATE monitor_lease SET owner='later-worker'")
    elif drift == "manifest_rows":
        marker = copy / "manifest.json"
        manifest = json.loads(marker.read_text())
        manifest["databases"][path.name]["tables"]["monitor_lease"]["rows"] = 0
        marker.write_text(json.dumps(manifest))
    elif drift == "unlisted_store":
        make_reports(copy)
    else:
        (copy / "security.sqlite3-journal").write_bytes(b"unexpected journal")
    before = directory_digests(copy)
    with pytest.raises(transfer.TransferError):
        transfer.clear_monitor_leases(copy)
    assert directory_digests(copy) == before


def test_lease_clear_preflights_all_stores_before_deleting(tmp_path):
    source = make_directory(tmp_path / "source")
    for name in ("security.sqlite3", "web-security.sqlite3"):
        path = source / name
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.executescript(
                "CREATE TABLE monitor_lease(id INTEGER PRIMARY KEY);"
                "INSERT INTO monitor_lease VALUES(1);"
            )
            if name == "web-security.sqlite3":
                connection.execute(
                    "CREATE TRIGGER unexpected AFTER DELETE ON monitor_lease BEGIN SELECT 1; END"
                )
        path.chmod(0o600)
    copy = tmp_path / "copy"
    transfer.snapshot(source, copy)
    before = directory_digests(copy)
    with pytest.raises(transfer.TransferError, match="triggers"):
        transfer.clear_monitor_leases(copy)
    assert directory_digests(copy) == before


def test_lease_clear_accepts_an_intact_partial_merge(tmp_path):
    authoritative = make_directory(tmp_path / "authoritative")
    supplemental = make_directory(tmp_path / "supplemental")
    make_reports(authoritative, [("r1", "day", '{"id":"r1"}')])
    make_reports(supplemental, [("r2", "day", '{"id":"r2"}')])
    output = tmp_path / "merged"
    manifest = transfer.merge_report_baseline_snapshots(authoritative, supplemental, output)
    with pytest.raises(transfer.TransferError):
        transfer.verify_snapshot(output)
    result = transfer.clear_monitor_leases(output)
    assert result["cleared_lease_rows"] == {}
    assert result["databases"] == manifest["databases"]


@pytest.mark.parametrize("hazard", ["trigger", "cascade", "uppercase_cascade"])
def test_lease_cleanup_cannot_modify_evidence_through_schema_side_effects(tmp_path, hazard):
    source = make_directory(tmp_path / "source")
    path = source / "security.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE monitor_lease(id INTEGER PRIMARY KEY)")
        if hazard in {"cascade", "uppercase_cascade"}:
            reference = "MONITOR_LEASE" if hazard == "uppercase_cascade" else "monitor_lease"
            connection.execute(
                "CREATE TABLE events(id TEXT PRIMARY KEY,"
                f"lease_id INTEGER REFERENCES {reference}(id) ON DELETE CASCADE)"  # noqa: S608 -- two fixed test literals.
            )
            connection.execute("INSERT INTO monitor_lease VALUES(1)")
            connection.execute("INSERT INTO events VALUES('event-1',1)")
        else:
            connection.execute("CREATE TABLE events(id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO monitor_lease VALUES(1)")
            connection.execute("INSERT INTO events VALUES('event-1')")
            connection.execute(
                "CREATE TRIGGER destructive_lease_delete AFTER DELETE ON monitor_lease "
                "BEGIN DELETE FROM events; END"
            )
    path.chmod(0o600)
    transfer.snapshot(source, tmp_path / "snapshot")
    with pytest.raises(transfer.TransferError):
        transfer.clear_monitor_leases(tmp_path / "snapshot")
    assert rows(tmp_path / "snapshot/security.sqlite3", "events") == rows(path, "events")
    assert len(rows(tmp_path / "snapshot/security.sqlite3", "monitor_lease")) == 1


@pytest.mark.parametrize("which", ["source_dir", "source_file", "output_dir"])
@pytest.mark.skipif(os.name != "posix", reason="Creating and inspecting real POSIX symbolic links")
def test_links_are_never_followed(tmp_path, which):
    source = make_directory(tmp_path / "source")
    path = make_reports(source)
    output = tmp_path / "snapshot"
    if which == "source_dir":
        linked = tmp_path / "linked"
        linked.symlink_to(source, target_is_directory=True)
        source = linked
    elif which == "source_file":
        moved = source / "real-database"
        path.rename(moved)
        path.symlink_to(moved)
    else:
        actual = make_directory(tmp_path / "actual-output")
        output.symlink_to(actual, target_is_directory=True)
    with pytest.raises(transfer.TransferError, match="Linked"):
        transfer.snapshot(source, output)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode bits")
def test_snapshots_are_private_even_with_permissive_process_umask(tmp_path):
    source = make_directory(tmp_path / "source")
    make_reports(source)
    previous = os.umask(0)
    try:
        transfer.snapshot(source, tmp_path / "snapshot")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "snapshot").stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in (tmp_path / "snapshot").iterdir())


def test_database_size_budget_fails_without_overwriting_source(tmp_path, monkeypatch):
    source = make_directory(tmp_path / "source")
    path = make_reports(source)
    original = path.read_bytes()
    monkeypatch.setattr(transfer, "MAX_DATABASE_BYTES", 1024)
    with pytest.raises(transfer.TransferError):
        transfer.snapshot(source, tmp_path / "snapshot")
    assert path.read_bytes() == original


def test_sources_and_output_cannot_overlap(tmp_path):
    source = make_directory(tmp_path / "source")
    make_reports(source)
    with pytest.raises(transfer.TransferError, match="separate"):
        transfer.snapshot(source, source / "nested-snapshot")


@pytest.fixture
def complete_controller(tmp_path):
    source = make_directory(tmp_path / "controller")
    make_reports(source, [("report-1", "2026-11-05", '{"secret":"PRIVATE-REPORT-CANARY"}')])
    for name in transfer.DATABASES:
        if name == "reports.sqlite3":
            continue
        path = source / name
        with closing(sqlite3.connect(path)) as connection, connection:
            if name == "patches.sqlite3":
                connection.execute(
                    "CREATE TABLE patch_jobs(job_id TEXT PRIMARY KEY, host_id TEXT, status TEXT, "
                    "revision INTEGER, notification_count INTEGER, payload TEXT)"
                )
                connection.execute(
                    "INSERT INTO patch_jobs VALUES(?,?,?,?,?,?)",
                    ("a" * 32, "private-host-canary", "verified", 7, 1, "{}"),
                )
            else:
                connection.execute("CREATE TABLE sample(id TEXT PRIMARY KEY)")
                connection.execute("INSERT INTO sample VALUES('committed-record')")
        path.chmod(0o600)
    return source


@pytest.fixture
def complete_snapshot(tmp_path, complete_controller):
    destination = tmp_path / "backup"
    manifest = transfer.snapshot(complete_controller, destination)
    return destination, manifest


def directory_digests(directory):
    return {entry.name: file_digest(entry) for entry in directory.iterdir()}


def damage_backup(directory, damage):
    path = directory / "reports.sqlite3"
    if damage == "missing":
        path.unlink()
    elif damage == "corrupt":
        path.write_bytes(b"not a SQLite database")
    elif damage == "changed_rows":
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("UPDATE reports SET payload='{}' WHERE id='report-1'")
    elif damage == "changed_manifest":
        marker = directory / "manifest.json"
        manifest = json.loads(marker.read_text())
        manifest["databases"][path.name]["tables"]["reports"]["rows"] += 1
        marker.write_text(json.dumps(manifest))
    elif damage == "wal":
        path.with_name(path.name + "-wal").write_bytes(b"unexpected sidecar")
    elif damage == "unexpected":
        (directory / "access-token").write_text("PRIVATE-TOKEN-CANARY")


def test_verify_complete_snapshot_summarizes_without_rewriting(complete_snapshot):
    backup, manifest = complete_snapshot
    before = directory_digests(backup)
    result = transfer.verify_snapshot(backup)
    assert result["status"] == "complete"
    assert result["database_count"] == len(transfer.DATABASES)
    assert set(result["databases"]) == set(transfer.DATABASES)
    assert result["databases"]["reports.sqlite3"] == {
        "sha256": manifest["databases"]["reports.sqlite3"]["sha256"],
        "size": (backup / "reports.sqlite3").stat().st_size,
        "table_count": 1,
        "row_count": 1,
    }
    assert "PRIVATE-REPORT-CANARY" not in json.dumps(result)
    assert "private-host-canary" not in json.dumps(result)
    assert directory_digests(backup) == before


@pytest.mark.parametrize(
    "damage", ["missing", "corrupt", "changed_rows", "changed_manifest", "wal", "unexpected"]
)
def test_damaged_snapshot_is_refused_before_rehearsal(tmp_path, complete_snapshot, damage):
    backup, _manifest = complete_snapshot
    damage_backup(backup, damage)
    before = directory_digests(backup)
    with pytest.raises(transfer.TransferError):
        transfer.verify_snapshot(backup)
    with pytest.raises(transfer.TransferError):
        transfer.rehearse(backup, tmp_path / "rehearsal")
    assert not (tmp_path / "rehearsal").exists()
    assert directory_digests(backup) == before


def test_rehearsal_creates_independent_verified_copy(tmp_path, complete_snapshot):
    backup, manifest = complete_snapshot
    before = directory_digests(backup)
    destination = tmp_path / "rehearsal"
    result = transfer.rehearse(backup, destination)
    assert result["status"] == "complete"
    assert result["database_count"] == len(transfer.DATABASES)
    checked = transfer.verify_snapshot(destination)
    assert checked["databases"] == result["databases"]
    assert set(directory_digests(destination)) == set(before)
    restored_manifest = json.loads((destination / "manifest.json").read_text())
    for name, expected in manifest["databases"].items():
        restored = restored_manifest["databases"][name]
        assert restored["schema_sha256"] == expected["schema_sha256"]
        assert restored["tables"] == expected["tables"]
    assert directory_digests(backup) == before

    damage_backup(destination, "changed_rows")
    with pytest.raises(transfer.TransferError):
        transfer.verify_snapshot(destination)
    assert transfer.verify_snapshot(backup)["status"] == "complete"
    assert directory_digests(backup) == before


def test_complete_snapshot_and_rehearsal_preserve_handoff_receipt(tmp_path, complete_controller):
    receipt = make_receipt(offset=10).model_copy(
        update={"report_id": "receipt-original", "host_id": "private-host-canary"}
    )
    report = make_report(receipt.report_id).model_copy(
        update={"source": "ssh", "host_id": receipt.host_id, "scope_hash": receipt.host_scope}
    )
    name = "reports.sqlite3"
    store = ReportStore(complete_controller / name)
    store.save(report)
    store.save_handoff_receipt(receipt)
    expected = rows(complete_controller / name, "handoff_receipts")
    assert len(expected) == 1 and expected[0][-1] == receipt.model_dump_json()
    assert store.get_handoff_receipt(report.id, receipt.job_id, receipt.id) == receipt
    source_before = directory_digests(complete_controller)

    backup, restored = tmp_path / "backup", tmp_path / "restored"
    manifest = transfer.snapshot(complete_controller, backup)
    assert set(manifest["databases"]) == set(transfer.DATABASES)
    backup_before = directory_digests(backup)
    assert transfer.verify_snapshot(backup)["status"] == "complete"
    assert transfer.rehearse(backup, restored)["status"] == "complete"
    assert transfer.verify_snapshot(restored)["status"] == "complete"
    assert (
        rows(backup / name, "handoff_receipts")
        == rows(restored / name, "handoff_receipts")
        == expected
    )
    assert rows(restored / name, "reports") == rows(complete_controller / name, "reports")
    assert directory_digests(complete_controller) == source_before
    assert directory_digests(backup) == backup_before


def test_rehearsal_refuses_nonempty_destination(tmp_path, complete_snapshot):
    backup, _manifest = complete_snapshot
    destination = make_directory(tmp_path / "destination")
    existing = make_reports(destination, [("existing", "2026-11-05", "{}")])
    before = existing.read_bytes()
    with pytest.raises(transfer.TransferError):
        transfer.rehearse(backup, destination)
    assert existing.read_bytes() == before
    assert list(destination.iterdir()) == [existing]


def test_failed_rehearsal_does_not_publish_partial_manifest(
    tmp_path, complete_snapshot, monkeypatch
):
    backup, _manifest = complete_snapshot
    before = directory_digests(backup)
    destination = tmp_path / "rehearsal"
    backup_one = transfer._backup
    calls = 0

    def interrupted_copy(source, stage):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise transfer.TransferError("fixture copy interrupted")
        backup_one(source, stage)

    monkeypatch.setattr(transfer, "_backup", interrupted_copy)
    with pytest.raises(transfer.TransferError, match="copy interrupted"):
        transfer.rehearse(backup, destination)
    assert calls == 2
    assert not destination.exists() or not any(destination.iterdir())
    assert directory_digests(backup) == before


def test_rehearsal_publish_conflict_preserves_racing_destination(
    tmp_path, complete_snapshot, monkeypatch
):
    backup, _manifest = complete_snapshot
    before = directory_digests(backup)
    destination = tmp_path / "rehearsal"
    conflict = destination / transfer.DATABASES[1]
    link = os.link

    def publish(source, target):
        if target == conflict:
            target.write_bytes(b"another operation owns this file")
        link(source, target)

    monkeypatch.setattr(transfer.os, "link", publish)
    with pytest.raises(FileExistsError):
        transfer.rehearse(backup, destination)
    assert list(destination.iterdir()) == [conflict]
    assert conflict.read_bytes() == b"another operation owns this file"
    assert directory_digests(backup) == before
