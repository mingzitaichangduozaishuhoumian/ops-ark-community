#!/usr/bin/env python3
"""Offline store transfer primitives; never copy credentials or a live WAL by hand."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import ExitStack, closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

DATABASES = (
    "reports.sqlite3",
    "baselines.sqlite3",
    "security.sqlite3",
    "web-security.sqlite3",
    "security-ai.sqlite3",
    "patches.sqlite3",
    "automation.sqlite3",
    "vulnerability-watch.sqlite3",
    "automatic.sqlite3",
    "vulnerability-ai.sqlite3",
)
MERGE_DATABASES = {"reports.sqlite3": "reports", "baselines.sqlite3": "baselines"}
# Fixed ReportStore receipt contract, kept local so offline transfer needs only the stdlib.
RECEIPT_TABLE = "handoff_receipts"
RECEIPT_DDL = (
    "CREATE TABLE handoff_receipts ("
    " id TEXT PRIMARY KEY NOT NULL, report_id TEXT NOT NULL REFERENCES reports(id),"
    " job_id TEXT NOT NULL, finished_at TEXT NOT NULL, payload TEXT NOT NULL )",
    "CREATE INDEX handoff_receipts_scope ON handoff_receipts"
    "(report_id, job_id, finished_at DESC, id DESC)",
)
RECEIPT_CATALOG = [
    ("index", "handoff_receipts_scope", RECEIPT_TABLE, RECEIPT_DDL[1]),
    ("table", RECEIPT_TABLE, RECEIPT_TABLE, RECEIPT_DDL[0]),
]
RECEIPT_IDS = {
    "id": r"br-[0-9a-f]{32}",
    "report_id": r"[A-Za-z0-9_-]{1,80}",
    "host_id": r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}",
    "job_id": r"[0-9a-f]{32}",
    "host_scope": r"[0-9a-f]{64}",
    "approval_digest": r"[0-9a-f]{64}",
    "profile_digest": r"[0-9a-f]{64}",
}
RECEIPT_FIELDS = (*RECEIPT_IDS, "started_at", "finished_at", "checks")
RECEIPT_STATES = {"passed", "failed", "inconclusive", "uncovered"}
ACTION_INTENTS = "action_handoff_recheck_intents_v1"
ACTION_RESULTS = "action_handoff_recheck_results_v1"
ACTION_INDEX = "action_handoff_recheck_binding_v1"
ACTION_ORIGINAL_INDEX = "action_handoff_recheck_original_v1"
ACTION_ORIGINAL_INDEX_DDL = (
    "CREATE INDEX action_handoff_recheck_original_v1 ON action_handoff_recheck_intents_v1"
    " (report_id, kind, plan_id, started_at DESC, sequence DESC)"
)
ACTION_DDL = (
    "CREATE TABLE action_handoff_recheck_intents_v1 ("
    " sequence INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,"
    " report_id TEXT NOT NULL REFERENCES reports(id),"
    " kind TEXT NOT NULL CHECK (kind IN ('nginx', 'container_restart')),"
    " plan_id TEXT NOT NULL, binding_sha256 TEXT NOT NULL, binding_json TEXT NOT NULL,"
    " started_at TEXT NOT NULL )",
    "CREATE INDEX action_handoff_recheck_binding_v1 ON action_handoff_recheck_intents_v1"
    " (report_id, kind, plan_id, binding_sha256, started_at DESC, sequence DESC)",
    "CREATE TABLE action_handoff_recheck_results_v1 ("
    " id TEXT PRIMARY KEY NOT NULL REFERENCES action_handoff_recheck_intents_v1(id),"
    " finished_at TEXT NOT NULL, result_sha256 TEXT NOT NULL, result_json TEXT NOT NULL )",
    ACTION_ORIGINAL_INDEX_DDL,
)
LEGACY_ACTION_CATALOG = [
    ("index", ACTION_INDEX, ACTION_INTENTS, ACTION_DDL[1]),
    ("table", ACTION_INTENTS, ACTION_INTENTS, ACTION_DDL[0]),
    ("table", ACTION_RESULTS, ACTION_RESULTS, ACTION_DDL[2]),
]
ACTION_CATALOG = [
    LEGACY_ACTION_CATALOG[0],
    ("index", ACTION_ORIGINAL_INDEX, ACTION_INTENTS, ACTION_ORIGINAL_INDEX_DDL),
    *LEGACY_ACTION_CATALOG[1:],
]
ACTION_BINDING_FIELDS = (
    "report_id",
    "kind",
    "plan_id",
    "host_id",
    "host_scope",
    "target_scope",
    "approval_digest",
    "execution_digest",
    "profile_digest",
    "configured_checks",
    "execution_at",
)
ACTION_DIGEST = r"[0-9a-f]{64}"
GENERATION_TABLE = "compose_generation_witnesses_v1"
GENERATION_DDL = (
    "CREATE TABLE compose_generation_witnesses_v1 ("
    " id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id) ON DELETE CASCADE,"
    " host_id TEXT NOT NULL, report_scope TEXT NOT NULL,"
    " observed_at TEXT NOT NULL, witness_sha256 TEXT NOT NULL, witness_json TEXT NOT NULL )"
)
GENERATION_CATALOG = [("table", GENERATION_TABLE, GENERATION_TABLE, GENERATION_DDL)]
GENERATION_FIELDS = (
    "binding",
    "key_epoch",
    "container",
    "image",
    "configuration",
    "compose_version",
)
ACCESS_PROFILES = "access_recheck_profiles_v1"
ACCESS_RECHECKS = "access_rechecks_v1"
ACCESS_INDEX = "access_rechecks_report_v1"
ACCESS_DDL = (
    "CREATE TABLE access_recheck_profiles_v1 ("
    " report_id TEXT PRIMARY KEY NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, profile_sha256 TEXT NOT NULL )",
    "CREATE TABLE access_rechecks_v1 ("
    " id TEXT PRIMARY KEY NOT NULL,"
    " report_id TEXT NOT NULL REFERENCES access_recheck_profiles_v1(report_id),"
    " finished_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL, payload TEXT NOT NULL )",
    "CREATE INDEX access_rechecks_report_v1 ON access_rechecks_v1"
    " (report_id, finished_at DESC, id DESC)",
)
ACCESS_CATALOG = [
    ("index", ACCESS_INDEX, ACCESS_RECHECKS, ACCESS_DDL[2]),
    ("table", ACCESS_PROFILES, ACCESS_PROFILES, ACCESS_DDL[0]),
    ("table", ACCESS_RECHECKS, ACCESS_RECHECKS, ACCESS_DDL[1]),
]
ACCESS_FIELDS = ("id", "report_id", "finished_at", "management", "external", "checks", "status")
CONTAINER_PROFILES = "container_recheck_profiles_v1"
CONTAINER_RECHECKS = "container_rechecks_v1"
CONTAINER_INDEX = "container_rechecks_report_v1"
CONTAINER_DDL = (
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
CONTAINER_CATALOG = [
    ("index", CONTAINER_INDEX, CONTAINER_RECHECKS, CONTAINER_DDL[2]),
    ("table", CONTAINER_PROFILES, CONTAINER_PROFILES, CONTAINER_DDL[0]),
    ("table", CONTAINER_RECHECKS, CONTAINER_RECHECKS, CONTAINER_DDL[1]),
]
CONTAINER_FIELDS = ("id", "report_id", "finished_at", "management", "checks", "status")
CHANGE_TABLE = "report_change_records_v1"
CHANGE_INDEX = "report_change_records_report_v1"
CHANGE_DDL = (
    "CREATE TABLE report_change_records_v1 ("
    " id TEXT PRIMARY KEY NOT NULL, report_id TEXT NOT NULL REFERENCES reports(id),"
    " host_scope TEXT NOT NULL, request_id TEXT NOT NULL, recorded_at TEXT NOT NULL,"
    " payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, UNIQUE(report_id, request_id) )",
    "CREATE INDEX report_change_records_report_v1 ON report_change_records_v1"
    " (report_id, recorded_at DESC, id DESC)",
)
CHANGE_CATALOG = [
    ("index", CHANGE_INDEX, CHANGE_TABLE, CHANGE_DDL[1]),
    ("table", CHANGE_TABLE, CHANGE_TABLE, CHANGE_DDL[0]),
]
CHANGE_FIELDS = (
    "id",
    "report_id",
    "kind",
    "claimed_at",
    "recorded_at",
    "source",
    "host_scope",
    "request_id",
)
CHANGE_KINDS = {
    "nginx_configuration",
    "compose_configuration",
    "image_update",
    "application_configuration",
    "service_restart",
    "unknown",
}
# HostPublic defaults used by the product's scope projection, with descriptive fields omitted.
ACTION_HOST_DEFAULTS = {
    "port": 22,
    "username": "opsark-readonly",
    "site_domain": "shop.example.com",
    "container_name": "api",
    "expected_upstream_port": 8081,
    "source": "replay",
    "health_checks": [],
    "nginx_config_path": None,
    "trusted_hosts_digest": None,
    "disk_reclaim_scope_digest": None,
}
ACTION_HEALTH_DEFAULTS = {
    "port": 80,
    "path": "/healthz",
    "expected_status": 200,
    "expected_body": "",
    "read_only_confirmed": False,
}
LEASE_TABLES = {
    "security.sqlite3": "monitor_lease",
    "web-security.sqlite3": "monitor_lease",
    "patches.sqlite3": "patch_monitor_lease",
}
EXTRA_LEASE_TABLES = (("patches.sqlite3", "service_activation_monitor"),)
MAX_DATABASE_BYTES = 268_435_456
MAX_TOTAL_BYTES = 536_870_912
MAX_ROWS = 200_000
MAX_TABLES = 64
MAX_SUMMARIES = 1000
MAX_CELL_BYTES = 4_194_304
TIME_BUDGET = 30
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
STATUSES = {
    "open",
    "acknowledged",
    "verified",
    "queued",
    "preflight",
    "downloading",
    "applying",
    "verifying",
    "awaiting_transport_verification",
    "running_overdue",
    "rejected",
    "failed",
    "unknown",
    "installed_restart_pending",
    "reboot_pending",
    "verification_failed",
}


class TransferError(ValueError):
    """A transfer was refused; no existing destination or source was replaced."""


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode()


def _plain_path(value):
    path = Path(value)
    if ".." in path.parts:
        raise TransferError("Parent traversal is not accepted")
    path = path.absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise TransferError("Linked paths are not accepted")
    return path


def _directory(value, *, private=False):
    path = _plain_path(value)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise TransferError("An ordinary directory is required")
    if (
        private
        and os.name == "posix"
        and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077)
    ):
        raise TransferError("The output directory must be private and controller-owned")
    return path


def _new_directory(value, sources=()):
    path = _plain_path(value)
    for source in sources:
        if path == source or path.is_relative_to(source) or source.is_relative_to(path):
            raise TransferError("Source and output directory trees must be separate")
    if path.exists():
        _directory(path, private=True)
        if any(path.iterdir()):
            raise TransferError("Output directory must be empty; existing files are never replaced")
    else:
        _directory(path.parent)
        path.mkdir(mode=0o700)
        path.chmod(0o700)
    return path


def _file(path, *, private=False, limit=MAX_DATABASE_BYTES):
    _plain_path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
        raise TransferError("An ordinary, single-link bounded store file is required")
    if os.name == "posix":
        if metadata.st_mode & 0o022:
            raise TransferError("Store files cannot be writable by other users")
        if private and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
            raise TransferError("Snapshot files must be private and controller-owned")
    return metadata


def _approved_files(directory):
    files = []
    total = 0
    for name in DATABASES:
        path = directory / name
        if not path.exists() and not path.is_symlink():
            continue
        total += _file(path).st_size
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                total += _file(sidecar).st_size
        if total > MAX_TOTAL_BYTES:
            raise TransferError("Store transfer byte budget exceeded")
        files.append(path)
    return files


def _connection(path, *, writable=False, deadline=None, immutable=False):
    mode = "rw" if writable else "ro"
    suffix = "&immutable=1" if immutable else ""
    connection = sqlite3.connect(f"{path.as_uri()}?mode={mode}{suffix}", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA foreign_keys=ON")
    if not writable:
        connection.execute("PRAGMA query_only=ON")
    if deadline is not None:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    return connection


def _integrity(connection):
    if [row[0] for row in connection.execute("PRAGMA quick_check")] != ["ok"]:
        raise TransferError("SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise TransferError("SQLite foreign-key check failed")


def _quoted(name):
    if not NAME.fullmatch(name):
        raise TransferError("Unsupported SQLite object name")
    return '"' + name + '"'


def _catalog(connection):
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name"
    ).fetchall()
    tables = [row["name"] for row in rows if row["type"] == "table"]
    if len(tables) > MAX_TABLES or any(not NAME.fullmatch(name) for name in tables):
        raise TransferError("SQLite table budget or name contract exceeded")
    if any(
        row["type"] == "table" and "CREATE VIRTUAL" in (row["sql"] or "").upper() for row in rows
    ):
        raise TransferError("Virtual tables are outside the transfer contract")
    return rows, tables


def _columns(connection, table):
    return [tuple(row) for row in connection.execute("PRAGMA table_xinfo(" + _quoted(table) + ")")]


def _rows(connection, table):
    columns = _columns(connection, table)
    keys = [column[1] for column in sorted(columns, key=lambda c: c[5]) if column[5]]
    ordering = ",".join(_quoted(key) for key in keys) if keys else "rowid"
    query = "SELECT * FROM " + _quoted(table) + " ORDER BY " + ordering  # noqa: S608 -- quoted identifiers
    cursor = connection.execute(query)
    for index, row in enumerate(cursor):
        if index >= MAX_ROWS:
            raise TransferError("SQLite row budget exceeded")
        yield row


def _cell(value):
    if isinstance(value, bytes):
        if len(value) > MAX_CELL_BYTES:
            raise TransferError("SQLite cell budget exceeded")
        return {"blob": base64.b64encode(value).decode()}
    if isinstance(value, str) and len(value.encode()) > MAX_CELL_BYTES:
        raise TransferError("SQLite cell budget exceeded")
    return value


def _safe_identifier(value):
    text = str(value)
    return (
        text if SAFE_ID.fullmatch(text) else "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    )


def _strict_json(value):
    if (
        not isinstance(value, str | bytes)
        or len(value if isinstance(value, bytes) else value.encode()) > MAX_CELL_BYTES
    ):
        raise TransferError("Evidence JSON exceeds its type or size contract")

    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise TransferError("Duplicate evidence JSON field")
            result[key] = item
        return result

    def invalid(_value):
        raise TransferError("Non-finite evidence JSON")

    return json.loads(value, object_pairs_hook=unique, parse_constant=invalid)


def _summary(row, table):
    if table not in {"alerts", "patch_jobs"}:
        return None
    keys = set(row.keys())
    payload = _strict_json(row["payload"]) if "payload" in keys else {}
    if not isinstance(payload, dict):
        raise TransferError("Alert/job evidence must be an object")
    identifier = row["id"] if table == "alerts" else row["job_id"]
    result = {"id": _safe_identifier(identifier)}
    if "host_id" in keys:
        result["host_id"] = _safe_identifier(row["host_id"])
    state = row["status"] if "status" in keys else payload.get("status")
    result["status"] = state if isinstance(state, str) and state in STATUSES else "unrecognized"
    for key in ("notification_count", "revision"):
        value = row[key] if key in keys else payload.get(key)
        if type(value) is int and 0 <= value <= 2**63 - 1:
            result[key] = value
    return result


def _hash_file(path):
    before = _file(path)
    with path.open("rb") as handle:
        result = hashlib.file_digest(handle, "sha256").hexdigest()
    after = _file(path)
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise TransferError("Snapshot changed while hashing")
    return result


def _describe(path, *, immutable=False):
    deadline = time.monotonic() + TIME_BUDGET
    with closing(_connection(path, deadline=deadline, immutable=immutable)) as connection:
        _integrity(connection)
        catalog, tables = _catalog(connection)
        if GENERATION_TABLE in tables:
            _generation_catalog(catalog)
        _access_catalog(catalog)
        if _container_catalog(catalog):
            _container_count(connection)
        if _change_catalog(catalog):
            _change_count(connection)
        result = {
            "size": _file(path).st_size,
            "tables": {},
            "schema_sha256": hashlib.sha256(_canonical([tuple(r) for r in catalog])).hexdigest(),
        }
        for table in tables:
            hasher = hashlib.sha256()
            summaries = []
            count = 0
            for row in _rows(connection, table):
                if table == GENERATION_TABLE:
                    _generation_witness(connection, row)
                elif table == ACCESS_PROFILES:
                    _access_profile(connection, row)
                elif table == ACCESS_RECHECKS:
                    _access_recheck(connection, row)
                elif table == CONTAINER_PROFILES:
                    _container_profile(connection, row)
                elif table == CONTAINER_RECHECKS:
                    _container_recheck(connection, row)
                elif table == CHANGE_TABLE:
                    _change_record(connection, row)
                hasher.update(_canonical([_cell(value) for value in row]) + b"\n")
                count += 1
                if table in {"alerts", "patch_jobs"} and len(summaries) < MAX_SUMMARIES:
                    summaries.append(_summary(row, table))
            result["tables"][table] = {"rows": count, "rows_sha256": hasher.hexdigest()}
            if table in {"alerts", "patch_jobs"}:
                result["tables"][table].update(
                    summaries=summaries, summaries_truncated=count > len(summaries)
                )
    result["sha256"] = _hash_file(path)
    return result


def _stage(directory, name):
    path = directory / ("." + name + "." + secrets.token_hex(12) + ".stage")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    path.chmod(0o600)
    return path


def _cleanup(stage):
    for path in (stage, *(Path(str(stage) + suffix) for suffix in ("-wal", "-shm", "-journal"))):
        if path.exists() or path.is_symlink():
            _file(path, private=True)
            path.unlink()


def _backup(source, stage, *, immutable=False):
    _file(source)
    deadline = time.monotonic() + TIME_BUDGET
    with (
        closing(_connection(source, deadline=deadline, immutable=immutable)) as original,
        closing(_connection(stage, writable=True, deadline=deadline)) as target,
    ):
        _integrity(original)
        page_size = original.execute("PRAGMA page_size").fetchone()[0]

        def progress(_status, _remaining, total):
            if time.monotonic() >= deadline or total * page_size > MAX_DATABASE_BYTES:
                raise TransferError("SQLite backup budget exceeded")

        original.backup(target, pages=64, progress=progress, sleep=0.01)
        # A transport snapshot is standalone; the app may select WAL after activation.
        target.execute("PRAGMA journal_mode=DELETE")
        _integrity(target)
    _file(stage, private=True)


def _manifest(directory, operation, *, status="complete", **extra):
    files = _approved_files(directory)
    if not files:
        raise TransferError("No approved stores were found")
    return {
        "schema_version": 1,
        "operation": operation,
        "status": status,
        "created_at": datetime.now(UTC).isoformat(),
        "databases": {path.name: _describe(path) for path in files},
        **extra,
    }


def _write_manifest(directory, value):
    target = directory / "manifest.json"
    if target.exists() or target.is_symlink():
        _file(target, private=True, limit=4_194_304)
    temporary = _stage(directory, "manifest.json")
    try:
        with temporary.open("wb") as handle:
            handle.write(_canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            _cleanup(temporary)


def _store_file_identity(info):
    # On Windows, lstat and fstat can report different ctime for the same file.
    timestamp = (
        getattr(info, "st_birthtime_ns", info.st_ctime_ns) if os.name == "nt" else info.st_ctime_ns
    )
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, timestamp


def _quiescent_source_identity(files):
    identity = {}
    for database in files:
        journal = database.with_name(database.name + "-journal")
        try:
            journal.lstat()
        except FileNotFoundError:
            pass
        else:
            raise TransferError("Cold snapshot refuses a SQLite rollback journal")
        for suffix in ("", "-wal", "-shm"):
            path = database.with_name(database.name + suffix)
            try:
                info = _file(path)
            except FileNotFoundError:
                if not suffix:
                    raise
                continue
            identity[path] = _store_file_identity(info)
    return identity


def _copy_quiescent_store_file(source, destination, identity):
    info = _file(source)
    if _store_file_identity(info) != identity:
        raise TransferError("Cold snapshot source metadata changed")
    with source.open("rb") as original, destination.open("xb") as copy:
        if _store_file_identity(os.fstat(original.fileno())) != identity:
            raise TransferError("Cold snapshot source metadata changed")
        remaining = info.st_size
        while remaining:
            chunk = original.read(min(remaining, 65536))
            if not chunk:
                raise TransferError("Cold snapshot source size changed")
            copy.write(chunk)
            remaining -= len(chunk)
        if original.read(1) or _store_file_identity(os.fstat(original.fileno())) != identity:
            raise TransferError("Cold snapshot source metadata changed")
    destination.chmod(0o600)


def _backup_quiescent(source, stage, identity):
    wal = source.with_name(source.name + "-wal")
    if wal not in identity or identity[wal][2] == 0:
        _backup(source, stage, immutable=True)
        return
    # Use normal WAL processing on a private copy. Immutable open can miss
    # committed frames on Windows, and normal open can write the WAL index.
    with TemporaryDirectory(prefix=".cold-wal-", dir=stage.parent) as temporary:
        folder = Path(temporary)
        local_source = folder / source.name
        _copy_quiescent_store_file(source, local_source, identity[source])
        _copy_quiescent_store_file(wal, folder / wal.name, identity[wal])
        _backup(local_source, stage)


def snapshot(source_dir, destination_dir, *, confirm_quiescent: bool = False):
    """Use SQLite Backup with locking unless the operator confirms a cold source."""
    if not isinstance(confirm_quiescent, bool):
        raise TransferError("Quiescence confirmation must be a boolean")
    source = _directory(source_dir)
    files = _approved_files(source)
    if not files:
        raise TransferError("No approved stores were found")
    if confirm_quiescent and sqlite3.sqlite_version_info < (3, 22, 0):
        raise TransferError("Cold snapshot requires SQLite 3.22.0 or newer")
    original_identity = _quiescent_source_identity(files) if confirm_quiescent else None
    output = _new_directory(destination_dir, (source,))
    published = []
    try:
        with TemporaryDirectory(prefix=".snapshot-", dir=output) as temporary:
            staging = Path(temporary)
            for original in files:
                stage = _stage(staging, original.name)
                if original_identity is not None:
                    _backup_quiescent(original, stage, original_identity)
                else:
                    _backup(original, stage)
                os.replace(stage, staging / original.name)
            if original_identity is not None and original_identity != _quiescent_source_identity(
                _approved_files(source)
            ):
                raise TransferError("Cold snapshot source metadata changed")
            result = _manifest(staging, "snapshot")
            _write_manifest(staging, result)
            for name in (*(path.name for path in files), "manifest.json"):
                staged, target = staging / name, output / name
                identity = staged.lstat()
                os.link(staged, target)
                published.append((target, identity))
                staged.unlink()
        return result
    except BaseException:
        for target, identity in reversed(published):
            try:
                if os.path.samestat(target.lstat(), identity):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise


_SNAPSHOT_OPERATIONS = {"snapshot", "clear_monitor_leases", "rehearse"}


def _require_snapshot_files(directory, databases):
    expected = {*databases, "manifest.json"}
    names = set()
    for path in directory.iterdir():
        if path.name not in expected:
            raise TransferError("Unexpected file in offline snapshot")
        names.add(path.name)
    if names != expected:
        raise TransferError("Offline snapshot is missing a manifested store")


def _read_snapshot_manifest(path, *, complete):
    _file(path, private=True, limit=MAX_CELL_BYTES)
    try:
        manifest = _strict_json(path.read_bytes())
        if not isinstance(manifest, dict):
            raise TransferError("Invalid snapshot manifest")
        operation = manifest.get("operation")
        databases = manifest.get("databases")
        fields = {"schema_version", "operation", "status", "created_at", "databases"}
        operations = (
            _SNAPSHOT_OPERATIONS if complete else _SNAPSHOT_OPERATIONS | {"merge_reports_baselines"}
        )
        if (
            not isinstance(operation, str)
            or operation not in operations
            or not isinstance(databases, dict)
            or not databases
            or not set(databases) <= set(DATABASES)
            or (complete or operation == "rehearse")
            and set(databases) != set(DATABASES)
            or operation == "merge_reports_baselines"
            and not set(databases) <= set(MERGE_DATABASES)
        ):
            raise TransferError("Invalid snapshot database scope")
        if operation == "clear_monitor_leases":
            fields.add("cleared_lease_rows")
            cleared = manifest.get("cleared_lease_rows")
            if not isinstance(cleared, dict) or any(
                name not in LEASE_TABLES
                or name not in databases
                or type(count) is not int
                or count < 0
                for name, count in cleared.items()
            ):
                raise TransferError("Invalid snapshot lease summary")
        if (
            set(manifest) != fields
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["status"] != "complete"
            or datetime.fromisoformat(manifest["created_at"]).utcoffset() is None
        ):
            raise TransferError("Invalid or unsupported snapshot manifest")
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise TransferError("Invalid or unsupported snapshot manifest") from error
    return manifest


def _inspect_snapshot(directory, *, complete=True):
    manifest_path = directory / "manifest.json"
    _file(manifest_path, private=True, limit=MAX_CELL_BYTES)
    manifest_digest = _hash_file(manifest_path)
    manifest = _read_snapshot_manifest(manifest_path, complete=complete)
    databases = manifest["databases"]
    _require_snapshot_files(directory, databases)
    size = 0
    checked = {}
    for name, expected in databases.items():
        path = directory / name
        metadata = _file(path, private=True)
        size += metadata.st_size
        if size > MAX_TOTAL_BYTES:
            raise TransferError("Store transfer byte budget exceeded")
        # Immutable SQLite reads do not create sidecars. A live WAL-mode file is not a
        # standalone snapshot, even if the sidecar was omitted during copying.
        with path.open("rb") as handle:
            header = handle.read(20)
        if not header.startswith(b"SQLite format 3\x00") or header[18:20] != b"\x01\x01":
            raise TransferError("Snapshot stores must be standalone SQLite files")
        if not isinstance(expected, dict) or expected.get("sha256") != _hash_file(path):
            raise TransferError("Snapshot file does not match its manifest digest")
        try:
            described = _describe(path, immutable=True)
        except sqlite3.Error as error:
            raise TransferError("Snapshot SQLite integrity or schema check failed") from error
        if _canonical(described) != _canonical(expected):
            raise TransferError("Snapshot schema or rows do not match the manifest")
        checked[path] = (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    _require_snapshot_files(directory, databases)
    for path, expected_metadata in checked.items():
        metadata = _file(path, private=True)
        if (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != expected_metadata:
            raise TransferError("Snapshot store changed while verifying")
    if _hash_file(manifest_path) != manifest_digest:
        raise TransferError("Snapshot manifest changed while verifying")
    return manifest


def _rehearsal_summary(operation, manifest):
    return {
        "operation": operation,
        "status": "complete",
        "database_count": len(DATABASES),
        "databases": {
            name: {
                "sha256": info["sha256"],
                "size": info["size"],
                "table_count": len(info["tables"]),
                "row_count": sum(table["rows"] for table in info["tables"].values()),
            }
            for name, info in manifest["databases"].items()
        },
    }


def verify_snapshot(directory):
    """Verify a private, complete, offline snapshot without writing any file."""
    return _rehearsal_summary("verify", _inspect_snapshot(_directory(directory, private=True)))


def rehearse(source_dir, destination_dir):
    """Prepare an independent offline rehearsal copy and publish its manifest last."""
    source = _directory(source_dir, private=True)
    original = _inspect_snapshot(source)
    output = _new_directory(destination_dir, (source,))
    published = []
    try:
        with TemporaryDirectory(prefix=".rehearse-", dir=output) as temporary:
            stage = Path(temporary)
            prepared = snapshot(source, stage)
            if original != _inspect_snapshot(source):
                raise TransferError("Snapshot source changed during rehearsal")
            for name in DATABASES:
                for field in ("tables", "schema_sha256"):
                    if prepared["databases"][name][field] != original["databases"][name][field]:
                        raise TransferError("Rehearsal copy differs from the verified source")
            prepared["operation"] = "rehearse"
            _write_manifest(stage, prepared)
            prepared = _inspect_snapshot(stage)
            for name in (*DATABASES, "manifest.json"):
                target = output / name
                # A same-volume link from the *independent staged copy* fails if the
                # destination exists. Drop the temporary link immediately after publishing.
                os.link(stage / name, target)
                published.append(target)
                (stage / name).unlink()
        return _rehearsal_summary("rehearse", prepared)
    except BaseException:
        for target in reversed(published):
            target.unlink(missing_ok=True)
        raise


def _schema(connection, table):
    catalog, tables = _catalog(connection)
    adjunct = set(tables) - {table}
    with_receipts = table == "reports" and RECEIPT_TABLE in adjunct
    with_actions = table == "reports" and {ACTION_INTENTS, ACTION_RESULTS} <= adjunct
    with_generation = table == "reports" and GENERATION_TABLE in adjunct
    with_access = _access_catalog(catalog)
    with_container = _container_catalog(catalog)
    with_changes = _change_catalog(catalog)
    action_schema = None
    allowed = {table}
    if with_receipts:
        allowed.add(RECEIPT_TABLE)
    if with_actions:
        allowed.update((ACTION_INTENTS, ACTION_RESULTS))
    if with_generation:
        allowed.add(GENERATION_TABLE)
    if table == "reports" and with_access:
        allowed.update((ACCESS_PROFILES, ACCESS_RECHECKS))
    if table == "reports" and with_container:
        allowed.update((CONTAINER_PROFILES, CONTAINER_RECHECKS))
    if table == "reports" and with_changes:
        allowed.add(CHANGE_TABLE)
    if set(tables) != allowed or any(row["type"] not in {"table", "index"} for row in catalog):
        raise TransferError("Merge accepts only the declared report/baseline schema")
    if with_receipts:
        received = [
            (row["type"], row["name"], row["tbl_name"], " ".join((row["sql"] or "").split()))
            for row in catalog
            if row["tbl_name"] == RECEIPT_TABLE
        ]
        if received != RECEIPT_CATALOG:
            raise TransferError("Business handoff receipt schema differs")
        catalog = [row for row in catalog if row["tbl_name"] != RECEIPT_TABLE]
    if with_actions:
        received = [
            (row["type"], row["name"], row["tbl_name"], " ".join((row["sql"] or "").split()))
            for row in catalog
            if row["tbl_name"] in {ACTION_INTENTS, ACTION_RESULTS}
        ]
        if received == ACTION_CATALOG:
            action_schema = "current"
        elif received == LEGACY_ACTION_CATALOG:
            action_schema = "legacy"
        else:
            raise TransferError("Action recheck receipt schema differs")
        catalog = [
            row for row in catalog if row["tbl_name"] not in {ACTION_INTENTS, ACTION_RESULTS}
        ]
    if with_generation:
        _generation_catalog(catalog)
        catalog = [row for row in catalog if row["tbl_name"] != GENERATION_TABLE]
    if with_access:
        catalog = [
            row for row in catalog if row["tbl_name"] not in {ACCESS_PROFILES, ACCESS_RECHECKS}
        ]
    if with_container:
        catalog = [
            row
            for row in catalog
            if row["tbl_name"] not in {CONTAINER_PROFILES, CONTAINER_RECHECKS}
        ]
    if with_changes:
        catalog = [row for row in catalog if row["tbl_name"] != CHANGE_TABLE]
    columns = _columns(connection, table)
    names = [column[1] for column in columns]
    if (
        "id" not in names
        or "payload" not in names
        or not next(c for c in columns if c[1] == "id")[5]
    ):
        raise TransferError("Merge schema lacks the expected primary ID or payload")
    return (
        (columns, [tuple(row) for row in catalog]),
        with_receipts,
        action_schema,
        with_generation,
        with_access,
        with_changes,
        with_container,
    )


def _receipt_time(value):
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None or value != parsed.isoformat().replace("+00:00", "Z"):
        raise ValueError
    return parsed


def _receipt_row(row):
    """Validate the fixed canonical receipt independently of application dependencies."""
    try:
        document = row["payload"]
        if not isinstance(document, str) or len(document) > 4096:
            raise ValueError
        payload = _strict_json(document)
        if (
            not isinstance(payload, dict)
            or tuple(payload) != RECEIPT_FIELDS
            or any(
                not isinstance(payload[field], str) or not re.fullmatch(pattern, payload[field])
                for field, pattern in RECEIPT_IDS.items()
            )
            or document != json.dumps(payload, separators=(",", ":"))
        ):
            raise ValueError
        checks = payload["checks"]
        started = _receipt_time(payload["started_at"])
        finished = _receipt_time(payload["finished_at"])
        if (
            started > finished
            or not isinstance(checks, list)
            or not 1 <= len(checks) <= 3
            or any(not isinstance(check, str) or check not in RECEIPT_STATES for check in checks)
            or any(row[field] != payload[field] for field in ("id", "report_id", "job_id"))
            or row["finished_at"] != finished.astimezone(UTC).isoformat(timespec="microseconds")
        ):
            raise ValueError
    except (ValueError, OverflowError, RecursionError):
        raise TransferError("Invalid business handoff receipt") from None


def _action_document(raw, digest, fields):
    if not isinstance(raw, str) or not 0 < len(raw) <= 4096:
        raise ValueError
    value = _strict_json(raw)
    if (
        not isinstance(value, dict)
        or tuple(value) != fields
        or raw != json.dumps(value, separators=(",", ":"))
        or hashlib.sha256(raw.encode()).hexdigest() != digest
    ):
        raise ValueError
    return value


def _action_instant(value, *, storage=False):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError
    instant = datetime.fromisoformat(value)
    canonical = (
        instant.isoformat(timespec="microseconds")
        if storage
        else instant.isoformat().replace("+00:00", "Z")
    )
    if instant.utcoffset() != timedelta(0) or canonical != value:
        raise ValueError
    return instant


def _action_host_scopes(raw, host_id, *, diagnostic_only=False):
    if not isinstance(raw, str) or len(raw) > 16384:
        raise ValueError
    host = _strict_json(raw)
    if (
        not isinstance(host, dict)
        or set(host)
        - (ACTION_HOST_DEFAULTS.keys() | {"id", "name", "address", "web_profile_digest"})
        or host["id"] != host_id
        or not isinstance(host["name"], str)
    ):
        raise ValueError
    values = ACTION_HOST_DEFAULTS | {
        key: value for key, value in host.items() if key not in {"name", "web_profile_digest"}
    }
    if values["source"] != "ssh":
        raise ValueError
    address, domain = values["address"], values["site_domain"]
    if not isinstance(address, str) or not isinstance(domain, str):
        raise ValueError
    try:
        values["address"] = str(ipaddress.ip_address(address))
    except ValueError:
        values["address"] = address.lower().rstrip(".")
    values["site_domain"] = domain.lower().rstrip(".")
    checks = values["health_checks"]
    if not isinstance(checks, list) or len(checks) > 3:
        raise ValueError
    for check in checks:
        if not isinstance(check, dict) or set(check) - (
            ACTION_HEALTH_DEFAULTS.keys() | {"id", "domain"}
        ):
            raise ValueError
    values["health_checks"] = sorted(
        [
            ACTION_HEALTH_DEFAULTS | check | {"domain": check["domain"].lower().rstrip(".")}
            for check in checks
        ],
        key=lambda check: check["id"],
    )
    disk_scope = values.pop("disk_reclaim_scope_digest")
    management = hashlib.sha256(_canonical(values)).hexdigest()
    diagnostic = management
    if disk_scope is not None:
        if not isinstance(disk_scope, str) or not re.fullmatch(ACTION_DIGEST, disk_scope):
            raise ValueError
        diagnostic = hashlib.sha256(
            _canonical(values | {"disk_reclaim_scope_digest": disk_scope})
        ).hexdigest()
    return {diagnostic} if diagnostic_only else {management, diagnostic}


def _action_intent(db, row):
    try:
        binding = _action_document(
            row["binding_json"], row["binding_sha256"], ACTION_BINDING_FIELDS
        )
        if (
            not re.fullmatch(r"ar-[0-9a-f]{32}", row["id"])
            or not re.fullmatch(RECEIPT_IDS["report_id"], binding["report_id"])
            or not re.fullmatch(RECEIPT_IDS["host_id"], binding["host_id"])
            or not re.fullmatch(r"[0-9a-f]{32}", binding["plan_id"])
            or binding["kind"] not in {"nginx", "container_restart"}
            or any(
                not re.fullmatch(ACTION_DIGEST, binding[field])
                for field in ACTION_BINDING_FIELDS[4:9]
            )
            or type(binding["configured_checks"]) is not int
            or not 1 <= binding["configured_checks"] <= 3
            or any(row[field] != binding[field] for field in ("report_id", "kind", "plan_id"))
            or type(row["sequence"]) is not int
            or row["sequence"] <= 0
        ):
            raise ValueError
        started = _action_instant(row["started_at"], storage=True)
        executed = _action_instant(binding["execution_at"])
        report = db.execute(
            "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
            "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
            "json_extract(payload,'$.scope_hash') AS scope,"
            "json_extract(payload,'$.target') AS target,"
            "json_type(payload,'$.target') AS target_type "
            "FROM reports WHERE id=?",
            (binding["report_id"],),
        ).fetchone()
        if (
            report is None
            or report["payload_id"] != binding["report_id"]
            or report["source"] != "ssh"
            or report["host"] != binding["host_id"]
            or not re.fullmatch(ACTION_DIGEST, report["scope"])
            or not datetime.fromisoformat(report["created_at"]) < executed < started
        ):
            raise ValueError
        if report["target_type"] in {None, "null"}:
            if report["scope"] != binding["host_scope"]:
                raise ValueError
        elif report["target_type"] != "object" or not {
            report["scope"],
            binding["host_scope"],
        } <= _action_host_scopes(report["target"], binding["host_id"]):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid action recheck intent") from None


def _action_result(db, row):
    try:
        result = _action_document(
            row["result_json"], row["result_sha256"], ("finished_at", "checks")
        )
        intent = db.execute(
            "SELECT started_at,"
            "json_extract(binding_json,'$.configured_checks') AS configured_checks "
            "FROM action_handoff_recheck_intents_v1 WHERE id=?",
            (row["id"],),
        ).fetchone()
        if intent is None or not re.fullmatch(r"ar-[0-9a-f]{32}", row["id"]):
            raise ValueError
        started = _action_instant(intent["started_at"], storage=True)
        finished = _action_instant(result["finished_at"])
        if (
            finished != _action_instant(row["finished_at"], storage=True)
            or not timedelta(0) <= finished - started <= timedelta(seconds=120)
            or not isinstance(result["checks"], list)
            or len(result["checks"]) != 3
            or any(check not in {"passed", "failed", "uncovered"} for check in result["checks"])
            or any(
                check != "uncovered" for check in result["checks"][intent["configured_checks"] :]
            )
        ):
            raise ValueError
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise TransferError("Invalid action recheck result") from None


def _validate_action_rows(db):
    for table, validate in ((ACTION_INTENTS, _action_intent), (ACTION_RESULTS, _action_result)):
        for row in _rows(db, table):
            validate(db, row)


def _generation_catalog(catalog):
    received = [
        (row["type"], row["name"], row["tbl_name"], " ".join((row["sql"] or "").split()))
        for row in catalog
        if row["tbl_name"] == GENERATION_TABLE
    ]
    if received != GENERATION_CATALOG:
        raise TransferError("Compose generation witness schema differs")


def _access_catalog(catalog):
    names = {ACCESS_PROFILES, ACCESS_RECHECKS, ACCESS_INDEX}
    received = [
        (row["type"], row["name"], row["tbl_name"], " ".join((row["sql"] or "").split()))
        for row in catalog
        if row["name"] in names or row["tbl_name"] in names
    ]
    if received and received != ACCESS_CATALOG:
        raise TransferError("Access recheck schema differs")
    return bool(received)


def _container_catalog(catalog):
    names = {CONTAINER_PROFILES, CONTAINER_RECHECKS, CONTAINER_INDEX}
    received = [
        tuple(row)
        for row in catalog
        if row["name"].lower() in names or row["tbl_name"].lower() in names
    ]
    if received and received != CONTAINER_CATALOG:
        raise TransferError("Container recheck schema differs")
    return bool(received)


def _container_count(db):
    if (
        db.execute(
            "SELECT 1 FROM container_rechecks_v1 GROUP BY report_id HAVING COUNT(*)>20 LIMIT 1"
        ).fetchone()
        is not None
    ):
        raise TransferError("Container recheck count exceeds the per-report limit")


def _container_profile(db, row):
    try:
        report_id, scope, profile = tuple(row)
        if (
            not re.fullmatch(RECEIPT_IDS["report_id"], report_id)
            or not re.fullmatch(ACTION_DIGEST, scope)
            or not re.fullmatch(ACTION_DIGEST, profile)
        ):
            raise ValueError
        parent = db.execute(
            "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
            "json_extract(payload,'$.created_at') AS payload_time,"
            "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
            "json_extract(payload,'$.scenario') AS scenario,"
            "json_extract(payload,'$.scope_hash') AS scope,"
            "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
            (report_id,),
        ).fetchone()
        if (
            parent is None
            or parent["payload_id"] != report_id
            or parent["source"] != "ssh"
            or parent["scenario"] != "container_restart"
            or parent["scope"] != scope
            or not re.fullmatch(RECEIPT_IDS["host_id"], parent["host"])
            or type(parent["target"]) is not str
            or len(parent["target"]) > 16384
        ):
            raise ValueError
        target = _strict_json(parent["target"])
        created = datetime.fromisoformat(parent["created_at"])
        if (
            not re.fullmatch(ACTION_DIGEST, target.get("trusted_hosts_digest", ""))
            or scope
            not in _action_host_scopes(parent["target"], parent["host"], diagnostic_only=True)
            or created.utcoffset() != timedelta(0)
            or created != datetime.fromisoformat(parent["payload_time"])
        ):
            raise ValueError
        return created
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid container recheck profile") from None


def _container_recheck(db, row):
    try:
        raw, request = row["payload"], row["request_id"]
        if (
            type(raw) is not str
            or not 0 < len(raw) <= 1024
            or not re.fullmatch(r"[0-9a-f]{32}", request)
        ):
            raise ValueError
        content = raw.encode("utf-8")
        digest = hashlib.sha256(
            b"opsark-container-recheck/v1\0" + request.encode("ascii") + b"\0" + content
        )
        if digest.hexdigest() != row["payload_sha256"]:
            raise ValueError
        payload = _action_document(raw, hashlib.sha256(content).hexdigest(), CONTAINER_FIELDS)
        parent = db.execute(
            "SELECT report_id,host_scope,profile_sha256 FROM container_recheck_profiles_v1"
            " WHERE report_id=?",
            (row["report_id"],),
        ).fetchone()
        finished = _action_instant(payload["finished_at"])
        management, checks = payload["management"], payload["checks"]
        if (
            parent is None
            or not re.fullmatch(r"rr-[0-9a-f]{32}", payload["id"])
            or any(row[key] != payload[key] for key in ("id", "report_id"))
            or finished != _action_instant(row["finished_at"], storage=True)
            or finished <= _container_profile(db, parent)
            or management not in {"verified", "unavailable"}
            or type(checks) is not list
            or not 1 <= len(checks) <= 3
            or any(type(check) is not str or check not in RECEIPT_STATES for check in checks)
            or (management == "unavailable" and {"passed", "failed"}.intersection(checks))
        ):
            raise ValueError
        expected = "pending"
        if "failed" in checks:
            expected = "failed"
        elif management == "verified" and set(checks) == {"passed"}:
            expected = "passed"
        if payload["status"] != expected:
            raise ValueError
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid container recheck receipt") from None


def _change_catalog(catalog):
    names = {CHANGE_TABLE, CHANGE_INDEX}
    observed = [
        tuple(row)
        for row in catalog
        if row["name"].lower() in names or row["tbl_name"].lower() in names
    ]
    if observed and observed != CHANGE_CATALOG:
        raise TransferError("Change record schema differs")
    return bool(observed)


def _change_count(db):
    if (
        db.execute(
            "SELECT 1 FROM report_change_records_v1 GROUP BY report_id HAVING COUNT(*)>20 LIMIT 1"
        ).fetchone()
        is not None
    ):
        raise TransferError("Change record count exceeds the per-report limit")


def _change_record(db, row):
    try:
        payload = _action_document(row["payload"], row["payload_sha256"], CHANGE_FIELDS)
        claimed = payload["claimed_at"]
        recorded = _action_instant(payload["recorded_at"])
        report_id, scope = (payload[key] for key in ("report_id", "host_scope"))
        if (
            not re.fullmatch(r"cr-[0-9a-f]{32}", payload["id"])
            or not re.fullmatch(RECEIPT_IDS["report_id"], report_id)
            or not re.fullmatch(r"[0-9a-f]{32}", payload["request_id"])
            or not re.fullmatch(ACTION_DIGEST, scope)
            or payload["kind"] not in CHANGE_KINDS
            or payload["source"] != "operator_statement"
            or any(
                row[key] != payload[key] for key in ("id", "report_id", "host_scope", "request_id")
            )
            or recorded != _action_instant(row["recorded_at"], storage=True)
            or type(claimed) is not dict
            or tuple(claimed) != ("precision", "value")
        ):
            raise ValueError
        precision, value = claimed["precision"], claimed["value"]
        if precision == "date":
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
                raise ValueError
            datetime.strptime(value, "%Y-%m-%d")
        elif precision == "instant":
            if len(value) != 20 or _action_instant(value) > recorded:
                raise ValueError
        elif precision != "unknown" or value is not None:
            raise ValueError
        parent = db.execute(
            "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
            "json_extract(payload,'$.created_at') AS payload_time,"
            "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
            "json_extract(payload,'$.scope_hash') AS scope,"
            "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
            (report_id,),
        ).fetchone()
        if (
            parent is None
            or parent["payload_id"] != report_id
            or parent["source"] != "ssh"
            or parent["scope"] != scope
            or not re.fullmatch(RECEIPT_IDS["host_id"], parent["host"])
            or type(parent["target"]) is not str
            or len(parent["target"]) > 16384
        ):
            raise ValueError
        target = _strict_json(parent["target"])
        created = datetime.fromisoformat(parent["created_at"])
        if (
            not re.fullmatch(ACTION_DIGEST, target.get("trusted_hosts_digest", ""))
            or scope
            not in _action_host_scopes(parent["target"], parent["host"], diagnostic_only=True)
            or created.utcoffset() != timedelta(0)
            or created != datetime.fromisoformat(parent["payload_time"])
            or recorded < created
        ):
            raise ValueError
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid change record") from None


def _access_profile(db, row):
    try:
        report_id, scope, profile = tuple(row)
        if (
            not re.fullmatch(RECEIPT_IDS["report_id"], report_id)
            or not re.fullmatch(ACTION_DIGEST, scope)
            or not re.fullmatch(ACTION_DIGEST, profile)
        ):
            raise ValueError
        parent = db.execute(
            "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
            "json_extract(payload,'$.created_at') AS payload_time,"
            "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
            "json_extract(payload,'$.scope_hash') AS scope,"
            "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
            (report_id,),
        ).fetchone()
        if (
            parent is None
            or parent["payload_id"] != report_id
            or parent["source"] != "ssh"
            or parent["scope"] != scope
            or not re.fullmatch(RECEIPT_IDS["host_id"], parent["host"])
            or type(parent["target"]) is not str
            or len(parent["target"]) > 16384
        ):
            raise ValueError
        target = _strict_json(parent["target"])
        created = datetime.fromisoformat(parent["created_at"])
        captured = datetime.fromisoformat(parent["payload_time"])
        if (
            not re.fullmatch(ACTION_DIGEST, target.get("trusted_hosts_digest", ""))
            or scope not in _action_host_scopes(parent["target"], parent["host"])
            or created.utcoffset() != timedelta(0)
            or created != captured
        ):
            raise ValueError
        return created
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid access recheck profile") from None


def _access_recheck(db, row):
    try:
        payload = _action_document(row["payload"], row["payload_sha256"], ACCESS_FIELDS)
        parent = db.execute(
            "SELECT report_id,host_scope,profile_sha256 FROM access_recheck_profiles_v1"
            " WHERE report_id=?",
            (row["report_id"],),
        ).fetchone()
        finished = _action_instant(payload["finished_at"])
        management, external, checks = (
            payload[key] for key in ("management", "external", "checks")
        )
        if (
            parent is None
            or not re.fullmatch(r"ar-[0-9a-f]{32}", payload["id"])
            or any(row[key] != payload[key] for key in ("id", "report_id"))
            or finished != _action_instant(row["finished_at"], storage=True)
            or finished <= _access_profile(db, parent)
            or management not in {"verified", "unavailable"}
            or external not in {"matched", "unreachable", "unavailable"}
            or type(checks) is not list
            or not 1 <= len(checks) <= 3
        ):
            raise ValueError
        ids, states = set(), set()
        for check in checks:
            if (
                type(check) is not dict
                or tuple(check) != ("id", "status")
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", check["id"])
                or check["id"] in ids
                or check["status"] not in RECEIPT_STATES
            ):
                raise ValueError
            ids.add(check["id"])
            states.add(check["status"])
        if management == "unavailable" and "passed" in states:
            raise ValueError
        expected = "pending"
        if external == "unreachable" or "failed" in states:
            expected = "failed"
        elif management == "verified" and external == "matched" and states == {"passed"}:
            expected = "accepted"
        if payload["status"] != expected:
            raise ValueError
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise TransferError("Invalid access recheck result") from None


def _generation_witness(db, row):
    try:
        identifier, host, scope, observed, seal, payload = tuple(row)
        if (
            not re.fullmatch(RECEIPT_IDS["report_id"], identifier)
            or not re.fullmatch(RECEIPT_IDS["host_id"], host)
            or not re.fullmatch(ACTION_DIGEST, scope)
            or not re.fullmatch(ACTION_DIGEST, seal)
            or type(payload) is not str
            or not 0 < len(payload) <= 700
        ):
            raise ValueError
        value = _strict_json(payload)
        if (
            type(value) is not dict
            or tuple(value) != GENERATION_FIELDS
            or json.dumps(value, separators=(",", ":")) != payload
            or any(not re.fullmatch(ACTION_DIGEST, value[key]) for key in GENERATION_FIELDS[:4])
            or (value["configuration"] is None) != (value["compose_version"] is None)
            or any(
                value[key] is not None and not re.fullmatch(ACTION_DIGEST, value[key])
                for key in GENERATION_FIELDS[4:]
            )
        ):
            raise ValueError
        raw = json.dumps(
            (identifier, host, scope, observed, payload), separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        instant = _action_instant(observed, storage=True)
        if hashlib.sha256(b"opsark-compose-generation-storage/v1\0" + raw).hexdigest() != seal:
            raise ValueError
        parent = db.execute(
            "SELECT created_at,json_extract(payload,'$.id') AS payload_id,"
            "json_extract(payload,'$.created_at') AS payload_time,"
            "json_extract(payload,'$.source') AS source,json_extract(payload,'$.host_id') AS host,"
            "json_extract(payload,'$.scenario') AS scenario,"
            "json_extract(payload,'$.scope_hash') AS scope,"
            "json_extract(payload,'$.target') AS target FROM reports WHERE id=?",
            (identifier,),
        ).fetchone()
        if (
            parent is None
            or parent["payload_id"] != identifier
            or parent["source"] != "ssh"
            or parent["host"] != host
            or parent["scenario"] != "container_restart"
            or parent["scope"] != scope
            or type(parent["target"]) is not str
            or len(parent["target"]) > 16384
        ):
            raise ValueError
        target = _strict_json(parent["target"])
        created = datetime.fromisoformat(parent["created_at"])
        payload_time = datetime.fromisoformat(parent["payload_time"])
        if (
            target.get("username", "opsark-readonly") != "opsark-readonly"
            or not re.fullmatch(ACTION_DIGEST, target.get("trusted_hosts_digest", ""))
            or scope not in _action_host_scopes(parent["target"], host, diagnostic_only=True)
            or created.utcoffset() is None
            or payload_time.utcoffset() is None
            or created != payload_time
            or abs(instant - created) > timedelta(seconds=120)
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TransferError("Invalid Compose generation witness") from None


def _equal_rows(left, right, columns):
    for column, a, b in zip(columns, left, right, strict=True):
        if column[1] == "payload":
            if _canonical(_strict_json(a)) != _canonical(_strict_json(b)):
                return False
        elif type(a) is not type(b) or a != b:
            return False
    return True


def _merge_rows(target, extra, table, columns, conflict):
    names = [column[1] for column in columns]
    if table == ACTION_INTENTS:
        # Sequence orders one controller's local history and is allocated anew on import.
        names.remove("sequence")
    insert = (
        "INSERT INTO "  # noqa: S608 -- strict quoted identifier gate
        + _quoted(table)
        + " ("
        + ",".join(_quoted(n) for n in names)
        + ") VALUES ("
        + ",".join("?" for _n in names)
        + ")"
    )
    identity = "report_id" if table in {ACCESS_PROFILES, CONTAINER_PROFILES} else "id"
    lookup = "SELECT * FROM " + _quoted(table) + " WHERE " + _quoted(identity) + "=?"  # noqa: S608
    is_receipt = table == RECEIPT_TABLE
    linked_check = {
        ACTION_INTENTS: _action_intent,
        ACTION_RESULTS: _action_result,
        GENERATION_TABLE: _generation_witness,
        ACCESS_PROFILES: _access_profile,
        ACCESS_RECHECKS: _access_recheck,
        CONTAINER_PROFILES: _container_profile,
        CONTAINER_RECHECKS: _container_recheck,
        CHANGE_TABLE: _change_record,
    }.get(table)
    for row in _rows(extra, table):
        if is_receipt:
            _receipt_row(row)
        if linked_check is not None:
            linked_check(extra, row)
        prior = target.execute(lookup, (row[identity],)).fetchone()
        if prior is not None:
            same = (
                all(prior[key] == row[key] for key in names)
                if is_receipt or linked_check is not None
                else _equal_rows(prior, row, columns)
            )
            if not same:
                conflict.update(
                    table=table,
                    id=None if table == GENERATION_TABLE else _safe_identifier(row[identity]),
                    reason="immutable_id_content_conflict",
                )
                raise TransferError("The same evidence ID has different content")
        else:
            if (
                table == CHANGE_TABLE
                and target.execute(
                    "SELECT 1 FROM report_change_records_v1 WHERE report_id=? AND request_id=?",
                    (row["report_id"], row["request_id"]),
                ).fetchone()
                is not None
            ):
                conflict.update(table=table, id=None, reason="immutable_change_request_conflict")
                raise TransferError("The same change request has different record identity")
            if (
                table == CONTAINER_RECHECKS
                and target.execute(
                    "SELECT 1 FROM container_rechecks_v1 WHERE report_id=? AND request_id=?",
                    (row["report_id"], row["request_id"]),
                ).fetchone()
                is not None
            ):
                conflict.update(table=table, id=None, reason="immutable_recheck_request_conflict")
                raise TransferError(
                    "The same container recheck request has different receipt identity"
                )
            if not is_receipt and linked_check is None:
                for value in row:
                    _cell(value)
                _strict_json(row["payload"])
            target.execute(insert, tuple(row[key] for key in names))


def merge_report_baseline_snapshots(authoritative_dir, supplemental_dir, output_dir):
    """Union immutable IDs; conflicting content/schema never replaces an original."""
    authoritative, supplemental = _directory(authoritative_dir), _directory(supplemental_dir)
    output = _new_directory(output_dir, (authoritative, supplemental))
    for source in (authoritative, supplemental):
        _approved_files(source)
    pending = []
    conflict = {"reason": "merge_refused"}
    try:
        for name, table in MERGE_DATABASES.items():
            primary, secondary = authoritative / name, supplemental / name
            if not primary.exists() and not secondary.exists():
                continue
            conflict = {"database": name, "table": table, "reason": "schema_or_integrity_mismatch"}
            stage = _stage(output, name)
            pending.append((stage, output / name))
            _backup(primary if primary.exists() else secondary, stage)
            deadline = time.monotonic() + TIME_BUDGET
            with closing(_connection(stage, deadline=deadline)) as prepared:
                (
                    schema,
                    target_receipts,
                    target_actions,
                    target_generation,
                    target_access,
                    target_changes,
                    target_container,
                ) = _schema(prepared, table)
                if target_receipts:
                    for row in _rows(prepared, RECEIPT_TABLE):
                        _receipt_row(row)
                if target_actions:
                    _validate_action_rows(prepared)
                if target_generation:
                    for row in _rows(prepared, GENERATION_TABLE):
                        _generation_witness(prepared, row)
                if target_access:
                    for access_table, validate in (
                        (ACCESS_PROFILES, _access_profile),
                        (ACCESS_RECHECKS, _access_recheck),
                    ):
                        for row in _rows(prepared, access_table):
                            validate(prepared, row)
                if target_changes:
                    _change_count(prepared)
                    for row in _rows(prepared, CHANGE_TABLE):
                        _change_record(prepared, row)
                if target_container:
                    _container_count(prepared)
                    for name_, validate in (
                        (CONTAINER_PROFILES, _container_profile),
                        (CONTAINER_RECHECKS, _container_recheck),
                    ):
                        for row in _rows(prepared, name_):
                            validate(prepared, row)
            if not primary.exists() or not secondary.exists():
                if target_actions == "legacy":
                    with (
                        closing(_connection(stage, writable=True, deadline=deadline)) as target,
                        target,
                    ):
                        target.execute(ACTION_ORIGINAL_INDEX_DDL)
                continue
            with (
                closing(_connection(secondary, deadline=deadline)) as extra,
                closing(_connection(stage, writable=True, deadline=deadline)) as target,
                target,
            ):
                _integrity(extra)
                (
                    extra_schema,
                    extra_receipts,
                    extra_actions,
                    extra_generation,
                    extra_access,
                    extra_changes,
                    extra_container,
                ) = _schema(extra, table)
                if schema != extra_schema:
                    raise TransferError("Report/baseline schemas differ; no columns are dropped")
                _merge_rows(target, extra, table, schema[0], conflict)
                if extra_receipts:
                    if not target_receipts:
                        for statement in RECEIPT_DDL:
                            target.execute(statement)
                    conflict["table"] = RECEIPT_TABLE
                    _merge_rows(
                        target, extra, RECEIPT_TABLE, _columns(extra, RECEIPT_TABLE), conflict
                    )
                if extra_actions:
                    if not target_actions:
                        for statement in ACTION_DDL:
                            target.execute(statement)
                    for action_table in (ACTION_INTENTS, ACTION_RESULTS):
                        conflict["table"] = action_table
                        _merge_rows(
                            target, extra, action_table, _columns(extra, action_table), conflict
                        )
                if target_actions == "legacy":
                    target.execute(ACTION_ORIGINAL_INDEX_DDL)
                if extra_generation:
                    if not target_generation:
                        target.execute(GENERATION_DDL)
                    conflict["table"] = GENERATION_TABLE
                    _merge_rows(
                        target, extra, GENERATION_TABLE, _columns(extra, GENERATION_TABLE), conflict
                    )
                if extra_access:
                    if not target_access:
                        for statement in ACCESS_DDL:
                            target.execute(statement)
                    for access_table in (ACCESS_PROFILES, ACCESS_RECHECKS):
                        conflict["table"] = access_table
                        _merge_rows(
                            target, extra, access_table, _columns(extra, access_table), conflict
                        )
                if extra_changes:
                    _change_count(extra)
                    if not target_changes:
                        for statement in CHANGE_DDL:
                            target.execute(statement)
                    conflict["table"] = CHANGE_TABLE
                    _merge_rows(
                        target, extra, CHANGE_TABLE, _columns(extra, CHANGE_TABLE), conflict
                    )
                    _change_count(target)
                if extra_container:
                    _container_count(extra)
                    if not target_container:
                        for statement in CONTAINER_DDL:
                            target.execute(statement)
                    for container_table in (CONTAINER_PROFILES, CONTAINER_RECHECKS):
                        conflict["table"] = container_table
                        _merge_rows(
                            target,
                            extra,
                            container_table,
                            _columns(extra, container_table),
                            conflict,
                        )
                    _container_count(target)
                _integrity(target)
        if not pending:
            raise TransferError("No report/baseline stores were found")
        # Validate every prepared store before publishing either result database.
        for stage, _target in pending:
            _describe(stage)
        for stage, target in pending:
            os.replace(stage, target)
        result = _manifest(output, "merge_reports_baselines")
        _write_manifest(output, result)
        return result
    except (TransferError, sqlite3.Error, ValueError):
        _write_manifest(
            output,
            {
                "schema_version": 1,
                "operation": "merge_reports_baselines",
                "status": "conflict",
                "conflict": conflict,
            },
        )
        raise
    finally:
        for stage, _target in pending:
            if stage.exists():
                _cleanup(stage)


def _lease_tables(connection, candidates):
    _integrity(connection)
    catalog, tables = _catalog(connection)
    if any(row["type"] == "trigger" for row in catalog):
        raise TransferError("Lease clearing refuses schemas with triggers")
    # SQLite resolves foreign-key table names without regard to ASCII case.
    lease_names = {name.casefold() for name in candidates}
    for table in tables:
        if any(
            row[2].casefold() in lease_names
            for row in connection.execute("PRAGMA foreign_key_list(" + _quoted(table) + ")")
        ):
            raise TransferError("Lease clearing refuses references to monitor leases")
    return tuple(name for name in candidates if name in tables)


def clear_monitor_leases(directory):
    """Clear only verified transport-copy leases after preflighting all affected stores."""
    target = _directory(directory, private=True)
    manifest = _inspect_snapshot(target, complete=False)
    databases = manifest["databases"]
    candidates = {}
    for name, table in (*LEASE_TABLES.items(), *EXTRA_LEASE_TABLES):
        if name in databases:
            candidates.setdefault(name, []).append(table)
    cleared = {}
    with ExitStack() as stack:
        prepared = {}
        deadline = time.monotonic() + TIME_BUDGET
        for name, tables in candidates.items():
            path = target / name
            _file(path, private=True)
            connection = stack.enter_context(
                closing(_connection(path, writable=True, deadline=deadline))
            )
            stack.enter_context(connection)
            connection.execute("BEGIN IMMEDIATE")
            if _hash_file(path) != databases[name]["sha256"]:
                raise TransferError("Snapshot changed before lease clearing")
            prepared[name] = connection, _lease_tables(connection, tables)
        _require_snapshot_files(target, databases)
        if _read_snapshot_manifest(target / "manifest.json", complete=False) != manifest:
            raise TransferError("Snapshot manifest changed before lease clearing")
        for name, (connection, tables) in prepared.items():
            for table in tables:
                removed = connection.execute(
                    "DELETE FROM " + _quoted(table)  # noqa: S608 -- fixed lease allowlist
                ).rowcount
                cleared[name] = cleared.get(name, 0) + removed
            _integrity(connection)
    result = _manifest(target, "clear_monitor_leases", cleared_lease_rows=cleared)
    _write_manifest(target, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    copy = sub.add_parser("snapshot")
    copy.add_argument("source", type=Path)
    copy.add_argument("destination", type=Path)
    copy.add_argument(
        "--confirm-quiescent",
        action="store_true",
        help="Use a cold read after all source writers have stopped for the entire snapshot",
    )
    merge = sub.add_parser("merge")
    merge.add_argument("authoritative", type=Path)
    merge.add_argument("supplemental", type=Path)
    merge.add_argument("output", type=Path)
    clear = sub.add_parser("clear-leases")
    clear.add_argument("directory", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("source", type=Path)
    drill = sub.add_parser("rehearse")
    drill.add_argument("source", type=Path)
    drill.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.operation in {"verify", "rehearse"}:
        try:
            result = (
                verify_snapshot(args.source)
                if args.operation == "verify"
                else rehearse(args.source, args.destination)
            )
        except TransferError as error:
            parser.exit(1, f"Offline snapshot refused: {error}\n")
        except (OSError, sqlite3.Error, ValueError, RecursionError):
            parser.exit(1, "Offline snapshot verification or rehearsal failed.\n")
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.operation == "snapshot":
        try:
            result = snapshot(
                args.source, args.destination, confirm_quiescent=args.confirm_quiescent
            )
        except TransferError as error:
            parser.exit(1, f"Store snapshot refused: {error}\n")
        except (OSError, sqlite3.Error, ValueError, RecursionError):
            parser.exit(1, "Store snapshot failed.\n")
    elif args.operation == "merge":
        result = merge_report_baseline_snapshots(args.authoritative, args.supplemental, args.output)
    else:
        try:
            result = clear_monitor_leases(args.directory)
        except TransferError as error:
            parser.exit(1, f"Offline lease clearing refused: {error}\n")
        except (OSError, sqlite3.Error, ValueError, RecursionError):
            parser.exit(1, "Offline lease clearing failed.\n")
    # Full safe manifests stay beside the snapshots; CLI output fits bounded SSH tools.
    print(
        json.dumps(
            {
                "operation": result["operation"],
                "status": result["status"],
                "databases": {
                    name: {
                        "sha256": value["sha256"],
                        "size": value["size"],
                        "table_rows": {t: info["rows"] for t, info in value["tables"].items()},
                    }
                    for name, value in result["databases"].items()
                },
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
