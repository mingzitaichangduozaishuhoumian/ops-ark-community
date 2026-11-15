"""New defense history in fake ten-store snapshots; no age, SSH or activation.

The archive round trip uses the production tar writer/extractor and a test-only
ordinary-file path adapter. Existing sealed-path/age suites cover authentication
and platform ACLs; these cases specifically check additive SQLite table fidelity.
"""

import hashlib
import io
import json
import sqlite3
import sys
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_defense_store as fixtures
from test_store_transfer import transfer

from opsark.automation_store import AutomationStore, ModeChange
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_models import ActionBody, DefenseRequest
from opsark.defense_store import (
    AIResult,
    AliasMap,
    DefenseAlias,
    DefenseConflict,
    DefenseRecheck,
    DefenseStore,
    UsageClaim,
)
from opsark.security_store import SecurityStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import sealed_backup as sealed  # noqa: E402 -- exact checkout, no deployment import.


def directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def contents(path):
    with closing(sqlite3.connect(path)) as database:
        names = [
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        assert all(transfer.NAME.fullmatch(name) for name in names)
        return {
            name: sorted(
                database.execute('SELECT * FROM "' + name + '"').fetchall(),  # noqa: S608 -- validated SQLite identifiers in synthetic database only.
                key=repr,
            )
            for name in names
        }


@pytest.fixture
def history(tmp_path):
    source = directory(tmp_path / "source")
    mode = AutomationStore(
        source / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
    )
    mode.change_mode(ModeChange(mode=Mode.assisted, expected_revision=0))
    path = source / "security.sqlite3"
    SecurityStore(path)
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("INSERT INTO monitor_lease VALUES(1,?,?)", ("legacy-owner", 123456.0))
    store = DefenseStore(path)
    fixtures.sync_mode(store)
    action, _, execution = fixtures.prepare(store)
    ctx = action.context
    approval = fixtures.approval(store, action)
    request = DefenseRequest(
        v=1,
        op="apply",
        request_id=action.rid,
        scope_sha256=ctx.root_scope,
        body=ActionBody(manifest_sha256=store.manifest(action.rid).sha256, approval=approval),
    )
    store.save_request(action.rid, request)
    assert store.begin_sendable(
        action.rid,
        "apply",
        context=ctx,
        owner=fixtures.OWNER,
        usage=execution,
        now=fixtures.NOW,
    )
    cursor = store.transaction(action.cursor_rid)
    source_key = "e" * 64
    store.save_source(
        source_key,
        store.cursor_source(cursor.rid, host_scope="a" * 64),
        alias_map=AliasMap(
            aliases=(
                DefenseAlias(
                    candidate_alias="candidate-1",
                    evidence_alias="evidence-1",
                    source_ref="d" * 32,
                    evidence_sha256="7" * 64,
                ),
            )
        ),
    )
    ai_usage = UsageClaim(
        intent_key="f" * 64,
        kind="ai",
        grant_ref="a" * 32,
        max_per_day=1,
        max_total=1,
        provider_fingerprint="b" * 64,
    )
    permit = store.begin_ai_usage(
        cursor.rid,
        source_key=source_key,
        context=ctx,
        owner=fixtures.OWNER,
        usage=ai_usage,
        analysis_id="c" * 32,
        input_digest="d" * 64,
        now=fixtures.NOW,
    )
    store.save_ai_result(
        AIResult(
            analysis_id=permit.analysis_id,
            intent_key=permit.intent_key,
            input_digest=permit.input_digest,
            provider_fingerprint=permit.provider_fingerprint,
            status="unknown",
            proof_sha256=None,
            decision=None,
            source_ref=None,
            evidence_sha256=None,
            reason_code=None,
        )
    )
    store.record_unavailable(action.rid, "apply", context=ctx, now=fixtures.NOW)
    store.save_recheck(
        DefenseRecheck(
            recheck_id="8" * 32,
            report_id="7" * 32,
            rid=action.rid,
            manifest_sha256=store.manifest(action.rid).sha256,
            approval_id=approval.approval_id,
            defense_scope=ctx.defense_scope,
            profile_sha256="6" * 64,
            started_at=fixtures.stamp(),
            ended_at=fixtures.stamp(1),
            checks=("ok", "timeout", "error"),
        )
    )
    assert store.acquire_worker(fixtures.OWNER, expires_at=fixtures.stamp(60), now=fixtures.NOW)
    for name in set(transfer.DATABASES) - {"security.sqlite3", "automation.sqlite3"}:
        with closing(sqlite3.connect(source / name)) as database, database:
            database.execute("CREATE TABLE synthetic_marker(id TEXT PRIMARY KEY,value TEXT)")
            database.execute("INSERT INTO synthetic_marker VALUES(?,?)", ("one", name))
        (source / name).chmod(0o600)
    snapshot = tmp_path / "snapshot"
    manifest = transfer.snapshot(source, snapshot)
    return SimpleNamespace(
        source=source,
        snapshot=snapshot,
        manifest=manifest,
        action=action,
        cursor=cursor,
        permit=permit,
        mode=mode,
        execution=execution,
    )


class OrdinaryFixturePaths:
    """Content-only fixture adapter; deliberately makes no platform ACL claim."""

    @staticmethod
    def private_directory(path):
        assert path.is_dir() and not path.is_symlink()
        return path

    @staticmethod
    @contextmanager
    def new_file(path):
        with path.open("xb") as output:
            yield output
        path.chmod(0o600)


def test_additive_defense_tables_survive_archive_rehearsal_and_reopen(
    history, tmp_path, monkeypatch
):
    h = history
    expected = contents(h.snapshot / "security.sqlite3")
    tables = h.manifest["databases"]["security.sqlite3"]["tables"]
    assert len(tables) <= transfer.MAX_TABLES
    assert {
        "defense_requests",
        "defense_usage",
        "defense_ai_intents",
        "defense_ai_results",
        "defense_mode_ack",
        "defense_target_latches",
        "defense_rechecks",
        "defense_worker_lease",
    } <= set(tables)
    assert sealed._store_transfer().verify_snapshot(h.snapshot)["database_count"] == 10
    payload = io.BytesIO()
    with ExitStack() as stack:
        sources, rows = {}, []
        for name in sorted(sealed.archive.CORE):
            path = h.snapshot / name.removeprefix("stores/")
            raw = path.read_bytes()
            sources[name] = SimpleNamespace(
                handle=stack.enter_context(path.open("rb")), verify=lambda: None
            )
            rows.append(
                {
                    "name": name,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "permissions": {"fixture_only": True},
                }
            )
        manifest = sealed.archive.make_manifest("sb-" + "1" * 32, "stores-v1", rows, False)
        sealed.archive.write_archive(payload, manifest, sources)
    restored = directory(tmp_path / "restored")
    monkeypatch.setattr(sealed, "paths", OrdinaryFixturePaths)
    payload.seek(0)
    assert sealed._extract_archive(payload, restored) == manifest
    copy = restored / "stores"
    assert transfer.verify_snapshot(copy)["database_count"] == 10
    for name in transfer.DATABASES:
        assert (copy / name).read_bytes() == (h.snapshot / name).read_bytes()
    rehearsal = tmp_path / "rehearsed"
    assert transfer.rehearse(copy, rehearsal)["database_count"] == 10
    assert contents(rehearsal / "security.sqlite3") == expected
    recovered = DefenseStore(rehearsal / "security.sqlite3")
    assert contents(recovered.path) == expected
    assert recovered.transaction(h.action.rid).query_required
    assert recovered.transaction(h.action.rid).phase == "unknown"
    assert recovered.usage(h.execution.intent_key).state == "unknown"
    assert recovered.ai_permit(analysis_id=h.permit.analysis_id) == h.permit
    ai_result = recovered.ai_result(h.permit.analysis_id)
    assert ai_result is not None and ai_result.status == "unknown"
    assert recovered.latched(h.action.context.host_id, h.action.context.defense_scope)
    mode_before = contents(rehearsal / "automation.sqlite3")
    reopened = AutomationStore(
        rehearsal / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
    )
    assert reopened.status()["mode"] == "assisted"
    assert contents(rehearsal / "automation.sqlite3") == mode_before
    with pytest.raises(DefenseConflict):
        recovered.begin_ai_usage(
            h.cursor.rid,
            source_key=h.permit.source_key,
            context=h.cursor.context,
            owner=fixtures.OWNER,
            usage=UsageClaim(
                intent_key=h.permit.intent_key,
                kind="ai",
                grant_ref="a" * 32,
                max_per_day=1,
                max_total=1,
                provider_fingerprint=h.permit.provider_fingerprint,
            ),
            analysis_id=h.permit.analysis_id,
            input_digest=h.permit.input_digest,
            now=fixtures.NOW,
        )


def test_optional_legacy_lease_clear_preserves_all_new_defense_history(history):
    h = history
    before = contents(h.snapshot / "security.sqlite3")
    result = transfer.clear_monitor_leases(h.snapshot)
    after = contents(h.snapshot / "security.sqlite3")
    assert result["cleared_lease_rows"]["security.sqlite3"] == 1
    assert before["monitor_lease"] and not after["monitor_lease"]
    assert all(after[name] == rows for name, rows in before.items() if name != "monitor_lease")
    assert after["defense_worker_lease"]
    assert transfer.verify_snapshot(h.snapshot)["database_count"] == 10


def test_missing_defense_registration_at_activation_requires_fresh_manual_scope(history):
    """Offline restore preserves mode; later activation with missing config changes scope."""
    path = history.snapshot / "automation.sqlite3"
    before = contents(path)
    reopened = AutomationStore(path, ControlPolicy())
    assert reopened.status()["mode"] == "manual"
    assert reopened.status()["revision"] == history.mode.status()["revision"] + 1
    after = contents(path)
    assert set(before["automation_audit"]) < set(after["automation_audit"])


@pytest.mark.parametrize("name", ["secrets/defense-targets.json", "secrets/defense-policy.json"])
def test_old_configuration_profile_refuses_new_defense_registration_names(name):
    """Document the unsupported configuration scope, rather than claiming a full handoff."""
    plan = {
        "schema_version": 1,
        "compose_files": ["compose.yaml", "compose.release.yaml"],
        "env_files": [],
        "configuration_files": ["secrets/inventory.toml", "secrets/known_hosts", name],
        "unregistered_configuration_sources": False,
        "external_environment_overrides": False,
        "operator_confirmed_configuration_complete": True,
        "credential_files_included": False,
        "remote_root_state_included": False,
        "image": {
            "image_id": "sha256:" + "a" * 64,
            "runtime_sha256": "b" * 64,
            "material": "identity_only",
            "archive_sha256": None,
        },
    }
    with pytest.raises(sealed.archive.ArchiveError, match="handover_file_registration"):
        sealed.archive.handover_plan(json.dumps(plan).encode())
