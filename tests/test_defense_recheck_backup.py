"""Real ten-store backup/archive/rehearsal fidelity using owned synthetic ledgers.

This exercises the production stores-v1 archive writer/extractor, not age or a
deployment activation. The ordinary-file adapter makes no platform ACL claim.
No main/config loader, credential, network transport or provider is used.
"""

import hashlib
import io
import sqlite3
import sys
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_defense_store as core
from test_defense_recheck_store import declaration, passing_result

from opsark.automation_store import AutomationStore, ModeChange
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_models import (
    ActionBody,
    DefenseApproval,
    DefenseRequest,
    canonical,
    digest,
    rebuild_manifest,
)
from opsark.defense_recheck_models import (
    ActionBusinessProfile,
    DefenseRecheckResult,
    DefenseRecheckRun,
    RecheckBusinessCheck,
    RecheckBusinessEvidence,
    RecheckClaim,
)
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_store import DefenseConflict, DefenseRecheck, DefenseStore, DefenseTransaction
from opsark.security_store import SecurityStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.observer import store_transfer as transfer  # noqa: E402 -- exact production source.
from tools import _sealed_archive as archive  # noqa: E402 -- no CLI/native execution.


@dataclass(frozen=True)
class _Case:
    transaction: DefenseTransaction
    profile: ActionBusinessProfile
    run: DefenseRecheckRun
    claim: RecheckClaim
    late_result: DefenseRecheckResult | None = None


def _directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _image(path: Path):
    """Include hidden rowids: table-content digests alone cannot verify the refs."""
    with closing(sqlite3.connect(path)) as connection:
        catalog = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name"
        ).fetchall()
        tables = [row[1] for row in catalog if row[0] == "table"]
        rows = {
            name: connection.execute(
                "SELECT rowid,* FROM " + transfer._quoted(name) + " ORDER BY rowid"  # noqa: S608 -- production identifier validator; owned fake schemas.
            ).fetchall()
            for name in tables
        }
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'"
        ).fetchone():
            rows["sqlite_sequence"] = connection.execute(
                "SELECT name,seq FROM sqlite_sequence ORDER BY name"
            ).fetchall()
        return catalog, rows


def _action(base: DefenseStore, rechecks: DefenseRecheckStore, host: str, mode: str):
    revision = 1 if mode == "semi" else 2
    context = core.context(
        host_id=host,
        mode=mode,
        global_revision=revision,
        wire_revision=revision + 1,
        defense_scope=digest({"newfake_defense_host": host}),
        root_scope=digest({"newfake_root_host": host}),
    )
    core.sync_mode(base, context)
    transaction, request, usage = core.prepare(base, send=False, ctx=context)
    usage = usage.model_copy(
        update={
            "intent_key": digest(
                {
                    "channel": "ssh-defense-execution/v1",
                    "defense_scope": context.defense_scope,
                    "cursor_rid": transaction.cursor_rid,
                }
            ),
            "max_per_day": 8,
            "max_total": 8,
        }
    )
    profile = ActionBusinessProfile(
        rid=transaction.rid,
        context_sha256=digest(context),
        prepare_request_sha256=base.request_metadata(transaction.rid, "prepare").request_sha256,
        host_scope="8" * 64,
        business_profile_sha256="9" * 64,
        check_ids=("health", "login"),
        sealed_at=core.stamp(),
    )
    rechecks.seal_action_profile(profile)
    assert base.begin_sendable(
        transaction.rid,
        "prepare",
        context=context,
        owner=core.OWNER,
        usage=usage,
        now=core.NOW,
    )
    ready = core.reply(transaction, "prepare", "ready")
    manifest = rebuild_manifest(request, ready)
    ready = ready.model_copy(update={"manifest_sha256": manifest.sha256})
    assert base.record_reply(
        transaction.rid, "prepare", ready, context=context, now=core.NOW
    ).accepted
    approval = None
    if mode == "semi":
        approval = DefenseApproval(
            approval_id=digest({"newfake_approval": transaction.rid})[:32],
            purpose="apply",
            request_id=transaction.rid,
            manifest_sha256=manifest.sha256,
            approved_at=core.stamp(),
            expires_at=core.stamp(60),
        )
        base.save_approval(
            transaction.rid,
            approval,
            context=context,
            controller_grant_ref=manifest.controller_grant_ref,
            root_grant_ref=manifest.root_grant_ref,
            now=core.NOW,
        )
    base.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="apply",
            request_id=transaction.rid,
            scope_sha256=context.root_scope,
            body=ActionBody(manifest_sha256=manifest.sha256, approval=approval),
        ),
    )
    assert base.begin_sendable(
        transaction.rid,
        "apply",
        context=context,
        owner=core.OWNER,
        usage=usage,
        now=core.NOW + timedelta(seconds=1),
    )
    assert core.action_reply(
        base, transaction, "active", now=core.NOW + timedelta(seconds=2)
    ).accepted
    return transaction, profile


class _OrdinaryFixturePaths:
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


def _archive_roundtrip(snapshot: Path, destination: Path):
    payload = io.BytesIO()
    with ExitStack() as stack:
        sources, files = {}, []
        for name in sorted(archive.CORE):
            path = snapshot / name.removeprefix("stores/")
            raw = path.read_bytes()
            sources[name] = SimpleNamespace(
                handle=stack.enter_context(path.open("rb")),
                verify=lambda: None,
            )
            files.append(
                {
                    "name": name,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "permissions": {"owned_fixture_only": True},
                }
            )
        manifest = archive.make_manifest("sb-" + "a" * 32, "stores-v1", files, False)
        archive.write_archive(payload, manifest, sources)
    payload.seek(0)
    assert archive.extract_archive(payload, destination, _OrdinaryFixturePaths) == manifest
    return destination / "stores"


@pytest.fixture(scope="module")
def preserved(tmp_path_factory, request: pytest.FixtureRequest):
    root = _directory(tmp_path_factory.mktemp("newfake-recheck-handover") / "owned")
    source = _directory(root / "source")
    mode = AutomationStore(
        source / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
    )
    mode.change_mode(ModeChange(mode=Mode.assisted, expected_revision=0))
    security = source / "security.sqlite3"
    SecurityStore(security)
    base, cases = DefenseStore(security), {}
    rechecks = DefenseRecheckStore(base)
    for index, (kind, verdict) in enumerate(
        (
            ("semi", "passed"),
            ("semi", "failed"),
            ("semi", "pending"),
            ("auto", "passed"),
            ("auto", "failed"),
            ("auto", "pending"),
            ("auto", "claimed"),
            ("auto", "interrupted"),
        )
    ):
        if index == 3:
            mode.change_mode(ModeChange(mode=Mode.automatic, expected_revision=1))
        if index == 7:
            # The final action's new v2 rows and Root observation references
            # remain in committed WAL pages during the production snapshot.
            witness = sqlite3.connect(security)
            request.addfinalizer(witness.close)
            assert witness.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
            witness.execute("PRAGMA wal_autocheckpoint=0")
        key = f"{kind}-{verdict}"
        transaction, profile = _action(base, rechecks, "newfake-" + key, kind)
        run = rechecks.create(
            declaration(base, transaction, format(15 - index, "x") * 32),
            now=core.NOW + timedelta(seconds=3),
        )
        claim = rechecks.claim(
            run.declaration.run_ref, owner="newfake-" + key, now=core.NOW + timedelta(seconds=3)
        )
        assert claim is not None
        late_result = None
        if verdict != "claimed":
            result = passing_result(
                base,
                rechecks,
                transaction,
                claim,
                after_state="expired" if key == "auto-passed" else "active",
            )
            if verdict in {"failed", "pending"}:
                business = RecheckBusinessEvidence(
                    status="failed" if verdict == "failed" else "inconclusive",
                    checks=(
                        RecheckBusinessCheck(
                            id="health",
                            status="failed" if verdict == "failed" else "inconclusive",
                            reason_code="body_mismatch"
                            if verdict == "failed"
                            else "receipt_unavailable",
                        ),
                        RecheckBusinessCheck(id="login", status="passed", reason_code="ok"),
                    ),
                )
                result = result.model_copy(
                    update={
                        "business": business,
                        "verdict": verdict,
                        "reason_codes": (
                            "business_failed" if verdict == "failed" else "business_inconclusive",
                        ),
                    }
                )
            if verdict == "interrupted":
                late_result = result
                rechecks.interrupt(
                    claim.run_ref,
                    expected_declaration_sha256=run.declaration_sha256,
                    now=core.NOW + timedelta(seconds=123),
                )
            else:
                rechecks.finish(claim, result)
        retained = rechecks.get(claim.run_ref)
        assert retained is not None
        cases[key] = _Case(transaction, profile, retained, claim, late_result)
    human = cases["semi-passed"].transaction
    authorization = base.approval_record(human.rid)
    assert authorization is not None
    legacy = DefenseRecheck(
        recheck_id="0" * 32,
        report_id="1" * 32,
        rid=human.rid,
        manifest_sha256=base.manifest(human.rid).sha256,
        approval_id=authorization.metadata.approval.approval_id,
        defense_scope=human.context.defense_scope,
        profile_sha256="9" * 64,
        started_at=core.stamp(3),
        ended_at=core.stamp(7),
        checks=("ok", "timeout"),
    )
    base.save_recheck(legacy)
    # Last-known historical success survives later uncertainty and a durable latch.
    base.record_unavailable(
        human.rid, "apply", context=human.context, now=core.NOW + timedelta(seconds=8)
    )
    assert base.latched(human.context.host_id, human.context.defense_scope)
    assert base.acquire_worker("newfake-original-worker", expires_at=core.stamp(60), now=core.NOW)
    with closing(sqlite3.connect(security)) as connection, connection:
        connection.execute(
            "INSERT INTO monitor_lease VALUES(1,?,?)", ("newfake-original-monitor", 123456.0)
        )
    for name in set(transfer.DATABASES) - {"security.sqlite3", "automation.sqlite3"}:
        with closing(sqlite3.connect(source / name)) as connection, connection:
            connection.execute(
                "CREATE TABLE newfake_marker(id TEXT PRIMARY KEY,value BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT INTO newfake_marker VALUES(?,?)", (name, ("newfake-" + name).encode())
            )
    last_ref = cases["auto-interrupted"].claim.run_ref
    assert (source / "security.sqlite3-wal").stat().st_size > 0
    with closing(sqlite3.connect(security.as_uri() + "?immutable=1", uri=True)) as main_only:
        assert (
            main_only.execute(
                "SELECT 1 FROM defense_recheck_runs_v2 WHERE run_ref=?", (last_ref,)
            ).fetchone()
            is None
        )
    before = {name: _image(source / name) for name in transfer.DATABASES}
    snapshot = root / "snapshot"
    manifest = transfer.snapshot(source, snapshot)
    assert set(manifest["databases"]) == set(transfer.DATABASES) == set(archive.DATABASES)
    assert len(transfer.DATABASES) == 10
    assert {name: _image(snapshot / name) for name in transfer.DATABASES} == before
    restored = _archive_roundtrip(snapshot, _directory(root / "extracted"))
    assert transfer.verify_snapshot(restored)["database_count"] == 10
    for name in (*transfer.DATABASES, "manifest.json"):
        assert (restored / name).read_bytes() == (snapshot / name).read_bytes()
    rehearsed = root / "rehearsed"
    assert transfer.rehearse(restored, rehearsed)["database_count"] == 10
    assert {name: _image(rehearsed / name) for name in transfer.DATABASES} == before
    return SimpleNamespace(
        source=source,
        snapshot=snapshot,
        restored=restored,
        rehearsed=rehearsed,
        before=before,
        cases=cases,
        legacy=legacy,
        mode_status=mode.status(),
    )


def test_v2_recheck_evidence_and_all_ten_stores_survive_production_archive_rehearsal(preserved):
    h = preserved
    base = DefenseStore(h.rehearsed / "security.sqlite3")
    rechecks = DefenseRecheckStore(base)
    for case in h.cases.values():
        recovered = rechecks.get(case.claim.run_ref)
        assert recovered == case.run
        assert rechecks.action_profile(case.transaction.rid) == case.profile
        assert base.transaction(case.transaction.rid) == DefenseStore(
            h.source / "security.sqlite3"
        ).transaction(case.transaction.rid)
        if case.run.result is not None:
            result = case.run.result
            assert rechecks.authority(case.transaction.rid, result.root_before) == result.authority
            assert result.root_before is not None and result.root_after is not None
            assert (
                case.claim.observation_sequence
                < result.root_before.sequence
                < result.root_after.sequence
            )
            for frame in (result.root_before, result.root_after):
                exact = base.observation_record(frame.observation.observation_id)
                assert canonical(exact) == canonical(frame)
        assert rechecks.list(case.transaction.context.host_id) == (case.run,)
    assert {
        case.run.result.verdict for case in h.cases.values() if case.run.result is not None
    } == {"passed", "failed", "pending"}
    assert {
        case.run.result.authority.kind for case in h.cases.values() if case.run.result is not None
    } == {"human_approval", "preauthorization"}
    old = base.legacy_recheck(h.legacy.recheck_id)
    assert old is not None and old.record == h.legacy and old.verdict == "pending"
    assert base.legacy_rechecks("newfake-semi-passed") == (old,)
    assert base.latched(
        "newfake-semi-passed", h.cases["semi-passed"].transaction.context.defense_scope
    )
    mode = AutomationStore(
        h.rehearsed / "automation.sqlite3", ControlPolicy(), supplemental_scope="a" * 64
    )
    assert mode.status() == h.mode_status
    assert {name: _image(h.rehearsed / name) for name in transfer.DATABASES} == h.before


def test_reopened_claims_never_recollect_or_overwrite_interrupted_history(preserved):
    h = preserved
    base = DefenseStore(h.rehearsed / "security.sqlite3")
    rechecks = DefenseRecheckStore(base)
    unfinished, interrupted = h.cases["auto-claimed"], h.cases["auto-interrupted"]
    assert rechecks.active_run(unfinished.transaction.context.host_id) == unfinished.run
    for case in (unfinished, interrupted):
        assert rechecks.create(case.run.declaration, now=core.NOW + timedelta(days=1)) == case.run
        assert (
            rechecks.claim(
                case.claim.run_ref, owner="newfake-restart", now=core.NOW + timedelta(days=1)
            )
            is None
        )
        assert rechecks.get(case.claim.run_ref) == case.run
    assert interrupted.late_result is not None
    with pytest.raises(DefenseConflict):
        rechecks.finish(interrupted.claim, interrupted.late_result)
    assert rechecks.active_run(interrupted.transaction.context.host_id) is None
    assert (
        base.acquire_worker(
            "newfake-restart", expires_at=core.stamp(50), now=core.NOW + timedelta(seconds=10)
        )
        is None
    )
    assert {name: _image(h.rehearsed / name) for name in transfer.DATABASES} == h.before
