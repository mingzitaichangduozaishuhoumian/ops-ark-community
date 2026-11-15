"""Owned fake action ledgers only; no credentials, remote hosts or providers."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from threading import Barrier

import pytest
from pydantic import ValidationError
from test_defense_store import (
    NOW,
    OWNER,
    action_reply,
    approval,
    context,
    prepare,
    reply,
    stamp,
    sync_mode,
)

from opsark.defense_models import ActionBody, DefenseRequest, canonical, digest, rebuild_manifest
from opsark.defense_recheck_models import (
    ActionBusinessProfile,
    DefenseRecheckDeclaration,
    DefenseRecheckResult,
    RecheckAuthority,
    RecheckBusinessCheck,
    RecheckBusinessEvidence,
    RecheckRootEvidence,
)
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_store import DefenseConflict, DefenseRecheck, DefenseStore


def action(tmp_path, *, mode="semi", sealed=True, applied=True, host="fake-host"):
    base = DefenseStore(tmp_path / "security.sqlite3")
    store = DefenseRecheckStore(base)
    ctx = context(mode=mode, host_id=host)
    sync_mode(base, ctx)
    transaction, request, usage = prepare(base, send=False, ctx=ctx)
    usage = usage.model_copy(
        update={
            "intent_key": digest(
                {
                    "channel": "ssh-defense-execution/v1",
                    "defense_scope": ctx.defense_scope,
                    "cursor_rid": transaction.cursor_rid,
                }
            )
        }
    )
    profile = ActionBusinessProfile(
        rid=transaction.rid,
        context_sha256=digest(ctx),
        prepare_request_sha256=base.request_metadata(transaction.rid, "prepare").request_sha256,
        host_scope="8" * 64,
        business_profile_sha256="9" * 64,
        check_ids=("health", "login"),
        sealed_at=stamp(),
    )
    if sealed:
        store.seal_action_profile(profile)
    assert base.begin_sendable(
        transaction.rid, "prepare", context=ctx, owner=OWNER, usage=usage, now=NOW
    )
    ready = reply(transaction, "prepare", "ready")
    manifest = rebuild_manifest(request, ready)
    ready = ready.model_copy(update={"manifest_sha256": manifest.sha256})
    assert base.record_reply(transaction.rid, "prepare", ready, context=ctx, now=NOW).accepted
    if applied:
        declaration = approval(base, transaction) if mode == "semi" else None
        apply = DefenseRequest(
            v=1,
            op="apply",
            request_id=transaction.rid,
            scope_sha256=ctx.root_scope,
            body=ActionBody(manifest_sha256=manifest.sha256, approval=declaration),
        )
        base.save_request(transaction.rid, apply)
        assert base.begin_sendable(
            transaction.rid,
            "apply",
            context=ctx,
            owner=OWNER,
            usage=usage,
            now=NOW + timedelta(seconds=1),
        )
        assert action_reply(base, transaction, "active", now=NOW + timedelta(seconds=2)).accepted
    return base, store, transaction, profile


def declaration(base, transaction, run_ref="f" * 32):
    return DefenseRecheckDeclaration(
        run_ref=run_ref,
        host_id=transaction.context.host_id,
        rid=transaction.rid,
        expected_manifest_sha256=base.manifest(transaction.rid).sha256,
        expected_profile_sha256="9" * 64,
    )


def frame(base, transaction, at, *, state="active", remaining=49000):
    changes = {"remaining_ms": remaining} if state == "active" else {}
    observation = action_reply(
        base,
        transaction,
        state,
        now=NOW + timedelta(seconds=at),
        changes=changes,
    )
    assert observation.accepted
    exact = base.observation_record(observation.observation_id)
    return RecheckRootEvidence.model_validate_json(canonical(exact))


def passing_result(base, store, transaction, claim, *, after_state="active"):
    before = frame(base, transaction, 4)
    after = frame(base, transaction, 6, state=after_state, remaining=48000)
    return DefenseRecheckResult(
        run_ref=claim.run_ref,
        host_id=transaction.context.host_id,
        rid=transaction.rid,
        manifest_sha256=base.manifest(transaction.rid).sha256,
        defense_scope=transaction.context.defense_scope,
        host_scope="8" * 64,
        business_profile_sha256="9" * 64,
        authority=store.authority(transaction.rid, before),
        business=RecheckBusinessEvidence(
            status="passed",
            checks=(
                RecheckBusinessCheck(id="health", status="passed", reason_code="ok"),
                RecheckBusinessCheck(id="login", status="passed", reason_code="ok"),
            ),
        ),
        root_before=before,
        root_after=after,
        expected_root_state="active",
        current_root_state=after_state,
        transition="ttl_elapsed" if after_state == "expired" else "unchanged",
        started_at=stamp(3),
        finished_at=stamp(7),
        verdict="passed",
        reason_codes=("ok",),
    )


@pytest.mark.parametrize("mode", ["semi", "auto"])
@pytest.mark.parametrize("after_state", ["active", "expired"])
def test_sealed_business_run_revalidates_human_or_automatic_authority(tmp_path, mode, after_state):
    base, store, transaction, profile = action(tmp_path, mode=mode)
    initial = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(
        initial.declaration.run_ref, owner="recheck-owner", now=NOW + timedelta(seconds=3)
    )
    assert claim is not None
    result = passing_result(base, store, transaction, claim, after_state=after_state)
    expected_kind = "human_approval" if mode == "semi" else "preauthorization"
    assert result.authority.kind == expected_kind
    finished = store.finish(claim, result)
    assert finished.status == "completed" and finished.result == result
    assert store.finish(claim, result) == finished
    restarted = DefenseRecheckStore(DefenseStore(base.path))
    assert restarted.get(initial.declaration.run_ref) == finished
    assert restarted.action_profile(transaction.rid) == profile
    assert store.create(initial.declaration, now=NOW + timedelta(days=1)) == finished
    assert store.claim(initial.declaration.run_ref, owner="other", now=NOW) is None


def test_profile_first_dispatch_boundary_is_immutable_and_legacy_cannot_be_backfilled(tmp_path):
    base, store, transaction, profile = action(tmp_path, sealed=False)
    assert store.action_profile(transaction.rid) is None
    with pytest.raises(DefenseConflict):
        store.seal_action_profile(profile)
    base2, store2, transaction2, profile2 = action(tmp_path / "another")
    assert store2.seal_action_profile(profile2) == profile2
    with pytest.raises(DefenseConflict):
        store2.seal_action_profile(profile2.model_copy(update={"check_ids": ("other",)}))
    assert base.manifest(transaction.rid) and base2.manifest(transaction2.rid)


def test_client_run_ref_global_declaration_identity_and_insertion_pagination(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    first = store.create(declaration(base, transaction, "f" * 32), now=NOW + timedelta(seconds=20))
    assert store.create(first.declaration, now=NOW) == first
    with pytest.raises(DefenseConflict):
        store.create(first.declaration.model_copy(update={"host_id": "another"}), now=NOW)
    second = store.create(declaration(base, transaction, "0" * 32), now=NOW)
    assert first.sequence < second.sequence
    assert store.list("fake-host", limit=1) == (first,)
    assert store.list("fake-host", after_sequence=first.sequence, limit=1) == (second,)
    assert store.list("fake-host", transaction.rid) == (first, second)
    assert store.list("retired-absent") == ()
    assert store.get("a" * 32) is None


def test_claim_once_host_serialization_and_crash_restart_never_recollect(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    original = store.create(declaration(base, transaction), now=NOW)
    store.create(declaration(base, transaction, "e" * 32), now=NOW)
    barrier = Barrier(2)

    def claim(index):
        local = DefenseRecheckStore(DefenseStore(base.path))
        barrier.wait()
        return local.claim(original.declaration.run_ref, owner=f"worker-{index}", now=NOW)

    with ThreadPoolExecutor(max_workers=2) as workers:
        claimed = list(workers.map(claim, range(2)))
    assert sum(value is not None for value in claimed) == 1
    restarted = DefenseRecheckStore(DefenseStore(base.path))
    unfinished = restarted.get(original.declaration.run_ref)
    assert unfinished is not None and unfinished.status == "claimed"
    assert (
        restarted.claim(original.declaration.run_ref, owner="restart", now=NOW + timedelta(days=1))
        is None
    )
    with pytest.raises(DefenseConflict):
        restarted.claim("e" * 32, owner="restart", now=NOW + timedelta(days=1))


def test_commit_failure_leaves_no_collection_claim(tmp_path, monkeypatch):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW)
    original_commit = base._commit

    def fail(_connection):
        raise sqlite3.OperationalError("newfake failed claim commit")

    monkeypatch.setattr(base, "_commit", fail)
    with pytest.raises(sqlite3.OperationalError):
        store.claim(run.declaration.run_ref, owner="worker", now=NOW)
    monkeypatch.setattr(base, "_commit", original_commit)
    assert store.get(run.declaration.run_ref).status == "pending"
    assert store.claim(run.declaration.run_ref, owner="worker", now=NOW) is not None


def test_used_approval_is_exact_apply_not_revoke_and_usage_is_original(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    record = base.approval_record(transaction.rid, "apply")
    assert (
        record is not None
        and record.dispatch_state == "used"
        and record.used_at == stamp(1).replace("Z", ".000000Z")
    )
    assert base.approval_record(transaction.rid, "revoke") is None
    usage = base.execution_usage(transaction.rid)
    assert usage is not None and usage.kind == "execution"
    assert store.authority(transaction.rid).kind == "human_approval"
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute(
            "UPDATE defense_authorizations SET dispatch_state='recorded',used_at=NULL WHERE rid=?",
            (transaction.rid,),
        )
    with pytest.raises(DefenseConflict):
        base.approval_record(transaction.rid)
    assert store.authority(transaction.rid).kind == "unproven"


def test_latest_observation_is_exact_insertion_even_after_utc_rollback_and_unavailable(tmp_path):
    base, _, transaction, _ = action(tmp_path)
    before = base.latest_observation(transaction.rid)
    assert before is not None and before.observation.accepted
    unavailable = base.record_unavailable(transaction.rid, "query", now=NOW - timedelta(seconds=1))
    after = base.latest_observation(transaction.rid)
    assert after is not None and after.sequence > before.sequence
    assert after.observation == unavailable and after.reply is None
    assert after.observation.observed_at < before.observation.observed_at


def test_legacy_recheck_bytes_untouched_and_history_hosts_include_retired(tmp_path):
    base, store, transaction, _ = action(tmp_path, host="Retired-A")
    old = DefenseRecheck(
        recheck_id="c" * 32,
        report_id="d" * 32,
        rid=transaction.rid,
        manifest_sha256=base.manifest(transaction.rid).sha256,
        approval_id="9" * 32,
        defense_scope=transaction.context.defense_scope,
        profile_sha256="8" * 64,
        started_at=stamp(3),
        ended_at=stamp(4),
        checks=("ok",),
    )
    base.save_recheck(old)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        original = connection.execute("SELECT * FROM defense_rechecks").fetchall()
    assert base.history_hosts() == ("Retired-A",)
    assert base.history_hosts(after="Retired-A") == ()
    legacy = base.legacy_recheck(old.recheck_id)
    assert legacy is not None and legacy.record == old and legacy.verdict == "pending"
    assert base.legacy_rechecks("Retired-A") == (legacy,)
    assert base.legacy_rechecks("Retired-A", after_sequence=legacy.sequence) == ()
    store.create(declaration(base, transaction), now=NOW)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        assert connection.execute("SELECT * FROM defense_rechecks").fetchall() == original
    for bad in (True, 0, 102, "1"):
        with pytest.raises(ValueError):
            base.history_hosts(limit=bad)


@pytest.mark.parametrize(
    "table,column",
    [
        ("defense_action_business_profiles_v1", "typed_profile"),
        ("defense_recheck_runs_v2", "typed_declaration"),
        ("defense_recheck_runs_v2", "typed_claim"),
        ("defense_recheck_results_v2", "typed_result"),
    ],
)
def test_all_v2_reads_reject_corrupted_hashes(tmp_path, table, column):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    result = passing_result(base, store, transaction, claim)
    store.finish(claim, result)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute(f"UPDATE {table} SET {column}=?", (b"{}",))  # noqa: S608 -- fixed test map.
    with pytest.raises(DefenseConflict):
        store.get(run.declaration.run_ref)


def test_old_snapshot_or_untyped_result_never_seals_green(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    result = passing_result(base, store, transaction, claim)
    with pytest.raises(TypeError):
        store.finish(claim, result.model_dump(mode="json"))
    wrong_claim = claim.model_copy(update={"owner": "another"})
    with pytest.raises(DefenseConflict):
        store.finish(wrong_claim, result)
    base.record_unavailable(transaction.rid, "query", now=NOW + timedelta(seconds=8))
    with pytest.raises(DefenseConflict):
        store.finish(claim, result)


def test_missing_original_profile_cannot_green_and_is_not_backfilled(tmp_path):
    base, store, transaction, _ = action(tmp_path, sealed=False)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    green = passing_result(base, store, transaction, claim)
    with pytest.raises(DefenseConflict):
        store.finish(claim, green)
    pending = green.model_copy(
        update={
            "business": RecheckBusinessEvidence(checks=(), status="uncovered"),
            "verdict": "pending",
            "reason_codes": ("profile_missing",),
        }
    )
    saved = store.finish(claim, pending)
    assert saved.result is not None and saved.result.verdict == "pending"
    assert store.action_profile(transaction.rid) is None


def test_rollback_preserves_actual_times_and_can_only_seal_pending(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    result = passing_result(base, store, transaction, claim)
    pending = result.model_copy(
        update={
            "finished_at": stamp(2),
            "verdict": "pending",
            "reason_codes": ("clock_regressed",),
        }
    )
    saved = store.finish(claim, pending)
    assert saved.result is not None and saved.result.finished_at == stamp(2)
    assert saved.result.started_at == stamp(3)
    with pytest.raises(ValidationError):
        DefenseRecheckResult.model_validate_json(
            canonical(pending.model_copy(update={"verdict": "passed"}))
        )


def test_pending_authority_history_is_not_upgraded_when_action_is_later_applied(tmp_path):
    base, store, transaction, _ = action(tmp_path, applied=False)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    result = DefenseRecheckResult(
        run_ref=claim.run_ref,
        host_id=transaction.context.host_id,
        rid=transaction.rid,
        manifest_sha256=base.manifest(transaction.rid).sha256,
        defense_scope=transaction.context.defense_scope,
        host_scope="8" * 64,
        business_profile_sha256="9" * 64,
        authority=RecheckAuthority(
            kind="unproven", proof_sha256=None, reason_codes=("apply_not_sent",)
        ),
        business=RecheckBusinessEvidence(checks=(), status="uncovered"),
        root_before=None,
        root_after=None,
        expected_root_state="unavailable",
        current_root_state="unavailable",
        transition="unknown",
        started_at=stamp(3),
        finished_at=stamp(4),
        verdict="pending",
        reason_codes=("authority_unproven",),
    )
    historical = store.finish(claim, result)
    # Later facts must not rewrite the sealed conservative conclusion.
    statement = approval(base, transaction)
    request = DefenseRequest(
        v=1,
        op="apply",
        request_id=transaction.rid,
        scope_sha256=transaction.context.root_scope,
        body=ActionBody(manifest_sha256=base.manifest(transaction.rid).sha256, approval=statement),
    )
    base.save_request(transaction.rid, request)
    usage = base.execution_usage(transaction.rid)
    assert usage is not None
    from opsark.defense_store import UsageClaim

    assert base.begin_sendable(
        transaction.rid,
        "apply",
        context=transaction.context,
        owner=OWNER,
        usage=UsageClaim(
            intent_key=usage.intent_key,
            kind="execution",
            grant_ref=usage.grant_ref,
            max_per_day=10,
            max_total=100,
        ),
        now=NOW + timedelta(seconds=5),
    )
    assert store.authority(transaction.rid).kind == "human_approval"
    assert store.get(claim.run_ref) == historical


@pytest.mark.parametrize("mutation", ["report", "extra", "bool", "free_text", "business_reason"])
def test_v2_schema_rejects_generic_report_fields_and_untyped_evidence(tmp_path, mutation):
    base, store, transaction, _ = action(tmp_path)
    raw = declaration(base, transaction).model_dump(mode="json")
    if mutation == "report":
        raw["report_id"] = "a" * 32
    elif mutation == "extra":
        raw["shell"] = "newfake forbidden shell"
    elif mutation == "bool":
        raw["v"] = True
    elif mutation == "free_text":
        with pytest.raises(ValidationError):
            RecheckAuthority.model_validate(
                {
                    "kind": "unproven",
                    "proof_sha256": None,
                    "reason_codes": ("newfake free text",),
                }
            )
        return
    else:
        with pytest.raises(ValidationError):
            RecheckBusinessCheck(id="health", status="passed", reason_code="body_mismatch")
        return
    with pytest.raises(ValidationError):
        DefenseRecheckDeclaration.model_validate(raw)
    with pytest.raises(TypeError):
        store.create(raw)


def test_explicit_hard_budget_interruption_preserves_unfinished_claim_and_releases_host(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    first = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    second = store.create(declaration(base, transaction, "e" * 32), now=NOW + timedelta(seconds=3))
    claim = store.claim(
        first.declaration.run_ref, owner="lost-worker", now=NOW + timedelta(seconds=3)
    )
    assert claim is not None
    result = passing_result(base, store, transaction, claim)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        original_usage = connection.execute("SELECT * FROM defense_usage").fetchall()
        original_root_requests = connection.execute("SELECT * FROM defense_requests").fetchall()
        original_latches = connection.execute("SELECT * FROM defense_target_latches").fetchall()
    for instant in (NOW + timedelta(seconds=2), NOW + timedelta(seconds=122.999999)):
        with pytest.raises(DefenseConflict):
            store.interrupt(
                first.declaration.run_ref,
                expected_declaration_sha256=first.declaration_sha256,
                now=instant,
            )
    with pytest.raises(DefenseConflict):
        store.interrupt(
            first.declaration.run_ref,
            expected_declaration_sha256="0" * 64,
            now=NOW + timedelta(seconds=123),
        )
    interrupted = store.interrupt(
        first.declaration.run_ref,
        expected_declaration_sha256=first.declaration_sha256,
        now=NOW + timedelta(seconds=123),
    )
    assert interrupted.status == "interrupted" and interrupted.result is None
    assert interrupted.claim == claim and interrupted.owner == "lost-worker"
    assert (
        interrupted.interruption is not None
        and interrupted.interruption.interrupted_at == stamp(123).replace("Z", ".000000Z")
    )
    assert store.active_run(transaction.context.host_id) is None
    assert (
        store.claim(first.declaration.run_ref, owner="restart", now=NOW + timedelta(seconds=124))
        is None
    )
    with pytest.raises(DefenseConflict):
        store.finish(claim, result)
    restarted = DefenseRecheckStore(DefenseStore(base.path))
    assert restarted.get(first.declaration.run_ref) == interrupted
    assert (
        restarted.interrupt(
            first.declaration.run_ref, expected_declaration_sha256=first.declaration_sha256, now=NOW
        )
        == interrupted
    )
    assert (
        restarted.claim(
            second.declaration.run_ref, owner="explicit-new-run", now=NOW + timedelta(seconds=124)
        )
        is not None
    )
    with closing(sqlite3.connect(base.path)) as connection, connection:
        assert connection.execute("SELECT * FROM defense_usage").fetchall() == original_usage
        assert (
            connection.execute("SELECT * FROM defense_requests").fetchall()
            == original_root_requests
        )
        assert (
            connection.execute("SELECT * FROM defense_target_latches").fetchall()
            == original_latches
        )


def test_pending_unclaimed_or_completed_runs_cannot_be_interrupted(tmp_path):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    with pytest.raises(DefenseConflict):
        store.interrupt(
            run.declaration.run_ref,
            expected_declaration_sha256=run.declaration_sha256,
            now=NOW + timedelta(days=1),
        )
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    store.finish(claim, passing_result(base, store, transaction, claim))
    with pytest.raises(DefenseConflict):
        store.interrupt(
            run.declaration.run_ref,
            expected_declaration_sha256=run.declaration_sha256,
            now=NOW + timedelta(days=1),
        )


def test_early_v2_schema_retains_original_claim_and_supports_explicit_interruption(tmp_path):
    base, _, transaction, _ = action(tmp_path)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute("DROP TABLE defense_recheck_runs_v2")
        connection.execute("""
            CREATE TABLE defense_recheck_runs_v2(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,run_ref TEXT NOT NULL UNIQUE,
                host_id TEXT NOT NULL,rid TEXT NOT NULL,
                declaration_sha256 TEXT NOT NULL,typed_declaration BLOB NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','claimed','completed')),
                created_at TEXT NOT NULL,claimed_at TEXT,owner TEXT,
                claim_sha256 TEXT,typed_claim BLOB)
        """)
    upgraded = DefenseRecheckStore(base)
    run = upgraded.create(declaration(base, transaction), now=NOW)
    claim = upgraded.claim(run.declaration.run_ref, owner="original", now=NOW)
    assert claim is not None
    with closing(sqlite3.connect(base.path)) as connection, connection:
        original_claim = connection.execute(
            "SELECT typed_claim FROM defense_recheck_runs_v2"
        ).fetchone()[0]
    interrupted = upgraded.interrupt(
        run.declaration.run_ref,
        expected_declaration_sha256=run.declaration_sha256,
        now=NOW + timedelta(seconds=120),
    )
    assert interrupted.status == "interrupted" and interrupted.result is None
    with closing(sqlite3.connect(base.path)) as connection, connection:
        assert (
            connection.execute("SELECT typed_claim FROM defense_recheck_runs_v2").fetchone()[0]
            == original_claim
        )
    assert upgraded.active_run(transaction.context.host_id) is None
    assert DefenseRecheckStore(DefenseStore(base.path)).get(run.declaration.run_ref) == interrupted


@pytest.mark.parametrize("original", ["approval", "root_query"])
def test_sealed_passing_history_revalidates_original_authority_and_root_rows(tmp_path, original):
    base, store, transaction, _ = action(tmp_path)
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    result = passing_result(base, store, transaction, claim)
    store.finish(claim, result)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        if original == "approval":
            connection.execute(
                "UPDATE defense_authorizations SET statement_sha256=? WHERE rid=?",
                ("0" * 64, transaction.rid),
            )
        else:
            assert result.root_after is not None
            connection.execute(
                "UPDATE defense_observations SET receipt_sha256=? WHERE observation_id=?",
                ("0" * 64, result.root_after.observation.observation_id),
            )
    with pytest.raises(DefenseConflict):
        store.get(run.declaration.run_ref)


def test_automatic_authority_proof_is_stable_when_usage_becomes_unknown(tmp_path):
    base, store, transaction, _ = action(tmp_path, mode="auto")
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    result = passing_result(base, store, transaction, claim)
    sealed = store.finish(claim, result)
    assert result.authority.kind == "preauthorization"
    assert base.approval_record(transaction.rid) is None
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute(
            "UPDATE defense_usage SET state='unknown' WHERE rid=?", (transaction.rid,)
        )
    assert store.authority(transaction.rid, result.root_before) == result.authority
    assert store.get(run.declaration.run_ref) == sealed
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute(
            "UPDATE defense_usage SET state='consumed' WHERE rid=?", (transaction.rid,)
        )
    assert store.authority(transaction.rid, result.root_before) == result.authority
    assert store.get(run.declaration.run_ref) == sealed


@pytest.mark.parametrize("mode", ["semi", "auto"])
def test_reserved_execution_usage_cannot_prove_authority_or_green_recheck(tmp_path, mode):
    base, store, transaction, _ = action(tmp_path, mode=mode)
    with closing(sqlite3.connect(base.path)) as connection, connection:
        connection.execute(
            "UPDATE defense_usage SET state='reserved' WHERE rid=? AND kind='execution'",
            (transaction.rid,),
        )
        original_usage = connection.execute("SELECT * FROM defense_usage").fetchall()
    run = store.create(declaration(base, transaction), now=NOW + timedelta(seconds=3))
    claim = store.claim(run.declaration.run_ref, owner="worker", now=NOW + timedelta(seconds=3))
    assert claim is not None
    before, after = frame(base, transaction, 4), frame(base, transaction, 6, remaining=48000)
    authority = store.authority(transaction.rid, before)
    assert authority.kind == "unproven" and authority.proof_sha256 is None
    result = DefenseRecheckResult(
        run_ref=claim.run_ref,
        host_id=transaction.context.host_id,
        rid=transaction.rid,
        manifest_sha256=base.manifest(transaction.rid).sha256,
        defense_scope=transaction.context.defense_scope,
        host_scope="8" * 64,
        business_profile_sha256="9" * 64,
        authority=authority,
        business=RecheckBusinessEvidence(
            status="passed",
            checks=(
                RecheckBusinessCheck(id="health", status="passed", reason_code="ok"),
                RecheckBusinessCheck(id="login", status="passed", reason_code="ok"),
            ),
        ),
        root_before=before,
        root_after=after,
        expected_root_state="active",
        current_root_state="active",
        transition="unchanged",
        started_at=stamp(3),
        finished_at=stamp(7),
        verdict="pending",
        reason_codes=("authority_unproven",),
    )
    finished = store.finish(claim, result)
    assert finished.result is not None and finished.result.verdict == "pending"
    with pytest.raises(ValidationError):
        DefenseRecheckResult.model_validate_json(
            canonical(result.model_copy(update={"verdict": "passed"}))
        )
    with closing(sqlite3.connect(base.path)) as connection, connection:
        assert connection.execute("SELECT * FROM defense_usage").fetchall() == original_usage
