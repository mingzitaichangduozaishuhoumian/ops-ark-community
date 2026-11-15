"""Dormant session sidecars: synthetic keys, local ledgers, no real transport/model."""

import hashlib
import socket
import sqlite3
from contextlib import closing
from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_defense_api import EVIDENCE, NOW, SOURCE, ArmRequest, stamp
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.automation_store import ModeChange
from opsark.baselines import scope_for
from opsark.control_modes import Mode
from opsark.defense_ai import AI_BUDGET_REF, DefenseAIService, intent_key
from opsark.defense_models import (
    ActionBody,
    DefenseCall,
    DefenseRequest,
    PrepareBody,
    canonical,
    digest,
)
from opsark.defense_session_models import (
    SessionAIIntent,
    SessionDeclaration,
    SessionModeSnapshot,
    SessionRuntime,
)
from opsark.defense_session_store import DefenseSessionStore
from opsark.defense_store import (
    AIResult,
    AliasMap,
    DefenseAlias,
    DefenseConflict,
    DefenseStore,
    UsageClaim,
)


@pytest.fixture(autouse=True)
def no_network_or_provider(monkeypatch):
    import httpx
    import paramiko

    attempts = []

    def reject(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("Synthetic session tests cannot access a network")

    async def reject_provider(*_args, **_kwargs):
        return reject()

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(paramiko.SSHClient, "connect", reject)
    monkeypatch.setattr(httpx.AsyncClient, "send", reject_provider)
    yield
    assert not attempts


def old_image(base):
    """Hash original defense rows including hidden rowids; never return their bytes."""
    h = hashlib.sha256()
    with closing(sqlite3.connect(base.path)) as db, db:
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'defense_%' "
            "AND name NOT LIKE 'defense_session%' ORDER BY name"
        ):
            quoted = '"' + name.replace('"', '""') + '"'
            h.update(name.encode())
            for row in db.execute("SELECT rowid,* FROM " + quoted + " ORDER BY rowid"):  # noqa: S608 -- quoted names from the owned SQLite catalog.
                h.update(repr(row).encode())
    return h.hexdigest()


@pytest.fixture
def session(harness):
    h = harness
    changed = h.coordinator.change_mode(ModeChange(mode=Mode.automatic, expected_revision=0))
    cursor = h.service.arm(
        "fixture", ArmRequest(expected_mode_revision=changed["revision"], confirm_arm=True)
    )
    h.service.query("fixture", cursor["request_id"])
    context = h.service._context("fixture")
    original = h.store.transaction(cursor["request_id"])
    source = h.store.cursor_source(original.rid, host_scope=scope_for(h.target.host.public))
    runtime = SessionRuntime(
        context=context,
        mode=SessionModeSnapshot.capture(h.service._snapshot()),
        host_scope=source.host_scope,
        enabled=True,
        stopping=False,
        mode_sync_complete=True,
        execution_authorized=True,
        observation_grant_ref=h.service.policy.observation.grant_ref,
        controller_grant_ref=h.service.policy.execution.grant_ref,
        root_grant_ref=h.service.policy.execution.root_grant_refs["fixture"],
        allowed_source_aliases=("fixture-a",),
        requires_ai=False,
        provider_fingerprint=None,
    )
    current, stopped = [runtime], [False]
    store = DefenseSessionStore(
        h.store,
        owner=h.service.owner,
        current_runtime=lambda _: current[0],
        stopped=lambda: stopped[0],
    )
    lease = h.store.acquire_worker(h.service.owner, expires_at=original.deadline_at, now=NOW)
    assert lease is not None
    declaration = SessionDeclaration(
        session_ref="1" * 32,
        cursor_rid=original.rid,
        boot_owner=h.service.owner,
        worker_epoch=lease.epoch,
        runtime=runtime,
        source=source,
        arm_request_sha256=h.store.request_metadata(original.rid, "arm").request_sha256,
        controller_created_at=original.created_at,
        controller_deadline_at=original.deadline_at,
    )
    return SimpleNamespace(
        h=h, store=store, declaration=declaration, lease=lease, current=current, stopped=stopped
    )


def admission(s, phase):
    return s.store.admit(s.declaration.session_ref, s.lease, expected_phase=phase, now=s.h.clock[0])


def observing(s):
    s.store.declare(s.declaration, now=NOW)
    a = admission(s, "declared")
    s.store.advance(a, next_phase="observing", now=NOW)
    a = admission(s, "observing")
    selection = s.store.select_source(a, s.declaration.source, SOURCE, EVIDENCE, now=NOW)
    return a, selection


def preparing(s):
    a, _ = observing(s)
    s.store.advance(a, next_phase="preparing", now=NOW)
    a = admission(s, "preparing")
    action = s.h.store.create_transaction(
        kind="action",
        context=s.declaration.runtime.context,
        owner=s.h.service.owner,
        cursor_rid=s.declaration.cursor_rid,
        deadline_at=s.declaration.controller_deadline_at,
        now=NOW,
        session_admission=a,
    )
    s.store.bind_action(a, action.rid, now=NOW)
    body = PrepareBody(
        cursor_id=s.h.root.records[s.declaration.cursor_rid]["cursor_id"],
        source_ref=SOURCE,
        evidence_sha256=EVIDENCE,
        policy_sha256=action.context.policy_sha256,
        mode="auto",
        mode_revision=action.context.wire_revision,
        controller_grant_ref=s.declaration.runtime.controller_grant_ref,
        root_grant_ref=s.declaration.runtime.root_grant_ref,
    )
    request = DefenseRequest(
        v=1, op="prepare", request_id=action.rid, scope_sha256=action.context.root_scope, body=body
    )
    s.store.bind_request(a, request, now=NOW)
    return a, action, request


def test_declaration_is_once_bound_to_current_explicit_arm_and_same_boot(session):
    s = session
    before, rpc = old_image(s.h.store), tuple(s.h.root.sent)
    first = s.store.declare(s.declaration, now=NOW)
    assert s.store.declare(s.declaration, now=NOW + timedelta(seconds=2)) == first
    with pytest.raises(DefenseConflict):
        s.store.declare(s.declaration.model_copy(update={"session_ref": "2" * 32}), now=NOW)
    with pytest.raises(DefenseConflict):
        s.store.declare(s.declaration.model_copy(update={"arm_request_sha256": "f" * 64}), now=NOW)
    assert old_image(s.h.store) == before and tuple(s.h.root.sent) == rpc


@pytest.mark.parametrize("change", ["owner", "unarmed", "context", "source", "deadline", "ack"])
def test_declaration_cannot_mint_or_adopt_an_unrelated_cursor(session, change):
    s = session
    declaration = s.declaration
    if change == "owner":
        s.store.owner = "another-process"
    elif change == "unarmed":
        with s.h.store._write() as db:
            db.execute(
                "UPDATE defense_requests SET reply_sha256=NULL WHERE rid=? AND op='arm'",
                (declaration.cursor_rid,),
            )
    elif change == "context":
        s.current[0] = s.current[0].model_copy(update={"execution_authorized": False})
    elif change == "source":
        declaration = declaration.model_copy(
            update={"source": declaration.source.model_copy(update={"root_reply_sha256": "f" * 64})}
        )
    elif change == "deadline":
        declaration = declaration.model_copy(
            update={"controller_deadline_at": stamp(NOW + timedelta(seconds=119))}
        )
    else:
        with s.h.store._write() as db:
            db.execute("UPDATE defense_mode_ack SET status='pending'")
    with pytest.raises(DefenseConflict):
        s.store.declare(declaration, now=NOW)


def test_phase_cas_and_process_local_admission_are_not_replayable(session):
    s = session
    s.store.declare(s.declaration, now=NOW)
    old = admission(s, "declared")
    before = old_image(s.h.store)
    assert s.store.assert_live(old, now=NOW) is None
    assert old_image(s.h.store) == before
    s.store.advance(old, next_phase="observing", now=NOW)
    with pytest.raises(DefenseConflict):
        s.store.advance(old, next_phase="observing", now=NOW)
    other = DefenseSessionStore(
        DefenseStore(s.h.store.path),
        owner="new-boot",
        current_runtime=lambda _: s.current[0],
        stopped=lambda: False,
    )
    original = s.store.get(s.declaration.session_ref, now=NOW)
    reopened = other.get(s.declaration.session_ref, now=NOW)
    assert (
        reopened.effective_phase == "reconciliation_only"
        and reopened.declaration == original.declaration
    )
    with pytest.raises(DefenseConflict):
        other.admit(s.declaration.session_ref, s.lease, expected_phase="observing", now=NOW)
    with s.h.store._write() as db, pytest.raises(DefenseConflict):
        other.atomic_assert(old, db, now=NOW)


@pytest.mark.parametrize(
    "changed", ["mode", "generation", "scope", "stop", "expiry", "clock", "lease"]
)
def test_atomic_assert_rechecks_current_runtime_and_lease_inside_receiver_write(session, changed):
    s = session
    s.store.declare(s.declaration, now=NOW)
    a = admission(s, "declared")
    now = NOW
    if changed == "mode":
        s.current[0] = s.current[0].model_copy(update={"execution_authorized": False})
    elif changed == "generation":
        s.current[0] = s.current[0].model_copy(update={"mode_sync_complete": False})
    elif changed == "scope":
        s.current[0] = s.current[0].model_copy(update={"host_scope": "f" * 64})
    elif changed == "stop":
        s.stopped[0] = True
    elif changed == "expiry":
        now += timedelta(seconds=120)
    elif changed == "clock":
        now -= timedelta(microseconds=1)
    else:
        s.h.store.release_worker(s.lease, now=NOW)
        assert s.h.store.acquire_worker(
            "new-owner", expires_at=stamp(NOW + timedelta(seconds=60)), now=NOW
        )
    before = old_image(s.h.store)
    with s.h.store._write() as db, pytest.raises(DefenseConflict):
        s.store.atomic_assert(a, db, now=now)
    assert old_image(s.h.store) == before


def test_fence_rejects_wrong_database_and_nontransaction_connections(session, tmp_path):
    s = session
    s.store.declare(s.declaration, now=NOW)
    a = admission(s, "declared")
    with s.h.store._connection() as db, pytest.raises(DefenseConflict):
        s.store.atomic_assert(a, db, now=NOW)
    with closing(sqlite3.connect(tmp_path / "other.sqlite3")) as db, db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(DefenseConflict):
            s.store.atomic_assert(a, db, now=NOW)


def test_selected_source_is_immutable_and_current_counts_cannot_be_borrowed(session):
    s = session
    a, selected = observing(s)
    assert (
        s.store.select_source(
            a, s.declaration.source, SOURCE, EVIDENCE, now=NOW + timedelta(seconds=1)
        )
        == selected
    )
    root = s.h.root
    # A different durable accepted query may refresh time, but not the selected facts.
    # Construct the changed wire receipt using the fixture's ordinary query output.
    call = s.h.store.query_call(s.declaration.cursor_rid)
    result = root(s.h.target, call, "readonly")
    reply = result.reply
    candidate = reply.candidates[0].model_copy(update={"distinct_failure_ports": 6})
    reply = reply.model_copy(update={"candidates": (candidate,)})
    s.h.store.record_reply(
        s.declaration.cursor_rid, "query", reply, context=s.declaration.runtime.context, now=NOW
    )
    with s.h.store._write() as db, pytest.raises(DefenseConflict):
        s.store.atomic_assert(a, db, now=NOW)


def test_one_bound_action_and_original_prepare_apply_identity(session):
    s = session
    a, action, request = preparing(s)
    assert (
        s.store.bind_request(a, request, now=NOW).request_sha256
        == hashlib.sha256(request.wire_bytes()).hexdigest()
    )
    other = request.model_copy(
        update={"body": request.body.model_copy(update={"source_ref": "e" * 32})}
    )
    with pytest.raises(DefenseConflict):
        s.store.bind_request(a, other, now=NOW)
    s.h.store.save_request(action.rid, request, session_admission=a, now=NOW)
    usage = s.h.service._usage(action, s.h.service.policy.execution)
    assert s.h.store.begin_sendable(
        action.rid,
        "prepare",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=a,
        now=NOW,
    )
    ready = s.h.root(s.h.target, DefenseCall(request), "control")
    s.h.store.record_reply(
        action.rid, "prepare", ready.reply, context=action.context, now=NOW, session_admission=a
    )
    s.store.advance(a, next_phase="prepared", now=NOW)
    s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
    a = admission(s, "applying")
    apply = DefenseRequest(
        v=1,
        op="apply",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=ActionBody(manifest_sha256=s.h.store.manifest(action.rid).sha256, approval=None),
    )
    s.store.bind_request(a, apply, now=NOW)
    s.h.store.save_request(action.rid, apply, session_admission=a, now=NOW)
    assert s.h.store.begin_sendable(
        action.rid,
        "apply",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=a,
        now=NOW,
    )
    result = s.h.root(
        s.h.target,
        DefenseCall(
            apply, prepare_request=request, expected_manifest=s.h.store.manifest(action.rid)
        ),
        "control",
    )
    s.h.store.record_reply(
        action.rid, "apply", result.reply, context=action.context, now=NOW, session_admission=a
    )
    s.store.advance(a, next_phase="confirmed", now=NOW)
    before, rpc = old_image(s.h.store), tuple(s.h.root.sent)
    result = s.store.advance(admission(s, "confirmed"), next_phase="completed", now=NOW)
    assert result.phase == "completed" and result.business_verdict == "pending"
    assert old_image(s.h.store) == before and tuple(s.h.root.sent) == rpc


@pytest.mark.parametrize("reason", ["requested", "result_unknown", "deadline_elapsed"])
def test_halt_preserves_original_work_and_cannot_be_reopened(session, reason):
    s = session
    a, action, request = preparing(s)
    s.h.store.save_request(action.rid, request, session_admission=a, now=NOW)
    before, rpc = old_image(s.h.store), tuple(s.h.root.sent)
    result = s.store.halt(s.declaration.session_ref, reason=reason, now=NOW)
    assert result.phase == "reconciliation_only"
    assert s.store.halt(s.declaration.session_ref, reason="requested", now=NOW) == result
    with pytest.raises(DefenseConflict):
        s.store.advance(a, next_phase="prepared", now=NOW)
    assert old_image(s.h.store) == before and tuple(s.h.root.sent) == rpc


def test_required_ai_cannot_be_skipped_or_repriced(session):
    s = session
    runtime = s.current[0].model_copy(
        update={"requires_ai": True, "provider_fingerprint": "f" * 64}
    )
    s.current[0] = runtime
    s.declaration = s.declaration.model_copy(update={"runtime": runtime})
    a, selection = observing(s)
    with pytest.raises(DefenseConflict):
        s.store.advance(a, next_phase="preparing", now=NOW)
    s.store.advance(a, next_phase="analyzing", now=NOW)
    a = admission(s, "analyzing")
    key = intent_key(selection.source, SOURCE, "f" * 64)
    binding = SessionAIIntent(
        session_ref=s.declaration.session_ref,
        analysis_id=digest({"ssh_defense_analysis": key})[:32],
        intent_key=key,
        input_digest="8" * 64,
        provider_fingerprint="f" * 64,
        selection_sha256=digest(selection),
    )
    before = old_image(s.h.store)
    assert s.store.bind_ai(a, binding, now=NOW) == binding
    assert old_image(s.h.store) == before
    with pytest.raises(DefenseConflict):
        s.store.bind_ai(a, binding.model_copy(update={"input_digest": "9" * 64}), now=NOW)
    with pytest.raises(DefenseConflict):
        s.store.advance(a, next_phase="analysis_ready", now=NOW)
    aliases = AliasMap(
        aliases=(
            DefenseAlias(
                candidate_alias="candidate-1",
                evidence_alias="evidence-1",
                source_ref=SOURCE,
                evidence_sha256=EVIDENCE,
            ),
        )
    )
    source_key = digest({"source": digest(selection.source), "aliases": digest(aliases)})
    s.h.store.save_source(source_key, selection.source, alias_map=aliases)
    permit = s.h.store.begin_ai_usage(
        s.declaration.cursor_rid,
        source_key=source_key,
        context=runtime.context,
        owner=s.h.service.owner,
        usage=UsageClaim(
            intent_key=key,
            kind="ai",
            grant_ref=AI_BUDGET_REF,
            max_per_day=1,
            max_total=1,
            provider_fingerprint="f" * 64,
        ),
        analysis_id=binding.analysis_id,
        input_digest=binding.input_digest,
        now=NOW,
        session_admission=a,
    )
    result = AIResult(
        analysis_id=binding.analysis_id,
        intent_key=key,
        input_digest=binding.input_digest,
        provider_fingerprint="f" * 64,
        status="completed",
        proof_sha256=None,
        decision="propose_defense",
        source_ref=SOURCE,
        evidence_sha256=EVIDENCE,
        reason_code="evidence_sufficient",
    )
    result = result.model_copy(
        update={
            "proof_sha256": DefenseAIService._proof(
                result, permit, selection.source, runtime.context
            )
        }
    )
    s.h.store.save_ai_result(result, session_admission=a, now=NOW)
    old = old_image(s.h.store)
    s.store.advance(a, next_phase="analysis_ready", now=NOW)
    s.store.advance(admission(s, "analysis_ready"), next_phase="preparing", now=NOW)
    assert old_image(s.h.store) == old


def test_same_boot_cannot_resume_a_session_after_reacquiring_a_different_epoch(session):
    s = session
    s.store.declare(s.declaration, now=NOW)
    original = admission(s, "declared")
    s.h.store.release_worker(s.lease, now=NOW)
    fresh = s.h.store.acquire_worker(
        s.h.service.owner, expires_at=s.declaration.controller_deadline_at, now=NOW
    )
    assert fresh is not None and fresh.epoch > s.lease.epoch
    before = old_image(s.h.store)
    record = s.store.get(s.declaration.session_ref, now=NOW)
    assert record.phase == "declared" and record.effective_phase == "reconciliation_only"
    with pytest.raises(DefenseConflict):
        s.store.admit(s.declaration.session_ref, fresh, expected_phase="declared", now=NOW)
    with s.h.store._write() as db, pytest.raises(DefenseConflict):
        s.store.atomic_assert(original, db, now=NOW)
    assert old_image(s.h.store) == before


def test_same_epoch_explicit_renewal_can_keep_existing_admission_until_original_deadline(session):
    s = session
    shortened = stamp(NOW + timedelta(seconds=20))
    with s.h.store._write() as db:
        db.execute("UPDATE defense_worker_lease SET expires_at=?", (shortened,))
    s.lease = s.lease.model_copy(update={"expires_at": shortened})
    s.store.declare(s.declaration, now=NOW)
    a = admission(s, "declared")
    with s.h.store._write() as db:
        changed = db.execute(
            "UPDATE defense_worker_lease SET expires_at=? "
            "WHERE owner=? AND epoch=? AND expires_at=?",
            (s.declaration.controller_deadline_at, s.lease.owner, s.lease.epoch, shortened),
        ).rowcount
        assert changed == 1
    with s.h.store._write() as db:
        s.store.atomic_assert(a, db, now=NOW + timedelta(seconds=21))
    with s.h.store._write() as db, pytest.raises(DefenseConflict):
        s.store.atomic_assert(a, db, now=NOW + timedelta(seconds=120))
    assert (
        s.store.get(s.declaration.session_ref, now=NOW + timedelta(seconds=120)).effective_phase
        == "expired"
    )


def test_session_epoch_is_part_of_immutable_declaration_not_a_replaceable_row_field(session):
    s = session
    s.store.declare(s.declaration, now=NOW)
    before = old_image(s.h.store)
    with s.h.store._write() as db:
        db.execute("UPDATE defense_sessions_v1 SET worker_epoch=worker_epoch+1")
    with pytest.raises(DefenseConflict):
        s.store.get(s.declaration.session_ref, now=NOW)
    assert old_image(s.h.store) == before


def test_atomic_sidecar_binding_rolls_back_with_callers_cost_transaction(session):
    s = session
    runtime = s.current[0].model_copy(
        update={"requires_ai": True, "provider_fingerprint": "f" * 64}
    )
    s.current[0] = runtime
    s.declaration = s.declaration.model_copy(update={"runtime": runtime})
    a, selection = observing(s)
    s.store.advance(a, next_phase="analyzing", now=NOW)
    a = admission(s, "analyzing")
    key = intent_key(selection.source, SOURCE, "f" * 64)
    intent = SessionAIIntent(
        session_ref=s.declaration.session_ref,
        analysis_id=digest({"ssh_defense_analysis": key})[:32],
        intent_key=key,
        input_digest="8" * 64,
        provider_fingerprint="f" * 64,
        selection_sha256=digest(selection),
    )
    before = old_image(s.h.store)
    with pytest.raises(DefenseConflict), s.h.store._write() as db:
        s.store.bind_ai(a, intent, now=NOW, connection=db)
        raise DefenseConflict("Synthetic independent cost gate refused")
    assert s.store.get(s.declaration.session_ref, now=NOW).ai_intent is None
    assert old_image(s.h.store) == before


def test_session_declaration_does_not_accept_extra_authority_or_boolean_counters(session):
    s = session
    with pytest.raises(ValueError):
        SessionDeclaration.model_validate_json(
            canonical(s.declaration.model_copy(update={"max_actions": 2}))
        )
    document = s.declaration.model_dump(mode="json")
    document["unbounded_root_permission"] = True
    with pytest.raises(ValueError):
        SessionDeclaration.model_validate_json(canonical(document))
    document.pop("unbounded_root_permission")
    document["worker_epoch"] = True
    with pytest.raises(ValueError):
        SessionDeclaration.model_validate_json(canonical(document))


def test_empty_observation_can_wait_for_candidate_without_restarting_cursor_window(session):
    s = session
    cursor = s.declaration.cursor_rid
    initial = s.h.root(s.h.target, s.h.store.query_call(cursor), "readonly").reply
    s.h.store.record_reply(
        cursor,
        "query",
        initial.model_copy(update={"candidates": ()}),
        context=s.declaration.runtime.context,
        now=NOW,
    )
    empty = s.h.store.cursor_source(cursor, host_scope=s.declaration.runtime.host_scope)
    assert empty.candidates == ()
    s.declaration = s.declaration.model_copy(update={"source": empty})
    original = s.store.declare(s.declaration, now=NOW)
    s.store.advance(admission(s, "declared"), next_phase="observing", now=NOW)
    s.h.service.query("fixture", cursor)
    later = s.h.store.cursor_source(cursor, host_scope=s.declaration.runtime.host_scope)
    assert later.candidates
    selection = s.store.select_source(admission(s, "observing"), later, SOURCE, EVIDENCE, now=NOW)
    retained = s.store.get(s.declaration.session_ref, now=NOW)
    assert (
        retained.declaration == original.declaration
        and retained.declaration.source.candidates == ()
    )
    assert (
        selection.source == later
        and retained.declaration.controller_deadline_at
        == original.declaration.controller_deadline_at
    )
