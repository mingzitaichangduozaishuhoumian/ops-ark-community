"""Persistent session mutation fences; only temporary ledgers and synthetic Root."""

import hashlib
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from test_defense_api import EVIDENCE, NOW, SOURCE, stamp
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_store import admission, observing, old_image
from test_defense_session_store import no_network_or_provider as no_network_or_provider
from test_defense_session_store import session as session

from opsark.defense_ai import AI_BUDGET_REF, DefenseAIService, intent_key
from opsark.defense_models import (
    ActionBody,
    DefenseApproval,
    DefenseCall,
    DefenseRequest,
    PrepareBody,
    digest,
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


def sidecar_image(base):
    hasher = hashlib.sha256()
    with closing(sqlite3.connect(base.path)) as db, db:
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'defense_session%' ORDER BY name"
        ):
            quoted = '"' + name.replace('"', '""') + '"'
            hasher.update(name.encode())
            for row in db.execute("SELECT rowid,* FROM " + quoted + " ORDER BY rowid"):  # noqa: S608 -- quoted table names from the owned catalog.
                hasher.update(repr(row).encode())
    return hasher.hexdigest()


def images(s):
    return old_image(s.h.store), sidecar_image(s.h.store), tuple(s.h.root.sent)


def prepare_phase(s):
    observing(s)
    s.store.advance(admission(s, "observing"), next_phase="preparing", now=NOW)
    return admission(s, "preparing")


def new_action(s, sa=None, *, base=None):
    base = base or s.h.store
    options = {} if sa is None else {"session_admission": sa}
    return base.create_transaction(
        kind="action",
        context=s.declaration.runtime.context,
        owner=s.h.service.owner,
        cursor_rid=s.declaration.cursor_rid,
        deadline_at=s.declaration.controller_deadline_at,
        now=NOW,
        **options,
    )


def prepare_request(s, action):
    runtime = s.declaration.runtime
    return DefenseRequest(
        v=1,
        op="prepare",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=PrepareBody(
            cursor_id=s.h.root.records[s.declaration.cursor_rid]["cursor_id"],
            source_ref=SOURCE,
            evidence_sha256=EVIDENCE,
            policy_sha256=runtime.context.policy_sha256,
            mode="auto",
            mode_revision=runtime.context.wire_revision,
            controller_grant_ref=runtime.controller_grant_ref,
            root_grant_ref=runtime.root_grant_ref,
        ),
    )


def prepared_action(s):
    sa = prepare_phase(s)
    action = new_action(s, sa)
    request = prepare_request(s, action)
    base = s.h.store
    base.save_request(action.rid, request, session_admission=sa, now=NOW)
    usage = s.h.service._usage(action, s.h.service.policy.execution)
    permit = base.begin_sendable(
        action.rid,
        "prepare",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    assert permit is not None
    result = s.h.root(s.h.target, DefenseCall(request), "control")
    base.record_reply(
        action.rid, "prepare", result.reply, context=action.context, session_admission=sa, now=NOW
    )
    s.store.advance(sa, next_phase="prepared", now=NOW)
    return action, request


def active_action(s):
    action, prepared = prepared_action(s)
    s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
    sa = admission(s, "applying")
    base = s.h.store
    request = DefenseRequest(
        v=1,
        op="apply",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=ActionBody(manifest_sha256=base.manifest(action.rid).sha256, approval=None),
    )
    base.save_request(action.rid, request, session_admission=sa, now=NOW)
    permit = base.begin_sendable(
        action.rid,
        "apply",
        context=action.context,
        owner=action.owner,
        usage=s.h.service._usage(action, s.h.service.policy.execution),
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    assert permit is not None
    call = DefenseCall(
        request, prepare_request=prepared, expected_manifest=base.manifest(action.rid)
    )
    result = s.h.root(s.h.target, call, "control")
    base.record_reply(
        action.rid, "apply", result.reply, context=action.context, session_admission=sa, now=NOW
    )
    s.store.advance(sa, next_phase="confirmed", now=NOW)
    return action, request


def ai_phase(s):
    runtime = s.current[0].model_copy(
        update={"requires_ai": True, "provider_fingerprint": "f" * 64}
    )
    s.current[0] = runtime
    s.declaration = s.declaration.model_copy(update={"runtime": runtime})
    _, selected = observing(s)
    s.store.advance(admission(s, "observing"), next_phase="analyzing", now=NOW)
    sa = admission(s, "analyzing")
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
    source_key = digest({"source": digest(selected.source), "aliases": digest(aliases)})
    s.h.store.save_source(source_key, selected.source, alias_map=aliases)
    key = intent_key(selected.source, SOURCE, "f" * 64)
    args = {
        "source_key": source_key,
        "context": runtime.context,
        "owner": s.h.service.owner,
        "usage": UsageClaim(
            intent_key=key,
            kind="ai",
            grant_ref=AI_BUDGET_REF,
            max_per_day=1,
            max_total=1,
            provider_fingerprint="f" * 64,
        ),
        "analysis_id": digest({"ssh_defense_analysis": key})[:32],
        "input_digest": "8" * 64,
        "now": NOW,
    }
    return sa, selected, args


def ai_result(s, selected, permit):
    result = AIResult(
        analysis_id=permit.analysis_id,
        intent_key=permit.intent_key,
        input_digest=permit.input_digest,
        provider_fingerprint=permit.provider_fingerprint,
        status="completed",
        proof_sha256=None,
        decision="propose_defense",
        source_ref=SOURCE,
        evidence_sha256=EVIDENCE,
        reason_code="evidence_sufficient",
    )
    return result.model_copy(
        update={
            "proof_sha256": DefenseAIService._proof(
                result,
                permit,
                selected.source,
                s.declaration.runtime.context,
            )
        }
    )


def test_guard_registration_is_one_object_and_unbound_none_keeps_legacy(session):
    s = session
    assert s.h.store.require_session_admission(s.declaration.cursor_rid, None, now=NOW) is None
    s.h.store.register_session_guard(s.store)
    with pytest.raises(DefenseConflict):
        s.h.store.register_session_guard(object())
    with pytest.raises(DefenseConflict):
        s.h.store.require_session_admission(s.declaration.cursor_rid, object(), now=NOW)


def test_old_api_and_new_base_without_registered_guard_cannot_create_bound_action(session):
    s = session
    prepare_phase(s)
    before = images(s)
    for base in (s.h.store, DefenseStore(s.h.store.path)):
        with pytest.raises(DefenseConflict):
            new_action(s, base=base)
    assert images(s) == before


@pytest.mark.parametrize("wrong", ["phase", "guard", "owner", "epoch"])
def test_wrong_admission_cannot_create_action_or_consume_any_original_record(session, wrong):
    s = session
    observing(s)
    old = admission(s, "observing")
    s.store.advance(old, next_phase="preparing", now=NOW)
    sa = admission(s, "preparing")
    if wrong == "phase":
        sa = old
    elif wrong == "guard":
        other_base = DefenseStore(s.h.store.path)
        other = DefenseSessionStore(
            other_base,
            owner=s.h.service.owner,
            current_runtime=lambda _: s.current[0],
            stopped=lambda: False,
        )
        sa = other.admit(s.declaration.session_ref, s.lease, expected_phase="preparing", now=NOW)
    elif wrong == "owner":
        s.h.store.release_worker(s.lease, now=NOW)
        assert s.h.store.acquire_worker(
            "another-boot", expires_at=s.declaration.controller_deadline_at, now=NOW
        )
    else:
        s.h.store.release_worker(s.lease, now=NOW)
        assert s.h.store.acquire_worker(
            s.h.service.owner, expires_at=s.declaration.controller_deadline_at, now=NOW
        )
    before = images(s)
    with pytest.raises(DefenseConflict):
        new_action(s, sa)
    assert images(s) == before


def test_valid_prepare_is_bound_at_create_save_and_sendable_in_same_ledger(session):
    s = session
    sa = prepare_phase(s)
    action = new_action(s, sa)
    assert s.store.get(s.declaration.session_ref, now=NOW).action.rid == action.rid
    request = prepare_request(s, action)
    before = images(s)
    for base in (s.h.store, DefenseStore(s.h.store.path)):
        with pytest.raises(DefenseConflict):
            base.save_request(action.rid, request)
    assert images(s) == before
    s.h.store.save_request(action.rid, request, session_admission=sa, now=NOW)
    with s.h.store._connection() as db:
        binding = db.execute(
            "SELECT session_ref FROM defense_session_requests_v1 WHERE rid=? AND op='prepare'",
            (action.rid,),
        ).fetchone()
        assert binding[0] == s.declaration.session_ref
    usage = s.h.service._usage(action, s.h.service.policy.execution)
    before = images(s)
    with pytest.raises(DefenseConflict):
        s.h.store.begin_sendable(
            action.rid, "prepare", context=action.context, owner=action.owner, usage=usage, now=NOW
        )
    assert images(s) == before
    assert s.h.store.begin_sendable(
        action.rid,
        "prepare",
        context=action.context,
        owner=action.owner,
        usage=usage,
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    assert s.h.store.execution_usage(action.rid).state == "reserved"


def test_action_and_request_sidecars_roll_back_with_original_writes(session, monkeypatch):
    s = session
    sa = prepare_phase(s)
    before = images(s)
    original = s.store.bind_action

    def fail_after_binding(*args, **kwargs):
        original(*args, **kwargs)
        raise DefenseConflict("Synthetic action binding refusal")

    with monkeypatch.context() as patch:
        patch.setattr(s.store, "bind_action", fail_after_binding)
        with pytest.raises(DefenseConflict):
            new_action(s, sa)
    assert images(s) == before
    action = new_action(s, sa)
    request = prepare_request(s, action)
    before = images(s)
    original_request = s.store.bind_request

    def fail_request(*args, **kwargs):
        original_request(*args, **kwargs)
        raise DefenseConflict("Synthetic request binding refusal")

    with monkeypatch.context() as patch:
        patch.setattr(s.store, "bind_request", fail_request)
        with pytest.raises(DefenseConflict):
            s.h.store.save_request(action.rid, request, session_admission=sa, now=NOW)
    assert images(s) == before


def test_prepare_commit_failure_keeps_sidecars_and_execution_cost_unchanged(session, monkeypatch):
    s = session
    sa = prepare_phase(s)
    action = new_action(s, sa)
    request = prepare_request(s, action)
    s.h.store.save_request(action.rid, request, session_admission=sa, now=NOW)
    before = images(s)

    def refuse_commit(_connection):
        raise sqlite3.OperationalError("Synthetic durable boundary failure")

    with monkeypatch.context() as patch:
        patch.setattr(s.h.store, "_commit", refuse_commit)
        with pytest.raises(sqlite3.OperationalError):
            s.h.store.begin_sendable(
                action.rid,
                "prepare",
                context=action.context,
                owner=action.owner,
                usage=s.h.service._usage(action, s.h.service.policy.execution),
                lease=s.lease,
                session_admission=sa,
                now=NOW,
            )
    assert images(s) == before


@pytest.mark.parametrize("op", ["prepare", "apply"])
def test_bound_mutation_receivers_reject_old_calls_but_accept_original_admission(session, op):
    s = session
    if op == "prepare":
        sa = prepare_phase(s)
        action = new_action(s, sa)
        request = prepare_request(s, action)
        call = DefenseCall(request)
    else:
        action, prepare = prepared_action(s)
        s.store.advance(admission(s, "prepared"), next_phase="applying", now=NOW)
        sa = admission(s, "applying")
        request = DefenseRequest(
            v=1,
            op="apply",
            request_id=action.rid,
            scope_sha256=action.context.root_scope,
            body=ActionBody(manifest_sha256=s.h.store.manifest(action.rid).sha256, approval=None),
        )
        call = DefenseCall(
            request, prepare_request=prepare, expected_manifest=s.h.store.manifest(action.rid)
        )
    base = s.h.store
    base.save_request(action.rid, request, session_admission=sa, now=NOW)
    assert base.begin_sendable(
        action.rid,
        op,
        context=action.context,
        owner=action.owner,
        usage=s.h.service._usage(action, s.h.service.policy.execution),
        lease=s.lease,
        session_admission=sa,
        now=NOW,
    )
    result = s.h.root(s.h.target, call, "control")
    before = images(s)
    for receiver in (base, DefenseStore(base.path)):
        with pytest.raises(DefenseConflict):
            receiver.record_reply(action.rid, op, result.reply, context=action.context, now=NOW)
        with pytest.raises(DefenseConflict):
            receiver.record_unavailable(action.rid, op, context=action.context, now=NOW)
    assert images(s) == before
    observation = base.record_reply(
        action.rid, op, result.reply, context=action.context, session_admission=sa, now=NOW
    )
    assert observation.accepted


def test_ai_cost_is_bound_once_and_new_base_cannot_charge_without_registered_guard(session):
    s = session
    sa, selected, args = ai_phase(s)
    before = images(s)
    for base in (s.h.store, DefenseStore(s.h.store.path)):
        with pytest.raises(DefenseConflict):
            base.begin_ai_usage(s.declaration.cursor_rid, **args)
    assert images(s) == before
    permit = s.h.store.begin_ai_usage(s.declaration.cursor_rid, session_admission=sa, **args)
    binding = s.store.get(s.declaration.session_ref, now=NOW).ai_intent
    assert binding is not None and binding.analysis_id == permit.analysis_id
    assert binding.intent_key == permit.intent_key and binding.input_digest == permit.input_digest
    assert s.h.store.usage(permit.intent_key).state == "consumed"
    result = ai_result(s, selected, permit)
    before = images(s)
    with pytest.raises(DefenseConflict):
        DefenseStore(s.h.store.path).save_ai_result(result, now=NOW)
    assert images(s) == before
    s.h.store.save_ai_result(result, session_admission=sa, now=NOW)
    assert s.h.store.ai_result(permit.analysis_id) == result


def test_ai_binding_failure_rolls_back_permit_fee_and_sidecar(session, monkeypatch):
    s = session
    sa, _, args = ai_phase(s)
    before = images(s)
    original = s.store.bind_ai_permit

    def refuse_after_binding(*args, **kwargs):
        original(*args, **kwargs)
        raise DefenseConflict("Synthetic AI sidecar refusal")

    with monkeypatch.context() as patch:
        patch.setattr(s.store, "bind_ai_permit", refuse_after_binding)
        with pytest.raises(DefenseConflict):
            s.h.store.begin_ai_usage(s.declaration.cursor_rid, session_admission=sa, **args)
    assert images(s) == before


def test_late_ai_result_cannot_create_proof_latch_or_refund_after_owner_change(session):
    s = session
    sa, selected, args = ai_phase(s)
    permit = s.h.store.begin_ai_usage(s.declaration.cursor_rid, session_admission=sa, **args)
    result = ai_result(s, selected, permit)
    s.h.store.release_worker(s.lease, now=NOW)
    assert s.h.store.acquire_worker(
        "replacement", expires_at=s.declaration.controller_deadline_at, now=NOW
    )
    before = images(s)
    with pytest.raises(DefenseConflict):
        s.h.store.save_ai_result(result, session_admission=sa, now=NOW)
    assert images(s) == before and s.h.store.ai_result(permit.analysis_id) is None
    assert s.h.store.usage(permit.intent_key).state == "consumed"


def test_query_and_independent_exact_human_revoke_do_not_reuse_session_authority(session):
    s = session
    action, _ = active_action(s)
    base = s.h.store
    stale = admission(s, "confirmed")
    base.release_worker(s.lease, now=NOW)
    call = base.query_call(action.rid)
    result = s.h.root(s.h.target, call, "readonly")
    base.record_reply(action.rid, "query", result.reply, context=action.context, now=NOW)
    manifest = base.manifest(action.rid)
    approval = DefenseApproval(
        approval_id="a" * 32,
        purpose="revoke",
        request_id=action.rid,
        manifest_sha256=manifest.sha256,
        approved_at=stamp(NOW),
        expires_at=stamp(NOW + timedelta(seconds=60)),
    )
    grant = s.h.service.policy.execution
    base.save_approval(
        action.rid,
        approval,
        context=action.context,
        controller_grant_ref=grant.grant_ref,
        root_grant_ref=grant.root_grant_refs["fixture"],
        now=NOW,
    )
    request = DefenseRequest(
        v=1,
        op="revoke",
        request_id=action.rid,
        scope_sha256=action.context.root_scope,
        body=ActionBody(manifest_sha256=manifest.sha256, approval=approval),
    )
    before = images(s)
    with pytest.raises(DefenseConflict):
        base.save_request(action.rid, request, session_admission=stale)
    assert images(s) == before
    base.save_request(action.rid, request)
    assert base.begin_sendable(
        action.rid, "revoke", context=action.context, owner=action.owner, now=NOW
    )
    result = s.h.root(
        s.h.target,
        DefenseCall(
            request, prepare_request=base.request(action.rid, "prepare"), expected_manifest=manifest
        ),
        "control",
    )
    base.record_reply(action.rid, "revoke", result.reply, context=action.context, now=NOW)
    assert base.transaction(action.rid).phase == "revoked"
