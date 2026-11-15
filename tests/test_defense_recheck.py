"""Real defense/run ledgers and bounded fake Root; no real network or credentials."""

from dataclasses import replace
from datetime import timedelta
from threading import Lock
from types import SimpleNamespace

import pytest
from test_defense_api import EVIDENCE, NOW, SOURCE, FakeRoot, policy
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.automation_store import AutomationStore, ModeChange
from opsark.baselines import scope_for
from opsark.business_readiness import (
    BusinessCheckResult,
    BusinessReadiness,
    ReadinessStatus,
    business_profile_digest,
)
from opsark.config import Settings
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_api import (
    ApplyRequest,
    ArmRequest,
    DefenseService,
    PrepareRequest,
    RevokeRequest,
    defense_service_scope,
)
from opsark.defense_models import digest, utc
from opsark.defense_recheck import DefenseRecheckService
from opsark.defense_recheck_api import DefenseRecheckInterrupt, DefenseRecheckRequest
from opsark.defense_recheck_models import ActionBusinessProfile
from opsark.defense_recheck_store import DefenseRecheckStore
from opsark.defense_store import DefenseConflict, DefenseRecheck, DefenseStore
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope
from opsark.models import BusinessCheck, CheckResult


@pytest.fixture
def environment(tmp_path, target, monkeypatch):
    def create(*, mode=Mode.assisted, legacy=False, apply_action=True, lose_apply=False):
        registered = (
            BusinessCheck(
                id="private_canary_a",
                domain="business-canary.invalid",
                port=80,
                path="/private-canary",
                expected_body_sha256="9" * 64,
                read_only_confirmed=True,
            ),
            BusinessCheck(
                id="private_canary_b",
                domain="business-canary.invalid",
                port=80,
                path="/other-canary",
                expected_body_sha256="8" * 64,
                read_only_confirmed=True,
            ),
        )
        host = replace(
            target.host,
            public=target.host.public.model_copy(
                update={
                    "trusted_hosts_digest": target.readonly.trusted_hosts_digest,
                }
            ),
            business_checks=registered,
        )
        current_target = replace(target, host=host)
        clock = [NOW]
        deployment = policy(current_target)
        scope = defense_service_scope({"fixture": current_target}, deployment)
        assert scope is not None
        registration = ModeParticipant("ssh-defense", scope, lambda _: False)
        automation = AutomationStore(
            tmp_path / "mode.sqlite3",
            ControlPolicy(),
            supplemental_scope=supplemental_scope((registration,)),
        )
        base = DefenseStore(tmp_path / "security.sqlite3")
        ledger = DefenseRecheckStore(base)
        root = FakeRoot(current_target, lambda: clock[0])
        controller = DefenseService(
            Settings(tmp_path, "newfake-recheck-only-token"),
            {"fixture": current_target},
            base,
            automation,
            policy=deployment,
            mode_lock=Lock(),
            invoker=root,
            clock=lambda: clock[0],
        )
        if not legacy:
            original = base.save_request

            def save_and_seal(rid, request):
                result = original(rid, request)
                if request.op == "prepare":
                    transaction = base.transaction(rid)
                    ledger.seal_action_profile(
                        ActionBusinessProfile(
                            rid=rid,
                            context_sha256=digest(transaction.context),
                            prepare_request_sha256=result.request_sha256,
                            host_scope=scope_for(host.public),
                            business_profile_sha256=business_profile_digest(host),
                            check_ids=tuple(check.id for check in host.business_checks),
                            sealed_at=transaction.created_at,
                        )
                    )
                return result

            monkeypatch.setattr(base, "save_request", save_and_seal)
        participant = controller.participant()
        assert participant is not None
        coordinator = ModeCoordinator(automation, controller.mode_lock, (participant,))
        rev = coordinator.change_mode(ModeChange(mode=mode, expected_revision=0))["revision"]
        cursor = controller.arm("fixture", ArmRequest(expected_mode_revision=rev, confirm_arm=True))
        action = controller.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=cursor["request_id"],
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=rev,
            ),
        )
        if apply_action:
            if lose_apply:
                root.lose = "apply"
            if mode == Mode.automatic:
                controller.automatic_apply(
                    "fixture", action["request_id"], expected_mode_revision=rev
                )
            else:
                controller.apply(
                    "fixture",
                    action["request_id"],
                    ApplyRequest(
                        expected_manifest_sha256=action["manifest"]["sha256"],
                        expected_mode_revision=rev,
                        confirm_execute=True,
                    ),
                )
        states: list[ReadinessStatus] = ["passed", "passed"]
        collected = []

        def collector(registered_host):
            assert controller.mode_lock.acquire(blocking=False)
            controller.mode_lock.release()
            collected.append(registered_host.public.id)
            rows = []
            for check, state in zip(registered_host.business_checks, states, strict=True):
                rows.append(
                    BusinessCheckResult(
                        id=check.id,
                        status=state,
                        http_status=503
                        if state == "failed"
                        else 200
                        if state == "passed"
                        else None,
                        status_matches=False
                        if state == "failed"
                        else True
                        if state == "passed"
                        else None,
                        body_matches=True if state == "passed" else None,
                    )
                )
            overall = next(
                (
                    state
                    for state in ("failed", "inconclusive", "uncovered", "passed")
                    if state in states
                ),
                "uncovered",
            )
            return BusinessReadiness(host_id="fixture", status=overall, checks=rows)

        service = DefenseRecheckService(
            controller, {"fixture": host}, ledger, collector=collector, clock=lambda: clock[0]
        )
        body = DefenseRecheckRequest(
            run_ref="a" * 32,
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_profile_sha256=business_profile_digest(host),
            confirm_recheck=True,
        )
        return SimpleNamespace(
            service=service,
            ledger=ledger,
            base=base,
            root=root,
            controller=controller,
            host=host,
            clock=clock,
            states=states,
            collected=collected,
            rid=action["request_id"],
            body=body,
            coordinator=coordinator,
            revision=rev,
        )

    return create


@pytest.mark.parametrize(
    "mode,authority", [(Mode.assisted, "human_approval"), (Mode.automatic, "preauthorization")]
)
def test_real_task_authority_exact_queries_and_business_receipts_close(
    environment, mode, authority
):
    h = environment(mode=mode)
    before = tuple(h.root.sent)
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == result["current_verdict"] == "passed"
    assert result["projection"]["authority_kind"] == authority
    assert h.collected == ["fixture"]
    assert tuple(h.root.sent[len(before) :]) == (("query", h.rid), ("query", h.rid))
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None and saved.claim is not None
    assert saved.result.root_before.sequence > saved.claim.observation_sequence
    assert saved.result.root_after.sequence > saved.result.root_before.sequence
    assert not h.controller.automation.policy.enabled


@pytest.mark.parametrize(
    "states,verdict",
    [
        (["passed", "inconclusive"], "pending"),
        (["failed", "inconclusive"], "failed"),
        (["passed", "uncovered"], "pending"),
    ],
)
def test_business_failure_and_incomplete_are_distinct(environment, states, verdict):
    h = environment()
    h.states[:] = states
    assert h.service.start("fixture", h.rid, h.body)["historical_verdict"] == verdict


def test_duplicate_post_and_new_process_never_collect_same_run_again(environment):
    h = environment()
    first = h.service.start("fixture", h.rid, h.body)
    before = tuple(h.root.sent)
    again = DefenseRecheckService(
        h.controller,
        {},
        DefenseRecheckStore(DefenseStore(h.base.path)),
        collector=lambda _: pytest.fail("replayed collector"),
        clock=lambda: h.clock[0],
    )
    second = again.start("fixture", h.rid, h.body)
    assert second["run_ref"] == first["run_ref"] and second["historical_verdict"] == "passed"
    assert h.collected == ["fixture"] and tuple(h.root.sent) == before
    with pytest.raises(DefenseConflict):
        again.start(
            "fixture", h.rid, h.body.model_copy(update={"expected_profile_sha256": "0" * 64})
        )


def test_missing_original_profile_does_not_backfill_or_green(environment):
    h = environment(legacy=True)
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert result["projection"]["business_verdict"] == "passed"
    assert "original_profile_missing" in result["projection"]["reasons"]
    assert h.ledger.action_profile(h.rid) is None


def test_missing_apply_authority_cannot_green_even_if_business_passes(environment):
    h = environment(apply_action=False)
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert result["projection"]["authority_kind"] == "unproven"


def test_history_and_export_are_local_after_retirement_and_new_unknown(environment):
    h = environment()
    result = h.service.start("fixture", h.rid, h.body)
    context = h.base.transaction(h.rid).context
    h.base.record_unavailable(h.rid, "query", context=context, now=h.clock[0])
    h.service.hosts = {}
    h.controller.targets = {}
    h.service.collector = lambda _: pytest.fail("GET opened business SSH")
    h.controller.invoker = lambda *_args, **_kwargs: pytest.fail("GET queried Root")
    selected = h.service.get("fixture", h.rid, h.body.run_ref)
    assert selected["historical_verdict"] == "passed" and selected["current_verdict"] == "pending"
    assert result["historical_verdict"] == "passed"
    assert h.service.list("fixture", h.rid)["runs"]
    rendered = h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)
    for private in (
        h.rid,
        h.body.run_ref,
        "private_canary",
        "business-canary",
        "/private-canary",
        h.controller.settings.token,
    ):
        assert private not in rendered
    assert "当前验收：待验收" in rendered
    assert "所选历史复验：登记业务复验通过" in rendered


def test_no_selected_historical_run_is_always_pending(environment):
    h = environment()
    h.service.start("fixture", h.rid, h.body)
    assert "当前验收：待验收" in h.service.handoff("fixture", h.rid)


def test_default_missing_collector_is_unavailable_and_can_run_false(environment):
    h = environment()
    h.service.collector = None
    assert h.service.list("fixture", h.rid)["can_run"] is False
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending" and h.collected == []


def test_actual_body_free_timeout_receipt_is_incomplete_not_failed(environment, monkeypatch):
    from opsark import business_readiness

    h = environment()

    def receipts(host, commands):
        assert tuple(commands) == tuple("business_" + row.id for row in host.business_checks)
        return {
            name: CheckResult(
                name=name,
                status="ok",
                exit_code=0,
                stdout="OPSARK_HTTP_READINESS_V1 inconclusive\n",
            )
            for name in commands
        }

    monkeypatch.setattr(business_readiness, "collect_business_receipts", receipts)
    h.service.collector = business_readiness.run_business_readiness
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert all(row["status"] == "inconclusive" for row in result["projection"]["checks"])


def test_natural_root_ttl_expiry_is_separate_from_business_passed(environment):
    h = environment()
    original = h.service.collector

    def expires(host):
        assert original is not None
        result = original(host)
        h.clock[0] += timedelta(seconds=61)
        h.root.records[h.rid]["state"] = "expired"
        return result

    h.service.collector = expires
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "passed"
    # The historical evidence may close across TTL expiry, while a collection
    # longer than the current business freshness budget cannot stay current.
    assert result["current_verdict"] == "pending"
    assert result["projection"]["root_before"] == "active"
    assert result["projection"]["root_after"] == "expired"
    assert result["projection"]["transition"] == "ttl_elapsed"
    assert "已到期，不代表仍在阻断" in h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)


def test_failed_before_query_cannot_borrow_old_last_confirmed(environment):
    h = environment(mode=Mode.automatic)
    h.root.lose = "query"
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert result["projection"]["root_before"] == "unavailable"
    assert h.base.last_confirmed(h.rid).state == "active"


def test_old_unknown_reconciled_by_this_runs_queries_remains_latched(environment):
    h = environment()
    context = h.base.transaction(h.rid).context
    h.base.record_unavailable(h.rid, "apply", context=context, now=h.clock[0])
    assert h.base.latched("fixture", context.defense_scope)
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "passed"
    assert h.base.latched("fixture", context.defense_scope)


def test_clock_rollback_preserves_real_times_and_pending(environment):
    h = environment()
    original = h.service.collector

    def rollback(host):
        assert original is not None
        result = original(host)
        h.clock[0] -= timedelta(seconds=1)
        return result

    h.service.collector = rollback
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None
    assert utc(saved.result.finished_at) < utc(saved.result.started_at)
    assert "time_unverified" in result["projection"]["reasons"]


def test_claimed_crash_is_not_replayed_and_is_visible_outside_page(environment, monkeypatch):
    h = environment()

    def crash(*_args):
        raise SystemExit("newfake process crash after durable claim")

    monkeypatch.setattr(h.service, "_query", crash)
    with pytest.raises(SystemExit):
        h.service.start("fixture", h.rid, h.body)
    assert h.collected == []
    original = tuple(h.root.sent)
    again = DefenseRecheckService(
        h.controller,
        {"fixture": h.host},
        h.ledger,
        collector=lambda _: pytest.fail("replayed unknown collection"),
        clock=lambda: h.clock[0],
    )
    result = again.start("fixture", h.rid, h.body)
    assert result["status"] == "claimed" and result["current_verdict"] == "pending"
    assert tuple(h.root.sent) == original
    page = again.list("fixture", h.rid, after_sequence=999)
    assert page["runs"] == [] and page["can_run"] is False
    assert page["active_run_ref"] == h.body.run_ref and page["active_request_id"] == h.rid
    with pytest.raises(DefenseConflict):
        again.start("fixture", h.rid, h.body.model_copy(update={"run_ref": "b" * 32}))
    assert tuple(h.root.sent) == original


def test_profile_change_during_collection_cannot_green(environment):
    h = environment()
    original = h.service.collector

    def changes_profile(host):
        assert original is not None
        result = original(host)
        h.service.hosts = {"fixture": replace(h.host, business_checks=h.host.business_checks[:1])}
        return result

    h.service.collector = changes_profile
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert "profile_changed" in result["projection"]["reasons"]


def test_current_manual_mode_does_not_disable_readonly_original_task_recheck(environment):
    h = environment()
    h.coordinator.change_mode(ModeChange(mode=Mode.manual, expected_revision=h.revision))
    before = tuple(h.root.sent)
    assert h.service.start("fixture", h.rid, h.body)["historical_verdict"] == "passed"
    assert tuple(h.root.sent[len(before) :]) == (("query", h.rid), ("query", h.rid))


def test_real_api_and_renderer_use_the_same_stored_run(environment):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from opsark.defense_recheck_api import register_defense_recheck_routes

    h = environment()
    app = FastAPI()
    register_defense_recheck_routes(app, h.service, [])
    client = TestClient(app)
    prefix = f"/api/hosts/fixture/ssh-defense/transactions/{h.rid}"
    response = client.post(prefix + "/rechecks", json=h.body.model_dump(mode="json"))
    assert response.status_code == 200 and response.json()["historical_verdict"] == "passed"
    assert response.headers["cache-control"] == "no-store"
    assert client.get(prefix + "/rechecks/" + h.body.run_ref).json()["run_ref"] == h.body.run_ref
    assert "登记业务复验通过" in client.get(prefix + "/handoff?run_ref=" + h.body.run_ref).text
    assert len(h.collected) == 1


def test_pin_change_before_run_opens_no_network_or_collection(environment):
    h = environment()
    before = tuple(h.root.sent)
    h.host.known_hosts_file.write_text("newfake-public-pin-canary")
    with pytest.raises(DefenseConflict):
        h.service.start("fixture", h.rid, h.body)
    assert tuple(h.root.sent) == before and h.collected == []
    assert h.ledger.get(h.body.run_ref) is None


def test_public_pin_change_during_collection_seals_pending(environment):
    h = environment()
    original = h.service.collector

    def changes_pin(host):
        assert original is not None
        result = original(host)
        h.host.known_hosts_file.write_text("newfake-changed-public-pin-canary")
        return result

    h.service.collector = changes_pin
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    assert "scope_changed" in result["projection"]["reasons"]
    assert "canary" not in h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)


def test_changed_original_physical_scope_is_refused_before_collection(environment):
    h = environment()
    h.service.hosts = {
        "fixture": replace(
            h.host, public=h.host.public.model_copy(update={"address": "192.0.2.99"})
        )
    }
    before = tuple(h.root.sent)
    with pytest.raises(DefenseConflict):
        h.service.start("fixture", h.rid, h.body)
    assert tuple(h.root.sent) == before and not h.collected


def test_claim_commit_failure_is_zero_collection_and_same_run_read_only(environment, monkeypatch):
    h = environment()
    original = h.ledger.claim

    def fail_claim(*args, **kwargs):
        def refused(_connection):
            raise OSError("newfake-commit-canary")

        monkeypatch.setattr(h.base, "_commit", refused)
        return original(*args, **kwargs)

    monkeypatch.setattr(h.ledger, "claim", fail_claim)
    before = tuple(h.root.sent)
    with pytest.raises(OSError):
        h.service.start("fixture", h.rid, h.body)
    assert not h.collected and tuple(h.root.sent) == before
    stored = h.ledger.get(h.body.run_ref)
    assert stored is not None and stored.status == "pending"
    assert h.service.start("fixture", h.rid, h.body)["status"] == "pending"
    assert not h.collected and tuple(h.root.sent) == before


def test_view_ages_out_current_acceptance_without_rewriting_historical_result(environment):
    h = environment()
    result = h.service.start("fixture", h.rid, h.body)
    h.clock[0] += timedelta(seconds=31)
    view = h.service.get("fixture", h.rid, h.body.run_ref)
    assert result["historical_verdict"] == view["historical_verdict"] == "passed"
    assert view["current_verdict"] == "pending"
    assert h.ledger.get(h.body.run_ref).result.verdict == "passed"


def test_explicit_interrupt_releases_only_old_read_lease_and_fences_late_owner(
    environment, monkeypatch
):
    h = environment()
    original_query = h.service._query

    def crash(*_args):
        raise SystemExit("newfake run owner died")

    monkeypatch.setattr(h.service, "_query", crash)
    with pytest.raises(SystemExit):
        h.service.start("fixture", h.rid, h.body)
    old = h.ledger.get(h.body.run_ref)
    assert old is not None and old.claim is not None
    body = DefenseRecheckInterrupt(
        expected_declaration_sha256=old.declaration_sha256, confirm_interrupt=True
    )
    before = tuple(h.root.sent)
    h.clock[0] = NOW - timedelta(seconds=1)
    with pytest.raises(DefenseConflict):
        h.service.interrupt("fixture", h.rid, h.body.run_ref, body)
    h.clock[0] = NOW + timedelta(seconds=119.999999)
    assert h.service.get("fixture", h.rid, h.body.run_ref)["can_interrupt"] is False
    with pytest.raises(DefenseConflict):
        h.service.interrupt("fixture", h.rid, h.body.run_ref, body)
    h.clock[0] = NOW + timedelta(seconds=120)
    assert h.service.get("fixture", h.rid, h.body.run_ref)["can_interrupt"] is True
    with pytest.raises(DefenseConflict):
        h.service.interrupt(
            "fixture",
            h.rid,
            h.body.run_ref,
            body.model_copy(update={"expected_declaration_sha256": "0" * 64}),
        )
    closed = h.service.interrupt("fixture", h.rid, h.body.run_ref, body)
    assert closed["status"] == "interrupted" and closed["historical_verdict"] == "pending"
    assert closed["projection"]["reasons"] == ["interrupted"]
    assert tuple(h.root.sent) == before and h.collected == []
    assert h.service.start("fixture", h.rid, h.body)["status"] == "interrupted"
    assert h.ledger.active_run("fixture") is None
    monkeypatch.setattr(h.service, "_query", original_query)
    h.root.records[h.rid]["state"] = "expired"
    next_body = h.body.model_copy(update={"run_ref": "b" * 32})
    new = h.service.start("fixture", h.rid, next_body)
    assert new["historical_verdict"] == "passed" and h.collected == ["fixture"]
    sealed = h.ledger.get(next_body.run_ref)
    assert sealed is not None and sealed.result is not None
    with pytest.raises(DefenseConflict):
        h.ledger.finish(old.claim, sealed.result.model_copy(update={"run_ref": h.body.run_ref}))
    assert h.ledger.get(h.body.run_ref).result is None


def test_bare_legacy_record_is_discoverable_but_never_business_green(environment):
    h = environment()
    authority = h.base.approval_record(h.rid)
    assert authority is not None
    context = h.base.transaction(h.rid).context
    legacy = DefenseRecheck(
        recheck_id="e" * 32,
        report_id="f" * 32,
        rid=h.rid,
        manifest_sha256=h.body.expected_manifest_sha256,
        approval_id=authority.metadata.approval.approval_id,
        defense_scope=context.defense_scope,
        profile_sha256=h.body.expected_profile_sha256,
        started_at=authority.metadata.approval.approved_at,
        ended_at=authority.metadata.approval.approved_at,
        checks=("ok", "ok"),
    )
    h.base.save_recheck(legacy)
    before = tuple(h.root.sent)
    rows = h.service.legacy_list("fixture", h.rid)["legacy_rechecks"]
    assert len(rows) == 1 and rows[0]["legacy_id"] == legacy.recheck_id
    assert (
        rows[0]["v"] == 1
        and rows[0]["historical_verdict"] == rows[0]["current_verdict"] == "pending"
    )
    assert rows[0]["projection"]["checks"] == []
    assert "legacy_incomplete" in rows[0]["projection"]["reasons"]
    assert h.service.legacy_get("fixture", h.rid, legacy.recheck_id) == rows[0]
    assert "不能作为业务验收通过" in h.service.legacy_handoff("fixture", h.rid, legacy.recheck_id)
    with pytest.raises(DefenseConflict):
        h.service.get("fixture", h.rid, legacy.recheck_id)
    assert tuple(h.root.sent) == before and h.collected == []


def test_unaccepted_root_unknown_is_retained_from_this_exact_observation(environment):
    import json

    h = environment(mode=Mode.automatic)
    first = [True]

    def unknown_once(raw):
        if not first[0]:
            return raw
        first[0] = False
        value = json.loads(raw)
        value.update(state="unknown", remaining_ms=None, reason_code="result_unknown")
        from opsark.defense_models import canonical

        return canonical(value) + b"\n"

    h.root.break_reply = unknown_once
    result = h.service.start("fixture", h.rid, h.body)
    assert result["historical_verdict"] == "pending"
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None and saved.result.root_before is not None
    before = saved.result.root_before
    assert before.reply is not None and before.reply.state == "unknown"
    assert before.observation.accepted is False
    exact = h.base.observation_record(before.observation.observation_id)
    assert exact.observation == before.observation


@pytest.mark.parametrize(
    "change",
    [
        "pin_changed",
        "pin_missing",
        "root_retired",
        "root_scope",
        "root_boot",
        "root_binding",
        "role_identity",
    ],
)
def test_current_public_registration_drift_cannot_keep_historical_run_green(
    environment, monkeypatch, change
):
    import copy

    from opsark import defense_client, defense_recheck

    h = environment()
    first = h.service.start("fixture", h.rid, h.body)
    assert first["current_verdict"] == "passed"
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None
    original_bytes = saved.result.model_dump_json()
    original_hash = saved.result_sha256
    before_rpc = tuple(h.root.sent)
    if change == "pin_changed":
        h.host.known_hosts_file.write_bytes(b"newfake-public-pin-replaced\n")
    elif change == "pin_missing":
        h.host.known_hosts_file.unlink()
    elif change == "root_retired":
        h.controller.targets = {}
    else:
        target = copy.copy(h.controller.targets["fixture"])
        if change == "role_identity":
            credential = copy.copy(target.readonly)
            object.__setattr__(credential, "key_identity", "9" * 64)
            object.__setattr__(target, "readonly", credential)
        else:
            field = {
                "root_scope": "root_scope_sha256",
                "root_boot": "boot_ref",
                "root_binding": "binding_ref",
            }[change]
            object.__setattr__(target, field, "9" * 64)
        h.controller.targets["fixture"] = target
    original_read = defense_recheck._read_file

    def public_only(path, limit, *, private=True):
        assert private is False, "GET attempted to read private credential bytes"
        return original_read(path, limit, private=False)

    monkeypatch.setattr(defense_recheck, "_read_file", public_only)
    monkeypatch.setattr(defense_client, "_read_file", public_only)
    h.controller.invoker = lambda *_args, **_kwargs: pytest.fail("GET attempted Root RPC")
    result = h.service.get("fixture", h.rid, h.body.run_ref)
    assert result["historical_verdict"] == "passed" and result["current_verdict"] == "pending"
    assert "current_unverified" in result["projection"]["reasons"]
    rendered = h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)
    assert "当前验收：待验收" in rendered
    assert "所选历史复验：登记业务复验通过" in rendered
    stored = h.ledger.get(h.body.run_ref)
    assert stored is not None and stored.result is not None
    assert (
        stored.result.model_dump_json() == original_bytes and stored.result_sha256 == original_hash
    )
    assert tuple(h.root.sent) == before_rpc


def test_current_manual_and_disabled_expired_grants_do_not_change_readonly_acceptance(environment):
    h = environment()
    h.service.start("fixture", h.rid, h.body)
    h.controller.automation.change_mode(ModeChange(mode=Mode.manual, expected_revision=h.revision))
    grant = h.controller.policy.execution
    assert grant is not None
    expired = (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    h.controller.policy = h.controller.policy.model_copy(
        update={
            "enabled": False,
            "execution": grant.model_copy(update={"enabled": False, "expires_at": expired}),
        }
    )
    before = tuple(h.root.sent)
    assert h.service.get("fixture", h.rid, h.body.run_ref)["current_verdict"] == "passed"
    assert tuple(h.root.sent) == before


@pytest.mark.parametrize("states", [["failed", "passed"], ["inconclusive", "passed"]])
def test_newer_business_run_cannot_refresh_or_be_hidden_by_old_pass(environment, states):
    h = environment()
    old = h.service.start("fixture", h.rid, h.body)
    stored = h.ledger.get(h.body.run_ref)
    assert stored is not None and stored.result is not None
    original = stored.result.model_dump_json(), stored.result_sha256
    h.states[:] = states
    newer = h.service.start("fixture", h.rid, h.body.model_copy(update={"run_ref": "b" * 32}))
    assert newer["historical_verdict"] == ("failed" if "failed" in states else "pending")
    before = tuple(h.root.sent)
    selected = h.service.get("fixture", h.rid, h.body.run_ref)
    assert old["historical_verdict"] == selected["historical_verdict"] == "passed"
    assert selected["current_verdict"] == "pending"
    assert "newer_recheck" in selected["projection"]["reasons"]
    assert "当前验收：待验收" in h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None
    assert (saved.result.model_dump_json(), saved.result_sha256) == original
    assert tuple(h.root.sent) == before


def test_fresh_root_query_cannot_extend_old_business_receipt_lifetime(environment):
    h = environment()
    h.service.start("fixture", h.rid, h.body)
    h.clock[0] += timedelta(seconds=31)
    h.controller.query("fixture", h.rid)
    before = tuple(h.root.sent)
    selected = h.service.get("fixture", h.rid, h.body.run_ref)
    assert selected["historical_verdict"] == "passed" and selected["current_verdict"] == "pending"
    assert "current_unverified" in selected["projection"]["reasons"]
    assert tuple(h.root.sent) == before


@pytest.mark.parametrize("status", ["pending", "claimed", "interrupted"])
def test_any_newer_run_keeps_selected_old_acceptance_pending(environment, status):
    from opsark.defense_recheck_models import DefenseRecheckDeclaration

    h = environment()
    h.service.start("fixture", h.rid, h.body)
    declaration = DefenseRecheckDeclaration(
        run_ref="b" * 32,
        host_id="fixture",
        rid=h.rid,
        expected_manifest_sha256=h.body.expected_manifest_sha256,
        expected_profile_sha256=h.body.expected_profile_sha256,
    )
    h.ledger.create(declaration, now=h.clock[0])
    if status != "pending":
        h.ledger.claim(declaration.run_ref, owner="newfake-review-owner", now=h.clock[0])
    if status == "interrupted":
        h.clock[0] += timedelta(seconds=120)
        h.ledger.interrupt(
            declaration.run_ref, expected_declaration_sha256=declaration.sha256, now=h.clock[0]
        )
    before = tuple(h.root.sent)
    selected = h.service.get("fixture", h.rid, h.body.run_ref)
    assert selected["historical_verdict"] == "passed" and selected["current_verdict"] == "pending"
    assert "newer_recheck" in selected["projection"]["reasons"]
    assert tuple(h.root.sent) == before


@pytest.mark.parametrize("age,verdict", [(30, "passed"), (30.000001, "pending")])
def test_business_freshness_has_an_independent_exact_controller_boundary(environment, age, verdict):
    h = environment()
    h.service.start("fixture", h.rid, h.body)
    h.clock[0] += timedelta(seconds=age)
    h.controller.query("fixture", h.rid)
    assert h.service.get("fixture", h.rid, h.body.run_ref)["current_verdict"] == verdict


@pytest.mark.parametrize("later,verdict", [(3, "passed"), (3.000001, "pending"), (4, "pending")])
def test_slow_root_after_rpc_cannot_renew_completed_business_evidence(
    environment, monkeypatch, later, verdict
):
    from opsark import defense_client, defense_recheck

    h = environment()
    original = h.service.collector

    def collect_then_delay_after(host):
        assert original is not None
        business = original(host)

        def delay_root_after():
            h.clock[0] += timedelta(seconds=27)

        h.root.before_admit = delay_root_after
        return business

    h.service.collector = collect_then_delay_after
    first = h.service.start("fixture", h.rid, h.body)
    assert first["historical_verdict"] == first["current_verdict"] == "passed"
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None and saved.result.root_before is not None
    assert utc(saved.result.root_before.observation.observed_at) == NOW
    assert utc(saved.result.finished_at) == NOW + timedelta(seconds=27)
    immutable = saved.result.model_dump_json(), saved.result_sha256
    original_read = defense_recheck._read_file

    def public_only(path, limit, *, private=True):
        assert private is False, "GET attempted private credential content"
        return original_read(path, limit, private=False)

    monkeypatch.setattr(defense_recheck, "_read_file", public_only)
    monkeypatch.setattr(defense_client, "_read_file", public_only)
    h.clock[0] += timedelta(seconds=later)
    rpc_before = tuple(h.root.sent)
    view = h.service.get("fixture", h.rid, h.body.run_ref)
    assert view["historical_verdict"] == "passed" and view["current_verdict"] == verdict
    rendered = h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)
    if verdict == "pending":
        assert "当前验收：待验收" in rendered
    assert tuple(h.root.sent) == rpc_before
    original_run = h.ledger.get(h.body.run_ref)
    assert original_run is not None and original_run.result is not None
    assert (original_run.result.model_dump_json(), original_run.result_sha256) == immutable


@pytest.mark.parametrize(
    "mode,kind", [(Mode.assisted, "human_approval"), (Mode.automatic, "preauthorization")]
)
def test_customer_timeline_closes_original_apply_lost_receipt_query_and_business(
    environment, monkeypatch, mode, kind
):
    from opsark import defense_client, defense_recheck

    h = environment(mode=mode, lose_apply=True)
    h.clock[0] += timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    h.controller.revoke(
        "fixture",
        h.rid,
        RevokeRequest(
            expected_manifest_sha256=h.body.expected_manifest_sha256,
            expected_mode_revision=h.revision,
            confirm_revoke=True,
        ),
    )
    h.service.start("fixture", h.rid, h.body)
    saved = h.ledger.get(h.body.run_ref)
    assert saved is not None and saved.result is not None
    immutable = saved.result.model_dump_json(), saved.result_sha256
    original_read = defense_recheck._read_file

    def public_only(path, limit, *, private=True):
        assert private is False, "local timeline attempted private credential content"
        return original_read(path, limit, private=False)

    monkeypatch.setattr(defense_recheck, "_read_file", public_only)
    monkeypatch.setattr(defense_client, "_read_file", public_only)
    before = tuple(h.root.sent)
    projection = h.service.get("fixture", h.rid, h.body.run_ref)["projection"]
    assert projection["original_authority_kind"] == kind
    assert projection["original_authority_at"] is not None
    assert projection["execution_status"] == "confirmed"
    assert projection["execution_submitted_at"] is not None
    assert projection["execution_confirmed_at"] is not None
    assert projection["receipt_status"] == "unconfirmed"
    assert projection["receipt_unconfirmed_at"] is not None
    assert projection["reconciliation_status"] == "reconciled"
    assert projection["reconciled_at"] is not None
    assert projection["root_after"] == "revoked"
    rendered = h.service.handoff("fixture", h.rid, run_ref=h.body.run_ref)
    assert "原执行已由同一清单的可信生效回执确认" in rendered
    assert "曾有原任务回执未确认" in rendered
    assert "不能据此断定发生网络断线" in rendered
    assert "其后已查询原任务并完成状态对账" in rendered
    assert "已确认撤销" in rendered
    no_selection = h.service.handoff("fixture", h.rid)
    assert "当前验收：待验收" in no_selection
    assert "原执行已由同一清单的可信生效回执确认" in no_selection
    assert tuple(h.root.sent) == before
    after = h.ledger.get(h.body.run_ref)
    assert after is not None and after.result is not None
    assert (after.result.model_dump_json(), after.result_sha256) == immutable
    for private in (
        h.rid,
        h.body.run_ref,
        "private_canary",
        "business-canary",
        h.controller.settings.token,
    ):
        assert private not in rendered


def test_submitted_unknown_without_later_query_does_not_claim_execution_confirmation(environment):
    h = environment(lose_apply=True)
    before = tuple(h.root.sent)
    timeline = h.service._execution_timeline("fixture", h.rid)
    assert timeline["execution_status"] == "submitted"
    assert timeline["execution_confirmed_at"] is None
    assert timeline["receipt_status"] == "unconfirmed"
    assert timeline["reconciliation_status"] == "pending"
    rendered = h.service.handoff("fixture", h.rid)
    assert "原执行提交意图已记录，生效尚未确认" in rendered
    assert "原执行已由同一清单的可信生效回执确认" not in rendered
    assert tuple(h.root.sent) == before


def test_later_gap_cannot_be_closed_by_an_earlier_original_query(environment):
    h = environment(lose_apply=True)
    h.clock[0] += timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    h.service.start("fixture", h.rid, h.body)
    assert h.service._execution_timeline("fixture", h.rid)["reconciliation_status"] == "reconciled"
    h.clock[0] += timedelta(seconds=1)
    h.base.record_unavailable(
        h.rid, "query", context=h.base.transaction(h.rid).context, now=h.clock[0]
    )
    before = tuple(h.root.sent)
    result = h.service.get("fixture", h.rid, h.body.run_ref)
    assert result["historical_verdict"] == "passed" and result["current_verdict"] == "pending"
    assert result["projection"]["execution_status"] == "confirmed"
    assert result["projection"]["reconciliation_status"] == "pending"
    assert tuple(h.root.sent) == before


def test_revoked_query_is_not_a_substitute_for_an_original_active_receipt(environment):
    h = environment(mode=Mode.automatic, lose_apply=True)
    h.root.records[h.rid]["state"] = "revoked"
    h.clock[0] += timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    timeline = h.service._execution_timeline("fixture", h.rid)
    assert timeline["reconciliation_status"] == "reconciled"
    assert timeline["execution_status"] == "submitted"
    assert timeline["execution_confirmed_at"] is None
    assert "原执行已由同一清单的可信生效回执确认" not in h.service.handoff("fixture", h.rid)


def test_semantically_unaccepted_active_reply_is_an_unconfirmed_gap(environment):
    h = environment()
    h.clock[0] += timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    h.root.records[h.rid]["active_until"] += timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    rejected = h.base.latest_observation(h.rid)
    assert rejected is not None and rejected.observation.state == "active"
    assert rejected.observation.accepted is False and rejected.observation.reason == "ttl_increased"
    before = tuple(h.root.sent)
    timeline = h.service._execution_timeline("fixture", h.rid)
    assert timeline["receipt_status"] == "unconfirmed"
    assert timeline["reconciliation_status"] == "pending"
    assert "曾有原任务回执未确认" in h.service.handoff("fixture", h.rid)
    assert tuple(h.root.sent) == before
    h.root.records[h.rid]["active_until"] -= timedelta(seconds=1)
    h.controller.query("fixture", h.rid)
    assert h.service._execution_timeline("fixture", h.rid)["reconciliation_status"] == "reconciled"


def test_explicit_root_rejection_is_not_misreported_as_an_unknown_receipt(environment):
    h = environment()
    reply = h.base.latest_reply(h.rid)
    assert reply is not None
    rejected = reply.model_copy(
        update={
            "op": "query",
            "state": "rejected",
            "reason_code": "authorization_denied",
            "action_id": None,
            "cursor_id": None,
            "manifest_sha256": None,
            "deadline_at": None,
            "remaining_ms": None,
        }
    )
    observation = h.base.record_reply(
        h.rid, "query", rejected, context=h.base.transaction(h.rid).context, now=h.clock[0]
    )
    assert observation.accepted is False and observation.reason == "rejected"
    before = tuple(h.root.sent)
    timeline = h.service._execution_timeline("fixture", h.rid)
    assert timeline["receipt_status"] == "no_gap"
    assert tuple(h.root.sent) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "f" * 32),
        ("scope_sha256", "f" * 64),
        ("action_id", "f" * 32),
        ("cursor_id", "f" * 32),
        ("manifest_sha256", "f" * 64),
        ("mode", "auto"),
        ("mode_revision", 9),
    ],
)
def test_timeline_does_not_accept_a_partial_or_other_action_active_receipt(
    environment, monkeypatch, field, value
):
    from opsark.defense_recheck import digest_wire

    h = environment()
    original = h.base.latest_observation(h.rid)
    assert original is not None and original.reply is not None
    reply = original.reply.model_copy(update={field: value})
    observation = original.observation.model_copy(update={"receipt_sha256": digest_wire(reply)})
    forged = original.model_copy(update={"observation": observation, "reply": reply})
    monkeypatch.setattr(h.base, "observations", lambda _rid: (observation,))
    monkeypatch.setattr(h.base, "observation_record", lambda _id: forged)
    timeline = h.service._execution_timeline("fixture", h.rid)
    assert (
        timeline["execution_status"] != "confirmed" and timeline["execution_confirmed_at"] is None
    )
