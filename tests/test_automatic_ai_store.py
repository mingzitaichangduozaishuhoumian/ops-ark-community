"""Durable model-call intent, independent cost limits and terminal-event audit."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from test_automatic_store import NOW, candidate, reserve, result

from opsark import automatic_store as module
from opsark.automatic_store import AutomaticStore


def begin(store, index=1, **changes):
    fields = {
        "request_key": f"{index:064x}",
        "host_id": "server-a",
        "scope_hash": "a" * 64,
        "candidate_id": f"{index + 100:064x}",
        "grant_id": "b" * 32,
        "provider_fingerprint": "c" * 64,
        "analysis_id": f"{index:032x}",
        "input_digest": f"{index + 200:064x}",
        "owner": "d" * 32,
        "daily_limit": 5,
        "total_limit": 5,
        "now": NOW,
    }
    return store.begin_ai_request(**(fields | changes))


def reference(request):
    return {
        "analysis_id": request["analysis_id"],
        "analysis_digest": "e" * 64,
        "proposal_id": "f" * 32,
        "candidate_id": "candidate-1",
        "input_digest": request["input_digest"],
        "provider_fingerprint": request["provider_fingerprint"],
    }


def finish(store, request, status="completed", **changes):
    fields = {
        "status": status,
        "result_ref": reference(request) if status == "completed" else None,
        "detail": "Program-owned bounded outcome.",
        "now": NOW + timedelta(seconds=1),
    }
    return store.finish_ai_request(request["request_key"], request["owner"], **(fields | changes))


def bound_candidate(store, *, request_owner="d" * 32):
    value = candidate(store)
    request = begin(store, candidate_id=value["id"], owner=request_owner)
    finished = finish(store, request)
    proof = {"request_key": request["request_key"], **finished["result_ref"]}
    return value, request, proof


def test_intent_consumes_cost_once_and_returned_dispatch_never_persists(tmp_path):
    path = tmp_path / "automatic.db"
    store = AutomaticStore(path)
    request = begin(store)
    assert request["dispatch"] is True and request["status"] == "submission_intent"
    assert request["deadline_at"] == (NOW + timedelta(seconds=120)).isoformat()
    assert "dispatch" not in store.get_ai_request(request["request_key"], now=NOW)
    with sqlite3.connect(path) as connection:
        raw = connection.execute("SELECT payload FROM automatic_ai_requests").fetchone()[0]
        assert "dispatch" not in json.loads(raw)
    assert store.ai_quotas("server-a", "b" * 32, NOW) == {"daily_used": 1, "total_used": 1}
    assert len(store.ai_requests()) == 1
    assert store.list_attempts() == []


def test_restart_new_scan_scope_provider_owner_and_grant_cannot_rebind_the_same_key(tmp_path):
    path = tmp_path / "automatic.db"
    request = begin(AutomaticStore(path))
    restarted = AutomaticStore(path)
    duplicate = begin(
        restarted,
        scope_hash="f" * 64,
        provider_fingerprint="f" * 64,
        grant_id="f" * 32,
        input_digest="f" * 64,
        analysis_id="f" * 32,
        owner="f" * 32,
    )
    assert duplicate == request | {"dispatch": False}
    assert restarted.ai_quotas("server-a", "f" * 32, NOW) == {
        "daily_used": 1,
        "total_used": 0,
    }


def test_concurrent_claims_dispatch_once_and_do_not_share_an_owner(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda n: begin(store, owner=f"{n + 10:032x}"), range(8)))
    assert sum(value["dispatch"] for value in values) == 1
    assert len({value["owner"] for value in values}) == 1
    assert store.ai_quotas("server-a", "b" * 32, NOW)["daily_used"] == 1


def test_concurrent_distinct_requests_cannot_overdraw_daily_budget(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda n: begin(store, n + 1, daily_limit=1), range(8)))
    assert sum(value is not None for value in values) == 1
    assert store.ai_quotas("server-a", "b" * 32, NOW) == {"daily_used": 1, "total_used": 1}


@pytest.mark.parametrize("status", sorted(module.AI_TERMINAL))
def test_every_finished_or_unknown_request_keeps_its_independent_cost_and_identity(
    tmp_path, status
):
    store = AutomaticStore(tmp_path / "automatic.db")
    request = begin(store, daily_limit=1, total_limit=1)
    final = finish(store, request, status)
    assert final["status"] == status
    assert begin(store, 2, daily_limit=1) is None
    assert begin(store, 2, total_limit=1, now=NOW + timedelta(days=1)) is None
    assert begin(store, grant_id="e" * 32, now=NOW + timedelta(days=1))["dispatch"] is False
    assert store.ai_quotas("server-a", "b" * 32, NOW + timedelta(days=1)) == {
        "daily_used": 0,
        "total_used": 1,
    }


def test_daily_host_budget_crosses_grants_but_total_is_host_and_grant_specific(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    begin(store, daily_limit=1)
    assert begin(store, 2, grant_id="e" * 32, daily_limit=1) is None
    assert begin(store, 2, host_id="server-b", daily_limit=1) is not None
    assert begin(store, 3, grant_id="e" * 32, total_limit=1, now=NOW + timedelta(days=1))


def test_capacity_refuses_new_identities_and_never_discards_an_existing_intent(
    tmp_path, monkeypatch
):
    store = AutomaticStore(tmp_path / "automatic.db")
    monkeypatch.setattr(module, "MAX_AI_REQUESTS", 1)
    request = begin(store)
    assert begin(store, 2) is None
    assert begin(store)["dispatch"] is False
    assert store.get_ai_request(request["request_key"], now=NOW)["status"] == "submission_intent"


def test_deadline_turns_pending_into_unknown_and_late_completion_cannot_revive_it(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    request = begin(store)
    assert store.get_ai_request(request["request_key"], NOW + timedelta(seconds=119))["status"] == (
        "submission_intent"
    )
    expired = store.get_ai_request(request["request_key"], NOW + timedelta(seconds=120))
    assert expired["status"] == "unknown" and expired["result_ref"] is None
    late = finish(store, request, now=NOW + timedelta(seconds=121))
    assert late == expired
    assert begin(store, now=NOW + timedelta(seconds=122))["dispatch"] is False


def test_only_owner_finishes_once_and_cannot_replace_a_terminal_result(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    request = begin(store)
    with pytest.raises(ValueError):
        store.finish_ai_request(
            request["request_key"], "f" * 32, status="failed", detail="wrong owner", now=NOW
        )
    original = finish(store, request)
    assert finish(store, request, "failed") == original
    assert store.get_ai_request("0" * 64, now=NOW) is None


@pytest.mark.parametrize(
    "change",
    [
        {"analysis_id": "a" * 32},
        {"input_digest": "a" * 64},
        {"provider_fingerprint": "a" * 64},
        {"analysis_digest": "bad"},
        {"proposal_id": "bad"},
        {"candidate_id": "/root/value"},
        {"content": "raw model text"},
        {"reasoning_content": "private reasoning"},
    ],
)
def test_result_reference_accepts_only_exact_bound_metadata_without_model_text(tmp_path, change):
    store = AutomaticStore(tmp_path / "automatic.db")
    request = begin(store)
    with pytest.raises(ValueError):
        finish(store, request, result_ref=reference(request) | change)
    assert store.get_ai_request(request["request_key"], now=NOW)["status"] == "submission_intent"


@pytest.mark.parametrize("field", ["daily_limit", "total_limit"])
@pytest.mark.parametrize("bad", [0, 6, True, 1.0, "1"])
def test_invalid_model_cost_limits_never_create_an_intent(tmp_path, field, bad):
    store = AutomaticStore(tmp_path / "automatic.db")
    with pytest.raises(ValueError):
        begin(store, **{field: bad})
    assert store.ai_requests() == []


def test_analysis_identity_cannot_be_alias_charged_under_a_second_request_key(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    request = begin(store)
    with pytest.raises(sqlite3.IntegrityError):
        begin(store, 2, analysis_id=request["analysis_id"])
    assert store.ai_quotas("server-a", "b" * 32, NOW)["total_used"] == 1


def test_bind_requires_exact_completed_request_and_preserves_old_process_provenance(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    value, request, proof = bound_candidate(store, request_owner="e" * 32)
    linked = store.bind_ai_result(value["id"], value["owner"], proof, now=NOW)
    assert linked["ai_proof"] == proof and linked["state"] == "planning"
    assert store.get(value["id"])["ai_proof"] == proof
    assert store.get_ai_request(request["request_key"], now=NOW)["owner"] == "e" * 32
    assert store.bind_ai_result(value["id"], "f" * 32, proof, now=NOW) is None


@pytest.mark.parametrize("change", [{"analysis_digest": "f" * 64}, {"candidate_id": "candidate-2"}])
def test_different_model_proof_cannot_be_bound_or_override_existing_proof(tmp_path, change):
    store = AutomaticStore(tmp_path / "automatic.db")
    value, _request, proof = bound_candidate(store)
    assert store.bind_ai_result(value["id"], value["owner"], proof | change, now=NOW) is None
    assert "ai_proof" not in store.get(value["id"])


@pytest.mark.parametrize("status", ["submission_intent", "failed", "unknown", "refused", "stale"])
def test_incomplete_or_unsuccessful_model_result_never_authorizes_candidate_binding(
    tmp_path, status
):
    store = AutomaticStore(tmp_path / "automatic.db")
    value = candidate(store)
    request = begin(store, candidate_id=value["id"])
    if status != "submission_intent":
        finish(store, request, status)
    proof = {"request_key": request["request_key"], **reference(request)}
    assert store.bind_ai_result(value["id"], value["owner"], proof, now=NOW) is None


@pytest.mark.parametrize(
    "changed", [{"host_id": "server-b"}, {"scope_hash": "f" * 64}, {"grant_id": "e" * 32}]
)
def test_model_request_cannot_bind_across_candidate_host_scope_or_grant(tmp_path, changed):
    store = AutomaticStore(tmp_path / "automatic.db")
    value = candidate(store)
    request = begin(store, candidate_id=value["id"], **changed)
    final = finish(store, request)
    proof = {"request_key": request["request_key"], **final["result_ref"]}
    assert store.bind_ai_result(value["id"], value["owner"], proof, now=NOW) is None


def test_submitted_candidate_cannot_gain_model_proof_after_authorization(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    value, _request, proof = bound_candidate(store)
    reserve(store, value)
    assert store.bind_ai_result(value["id"], value["owner"], proof, now=NOW) is None


def test_alert_deduplication_and_acknowledgment_survive_restart_without_reopening(tmp_path):
    path = tmp_path / "automatic.db"
    store = AutomaticStore(path)
    alert = store.emit_ai_alert("server-a", "stable:event", "blocked", "Needs review", now=NOW)
    acknowledged = store.ack_ai_alert(alert["id"], NOW + timedelta(seconds=1))
    restarted = AutomaticStore(path)
    same = restarted.emit_ai_alert(
        "server-a", "stable:event", "blocked", "Later repeated text", now=NOW + timedelta(days=1)
    )
    assert same == acknowledged and same["acknowledged"] is True
    assert len(restarted.ai_alerts()) == 1
    assert restarted.ack_ai_alert("f" * 64, NOW) is None
    assert restarted.ack_ai_alert(alert["id"], NOW + timedelta(days=2)) == same
    assert (
        restarted.emit_ai_alert("server-b", "stable:event", "blocked", "Review", now=NOW)["id"]
        != alert["id"]
    )


def test_full_alert_ledger_preserves_pending_and_acknowledged_identities(tmp_path, monkeypatch):
    store = AutomaticStore(tmp_path / "automatic.db")
    monkeypatch.setattr(module, "MAX_AI_ALERTS", 1)
    alert = store.emit_ai_alert("server-a", "first", "blocked", "Review", now=NOW)
    with pytest.raises(ValueError):
        store.emit_ai_alert("server-a", "second", "blocked", "Review", now=NOW)
    store.ack_ai_alert(alert["id"], NOW)
    with pytest.raises(ValueError):
        store.emit_ai_alert("server-a", "second", "blocked", "Review", now=NOW)
    assert (
        store.emit_ai_alert("server-a", "first", "blocked", "Review", now=NOW)["id"]
        == (alert["id"])
    )


def test_model_analysis_completion_is_distinct_from_a_verified_native_plan(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    analysis = store.emit_ai_alert(
        "server-a", "same-candidate", "analysis_completed", "Model proposal checked", now=NOW
    )
    plan = store.emit_ai_alert(
        "server-a", "same-candidate", "plan_ready", "Native Root plan checked", now=NOW
    )
    assert analysis["kind"] == "analysis_completed" and plan["kind"] == "plan_ready"
    assert analysis["id"] != plan["id"]
    assert len(store.ai_alerts()) == 2


def test_alert_and_result_details_redact_credentials_and_do_not_save_model_fields(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    private = "sk-privatefixture123456789"
    alert = store.emit_ai_alert(
        "server-a",
        "credential-failure",
        "analysis_failed",
        "Authorization: Bearer " + private,
        now=NOW,
    )
    request = begin(store)
    finish(store, request, "failed", detail="api_key=" + private)
    assert private not in json.dumps(store.ai_alerts() + store.ai_requests())
    assert private.encode() not in store.path.read_bytes()
    assert "[REDACTED]" in alert["detail"]
    with pytest.raises(ValueError):
        store.emit_ai_alert("server-a", "event", "invented_kind", "detail", now=NOW)
    with pytest.raises(ValueError):
        store.emit_ai_alert("server-a", private, "blocked", "detail", now=NOW)


def test_ai_outcomes_prioritize_unnotified_results_without_changing_candidates(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    first, _request, proof = bound_candidate(store)
    linked = store.bind_ai_result(first["id"], first["owner"], proof, now=NOW)
    submitted = reserve(store, linked)
    completed = store.record_result(first["id"], result(submitted), now=NOW)
    assert store.ai_outcomes() == [completed]
    store.emit_ai_alert(
        "server-a", first["id"], "repair_verified", "Verified", candidate_id=first["id"], now=NOW
    )
    later = candidate(store, index=2, host="server-b")
    req = begin(store, 2, host_id="server-b", candidate_id=later["id"])
    ref = finish(store, req)
    linked = store.bind_ai_result(
        later["id"],
        later["owner"],
        {"request_key": req["request_key"], **ref["result_ref"]},
        now=NOW,
    )
    submitted = reserve(store, linked)
    failed = store.record_result(later["id"], result(submitted, "failed"), now=NOW)
    assert store.ai_outcomes(1) == [failed]
    assert store.ai_outcomes() == [failed, completed]
    assert store.get(first["id"]) == completed
    assert store.get(later["id"]) == failed


def test_ai_outcomes_exclude_unbound_and_unfinished_candidates(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    plain = reserve(store, candidate(store))
    store.record_result(plain["id"], result(plain), now=NOW)
    assert store.ai_outcomes() == []
    later = candidate(store, index=2)
    req = begin(store, 2, candidate_id=later["id"])
    finish(store, req)
    linked = store.bind_ai_result(
        later["id"], later["owner"], {"request_key": req["request_key"], **reference(req)}, now=NOW
    )
    assert linked["state"] == "planning" and store.ai_outcomes() == []


@pytest.mark.parametrize("method", ["ai_requests", "ai_alerts", "ai_outcomes"])
@pytest.mark.parametrize("bad", [0, 101, True, 1.0])
def test_ai_audit_lists_are_bounded(tmp_path, method, bad):
    store = AutomaticStore(tmp_path / "automatic.db")
    with pytest.raises(ValueError):
        getattr(store, method)(bad)
