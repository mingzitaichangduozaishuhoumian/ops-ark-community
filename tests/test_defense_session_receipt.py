"""Pure local original-session AI receipts, including damaged historical bindings."""

import hashlib
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from test_defense_ai import wire
from test_defense_session_coordinator import REF, start
from test_defense_session_coordinator import harness as harness
from test_defense_session_coordinator import keyset as keyset
from test_defense_session_coordinator import no_real_transport as no_real_transport
from test_defense_session_coordinator import scene as scene
from test_defense_session_coordinator import target as target

from opsark.defense_api import DefenseService
from opsark.defense_models import canonical, digest
from opsark.defense_session import DefenseSessionCoordinator
from opsark.defense_session_api import register_defense_session_routes
from opsark.defense_store import DefenseConflict, DefenseStore

TOKEN = "synthetic-local-session-receipt-token"
PRIVATE = "FAKE_PRIVATE_RECEIPT_NOT_FOR_RESPONSE"
KEYS = {
    "v",
    "session_ref",
    "analysis_id",
    "status",
    "decision",
    "usage_state",
    "input_digest",
    "proof_sha256",
    "actions_executable",
}


class Dispatcher:
    enabled = False

    def status(self):
        return {"enabled": False}

    def wake(self):
        raise AssertionError("A receipt cannot start a worker")


def client(coordinator):
    app = FastAPI()

    def authorize(request: Request):
        if request.headers.get("Authorization") != "Bearer " + TOKEN:
            raise HTTPException(401, "Authentication required")

    register_defense_session_routes(app, coordinator, Dispatcher(), [Depends(authorize)])
    return TestClient(app)


def read(coordinator, *, host="fixture", authenticated=True):
    headers = {"Authorization": "Bearer " + TOKEN} if authenticated else {}
    return client(coordinator).get(
        f"/api/hosts/{host}/ssh-defense/sessions/{REF}/ai-receipt", headers=headers
    )


def image(s):
    with closing(sqlite3.connect(s.store.path)) as db, db:
        return hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()


def analyzed(scene, monkeypatch):
    s = scene(requires_ai=True)
    calls = wire(monkeypatch, s.provider_state)
    start(s)
    assert s.coordinator.tick(REF).phase == "analyzing"
    assert s.coordinator.tick(REF).phase == "analysis_ready"
    return s, calls


def change_result(s, **changes):
    intent = s.coordinator.get(REF).ai_intent
    value = s.store.ai_result(intent.analysis_id).model_copy(update=changes)
    with closing(sqlite3.connect(s.store.path)) as db, db:
        db.execute(
            "UPDATE defense_ai_results SET typed_result=?,result_sha256=? WHERE analysis_id=?",
            (canonical(value), digest(value), intent.analysis_id),
        )


def test_completed_receipt_is_small_local_readonly_and_never_execution(scene, monkeypatch):
    s, calls = analyzed(scene, monkeypatch)
    record = s.coordinator.get(REF)
    expected = s.ai.get("fixture", record.ai_intent.analysis_id)
    before, sent = image(s), tuple(s.root.sent)
    response = read(s.coordinator)
    assert response.status_code == 200
    value = response.json()
    assert set(value) == KEYS
    assert value == {
        "v": 1,
        "session_ref": REF,
        "analysis_id": expected["analysis_id"],
        "status": "completed",
        "decision": "propose_defense",
        "usage_state": "consumed",
        "input_digest": expected["input_digest"],
        "proof_sha256": expected["proof_sha256"],
        "actions_executable": False,
    }
    assert response.headers["cache-control"] == "no-store"
    assert image(s) == before and tuple(s.root.sent) == sent and len(calls) == 1
    for private in (
        s.service.settings.token,
        s.service.settings.ai_key,
        "provider",
        "source",
        "alias",
        "prompt",
        "reason_code",
    ):
        assert private not in response.text


@pytest.mark.parametrize("requires_ai,status", [(False, "not_required"), (True, "not_started")])
def test_original_declaration_distinguishes_no_ai_intent(scene, requires_ai, status):
    s = scene(requires_ai=requires_ai)
    start(s)
    before, sent = image(s), tuple(s.root.sent)
    response = read(s.coordinator)
    assert response.status_code == 200
    value = response.json()
    assert set(value) == KEYS and value["status"] == status
    assert value["session_ref"] == REF and value["actions_executable"] is False
    assert all(
        value[key] is None
        for key in ("analysis_id", "decision", "usage_state", "input_digest", "proof_sha256")
    )
    assert image(s) == before and tuple(s.root.sent) == sent


@pytest.mark.parametrize("state", ["reserved", "consumed", "unknown"])
def test_missing_result_stays_unknown_and_local_quota_state_is_preserved(scene, monkeypatch, state):
    s, calls = analyzed(scene, monkeypatch)
    with closing(sqlite3.connect(s.store.path)) as db, db:
        db.execute(
            "DELETE FROM defense_ai_results"
        )  # Simulate result lost after original cost commit.
        db.execute("UPDATE defense_usage SET state=? WHERE kind='ai'", (state,))
    before = image(s)
    value = read(s.coordinator).json()
    assert value["status"] == "unknown" and value["usage_state"] == state
    assert value["decision"] is value["proof_sha256"] is None
    assert value["analysis_id"] and value["input_digest"] and not value["actions_executable"]
    assert image(s) == before and len(calls) == 1


def test_real_provider_timeout_stays_unknown_without_another_attempt(scene, monkeypatch):
    s = scene(requires_ai=True)

    def unknown(request):
        raise httpx.ReadTimeout("Synthetic unknown only", request=request)

    calls = wire(monkeypatch, s.provider_state, handler=unknown)
    start(s)
    s.coordinator.tick(REF)
    assert s.coordinator.tick(REF).phase == "reconciliation_only"
    before, sent = image(s), tuple(s.root.sent)
    value = read(s.coordinator).json()
    assert value["status"] == "unknown" and value["usage_state"] == "unknown"
    assert value["decision"] is value["proof_sha256"] is None
    assert image(s) == before and tuple(s.root.sent) == sent and len(calls) == 1


@pytest.mark.parametrize("status", ["unknown", "refused", "failed", "stale"])
def test_original_noncompletion_is_not_upgraded_to_a_decision(scene, monkeypatch, status):
    s, calls = analyzed(scene, monkeypatch)
    change_result(
        s,
        status=status,
        decision=None,
        reason_code=None,
        source_ref=None,
        evidence_sha256=None,
        proof_sha256=None,
    )
    response = read(s.coordinator)
    assert response.status_code == 200
    value = response.json()
    assert value["status"] == status and value["usage_state"] == "consumed"
    assert value["decision"] is value["proof_sha256"] is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "decision,reason",
    [
        ("no_action", "no_match"),
        ("collect_more", "evidence_gap"),
        ("review_access", "access_review"),
    ],
)
def test_completed_nonproposal_has_no_proof_or_execution_authority(
    scene, monkeypatch, decision, reason
):
    s, _ = analyzed(scene, monkeypatch)
    change_result(
        s,
        decision=decision,
        reason_code=reason,
        source_ref=None,
        evidence_sha256=None,
        proof_sha256=None,
    )
    response = read(s.coordinator)
    assert response.status_code == 200
    value = response.json()
    assert value["status"] == "completed" and value["decision"] == decision
    assert value["proof_sha256"] is None and value["actions_executable"] is False


def test_old_owner_retired_target_expired_window_and_missing_provider_remain_readable(
    scene, monkeypatch
):
    s, calls = analyzed(scene, monkeypatch)
    expected = read(s.coordinator).json()
    s.clock[0] += timedelta(days=2)

    def deny(*_args, **_kwargs):
        raise AssertionError("Historical receipts cannot inspect current providers or invoke SSH")

    restarted = DefenseService(
        replace(s.service.settings, ai_base_url=None, ai_key=None, ai_model=None),
        {},
        DefenseStore(s.store.path),
        s.automation,
        invoker=deny,
        clock=lambda: s.clock[0],
    )
    second = DefenseSessionCoordinator(restarted)
    monkeypatch.setattr(second, "runtime", deny)
    monkeypatch.setattr(second, "_pins", deny)
    before = image(s)
    assert second.controller.owner != s.service.owner
    assert second.controller.ai_service is None and not second.controller.targets
    assert read(second).json() == expected
    assert image(s) == before and len(calls) == 1 and not second.owned_session_refs()


def test_auth_and_original_host_are_enforced_before_projection(scene, monkeypatch):
    s, _ = analyzed(scene, monkeypatch)
    assert read(s.coordinator, authenticated=False).status_code == 401
    response = read(s.coordinator, host="other")
    assert response.status_code == 409 and response.json() == {
        "detail": "单次会话状态或授权无法核实。"
    }
    assert set(response.json()) == {"detail"}


@pytest.mark.parametrize(
    "damage",
    [
        "sidecar_hash",
        "sidecar_input",
        "missing_sidecar",
        "missing_sidecar_and_quota",
        "orphaned_original_permit",
        "permit_owner",
        "permit_input",
        "permit_deadline",
        "usage_host",
        "usage_kind",
        "usage_provider",
        "usage_grant",
        "usage_day",
        "usage_created",
        "usage_missing",
        "result_proof",
        "result_input",
        "result_lookup",
        "result_private_shape",
        "source_alias",
    ],
)
def test_damaged_binding_rejects_whole_receipt_with_fixed_message(scene, monkeypatch, damage):
    s, calls = analyzed(scene, monkeypatch)
    with closing(sqlite3.connect(s.store.path)) as db, db:
        if damage == "sidecar_hash":
            db.execute("UPDATE defense_session_ai_v1 SET sha256=?", ("f" * 64,))
        elif damage in {"missing_sidecar", "missing_sidecar_and_quota", "orphaned_original_permit"}:
            db.execute("DELETE FROM defense_session_ai_v1")
            if damage != "missing_sidecar":
                db.execute("DELETE FROM defense_usage WHERE kind='ai'")
            if damage == "orphaned_original_permit":
                db.execute("UPDATE defense_sessions_v1 SET phase='analyzing'")
        elif damage.startswith("sidecar_") or damage.startswith("permit_"):
            sidecar = damage.startswith("sidecar_")
            table, body_key, hash_key = (
                ("defense_session_ai_v1", "typed_record", "sha256")
                if sidecar
                else ("defense_ai_intents", "typed_permit", "permit_sha256")
            )
            import json

            value = json.loads(db.execute("SELECT " + body_key + " FROM " + table).fetchone()[0])  # noqa: S608 -- fixed internal table/column literals only.
            field = {
                "sidecar_input": "input_digest",
                "permit_owner": "owner",
                "permit_input": "input_digest",
                "permit_deadline": "deadline_at",
            }[damage]
            value[field] = (
                "f" * 64
                if "input" in damage
                else ("other-owner" if field == "owner" else "2020-01-01T00:00:00.000000Z")
            )
            db.execute(
                "UPDATE " + table + " SET " + body_key + "=?," + hash_key + "=?",  # noqa: S608 -- fixed internal table/column literals only.
                (canonical(value), digest(value)),
            )
        elif damage == "usage_missing":
            db.execute("DELETE FROM defense_usage WHERE kind='ai'")
        elif damage.startswith("usage_"):
            column = {
                "usage_host": "host_id",
                "usage_kind": "kind",
                "usage_provider": "provider_fingerprint",
                "usage_grant": "grant_ref",
                "usage_day": "charged_day",
                "usage_created": "created_at",
            }[damage]
            value = {
                "usage_host": "other",
                "usage_kind": "execution",
                "usage_provider": "f" * 64,
                "usage_grant": "f" * 32,
                "usage_day": "2020-01-01",
                "usage_created": "2020-01-01T00:00:00.000000Z",
            }[damage]
            db.execute("UPDATE defense_usage SET " + column + "=?", (value,))  # noqa: S608 -- fixed internal column literals only.
        elif damage == "result_lookup":
            db.execute("UPDATE defense_ai_results SET intent_key=?", ("f" * 64,))
        elif damage == "result_private_shape":
            raw = canonical({"private": PRIVATE})
            db.execute(
                "UPDATE defense_ai_results SET typed_result=?,result_sha256=?",
                (raw, hashlib.sha256(raw).hexdigest()),
            )
        elif damage == "source_alias":
            raw = canonical({"aliases": []})
            db.execute(
                "UPDATE defense_sources SET alias_map=?,alias_sha256=?",
                (raw, hashlib.sha256(raw).hexdigest()),
            )
    if damage in {"result_proof", "result_input"}:
        change_result(
            s, **{"proof_sha256" if damage == "result_proof" else "input_digest": "f" * 64}
        )
    before, sent = image(s), tuple(s.root.sent)
    response = read(s.coordinator)
    assert response.status_code == 409
    assert response.json() == {"detail": "单次会话状态或授权无法核实。"}
    assert PRIVATE not in response.text and set(response.json()) == {"detail"}
    assert image(s) == before and tuple(s.root.sent) == sent and len(calls) == 1


def test_coordinator_cross_host_rejects_without_reading_current_registry(scene):
    s = scene()
    start(s)
    with pytest.raises(DefenseConflict):
        s.coordinator.ai_receipt("other", REF)
