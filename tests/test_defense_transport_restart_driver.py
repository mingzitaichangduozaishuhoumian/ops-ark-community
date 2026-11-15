"""Transport lifecycle adapter guards; all lifecycle/Root facts are synthetic."""

import hashlib
import inspect
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import test_defense_api as root_fixture
from browser_defense_session_native_smoke import _ledger
from browser_defense_transport_restart_smoke import (
    ONE_COUNTS,
    PRESERVED,
    REPLACED,
    RESTART_FLAGS,
    ZERO_COUNTS,
    _before_restart,
    _Once,
    _require_callback,
    _restart_proof,
    _verified_source,
    run_transport_restart_browser,
)
from defense_recheck_process_restart import RestartAcceptanceError
from defense_session_process import SessionProcess
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_live_process import _decode as decode_fake
from test_defense_session_native_driver import _session_refs, _settings


@pytest.mark.parametrize("callback", [None, False, 1, "restart"])
def test_transport_restart_requires_an_explicit_callable(callback):
    with pytest.raises(RestartAcceptanceError, match="transport_restart_callback_required"):
        _require_callback(callback)


def test_transport_restart_rejects_async_callback():
    async def callback():
        return {}

    assert inspect.iscoroutinefunction(callback)
    with pytest.raises(RestartAcceptanceError, match="transport_restart_callback_required"):
        _require_callback(callback)


def test_transport_restart_gate_is_taken_before_call_and_never_reused():
    once = _Once()
    once.take()
    assert once.calls == 1
    with pytest.raises(RestartAcceptanceError, match="transport_restart_repeated"):
        once.take()
    assert once.calls == 1


@pytest.mark.parametrize("name", ["_restart", "run_session_browser"])
def test_transport_adapter_rejects_replaced_original_function(monkeypatch, name):
    import browser_defense_session_native_smoke as session

    monkeypatch.setattr(session, name, lambda *_args, **_kwargs: {})
    with pytest.raises(RestartAcceptanceError, match="transport_session_function_changed"):
        _verified_source()


@pytest.mark.parametrize(
    "damage",
    [
        "first_running",
        "first_model",
        "before_ack",
        "unknown_fee",
        "duplicate_apply",
        "wrong_boundary",
    ],
)
def test_lifecycle_callback_cannot_run_before_verified_direct_ack_and_first_exit(damage):
    first = {
        "stopped": True,
        "session_worker_stopped": True,
        "worker_disabled": True,
        "model_attempts": 0,
        "write_requests": {"mode": 1, "arm": 1, "session_start": 1},
    }
    record = {
        "controller_process_restart_verified": True,
        "phase": "restart_readonly",
        "terminal_phase": "completed",
        "expected_ack_behavior": "direct_ack",
        "expected_ai_calls": 0,
        "business_verdict": "pending",
        "business_recollection": False,
        "processes": [first],
    }
    ledger: dict[str, Any] = {
        "totals": {"sessions": 1, "actions": 1, "apply_intents": 1, "business_rechecks": 0},
        "fees": [{"kind": "execution", "state": "consumed", "count": 1}],
        "ai_evidence": None,
        "requests": [{"op": "apply", "dispatch_phase": "replied", "reply_sha256": "a" * 64}],
        "observations": [{"op": "apply", "accepted": 1, "state": "active"}],
    }
    bound = {
        "record": record,
        "ledger": ledger,
        "process": SimpleNamespace(index=2),
        "rid": "b" * 32,
        "cursor": "c" * 32,
        "final": {
            "phase": "completed",
            "effective_phase": "completed",
            "action_request_id": "b" * 32,
            "cursor_request_id": "c" * 32,
        },
    }
    if damage == "first_running":
        first["stopped"] = False
    elif damage == "first_model":
        first["model_attempts"] = 1
    elif damage == "before_ack":
        ledger["requests"] = [{"op": "apply", "dispatch_phase": "replied", "reply_sha256": None}]
    elif damage == "unknown_fee":
        ledger["fees"][0]["state"] = "unknown"
    elif damage == "duplicate_apply":
        ledger["totals"]["apply_intents"] = 2
    else:
        record["phase"] = "worker_only"
    with pytest.raises(RestartAcceptanceError):
        _before_restart(bound)


def _proof(bound):
    before = {
        name: hashlib.sha256((name + ":synthetic-before").encode()).hexdigest()
        for name in PRESERVED + REPLACED
    }
    after = dict(before)
    for name in REPLACED:
        after[name] = hashlib.sha256((name + ":synthetic-after").encode()).hexdigest()
    return {
        "schema": "opsark-root-transport-restart-proof/v1",
        "completed": True,
        "restart_count": 1,
        "request_id_sha256": hashlib.sha256(bound["rid"].encode()).hexdigest(),
        "manifest_sha256": bound["ledger"]["manifest_sha256"],
        "identity_binding_sha256": bound["ledger"]["identity_binding_sha256"],
        "before": before,
        "after": after,
        **dict.fromkeys(RESTART_FLAGS, True),
        **dict.fromkeys(ZERO_COUNTS, 0),
        **dict.fromkeys(ONE_COUNTS, 1),
    }


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "secret_extra",
        "wrong_schema",
        "repeated",
        "initialized",
        "provisioned",
        "host_key_regenerated",
        "usage_changed",
        "bool_count",
        "wrong_rid",
        "wrong_manifest",
        "protected_changed",
        "same_transport",
        "unsafe_state",
    ],
)
def test_transport_lifecycle_proof_must_be_complete_exact_and_bound(damage):
    bound = {
        "rid": "a" * 32,
        "ledger": {"manifest_sha256": "b" * 64, "identity_binding_sha256": "c" * 64},
    }
    value = _proof(bound)
    if damage == "missing":
        del value["before"]
    elif damage == "secret_extra":
        value["raw_log"] = "FAKE_SECRET_RAW_LOG"
    elif damage == "wrong_schema":
        value["schema"] = "synthetic_other_schema"
    elif damage == "repeated":
        value["restart_count"] = 2
    elif damage == "initialized":
        value["initialize_calls_during_restart"] = 1
    elif damage == "provisioned":
        value["provision_calls_during_restart"] = 1
    elif damage == "host_key_regenerated":
        value["host_key_generation_calls_during_restart"] = 1
    elif damage == "usage_changed":
        value["usage_count_after"] = 2
    elif damage == "bool_count":
        value["restart_count"] = True
    elif damage == "wrong_rid":
        value["request_id_sha256"] = "d" * 64
    elif damage == "wrong_manifest":
        value["manifest_sha256"] = "d" * 64
    elif damage == "protected_changed":
        value["after"]["protected_process_sha256"] = "d" * 64
    elif damage == "same_transport":
        value["after"]["transport_process_sha256"] = value["before"]["transport_process_sha256"]
    else:
        value["after"]["root_ledger_sha256"] = "FAKE_SECRET_DATABASE_TEXT"
    with pytest.raises(RestartAcceptanceError):
        _restart_proof(value, bound)


@pytest.mark.parametrize("kind", ["active", "expired", "incomplete_proof", "callback_exception"])
def test_ui_rule_direct_ack_restart_then_query_original_once(tmp_path, target, monkeypatch, kind):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target)
    import test_defense_session_native_driver as fake_child

    monkeypatch.setattr(
        SessionProcess,
        "_command",
        lambda _: [
            sys.executable,
            "-I",
            "-B",
            str(Path(fake_child.__file__).resolve()),
            "--fake-session-child",
        ],
    )
    import browser_defense_session_native_smoke as original

    monkeypatch.setattr(original, "RESTART_OBSERVE_SECONDS", 0.2)
    order = []

    def stimulus(cursor):
        order.append("stimulus")
        return {"cursor_request_id": cursor}

    def state():
        return decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))

    def snapshot():
        order.append("snapshot")
        value = state()
        assert sum(op == "apply" for op, _ in value["sent"]) == 1
        return {"ledger": {"usage_count": 1, "intents": 1}, "projection": {"apply_fault": None}}

    def restart():
        order.append("restart")
        processes = tmp_path / "controller-processes"
        audit = json.loads((processes / "process-1-audit.json").read_text())
        assert audit["stopped"] and audit["session_worker_stopped"]
        assert (processes / "process-2-ready.json").exists()
        if kind == "callback_exception":
            raise RestartAcceptanceError("FAKE_SECRET_CALLBACK_EXCEPTION_WITH_DATABASE_TEXT")
        value = state()
        rid = next(rid for rid, row in value["records"].items() if row.get("kind") == "action")
        assert not any(op == "query" and sent == rid for op, sent in value["sent"])
        ledger = _ledger(settings.data_dir, _session_refs(settings.data_dir)[0], rid)
        proof = _proof({"rid": rid, "ledger": ledger})
        if kind == "expired":
            (tmp_path / "expire-original-query").write_text("synthetic expiry", encoding="ascii")
        if kind == "incomplete_proof":
            del proof["after"]["root_binding_sha256"]
        return proof

    result = run_transport_restart_browser(
        settings,
        stimulate_after_arm=stimulus,
        snapshot=snapshot,
        restart_transport=restart,
        proof_path=tmp_path / "proof.json",
    )
    assert order == ["stimulus", "snapshot", "restart"]
    assert result["restart_callback_attempts"] == 1
    assert result["completed"] is (kind in {"active", "expired"}), result
    value = state()
    rid = next(rid for rid, row in value["records"].items() if row.get("kind") == "action")
    assert sum(op == "apply" for op, _ in value["sent"]) == 1
    assert sum(op == "prepare" for op, _ in value["sent"]) == 1
    queries = sum(op == "query" and sent == rid for op, sent in value["sent"])
    if kind in {"incomplete_proof", "callback_exception"}:
        assert not result["transport_restart_acceptance_passed"] and queries == 0
    else:
        assert result["transport_restart_acceptance_passed"] and queries == 1
        assert result["original_query_state"] == kind
        assert result["ttl"]["not_increased"] and result["ttl"]["original_deadline_unchanged"]
        assert result["processes"][1]["write_requests"] == {"query": 1}
        assert all(row["model_attempts"] == 0 for row in result["processes"])
        assert not result["production_root_invoker"] and not result["production_http_transport"]
        assert result["business_verdict"] == "pending" and not result["business_recollection"]
    for name in ("proof.json", "proof-session.json"):
        text = (tmp_path / name).read_text()
        assert rid not in text and settings.token not in text and "FAKE_SECRET" not in text
    assert original._restart.__module__ == original.__name__
    _verified_source()
