"""Negative lifecycle browser acceptance; temporary FakeRoot/transport only."""

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import httpx  # noqa: E402
import pytest  # noqa: E402
import test_defense_api as root_fixture  # noqa: E402
from browser_defense_binding_loss_smoke import (  # noqa: E402
    OBSERVED,
    PRESERVED,
    REPLACED,
    TRUE_FLAGS,
    _restart_proof,
    _verified_source,
    run_binding_loss_browser,
)
from browser_defense_session_native_smoke import _ledger  # noqa: E402
from browser_defense_transport_restart_smoke import ONE_COUNTS, ZERO_COUNTS  # noqa: E402
from defense_recheck_process_restart import RestartAcceptanceError  # noqa: E402
from defense_session_process import SessionProcess  # noqa: E402
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402
from test_defense_live_process import _decode as decode_fake  # noqa: E402
from test_defense_session_native_driver import (  # noqa: E402
    _fake_application,
    _fake_transport,
    _session_refs,
    _settings,
)

from opsark.config import Settings  # noqa: E402
from opsark.defense_client import _call_context, _validate_reply  # noqa: E402
from opsark.defense_models import canonical  # noqa: E402


def test_negative_adapter_cannot_replace_hook_while_transport_adapter_owns_it(tmp_path):
    import browser_defense_transport_restart_smoke as transport

    assert transport._LOCK.acquire(blocking=False)
    try:
        with pytest.raises(RestartAcceptanceError, match="binding_loss_adapter_busy"):
            run_binding_loss_browser(
                Settings(tmp_path / "data", "synthetic-binding-lock-console-token-only"),
                stimulate_after_arm=lambda _: {},
                snapshot=lambda: {},
                restart_protected_listener=lambda: {},
                proof_path=tmp_path / "proof.json",
            )
    finally:
        transport._LOCK.release()
    assert not (tmp_path / "proof.json").exists() and not (tmp_path / "data").exists()


def _proof(bound):
    before = {
        name: hashlib.sha256((name + ":synthetic-before").encode()).hexdigest()
        for name in PRESERVED + REPLACED
    }
    before["current_binding_sha256"] = before["root_binding_sha256"]
    after = dict(before)
    for name in REPLACED:
        after[name] = hashlib.sha256((name + ":synthetic-after").encode()).hexdigest()
    return {
        "schema": "opsark-protected-listener-restart-proof/v1",
        "completed": True,
        "restart_count": 1,
        "request_id_sha256": hashlib.sha256(bound["rid"].encode()).hexdigest(),
        "manifest_sha256": bound["ledger"]["manifest_sha256"],
        "identity_binding_sha256": bound["ledger"]["identity_binding_sha256"],
        "execution_continuation_supported": False,
        "before": before,
        "after": after,
        **dict.fromkeys(TRUE_FLAGS, True),
        **dict.fromkeys(ZERO_COUNTS, 0),
        **dict.fromkeys(ONE_COUNTS, 1),
    }


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "secret_extra",
        "wrong_schema",
        "continued",
        "repeat",
        "reinitialized",
        "new_host_key",
        "usage_reset",
        "protocol_restarted",
        "root_ledger_changed",
        "binding_updated",
        "protected_not_restarted",
        "wrong_original",
        "bad_prefix",
        "old_current_mismatch",
        "new_current_not_changed",
    ],
)
def test_negative_lifecycle_proof_is_exact_and_cannot_rebind_or_continue(damage):
    bound = {
        "rid": "a" * 32,
        "ledger": {"manifest_sha256": "b" * 64, "identity_binding_sha256": "c" * 64},
    }
    value = _proof(bound)
    if damage == "missing":
        del value["binding_changed"]
    elif damage == "secret_extra":
        value["raw_log"] = "FAKE_SECRET_RAW_LOG"
    elif damage == "wrong_schema":
        value["schema"] = "synthetic_other"
    elif damage == "continued":
        value["execution_continuation_supported"] = True
    elif damage == "repeat":
        value["restart_count"] = 2
    elif damage == "reinitialized":
        value["initialize_calls_during_restart"] = 1
    elif damage == "new_host_key":
        value["host_key_generation_calls_during_restart"] = 1
    elif damage == "usage_reset":
        value["usage_count_after"] = 0
    elif damage == "protocol_restarted":
        value["after"]["protocol_process_sha256"] = "d" * 64
    elif damage == "root_ledger_changed":
        value["after"]["root_ledger_sha256"] = "d" * 64
    elif damage == "binding_updated":
        value["after"]["root_binding_sha256"] = "d" * 64
    elif damage == "protected_not_restarted":
        value["after"]["protected_process_sha256"] = value["before"]["protected_process_sha256"]
    elif damage == "wrong_original":
        value["identity_binding_sha256"] = "d" * 64
    elif damage == "bad_prefix":
        value["after"]["protected_log_prefix_sha256"] = "FAKE_SECRET_LOG_TEXT"
    elif damage == "old_current_mismatch":
        value["before"]["current_binding_sha256"] = "d" * 64
    else:
        value["after"]["current_binding_sha256"] = value["after"]["root_binding_sha256"]
    with pytest.raises(RestartAcceptanceError):
        _restart_proof(value, bound)


def _binding_application(settings):
    app = _fake_application(settings)
    original = app.state.defense_service.invoker
    marker = settings.inventory_path.parent / "synthetic-binding-loss"

    def invoke(target, call, role, **options):
        result = original(target, call, role, **options)
        if marker.exists() and call.request.op == "query" and call.request.body.kind == "action":
            kind = marker.read_text(encoding="ascii")
            reply = result.reply.model_copy(
                update={
                    "state": "unknown",
                    "remaining_ms": None,
                    "reason_code": "binding_changed"
                    if kind != "unrelated_unknown"
                    else "result_unknown",
                }
            )
            return _validate_reply(target, _call_context(target, call), canonical(reply) + b"\n")
        return result

    app.state.defense_service.invoker = invoke
    return app


@pytest.mark.parametrize(
    "kind", ["binding_changed", "incomplete_proof", "unrelated_unknown", "callback_exception"]
)
def test_actual_processes_query_unknown_keeps_old_confirmation_and_one_charge(
    tmp_path, target, monkeypatch, kind
):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target)
    monkeypatch.setattr(
        SessionProcess,
        "_command",
        lambda _: [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--fake-binding-child",
        ],
    )
    order = []

    def state():
        return decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))

    def stimulus(cursor):
        order.append("stimulus")
        return {"cursor_request_id": cursor}

    def snapshot():
        order.append("snapshot")
        assert sum(op == "apply" for op, _ in state()["sent"]) == 1
        return {"ledger": {"usage_count": 1, "intents": 1}, "projection": {"apply_fault": None}}

    def restart():
        order.append("restart")
        audit = json.loads((tmp_path / "controller-processes" / "process-1-audit.json").read_text())
        assert audit["stopped"] and audit["session_worker_stopped"]
        if kind == "callback_exception":
            raise RestartAcceptanceError("FAKE_SECRET_CALLBACK_TEXT")
        value = state()
        rid = next(rid for rid, row in value["records"].items() if row.get("kind") == "action")
        assert not any(op == "query" and sent == rid for op, sent in value["sent"])
        ledger = _ledger(settings.data_dir, _session_refs(settings.data_dir)[0], rid)
        proof = _proof({"rid": rid, "ledger": ledger})
        (tmp_path / "synthetic-binding-loss").write_text(kind, encoding="ascii")
        if kind == "incomplete_proof":
            del proof["after"]["protocol_listener_sha256"]
        return proof

    result = run_binding_loss_browser(
        settings,
        stimulate_after_arm=stimulus,
        snapshot=snapshot,
        restart_protected_listener=restart,
        proof_path=tmp_path / "proof.json",
    )
    assert result["negative_acceptance_passed"] is (kind == "binding_changed"), result
    assert result["base_completed"] is False
    assert result["restart_callback_attempts"] == 1
    assert order == ["stimulus", "snapshot", "restart"]
    base = json.loads((tmp_path / "proof-session.json").read_text())
    assert base["completed"] is False and base["session_acceptance_passed"] is False
    assert len(base["processes"]) == 2 and all(row["stopped"] for row in base["processes"])
    value = state()
    rid = next(rid for rid, row in value["records"].items() if row.get("kind") == "action")
    assert sum(op == "apply" for op, _ in value["sent"]) == 1
    assert sum(op == "prepare" for op, _ in value["sent"]) == 1
    assert not any(op == "revoke" for op, _ in value["sent"])
    assert sum(op == "query" and sent == rid for op, sent in value["sent"]) == (
        1 if kind in {"binding_changed", "unrelated_unknown"} else 0
    )
    assert all(row["model_attempts"] == 0 for row in base["processes"])
    if kind == "binding_changed":
        assert base["failure_code"] == OBSERVED
        observed = result["observation"]
        assert observed["root_state"] == "unknown" and observed["root_reason"] == "binding_changed"
        assert observed["query_required"] and not observed["current_root_verified"]
        assert observed["historical_session_phase"] == "completed"
        assert observed["historical_last_confirmed_state"] == "active"
        assert (
            observed["charge_state_before"],
            observed["charge_state_after"],
            observed["charge_count"],
        ) == ("consumed", "unknown", 1)
        assert result["processes"][1]["write_requests"] == {"query": 1}
        assert result["business_verdict"] == "pending" and not result["business_recollection"]
        assert not result["production_root_invoker"] and not result["production_http_transport"]
    for name in ("proof.json", "proof-session.json"):
        text = (tmp_path / name).read_text()
        assert rid not in text and settings.token not in text and "FAKE_SECRET" not in text
    _verified_source()


if __name__ == "__main__":
    if sys.argv[1:] == ["--fake-binding-child"]:
        import defense_session_process
        import paramiko

        monkey = pytest.MonkeyPatch()

        def no_ssh(*_args, **_kwargs):
            raise AssertionError("Synthetic binding-loss child cannot connect SSH")

        monkey.setattr(paramiko.SSHClient, "connect", no_ssh)
        monkey.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_transport)
        monkey.setattr(defense_session_process, "_application", _binding_application)
        raise SystemExit(defense_session_process._child())
    raise SystemExit(2)
