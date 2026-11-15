"""Actual processes/UI; only tmp FakeRoot and MockTransport receipts."""

import json
import sys
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import httpx  # noqa: E402
import pytest  # noqa: E402
import test_defense_api as root_fixture  # noqa: E402
from browser_defense_session_native_smoke import _ledger, _native, run_session_browser  # noqa: E402
from defense_recheck_process_restart import RestartAcceptanceError  # noqa: E402
from defense_session_process import (  # noqa: E402
    SessionProcess,
    _configuration,
    _decode,
    _model_request_metadata,
    _write_operation,
)
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402
from test_defense_live_process import _decode as decode_fake  # noqa: E402
from test_defense_live_process import _encode  # noqa: E402
from test_defense_task_watch_native_driver import _settings as inert_settings  # noqa: E402

from opsark.ai_provider import provider_fingerprint  # noqa: E402
from opsark.defense_client import UnknownDefenseResult  # noqa: E402


def _settings(tmp_path, target, *, ai=False):
    configured = replace(inert_settings(tmp_path, target), defense_session_enabled=True)
    if ai:
        key = tmp_path / "synthetic-model-key"
        key.write_text("synthetic-session-provider-secret-only", encoding="ascii")
        key.chmod(0o600)
        configured = replace(
            configured,
            ai_base_url="https://synthetic-provider.invalid/v1",
            ai_model="synthetic-session-model",
            ai_key_file=key,
            ai_max_output_tokens=512,
            ai_thinking_mode="disabled",
        )
        policy = json.loads(configured.defense_policy_path.read_text())
        policy["ai"] = {
            "enabled": True,
            "requires_ai": True,
            "provider_fingerprint": provider_fingerprint(configured),
            "max_analyses_per_day": 1,
            "max_total_analyses": 1,
        }
        configured.defense_policy_path.write_text(json.dumps(policy), encoding="ascii")
    return configured


def _fake_application(settings):
    from opsark.main import create_app

    app = create_app(settings)
    controller = app.state.defense_service
    base = settings.inventory_path.parent
    state_path = base / "fake-root-state.json"
    root = root_fixture.FakeRoot(controller.targets["fixture"], lambda: datetime.now(UTC))
    if state_path.exists():
        state = decode_fake(json.loads(state_path.read_text()))
        root.mode, root.revision = state["mode"], state["revision"]
        root.records, root.sent, root.lose = state["records"], state["sent"], state["lose"]
    elif (base / "synthetic-loss").exists():
        root.lose = "apply"
    serial = Lock()

    def invoke(target, call, role, **options):
        with serial:
            if (base / "expire-original-query").exists() and call.request.op == "query":
                for row in root.records.values():
                    if row.get("state") == "active":
                        row["state"] = "expired"
            try:
                return root(target, call, role, admit=options.get("admit"))
            except OSError:
                raise UnknownDefenseResult(call.request.request_id) from None
            finally:
                state_path.write_text(
                    json.dumps(
                        _encode(
                            {
                                "mode": root.mode,
                                "revision": root.revision,
                                "records": root.records,
                                "sent": root.sent,
                                "lose": root.lose,
                            }
                        )
                    ),
                    encoding="ascii",
                )

    controller.invoker = invoke

    def forbid_collection(_host):
        raise AssertionError("No business collection belongs to this session acceptance")

    app.state.defense_recheck_service.collector = forbid_collection
    return app


async def _fake_transport(_transport, request):
    """Production transport observer wraps this MockTransport, never a socket."""

    def respond(request):
        value = {
            "v": 1,
            "decision": "propose_defense",
            "candidate_alias": "candidate-1",
            "evidence_aliases": ["evidence-1"],
            "reason_code": "evidence_sufficient",
        }
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(value),
                        },
                    }
                ]
            },
        )

    return await httpx.MockTransport(respond).handle_async_request(request)


@pytest.mark.parametrize("change", ["disabled", "watch", "observe", "vuln", "inline", "ai_budget"])
def test_dedicated_session_keeps_old_inert_boundary(tmp_path, target, monkeypatch, change):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target)
    modified = {
        "disabled": replace(settings, defense_session_enabled=False),
        "watch": replace(
            settings, defense_task_watch_enabled=True, defense_task_watch_host_ids=("fixture",)
        ),
        "observe": replace(settings, observation_enabled=True, observation_host_ids=("fixture",)),
        "vuln": replace(
            settings, vulnerability_scan_enabled=True, vulnerability_scan_host_ids=("fixture",)
        ),
        "inline": replace(settings, ai_key="FAKE_PRIVATE_INLINE_KEY"),
        "ai_budget": settings,
    }[change]
    with pytest.raises(RestartAcceptanceError):
        _configuration(modified, 2 if change == "ai_budget" else 0)
    document = _configuration(settings)
    assert _decode(json.loads(json.dumps(document))) == (settings, 0)
    from defense_live_process import _configuration as old_boundary

    with pytest.raises(RestartAcceptanceError):
        old_boundary(settings)


@pytest.mark.parametrize("change", ["thinking", "tokens", "inline", "provider", "rule"])
def test_explicit_ai_profile_bounded_provider(tmp_path, target, monkeypatch, change):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target, ai=True)
    changed = {
        "thinking": replace(settings, ai_thinking_mode="provider_default"),
        "tokens": replace(settings, ai_max_output_tokens=1024),
        "inline": replace(settings, ai_key_file=None, ai_key="FAKE_INLINE_KEY"),
        "provider": replace(settings, ai_model=None),
        "rule": settings,
    }[change]
    with pytest.raises(RestartAcceptanceError):
        _configuration(changed, 0 if change == "rule" else 1)
    assert _decode(json.loads(json.dumps(_configuration(settings, 1)))) == (settings, 1)


@pytest.mark.parametrize(
    "suffix",
    ["prepare", "transactions/a/apply", "transactions/a/revoke", "sessions/a/stop", "ai/analyze"],
)
def test_browser_cannot_replace_worker_with_manual_mutations(suffix):
    assert _write_operation("POST", "/api/hosts/a/ssh-defense/" + suffix) == "forbidden"


@pytest.mark.parametrize("seconds", [0, -1, 20.001, None, "20", True, float("nan"), float("inf")])
def test_transport_observer_rejects_nonfinite_or_excessive_timeout(tmp_path, seconds):
    from opsark.config import Settings

    settings = Settings(
        tmp_path,
        "synthetic-transport-observer-console-token-only",
        ai_base_url="https://synthetic-provider.invalid/v1",
    )
    request = httpx.Request(
        "POST",
        "https://synthetic-provider.invalid/v1/chat/completions",
        json={"thinking": {"type": "disabled"}, "max_tokens": 512},
        extensions={"timeout": {name: seconds for name in ("connect", "read", "write", "pool")}},
    )
    with pytest.raises(RestartAcceptanceError, match="model_timeout_budget_changed"):
        _model_request_metadata(settings, request)


@pytest.mark.parametrize("port", [443, 8443])
def test_transport_observer_binds_exact_provider_port_and_dynamic_budget(tmp_path, port):
    from opsark.config import Settings

    settings = Settings(
        tmp_path,
        "synthetic-transport-port-console-token-only",
        ai_base_url="https://synthetic-provider.invalid:8443/v1",
    )
    request = httpx.Request(
        "POST",
        "https://synthetic-provider.invalid:" + str(port) + "/v1/chat/completions",
        json={
            "thinking": {"type": "disabled"},
            "max_tokens": 512,
            "messages": [
                {"role": "system", "content": "synthetic-only"},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "v": 1,
                            "candidates": [
                                {
                                    "candidate_alias": "candidate-1",
                                    "evidence_alias": "evidence-1",
                                    "classification": "eligible",
                                    "distinct_failure_ports": 5,
                                    "ttl_seconds": 60,
                                }
                            ],
                            "omitted_candidate_count": 1,
                        }
                    ),
                },
            ],
        },
        extensions={"timeout": {name: 7.125 for name in ("connect", "read", "write", "pool")}},
    )
    if port == 443:
        with pytest.raises(RestartAcceptanceError, match="unexpected_model_route"):
            _model_request_metadata(settings, request)
    else:
        result = _model_request_metadata(settings, request)
        assert result["timeout_seconds"] == 7.125
        assert len(result["body_sha256"]) == 64 and result["body_bytes"] > 0
        assert "synthetic-provider.invalid" not in json.dumps(result)


@pytest.mark.parametrize(
    "field,value,accepted",
    [
        ("fault_layer", "target_exact_ssh_socket_interruption", True),
        ("layer", "target_exact_ssh_socket_interruption", False),
        ("fault_layer", "synthetic_wrong_fault_layer", False),
    ],
)
def test_native_fault_requires_exact_frozen_marker_field(field, value, accepted):
    rid, request_sha, identity_sha = "a" * 32, "b" * 64, "c" * 64
    fault = {
        "request_ref": rid,
        "request_sha256": request_sha,
        "identity_binding_sha256": identity_sha,
        field: value,
        "request_master_preserved": True,
        "native_listener_preserved": True,
        "root_cli_completed": True,
        "after_absence": True,
        "socket_close_exec_count": 1,
        "session_signal_sent": False,
    }
    ledger = {
        "requests": [{"op": "apply", "request_sha256": request_sha}],
        "identity_binding_sha256": identity_sha,
    }

    def snapshot():
        return {"ledger": {"usage_count": 1, "intents": 1}, "projection": {"apply_fault": fault}}

    if accepted:
        result = _native(
            snapshot, expected_ack_behavior="exact_apply_socket_loss", rid=rid, ledger=ledger
        )
        assert result["fault_marker_bound"] is True
    else:
        with pytest.raises(RestartAcceptanceError, match="native_fault_marker_unbound"):
            _native(
                snapshot, expected_ack_behavior="exact_apply_socket_loss", rid=rid, ledger=ledger
            )


@pytest.mark.parametrize(
    "loss,ai,expired",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (True, True, True),
    ],
)
def test_real_process_ui_worker_once_restart_readonly(
    tmp_path, target, monkeypatch, loss, ai, expired
):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target, ai=ai)
    if loss:
        (tmp_path / "synthetic-loss").write_text("synthetic only", encoding="ascii")
    monkeypatch.setattr(
        SessionProcess,
        "_command",
        lambda _: [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--fake-session-child",
        ],
    )
    import browser_defense_session_native_smoke as driver

    monkeypatch.setattr(driver, "RESTART_OBSERVE_SECONDS", 0.3)

    def snapshot():
        state = decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))
        action = next(rid for rid, row in state["records"].items() if row.get("kind") == "action")
        session = next(iter(_session_refs(settings.data_dir)))
        evidence = _ledger(settings.data_dir, session, action)
        marker = None
        if loss:
            marker = {
                "request_ref": action,
                "request_sha256": next(
                    row["request_sha256"] for row in evidence["requests"] if row["op"] == "apply"
                ),
                "identity_binding_sha256": evidence["identity_binding_sha256"],
                "fault_layer": "target_exact_ssh_socket_interruption",
                "request_master_preserved": True,
                "native_listener_preserved": True,
                "root_cli_completed": True,
                "after_absence": True,
                "socket_close_exec_count": 1,
                "session_signal_sent": False,
            }
        if expired:
            (tmp_path / "expire-original-query").write_text("synthetic expiry", encoding="ascii")
        return {"ledger": {"usage_count": 1, "intents": 1}, "projection": {"apply_fault": marker}}

    result = run_session_browser(
        settings,
        stimulate_after_arm=lambda cursor: {"cursor_request_id": cursor},
        snapshot=snapshot,
        proof_path=tmp_path / "proof.json",
        expected_ack_behavior="exact_apply_socket_loss" if loss else "direct_ack",
        expected_ai_calls=int(ai),
    )
    assert result["completed"] and result["session_acceptance_passed"], result
    assert result["terminal_phase"] == ("reconciliation_only" if loss else "completed")
    assert result["ai_dispatches"] == int(ai)
    assert result["business_verdict"] == "pending" and not result["business_recollection"]
    assert result["controller_process_restart_verified"] and result["old_owner_readonly_verified"]
    assert result["original_query_state"] == ("expired" if expired else "active")
    assert not result["production_root_invoker"] and not result["production_business_collector"]
    assert result["production_session_worker"] and result["production_session_coordinator"]
    assert not result["production_http_transport"]
    assert result["processes"][0]["write_requests"] == {"mode": 1, "arm": 1, "session_start": 1}
    assert result["processes"][1]["write_requests"] == {"query": 1}
    assert sum(row["model_attempts"] for row in result["processes"]) == int(ai)
    assert all(row["session_worker_stopped"] for row in result["processes"])
    state = decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))
    assert sum(op == "apply" for op, _ in state["sent"]) == 1
    assert sum(op == "prepare" for op, _ in state["sent"]) == 1
    assert sum(op == "arm" for op, _ in state["sent"]) == 1
    assert not any(op == "revoke" for op, _ in state["sent"])
    proof = (tmp_path / "proof.json").read_text()
    summary = (tmp_path / "session-business-pending.md").read_text(encoding="utf-8")
    for value in (
        settings.token,
        "synthetic-session-provider-secret-only",
        "synthetic-provider.invalid",
        "business.opsark.invalid",
    ):
        assert value not in proof and value not in summary
    for rid in state["records"]:
        assert rid not in proof and rid not in summary
    assert "当前验收：待验收" in summary


def _session_refs(directory):
    import sqlite3

    with closing(sqlite3.connect(directory / "security.sqlite3")) as db, db:
        return [row[0] for row in db.execute("SELECT session_ref FROM defense_sessions_v1")]


if __name__ == "__main__":
    if sys.argv[1:] == ["--fake-session-child"]:
        import defense_session_process
        import paramiko

        monkey = pytest.MonkeyPatch()

        def no_ssh(*_args, **_kwargs):
            raise AssertionError("Synthetic session child cannot connect SSH")

        monkey.setattr(paramiko.SSHClient, "connect", no_ssh)
        monkey.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _fake_transport)
        monkey.setattr(defense_session_process, "_application", _fake_application)
        raise SystemExit(defense_session_process._child())
    raise SystemExit(2)
