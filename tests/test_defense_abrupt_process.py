"""Actual os._exit and recovery; all Root/HTTP receipts are tmp-only synthetic."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import pytest  # noqa: E402
import test_defense_api as root_fixture  # noqa: E402
from browser_defense_abrupt_process_smoke import run_abrupt_process_browser  # noqa: E402
from defense_abrupt_process import EXIT_CODE, AbruptProcess  # noqa: E402
from defense_live_process import LiveProcess  # noqa: E402
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402
from test_defense_config import document  # noqa: E402
from test_defense_live_process import _decode, _fake_application  # noqa: E402

from opsark.config import Settings  # noqa: E402
from opsark.defense_client import DefenseClientError, UnknownDefenseResult  # noqa: E402


@pytest.mark.parametrize("kind", ["ordinary_error", "pre_dispatch", "different_request"])
def test_crash_boundary_does_not_accept_other_errors_or_request_ids(tmp_path, monkeypatch, kind):
    import defense_abrupt_process as fixture
    import httpx
    from defense_recheck_process_restart import RestartAcceptanceError

    recorded = []
    store = SimpleNamespace(record_unavailable=lambda *args, **kwargs: recorded.append(args))

    class App:
        state = SimpleNamespace(
            defense_service=SimpleNamespace(store=store, invoker=None),
            defense_recheck_service=SimpleNamespace(collector=None),
        )

        def middleware(self, _kind):
            return lambda function: function

    monkeypatch.setattr(fixture, "_application", lambda _: App())
    monkeypatch.setattr(httpx.AsyncClient, "send", httpx.AsyncClient.send)
    monkeypatch.setattr(fixture.os, "_exit", lambda _: pytest.fail("Must not kill this process"))
    fixture._crash_application(
        Settings(tmp_path / "data", "synthetic-crash-boundary-token-only"),
        {"audit": str(tmp_path / "audit.json")},
    )
    error = {
        "ordinary_error": OSError("FAKE_PRIVATE_EXCEPTION"),
        "pre_dispatch": DefenseClientError(),
        "different_request": UnknownDefenseResult("b" * 32),
    }[kind]
    try:
        raise error
    except Exception:
        if kind == "different_request":
            with pytest.raises(RestartAcceptanceError, match="unknown_request_changed"):
                store.record_unavailable("a" * 32, "apply")
        else:
            store.record_unavailable("a" * 32, "apply")
    assert len(recorded) == int(kind != "different_request")
    assert not (tmp_path / "apply-crash-marker.json").exists()
    assert not (tmp_path / "audit.json").exists()


def _fake_crash_application(settings):
    app = _fake_application(settings)
    original = app.state.defense_service.invoker

    def invoke(target, call, role, **options):
        try:
            return original(target, call, role, **options)
        except OSError:
            # Match the production client's normalized post-dispatch exception.
            # This test does not claim to destroy an actual SSH socket.
            raise UnknownDefenseResult(call.request.request_id) from None

    app.state.defense_service.invoker = invoke
    return app


@pytest.mark.parametrize("expire_on_restart", [False, True])
def test_abrupt_child_preserves_sendable_original_and_recovery_does_not_replay(
    tmp_path, target, monkeypatch, expire_on_restart
):
    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps(document(target)), encoding="ascii")
    registry.chmod(0o600)
    inventory = tmp_path / "hosts.toml"
    inventory.write_text(
        "[credentials.synthetic]\nkey_file = "
        + json.dumps(str(target.host.key_file))
        + "\nknown_hosts_file = "
        + json.dumps(str(target.host.known_hosts_file))
        + '\n[[hosts]]\nid = "fixture"\naddress = "192.0.2.10"\n'
        + 'site_domain = "business.opsark.invalid"\ncredential = "synthetic"\n'
        + "".join(
            '[[hosts.business_checks]]\nid = "'
            + name
            + '"\ndomain = "business.opsark.invalid"\npath = "/'
            + name
            + '"\nport = 42180\nexpected_body_sha256 = "'
            + "a" * 64
            + '"\nread_only_confirmed = true\n'
            for name in ("health", "application", "dependency")
        ),
        encoding="ascii",
    )
    inventory.chmod(0o600)
    policy = tmp_path / "policy.json"
    policy.write_text(root_fixture.policy(target).model_dump_json(), encoding="ascii")
    policy.chmod(0o600)
    if expire_on_restart:
        (tmp_path / "expire-on-restart").write_text("synthetic expiry only", encoding="ascii")
    (tmp_path / "fake-phase.txt").write_text("restored", encoding="ascii")
    settings = Settings(
        tmp_path / "data",
        "synthetic-abrupt-process-console-token-only",
        inventory_path=inventory,
        defense_inventory_path=registry,
        defense_policy_path=policy,
    )
    monkeypatch.setattr(
        AbruptProcess,
        "_command",
        lambda _: [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--fake-crash-child"],
    )
    monkeypatch.setattr(
        LiveProcess,
        "_command",
        lambda _: [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--fake-normal-child",
        ],
    )

    def phase(value):
        assert value in {"mixed", "timeout_only", "restored"}
        (tmp_path / "fake-phase.txt").write_text(value, encoding="ascii")
        return {"phase": value}

    def snapshot():
        state = _decode(json.loads((tmp_path / "fake-root-state.json").read_text()))
        records = list(state["records"].values())
        return {
            "ledger": {
                "usage_count": sum("active_until" in row for row in records),
                "intents": sum("active_until" in row for row in records),
                "kernel_active": any(row.get("state") == "active" for row in records),
            }
        }

    result = run_abrupt_process_browser(
        settings,
        stimulate_after_arm=lambda cursor: {"cursor_request_id": cursor},
        change_phase=phase,
        snapshot=snapshot,
        proof_path=tmp_path / "proof.json",
    )
    assert result["flow_completed"], result
    assert result["completed"] is (not expire_on_restart), result
    assert result["os_exit_boundary_verified"]
    assert result["actual_process_exit_code"] == EXIT_CODE
    assert result["apply_request_failed_without_response"]
    assert result["original_submission_unchanged"]
    assert result["controller_process_restart_verified"]
    assert result["unknown_preserved_after_restart"] and result["old_reports_reopened"]
    assert not result["live_root_reconnect_verified"]
    assert not result["production_root_invoker"] and not result["production_business_collector"]
    first, second = result["processes"]
    assert first["pid"] != second["pid"]
    assert first["termination_kind"] == "os_exit" and not first["graceful_shutdown"]
    assert first["actual_exit_code"] == EXIT_CODE and first["process_exit_verified"]
    assert first["boundary"]["client_result"] == "post_dispatch_result_unknown"
    assert first["boundary"]["unavailable_observation_committed"] is False
    assert first["write_requests"]["apply"] == 1
    assert not second["write_requests"].get("apply")
    assert all(row["model_attempts"] == 0 and row["stopped"] for row in (first, second))
    assert [row["historical_verdict"] for row in result["runs"]] == ["failed", "pending", "passed"]
    assert result["runs"][-1]["current_verdict"] == ("pending" if expire_on_restart else "passed")
    assert not (tmp_path / "controller-processes/process-1-stop.json").exists()
    state = _decode(json.loads((tmp_path / "fake-root-state.json").read_text()))
    assert sum(op == "apply" for op, _ in state["sent"]) == 1
    assert sum(op == "revoke" for op, _ in state["sent"]) == int(not expire_on_restart)
    assert (tmp_path / "fake-collections.txt").read_text().splitlines() == [
        "mixed",
        "timeout_only",
        "restored",
    ]


if __name__ == "__main__":
    if sys.argv[1:] == ["--fake-crash-child"]:
        import defense_abrupt_process

        pytest.MonkeyPatch().setattr(
            defense_abrupt_process, "_application", _fake_crash_application
        )
        raise SystemExit(defense_abrupt_process._child())
    if sys.argv[1:] == ["--fake-normal-child"]:
        import defense_live_process

        pytest.MonkeyPatch().setattr(defense_live_process, "_application", _fake_application)
        raise SystemExit(defense_live_process._child())
    raise SystemExit(2)
