"""History driver tests use only newly generated tmp credentials and fake Root."""

import ast
import inspect
from dataclasses import replace
from datetime import UTC, datetime

import pytest
import test_defense_api as root_fixture
from browser_defense_session_receipt_history_smoke import (
    ExpectedSession,
    ReceiptHistoryProcess,
    _configuration,
    _receipt,
    run_receipt_history,
)
from defense_recheck_process_restart import RestartAcceptanceError, database_images
from test_defense_ai import wire
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_native_driver import _settings

from opsark.automation_store import ModeChange
from opsark.control_modes import Mode
from opsark.defense_api import ArmRequest
from opsark.defense_client import invoke

REFERENCE = "a" * 32


def receipt(status="not_required"):
    value = {
        "v": 1,
        "session_ref": REFERENCE,
        "analysis_id": None,
        "status": status,
        "decision": None,
        "usage_state": None,
        "input_digest": None,
        "proof_sha256": None,
        "actions_executable": False,
    }
    if status not in {"not_required", "not_started"}:
        value.update(analysis_id="b" * 32, usage_state="consumed", input_digest="c" * 64)
    if status == "completed":
        value.update(decision="propose_defense", proof_sha256="d" * 64)
    return value


@pytest.mark.parametrize(
    "status", ["not_required", "not_started", "unknown", "completed", "refused", "failed", "stale"]
)
def test_expected_receipts_are_closed_fixed_summaries(status):
    value = receipt(status)
    assert _receipt(value, REFERENCE) == value
    assert ExpectedSession("fixture", REFERENCE, "e" * 64, "completed", value).validate()


@pytest.mark.parametrize(
    "change",
    [
        {"provider": "FAKE_PRIVATE"},
        {"actions_executable": True},
        {"v": True},
        {"session_ref": "f" * 32},
        {"status": "private"},
        {"proof_sha256": "d" * 64},
    ],
)
def test_receipt_unknown_fields_authority_or_no_intent_proof_is_rejected(change):
    with pytest.raises(RestartAcceptanceError):
        _receipt(receipt() | change, REFERENCE)


@pytest.mark.parametrize("change", ["session", "watch", "observe", "scan", "model", "key"])
def test_history_preserves_original_inert_configuration(tmp_path, target, change):
    settings = replace(_settings(tmp_path, target), defense_session_enabled=False)
    modified = {
        "session": lambda: replace(settings, defense_session_enabled=True),
        "watch": lambda: replace(
            settings, defense_task_watch_enabled=True, defense_task_watch_host_ids=("fixture",)
        ),
        "observe": lambda: replace(
            settings, observation_enabled=True, observation_host_ids=("fixture",)
        ),
        "scan": lambda: replace(
            settings, vulnerability_scan_enabled=True, vulnerability_scan_host_ids=("fixture",)
        ),
        "model": lambda: replace(
            settings,
            ai_base_url="https://synthetic.invalid/v1",
            ai_model="synthetic",
            ai_key="synthetic-private-model-key",
        ),
        "key": lambda: replace(settings, ai_key_file=tmp_path / "unread-private-key"),
    }[change]()
    with pytest.raises(RestartAcceptanceError):
        _configuration(modified)
    assert _configuration(settings)["defense_session_enabled"] is False


def test_driver_exposes_no_fake_application_or_server_factory():
    import browser_defense_session_receipt_history_smoke as driver

    signature = inspect.signature(run_receipt_history)
    assert set(signature.parameters) == {"settings", "expected", "proof_path"}
    source = inspect.getsource(driver)
    tree = ast.parse(source)
    assert "FakeRoot" not in source and "from opsark.main import create_app" in source
    assert "data/" not in source and "scoped_admin" not in source
    child = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_child"
    )
    assert "paramiko.SSHClient.connect = no_ssh" in ast.unparse(child)
    assert "httpx.HTTPTransport.handle_request = no_model" in ast.unparse(child)
    assert "httpx.AsyncHTTPTransport.handle_async_request = no_async_model" in ast.unparse(child)
    assert ReceiptHistoryProcess._command is not None


def test_failed_history_reports_actual_attempt_instead_of_a_default_zero(
    tmp_path, target, monkeypatch
):
    import browser_defense_session_receipt_history_smoke as driver

    settings = replace(_settings(tmp_path, target), defense_session_enabled=False)
    settings.data_dir.mkdir()

    class RefusedProcess:
        audit = {"ssh_attempts": 1, "model_attempts": 0, "blocked_writes": 0}

        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def refuse(*args):
        raise RestartAcceptanceError("synthetic_boundary_failure")

    monkeypatch.setattr(driver, "ReceiptHistoryProcess", RefusedProcess)
    monkeypatch.setattr(driver, "database_images", lambda _: {"synthetic": "a" * 64})
    monkeypatch.setattr(
        driver,
        "_get",
        lambda *args: ({"enabled": False, "running": False, "owned_sessions": 0}, {}),
    )
    monkeypatch.setattr(driver, "_browser_observe", refuse)
    expected = ExpectedSession("fixture", REFERENCE, "e" * 64, "completed", receipt())
    report = run_receipt_history(settings, (expected,), proof_path=tmp_path / "failed.safe.json")
    assert report["completed"] is False and report["ssh_attempts"] == 1
    assert report["model_attempts"] == report["blocked_writes"] == 0
    assert report.get("stores_unchanged") is not True


@pytest.mark.parametrize("mode", ["rule", "ai", "lost_ack"])
def test_actual_child_main_chromium_reads_synthetic_history_without_any_sender(
    tmp_path, target, main_module, monkeypatch, mode
):
    now = datetime.now(UTC)
    monkeypatch.setattr(root_fixture, "NOW", now)
    settings = _settings(tmp_path, target, ai=mode == "ai")
    app = main_module.create_app(settings)
    controller = app.state.defense_service
    controller.clock = lambda: now
    coordinator = app.state.defense_session_coordinator
    coordinator.clock = controller.clock
    root = root_fixture.FakeRoot(controller.targets["fixture"], controller.clock)
    if mode == "lost_ack":
        root.lose = "apply"

    def fake_invoke(target, call, role, *, admit=None, timeout=28):
        return root(target, call, role, admit=admit)

    controller.invoker = fake_invoke
    assert controller.invoker is not invoke
    calls = wire(monkeypatch, {"settings": settings}) if mode == "ai" else []
    changed = app.state.mode_coordinator.change_mode(
        ModeChange(mode=Mode.automatic, expected_revision=0)
    )
    cursor = controller.arm(
        "fixture", ArmRequest(expected_mode_revision=changed["revision"], confirm_arm=True)
    )
    coordinator.start(
        "fixture",
        cursor["request_id"],
        expected_mode_revision=changed["revision"],
        session_ref=REFERENCE,
    )
    for _ in range(10):
        result = coordinator.tick(REFERENCE)
        if result.phase in {"completed", "reconciliation_only", "stopped", "expired"}:
            break
    assert result.phase == ("reconciliation_only" if mode == "lost_ack" else "completed")
    expected = ExpectedSession(
        "fixture",
        REFERENCE,
        result.declaration_sha256,
        result.phase,
        coordinator.ai_receipt("fixture", REFERENCE),
    )
    inert = replace(
        settings,
        defense_session_enabled=False,
        ai_base_url=None,
        ai_model=None,
        ai_key=None,
        ai_key_file=None,
    )
    before = database_images(inert.data_dir)
    report = run_receipt_history(inert, (expected,), proof_path=tmp_path / "history-proof.json")
    assert (
        report["completed"] and report["browser_verified"] and report["old_owner_readonly_verified"]
    )
    assert report["stores_unchanged"] and report["fees_unchanged"]
    assert report["production_root_invoker"] and report["production_business_collector"]
    assert report["ssh_attempts"] == report["model_attempts"] == report["blocked_writes"] == 0
    assert report["rows"][0]["status"] == ("completed" if mode == "ai" else "not_required")
    assert report["rows"][0]["business_verdict"] == "pending"
    assert database_images(inert.data_dir) == before
    assert len(calls) == int(mode == "ai")
    raw = (tmp_path / "history-proof.json").read_text(encoding="ascii")
    for private in (settings.token, REFERENCE, "key_file", "provider_fingerprint", "-----BEGIN"):
        assert private not in raw
    with pytest.raises(RestartAcceptanceError):
        run_receipt_history(inert, (expected,), proof_path=tmp_path / "history-proof.json")
