"""Two real processes and Chromium; persisted FakeRoot/receipts are tmp-only."""

import json
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import pytest  # noqa: E402
import test_defense_api as root_fixture  # noqa: E402
from browser_defense_live_process_smoke import run_live_process_browser  # noqa: E402
from defense_live_process import LiveProcess  # noqa: E402
from defense_recheck_process_restart import RestartAcceptanceError  # noqa: E402
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402
from test_defense_config import document  # noqa: E402

from opsark.business_readiness import BusinessCheckResult, BusinessReadiness  # noqa: E402
from opsark.config import Settings  # noqa: E402
from opsark.defense_models import DefenseManifest, DefenseRequest  # noqa: E402


def _encode(value):
    if isinstance(value, DefenseRequest):
        return {"fake_type": "request", "value": value.wire_bytes().hex()}
    if isinstance(value, DefenseManifest):
        return {"fake_type": "manifest", "value": value.model_dump(mode="json")}
    if isinstance(value, datetime):
        return {"fake_type": "datetime", "value": value.isoformat()}
    if isinstance(value, dict):
        return {key: _encode(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_encode(item) for item in value]
    return value


def _decode(value):
    if isinstance(value, dict):
        if value.get("fake_type") == "request":
            return DefenseRequest.parse(bytes.fromhex(value["value"]))
        if value.get("fake_type") == "manifest":
            return DefenseManifest.model_validate_json(json.dumps(value["value"]))
        if value.get("fake_type") == "datetime":
            return datetime.fromisoformat(value["value"])
        return {key: _decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode(item) for item in value]
    return value


def _fake_application(settings):
    from opsark.main import create_app

    app = create_app(settings)
    controller = app.state.defense_service
    target = controller.targets["fixture"]
    base = settings.inventory_path.parent
    state_path = base / "fake-root-state.json"
    restarted = state_path.exists()
    root = root_fixture.FakeRoot(target, lambda: datetime.now(UTC))
    if restarted:
        state = _decode(json.loads(state_path.read_text()))
        root.mode, root.revision = state["mode"], state["revision"]
        root.records, root.sent, root.lose = state["records"], state["sent"], state["lose"]
    else:
        root.lose = "apply"

    def invoke(*args, **kwargs):
        if restarted and (base / "expire-on-restart").exists():
            for record in root.records.values():
                if record.get("state") == "active":
                    record["state"] = "expired"
        try:
            return root(*args, **kwargs)
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

    def collect(host):
        phase = (base / "fake-phase.txt").read_text(encoding="ascii")
        with (base / "fake-collections.txt").open("a", encoding="ascii") as output:
            output.write(phase + "\n")
        rows = []
        for check in host.business_checks:
            status = 503 if phase == "mixed" and check.id == "application" else 200
            incomplete = phase != "restored" and check.id == "dependency"
            rows.append(
                BusinessCheckResult(
                    id=check.id,
                    status="inconclusive"
                    if incomplete
                    else "failed"
                    if status == 503
                    else "passed",
                    http_status=None if incomplete else status,
                    status_matches=None if incomplete else status == 200,
                    body_matches=None if incomplete or status == 503 else True,
                )
            )
        return BusinessReadiness(
            host_id=host.public.id,
            status="failed"
            if phase == "mixed"
            else "inconclusive"
            if phase == "timeout_only"
            else "passed",
            checks=rows,
        )

    controller.invoker = invoke
    app.state.defense_recheck_service.collector = collect
    return app


@pytest.mark.parametrize("expire_on_restart", [False, True])
def test_live_process_driver_reconciles_same_task_without_replaying_apply(
    tmp_path, target, monkeypatch, expire_on_restart
):
    now = datetime.now(UTC)
    monkeypatch.setattr(root_fixture, "NOW", now)
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
        "synthetic-live-process-console-token-only",
        inventory_path=inventory,
        defense_inventory_path=registry,
        defense_policy_path=policy,
    )
    monkeypatch.setattr(
        LiveProcess,
        "_command",
        lambda _: [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--fake-child"],
    )

    def phase(value):
        assert value in {"mixed", "timeout_only", "restored"}
        (tmp_path / "fake-phase.txt").write_text(value, encoding="ascii")
        return {"phase": value}

    def snapshot():
        state = _decode(json.loads((tmp_path / "fake-root-state.json").read_text()))
        records = state["records"].values()
        return {
            "ledger": {
                "usage_count": sum("active_until" in record for record in records),
                "intents": sum("active_until" in record for record in records),
                "kernel_active": any(record.get("state") == "active" for record in records),
            }
        }

    result = run_live_process_browser(
        settings,
        stimulate_after_arm=lambda cursor: {"cursor_request_id": cursor},
        change_phase=phase,
        snapshot=snapshot,
        proof_path=tmp_path / "proof.json",
    )
    assert result["flow_completed"], result
    assert result["completed"] is (not expire_on_restart), result
    assert result["controller_process_restart_verified"]
    assert not result["live_root_reconnect_verified"]
    assert not result["production_root_invoker"] and not result["production_business_collector"]
    assert result["unknown_preserved_after_restart"] and result["old_reports_reopened"]
    assert result["processes"][0]["pid"] != result["processes"][1]["pid"]
    assert result["processes"][0]["write_requests"]["apply"] == 1
    assert not result["processes"][1]["write_requests"].get("apply")
    assert all(row["model_attempts"] == 0 and row["stopped"] for row in result["processes"])
    assert [row["historical_verdict"] for row in result["runs"]] == ["failed", "pending", "passed"]
    assert result["runs"][-1]["current_verdict"] == ("pending" if expire_on_restart else "passed")
    state = _decode(json.loads((tmp_path / "fake-root-state.json").read_text()))
    assert sum(op == "apply" for op, _rid in state["sent"]) == 1
    assert sum(op == "revoke" for op, _rid in state["sent"]) == int(not expire_on_restart)
    assert (tmp_path / "fake-collections.txt").read_text().splitlines() == [
        "mixed",
        "timeout_only",
        "restored",
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"ai_base_url": "https://synthetic-model.invalid/v1", "ai_model": "synthetic"},
        {
            "observation_enabled": True,
            "observation_host_ids": ("fixture",),
            "web_observation_enabled": True,
        },
    ],
)
def test_live_process_rejects_model_and_workers_before_spawning(tmp_path, monkeypatch, changes):
    settings = replace(
        Settings(tmp_path / "data", "synthetic-live-process-console-token-only"), **changes
    )

    def forbidden(_self):
        pytest.fail("No process may be created for an AI/worker-enabled configuration")

    monkeypatch.setattr(LiveProcess, "_command", forbidden)
    with pytest.raises(RestartAcceptanceError), LiveProcess(settings, tmp_path, 1):
        pytest.fail("The forbidden child started")


@pytest.mark.parametrize("failure", ["launcher_timeout", "runtime_timeout"])
def test_failed_stop_terminates_only_the_owned_runtime_handle(tmp_path, monkeypatch, failure):
    events, handle = [], object()

    class Launcher:
        returncode = None if failure == "launcher_timeout" else 0

        def wait(self, timeout):
            events.append(("wait_launcher", timeout))
            if self.returncode is None:
                raise subprocess.TimeoutExpired("owned-test-launcher", timeout)
            return self.returncode

        def poll(self):
            return self.returncode

        def kill(self):
            events.append(("kill_launcher",))
            self.returncode = 1

    class Kernel:
        alive = True

        def WaitForSingleObject(self, received, milliseconds):
            assert received is handle
            events.append(("wait_handle", milliseconds))
            return 258 if self.alive else 0

        def TerminateProcess(self, received, code):
            assert received is handle and code == 1
            events.append(("terminate_handle",))
            self.alive = False
            return True

        def CloseHandle(self, received):
            assert received is handle
            events.append(("close_handle",))
            return True

    fixture = LiveProcess(
        Settings(tmp_path / "data", "synthetic-live-process-console-token-only"), tmp_path, 1
    )
    monkeypatch.setattr(fixture, "process", Launcher())
    monkeypatch.setattr(fixture, "_runtime_handle", (Kernel(), handle))
    with pytest.raises(RuntimeError):
        fixture._finish(True)
    assert events.count(("terminate_handle",)) == events.count(("close_handle",)) == 1
    assert events.count(("kill_launcher",)) == int(failure == "launcher_timeout")
    assert fixture._runtime_handle is None
    assert ("wait_handle", 5000) in events


def test_wrong_selected_run_download_is_rejected(monkeypatch):
    import browser_defense_live_process_smoke as driver

    monkeypatch.setattr(driver, "_read", lambda *_: (200, b"correct original run summary", {}))
    monkeypatch.setattr(driver, "download", lambda *_: "a different selected run summary")
    with pytest.raises(RestartAcceptanceError, match="download_wrong_run"):
        driver._download_for_run(
            None,
            "http://127.0.0.1:1",
            Settings(Path("unused"), "synthetic-live-process-console-token-only"),
            "/fixed",
            "a" * 32,
        )


def test_reused_pid_creation_mismatch_closes_without_termination(tmp_path, monkeypatch):
    import defense_live_process as driver

    events, handle = [], object()

    class Kernel:
        def OpenProcess(self, rights, inherit, pid):
            assert rights == 0x101001 and inherit is False and pid == 1880
            events.append("open")
            return handle

        def CloseHandle(self, received):
            assert received is handle
            events.append("close")
            return True

        def TerminateProcess(self, *_):
            pytest.fail("A mismatched runtime must never be terminated")

    fixture = LiveProcess(
        Settings(tmp_path / "data", "synthetic-live-process-console-token-only"), tmp_path, 1
    )
    fixture.pid = 1880
    monkeypatch.setattr(driver, "_windows_kernel", lambda: Kernel())
    monkeypatch.setattr(
        driver, "_creation_filetime", lambda _kernel, received: 129 if received is handle else None
    )
    with pytest.raises(RestartAcceptanceError, match="runtime_creation_changed"):
        fixture._bind_windows_runtime({"creation_filetime": 128})
    assert events == ["open", "close"] and fixture._runtime_handle is None


if __name__ == "__main__":
    if sys.argv[1:] != ["--fake-child"]:
        raise SystemExit(2)
    import defense_live_process

    pytest.MonkeyPatch().setattr(defense_live_process, "_application", _fake_application)
    raise SystemExit(defense_live_process._child())
