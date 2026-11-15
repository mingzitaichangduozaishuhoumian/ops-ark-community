"""Three real processes/Chromium; only tmp synthetic Root and accelerated ticks."""

import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import pytest  # noqa: E402
import test_defense_api as root_fixture  # noqa: E402
from browser_defense_task_watch_smoke import run_task_watch_browser  # noqa: E402
from defense_abrupt_process import AbruptProcess  # noqa: E402
from defense_recheck_process_restart import RestartAcceptanceError  # noqa: E402
from defense_task_watch_process import WatchProcess, _configuration, _decode  # noqa: E402
from test_defense_abrupt_process import _fake_crash_application  # noqa: E402
from test_defense_client import keyset as keyset  # noqa: E402
from test_defense_client import target as target  # noqa: E402
from test_defense_config import document  # noqa: E402
from test_defense_live_process import _decode as decode_fake  # noqa: E402
from test_defense_live_process import _encode  # noqa: E402

from opsark.config import Settings  # noqa: E402


def _fake_watch_application(settings):
    """Only this test entry accelerates the real worker's scheduling clock."""
    from opsark.main import create_app

    app = create_app(settings)
    controller = app.state.defense_service
    watcher = app.state.defense_task_watcher
    base = settings.inventory_path.parent
    state_path = base / "fake-root-state.json"
    state = decode_fake(json.loads(state_path.read_text()))
    root = root_fixture.FakeRoot(controller.targets["fixture"], lambda: datetime.now(UTC))
    root.mode, root.revision = state["mode"], state["revision"]
    root.records, root.sent, root.lose = state["records"], state["sent"], state["lose"]
    serial = Lock()

    def invoke(target, call, role, **options):
        with serial:
            request = call.request
            if (
                request.op == "query"
                and request.request_id in root.records
                and (
                    controller.automation.status()["mode"] == "manual"
                    or (base / "expire-before-watch").exists()
                )
            ):
                for item in root.records.values():
                    if item.get("state") == "active":
                        item["state"] = "expired"
            try:
                return root(target, call, role, **options)
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
        raise AssertionError("No business collector is part of this watcher test")

    app.state.defense_recheck_service.collector = forbid_collection
    clock_path = base / "fake-watch-clock.json"
    offset = [json.loads(clock_path.read_text())["offset"] if clock_path.exists() else 0]
    watcher.clock = lambda: datetime.now(UTC) + timedelta(seconds=offset[0])
    controller.clock = watcher.clock

    def run():
        while not watcher.stopped.is_set():
            watcher.tick()
            with (base / "fake-watch-ticks.txt").open("a", encoding="ascii") as output:
                output.write("tick\n")
            if controller.automation.status()["mode"] == "manual":
                offset[0] += 31
            clock_path.write_text(json.dumps({"offset": offset[0]}), encoding="ascii")
            watcher.stopped.wait(0.7)

    watcher._run = run
    return app


def _settings(tmp_path, target):
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
    return Settings(
        tmp_path / "data",
        "synthetic-task-watch-process-console-token-only",
        inventory_path=inventory,
        defense_inventory_path=registry,
        defense_policy_path=policy,
    )


@pytest.mark.parametrize("change", ["disabled", "multiple", "interval", "model"])
def test_special_watch_child_keeps_default_fixture_boundary(tmp_path, change):
    inert = Settings(
        tmp_path / "data",
        "synthetic-task-watch-configuration-token-only",
        defense_inventory_path=tmp_path / "registry.json",
        defense_policy_path=tmp_path / "policy.json",
        defense_task_watch_enabled=True,
        defense_task_watch_host_ids=("fixture",),
        defense_task_watch_interval_seconds=30,
    )
    modified = {
        "disabled": replace(inert, defense_task_watch_enabled=False),
        "multiple": replace(inert, defense_task_watch_host_ids=("fixture", "other")),
        "interval": replace(inert, defense_task_watch_interval_seconds=60),
        "model": replace(inert, ai_base_url="https://synthetic-model.invalid/v1"),
    }[change]
    with pytest.raises(RestartAcceptanceError):
        _configuration(modified)
    valid = _configuration(inert)
    assert _decode(json.loads(json.dumps(valid))) == inert
    from defense_live_process import _configuration as original_boundary

    with pytest.raises(RestartAcceptanceError):
        original_boundary(inert)


@pytest.mark.parametrize("expired_first", [False, True])
def test_real_background_followup_manual_ack_and_restart_no_http_query(
    tmp_path, target, monkeypatch, expired_first
):
    import browser_defense_task_watch_smoke as browser_fixture

    monkeypatch.setattr(root_fixture, "NOW", datetime.now(UTC))
    settings = _settings(tmp_path, target)
    if expired_first:
        (tmp_path / "expire-before-watch").write_text("synthetic expiry", encoding="ascii")
    monkeypatch.setattr(
        AbruptProcess,
        "_command",
        lambda _: [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--fake-crash-child"],
    )
    monkeypatch.setattr(
        WatchProcess,
        "_command",
        lambda _: [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--fake-watch-child"],
    )
    monkeypatch.setattr(browser_fixture, "RESTART_OBSERVE_SECONDS", 1.0)
    monkeypatch.setattr(browser_fixture, "WATCH_WAIT_SECONDS", 12)

    def snapshot():
        state = decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))
        records = list(state["records"].values())
        return {
            "ledger": {
                "usage_count": sum("active_until" in row for row in records),
                "intents": sum("active_until" in row for row in records),
                "kernel_active": any(row.get("state") == "active" for row in records),
            }
        }

    proof = run_task_watch_browser(
        settings,
        stimulate_after_arm=lambda cursor: {"cursor_request_id": cursor},
        snapshot=snapshot,
        proof_path=tmp_path / "proof.json",
    )
    if expired_first:
        assert not proof["completed"] and not proof["watch_acceptance_passed"], proof
        assert proof["phase"] == "reconciled_only" and proof["first_reconciled_state"] == "expired"
        assert proof["worker_automatic_queries_verified"] and not proof["manual_followup_verified"]
        assert len(proof["processes"]) == 2
    else:
        assert proof["completed"] and proof["watch_acceptance_passed"], proof
        assert proof["manual_followup_verified"] and proof["worker_automatic_queries_verified"]
        assert proof["ack_only_confirmed"] and proof["restart_events_and_budgets_preserved"]
        assert proof["business_verdict"] == "pending" and not proof["business_recollection"]
        assert proof["watch_after_restart"]["task"]["last_state"] == "expired"
        assert [item["state"] for item in proof["watch_after_restart"]["events"]] == [
            "active",
            "expired",
        ]
        assert proof["watch_after_restart"]["events"][0]["acknowledged_at"]
        assert len(proof["processes"]) == 3
        assert not proof["live_root_reconnect_verified"]
        assert not proof["production_root_invoker"] and not proof["production_business_collector"]
        assert not (tmp_path / "fake-collections.txt").exists()
        assert (tmp_path / "watch-business-pending.md").exists()
    assert proof["original_submission_unchanged"]
    assert proof["os_exit_boundary_verified"] and proof["actual_process_exit_code"] == 91
    assert all(item["stopped"] and item["model_attempts"] == 0 for item in proof["processes"])
    assert all(
        not any(
            item["write_requests"].get(op, 0)
            for op in ("arm", "prepare", "apply", "query", "revoke", "rechecks")
        )
        for item in proof["processes"][1:]
    )
    state = decode_fake(json.loads((tmp_path / "fake-root-state.json").read_text()))
    assert sum(op == "apply" for op, _ in state["sent"]) == 1
    assert sum(op == "revoke" for op, _ in state["sent"]) == 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--fake-crash-child"]:
        import defense_abrupt_process

        pytest.MonkeyPatch().setattr(
            defense_abrupt_process, "_application", _fake_crash_application
        )
        raise SystemExit(defense_abrupt_process._child())
    if sys.argv[1:] == ["--fake-watch-child"]:
        import defense_task_watch_process

        pytest.MonkeyPatch().setattr(
            defense_task_watch_process, "_application", _fake_watch_application
        )
        raise SystemExit(defense_task_watch_process._child())
    raise SystemExit(2)
