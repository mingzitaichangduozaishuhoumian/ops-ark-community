"""Real Python/Uvicorn restarts; tmp-only fake Root, owned synthetic keys and receipts."""

import json

import pytest
from defense_recheck_process_restart import (
    OriginalHistory,
    RestartAcceptanceError,
    StoredRun,
    run_offline_restart,
)
from fastapi.testclient import TestClient
from test_defense_api import NOW, FakeRoot, policy
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_config import document
from test_defense_recheck_application import TOKEN, approved_action

from opsark.business_readiness import BusinessCheckResult, BusinessReadiness, ReadinessStatus
from opsark.config import Settings, load_hosts
from opsark.defense_config import load_defense_targets
from opsark.defense_recheck_models import DefenseRecheckDeclaration


def test_two_real_processes_keep_history_claims_modes_and_all_ten_stores(
    tmp_path, target, main_module
):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps(document(target)), encoding="ascii")
    registry.chmod(0o600)
    inventory = tmp_path / "hosts.toml"
    inventory.write_text(
        "[credentials.synthetic]\n"
        + "key_file = "
        + json.dumps(str(target.host.key_file))
        + "\n"
        + "known_hosts_file = "
        + json.dumps(str(target.host.known_hosts_file))
        + "\n"
        + '[[hosts]]\nid = "fixture"\naddress = "192.0.2.10"\n'
        + 'site_domain = "synthetic-business.invalid"\ncredential = "synthetic"\n'
        + "".join(
            "[[hosts.business_checks]]\nid = "
            + json.dumps(name)
            + '\ndomain = "synthetic-business.invalid"\npath = "/'
            + name
            + '"\n'
            + 'port = 42180\nexpected_body_sha256 = "'
            + "a" * 64
            + '"\nread_only_confirmed = true\n'
            for name in ("health", "application", "dependency")
        ),
        encoding="ascii",
    )
    inventory.chmod(0o600)
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(policy(target).model_dump_json(), encoding="ascii")
    policy_file.chmod(0o600)
    settings = Settings(
        tmp_path / "data",
        TOKEN,
        inventory_path=inventory,
        defense_inventory_path=registry,
        defense_policy_path=policy_file,
    )
    hosts = load_hosts(settings)
    loaded = load_defense_targets(settings, hosts, {})["fixture"]
    app = main_module.create_app(settings)
    root = FakeRoot(loaded, lambda: NOW)
    app.state.defense_service.invoker = root
    app.state.defense_service.clock = lambda: NOW
    app.state.defense_recheck_service.clock = lambda: NOW
    outcomes: list[ReadinessStatus] = ["passed", "failed", "inconclusive"]
    collected = []

    def collect(host):
        assert host == loaded.host
        collected.append(tuple(outcomes))
        return BusinessReadiness(
            host_id="fixture",
            status="failed"
            if "failed" in outcomes
            else "inconclusive"
            if "inconclusive" in outcomes
            else "passed",
            checks=[
                BusinessCheckResult(
                    id=check.id,
                    status=status,
                    http_status=200 if status == "passed" else 503 if status == "failed" else None,
                    status_matches=True
                    if status == "passed"
                    else False
                    if status == "failed"
                    else None,
                    body_matches=True if status == "passed" else None,
                )
                for check, status in zip(host.business_checks, outcomes, strict=True)
            ],
        )

    app.state.defense_recheck_service.collector = collect
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    application = app, client, root, loaded, outcomes, collected
    action = approved_action(application)
    rid = action["request_id"]
    assert (
        client.put("/api/automation", json={"mode": "manual", "expected_revision": 1}).status_code
        == 200
    )
    profile = app.state.defense_recheck_store.action_profile(rid)
    runs = []
    prefix = "/api/hosts/fixture/ssh-defense/transactions/" + rid
    matrix: tuple[tuple[list[ReadinessStatus], str], ...] = (
        (["passed", "failed", "inconclusive"], "failed"),
        (["passed", "passed", "inconclusive"], "pending"),
        (["passed", "passed", "passed"], "passed"),
    )
    for index, (states, verdict) in enumerate(matrix, 1):
        outcomes[:] = states
        ref = f"{index:032x}"
        body = {
            "run_ref": ref,
            "expected_manifest_sha256": action["manifest"]["sha256"],
            "expected_profile_sha256": profile.business_profile_sha256,
            "confirm_recheck": True,
        }
        response = client.post(prefix + "/rechecks", json=body)
        assert response.status_code == 200 and response.json()["historical_verdict"] == verdict
        runs.append(StoredRun(ref, verdict))
    declaration = DefenseRecheckDeclaration(
        run_ref="4" * 32,
        host_id="fixture",
        rid=rid,
        expected_manifest_sha256=action["manifest"]["sha256"],
        expected_profile_sha256=profile.business_profile_sha256,
    )
    ledger = app.state.defense_recheck_store
    ledger.create(declaration, now=NOW)
    ledger.claim(declaration.run_ref, owner="synthetic-dead-process", now=NOW)
    runs.append(StoredRun(declaration.run_ref, "pending", "claimed"))
    sent_before, collected_before = tuple(root.sent), tuple(collected)
    proof = run_offline_restart(
        settings,
        OriginalHistory("fixture", rid, tuple(runs)),
        output=tmp_path / "restart",
        browser=True,
        verify_write_barrier=True,
    )
    assert proof["completed"] and proof["controller_process_restart_verified"]
    assert proof["browser_verified"] and not proof["live_root_reconnect_verified"]
    assert len(proof["database_images_before_between_after"]) == 10
    assert len(proof["sealed_runs"]) == 4
    assert [row["historical_verdict"] for row in proof["processes"][1]["runs"]] == [
        "failed",
        "pending",
        "passed",
        "pending",
    ]
    assert all(
        row["blocked_writes"] == 1 and row["ssh_attempts"] == row["model_attempts"] == 0
        for row in proof["processes"]
    )
    assert proof["processes"][0]["pid"] != proof["processes"][1]["pid"]
    assert tuple(root.sent) == sent_before and tuple(collected) == collected_before
    assert len(collected) == 3 and sum(op == "apply" for op, _ in root.sent) == 1


def test_offline_restart_rejects_model_settings_before_opening_original_history(tmp_path):
    source = tmp_path / "synthetic-empty-data"
    source.mkdir()
    settings = Settings(source, TOKEN, ai_key="synthetic-disabled-provider-only")
    with pytest.raises(RestartAcceptanceError, match="offline_settings_required"):
        run_offline_restart(
            settings,
            OriginalHistory("fixture", "a" * 32, (StoredRun("b" * 32, "passed"),)),
            output=tmp_path / "must-not-exist",
        )
    assert not tuple(source.iterdir()) and not (tmp_path / "must-not-exist").exists()
