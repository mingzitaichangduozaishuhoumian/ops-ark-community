"""Real application assembly; all transports, keys and business receipts are synthetic."""

import hashlib
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_defense_api import EVIDENCE, NOW, SOURCE, FakeRoot, policy
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.business_readiness import (
    BusinessCheckResult,
    BusinessReadiness,
    ReadinessStatus,
    business_profile_digest,
)
from opsark.config import Settings
from opsark.models import BusinessCheck

TOKEN = "synthetic-recheck-main-assembly-token-only"
PREFIX = "/api/hosts/fixture/ssh-defense"


@pytest.fixture
def application(tmp_path, target, keyset, monkeypatch, main_module):
    checks = tuple(
        BusinessCheck(
            id=name,
            domain="synthetic-business.invalid",
            port=42180,
            path="/" + name,
            expected_status=200,
            expected_body_sha256="a" * 64,
            read_only_confirmed=True,
        )
        for name in ("health", "application", "dependency")
    )
    known = tmp_path / "business-known-hosts"
    known.write_text(f"192.0.2.10 {keyset[0].get_name()} {keyset[0].get_base64()}\n")
    known.chmod(0o600)
    public = target.host.public.model_copy(
        update={"trusted_hosts_digest": hashlib.sha256(known.read_bytes()).hexdigest()}
    )
    target = replace(
        target,
        host=replace(target.host, public=public, known_hosts_file=known, business_checks=checks),
    )
    monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": target.host})
    monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": target})
    monkeypatch.setattr(main_module, "load_defense_policy", lambda _: policy(target))
    app = main_module.create_app(Settings(tmp_path / "data", TOKEN))
    controller = app.state.defense_service
    controller.clock = lambda: NOW
    root = FakeRoot(target, controller.clock)
    controller.invoker = root
    app.state.defense_recheck_service.clock = controller.clock
    outcomes: list[ReadinessStatus] = ["passed", "failed", "inconclusive"]
    collections = []

    def collect(host):
        assert host == target.host
        collections.append(tuple(outcomes))
        status = next(s for s in ("failed", "inconclusive", "uncovered", "passed") if s in outcomes)
        return BusinessReadiness(
            host_id="fixture",
            status=status,
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
                for check, status in zip(checks, outcomes, strict=True)
            ],
        )

    app.state.defense_recheck_service.collector = collect
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    return app, client, root, target, outcomes, collections


def approved_action(application):
    app, client, root, *_ = application
    assert (
        client.put("/api/automation", json={"mode": "assisted", "expected_revision": 0}).status_code
        == 200
    )
    armed = client.post(PREFIX + "/arm", json={"expected_mode_revision": 1, "confirm_arm": True})
    assert armed.status_code == 200
    cursor = armed.json()["request_id"]
    prepare = client.post(
        PREFIX + "/prepare",
        json={
            "cursor_request_id": cursor,
            "source_ref": SOURCE,
            "expected_evidence_sha256": EVIDENCE,
            "expected_mode_revision": 1,
        },
    )
    assert prepare.status_code == 200
    action = prepare.json()
    profile = app.state.defense_recheck_store.action_profile(action["request_id"])
    assert profile is not None
    applied = client.post(
        PREFIX + "/transactions/" + action["request_id"] + "/apply",
        json={
            "expected_manifest_sha256": action["manifest"]["sha256"],
            "expected_mode_revision": 1,
            "confirm_execute": True,
        },
    )
    assert applied.status_code == 200 and applied.json()["phase"] == "active"
    assert sum(op == "apply" for op, _ in root.sent) == 1
    return action


def test_real_main_recheck_matrix_and_old_exports_remain_bound_to_one_action(application):
    app, client, root, target, outcomes, collections = application
    action = approved_action(application)
    rid = action["request_id"]
    prefix = PREFIX + "/transactions/" + rid
    profile = app.state.defense_recheck_store.action_profile(rid)
    assert profile is not None and profile.check_ids == ("health", "application", "dependency")
    assert profile.business_profile_sha256 == business_profile_digest(target.host)
    assert "待验收" in client.get(prefix + "/handoff").text and not collections
    assert (
        client.put("/api/automation", json={"mode": "manual", "expected_revision": 1}).status_code
        == 200
    )
    refs = []
    for index, (states, expected) in enumerate(
        (
            (["passed", "failed", "inconclusive"], "failed"),
            (["passed", "passed", "inconclusive"], "pending"),
            (["passed", "passed", "passed"], "passed"),
        ),
        1,
    ):
        outcomes[:] = states
        ref = f"{index:032x}"
        refs.append(ref)
        body = {
            "run_ref": ref,
            "expected_manifest_sha256": action["manifest"]["sha256"],
            "expected_profile_sha256": profile.business_profile_sha256,
            "confirm_recheck": True,
        }
        result = client.post(prefix + "/rechecks", json=body)
        assert result.status_code == 200
        assert result.json()["historical_verdict"] == expected
        assert client.post(prefix + "/rechecks", json=body).status_code == 200
        assert len(collections) == index
    listing = client.get(prefix + "/rechecks").json()
    assert len(listing["runs"]) == 3
    for ref, expected in zip(refs, ("failed", "pending", "passed"), strict=True):
        record = client.get(prefix + "/rechecks/" + ref)
        assert record.status_code == 200 and record.json()["historical_verdict"] == expected
        exported = client.get(prefix + "/handoff", params={"run_ref": ref})
        assert exported.status_code == 200
        assert "attachment" in exported.headers["content-disposition"]
        for private in (
            TOKEN,
            "192.0.2.10",
            "synthetic-business.invalid",
            "source_ref",
            "key_file",
        ):
            assert private not in exported.text
    assert sum(op == "apply" for op, _ in root.sent) == 1
    assert not any(op == "revoke" for op, _ in root.sent)


def test_main_exposes_local_history_after_retiring_a_target(application):
    app, client, root, *_ = application
    action = approved_action(application)
    rid = action["request_id"]
    app.state.defense_service.targets.clear()
    before = tuple(root.sent)
    history = client.get("/api/ssh-defense/history-targets")
    assert history.status_code == 200
    assert history.json()["history_targets"] == [{"host_id": "fixture"}]
    assert client.get(PREFIX + "/transactions/" + rid).status_code == 200
    assert client.get(PREFIX + "/transactions/" + rid + "/handoff").status_code == 200
    assert tuple(root.sent) == before


def test_original_business_profile_is_sealed_before_the_first_prepare_dispatch(
    application, monkeypatch
):
    app, _, root, *_ = application
    ledger = app.state.defense_recheck_store
    seal = ledger.seal_action_profile
    captured = []

    def before_transport(profile):
        metadata = app.state.defense_store.request_metadata(profile.rid, "prepare")
        assert metadata.dispatch_phase == "intent" and metadata.send_started_at is None
        assert not any(op == "prepare" for op, _ in root.sent)
        captured.append(profile)
        return seal(profile)

    monkeypatch.setattr(ledger, "seal_action_profile", before_transport)
    action = approved_action(application)
    assert len(captured) == 1 and captured[0].rid == action["request_id"]
    assert ledger.action_profile(action["request_id"]) == captured[0]
