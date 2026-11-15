"""Product API/SQLite regression tests with a synthetic, bounded host transport."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_managed_nginx_host import CANDIDATE, ORIGINAL, TARGET, Lab, action, journal

from opsark import main
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.config import Settings
from opsark.models import HostPublic, Report
from opsark.nginx_action_client import NginxActionTransportError

TOKEN = "synthetic-managed-nginx-test-console-token-01"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
ROOT = "/api/nginx-actions"


def action_id(plan_id, action):
    return hashlib.sha256(
        json.dumps(
            {"domain": "opsark-nginx-action-v1", "plan_id": plan_id, "action": action},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


class Host:
    """No file/network access; simulates root operation replies at the RPC boundary."""

    def __init__(self):
        self.calls = []
        self.plans = {}
        self.results = {}
        self.lose_prepare = False
        self.lose_submit = False
        self.override = None
        self.before_submit = None

    def __call__(self, target, operation, *, policy_digest=None, **fields):
        policy = target.policy_digest if policy_digest is None else policy_digest
        self.calls.append((operation, policy, fields))
        if operation in {"prepare", "rollback_prepare"}:
            restore = operation == "rollback_prepare"
            plan = fields["plan_id"]
            source, candidate = ("2" * 64, "1" * 64) if restore else ("1" * 64, "2" * 64)
            action = "restore" if restore else "apply"
            reply = {
                "schema_version": 1,
                "status": "ready",
                "plan_id": plan,
                "action": action,
                "action_id": action_id(plan, action),
                "policy_digest": policy,
                "plan_digest": hashlib.sha256(plan.encode()).hexdigest(),
                "mode_revision": fields["mode_revision"],
                "source_sha256": source,
                "candidate_sha256": candidate,
                "backup_sha256": "1" * 64,
                "context_sha256": "5" * 64,
                "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                "upstream_before": "127.0.0.1:18082" if restore else "127.0.0.1:18081",
                "upstream_after": "127.0.0.1:18081" if restore else "127.0.0.1:18082",
                "affected_site_ids": ["fixture"],
                "syntax": "passed",
                "original_action_id": fields.get("original_action_id"),
            }
            self.plans[plan] = reply
            if self.lose_prepare:
                raise NginxActionTransportError("test-loss")
        elif operation == "plan_status":
            reply = self.plans[fields["plan_id"]]
        elif operation == "submit":
            if self.before_submit:
                self.before_submit(fields)
            plan = self.plans[fields["plan_id"]]
            reply = {
                "schema_version": 1,
                "status": "unknown" if self.lose_submit else "verified",
                "policy_digest": policy,
                "action_id": fields["action_id"],
                "action": plan["action"],
                "plan_id": fields["plan_id"],
                "plan_digest": fields["plan_digest"],
                "mode_revision": fields["mode_revision"],
                "reason": None,
                "reconciliation_status": None,
            }
            self.results[fields["action_id"]] = reply
            if self.lose_submit:
                raise NginxActionTransportError("test-loss")
        else:
            reply = self.results[fields["action_id"]]
            if operation == "observe":
                reply = {**reply, "reconciliation_status": "verified"}
        return self.override(reply) if self.override else reply


def change_mode(client, mode, revision):
    response = client.put(
        "/api/automation", headers=AUTH, json={"mode": mode, "expected_revision": revision}
    )
    assert response.status_code == 200
    return response.json()["revision"]


def prepare(client, revision):
    response = client.post(
        ROOT + "/prepare",
        headers=AUTH,
        json={"host_id": "test-nginx", "expected_mode_revision": revision},
    )
    assert response.status_code == 200
    return response.json()


def approve(client, row, **updates):
    body = {
        "expected_plan_digest": row["plan"]["plan_digest"],
        "expected_mode_revision": row["plan"]["mode_revision"],
        "confirm": True,
        **updates,
    }
    return client.post(f"{ROOT}/{row['plan_id']}/approve", headers=AUTH, json=body)


@pytest.fixture
def product(tmp_path, monkeypatch):
    target = SimpleNamespace(
        policy_digest="a" * 64, target_scope="b" * 64, transport_scope="c" * 64
    )
    monkeypatch.setattr(main, "load_nginx_targets", lambda *_args: {"test-nginx": target})
    settings = Settings(tmp_path, TOKEN)
    application = main.create_app(settings)
    transport = Host()
    application.state.nginx_action_service.invoker = transport
    with TestClient(application) as client:
        yield client, transport, settings, target


def test_default_off_requires_auth_and_leaves_no_new_table(tmp_path):
    app = main.create_app(Settings(tmp_path, TOKEN))
    with TestClient(app) as client:
        assert client.get(ROOT).status_code == 401
        assert client.get(ROOT, headers=AUTH).json() == []
        assert (
            client.post(
                ROOT + "/prepare",
                headers=AUTH,
                json={
                    "host_id": "test-nginx",
                    "expected_mode_revision": 0,
                },
            ).status_code
            == 403
        )
    with closing(sqlite3.connect(tmp_path / "automation.sqlite3")) as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='nginx_managed_actions'"
        ).fetchone()
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='nginx_action_handoff'"
        ).fetchone()


def bind_report(client, target, *, host_id="test-nginx", report_host=None, future=False):
    public = HostPublic(id=host_id, name="synthetic target", address="192.0.2.1", source="ssh")
    target.host = SimpleNamespace(public=public)
    observed = public if report_host is None else report_host
    report = Report(
        id="synthetic-nginx-report",
        host_id=observed.id,
        host_name=observed.name,
        scenario="web_502",
        source="ssh",
        created_at=datetime.now(UTC) + (timedelta(hours=1) if future else timedelta()),
        status="inconclusive",
        title="synthetic report",
        summary="synthetic report",
        facts=[],
        candidates=[],
        missing=[],
        evidence=[],
        next_steps=[],
        scope_hash=diagnostic_scope_for(observed),
        target=observed,
    )
    client.app.state.store.save(report)
    return report


def linked_plan(client, revision, report_id):
    return client.post(
        ROOT + "/prepare",
        headers=AUTH,
        json={"host_id": "test-nginx", "expected_mode_revision": revision, "report_id": report_id},
    )


@pytest.mark.parametrize("mismatch", ["unknown", "changed_registration", "future"])
def test_handoff_prepare_refuses_untrusted_original_report_before_root(product, mismatch):
    client, transport, _, target = product
    changed = HostPublic(
        id="test-nginx", name="synthetic target", address="192.0.2.2", source="ssh"
    )
    report = bind_report(
        client,
        target,
        report_host=changed if mismatch == "changed_registration" else None,
        future=mismatch == "future",
    )
    reply = linked_plan(client, 0, "unknown" if mismatch == "unknown" else report.id)
    assert reply.status_code == 409
    assert transport.calls == []


def test_handoff_preserves_original_report_and_receipt_observation_after_deregistration(product):
    client, transport, settings, target = product
    report = bind_report(client, target)
    service = client.app.state.nginx_action_service
    rev = change_mode(client, "assisted", 0)
    linked = linked_plan(client, rev, report.id).json()
    assert service.read_handoff(linked["plan_id"]) is None
    transport.lose_submit = True
    assert approve(client, linked).json()["blocking"] is True
    original = service.read_handoff(linked["plan_id"])
    assert original["report_id"] == report.id
    assert original["host_scope"] == scope_for(target.host.public)
    assert original["operation_status"] == "unknown" and original["receipt_source"] is None
    assert original["approved_at"] and original["receipt_observed_at"] is None
    assert client.post(f"{ROOT}/{linked['plan_id']}/observe", headers=AUTH).status_code == 200
    observed = service.read_handoff(linked["plan_id"])
    assert observed["receipt_source"] == "observe"
    assert observed["receipt_observed_at"] >= observed["approved_at"] == original["approved_at"]
    assert (
        observed["operation_status"] == "unknown"
        and observed["reconciliation_status"] == "verified"
    )
    assert observed["blocking"] is False
    assert not {"plan", "receipt", "policy_digest", "upstream_before"}.intersection(observed)

    restored = client.post(
        f"{ROOT}/{linked['plan_id']}/rollback/prepare",
        headers=AUTH,
        json={"expected_mode_revision": rev},
    ).json()
    transport.lose_submit = False
    assert approve(client, restored).json()["status"] == "verified"
    rollback = service.read_handoff(restored["plan_id"])
    assert rollback["action"] == "restore" and rollback["receipt_source"] == "submit"
    assert rollback["original_action_id"] == observed["action_id"]
    assert (
        rollback["report_id"] == observed["report_id"]
        and rollback["host_scope"] == observed["host_scope"]
    )

    historical = main.create_app(settings).state.nginx_action_service
    historical.targets.clear()
    before_read = len(transport.calls)
    assert historical.read_handoff(linked["plan_id"]) == observed
    assert historical.read_handoff(restored["plan_id"]) == rollback
    assert len(transport.calls) == before_read


def test_handoff_does_not_infer_evidence_for_unlinked_action(product):
    client, _, _, _ = product
    rev = change_mode(client, "assisted", 0)
    legacy = prepare(client, rev)
    assert approve(client, legacy).json()["status"] == "verified"
    assert client.app.state.nginx_action_service.read_handoff(legacy["plan_id"]) is None


def test_handoff_rejects_changed_local_report_link_without_querying_root(product):
    client, transport, settings, target = product
    report = bind_report(client, target)
    rev = change_mode(client, "assisted", 0)
    linked = linked_plan(client, rev, report.id).json()
    assert approve(client, linked).json()["status"] == "verified"
    with closing(sqlite3.connect(settings.data_dir / "automation.sqlite3")) as db, db:
        db.execute(
            "UPDATE nginx_action_handoff SET report_id=? WHERE plan_id=?",
            ("unrelated-synthetic-report", linked["plan_id"]),
        )
    before = list(transport.calls)
    service = client.app.state.nginx_action_service
    with pytest.raises(ValueError, match="交接登记"):
        service.read_handoff(linked["plan_id"])
    refused = client.post(
        f"{ROOT}/{linked['plan_id']}/rollback/prepare",
        headers=AUTH,
        json={"expected_mode_revision": rev},
    )
    assert refused.status_code == 503
    assert transport.calls == before


def test_preview_requires_explicit_current_assisted_approval(product):
    client, transport, _, _ = product
    row = prepare(client, 0)
    assert row["status"] == "ready" and not row["approved"]
    assert approve(client, row).status_code == 409
    assert [op for op, _, _ in transport.calls] == ["prepare"]
    revision = change_mode(client, "assisted", 0)
    assert approve(client, row).status_code == 409
    row = prepare(client, revision)
    assert approve(client, row, confirm=1).status_code == 422
    assert approve(client, row, expected_plan_digest="b" * 64).status_code == 409
    assert approve(client, row, path="/unregistered").status_code == 422
    result = approve(client, row).json()
    assert result["status"] == "verified" and result["approved"]
    assert approve(client, row).json() == result
    assert [op for op, _, _ in transport.calls].count("submit") == 1


def test_loss_recovers_original_plan_then_reads_original_action_without_replay(product):
    client, transport, settings, _ = product
    revision = change_mode(client, "assisted", 0)
    transport.lose_prepare = True
    row = prepare(client, revision)
    assert row["status"] == "prepare_pending"
    plan_id = row["plan_id"]
    row = client.get(f"{ROOT}/{plan_id}", headers=AUTH).json()
    assert row["status"] == "ready" and row["plan_id"] == plan_id
    assert [op for op, _, _ in transport.calls] == ["prepare", "plan_status"]

    def durable(fields):
        with closing(sqlite3.connect(settings.data_dir / "automation.sqlite3")) as db:
            assert db.execute(
                "SELECT state,approval_id FROM nginx_managed_actions WHERE plan_id=?", (plan_id,)
            ).fetchone() == ("submitting", fields["approval_id"])

    transport.before_submit = durable
    transport.lose_submit = True
    lost = approve(client, row).json()
    assert lost["status"] == "unknown" and lost["approved"]
    assert approve(client, row).json() == lost
    assert (
        client.post(
            ROOT + "/prepare",
            headers=AUTH,
            json={"host_id": "test-nginx", "expected_mode_revision": revision},
        ).status_code
        == 409
    )
    raw = client.get(f"{ROOT}/{plan_id}", headers=AUTH).json()
    assert raw["receipt"]["status"] == "unknown"
    observed = client.post(f"{ROOT}/{plan_id}/observe", headers=AUTH).json()
    assert (
        observed["status"] == "unknown"
        and observed["receipt"]["reconciliation_status"] == "verified"
    )
    assert client.get(f"{ROOT}/{plan_id}", headers=AUTH).json() == observed
    assert [op for op, _, _ in transport.calls].count("submit") == 1
    assert (
        transport.calls[-2][2] == transport.calls[-1][2] == {"action_id": row["plan"]["action_id"]}
    )


def test_only_bound_post_expiry_no_start_proof_releases_the_host(product):
    client, host, _, _ = product
    service = client.app.state.nginx_action_service
    revision = change_mode(client, "assisted", 0)
    plan = prepare(client, revision)["plan"]
    row = {"plan_id": plan["plan_id"], "plan": plan}
    query = f"{ROOT}/{plan['plan_id']}"
    proof = {
        **{
            name: plan[name]
            for name in ("action", "action_id", "plan_id", "plan_digest", "mode_revision")
        },
        "schema_version": 1,
        "policy_digest": plan["policy_digest"],
        "status": "not_started",
        "reason": "expired",
        "reconciliation_status": None,
    }
    operations = []
    returned = {**proof, "plan_digest": "d" * 64}

    def invoke(target, operation, **fields):
        operations.append(operation)
        if operation == "submit":
            raise NginxActionTransportError("test-no-delivery")
        if operation == "status":
            return proof
        if operation == "reconcile_status":
            assert fields == {
                name: proof[name]
                for name in (
                    "policy_digest",
                    "action_id",
                    "plan_id",
                    "plan_digest",
                    "mode_revision",
                )
            }
            return returned
        return host(target, operation, **fields)

    service.invoker = invoke
    assert approve(client, row).json()["status"] == "unknown"
    assert client.get(query, headers=AUTH).json()["status"] == "unknown"
    assert operations == ["submit", "status"]
    service.clock = lambda: datetime.fromisoformat(plan["expires_at"]) + timedelta(seconds=1)
    assert client.get(query, headers=AUTH).json()["status"] == "unknown"
    returned = proof
    closed = client.get(query, headers=AUTH).json()
    assert closed["approved"] and closed["status"] == "not_started"
    assert closed["receipt"] == proof
    assert approve(client, row).json() == closed
    assert prepare(client, revision)["status"] == "ready"
    assert operations == ["submit", "status", "reconcile_status", "reconcile_status", "prepare"]


def test_published_disk_old_live_allows_only_independent_original_restore(product):
    client, host, _, _ = product
    revision = change_mode(client, "assisted", 0)
    original = prepare(client, revision)
    original_url = f"{ROOT}/{original['plan_id']}"
    host.lose_submit = True
    assert approve(client, original).json()["status"] == "unknown"
    assert (
        client.post(
            f"{original_url}/rollback/prepare",
            headers=AUTH,
            json={"expected_mode_revision": revision},
        ).status_code
        == 409
    )
    observed = "disk_published_live_previous"
    host.override = lambda reply: {**reply, "reconciliation_status": observed}
    result = client.post(f"{original_url}/observe", headers=AUTH).json()
    assert result["status"] == "unknown" and result["receipt"]["reconciliation_status"] == observed
    host.override = None
    assert client.get(original_url, headers=AUTH).json() == result
    assert (
        client.post(
            ROOT + "/prepare",
            headers=AUTH,
            json={"host_id": "test-nginx", "expected_mode_revision": revision},
        ).status_code
        == 409
    )
    restored = client.post(
        f"{original_url}/rollback/prepare", headers=AUTH, json={"expected_mode_revision": revision}
    ).json()
    assert restored["plan"]["original_action_id"] == original["plan"]["action_id"]
    assert restored["plan_id"] != original["plan_id"]
    assert approve(client, restored, confirm=False).status_code == 422
    uncertain_restore = approve(client, restored).json()
    assert uncertain_restore["blocking"]
    host.override = lambda reply: {**reply, "reconciliation_status": "unchanged_from_preview"}
    closed_restore = client.post(f"{ROOT}/{restored['plan_id']}/observe", headers=AUTH).json()
    host.override = None
    assert not closed_restore["blocking"] and closed_restore["status"] == "unknown"
    assert closed_restore["receipt"]["reconciliation_status"] == "unchanged_from_preview"
    assert client.get(original_url, headers=AUTH).json() == result
    assert approve(client, restored).json() == closed_restore
    retry = client.post(
        f"{original_url}/rollback/prepare", headers=AUTH, json={"expected_mode_revision": revision}
    ).json()
    assert retry["plan_id"] != restored["plan_id"]
    host.lose_submit = False
    assert approve(client, retry).json()["status"] == "verified"
    assert client.get(original_url, headers=AUTH).json()["receipt"] == result["receipt"]
    assert prepare(client, revision)["status"] == "ready"
    assert [op for op, _, _ in host.calls].count("submit") == 3


def test_unchanged_original_closes_only_after_matching_observation(product):
    client, host, _, _ = product
    revision = change_mode(client, "assisted", 0)
    original = prepare(client, revision)
    plan_url = f"{ROOT}/{original['plan_id']}"
    host.lose_submit = True
    assert approve(client, original).json()["blocking"]
    host.override = lambda reply: {
        **reply,
        "reconciliation_status": "unchanged_from_preview",
        "mode_revision": revision + 1,
    }
    assert client.post(f"{plan_url}/observe", headers=AUTH).json()["blocking"]
    host.override = lambda reply: {**reply, "reconciliation_status": "unchanged_from_preview"}
    settled = client.post(f"{plan_url}/observe", headers=AUTH).json()
    host.override = None
    assert not settled["blocking"] and settled["status"] == "unknown"
    assert settled["receipt"]["reconciliation_status"] == "unchanged_from_preview"
    assert client.get(plan_url, headers=AUTH).json() == settled
    assert approve(client, original).json() == settled
    assert (
        client.post(
            f"{plan_url}/rollback/prepare", headers=AUTH, json={"expected_mode_revision": revision}
        ).status_code
        == 409
    )
    assert prepare(client, revision)["plan_id"] != original["plan_id"]
    assert [op for op, _, _ in host.calls].count("submit") == 1


def test_host_reconciles_approved_intent_interrupted_before_rename(product, monkeypatch):
    client, _, _, target = product
    lab = Lab(monkeypatch)
    target.policy_digest = lab.policy.policy_digest
    operations = []

    def invoke(selected, operation, *, policy_digest=None, **fields):
        assert policy_digest in {None, selected.policy_digest}
        operations.append(operation)
        return lab.call(operation, **fields)

    client.app.state.nginx_action_service.invoker = invoke
    revision = change_mode(client, "assisted", 0)
    original = prepare(client, revision)
    original_url = f"{ROOT}/{original['plan_id']}"

    def before_replace(*_args, **_kwargs):
        assert lab.events == ["intent"]
        raise OSError("synthetic interruption before rename")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(action.os, "replace", before_replace)
        pending = approve(client, original).json()
    assert pending["approved"] and pending["blocking"] and pending["status"] == "unknown"
    assert lab.files[TARGET] == ORIGINAL
    result = client.post(f"{original_url}/observe", headers=AUTH).json()
    assert result["status"] == "unknown" and not result["blocking"]
    assert result["receipt"]["reconciliation_status"] == "unchanged_from_preview"
    assert approve(client, original).json() == result
    assert client.get(original_url, headers=AUTH).json() == result
    fresh = prepare(client, revision)
    assert fresh["plan_id"] != original["plan_id"]
    assert approve(client, fresh).json()["status"] == "verified"
    assert lab.files[TARGET] == CANDIDATE and lab.events.count("replace") == 1
    assert operations.count("submit") == 2


@pytest.mark.parametrize("lose_restore_verification", [False, True])
def test_host_protocol_recovers_both_disconnect_boundaries(
    product, monkeypatch, lose_restore_verification
):
    client, _, _, target = product
    lab = Lab(monkeypatch)
    target.policy_digest = lab.policy.policy_digest
    service = client.app.state.nginx_action_service
    calls = []
    drop_before_delivery = True

    def invoke(selected, operation, *, policy_digest=None, **fields):
        assert policy_digest in {None, selected.policy_digest}
        calls.append(operation)
        if operation == "submit" and drop_before_delivery:
            raise NginxActionTransportError("test-no-delivery")
        return lab.call(operation, **fields)

    service.invoker = invoke
    revision = change_mode(client, "assisted", 0)
    missing = prepare(client, revision)
    missing_url = f"{ROOT}/{missing['plan_id']}"
    assert approve(client, missing).json()["blocking"]
    assert client.get(missing_url, headers=AUTH).json()["blocking"]
    deadline = datetime.fromisoformat(missing["plan"]["expires_at"])

    class ExpiredClock(datetime):
        @classmethod
        def now(cls, _tz):
            return deadline + timedelta(seconds=1)

    with monkeypatch.context() as clock:
        clock.setattr(action, "datetime", ExpiredClock)
        clock.setattr(service, "clock", lambda: ExpiredClock.now(UTC))
        closed = client.get(missing_url, headers=AUTH).json()
        assert closed["status"] == "not_started" and not closed["blocking"]
    assert lab.events == ["not_started"]
    assert approve(client, missing).json() == closed

    drop_before_delivery = False
    original = prepare(client, revision)
    original_url = f"{ROOT}/{original['plan_id']}"

    def stop_before_signal(_transaction, _identifier):
        raise OSError("synthetic interruption before durable activation")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(journal._Transaction, "mark_activation", stop_before_signal)
        assert approve(client, original).json()["status"] == "unknown"
    assert lab.files[TARGET] == CANDIDATE and not lab.loaded_candidate
    observed = client.post(f"{original_url}/observe", headers=AUTH).json()
    assert observed["blocking"] and observed["status"] == "unknown"
    assert observed["receipt"]["reconciliation_status"] == "disk_published_live_previous"
    rollback = client.post(
        f"{original_url}/rollback/prepare", headers=AUTH, json={"expected_mode_revision": revision}
    ).json()
    assert rollback["plan"]["original_action_id"] == original["plan"]["action_id"]
    if lose_restore_verification:
        with monkeypatch.context() as loss:
            loss.setattr(action, "_after_probe", lambda *_args, **_kwargs: False)
            uncertain = approve(client, rollback).json()
        assert uncertain["blocking"] and uncertain["status"] == "unknown"
        assert client.get(original_url, headers=AUTH).json() == observed
        settled = client.post(f"{ROOT}/{rollback['plan_id']}/observe", headers=AUTH).json()
        assert settled["status"] == "unknown" and not settled["blocking"]
        assert settled["receipt"]["reconciliation_status"] == "verified"
    else:
        assert approve(client, rollback).json()["status"] == "verified"
    assert lab.files[TARGET] == ORIGINAL and "reload" not in lab.events
    assert client.get(original_url, headers=AUTH).json() == {**observed, "blocking": False}
    assert (
        client.post(
            f"{original_url}/rollback/prepare",
            headers=AUTH,
            json={"expected_mode_revision": revision},
        ).status_code
        == 409
    )
    assert calls.count("submit") == 3 and lab.events.count("replace") == 2


def test_history_is_preserved_on_restart_and_restore_needs_separate_approval(product):
    client, transport, settings, _ = product
    revision = change_mode(client, "assisted", 0)
    row = prepare(client, revision)
    assert (
        client.post(
            f"{ROOT}/{row['plan_id']}/rollback/prepare",
            headers=AUTH,
            json={"expected_mode_revision": revision},
        ).status_code
        == 409
    )
    original = approve(client, row).json()
    restarted = main.create_app(settings)
    restarted.state.nginx_action_service.invoker = transport
    with TestClient(restarted) as second:
        assert second.get(f"{ROOT}/{row['plan_id']}", headers=AUTH).json() == original
        restore = second.post(
            f"{ROOT}/{row['plan_id']}/rollback/prepare",
            headers=AUTH,
            json={"expected_mode_revision": revision},
        ).json()
        assert restore["status"] == "ready" and not restore["approved"]
        assert restore["plan"]["original_action_id"] == original["plan"]["action_id"]
        assert restore["plan"]["action_id"] != original["plan"]["action_id"]
        assert approve(second, restore).json()["status"] == "verified"
        assert second.get(f"{ROOT}/{row['plan_id']}", headers=AUTH).json() == original


def test_unclassified_root_fields_and_expired_plans_never_enable_execution(product):
    client, transport, _, _ = product
    revision = change_mode(client, "assisted", 0)
    transport.override = lambda value: {**value, "raw_config": "SYNTHETIC_CONFIG_BODY"}
    pending = prepare(client, revision)
    assert pending["status"] == "prepare_pending" and pending["plan"] is None
    assert "SYNTHETIC_CONFIG_BODY" not in json.dumps(pending)
    transport.override = lambda value: {**value, "expires_at": "2000-01-01T00:00:00Z"}
    row = prepare(client, revision)
    assert row["status"] == "ready"
    assert approve(client, row).status_code == 409
    assert all(op != "submit" for op, _, _ in transport.calls)


def test_cold_ten_store_snapshot_retains_original_unknown_approval(tmp_path, monkeypatch):
    from deploy.observer import store_transfer

    target = SimpleNamespace(
        policy_digest="a" * 64, target_scope="b" * 64, transport_scope="c" * 64
    )
    monkeypatch.setattr(main, "load_nginx_targets", lambda *_args: {"test-nginx": target})
    app = main.create_app(Settings(tmp_path / "original", TOKEN))
    transport = Host()
    transport.lose_submit = True
    app.state.nginx_action_service.invoker = transport
    with TestClient(app) as client:
        row = prepare(client, change_mode(client, "assisted", 0))
        original = approve(client, row).json()
        assert original["status"] == "unknown" and original["approved"]
    snapshot = tmp_path / "snapshot"
    restored = tmp_path / "restored"
    store_transfer.snapshot(tmp_path / "original", snapshot, confirm_quiescent=True)
    assert store_transfer.verify_snapshot(snapshot)["database_count"] == 10
    store_transfer.rehearse(snapshot, restored)
    recovered = main.create_app(Settings(restored, TOKEN))
    recovered.state.nginx_action_service.invoker = transport
    with TestClient(recovered) as client:
        assert client.get(ROOT, headers=AUTH).json() == [original]
        assert approve(client, row).json() == original
    assert [op for op, _, _ in transport.calls] == ["prepare", "submit"]
