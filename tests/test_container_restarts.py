import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import paramiko
import pytest
from fastapi.testclient import TestClient

from opsark import container_restart_client, main, nginx_action_client
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.config import HostConfig, Settings
from opsark.container_restarts import _action_id
from opsark.models import HostPublic, Report
from opsark.nginx_action_client import NginxActionTransportError
from opsark.nginx_dependencies import (
    ContainerImpactSite,
    ContainerRestartImpact,
    dependency_binding_digest,
)

AUTH = {"Authorization": "Bearer " + "synthetic-container-test-token-11111"}
BASE = "/api/container-restarts"
TARGET = SimpleNamespace(
    target_scope="a" * 64, transport_scope="b" * 64, policy_digest="c" * 64, container_id="d" * 64
)


class Guest:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.plans = {}
        self.status = "unknown"
        self.lose_prepare = False
        self.lose_submit = False
        self.observe_verified = False
        self.override = None
        self.before_submit = None

    def __call__(self, target, operation, *, policy_digest=None, **fields):
        self.calls.append((operation, fields))
        policy = target.policy_digest if policy_digest is None else policy_digest
        if operation == "prepare":
            plan_id = fields["plan_id"]
            result = {
                "schema_version": 1,
                "status": "ready",
                "policy_digest": policy,
                "plan_id": plan_id,
                "action_id": _action_id(plan_id),
                "plan_digest": "e" * 64,
                "mode_revision": fields["mode_revision"],
                "container_id": target.container_id,
                "image_id": "sha256:" + "f" * 64,
                "expires_at": (self.clock[0] + timedelta(minutes=2)).isoformat(),
            }
            self.plans[plan_id] = result
            if self.lose_prepare:
                raise NginxActionTransportError("lost prepare")
        elif operation == "plan_status":
            result = self.plans[fields["plan_id"]]
        else:
            plan = next(
                row for row in self.plans.values() if row["action_id"] == fields["action_id"]
            )
            if operation == "submit":
                if self.before_submit:
                    self.before_submit(fields)
                if self.lose_submit:
                    raise NginxActionTransportError("lost submit")
            status = self.status
            result = {
                "schema_version": 1,
                "status": status,
                "policy_digest": policy,
                "action_id": plan["action_id"],
                "plan_id": plan["plan_id"],
                "plan_digest": plan["plan_digest"],
                "mode_revision": plan["mode_revision"],
                "reason": {"verified": None, "not_started": "expired", "missing": "not_found"}.get(
                    status, "operation_unconfirmed"
                ),
                "reconciliation_status": "verified"
                if operation == "observe" and self.observe_verified
                else None,
            }
            if status == "missing":
                result.update(plan_id=None, plan_digest=None, mode_revision=None)
        return self.override(result) if self.override else result


def mode(client, selected, revision):
    result = client.put(
        "/api/automation", headers=AUTH, json={"mode": selected, "expected_revision": revision}
    )
    assert result.status_code == 200
    return result.json()["revision"]


def prepare(client, revision, **fields):
    result = client.post(
        BASE + "/prepare",
        headers=AUTH,
        json={"host_id": "fixture", "expected_mode_revision": revision, **fields},
    )
    assert result.status_code == 200
    return result.json()


def approve(client, row, **updates):
    body = {
        "expected_plan_digest": row["plan"]["plan_digest"],
        "expected_mode_revision": row["plan"]["mode_revision"],
        "confirm": True,
        **updates,
    }
    return client.post(f"{BASE}/{row['plan_id']}/approve", headers=AUTH, json=body)


@pytest.fixture
def product(tmp_path, monkeypatch):
    host = HostConfig(
        HostPublic(id="fixture", name="fixture", address="192.0.2.1", source="ssh"),
        tmp_path / "readonly-key",
        tmp_path / "known-hosts",
        compose_project="fixture",
        nginx_scope_digest="a" * 64,
    )
    monkeypatch.setattr(main, "load_hosts", lambda _: {"fixture": host})
    restart_target = SimpleNamespace(**vars(TARGET), host=host)
    monkeypatch.setattr(
        main, "load_container_restart_targets", lambda *_: {"fixture": restart_target}
    )
    clock = [datetime(2026, 11, 13, tzinfo=UTC)]
    guest = Guest(clock)
    settings = Settings(tmp_path, AUTH["Authorization"].removeprefix("Bearer "))

    def create():
        app = main.create_app(settings)
        service = app.state.container_restart_service
        service.invoker = guest
        service.clock = lambda: clock[0]
        return app

    with TestClient(create()) as client:
        yield client, guest, clock, create


def test_impact_is_explicit_read_only_and_bound_to_original_ready_plan(product, monkeypatch):
    client, guest, clock, _ = product
    calls = []

    def collect(host, _settings, container_id):
        calls.append((host.public.id, container_id))
        return ContainerRestartImpact(
            status="observed",
            observed_at=clock[0],
            sites=[ContainerImpactSite(domain="shop.invalid", file="/etc/nginx/shop.conf", line=9)],
        )

    monkeypatch.setattr(main, "run_container_restart_impact", collect)
    plan = prepare(client, 0)
    plan_id = plan["plan_id"]
    url = f"{BASE}/{plan_id}/impact"
    assert client.post(url, json={}).status_code == 401
    assert client.post(url, headers=AUTH, json={"container_id": "b" * 64}).status_code == 422
    assert client.post(f"{BASE}/{'a' * 32}/impact", headers=AUTH, json={}).status_code == 404
    with client.app.state.investigation_lock:
        assert client.post(url, headers=AUTH, json={}).status_code == 409
    assert not calls

    response = client.post(url, headers=AUTH, json={})
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "plan_id": plan_id,
        "binding_digest": dependency_binding_digest(
            client.app.state.container_restart_service.targets["fixture"].host
        ),
        "status": "observed",
        "reason": None,
        "observed_at": "2026-11-13T00:00:00Z",
        "loaded_generation": "unknown",
        "sites": [{"domain": "shop.invalid", "file": "/etc/nginx/shop.conf", "line": 9}],
    }
    assert calls == [("fixture", TARGET.container_id)]
    assert client.get(f"{BASE}/{plan_id}", headers=AUTH).json() == plan
    assert [operation for operation, _ in guest.calls] == ["prepare"]
    clock[0] += timedelta(minutes=3)
    assert client.post(url, headers=AUTH, json={}).status_code == 409
    assert len(calls) == 1


def test_impact_rejects_changed_registration_and_expiry_during_collection(product, monkeypatch):
    client, guest, clock, _ = product
    service = client.app.state.container_restart_service
    host = service.targets["fixture"].host
    plan = prepare(client, 0)
    url = f"{BASE}/{plan['plan_id']}/impact"
    calls = []

    def collect(*_args):
        calls.append(1)
        clock[0] += timedelta(minutes=3)
        return ContainerRestartImpact(status="unavailable", reason="collection_unavailable")

    monkeypatch.setattr(main, "run_container_restart_impact", collect)
    monkeypatch.setattr(main, "load_hosts", lambda _: {})
    assert client.post(url, headers=AUTH, json={}).status_code == 409
    assert not calls
    monkeypatch.setattr(main, "load_hosts", lambda _: {"fixture": host})
    response = client.post(url, headers=AUTH, json={})
    assert response.status_code == 409 and "sites" not in response.json()
    assert calls == [1] and [operation for operation, _ in guest.calls] == ["prepare"]


def report_for(service, at, **changes):
    public = service.targets["fixture"].host.public
    fields = {
        "id": "original-report",
        "host_id": public.id,
        "host_name": public.name,
        "scenario": "container_restart",
        "source": "ssh",
        "created_at": at,
        "status": "needs_attention",
        "title": "synthetic-private-title",
        "summary": "synthetic-private-log-canary",
        "facts": [],
        "candidates": [],
        "missing": [],
        "evidence": [],
        "next_steps": [],
        "scope_hash": diagnostic_scope_for(public),
        "target": public,
    }
    return Report(**(fields | changes))


def test_handoff_prepare_checks_saved_report_scope_before_any_ssh(product):
    client, guest, clock, _ = product
    service = client.app.state.container_restart_service
    store = client.app.state.store
    foreign = service.targets["fixture"].host.public.model_copy(update={"address": "192.0.2.89"})
    for row in (
        report_for(service, clock[0], id="replay-report", source="replay"),
        report_for(
            service,
            clock[0],
            id="foreign-report",
            target=foreign,
            scope_hash=diagnostic_scope_for(foreign),
        ),
        report_for(service, clock[0], id="missing-target", target=None),
        report_for(service, clock[0] + timedelta(seconds=1), id="future-report"),
    ):
        store.save(row)
    for report_id, status in (
        ("absent", 404),
        ("replay-report", 409),
        ("foreign-report", 409),
        ("missing-target", 409),
        ("future-report", 409),
    ):
        result = client.post(
            BASE + "/prepare",
            headers=AUTH,
            json={
                "host_id": "fixture",
                "expected_mode_revision": 0,
                "report_id": report_id,
            },
        )
        assert result.status_code == status
    assert guest.calls == [] and service.list() == []


def test_handoff_accepts_exact_original_and_reads_after_deregistration(product, monkeypatch):
    client, guest, clock, create = product
    service = client.app.state.container_restart_service
    report = report_for(service, clock[0])
    client.app.state.store.save(report)
    revision = mode(client, "assisted", 0)
    row = prepare(client, revision, report_id=report.id)
    plan_id = row["plan_id"]
    assert "report_id" not in row and service.read_handoff(plan_id) is None
    guest.lose_submit = True
    original = []

    def inspect_during_submit(fields):
        assert original == []
        linked = service.read_handoff(plan_id)
        assert linked["approval_id"] == fields["approval_id"]
        assert linked["operation_status"] == "unknown" and linked["blocking"] is True
        assert linked["receipt_source"] is linked["receipt_observed_at"] is None
        original.append(linked)

    guest.before_submit = inspect_during_submit
    clock[0] += timedelta(seconds=1)
    assert approve(client, row).json()["blocking"] is True
    assert original[0]["report_id"] == report.id
    assert original[0]["host_scope"] == scope_for(report.target)
    clock[0] += timedelta(seconds=1)
    guest.observe_verified = True
    path = f"{BASE}/{plan_id}"
    assert client.post(path + "/observe", headers=AUTH).json()["blocking"] is False
    observed = service.read_handoff(plan_id)
    assert observed == {
        **original[0],
        "receipt_observed_at": clock[0].isoformat().replace("+00:00", "Z"),
        "receipt_source": "observe",
        "reconciliation_status": "verified",
        "blocking": False,
    }
    assert "synthetic-private" not in str(observed) and "container_id" not in observed
    assert [op for op, _ in guest.calls] == ["prepare", "submit", "observe"]
    monkeypatch.setattr(main, "load_container_restart_targets", lambda *_: {})
    monkeypatch.setattr(main, "load_hosts", lambda _: {})
    reopened = create().state.container_restart_service
    reopened.resolve_report = Mock(side_effect=AssertionError("read must not resolve current host"))
    reopened.invoker = Mock(side_effect=AssertionError("handoff read must not use SSH"))
    assert reopened.read_handoff(plan_id) == observed
    reopened.resolve_report.assert_not_called()
    reopened.invoker.assert_not_called()


def test_handoff_rejects_changed_binding_and_preserves_legacy_eligibility(product):
    client, guest, clock, _ = product
    service = client.app.state.container_restart_service
    revision = mode(client, "assisted", 0)
    legacy = prepare(client, revision)
    guest.status = "verified"
    assert approve(client, legacy).json()["status"] == "verified"
    assert service.read_handoff(legacy["plan_id"]) is None
    report = report_for(service, clock[0])
    client.app.state.store.save(report)
    plan = prepare(client, revision, report_id=report.id)
    assert approve(client, plan).json()["status"] == "verified"
    assert service.read_handoff(plan["plan_id"])["receipt_source"] == "submit"
    with closing(sqlite3.connect(service.automation.path)) as db, db:
        db.execute("UPDATE container_restart_handoff SET report_id='another-report'")
    with pytest.raises(ValueError, match="交接登记"):
        service.read_handoff(plan["plan_id"])


@pytest.mark.parametrize(
    ("guest_status", "operation", "later", "reconciled"),
    [
        ("verified", "status", timedelta(seconds=5), None),
        ("not_started", "reconcile_status", timedelta(minutes=3), None),
        ("unknown", "status", timedelta(seconds=5), "verified"),
    ],
)
def test_handoff_preserves_first_bound_terminal_observation(
    product, guest_status, operation, later, reconciled
):
    client, guest, clock, _ = product
    service = client.app.state.container_restart_service
    report = report_for(service, clock[0])
    client.app.state.store.save(report)
    revision = mode(client, "assisted", 0)
    plan = prepare(client, revision, report_id=report.id)
    guest.lose_submit = True
    assert approve(client, plan).json()["blocking"] is True
    guest.status = guest_status
    if reconciled is not None:
        guest.override = lambda result: {**result, "reconciliation_status": reconciled}
    clock[0] += later
    path = f"{BASE}/{plan['plan_id']}"
    assert client.get(path, headers=AUTH).json()["blocking"] is False
    observed = service.read_handoff(plan["plan_id"])
    assert observed["operation_status"] == guest_status
    assert observed["reconciliation_status"] == reconciled
    assert observed["receipt_source"] == operation
    assert observed["receipt_observed_at"] == clock[0].isoformat().replace("+00:00", "Z")
    assert guest.calls[-1][0] == operation
    before = len(guest.calls)
    clock[0] += timedelta(minutes=5)
    assert client.get(path, headers=AUTH).status_code == 200
    assert service.read_handoff(plan["plan_id"]) == observed
    assert len(guest.calls) == before


def test_default_off_is_protected_without_new_table(tmp_path):
    app = main.create_app(Settings(tmp_path, AUTH["Authorization"].removeprefix("Bearer ")))
    with TestClient(app) as client:
        assert client.get(BASE).status_code == 401
        assert client.post(BASE + "/prepare", json={}).status_code == 401
        assert client.get(BASE, headers=AUTH).json() == []
        assert "container_restart" not in client.get("/api/capabilities", headers=AUTH).json()
        assert (
            client.post(
                BASE + "/prepare",
                headers=AUTH,
                json={"host_id": "fixture", "expected_mode_revision": 0},
            ).status_code
            == 403
        )
    with closing(sqlite3.connect(tmp_path / "automation.sqlite3")) as db:
        assert (
            db.execute("SELECT 1 FROM sqlite_master WHERE name='container_restarts'").fetchone()
            is None
        )
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='container_restart_handoff'"
            ).fetchone()
            is None
        )


def test_approval_binds_digest_mode_and_exact_container(product):
    client, guest, _, _ = product
    assert client.get("/api/capabilities", headers=AUTH).json()["container_restart"] is True
    host = next(
        row for row in client.get("/api/hosts", headers=AUTH).json() if row["id"] == "fixture"
    )
    assert host["container_restart_configured"] is True
    assert host["container_restart_binding_digest"] == TARGET.target_scope
    manual = prepare(client, 0)
    assert approve(client, manual).status_code == 409
    revision = mode(client, "assisted", 0)
    row = prepare(client, revision)
    assert row["binding_digest"] == TARGET.target_scope
    assert row["plan"]["container_id"] == TARGET.container_id
    assert row["plan"]["impact"] == {
        "expected_downtime_seconds": None,
        "no_recreate": True,
        "no_volume_changes": True,
    }
    assert approve(client, row, confirm=1).status_code == 422
    assert approve(client, row, expected_plan_digest="0" * 64).status_code == 409
    assert approve(client, row, expected_mode_revision=0).status_code == 409
    assert approve(client, row, container_id=TARGET.container_id).status_code == 422
    guest.status = "verified"
    settled = approve(client, row).json()
    assert settled["approved"] and not settled["blocking"] and settled["status"] == "verified"
    assert approve(client, row).json() == settled
    assert [op for op, _ in guest.calls] == ["prepare", "prepare", "submit"]


def test_lost_submit_same_id_reconciles_after_controller_restart(product):
    client, guest, _, create = product
    revision = mode(client, "assisted", 0)
    guest.lose_prepare = True
    pending = prepare(client, revision)
    assert pending["status"] == "prepare_pending"
    path = f"{BASE}/{pending['plan_id']}"
    row = client.get(path, headers=AUTH).json()
    assert row["status"] == "ready"
    guest.lose_submit = True
    first = approve(client, row).json()
    assert first["status"] == "unknown" and first["blocking"] and first["receipt"] is None
    mode(client, "manual", revision)
    with TestClient(create()) as restarted:
        assert approve(restarted, row).json() == first
        pending = restarted.get(path, headers=AUTH).json()
        assert pending["blocking"] and pending["receipt"]["action_id"] == row["plan"]["action_id"]
        guest.observe_verified = True
        recovered = restarted.post(path + "/observe", headers=AUTH).json()
        assert recovered["status"] == "unknown" and not recovered["blocking"]
        assert recovered["receipt"]["reconciliation_status"] == "verified"
        assert restarted.get(path, headers=AUTH).json() == recovered
    assert [op for op, _ in guest.calls] == [
        "prepare",
        "plan_status",
        "submit",
        "status",
        "observe",
    ]
    assert guest.calls[-1][1] == {"action_id": row["plan"]["action_id"]}


def test_only_expired_original_can_close_durable_absence(product):
    client, guest, clock, _ = product
    row = prepare(client, mode(client, "assisted", 0))
    guest.status = "refused"
    path = f"{BASE}/{row['plan_id']}"
    assert approve(client, row).json()["blocking"]
    guest.status = "not_started"
    assert client.get(path, headers=AUTH).json()["blocking"]
    clock[0] += timedelta(minutes=3)
    settled = client.get(path, headers=AUTH).json()
    assert settled["status"] == "not_started" and not settled["blocking"]
    assert guest.calls[-1] == (
        "reconcile_status",
        {key: row["plan"][key] for key in ("action_id", "plan_id", "plan_digest", "mode_revision")},
    )
    assert sum(op == "submit" for op, _ in guest.calls) == 1


def test_mismatched_host_preview_and_receipt_fail_closed(product):
    client, guest, _, _ = product
    revision = mode(client, "assisted", 0)
    guest.override = lambda row: {**row, "container_id": "0" * 64}
    assert prepare(client, revision)["status"] == "prepare_pending"
    guest.override = None
    row = prepare(client, revision)
    guest.status = "verified"
    guest.override = lambda row: {**row, "action_id": "0" * 64}
    unknown = approve(client, row).json()
    assert unknown["blocking"] and unknown["receipt"] is None


def test_concurrent_confirmation_commits_exactly_one_intent_before_ssh(product):
    client, guest, _, _ = product
    row = prepare(client, mode(client, "assisted", 0))
    entered, release = Event(), Event()

    def on_submit(_fields):
        entered.set()
        assert release.wait(5)

    guest.before_submit = on_submit
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(approve, client, row)
        try:
            assert entered.wait(5)
            duplicate = approve(client, row).json()
            assert duplicate["approved"] and duplicate["blocking"]
        finally:
            release.set()
        assert future.result(timeout=5).json()["blocking"]
    assert sum(op == "submit" for op, _ in guest.calls) == 1


def test_fixed_transport_uses_separate_role_and_exact_wire(monkeypatch):
    target = SimpleNamespace(
        host=SimpleNamespace(public=SimpleNamespace(address="192.0.2.1", port=22)),
        policy_digest=TARGET.policy_digest,
    )
    channel = Mock(closed=False, eof_received=True)
    channel.recv_ready.side_effect = [True, False]
    channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = True
    channel.recv_exit_status.return_value = 0
    channel.recv.return_value = b'{"schema_version":1,"status":"missing"}\n'
    ssh, stdin, key = Mock(), Mock(), object()
    ssh.exec_command.return_value = (stdin, SimpleNamespace(channel=channel), None)
    factory = Mock(return_value=ssh)
    monkeypatch.setattr(nginx_action_client.paramiko, "SSHClient", factory)
    monkeypatch.setattr(nginx_action_client, "_credentials", lambda _: (key, {}))
    assert (
        container_restart_client.invoke(target, "observe", action_id="e" * 64)["status"]
        == "missing"
    )
    assert ssh.exec_command.call_args.args == ("opsark-container-restart-v1",)
    assert ssh.exec_command.call_args.kwargs["get_pty"] is False
    assert isinstance(ssh.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
    assert ssh.connect.call_args.kwargs["username"] == "opsark-container-restart"
    assert ssh.connect.call_args.kwargs["pkey"] is key
    assert (
        not ssh.connect.call_args.kwargs["allow_agent"]
        and not ssh.connect.call_args.kwargs["look_for_keys"]
    )
    assert channel.sendall.call_args.args[0] == (
        nginx_action_client.canonical(
            {
                "schema_version": 1,
                "op": "observe",
                "policy_digest": TARGET.policy_digest,
                "action_id": "e" * 64,
            }
        )
        + b"\n"
    )
    stdin.close.assert_called_once_with()
    with pytest.raises(ValueError):
        container_restart_client.invoke(
            target, "observe", action_id="e" * 64, command="unregistered"
        )
    assert factory.call_count == 1


def test_inventory_refuses_normalized_writer_overlap_without_loading_key(tmp_path, monkeypatch):
    host = HostConfig(
        HostPublic(id="fixture", name="fixture", address="::ffff:" + "192.0.2.1", source="ssh"),
        tmp_path / "read",
        tmp_path / "pins",
    )
    patch = SimpleNamespace(host=SimpleNamespace(public=SimpleNamespace(address="192.0.2.1")))
    path = tmp_path / "inventory.json"
    reads = Mock(
        return_value=(
            nginx_action_client.canonical(
                {
                    "schema_version": 1,
                    "targets": {
                        "fixture": {
                            "key_file": str(tmp_path / "restart"),
                            "policy_digest": TARGET.policy_digest,
                            "container_id": TARGET.container_id,
                        }
                    },
                }
            ),
            object(),
        )
    )
    constructor = Mock(side_effect=AssertionError("restart key must not be loaded"))
    monkeypatch.setattr(container_restart_client, "_read_file", reads)
    monkeypatch.setattr(container_restart_client, "ContainerRestartTarget", constructor)
    with pytest.raises(ValueError, match="容器重启登记"):
        container_restart_client.load_container_restart_targets(path, {"fixture": host}, (patch,))
    reads.assert_called_once_with(path, 16384, private=True)
    constructor.assert_not_called()
