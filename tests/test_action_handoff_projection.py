"""Project real local ledgers after synthetic product requests. No network transport."""

import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from test_container_restarts import AUTH as container_auth
from test_container_restarts import BASE as container_base
from test_container_restarts import approve as approve_container
from test_container_restarts import mode as container_mode
from test_container_restarts import prepare as prepare_container
from test_container_restarts import product as _container_product
from test_container_restarts import report_for
from test_nginx_managed_actions import AUTH, ROOT, approve, bind_report, change_mode, linked_plan
from test_nginx_managed_actions import product as _nginx_product

from opsark import action_handoff_recheck_store
from opsark.action_handoff import action_handoff_markdown
from opsark.action_handoff_projection import ActionHandoffProjection
from opsark.action_handoff_recheck_store import ActionHandoffRecheckStore
from opsark.config import HostConfig
from opsark.models import BusinessCheck

container_product = _container_product
nginx_product = _nginx_product


def _profile(public, tmp_path):
    check = BusinessCheck(
        id="private_probe",
        domain="private-probe.invalid",
        path="/private-probe-canary",
        expected_body_sha256="a1" * 32,
        read_only_confirmed=True,
    )
    return HostConfig(public, tmp_path / "readonly-key", tmp_path / "known-hosts", (check,))


def _services(client):
    state = client.app.state
    receipts = ActionHandoffRecheckStore(state.store)
    projection = ActionHandoffProjection(
        state.store, state.nginx_action_service, state.container_restart_service, receipts
    )
    return projection, receipts


def _finish(receipts, binding, monkeypatch, *checks):
    monkeypatch.setattr(
        action_handoff_recheck_store, "_now", lambda: binding.execution_at + timedelta(seconds=1)
    )
    row = receipts.start(binding)
    receipts.finish(binding, row.id, checks=checks)
    return row.id


@pytest.fixture
def container(container_product, tmp_path):
    client, guest, clock, _ = container_product
    service = client.app.state.container_restart_service
    target = service.targets["fixture"]
    profile = _profile(target.host.public, tmp_path)
    target.host = profile
    report = report_for(service, clock[0])
    client.app.state.store.save(report)
    rev = container_mode(client, "assisted", 0)
    original = prepare_container(client, rev, report_id=report.id)
    clock[0] += timedelta(seconds=1)
    return client, guest, profile, report, original


@pytest.fixture
def nginx(nginx_product, tmp_path):
    client, transport, _, target = nginx_product
    report = bind_report(client, target)
    profile = _profile(target.host.public, tmp_path)
    target.host = profile
    rev = change_mode(client, "assisted", 0)
    original = linked_plan(client, rev, report.id).json()
    assert approve(client, original).json()["status"] == "verified"
    return client, transport, profile, report, rev, original


def _restore(client, original, rev):
    prepared = client.post(
        f"{ROOT}/{original['plan_id']}/rollback/prepare",
        headers=AUTH,
        json={"expected_mode_revision": rev},
    )
    assert prepared.status_code == 200
    return prepared.json()


def test_container_unverified_is_pending_and_newest_attempt_wins(container, monkeypatch):
    client, guest, profile, report, original = container
    projection, receipts = _services(client)
    key = (report.id, "container_restart", original["plan_id"])
    assert projection.timeline(*key) is None
    guest.lose_submit = True
    assert approve_container(client, original).json()["blocking"] is True
    assert projection.timeline(*key, profile=profile).business is None
    with pytest.raises(ValueError):
        projection.binding(*key, profile)

    guest.observe_verified = True
    assert client.post(f"{container_base}/{key[-1]}/observe", headers=container_auth).is_success
    binding = projection.binding(*key, profile)
    assert binding.configured_checks == 1
    passed = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    before_read = list(guest.calls)
    current = projection.timeline(*key, profile=profile)
    assert current.operation_verified and current.business.status == "passed"
    assert current.business.selection == "current"
    markdown = action_handoff_markdown(current)
    assert "1 / 1" in markdown
    assert all(
        secret not in markdown
        for secret in (
            "private-probe",
            "synthetic-private",
            binding.profile_digest,
            binding.execution_digest,
            report.id,
            key[-1],
            passed,
        )
    )
    failure = _finish(receipts, binding, monkeypatch, "failed", "uncovered", "uncovered")
    assert projection.timeline(*key, profile=profile).business.status == "failed"
    unfinished = receipts.start(binding)
    assert projection.timeline(*key, profile=profile).business is None
    assert projection.timeline(*key, profile=profile, recheck_id=unfinished.id).business is None
    old = projection.timeline(*key, profile=profile, recheck_id=passed).business
    assert old.status == "passed" and old.selection == "historical"
    assert projection.timeline(*key, recheck_id=failure).business.status == "failed"
    history = projection.rechecks(*key, profile=profile)
    assert [(item.id, item.selection, item.verdict) for item in history] == [
        (unfinished.id, "current", "pending"),
        (failure, "historical", "failed"),
        (passed, "historical", "passed"),
    ]
    assert history[0].finished_at is None
    assert guest.calls == before_read


def test_projection_rejects_other_report_and_forged_execution(container, monkeypatch):
    client, guest, profile, report, original = container
    guest.status = "verified"
    assert approve_container(client, original).json()["status"] == "verified"
    projection, receipts = _services(client)
    key = (report.id, "container_restart", original["plan_id"])
    binding = projection.binding(*key, profile)
    with pytest.raises(ValueError):
        projection.timeline("another-report", *key[1:], profile=profile)
    other = report.model_copy(update={"id": "other-original"})
    client.app.state.store.save(other)
    wrong_report = binding.model_copy(update={"report_id": other.id})
    wrong_epoch = binding.model_copy(update={"execution_digest": "8" * 64})
    for mismatched in (wrong_report, wrong_epoch):
        receipt = _finish(receipts, mismatched, monkeypatch, "passed", "uncovered", "uncovered")
        with pytest.raises(ValueError):
            projection.timeline(*key, profile=profile, recheck_id=receipt)
    assert projection.timeline(*key, profile=profile).business is None


def test_nginx_preview_then_pending_and_verified_rollback_fences_original(nginx, monkeypatch):
    client, transport, profile, report, rev, original = nginx
    projection, receipts = _services(client)
    key = (report.id, "nginx", original["plan_id"])
    binding = projection.binding(*key, profile)
    old_id = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    restore = _restore(client, original, rev)
    assert projection.timeline(*key, profile=profile).business.selection == "current"
    transport.lose_submit = True
    assert approve(client, restore).json()["blocking"] is True
    restore_key = (report.id, "nginx", restore["plan_id"])
    assert projection.timeline(*restore_key).operation_status == "unknown"
    for fenced in (key, restore_key):
        with pytest.raises(ValueError):
            projection.binding(*fenced, profile)
    assert projection.timeline(*key, profile=profile).business is None
    old = projection.timeline(*key, profile=profile, recheck_id=old_id).business
    assert old.selection == "historical" and old.status == "passed"
    assert [(item.id, item.selection) for item in projection.rechecks(*key, profile=profile)] == [
        (old_id, "historical")
    ]
    assert client.post(f"{ROOT}/{restore_key[-1]}/observe", headers=AUTH).is_success
    restored_binding = projection.binding(*restore_key, profile)
    assert restored_binding.execution_digest != binding.execution_digest
    _finish(receipts, restored_binding, monkeypatch, "passed", "uncovered", "uncovered")
    assert projection.timeline(*restore_key, profile=profile).business.status == "passed"
    assert projection.timeline(*key, profile=profile).business is None


def test_nginx_unrelated_rollback_and_deregistration_keep_original_history(nginx, monkeypatch):
    client, transport, profile, report, rev, original = nginx
    projection, receipts = _services(client)
    key = (report.id, "nginx", original["plan_id"])
    binding = projection.binding(*key, profile)
    old_id = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    other = linked_plan(client, rev, report.id).json()
    assert approve(client, other).json()["status"] == "verified"
    assert approve(client, _restore(client, other, rev)).json()["status"] == "verified"
    assert projection.timeline(*key, profile=profile).business.selection == "current"
    before_read = list(transport.calls)
    service = client.app.state.nginx_action_service
    registered = service.targets[profile.public.id]
    changed = replace(
        profile,
        business_checks=(
            profile.business_checks[0].model_copy(update={"path": "/changed-readiness"}),
        ),
    )
    registered.host = changed
    assert projection.timeline(*key, profile=profile).business is None
    assert projection.timeline(*key, profile=changed).business is None
    assert projection.binding(*key, changed).profile_digest != binding.profile_digest
    changed_binding = projection.binding(*key, changed)
    changed_id = _finish(
        receipts, changed_binding, monkeypatch, "uncovered", "uncovered", "uncovered"
    )
    assert [(item.id, item.selection) for item in projection.rechecks(*key, profile=changed)] == [
        (changed_id, "current"),
        (old_id, "historical"),
    ]
    service.targets.clear()
    assert projection.timeline(*key, profile=profile).business is None
    old = projection.timeline(*key, recheck_id=old_id).business
    assert old.selection == "historical" and old.status == "passed"
    assert {item.selection for item in projection.rechecks(*key)} == {"historical"}
    assert transport.calls == before_read


def test_nginx_old_ledger_without_index_reads_history_and_refuses_current(nginx, monkeypatch):
    client, _, profile, report, _, original = nginx
    projection, receipts = _services(client)
    key = (report.id, "nginx", original["plan_id"])
    binding = projection.binding(*key, profile)
    old_id = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    service = client.app.state.nginx_action_service
    with closing(sqlite3.connect(service.automation.path)) as db, db:
        db.execute("DROP INDEX nginx_handoff_approved_restore")
    timeline = projection.timeline(*key, profile=profile)
    assert timeline.operation_verified and timeline.business is None
    assert projection.timeline(*key, recheck_id=old_id).business.selection == "historical"
    with pytest.raises(ValueError):
        projection.binding(*key, profile)


def test_nginx_approval_during_projection_suppresses_current_green(nginx, monkeypatch):
    client, _, profile, report, rev, original = nginx
    projection, receipts = _services(client)
    key = (report.id, "nginx", original["plan_id"])
    binding = projection.binding(*key, profile)
    _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    restore = _restore(client, original, rev)
    latest = receipts.latest

    def during_projection(key):
        selected = latest(key)
        assert approve(client, restore).json()["status"] == "verified"
        return selected

    monkeypatch.setattr(receipts, "latest", during_projection)
    assert projection.timeline(*key, profile=profile).business is None


def test_report_storage_metadata_cannot_retime_original_action(container):
    client, guest, profile, report, original = container
    guest.status = "verified"
    assert approve_container(client, original).json()["status"] == "verified"
    projection, _ = _services(client)
    reports = client.app.state.store
    with reports._connection() as db:
        db.execute(
            "UPDATE reports SET created_at=? WHERE id=?",
            ((datetime.now(UTC) - timedelta(days=1000)).isoformat(), report.id),
        )
    with pytest.raises(ValueError):
        projection.timeline(report.id, "container_restart", original["plan_id"], profile=profile)


def test_operator_picker_is_bounded_and_old_exact_selection_remains(container, monkeypatch):
    client, guest, profile, report, original = container
    guest.status = "verified"
    assert approve_container(client, original).json()["status"] == "verified"
    projection, receipts = _services(client)
    key = (report.id, "container_restart", original["plan_id"])
    binding = projection.binding(*key, profile)
    oldest = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    recent = [receipts.start(binding).id for _ in range(20)]
    before = list(guest.calls)
    history = projection.rechecks(*key, profile=profile)
    assert [row.id for row in history] == recent[::-1]
    assert set(history[0].model_dump()) == {
        "id",
        "selection",
        "verdict",
        "started_at",
        "finished_at",
    }
    assert projection.timeline(*key, recheck_id=oldest).business.selection == "historical"
    assert guest.calls == before


def test_older_picker_index_can_be_created_on_next_write(container, monkeypatch):
    client, guest, profile, report, original = container
    guest.status = "verified"
    assert approve_container(client, original).json()["status"] == "verified"
    projection, receipts = _services(client)
    key = (report.id, "container_restart", original["plan_id"])
    binding = projection.binding(*key, profile)
    oldest = _finish(receipts, binding, monkeypatch, "passed", "uncovered", "uncovered")
    with client.app.state.store._connection() as db:
        db.execute("DROP INDEX action_handoff_recheck_original_v1")
    assert projection.rechecks(*key, profile=profile) == []
    assert projection.timeline(*key, recheck_id=oldest).business.selection == "historical"
    latest = receipts.start(binding)
    assert [row.id for row in projection.rechecks(*key, profile=profile)] == [latest.id, oldest]
