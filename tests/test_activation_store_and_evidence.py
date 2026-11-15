"""Store atomicity and read-only activation observations cannot alter patch history."""

import copy
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_activation_controller import ACTIVATION, prepare, seal, submit
from test_activation_controller import activation as activation
from test_automatic_monitor import HOST
from test_automatic_service import env as env

from opsark import activation_store
from opsark.activation_api import register_activation_routes
from opsark.activation_evidence import build_evidence, verify_bundle
from opsark.activation_monitor import ActivationMonitor
from opsark.activation_store import ActivationStore
from opsark.automatic_store import canonical, digest
from opsark.vulnerability_store import VulnerabilityStore


def verified(a):
    record = prepare(a)
    submit(a, record)
    a.root_status, a.root_revision = "verified", 4
    return a.service.poll(HOST, ACTIVATION)


def test_concurrent_submission_has_one_durable_winner(activation):
    a = activation
    record = prepare(a)
    args = (HOST, ACTIVATION, record["activation_digest"], record["plan"]["mode_revision"])
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: a.store.begin_submission(*args, now=a.e.clock), range(2))
        )
    assert sorted(first for first, _ in results) == [False, True]
    assert all(value["status"] == "submission_intent" for _, value in results)
    assert not any(call["op"] == "activation_submit" for call in a.calls)


def test_ledger_full_preserves_original_identity_and_never_evicts(activation, monkeypatch):
    a = activation
    record = prepare(a)
    monkeypatch.setattr(activation_store, "MAX_RECORDS", 1)
    plan = copy.deepcopy(record["plan"])
    plan["activation_id"] = "8" * 32
    seal(plan, "activation_digest")
    with pytest.raises(ValueError, match="full"):
        a.store.save_plan(
            HOST,
            plan,
            scope_hash=record["scope_hash"],
            controller_policy_digest=record["controller_policy_digest"],
            original_job=record["original_job"],
            now=a.e.clock,
        )
    assert a.store.get(HOST, ACTIVATION) == a.store.list(limit=1)[0]


def test_acknowledgement_does_not_rearm_unknown_submission(activation):
    a = activation
    record = prepare(a)
    a.submit_loss = True
    submit(a, record)
    acknowledged = a.store.acknowledge(HOST, ACTIVATION, now=a.e.clock)
    assert acknowledged["acknowledged"] and acknowledged["notification_count"] == 1
    assert submit(a, record)["status"] == "unknown"
    assert len([c for c in a.calls if c["op"] == "activation_submit"]) == 1


def test_expired_or_different_mode_preview_stops_before_submit(activation):
    a = activation
    record = prepare(a)
    a.e.clock += timedelta(minutes=6)
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        submit(a, record)
    assert not any(c["op"] == "activation_submit" for c in a.calls)


def test_monitor_lease_cannot_be_stolen_during_an_original_poll(activation):
    a = activation
    assert a.store.claim_monitor("1" * 32, now=a.e.clock)
    assert not a.store.claim_monitor("2" * 32, now=a.e.clock)
    assert a.store.claim_monitor("2" * 32, now=a.e.clock + timedelta(seconds=121))
    a.store.release_monitor("1" * 32)
    assert not a.store.claim_monitor("3" * 32, now=a.e.clock + timedelta(seconds=122))


def test_hardlinked_database_is_rejected_without_reading_records(activation, tmp_path):
    a = activation
    link = tmp_path / "alias.sqlite3"
    try:
        os.link(a.store.path, link)
    except OSError:
        pytest.skip("Local filesystem cannot create a hard link")
    with pytest.raises(ValueError):
        ActivationStore(a.store.path)


@pytest.mark.parametrize("suffix", ["duplicate", "nonfinite", "missing"])
def test_corrupt_payload_is_sanitized_not_parsed_as_a_new_approval(activation, suffix):
    a = activation
    prepare(a)
    with closing(sqlite3.connect(a.store.path)) as connection, connection:
        raw = connection.execute("SELECT payload FROM service_activation_records").fetchone()[0]
        if suffix == "duplicate":
            raw = raw[:-1] + ',"status":"prepared"}'
        elif suffix == "nonfinite":
            value = json.loads(raw)
            value["detail"] = float("nan")
            raw = json.dumps(value)
        else:
            value = json.loads(raw)
            value.pop("original_job")
            raw = json.dumps(value)
        connection.execute("UPDATE service_activation_records SET payload=?", (raw,))
    with pytest.raises(ValueError, match="inconsistent") as caught:
        a.store.get(HOST, ACTIVATION)
    assert "NaN" not in str(caught.value) and "payload" not in str(caught.value)


def observed_reference(a, watch):
    scope = "b" * 64
    request = watch.request_activation_rescan(
        HOST, scope, ACTIVATION, a.e.job["job_id"], now=a.e.clock
    )
    reference = {
        key: request[key]
        for key in (
            "host_id",
            "activation_id",
            "original_job_id",
            "scope_hash",
            "event_key",
            "rescan_request_id",
        )
    }
    a.store.attach_rescan(HOST, ACTIVATION, reference)
    return request


def test_evidence_binds_independent_activation_observation_without_rewriting_job(
    activation, tmp_path
):
    a = activation
    verified(a)
    watch = VulnerabilityStore(tmp_path / "watch.sqlite3")
    request = observed_reference(a, watch)
    observed = {
        "id": "9" * 32,
        "host_id": HOST,
        "scope_hash": "b" * 64,
        "status": "partial",
        "scan_id": "8" * 32,
        "collected_at": a.e.clock.isoformat(),
    }
    request.update(
        status="complete",
        result_observation_id=observed["id"],
        result_scan_id=observed["scan_id"],
        claimed_at=a.e.clock.isoformat(),
        completed_at=a.e.clock.isoformat(),
    )
    with closing(sqlite3.connect(watch.path)) as connection, connection:
        connection.execute(
            "UPDATE vulnerability_rescans SET status='complete',payload=?", (canonical(request),)
        )
        connection.execute(
            "INSERT INTO vulnerability_observations VALUES(?,?,?,?,?)",
            (observed["id"], HOST, "b" * 64, a.e.clock.isoformat(), canonical(observed)),
        )
    a.service.evidence_observation_store = watch
    before = a.store.path.read_bytes(), watch.path.read_bytes(), list(a.calls)
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    assert bundle["evidence_status"] == "internally_consistent"
    assert bundle["rescan_request"]["event_kind"] == "service_activation"
    assert bundle["rescan_request"]["job_id"] is None
    assert bundle["rescan_request"]["original_job_id"] == a.e.job["job_id"]
    assert bundle["observations"] == [observed]
    assert bundle["original_patch_job"]["status"] == "installed_restart_pending"
    assert (a.store.path.read_bytes(), watch.path.read_bytes(), a.calls) == before
    assert verify_bundle(bundle)["valid"] is True


@pytest.mark.parametrize("status", ["pending", "claimed", "failed"])
def test_unfinished_rescan_cannot_export_as_complete(activation, tmp_path, status):
    a = activation
    verified(a)
    watch = VulnerabilityStore(tmp_path / "watch.sqlite3")
    request = observed_reference(a, watch)
    request["status"] = status
    with closing(sqlite3.connect(watch.path)) as connection, connection:
        connection.execute(
            "UPDATE vulnerability_rescans SET status=?,payload=?", (status, canonical(request))
        )
    a.service.evidence_observation_store = watch
    before = list(a.calls)
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    assert bundle["evidence_status"] == "incomplete"
    assert "activation_rescan:" + status in bundle["missing_components"]
    assert verify_bundle(bundle)["status"] == "incomplete"
    forged = copy.deepcopy(bundle)
    forged.update(evidence_status="internally_consistent", missing_components=[])
    seal(forged, "bundle_digest")
    assert verify_bundle(forged)["valid"] is False
    assert a.calls == before


def completed_observation(a, tmp_path):
    watch = VulnerabilityStore(tmp_path / "watch.sqlite3")
    request = observed_reference(a, watch)
    owner = "d" * 32
    watch.claim_monitor(owner, now=a.e.clock)
    ids = watch.claim_rescans(HOST, "b" * 64, owner, now=a.e.clock)
    scan = {
        "schema_version": 1,
        "host_id": HOST,
        "scan_id": "9" * 32,
        "collected_at": a.e.clock.isoformat(),
        "coverage": {"status": "partial"},
        "findings": [],
        "gaps": ["debian_vendor_assessment_not_implemented"],
        "evidence_origin": "controlled_lab",
    }
    result = watch.ingest(HOST, "b" * 64, scan, now=a.e.clock)
    watch.finish_rescans(HOST, "b" * 64, owner, ids, result, scan=scan, now=a.e.clock)
    a.service.evidence_observation_store = watch
    return watch, watch.get_rescan(request["rescan_request_id"])


@pytest.mark.parametrize(
    "change",
    [
        {"result_scan_id": "8" * 32},
        {"original_job_id": "7" * 32},
        {"job_id": "5" * 32},
        {"event_kind": "patch_job"},
        {"requested_at": "2099-01-01T00:00:00+00:00"},
        {"claimed_at": "2099-01-01T00:00:00+00:00"},
    ],
)
def test_export_rejects_rescan_identity_or_time_contradictions(activation, tmp_path, change):
    a = activation
    verified(a)
    watch, request = completed_observation(a, tmp_path)
    valid = build_evidence(a.service, HOST, ACTIVATION)
    assert valid["evidence_status"] == "internally_consistent"
    request.update(change)
    with closing(sqlite3.connect(watch.path)) as connection, connection:
        connection.execute("UPDATE vulnerability_rescans SET payload=?", (canonical(request),))
    with pytest.raises(ValueError):
        build_evidence(a.service, HOST, ACTIVATION)
    forged = copy.deepcopy(valid)
    forged["rescan_request"].update(change)
    seal(forged, "bundle_digest")
    assert verify_bundle(forged)["valid"] is False


def test_missing_result_does_not_get_backfilled_from_latest(activation, tmp_path):
    a = activation
    verified(a)
    watch, request = completed_observation(a, tmp_path)
    with closing(sqlite3.connect(watch.path)) as connection, connection:
        connection.execute("DELETE FROM vulnerability_observations")
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    assert bundle["evidence_status"] == "incomplete"
    assert "activation_observation:not_retained" in bundle["missing_components"]
    assert verify_bundle(bundle)["integrity_valid"] is True
    assert verify_bundle(bundle)["valid"] is False


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b["original_patch_job"].update(status="verified"),
        lambda b: b["observations"][0].update(scan_id="7" * 32),
        lambda b: b["evidence_provenance"].update(original_patch="real_verified"),
        lambda b: b.update(actions_executable=True),
    ],
)
def test_resealed_download_cannot_forge_its_internal_associations(activation, tmp_path, change):
    a = activation
    verified(a)
    completed_observation(a, tmp_path)
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    assert verify_bundle(bundle)["valid"]
    change(bundle)
    seal(bundle, "bundle_digest")
    assert verify_bundle(bundle)["status"] == "invalid"


def test_activation_download_cli_runs_from_another_directory_without_remote_calls(
    activation, tmp_path
):
    a = activation
    verified(a)
    completed_observation(a, tmp_path)
    bundle = build_evidence(a.service, HOST, ACTIVATION)
    source = tmp_path / "download.json"
    source.write_text(json.dumps(bundle), encoding="utf-8")
    entry = Path(__file__).resolve().parents[1] / "tools/verify_activation_evidence.py"
    response = subprocess.run(  # noqa: S603 -- fixed repository verifier and owned test file.
        [sys.executable, str(entry), str(source)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert response.returncode == 0
    report = json.loads(response.stdout)
    assert report["valid"] and report["status"] == "internally_consistent"
    assert report["origin_authenticity"] == "not_authenticated"
    source.write_text('{"secret":"do-not-display","secret":0}', encoding="utf-8")
    invalid = subprocess.run(  # noqa: S603 -- fixed verifier, deliberately invalid owned file.
        [sys.executable, str(entry), str(source)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert invalid.returncode == 2
    assert "do-not-display" not in invalid.stdout


def test_forged_activation_as_original_patch_rescan_is_rejected(activation, tmp_path):
    a = activation
    verified(a)
    watch = VulnerabilityStore(tmp_path / "watch.sqlite3")
    request = observed_reference(a, watch)
    request["job_id"] = a.e.job["job_id"]
    with closing(sqlite3.connect(watch.path)) as connection, connection:
        connection.execute("UPDATE vulnerability_rescans SET payload=?", (canonical(request),))
    a.service.evidence_observation_store = watch
    with pytest.raises(ValueError):
        build_evidence(a.service, HOST, ACTIVATION)


def test_evidence_http_missing_and_corrupt_original_are_distinct(activation):
    a = activation
    prepare(a)
    app = FastAPI()
    register_activation_routes(app, a.service, [])
    with TestClient(app) as client:
        assert client.get(f"/api/service-activations/{HOST}/{'9' * 32}/evidence").status_code == 404
        response = client.get(f"/api/service-activations/{HOST}/{ACTIVATION}/evidence")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert response.json()["bundle_digest"] == digest(
            {key: value for key, value in response.json().items() if key != "bundle_digest"}
        )
        with closing(sqlite3.connect(a.store.path)) as connection, connection:
            connection.execute("UPDATE service_activation_records SET payload='{}'")
        assert (
            client.get(f"/api/service-activations/{HOST}/{ACTIVATION}/evidence").status_code == 409
        )


@pytest.mark.parametrize("confirmation", [False, 0, "true"])
def test_activation_never_accepts_implicit_confirmation(confirmation):
    from opsark.activation_api import ActivationSubmitRequest

    with pytest.raises(ValueError):
        ActivationSubmitRequest(
            host_id=HOST,
            activation_id=ACTIVATION,
            expected_activation_digest="a" * 64,
            expected_mode_revision=1,
            confirm_activate=confirmation,
        )


def test_final_receipt_and_original_identity_cannot_be_downgraded(activation):
    a = activation
    final = verified(a)
    old = copy.deepcopy(a.results[ACTIVATION])
    with pytest.raises(ValueError):
        a.store.outcome(HOST, ACTIVATION, result=old, detail="stale", now=a.e.clock)
    assert a.store.get(HOST, ACTIVATION) == final
    assert a.e.job["status"] == "installed_restart_pending"


def test_explicit_stop_does_not_poll_or_prepare_again(activation):
    a = activation
    record = prepare(a)
    submit(a, record)
    before = list(a.calls)
    monitor = ActivationMonitor(a.service)
    monitor.stop()
    monitor.poll_once()
    assert a.calls == before


def test_inflight_submit_admission_does_not_get_a_competing_status_rpc(activation):
    a = activation
    record = prepare(a)
    a.store.begin_submission(
        HOST,
        ACTIVATION,
        record["activation_digest"],
        record["plan"]["mode_revision"],
        now=a.e.clock,
    )
    before = list(a.calls)
    with a.e.service.mode_lock:
        assert a.service.poll(HOST, ACTIVATION)["status"] == "submission_intent"
    assert a.calls == before


def test_corrupt_cached_verified_receipt_never_displays_or_triggers_observation(activation):
    from opsark.patch_client import PatchClientError

    a = activation
    verified(a)
    with closing(sqlite3.connect(a.store.path)) as connection, connection:
        value = json.loads(
            connection.execute("SELECT payload FROM service_activation_records").fetchone()[0]
        )
        value["result"]["verification"]["fresh_ssh"]["passed"] = False
        seal(value["result"], "record_digest")
        connection.execute("UPDATE service_activation_records SET payload=?", (canonical(value),))
    with pytest.raises(PatchClientError):
        a.service.get(HOST, ACTIVATION)
    called = []
    monitor = ActivationMonitor(a.service, on_verified=lambda r: called.append(r))
    monitor.poll_once()
    assert not called and monitor.last_error
    with pytest.raises(ValueError):
        build_evidence(a.service, HOST, ACTIVATION)
