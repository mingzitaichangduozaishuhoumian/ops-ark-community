"""Keep declarations and measured comparisons independently bound to one report."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from test_compose_generation_store import report as ssh_report
from test_compose_generation_store import witness

from opsark import baselines, main
from opsark.baselines import BaselineStore, diagnostic_scope_for
from opsark.compose_generation_store import ComposeGenerationStore
from opsark.config import HostConfig, Settings
from opsark.models import BaselineComparison, Evidence
from opsark.storage import ReportStore

TOKEN = "synthetic-change-record-test-fixture"
AUTH = {"Authorization": "Bearer " + TOKEN}
CANARY = "synthetic-private-evidence-marker"


def path(report):
    return f"/api/reports/{report.id}/change-records"


def body(index=1, **changes):
    return {
        "request_id": f"{index:032x}",
        "kind": "compose_configuration",
        "claimed_at": {"precision": "date", "value": "2026-06-09"},
    } | changes


@pytest.fixture
def target(tmp_path, monkeypatch):
    original = ssh_report("original")
    assert original.target is not None
    original.evidence = [
        Evidence(
            id="E-OS-RELEASE",
            check_id="os_release",
            target=original.host_id,
            source="ssh",
            collected_at=original.created_at,
            status="ok",
            exit_code=0,
            output='ID=ubuntu\nVERSION_ID="24.04"\n',
        )
    ]
    registration = HostConfig(original.target, tmp_path / "key-reference", tmp_path / "host-trust")
    registrations = {original.host_id: registration}
    monkeypatch.setattr(main, "load_hosts", lambda _: registrations)
    monkeypatch.setattr(main, "collect_ssh", lambda *_: pytest.fail("no SSH for history"))
    monkeypatch.setattr(main, "explain", lambda *_: pytest.fail("no model for history"))
    store = ReportStore(tmp_path / "reports.sqlite3")
    store.save(original)
    return original, store, registrations, Settings(tmp_path, TOKEN)


def test_original_and_frozen_export_survive_append_restart_and_scope_change(target):
    report, _, registrations, settings = target
    endpoint = path(report)
    with TestClient(main.create_app(settings)) as client:
        assert client.get(endpoint).status_code == 401
        assert client.post(endpoint, json=body()).status_code == 401
        original = client.get(f"/api/reports/{report.id}", headers=AUTH).content
        old_handoff = client.get(f"/api/reports/{report.id}/handoff", headers=AUTH).content
        empty = client.get(endpoint, headers=AUTH).json()
        assert empty["can_record"] is True and empty["records"] == []
        assert empty["observation"]["baseline_status"] == "no_baseline"
        assert empty["observation"]["changes"] == []
        response = client.post(endpoint, headers=AUTH, json=body())
        assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
        saved = response.json()
        assert set(saved) == {"id", "report_id", "kind", "source", "claimed_at", "recorded_at"}
        assert (
            saved["claimed_at"] == body()["claimed_at"] and saved["source"] == "operator_statement"
        )
        assert client.post(endpoint, headers=AUTH, json=body()).json() == saved
        assert (
            client.post(endpoint, headers=AUTH, json=body(kind="image_update")).status_code == 409
        )
        after = client.get(endpoint, headers=AUTH).json()
        assert after == empty | {"records": [saved]}
        export_path = endpoint + f"/{saved['id']}/handoff"
        assert client.get(export_path).status_code == 401
        export = client.get(export_path, headers=AUTH)
        assert export.status_code == 200 and "attachment" in export.headers["content-disposition"]
        assert "维护者陈述" in export.text and "实际执行时间、部署来源和操作者仍未知" in export.text
        assert "2026-06-09（日历日期）" in export.text
        assert not any(secret in export.text for secret in (TOKEN, "192.0.2.5", report.scope_hash))
        assert client.post(endpoint, headers=AUTH, json=body(2, note=CANARY)).status_code == 422
        future = {"precision": "instant", "value": "2099-01-01T00:00:00Z"}
        assert (
            client.post(endpoint, headers=AUTH, json=body(2, claimed_at=future)).status_code == 422
        )
        assert client.post(endpoint, headers=AUTH, json=body(2)).status_code == 201
        assert client.get(export_path, headers=AUTH).content == export.content
        assert client.get(f"/api/reports/{report.id}", headers=AUTH).content == original
        assert client.get(f"/api/reports/{report.id}/handoff", headers=AUTH).content == old_handoff
        entry = registrations[report.host_id]
        registrations[report.host_id] = replace(
            entry, public=entry.public.model_copy(update={"trusted_hosts_digest": "e" * 64})
        )
        assert client.post(endpoint, headers=AUTH, json=body(3)).status_code == 409

    with TestClient(main.create_app(settings)) as client:
        history = client.get(endpoint, headers=AUTH).json()
        assert history["can_record"] is False and len(history["records"]) == 2
        assert client.get(export_path, headers=AUTH).content == export.content


def test_only_a_verified_pair_reports_intervals_and_cross_report_export_is_refused(
    target, monkeypatch
):
    original, store, _, settings = target
    baseline_at = original.created_at + timedelta(seconds=1)

    class BaselineClock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return baseline_at

    with monkeypatch.context() as clock:
        clock.setattr(baselines, "datetime", BaselineClock)
        base = BaselineStore(settings.data_dir / "baselines.sqlite3").save(original)
    later = ssh_report("later", elapsed=10).model_copy(
        update={
            "comparison": BaselineComparison(
                status="compared",
                baseline_id=base.id,
                baseline_report_id=original.id,
                baseline_created_at=base.created_at,
            ),
        }
    )
    original_time = original.created_at
    later_time = later.created_at
    generation = ComposeGenerationStore(store)
    generation.save(original.id, witness().model_copy(update={"observed_at": original_time}))
    store.save(later)
    generation.save(
        later.id,
        witness(container="31" * 32, configuration="21" * 32).model_copy(
            update={"observed_at": later_time}
        ),
    )
    other = ssh_report("other")
    assert other.target is not None
    alternate = other.target.model_copy(update={"address": "192.0.2.25"})
    other.target, other.scope_hash = alternate, diagnostic_scope_for(alternate)
    store.save(other)
    with TestClient(main.create_app(settings)) as client:
        first = client.get(path(later), headers=AUTH).json()["observation"]
        assert [item["field"] for item in first["changes"]] == [
            "container",
            "compose_configuration",
        ]
        for span in first["changes"]:
            assert datetime.fromisoformat(span["from_at"]) == original_time
            assert datetime.fromisoformat(span["to_at"]) == later_time
        response = client.post(path(later), headers=AUTH, json=body())
        assert response.status_code == 201
        note = response.json()
        assert client.get(path(later), headers=AUTH).json()["observation"] == first
        assert client.get(path(other) + f"/{note['id']}/handoff", headers=AUTH).status_code == 404
        assert client.post(path(other), headers=AUTH, json=body()).status_code == 409
