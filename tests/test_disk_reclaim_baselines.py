"""Scoped allocation history with synthetic metadata only; no file identity or cleanup claims."""

import json
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from test_ai import settings as ai_settings
from test_disk_reclaim import Metadata, check, collection, helper, host, meta, scope

from opsark import ai, main
from opsark.ai_egress import AIEgressBlocked, guard_request
from opsark.baselines import BaselineStore, compare, diagnostic_scope_for, snapshot
from opsark.diagnostics import diagnose
from opsark.disk_reclaim import (
    DiskAllocationRejected,
    allocation_features,
    parse_disk_reclaim,
    validate_allocation_features,
)
from opsark.models import BaselineChange, BaselineComparison

GROUP = "disk_scope.group.log.directory-1+directory-3.allocated_bytes"


def raw_scope():
    value = json.loads(scope())
    value["directories"].append({"path": "/srv/second-logs", "category": "log"})
    return helper.canonical(value)


def filesystem(*, grow=False, cross_link=True):
    fs = Metadata()
    fs.stats["/srv/second-logs"] = meta(100, mode=0o40755)
    shared = fs.stats["/srv/registered-logs/external-link.log"]
    if cross_link:
        fs.stats["/srv/second-logs/second-link.log"] = shared
    else:
        shared.st_nlink = 1
    if grow:
        for path, blocks in (
            ("/srv/registered-logs/a.log", 16),
            ("/srv/registered-logs/external-link.log", 5),
            ("/srv/registered-data/data.db", 32),
        ):
            fs.stats[path].st_blocks = blocks
            fs.stats[path].st_ctime_ns = 2
    return fs


def report(fs=None, raw=None):
    raw = raw or raw_scope()
    value = helper.project(raw, fs or filesystem())
    target = host().model_copy(update={"disk_reclaim_scope_digest": helper.digest(raw)})
    result = diagnose("disk", target, collection(check(value)))
    result.scope_hash = diagnostic_scope_for(target)
    return result


def test_two_snapshots_point_to_class_and_directory_combination_without_counting_hardlinks_twice(
    tmp_path,
):
    first = report()
    features, refs, missing = snapshot(first)
    assert not missing
    assert features[GROUP] == "512"
    assert features["disk_scope.group.log.directory-1.allocated_bytes"] == "16384"
    assert features["disk_scope.category.log.allocated_bytes"] == "16896"
    assert features["disk_scope.category.business.allocated_bytes"] == "8192"
    assert features["disk_scope.total.allocated_bytes"] == "25088"
    assert all(
        value == ["E-DISK-RECLAIM"] for key, value in refs.items() if key.startswith("disk_scope")
    )
    baseline = BaselineStore(tmp_path / "observations.sqlite3").save(first)
    second = report(filesystem(grow=True))
    second.comparison = compare(second, baseline)
    assert second.comparison.status == "compared"
    changes = {item.field: (item.before, item.after) for item in second.comparison.changes}
    assert changes[GROUP] == ("512", "2560")
    assert changes["disk_scope.group.log.directory-1.allocated_bytes"] == ("16384", "20480")
    assert changes["disk_scope.category.log.allocated_bytes"] == ("16896", "23040")
    assert changes["disk_scope.category.business.allocated_bytes"] == ("8192", "16384")
    assert changes["disk_scope.total.allocated_bytes"] == ("25088", "39424")
    assert all(item.evidence_ids == ["E-DISK-RECLAIM"] for item in second.comparison.changes)
    assert any(
        "不连续追踪单文件" in note and "业务数据排除清理" in note
        for note in second.comparison.missing
    )
    serialized = baseline.model_dump_json() + second.comparison.model_dump_json()
    assert (
        "/srv/" not in serialized
        and "process-" not in serialized
        and "object_ref" not in serialized
    )
    rendered = main.report_markdown(second)
    assert "登记目录组合 directory-1 + directory-3" in rendered
    assert "已分配字节变化 +2048" in rendered
    assert "业务数据（排除清理）" in rendered


def test_ctime_only_changes_object_refs_but_does_not_claim_file_growth(tmp_path):
    first = report()
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(first)
    fs = filesystem()
    fs.stats["/srv/registered-logs/a.log"].st_ctime_ns = 9
    second = report(fs)
    before = json.loads(first.evidence[-1].output)
    after = json.loads(second.evidence[-1].output)
    assert {obj["object_ref"] for obj in before["objects"]} != {
        obj["object_ref"] for obj in after["objects"]
    }
    assert snapshot(first)[0] == snapshot(second)[0]
    result = compare(second, baseline)
    assert result.status == "compared" and result.changes == []


def test_full_same_scope_scans_allow_zero_for_new_and_disappeared_combinations(tmp_path):
    first = report(filesystem(cross_link=False))
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    baseline = store.save(first)
    second = report()
    result = compare(second, baseline)
    changes = {item.field: item for item in result.changes}
    assert (changes[GROUP].before, changes[GROUP].after) == ("0", "512")
    assert "disk_scope.total.allocated_bytes" not in changes
    assert "disk_scope.category.log.allocated_bytes" not in changes
    second.comparison = result
    assert ai.explanation_input(second)["observation_comparison"]["change_count"] == 2
    next_baseline = store.save(second)
    third = report(filesystem(cross_link=False))
    reversed_changes = {item.field: item for item in compare(third, next_baseline).changes}
    assert (reversed_changes[GROUP].before, reversed_changes[GROUP].after) == ("512", "0")


def test_scope_drift_and_missing_metadata_never_become_growth_or_zero(tmp_path):
    first = report()
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(first)
    changed = json.loads(raw_scope())
    changed["max_depth"] = 2
    drifted = report(raw=helper.canonical(changed))
    assert compare(drifted, baseline).status == "scope_changed"
    assert compare(drifted, baseline).changes == []
    incomplete = report()
    incomplete.evidence[-1] = incomplete.evidence[-1].model_copy(update={"status": "timeout"})
    result = compare(incomplete, baseline)
    assert result.status == "incomplete"
    assert not any(item.field.startswith("disk_scope") for item in result.changes)
    assert any("不能以空值或零代替" in note for note in result.missing)
    absent = report()
    absent.evidence.pop()
    assert any("不能以零占用替代" in note for note in snapshot(absent)[2])
    assert not any(
        item.field.startswith("disk_scope") for item in compare(absent, baseline).changes
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda fields: fields.update({"disk_scope.unknown": "512"}),
        lambda fields: fields.update(
            {"disk_scope.group.log.directory-3+directory-1.allocated_bytes": "512"}
        ),
        lambda fields: fields.update(
            {"disk_scope.group.log.directory-1+directory-1.allocated_bytes": "512"}
        ),
        lambda fields: fields.update({"disk_scope.total.allocated_bytes": "999"}),
        lambda fields: fields.update({"disk_scope.total.allocated_bytes": "025088"}),
        lambda fields: fields.update({"disk_scope.algorithm": "unknown"}),
        lambda fields: fields.pop("disk_scope.category.business.allocated_bytes"),
    ],
)
def test_unknown_or_inconsistent_metrics_reject_whole_comparison_and_ai(tmp_path, mutate):
    before = report()
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(before)
    fields = dict(baseline.features)
    mutate(fields)
    with pytest.raises(DiskAllocationRejected):
        validate_allocation_features(fields)
    current = report(filesystem(grow=True))
    current.comparison = compare(current, baseline.model_copy(update={"features": fields}))
    assert current.comparison.status == "incomplete" and current.comparison.changes == []
    assert current.ai_egress_block_reason == "unclassified_payload"
    assert "unknown" not in current.comparison.model_dump_json()
    with pytest.raises(ValueError):
        ai.explanation_input(current)


@pytest.mark.parametrize(
    "change",
    [
        BaselineChange(
            field="disk_scope.unknown", before="0", after="512", evidence_ids=["E-DISK-RECLAIM"]
        ),
        BaselineChange(field=GROUP, before="0", after="999", evidence_ids=["E-DISK-RECLAIM"]),
        BaselineChange(field=GROUP, before="0", after="512", evidence_ids=["E-DISK-BYTES"]),
    ],
)
def test_unclassified_comparison_cannot_be_projected_or_exported(change):
    current = report()
    current.comparison = BaselineComparison(status="compared", changes=[change])
    with pytest.raises(ValueError):
        ai.explanation_input(current)
    with pytest.raises(ValueError):
        main.report_markdown(current)


def test_api_two_investigations_save_compare_readback_export_and_closed_ai(tmp_path, monkeypatch):
    settings = ai_settings(tmp_path)
    pair = [report(), report(filesystem(grow=True))]
    streams = []
    for item in pair:
        value = json.loads(item.evidence[-1].output)
        streams.append((item.target, collection(check(value))))
    monkeypatch.setattr(
        main,
        "list_samples",
        lambda: [
            {"id": "disk-history", "scenario": "disk", "title": "Fixture", "host_id": "fixture"}
        ],
    )
    monkeypatch.setattr(main, "collect_replay", lambda _: streams.pop(0))
    calls = []
    monkeypatch.setattr(ai, "request_document", lambda *args, **kwargs: calls.append(True))
    with TestClient(main.create_app(settings)) as client:
        headers = {"Authorization": "Bearer " + settings.token}
        payload = {"source": "replay", "scenario": "disk", "sample_id": "disk-history"}
        first = client.post("/api/investigations", headers=headers, json=payload).json()
        saved = client.post(
            "/api/reports/" + first["id"] + "/baseline",
            headers=headers,
            json={"confirm_observation_only": True},
        )
        assert saved.status_code == 200
        assert saved.json()["features"][GROUP] == "512"
        response = client.post("/api/investigations", headers=headers, json=payload)
        assert response.status_code == 200
        second = response.json()
        changes = {item["field"]: item for item in second["comparison"]["changes"]}
        assert changes[GROUP]["after"] == "2560"
        assert client.get("/api/reports/" + second["id"], headers=headers).json() == second
        export = client.get("/api/reports/" + second["id"] + "/export", headers=headers)
        assert "登记目录组合 directory-1 + directory-3" in export.text
        handoff = client.get("/api/reports/" + second["id"] + "/handoff", headers=headers)
        assert handoff.status_code == 200
        assert "/srv/" not in saved.text + response.text + export.text + handoff.text
        assert "disk_scope" not in handoff.text and "directory-" not in handoff.text
        current = client.app.state.store.get(second["id"])
        summary = ai.explanation_input(current)
        encoded = json.dumps(summary)
        assert summary["observation_comparison"]["change_count"] == 6
        assert all(
            private not in encoded for private in ("directory-", "disk_scope", "/srv/", "2560")
        )
        body = {
            "model": settings.ai_model,
            "max_tokens": settings.ai_max_output_tokens,
            "messages": [
                {"role": "system", "content": ai.egress_system(summary)},
                {"role": "user", "content": encoded},
            ],
            "response_format": ai.egress_format(settings),
        }
        guard_request(body, settings, "diagnosis")
        body["messages"][1]["content"] = json.dumps({**summary, "allocation_metric": GROUP})
        with pytest.raises(AIEgressBlocked):
            guard_request(body, settings, "diagnosis")
        bad = deepcopy(current)
        bad.id += "-unknown"
        bad.comparison.changes[0].field = "disk_scope.unknown"
        client.app.state.store.save(bad)
        assert client.get("/api/reports/" + bad.id + "/export", headers=headers).status_code == 409
        assert client.get("/api/reports/" + bad.id + "/handoff", headers=headers).status_code == 409
        refused_baseline = client.post(
            "/api/reports/" + bad.id + "/baseline",
            headers=headers,
            json={"confirm_observation_only": True},
        )
        assert refused_baseline.status_code == 409
        explanation = client.post(
            "/api/reports/" + bad.id + "/explain", headers=headers, json={"confirm_send": True}
        )
        assert explanation.json()["status"] == "failed"
    assert calls == []


def test_old_baseline_without_metadata_fields_does_not_invent_zero_history(tmp_path):
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(report())
    old = baseline.model_copy(
        update={
            "features": {
                key: value
                for key, value in baseline.features.items()
                if not key.startswith("disk_scope")
            },
            "references": {
                key: value
                for key, value in baseline.references.items()
                if not key.startswith("disk_scope")
            },
        }
    )
    current = report(filesystem(grow=True))
    result = compare(current, old)
    assert result.status == "incomplete"
    assert not any(item.field.startswith("disk_scope") for item in result.changes)
    assert any("基线未保存字段 disk_scope" in gap for gap in result.missing)
    assert current.ai_egress_block_reason is None


def test_business_growth_is_occupancy_only_and_never_increases_log_reclaim_bound(tmp_path):
    first = report()
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(first)
    fs = filesystem()
    fs.stats["/srv/registered-data/data.db"].st_blocks = 32
    fs.stats["/srv/registered-data/data.db"].st_ctime_ns = 2
    current = report(fs)
    changes = {item.field for item in compare(current, baseline).changes}
    assert changes == {
        "disk_scope.total.allocated_bytes",
        "disk_scope.category.business.allocated_bytes",
        "disk_scope.group.business.directory-2.allocated_bytes",
    }
    prior = json.loads(first.evidence[-1].output)
    latest = json.loads(current.evidence[-1].output)
    assert prior["conditional_log_upper_bytes"] == latest["conditional_log_upper_bytes"]
    assert latest["actions_enabled"] is False and current.action.executable is False


def test_aggregate_fields_are_derived_only_after_closed_projection_validation():
    value = helper.project(raw_scope(), filesystem())
    parsed = parse_disk_reclaim(check(value), helper.digest(raw_scope()))
    assert allocation_features(parsed)["disk_scope.total.allocated_bytes"] == "25088"
