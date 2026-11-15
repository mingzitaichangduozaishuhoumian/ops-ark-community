import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime

import pytest

from opsark.baselines import BaselineStore, compare, scope_for, snapshot
from opsark.health import evaluate_health
from opsark.models import (
    CheckResult,
    Collection,
    Evidence,
    HealthCheck,
    HostPublic,
    Report,
    Verification,
)
from opsark.redaction import redact


def test_legacy_derived_baseline_is_not_reused_after_raw_health_policy_change(tmp_path):
    before = make_report({"nginx_status": "active\n"})
    baseline = BaselineStore(tmp_path / "legacy.sqlite3").save(before)
    legacy = baseline.model_copy(update={"schema_version": 0})
    comparison = compare(before, legacy)
    assert comparison.status == "incomplete"
    assert comparison.changes == []
    assert any("算法版本" in item for item in comparison.missing)


def host(**overrides) -> HostPublic:
    return HostPublic(id="web-1", name="Website", address="192.0.2.10", **overrides)


def make_report(
    checks: dict[str, str],
    report_id: str = "report-1",
    registered: HostPublic | None = None,
    **overrides,
) -> Report:
    registered = registered or host(
        health_checks=[HealthCheck(id="shop", domain="shop.example.com", read_only_confirmed=True)],
        nginx_config_path="/etc/nginx/conf.d/site.conf",
    )
    created = datetime(2026, 10, 26, 12, tzinfo=UTC)
    values = {
        "id": report_id,
        "host_id": registered.id,
        "host_name": registered.name,
        "scenario": "web_502",
        "source": registered.source,
        "created_at": created,
        "status": "inconclusive",
        "title": "Read-only observation",
        "summary": "Needs evidence",
        "facts": [],
        "candidates": [],
        "missing": [],
        "next_steps": [],
        "scope_hash": scope_for(registered),
        "target": registered,
        "evidence": [
            Evidence(
                id="E-" + name.replace("_", "-").upper(),
                check_id=name,
                target=registered.id,
                source=registered.source,
                collected_at=created,
                status="ok",
                exit_code=0,
                output=redact(output),
            )
            for name, output in checks.items()
        ],
        "verification": evaluate_health(
            registered,
            Collection(
                host_id=registered.id,
                source=registered.source,
                started_at=created,
                checks=[CheckResult(name=name, stdout=output) for name, output in checks.items()],
            ),
        ),
    }
    values.update(overrides)
    return Report(**values)


def container(**overrides) -> str:
    values = {
        "Name": "/api",
        "State": {"Status": "running", "OOMKilled": False},
        "RestartCount": 0,
        "MemoryLimit": 536870912,
        "Image": "sha256:" + "a" * 64,
        "ImageReference": "registry.example/app:stable",
        "Ports": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8081"}]},
    }
    values.update(overrides)
    return json.dumps(values)


def test_scope_is_stable_and_changes_with_deployment_identity():
    original = host()
    assert len(scope_for(original)) == 64
    assert scope_for(original) == scope_for(original.model_copy(update={"name": "Renamed"}))
    assert scope_for(original) != scope_for(original.model_copy(update={"address": "192.0.2.11"}))
    assert scope_for(original) != scope_for(original.model_copy(update={"source": "ssh"}))
    assert scope_for(original) != scope_for(original.model_copy(update={"container_name": "db"}))
    assert scope_for(original) != scope_for(
        original.model_copy(update={"trusted_hosts_digest": "a" * 64})
    )


def test_scope_health_order_and_domain_case_are_semantically_stable():
    checks = [
        HealthCheck(id="shop", domain="shop.example.com"),
        HealthCheck(id="blog", domain="blog.example.com"),
    ]
    first = host(health_checks=checks)
    second = first.model_copy(
        update={"health_checks": list(reversed(checks)), "site_domain": "SHOP.EXAMPLE.COM."}
    )
    assert scope_for(first) == scope_for(second)
    changed = first.model_copy(
        update={"health_checks": [checks[0].model_copy(update={"expected_status": 204}), checks[1]]}
    )
    assert scope_for(first) != scope_for(changed)


def test_snapshot_extracts_only_typed_metadata_and_current_references():
    report = make_report(
        {
            "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="not stored"\n',
            "container_state": container(),
            "disk_bytes": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/test 10000000 2000000 8000000 20% /\n",
            "disk_inodes": "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
            "/dev/test 10000 1000 9000 10% /\n",
            "nginx_status": "active\n",
            "nginx_config_hash": "b" * 64 + "  /etc/nginx/conf.d/site.conf\n",
            "http_shop": "private response body\nOPSARK_HTTP_STATUS:200\n",
        }
    )
    features, references, missing = snapshot(report)
    assert not missing
    assert features["os.id"] == "ubuntu"
    assert features["container.image_id"] == "sha256:" + "a" * 64
    assert features["container.name"] == "api"
    assert features["disk.used_percent"] == "20"
    assert features["inode.available"] == "9000"
    assert features["http.shop.status"] == "200"
    assert features["http.shop.body_matches"] == "true"
    assert features["http.shop.expected_status_matches"] == "true"
    assert "private response body" not in str(features)
    assert "not stored" not in str(features)
    assert references["http.shop.status"] == ["E-HTTP-SHOP"]
    assert set(features) == set(references)


@pytest.mark.parametrize(
    "update",
    [
        {"status": "permission_denied"},
        {"status": "timeout"},
        {"exit_code": None},
        {"exit_code": 1},
        {"truncated": True},
    ],
)
def test_failed_or_partial_evidence_never_becomes_a_known_old_value(update):
    report = make_report({"container_state": container()})
    report.evidence[0] = report.evidence[0].model_copy(update=update)
    features, references, missing = snapshot(report)
    assert features == references == {}
    assert missing


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "[]",
        '{"State": []}',
        '{"Name":"api;secret=value","State":{"Status":"running"}}',
    ],
)
def test_uninterpretable_container_metadata_is_not_preserved(output):
    features, _, missing = snapshot(make_report({"container_state": output}))
    assert not features
    assert missing


def test_boolean_counters_and_untrusted_image_reference_are_rejected():
    features, _, missing = snapshot(
        make_report(
            {
                "container_state": container(
                    RestartCount=True,
                    MemoryLimit="512",
                    ImageReference="https://user:secret@registry/app",
                )
            }
        )
    )
    assert "container.restart_count" not in features
    assert "container.memory_limit_bytes" not in features
    assert "container.image_reference" not in features
    assert missing


def test_unknown_raw_log_and_container_secret_fields_do_not_enter_database(tmp_path):
    report = make_report(
        {
            "container_state": container(
                Env=["PASSWORD=original-secret"], Error="private-error-secret"
            ),
            "nginx_errors": "Authorization: Bearer raw-log-secret",
            "http_shop": "user-private-body-secret\nOPSARK_HTTP_STATUS:502\n",
        }
    )
    path = tmp_path / "baselines.sqlite3"
    saved = BaselineStore(path).save(report)
    raw = saved.model_dump_json()
    with closing(sqlite3.connect(path)) as connection:
        raw += connection.execute("SELECT payload FROM baselines").fetchone()[0]
    for secret in (
        "original-secret",
        "private-error-secret",
        "raw-log-secret",
        "user-private-body-secret",
    ):
        assert secret not in raw
    assert "http.shop.status" in saved.features


def test_private_provider_token_shaped_container_names_are_not_preserved():
    report = make_report({"container_state": container(Name="sk-123456789secret")})
    assert not snapshot(report)[0]


def test_ports_normalize_order_and_reject_invalid_bindings():
    first = make_report(
        {
            "container_state": container(
                Ports={
                    "8000/tcp": [
                        {"HostIp": "::", "HostPort": "8081"},
                        {"HostIp": "127.0.0.1", "HostPort": "8081"},
                    ],
                    "9000/udp": None,
                }
            )
        }
    )
    features, _, missing = snapshot(first)
    assert not missing
    assert "9000/udp" in features["container.published_ports"]
    invalid = make_report(
        {
            "container_state": container(
                Ports={"8000/tcp": [{"HostIp": "private-secret.invalid", "HostPort": True}]}
            )
        }
    )
    assert "container.published_ports" not in snapshot(invalid)[0]


@pytest.mark.parametrize(
    "check,output",
    [
        ("os_release", 'ID=ubuntu\nID=debian\nVERSION_ID="24.04"\n'),
        ("nginx_status", "inactive\n"),
        ("nginx_config_hash", "unexpected private config body"),
        ("http_shop", "OPSARK_HTTP_STATUS:200\nbody without a trailing controlled marker"),
        ("http_shop", "body\nOPSARK_HTTP_STATUS:000\n"),
        (
            "disk_bytes",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/test 100 10 90 10% /other\n",
        ),
    ],
)
def test_invalid_fields_are_missing_rather_than_assumed_normal(check, output):
    features, _, missing = snapshot(make_report({check: output}))
    assert missing
    if check != "os_release":
        assert not features
    else:
        assert "os.id" not in features


def test_http_body_cannot_override_the_controlled_final_status():
    features, _, missing = snapshot(
        make_report({"http_shop": "injected\nOPSARK_HTTP_STATUS:200\n\nOPSARK_HTTP_STATUS:503\n"})
    )
    assert not missing
    assert features == {
        "http.shop.status": "503",
        "http.shop.body_matches": "true",
        "http.shop.expected_status_matches": "false",
    }


def test_http_200_body_condition_drift_is_recorded_without_body_or_expectation(tmp_path):
    def health_report(body, report_id):
        target = host(
            health_checks=[
                HealthCheck(
                    id="shop",
                    domain="shop.example.com",
                    expected_body="private-ready-marker",
                    read_only_confirmed=True,
                )
            ]
        )
        return make_report(
            {"http_shop": body + "\nOPSARK_HTTP_STATUS:200\n"}, report_id, registered=target
        )

    before = health_report("private-ready-marker response-content", "http-before")
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(before)
    after = health_report("different-private-response-content", "http-after")
    comparison = compare(after, baseline)
    assert comparison.status == "compared"
    assert [(item.field, item.before, item.after) for item in comparison.changes] == [
        ("http.shop.body_matches", "true", "false")
    ]
    assert comparison.changes[0].evidence_ids == ["E-HTTP-SHOP"]
    serialized = baseline.model_dump_json() + comparison.model_dump_json()
    for private in (
        "private-ready-marker",
        "response-content",
        "different-private-response-content",
    ):
        assert private not in serialized
    for report, expected in ((before, "passed"), (after, "failed")):
        assert report.target is not None
        result = evaluate_health(
            report.target,
            Collection(
                host_id=report.host_id,
                source=report.source,
                started_at=report.created_at,
                checks=[CheckResult(name="http_shop", stdout=report.evidence[0].output)],
            ),
        )
        assert result[0].status == expected


def test_http_status_condition_drift_and_collection_error_remain_distinct(tmp_path):
    before = make_report({"http_shop": "body\nOPSARK_HTTP_STATUS:200\n"})
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(before)
    after = make_report({"http_shop": "body\nOPSARK_HTTP_STATUS:503\n"}, "http-failed")
    comparison = compare(after, baseline)
    changes = {item.field: (item.before, item.after) for item in comparison.changes}
    assert changes["http.shop.expected_status_matches"] == ("true", "false")
    assert changes["http.shop.status"] == ("200", "503")
    after.evidence[0] = after.evidence[0].model_copy(update={"status": "timeout"})
    features, _, missing = snapshot(after)
    assert not any(field.startswith("http.") for field in features)
    assert missing


def test_redaction_marker_cannot_turn_the_original_body_condition_into_a_pass():
    output = '{"token":"sensitive-value"}\nOPSARK_HTTP_STATUS:200\n'
    target = host(
        health_checks=[
            HealthCheck(
                id="shop",
                domain="shop.example.com",
                expected_body="[REDACTED]",
                read_only_confirmed=True,
            )
        ]
    )
    report = make_report({"http_shop": output}, registered=target)
    assert "[REDACTED]" in report.evidence[0].output
    features, _, missing = snapshot(report)
    assert not missing
    assert features["http.shop.body_matches"] == "false"
    assert features["http.shop.expected_status_matches"] == "true"
    assert "sensitive-value" not in json.dumps(features)
    result = evaluate_health(
        target,
        Collection(
            host_id=report.host_id,
            source=report.source,
            started_at=report.created_at,
            checks=[CheckResult(name="http_shop", stdout=output)],
        ),
    )
    assert result[0].status == "failed"


@pytest.mark.parametrize(
    "update",
    [
        {"http_status": None},
        {"http_status": True},
        {"http_status": "200"},
        {"http_status": 200.0},
        {"status_matches": None},
        {"status_matches": "true"},
        {"body_matches": None},
        {"body_matches": 1},
        {"http_status": 503},
        {"status_matches": False},
        {"body_matches": False},
        {"status": "failed"},
        {"status": "error"},
        {"evidence_ids": ["E-HTTP-SHOP", "E-OTHER"]},
    ],
)
def test_missing_or_contradictory_original_http_metadata_is_not_saved(update):
    report = make_report({"http_shop": "body\nOPSARK_HTTP_STATUS:200\n"})
    original = Verification(
        name="HTTP original decision",
        status="passed",
        detail="Do not store this detail",
        evidence_ids=["E-HTTP-SHOP"],
        http_status=200,
        status_matches=True,
        body_matches=True,
    )
    report.verification = [original.model_copy(update=update)]
    features, _, missing = snapshot(report)
    assert not any(field.startswith("http.") for field in features)
    assert missing


def test_duplicate_or_old_http_judgments_are_not_rebuilt_from_displayed_output():
    report = make_report({"http_shop": "body\nOPSARK_HTTP_STATUS:200\n"})
    old = Verification(
        name="Old compatible result",
        status="passed",
        detail="No metadata",
        evidence_ids=["E-HTTP-SHOP"],
    )
    report.verification = [old]
    assert not snapshot(report)[0]
    valid = old.model_copy(
        update={"http_status": 200, "status_matches": True, "body_matches": True}
    )
    report.verification = [valid, valid.model_copy()]
    assert not snapshot(report)[0]
    report.verification = []
    assert not snapshot(report)[0]


def test_original_http_judgment_survives_redaction_without_persisting_secrets(tmp_path):
    target = host(
        health_checks=[
            HealthCheck(
                id="shop",
                domain="shop.example.com",
                expected_body="sensitive-value",
                read_only_confirmed=True,
            )
        ]
    )
    raw = '{"token":"sensitive-value"}\nOPSARK_HTTP_STATUS:200\n'
    report = make_report({"http_shop": raw}, registered=target)
    assert "sensitive-value" not in report.evidence[0].output
    # Displayed evidence cannot be used to reproduce the first-hand body decision.
    assert report.verification[0].body_matches is True
    features, _, missing = snapshot(report)
    assert not missing
    assert features["http.shop.body_matches"] == "true"
    report.verification[0].detail = "private-verification-detail"
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    saved = store.save(report)
    with closing(sqlite3.connect(store.path)) as connection:
        serialized = connection.execute("SELECT payload FROM baselines").fetchone()[0]
    assert "sensitive-value" not in serialized
    assert "private-verification-detail" not in serialized
    assert saved.features["http.shop.expected_status_matches"] == "true"


def test_scope_and_duplicate_evidence_are_required():
    report = make_report({"nginx_status": "active\n"})
    report.evidence.append(report.evidence[0])
    with pytest.raises(ValueError):
        snapshot(report)
    report = make_report({"nginx_status": "active\n"})
    report.evidence[0].target = "other-host"
    with pytest.raises(ValueError):
        snapshot(report)


def test_target_metadata_and_scope_digest_must_match_report():
    report = make_report({"nginx_status": "active\n"})
    assert not snapshot(report.model_copy(update={"target": None}))[0]
    assert report.target is not None
    with pytest.raises(ValueError):
        snapshot(
            report.model_copy(
                update={"target": report.target.model_copy(update={"id": "other-host"})}
            )
        )
    with pytest.raises(ValueError):
        snapshot(report.model_copy(update={"scope_hash": "a" * 64}))


def test_live_baseline_requires_identity_bound_to_trusted_hosts():
    report = make_report({"nginx_status": "active\n"})
    assert report.target is not None
    target = report.target.model_copy(update={"source": "ssh"})
    report = report.model_copy(
        update={
            "source": "ssh",
            "target": target,
            "scope_hash": scope_for(target),
            "evidence": [item.model_copy(update={"source": "ssh"}) for item in report.evidence],
        }
    )
    features, _, missing = snapshot(report)
    assert not features
    assert any("主机记录摘要" in item for item in missing)
    target = target.model_copy(update={"trusted_hosts_digest": "a" * 64})
    features, _, missing = snapshot(
        report.model_copy(update={"target": target, "scope_hash": scope_for(target)})
    )
    assert not missing
    assert features == {"nginx.status": "active"}


def test_wrong_container_never_becomes_the_registered_target_baseline():
    report = make_report({"container_state": container(Name="/unrelated-db")})
    features, _, missing = snapshot(report)
    assert not features
    assert any("登记目标不一致" in item for item in missing)


def test_unregistered_or_unconfirmed_http_check_is_not_saved():
    report = make_report({"http_other": "body\nOPSARK_HTTP_STATUS:200\n"})
    assert not snapshot(report)[0]
    report = make_report({"http_shop": "body\nOPSARK_HTTP_STATUS:200\n"})
    assert report.target is not None
    target = report.target.model_copy(
        update={
            "health_checks": [
                HealthCheck(id="shop", domain="shop.example.com", read_only_confirmed=False)
            ]
        }
    )
    features, _, missing = snapshot(
        report.model_copy(update={"target": target, "scope_hash": scope_for(target)})
    )
    assert not features
    assert any("未确认只读" in item for item in missing)


def test_hash_filename_must_belong_to_registered_config():
    report = make_report({"nginx_config_hash": "a" * 64 + "  /etc/nginx/conf.d/unrelated.conf\n"})
    assert not snapshot(report)[0]
    assert report.target is not None
    target = report.target.model_copy(update={"nginx_config_path": None})
    assert not snapshot(
        report.model_copy(update={"target": target, "scope_hash": scope_for(target)})
    )[0]


def test_oversized_metadata_is_missing_without_retaining_its_content():
    report = make_report({"os_release": "private-marker" * 2000})
    features, _, missing = snapshot(report)
    assert not features
    assert "private-marker" not in str(missing)


def test_port_order_does_not_create_a_false_drift(tmp_path):
    ports = {
        "8000/tcp": [
            {"HostIp": "::", "HostPort": "8081"},
            {"HostIp": "127.0.0.1", "HostPort": "8081"},
        ]
    }
    before = make_report({"container_state": container(Ports=ports)})
    baseline = BaselineStore(tmp_path / "baseline.sqlite3").save(before)
    after = make_report(
        {"container_state": container(Ports={"8000/tcp": list(reversed(ports["8000/tcp"]))})},
        report_id="after",
    )
    result = compare(after, baseline)
    assert result.status == "compared"
    assert result.changes == []


def test_store_persists_immutable_snapshot_and_latest_is_scoped(tmp_path):
    path = tmp_path / "baselines.sqlite3"
    store = BaselineStore(path)
    report = make_report({"nginx_status": "active\n"})
    saved = store.save(report)
    assert saved.restore_capable is False and saved.purpose == "observation_only"
    reopened = BaselineStore(path)
    assert reopened.latest("replay", "web-1", "web_502") == saved
    assert reopened.latest("ssh", "web-1", "web_502") is None
    assert reopened.latest("replay", "other", "web_502") is None
    assert reopened.latest("replay", "web-1", "disk") is None
    assert reopened.save(report) == saved
    target = report.target.model_copy(update={"address": "192.0.2.11"})
    changed = report.model_copy(update={"scope_hash": scope_for(target), "target": target})
    with pytest.raises(ValueError):
        reopened.save(changed)
    assert reopened.latest("replay", "web-1", "web_502") == saved
    assert "features" not in reopened.list()[0]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_refuses_old_reports_and_reports_without_metadata(tmp_path):
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    old = make_report({"nginx_status": "active\n"}).model_dump(exclude={"scope_hash", "comparison"})
    report = Report.model_validate(old)
    assert report.comparison.status == "no_baseline"
    with pytest.raises(ValueError):
        store.save(report)
    with pytest.raises(ValueError):
        store.save(make_report({"nginx_errors": "raw private log"}))


def test_compare_reports_changes_with_current_refs_without_mutating_history(tmp_path):
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    before = make_report({"container_state": container()})
    saved = store.save(before)
    after = make_report({"container_state": container(RestartCount=4)}, report_id="report-2")
    result = compare(after, saved)
    assert result.status == "compared"
    assert result.baseline_report_id == before.id
    assert [(change.field, change.before, change.after) for change in result.changes] == [
        ("container.restart_count", "0", "4")
    ]
    assert result.changes[0].evidence_ids == ["E-CONTAINER-STATE"]
    assert result.restore_capable is False
    assert "合成样本" in "".join(result.missing)
    assert before.comparison.status == after.comparison.status == "no_baseline"
    assert store.latest("replay", "web-1", "web_502") == saved


def test_missing_current_or_baseline_fields_are_not_compared_as_zero(tmp_path):
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    base = store.save(make_report({"container_state": container()}))
    current = make_report({"container_state": container(MemoryLimit=None)}, report_id="new")
    result = compare(current, base)
    assert result.status == "incomplete"
    assert not any(change.field == "container.memory_limit_bytes" for change in result.changes)
    assert any("memory_limit_bytes" in item for item in result.missing)
    base = base.model_copy(update={"features": {"container.status": "running"}})
    result = compare(make_report({"container_state": container()}), base)
    assert result.status == "incomplete"
    assert any("基线未保存字段" in item for item in result.missing)


def test_scope_changes_stop_comparison_and_foreign_baselines_rejected(tmp_path):
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    baseline = store.save(make_report({"nginx_status": "active\n"}))
    current = make_report({"nginx_status": "active\n"}, scope_hash="f" * 64)
    assert compare(current, baseline).status == "scope_changed"
    assert not compare(current, baseline).changes
    for update in ({"source": "ssh"}, {"host_id": "different"}, {"scenario": "disk"}):
        with pytest.raises(ValueError):
            compare(current.model_copy(update=update), baseline)
    assert compare(current, None).status == "no_baseline"


def test_sql_identifiers_remain_parameters_and_list_is_limited(tmp_path):
    store = BaselineStore(tmp_path / "baseline.sqlite3")
    for index in range(102):
        store.save(make_report({"nginx_status": "active\n"}, report_id=f"report-{index}"))
    special = make_report({"nginx_status": "active\n"}, report_id="');DROP TABLE baselines;--")
    saved = store.save(special)
    assert store.latest("replay", "web-1", "web_502") == saved
    assert store.latest("replay", "' OR 1=1 --", "web_502") is None
    assert len(store.list()) == 100
