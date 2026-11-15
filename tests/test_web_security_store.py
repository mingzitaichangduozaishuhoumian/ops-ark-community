"""Web rules use trustworthy, distinct reduced evidence, never request volume alone."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from opsark.web_security_models import WebSecurityEvent, WebSecurityObservation
from opsark.web_security_store import WebSecurityStore

NOW = datetime(2026, 10, 28, 7, tzinfo=UTC)
SCOPE = "a" * 64
PROFILE = "b" * 64
CLASSES = ("secret_probe", "repo_probe", "cms_probe", "admin_probe", "traversal_probe")


def event(
    index,
    *,
    when=None,
    scope=SCOPE,
    host="lab",
    site="web",
    origin="system_web",
    source="192.0.2.10",
    peer=None,
    trust="direct_peer",
    path="normal",
    status=200,
    client="browser",
    duration=20,
    expected=False,
):
    cursor = f"s=web;i={index}"
    return WebSecurityEvent(
        id=hashlib.sha256((scope + "\n" + cursor).encode()).hexdigest(),
        host_id=host,
        scope_hash=scope,
        occurred_at=when or NOW - timedelta(seconds=60) + timedelta(milliseconds=index),
        origin=origin,
        site_id=site,
        source_ip=source,
        peer_ip=peer or source or "192.0.2.200",
        source_trust=trust,
        method="POST" if path == "callback" else "GET",
        status=status,
        path_class=path,
        client_class=client,
        request_time_ms=duration,
        bytes_sent=10,
        journal_cursor=cursor,
        request_id=f"{index:032x}",
        expected_error=expected,
    )


def scans(start=0, **changes):
    return [
        event(start + index, path=CLASSES[index % len(CLASSES)], status=404, **changes)
        for index in range(5)
    ]


def observation(
    values=(),
    *,
    identifier="batch-1",
    when=NOW,
    status="complete",
    gaps=None,
    scope=SCOPE,
    profile=PROFILE,
    host="lab",
):
    return WebSecurityObservation(
        id=identifier,
        host_id=host,
        scope_hash=scope,
        profile_digest=profile,
        collected_at=when,
        window_started_at=when - timedelta(minutes=15),
        window_ended_at=when,
        status=status,
        events=list(values),
        gaps=gaps or [],
        raw_records_seen=len(values),
    )


def test_unique_sensitive_events_and_categories_survive_overlap_and_restart(tmp_path):
    path = tmp_path / "web.sqlite3"
    store = WebSecurityStore(path)
    values = scans()
    assert store.ingest(observation(values[:4]))["new_alerts"] == 0
    assert store.ingest(observation(values[:4], identifier="overlap"))["inserted_events"] == 0
    reopened = WebSecurityStore(path)
    result = reopened.ingest(observation(values, identifier="fifth"))
    assert result["inserted_events"] == 1 and result["new_alerts"] == 1
    alert = reopened.list_alerts()[0]
    assert alert["kind"] == "web_scan" and alert["channel"] == "web"
    assert alert["unique_event_count"] == 5 and alert["notification_count"] == 1
    assert reopened.ingest(observation(values, identifier="again"))["updated_alerts"] == 0
    assert reopened.list_alerts()[0] == alert


def test_one_sensitive_category_and_normal_high_volume_are_not_scan(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, path="secret_probe", status=404) for i in range(20)]
    store.ingest(observation(values))
    assert not store.list_alerts()
    store.ingest(
        observation(
            [event(100 + i, when=NOW, client="declared_crawler") for i in range(40)],
            identifier="crawler",
        )
    )
    assert not store.list_alerts()


def test_declared_crawler_is_not_an_authorization_bypass(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation(scans(client="declared_crawler")))
    assert store.list_alerts()[0]["kind"] == "web_scan"
    assert "不能据此确认入侵或数据泄露" in store.list_alerts()[0]["detail"]


def test_shared_exit_and_legitimate_callback_traffic_do_not_alert_by_volume(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, path="callback", status=204, when=NOW) for i in range(40)]
    values += [
        event(100 + i, path="robots", when=NOW, client="declared_crawler") for i in range(20)
    ]
    store.ingest(observation(values))
    assert store.list_alerts() == []


def test_site_ip_origin_and_scope_are_independent_scan_groups(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [
        event(i, path=CLASSES[i % 5], status=404, source=f"192.0.2.{i + 1}") for i in range(6)
    ]
    values += scans(10, site="other")[:4] + scans(20, origin="controlled_web_probe")[:4]
    store.ingest(observation(values))
    assert not store.list_alerts()
    store.ingest(observation(scans(30, scope="c" * 64), identifier="scope", scope="c" * 64))
    assert len(store.list_alerts()) == 1 and store.list_alerts()[0]["scope_hash"] == "c" * 64
    assert store.list_alerts()[0]["kind"] == "web_scan"


def test_forwarded_header_ignored_uses_real_peer_for_attribution(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = scans(trust="forwarded_ignored", source="192.0.2.15")
    store.ingest(observation(values))
    alert = store.list_alerts()[0]
    assert alert["source_ip"] == "192.0.2.15" and alert["source_trust"] == "forwarded_ignored"
    forged = event(
        20,
        source="198.51.100.88",
        peer="192.0.2.15",
        trust="forwarded_ignored",
        path="secret_probe",
    )
    result = store.ingest(observation([forged], identifier="forged"))
    assert result["observation_status"] == "degraded" and result["inserted_events"] == 0
    assert not any(a["source_ip"] == "198.51.100.88" for a in store.list_alerts())


def test_unresolved_proxy_never_becomes_attack_source(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation(scans(source=None, trust="unresolved_proxy", peer="192.0.2.200")))
    alert = store.list_alerts()[0]
    assert alert["source_ip"] is None and alert["source_trust"] == "unresolved_proxy"
    assert "不能封禁网关" in alert["detail"]
    assert all(e["peer_ip"] == "192.0.2.200" for e in store.get_alert(alert["id"])["events"])


def test_trusted_proxy_attribution_keeps_verified_source_and_peer(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(
        observation(scans(source="198.51.100.10", peer="192.0.2.200", trust="trusted_proxy"))
    )
    alert = store.list_alerts()[0]
    assert alert["source_ip"] == "198.51.100.10" and alert["source_trust"] == "trusted_proxy"


def test_error_burst_uses_ratio_sample_minimum_and_site_aggregation(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, status=502, source=f"192.0.2.{i + 1}") for i in range(5)]
    store.ingest(observation(values))
    assert not store.list_alerts()
    values += [event(10 + i) for i in range(5)]
    store.ingest(observation(values, identifier="ten"))
    alert = store.list_alerts()[0]
    assert alert["kind"] == "web_error_burst" and alert["source_ip"] is None
    assert alert["source_trust"] == "site_aggregate"
    assert alert["matching_event_count"] == 5 and alert["observed_request_count"] == 10
    assert "不证明请求来源在攻击" in alert["detail"]
    detail = store.get_alert(alert["id"])
    assert len(detail["events"]) == 10 and detail["evidence_retained"]


@pytest.mark.parametrize(
    "case", ["expected_maintenance", "below_ratio", "old_window", "health_checks", "client_errors"]
)
def test_response_negative_controls_do_not_make_error_burst(tmp_path, case):
    store = WebSecurityStore(tmp_path / "web.db")
    changes = (
        {"status": 503, "expected": True}
        if case == "expected_maintenance"
        else {"status": 404}
        if case == "client_errors"
        else {"status": 502}
    )
    if case == "health_checks":
        changes["path"] = "health"
    if case == "old_window":
        changes["when"] = NOW - timedelta(minutes=6)
    values = [event(i, **changes) for i in range(5)]
    values += [event(20 + i, when=NOW) for i in range(6 if case == "below_ratio" else 5)]
    store.ingest(observation(values))
    assert not store.list_alerts()


def test_slow_cluster_requires_ten_samples_and_half_slow(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, duration=2500) for i in range(5)]
    store.ingest(observation(values))
    assert not store.list_alerts()
    store.ingest(observation([*values, *[event(10 + i) for i in range(5)]], identifier="slow"))
    alert = store.list_alerts()[0]
    assert alert["kind"] == "web_request_anomaly" and alert["source_ip"] is None
    assert "不能仅按请求量或 IP 判定攻击" in alert["detail"]


def test_probe_origin_is_clear_and_not_mixed_with_real_traffic(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation(scans(origin="controlled_web_probe")))
    alert = store.list_alerts()[0]
    assert alert["origin"] == "controlled_web_probe" and alert["title"].startswith("受控实验")
    assert "不是实际攻击认定" in alert["detail"]


def test_retained_scan_evidence_preserves_three_supporting_categories(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = scans()
    values += [event(10 + i, path="secret_probe", status=404, when=NOW) for i in range(40)]
    store.ingest(observation(values))
    alert = store.get_alert(store.list_alerts()[0]["id"])
    assert len(alert["events"]) == 20 and len({e["path_class"] for e in alert["events"]}) >= 3
    store.ingest(observation(identifier="later", when=NOW + timedelta(days=2)))
    assert len(store.get_alert(alert["id"])["events"]) == 20


def test_cursor_conflict_and_invalid_identity_fail_closed(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    original = event(1)
    store.ingest(observation([original]))
    for number, changed in enumerate(
        (
            original.model_copy(update={"status": 503}),
            original.model_copy(update={"id": "f" * 64}),
            original.model_copy(update={"host_id": "other"}),
        )
    ):
        result = store.ingest(observation([changed], identifier=f"conflict-{number}"))
        assert result["inserted_events"] == 0 and result["observation_status"] == "degraded"
    assert all(a["kind"] == "observation_gap" for a in store.list_alerts())


def test_profile_digest_cannot_change_without_changing_scope(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation())
    result = store.ingest(observation(scans(), identifier="changed", profile="c" * 64))
    assert result["observation_status"] == "degraded" and result["inserted_events"] == 0
    assert all(a["kind"] == "observation_gap" for a in store.list_alerts())


def test_observation_identifier_is_immutable_and_duplicates_are_idempotent(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    original = observation(scans())
    store.ingest(original)
    assert store.ingest(original)["inserted_events"] == 0
    with pytest.raises(ValueError, match="replace"):
        store.ingest(original.model_copy(update={"duration_ms": 5}))


def test_ack_and_cooldown_require_fresh_matching_evidence_to_notify(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = scans()
    store.ingest(observation(values))
    identifier = store.list_alerts()[0]["id"]
    assert store.acknowledge(identifier)["status"] == "acknowledged"
    later = NOW + timedelta(seconds=601)
    store.ingest(observation(values, identifier="quiet", when=later))
    assert store.list_alerts()[0]["notification_count"] == 1
    new = scans(100, when=later)
    store.ingest(observation([*values, *new], identifier="fresh", when=later))
    alert = store.list_alerts()[0]
    assert alert["notification_count"] == 2 and alert["status"] == "open"
    assert alert["unique_event_count"] == 10


def test_new_normal_samples_do_not_renotify_old_error_evidence(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, status=502) for i in range(6)] + [event(10 + i) for i in range(4)]
    store.ingest(observation(values))
    identifier = store.list_alerts()[0]["id"]
    store.acknowledge(identifier)
    # During the same error window, one fresh normal request does not represent a new error.
    store.ingest(
        observation(
            [*values, event(30, when=NOW + timedelta(seconds=1))],
            identifier="normal",
            when=NOW + timedelta(seconds=1),
        )
    )
    assert store.list_alerts()[0]["status"] == "acknowledged"
    assert store.list_alerts()[0]["notification_count"] == 1


def test_collection_failures_are_quiet_until_recovery_and_new_episode(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")

    def unavailable(identifier, when):
        return observation(
            identifier=identifier, when=when, status="unavailable", gaps=["web_reader_unavailable"]
        )

    store.ingest(unavailable("failure", NOW))
    alert = store.list_alerts()[0]
    assert alert["origin"] == "web_collector" and alert["channel"] == "web"
    assert store.ingest(unavailable("repeat", NOW + timedelta(seconds=60)))["updated_alerts"] == 0
    store.ingest(observation(identifier="recovery", when=NOW + timedelta(seconds=120)))
    store.ingest(unavailable("new_failure", NOW + timedelta(seconds=601)))
    assert store.list_alerts()[0]["notification_count"] == 2


def test_offline_gap_and_backward_clock_are_not_silent_full_coverage(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation())
    later = NOW + timedelta(minutes=16)
    result = store.ingest(observation(identifier="offline", when=later))
    assert result["observation_status"] == "degraded"
    assert (
        store.ingest(observation(identifier="next", when=later + timedelta(seconds=60)))[
            "observation_status"
        ]
        == "complete"
    )
    result = store.ingest(observation(scans(), identifier="backward", when=NOW))
    assert result["observation_status"] == "degraded" and result["inserted_events"] == 0


def test_unavailable_batch_and_invalid_proxy_metadata_cannot_count(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    result = store.ingest(observation(scans(), status="unavailable", gaps=["failed"]))
    assert result["inserted_events"] == 0 and result["observation_status"] == "unavailable"
    bad = event(100, trust="unresolved_proxy", source="192.0.2.200")
    assert store.ingest(observation([bad], identifier="invalid_proxy"))["inserted_events"] == 0


def test_strict_contract_rejects_raw_data_and_coerced_status():
    original = event(1).model_dump()
    with pytest.raises(ValidationError):
        WebSecurityEvent.model_validate({**original, "raw_uri": "/secret?token=not-to-store"})
    with pytest.raises(ValidationError):
        WebSecurityEvent.model_validate({**original, "status": True})


def test_inherited_storage_queries_and_host_state_remain_safe(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation(scans()))
    assert store.get_alert("' OR 1=1 --") is None
    assert store.get_observation("' OR 1=1 --") is None
    store.set_host_state(
        "lab", SCOPE, status="ok", last_success=NOW, next_poll=NOW + timedelta(seconds=60)
    )
    assert store.host_states()[0]["status"] == "ok"
    assert store.path.stat().st_size > 0


@pytest.mark.parametrize("mode", ["error", "slow"])
def test_partial_snapshot_keeps_absolute_evidence_but_never_uses_sample_ratio(tmp_path, mode):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [
        event(i, status=502 if mode == "error" else 200, duration=2500 if mode == "slow" else 20)
        for i in range(10)
    ]
    result = store.ingest(observation(values, status="degraded", gaps=["projection_output_limit"]))
    assert result["inserted_events"] == 10
    assert {a["kind"] for a in store.list_alerts()} == {"observation_gap"}
    assert len(store.get_observation("batch-1")["events"]) == 10
    # Once the full snapshot is available the same known records can support
    # a new ratio alert; deduplication must not discard their evidence.
    store.ingest(observation(values, identifier="complete"))
    expected = "web_error_burst" if mode == "error" else "web_request_anomaly"
    alert = next(a for a in store.list_alerts() if a["kind"] == expected)
    assert alert["metric_basis"] == "complete_snapshot_sample"
    assert alert["coverage_status"] == "complete"
    assert "不是全量流量" in alert["detail"]


def test_partial_scan_is_a_valid_lower_bound_and_labels_coverage(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    store.ingest(observation(scans(), status="degraded", gaps=["journal_record_limit"]))
    alert = next(a for a in store.list_alerts() if a["kind"] == "web_scan")
    assert alert["unique_event_count"] == 5
    assert alert["coverage_status"] == "degraded"
    assert alert["metric_basis"] == "observed_evidence"
    assert "仅是已取得证据的下界" in alert["detail"]


def test_complete_snapshot_ratio_does_not_merge_old_partial_denominator(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    old = [event(i, status=502) for i in range(10)]
    store.ingest(observation(old, status="degraded", gaps=["journal_output_limit"]))
    current = [event(20 + i) for i in range(10)]
    store.ingest(observation(current, identifier="new_complete"))
    assert not any(a["kind"] == "web_error_burst" for a in store.list_alerts())


def test_short_complete_window_cannot_stand_in_for_five_minute_ratio(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    values = [event(i, status=502) for i in range(10)]
    short = observation(values).model_copy(
        update={"window_started_at": NOW - timedelta(seconds=90)}
    )
    store.ingest(short)
    assert store.list_alerts() == []


def test_complete_fifteen_minute_snapshot_of_root_probe_case_alerts_immediately(tmp_path):
    store = WebSecurityStore(tmp_path / "web.db")
    normal = [event(i, path="health") for i in range(6)] + [event(6, path="robots")]
    forged = [event(10 + i, trust="forwarded_ignored") for i in range(5)]
    errors = [event(20 + i, status=503) for i in range(12)]
    assert store.ingest(observation(normal + forged))["new_alerts"] == 0
    # The reader's complete snapshot includes the earlier negative controls;
    # runtime need not last five minutes when its declared window covers 15.
    result = store.ingest(observation(normal + forged + errors, identifier="errors"))
    assert result["inserted_events"] == 12 and result["new_alerts"] == 1
    alert = store.list_alerts()[0]
    assert alert["kind"] == "web_error_burst"
    assert alert["observed_request_count"] == 18
    assert alert["matching_event_count"] == 12
    assert alert["coverage_status"] == "complete"
