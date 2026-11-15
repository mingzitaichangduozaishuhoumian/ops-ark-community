import asyncio
import copy
import json

import httpx
import pytest

from opsark import ai_provider as provider
from opsark import security_ai
from opsark.config import Settings

EVIDENCE = "a" * 64
OTHER = "b" * 64
EVENT_REF = "event-1"


def alert():
    return {
        "id": "private-alert-id",
        "host_id": "private-machine",
        "scope_hash": "c" * 64,
        "channel": "web",
        "site_id": "private.example",
        "kind": "web_scan",
        "severity": "warning",
        "origin": "controlled_web_probe",
        "source_ip": "192.0.2.99",
        "source_trust": "forwarded_ignored",
        "title": "private-title",
        "detail": "https://private.example/a",
        "unique_event_count": 5,
        "current_window_count": 5,
        "first_seen": "2026-10-28T04:00:00+00:00",
        "last_seen": "2026-10-28T04:02:00+00:00",
        "event_ids": [EVIDENCE],
        "events": [
            {
                "id": EVIDENCE,
                "host_id": "private-machine",
                "scope_hash": "c" * 64,
                "kind": "web_request",
                "occurred_at": "2026-10-28T04:01:00Z",
                "origin": "controlled_web_probe",
                "site_id": "private.example",
                "source_ip": "192.0.2.99",
                "peer_ip": "192.0.2.99",
                "source_trust": "forwarded_ignored",
                "method": "GET",
                "status": 404,
                "path_class": "secret_probe",
                "client_class": "declared_crawler",
                "request_time_ms": 10,
                "bytes_sent": 12,
                "expected_error": False,
                "journal_cursor": "s=raw-journal-secret",
                "request_id": "not-required-private-id",
                "query": "search=private-query-value",
                "raw_uri": "/private-user/path",
                "user_agent": "private-agent",
                "username": "private-person",
            }
        ],
        "observation": {
            "status": "degraded",
            "gaps": ["private-gap https://private.example/"],
            "collected_at": "2026-10-28T04:02:00Z",
            "window_started_at": "2026-10-28T03:47:00Z",
            "window_ended_at": "2026-10-28T04:02:00Z",
        },
    }


def settings(tmp_path):
    return Settings(
        data_dir=tmp_path,
        token="test-placeholder-" * 3,
        ai_base_url="https://provider.example/v1",
        ai_key="private-provider-key",
        ai_model="chosen-model",
    )


def output(**changes):
    return {
        "summary": "实验显示多类探测线索，仍需管理员复核。",
        "uncertainty": ["仅有有限时间窗，不能确认成功利用或DDoS。"],
        "evidence_ids": [EVENT_REF],
        "recommendations": [
            {
                "kind": "collect_more_evidence",
                "rationale": "核对授权来源和窗口覆盖。",
                "evidence_ids": [EVENT_REF],
            }
        ],
        "actions_executable": False,
        **changes,
    }


def response(payload, **message_fields):
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {"content": json.dumps(payload), **message_fields},
                    "finish_reason": "stop",
                }
            ]
        },
    )


def mock(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        provider.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )


def test_input_rebuilds_only_categorical_evidence_without_identity_or_raw_text():
    original = alert()
    snapshot = copy.deepcopy(original)
    reduced = security_ai.analysis_input(original)
    encoded = json.dumps(reduced)
    for secret in (
        "private-machine",
        "private-alert-id",
        "private.example",
        "192.0.2.99",
        "raw-journal-secret",
        "private-title",
        "private-person",
        "private-query-value",
        "top-secret",
        "private-cookie",
        "private-agent",
        "raw_uri",
        "Authorization",
        "Cookie",
    ):
        assert secret not in encoded
    assert reduced["target_ref"] == "target-1"
    assert reduced["events"][0]["source_ref"] == "source-1"
    assert reduced["events"][0]["site_ref"] == "site-1"
    assert reduced["events"][0]["id"] == EVENT_REF
    assert EVIDENCE not in encoded and "2026-10-28" not in encoded
    assert reduced["observation"]["coverage_gap_count"] == 1
    assert reduced["constraints"]["network_ddos_evidence_available"] is False
    assert original == snapshot


def test_safe_input_and_digest_stable_across_event_order_and_private_names():
    original = alert()
    second = copy.deepcopy(original["events"][0])
    second["id"] = OTHER
    second["occurred_at"] = "2026-10-28T04:00:59+00:00"
    original["events"].append(second)
    changed = copy.deepcopy(original)
    changed["events"].reverse()
    changed["title"] = "arbitrary prompt injection"
    changed["detail"] = "hostname=secret"
    assert security_ai.input_digest(original) == security_ai.input_digest(changed)
    changed["events"][0]["status"] = 500
    assert security_ai.input_digest(original) != security_ai.input_digest(changed)


def test_consent_digest_binds_local_alert_identity_without_sending_it():
    first = alert()
    second = copy.deepcopy(first)
    second["id"] = "other-local-alert"
    assert security_ai.analysis_input(first) == security_ai.analysis_input(second)
    assert security_ai.input_digest(first) != security_ai.input_digest(second)


def test_representative_evidence_is_not_used_as_ratio_denominator():
    value = alert()
    value.update(
        matching_event_count=12,
        observed_request_count=18,
        window_seconds=300,
        coverage_status="complete",
        metric_basis="complete_snapshot_sample",
        evidence_retained=True,
    )
    reduced = security_ai.analysis_input(value)
    assert reduced["metrics"]["retained_evidence_count"] == 1
    assert reduced["metrics"]["observed_request_count"] == 18
    assert reduced["metrics"]["matching_event_count"] == 12
    assert reduced["constraints"]["ratio_sample_available"] is True
    assert reduced["constraints"]["retained_samples_are_not_rate_denominator"] is True
    value["coverage_status"] = "degraded"
    assert security_ai.analysis_input(value)["constraints"]["ratio_sample_available"] is False


def test_malformed_aggregate_does_not_enable_ratio_analysis():
    value = alert()
    value.update(
        matching_event_count=99,
        observed_request_count=18,
        window_seconds=300,
        coverage_status="complete",
        metric_basis="complete_snapshot_sample",
    )
    reduced = security_ai.analysis_input(value)
    assert reduced["metrics"]["matching_event_count"] is None
    assert reduced["constraints"]["ratio_sample_available"] is False


def test_unresolved_source_never_becomes_an_ai_target_ip():
    value = alert()
    value["source_ip"] = None
    value["source_trust"] = "unresolved_proxy"
    value["events"][0].update(source_ip=None, source_trust="unresolved_proxy")
    reduced = security_ai.analysis_input(value)
    assert reduced["source_ref"] is None
    assert reduced["events"][0]["source_ref"] is None
    assert reduced["events"][0]["peer_ref"] == "source-1"
    assert reduced["events"][0]["source_trust"] == "unresolved_proxy"


def test_unknown_strings_and_invalid_dates_do_not_enter_provider_input():
    value = alert()
    value.update(kind="raw-secret-kind", origin="raw-secret-origin", first_seen="raw-secret-date")
    value["events"][0].update(
        method="raw-secret-method", path_class="raw-secret-path", occurred_at="raw-secret-time"
    )
    reduced = security_ai.analysis_input(value)
    assert "raw-secret" not in json.dumps(reduced)
    assert reduced["kind"] == "unknown" and reduced["evidence_span_seconds"] is None


def test_configured_provider_receives_only_safe_summary_and_no_tools(tmp_path, monkeypatch):
    def handler(request):
        body = json.loads(request.content)
        assert request.url.path == "/v1/chat/completions"
        assert body["model"] == "chosen-model"
        assert body["response_format"] == {"type": "json_object"}
        assert "tools" not in body and "tool_choice" not in body
        assert "192.0.2.99" not in json.dumps(body)
        assert "private.example" not in json.dumps(body)
        assert EVIDENCE not in json.dumps(body)
        assert json.loads(body["messages"][1]["content"])["events"][0]["id"] == EVENT_REF
        return response(output())

    mock(monkeypatch, handler)
    source = alert()
    before = copy.deepcopy(source)
    result = security_ai.analyze_alert(source, settings(tmp_path))
    assert result["status"] == "completed"
    assert result["actions_executable"] is False
    assert result["input_digest"] == security_ai.input_digest(source)
    assert result["evidence_ids"] == [EVIDENCE]
    assert result["recommendations"][0]["evidence_ids"] == [EVIDENCE]
    assert source == before


@pytest.mark.parametrize(
    "event_field",
    [{"Authorization": "Bearer raw-credential"}, {"detail": "CREATE TABLE people(id int)"}],
)
def test_security_sensitive_source_is_blocked_before_network(tmp_path, monkeypatch, event_field):
    source = alert()
    source["events"][0].update(event_field)

    def forbidden(**_kwargs):
        pytest.fail("Unsafe source must be blocked before network setup")

    monkeypatch.setattr(provider.httpx, "AsyncClient", forbidden)
    assert security_ai.analyze_alert(source, settings(tmp_path))["status"] == "failed"


@pytest.mark.parametrize(
    ("part", "fields"),
    [
        ("alert", {"severity": "malformed"}),
        ("alert", {"origin": []}),
        ("alert", {"unique_event_count": True}),
        ("alert", {"current_window_count": -1}),
        ("alert", {"window_seconds": "300"}),
        ("alert", {"matching_event_count": 12, "observed_request_count": 10}),
        ("observation", {"status": "partial"}),
        ("event", {"method": "custom method"}),
        ("event", {"method": "password"}),
        ("event", {"path_class": "custom path"}),
        ("event", {"request_time_ms": "10"}),
        ("event", {"status": 99}),
        ("event", {"expected_error": 0}),
        ("event", {"id": "not-a-local-event-id"}),
    ],
)
def test_security_malformed_projected_source_is_blocked_before_network(
    tmp_path, monkeypatch, part, fields
):
    source = alert()
    {"alert": source, "observation": source["observation"], "event": source["events"][0]}[
        part
    ].update(fields)

    def forbidden(**_kwargs):
        pytest.fail("Malformed source must be blocked before network setup")

    monkeypatch.setattr(provider.httpx, "AsyncClient", forbidden)
    assert security_ai.analyze_alert(source, settings(tmp_path))["status"] == "failed"


@pytest.mark.parametrize("method", ["OTHER", "unknown"])
def test_security_accepts_http_other_optional_unknown_and_absent_values(
    tmp_path, monkeypatch, method
):
    source = alert()
    source.pop("origin")
    source["severity"] = None
    source["events"][0].update(method=method, source_trust="unknown", bytes_sent=2**63 - 1)
    source["events"][0].pop("expected_error")

    def handler(request):
        projection = json.loads(json.loads(request.content)["messages"][1]["content"])
        event = projection["events"][0]
        assert event["method"] == method
        assert event["source_trust"] == "unknown"
        assert event["bytes_sent"] is None
        assert event["expected_error"] is False
        return response(output())

    mock(monkeypatch, handler)
    assert security_ai.analyze_alert(source, settings(tmp_path))["status"] == "completed"


@pytest.mark.parametrize(
    "change",
    [
        {"actions_executable": True},
        {"actions_executable": 0},
        {"command": "sudo arbitrary"},
        {"evidence_ids": ["event-2"]},
        {"evidence_ids": [EVIDENCE]},
        {
            "recommendations": [
                {"kind": "run_shell", "rationale": "unsafe", "evidence_ids": [EVENT_REF]}
            ]
        },
        {
            "recommendations": [
                {"kind": "propose_rate_limit", "rationale": "unsupported", "evidence_ids": []}
            ]
        },
        {
            "recommendations": [
                {"kind": "review_access", "rationale": "invented ref", "evidence_ids": ["event-2"]}
            ]
        },
    ],
)
def test_authority_unknown_actions_and_invented_evidence_fail_closed(tmp_path, monkeypatch, change):
    mock(monkeypatch, lambda request: response(output(**change)))
    assert security_ai.analyze_alert(alert(), settings(tmp_path))["status"] == "failed"


def test_unsolicited_tool_calls_are_rejected_even_if_content_is_valid(tmp_path, monkeypatch):
    mock(
        monkeypatch,
        lambda request: response(
            output(),
            tool_calls=[{"type": "function", "function": {"name": "shell", "arguments": "{}"}}],
        ),
    )
    assert security_ai.analyze_alert(alert(), settings(tmp_path))["status"] == "failed"


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx.Response(401, text="private-provider-error"),
        lambda request: httpx.Response(200, content=b"x" * (security_ai.MAX_RESPONSE_BYTES + 1)),
        lambda request: httpx.Response(302, headers={"Location": "https://other.example"}),
        lambda request: httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": json.dumps(output())}, "finish_reason": "length"}
                ]
            },
        ),
    ],
)
def test_provider_failures_do_not_echo_provider_text(tmp_path, monkeypatch, handler):
    mock(monkeypatch, handler)
    result = security_ai.analyze_alert(alert(), settings(tmp_path))
    assert result["status"] == "failed" and "private-provider-error" not in str(result)
    assert result["actions_executable"] is False


def test_missing_credentials_never_create_network_client(tmp_path, monkeypatch):
    def forbidden(**kwargs):
        raise AssertionError("No configured model may receive data")

    monkeypatch.setattr(provider.httpx, "AsyncClient", forbidden)
    result = security_ai.analyze_alert(alert(), Settings(data_dir=tmp_path, token="unused"))
    assert result["status"] == "disabled" and not result["recommendations"]


def test_total_budget_cancels_slow_provider_before_any_response_headers(tmp_path, monkeypatch):
    cancelled = []

    async def slow(request):
        try:
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return response(output())

    monkeypatch.setattr(security_ai, "MAX_SECONDS", 0.02)
    mock(monkeypatch, slow)
    result = security_ai.analyze_alert(alert(), settings(tmp_path))
    assert result["status"] == "failed" and result["actions_executable"] is False
    assert cancelled == [True]
