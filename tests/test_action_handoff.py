"""Customer projections and Markdown admit only closed action facts."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from opsark.action_handoff import ActionTimeline, BusinessSnapshot, action_handoff_markdown
from opsark.models import Finding, Report
from opsark.report_handoff import handoff_markdown

START = datetime(2026, 11, 13, 1, 30, tzinfo=UTC)
APPROVED = START + timedelta(minutes=1)
OBSERVED = APPROVED + timedelta(minutes=1)
CHECK = OBSERVED + timedelta(minutes=1)
CANARY = "synthetic-sensitive-customer-marker"


def timeline(**changes):
    return ActionTimeline(
        **(
            {
                "kind": "container_restart",
                "investigated_at": START,
                "approved_at": APPROVED,
                "receipt_observed_at": OBSERVED,
                "operation_status": "verified",
            }
            | changes
        )
    )


def snapshot(**changes):
    return BusinessSnapshot(
        **(
            {
                "selection": "current",
                "started_at": CHECK,
                "finished_at": CHECK + timedelta(seconds=1),
                "configured_checks": 3,
                "passed_checks": 2,
                "failed_checks": 0,
            }
            | changes
        )
    )


@pytest.mark.parametrize(
    ("kind", "label"),
    [
        ("container_restart", "容器重启"),
        ("nginx_apply", "Nginx 配置变更"),
        ("nginx_restore", "Nginx 配置回退"),
    ],
)
def test_operational_verification_does_not_approve_business(kind, label):
    rendered = action_handoff_markdown(timeline(kind=kind))
    assert f"已人工批准{label}" in rendered
    assert "**原动作已核实。**" in rendered and "**待验收。**" in rendered
    assert "登记业务复验通过" not in rendered


@pytest.mark.parametrize(
    ("passed", "failed", "label"),
    [(1, 1, "复验未通过"), (2, 0, "待验收"), (3, 0, "登记业务复验通过")],
)
def test_business_counts_derive_verdict_and_failure_has_priority(passed, failed, label):
    business = snapshot(passed_checks=passed, failed_checks=failed)
    rendered = action_handoff_markdown(timeline(business=business))
    assert f"**{label}。**" in rendered
    assert f"{passed} / 3 项登记检查符合条件" in rendered
    assert "完整业务恢复" not in rendered


def test_historical_business_is_explicit_and_uses_its_own_times():
    business = snapshot(
        selection="historical",
        passed_checks=3,
        started_at=CHECK.astimezone(timezone(timedelta(hours=8))),
    )
    rendered = action_handoff_markdown(
        timeline(operation_status="unknown", reconciliation_status="verified", business=business)
    )
    assert "已对账，原动作已核实" in rendered
    assert "以下为所选历史复验。当前业务状态需另行核对。" in rendered
    assert "**登记业务复验通过。**" in rendered
    assert "2026-11-13T01:33:01+00:00" in rendered and "+08:00" not in rendered


@pytest.mark.parametrize(
    ("operation", "reconciliation", "label"),
    [
        ("unknown", None, "原动作结果未知，待对账"),
        ("unknown", "disk_published_live_previous", "服务仍使用原配置"),
        ("unknown", "unchanged_from_preview", "原动作结果仍未知"),
        ("not_started", None, "已核实原动作未开始"),
        ("refused", None, "原动作被拒绝"),
    ],
)
def test_unverified_operations_keep_pending_and_reject_business(operation, reconciliation, label):
    values = {
        "kind": "nginx_apply",
        "operation_status": operation,
        "reconciliation_status": reconciliation,
    }
    rendered = action_handoff_markdown(timeline(**values))
    assert label in rendered and "**待验收。**" in rendered
    with pytest.raises(ValidationError, match="核实后"):
        timeline(**values, business=snapshot(passed_checks=3))


@pytest.mark.parametrize(
    "changes",
    [
        {"investigated_at": APPROVED + timedelta(seconds=1)},
        {"approved_at": START.replace(tzinfo=None)},
        {"receipt_observed_at": None},
        {"receipt_observed_at": START},
        {"reconciliation_status": "verified"},
        {"operation_status": "unknown", "reconciliation_status": "disk_published_live_previous"},
        {"operation_status": "unknown", "reconciliation_status": "unchanged_from_preview"},
        {"business": snapshot(started_at=OBSERVED)},
    ],
)
def test_invalid_order_or_incompatible_action_status_fails_closed(changes):
    with pytest.raises(ValidationError):
        timeline(**changes)


def test_ambiguous_submit_may_have_no_observed_time():
    rendered = action_handoff_markdown(
        timeline(operation_status="unknown", receipt_observed_at=None)
    )
    assert "原动作结果未知，待对账" in rendered and "已读取原动作回执" not in rendered


@pytest.mark.parametrize(
    "field",
    ["report_id", "plan_id", "approval_id", "receipt_digest", "config", "log", "path", "text"],
)
def test_customer_projection_rejects_sensitive_canary_fields(field):
    with pytest.raises(ValidationError, match="extra_forbidden"):
        timeline(**{field: CANARY})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        snapshot(**{field: CANARY})


def test_free_text_or_unvalidated_typed_updates_cannot_reach_markdown():
    with pytest.raises(ValidationError):
        timeline(kind=CANARY)
    with pytest.raises(ValidationError):
        timeline(operation_status=CANARY)
    with pytest.raises(ValidationError):
        snapshot(passed_checks=True)
    with pytest.raises(ValidationError):
        snapshot(passed_checks=3, failed_checks=1)
    with pytest.raises(ValidationError):
        snapshot(finished_at=OBSERVED)
    with pytest.raises(TypeError):
        action_handoff_markdown({"kind": CANARY})
    with pytest.raises(ValidationError):
        action_handoff_markdown(timeline().model_copy(update={"operation_status": CANARY}))


def test_original_report_renderer_still_projects_only_existing_classification():
    report = Report(
        id=CANARY,
        host_id="synthetic-host",
        host_name=CANARY,
        scenario="container_restart",
        source="replay",
        created_at=START,
        status="needs_attention",
        title=CANARY,
        summary=CANARY,
        facts=[Finding(text=CANARY, evidence_ids=[])],
        candidates=[],
        missing=[],
        evidence=[],
        next_steps=[],
    )
    rendered = handoff_markdown(report)
    assert "回放样本为合成数据" in rendered and "**待验收。**" in rendered
    assert "## 处置时间线" not in rendered and CANARY not in rendered
