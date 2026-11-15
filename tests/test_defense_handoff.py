"""Pure customer projection: no host, key, database, collector or network."""

import pytest
from pydantic import ValidationError

from opsark.defense_handoff import (
    DefenseHandoffProjection,
    HandoffCheck,
    defense_handoff_markdown,
    merge_business,
    merge_verdict,
)

NOW = "2026-11-06T01:00:00Z"


def checks(*states):
    return tuple(
        HandoffCheck(
            number=i, status=status, reason_code="matched" if status == "passed" else "incomplete"
        )
        for i, status in enumerate(states, 1)
    )


@pytest.mark.parametrize(
    "states,complete,verdict",
    [
        (("passed", "passed"), True, "passed"),
        (("passed", "inconclusive"), True, "pending"),
        (("passed", "uncovered"), True, "pending"),
        (("passed", "failed", "inconclusive"), True, "failed"),
        (("passed",), False, "pending"),
        (("failed",), False, "failed"),
        ((), True, "pending"),
    ],
)
def test_failure_has_priority_and_incomplete_evidence_never_passes(states, complete, verdict):
    assert merge_verdict(checks(*states), bindings_complete=complete) == verdict


def test_expired_is_root_state_and_never_a_business_result():
    projection = DefenseHandoffProjection(
        original_authority_kind="preauthorization",
        original_authority_at=NOW,
        execution_status="confirmed",
        execution_submitted_at=NOW,
        execution_confirmed_at=NOW,
        reconciliation_status="not_needed",
        historical_verdict="passed",
        current_verdict="passed",
        business_verdict="passed",
        authority_kind="preauthorization",
        root_before="active",
        root_after="expired",
        current_root="expired",
        transition="ttl_elapsed",
        started_at=NOW,
        finished_at=NOW,
        root_observed_at=NOW,
        current_root_observed_at=NOW,
        checks=checks("passed", "passed"),
    )
    rendered = defense_handoff_markdown(projection)
    assert "已到期，不代表仍在阻断" in rendered
    assert "到期本身不证明业务通过或失败" in rendered
    assert "登记业务复验通过" in rendered and "2 / 2" in rendered
    assert merge_business(()) == "pending"


def test_new_unknown_does_not_rewrite_historical_passed():
    projection = DefenseHandoffProjection(
        historical_verdict="passed",
        current_verdict="pending",
        business_verdict="passed",
        authority_kind="human_approval",
        root_before="active",
        root_after="active",
        current_root="unknown",
        transition="unchanged",
        started_at=NOW,
        finished_at=NOW,
        root_observed_at=NOW,
        checks=checks("passed"),
        reasons=("current_unknown",),
    )
    rendered = defense_handoff_markdown(projection)
    assert "当前验收：待验收" in rendered
    assert "所选历史复验：登记业务复验通过" in rendered
    assert "原任务结果未知" in rendered


@pytest.mark.parametrize(
    "private",
    [
        "hostname",
        "address",
        "url",
        "check_id",
        "raw_log",
        "key_file",
        "grant_ref",
        "manifest_sha256",
    ],
)
def test_customer_projection_forbids_free_form_private_fields(private):
    with pytest.raises(ValidationError):
        DefenseHandoffProjection.model_validate({private: "secret-canary"})


@pytest.mark.parametrize(
    "change",
    [
        {"current_verdict": "passed"},
        {"historical_verdict": "passed"},
        {"checks": [HandoffCheck(number=2, status="passed", reason_code="matched")]},
    ],
)
def test_invalid_green_or_unclosed_check_numbering_is_rejected(change):
    with pytest.raises(ValidationError):
        DefenseHandoffProjection.model_validate(change)


def test_default_export_is_pending_and_has_only_fixed_text():
    rendered = defense_handoff_markdown(DefenseHandoffProjection())
    assert "待验收" in rendered and "0 / 0" in rendered
    assert "http" not in rendered and "grant" not in rendered and "run_ref" not in rendered


def test_server_task_digest_is_a_bounded_reference_not_free_text():
    projection = DefenseHandoffProjection(task_reference_sha256="a" * 64)
    assert "服务端任务引用摘要：" + "a" * 64 in defense_handoff_markdown(projection)
    with pytest.raises(ValidationError):
        DefenseHandoffProjection(task_reference_sha256="https://private-canary.invalid/task")


@pytest.mark.parametrize(
    "fields",
    [
        {"original_authority_kind": "human_approval"},
        {"execution_status": "confirmed"},
        {"receipt_status": "unconfirmed"},
        {"reconciliation_status": "reconciled", "reconciled_at": NOW},
    ],
)
def test_timeline_labels_cannot_claim_closed_events_without_dates(fields):
    with pytest.raises(ValidationError):
        DefenseHandoffProjection.model_validate(fields)
