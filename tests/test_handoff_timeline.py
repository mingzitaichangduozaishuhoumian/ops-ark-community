from datetime import UTC, datetime, timedelta, timezone

import pytest

from opsark import handoff_timeline
from opsark.activation_api import _raw_job
from opsark.automatic_store import digest
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.handoff_timeline import (
    BusinessHandoffRecheck,
    build_handoff_timeline,
    handoff_approval_digest,
)
from opsark.models import Evidence, HealthCheck, HostPublic, Report, Verification
from opsark.report_handoff import handoff_markdown
from opsark.storage import ReportStore

START = datetime(2026, 11, 4, 8, tzinfo=UTC)
MARKER = "do-not-return-customer-timeline-private-data"


def at(minutes):
    return START + timedelta(minutes=minutes)


@pytest.fixture
def episode():
    target = HostPublic(
        id="private-host-id",
        name=MARKER,
        address="192.0.2.25",
        source="ssh",
        health_checks=[
            HealthCheck(
                id="shop", domain="shop.example.com", expected_body=MARKER, read_only_confirmed=True
            )
        ],
    )
    report = Report(
        id="private-original-report",
        host_id=target.id,
        host_name=target.name,
        source="ssh",
        scenario="web_502",
        created_at=START,
        status="needs_attention",
        title=MARKER,
        summary=MARKER,
        facts=[],
        candidates=[],
        missing=[],
        evidence=[],
        next_steps=[],
        scope_hash=scope_for(target),
        target=target,
    )
    audit = {
        "host_id": target.id,
        "host_scope": report.scope_hash,
        "job_id": "1" * 32,
        "plan_id": "2" * 32,
        "plan_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "mode_revision": 7,
        "authorization": "assisted",
        "approved_at": at(1).isoformat(),
    }
    job = {
        **{
            key: audit[key]
            for key in (
                "host_id",
                "job_id",
                "plan_id",
                "plan_digest",
                "mode_revision",
                "authorization",
            )
        },
        "execution_policy_digest": audit["policy_digest"],
        "schema_version": 1,
        "install_exit_code": 0,
        "status": "verified",
        "revision": 8,
        "created_at": at(2).isoformat(),
        "updated_at": at(4).isoformat(),
        "detail": MARKER,
        "installed_version": MARKER,
    }
    evidence = Evidence(
        id="E-HTTP-SHOP",
        check_id="http_shop",
        target=target.id,
        source="ssh",
        collected_at=at(8),
        status="ok",
        output=MARKER,
        exit_code=0,
    )
    verification = Verification(
        name="站点即时检查：shop（shop.example.com）",
        status="passed",
        detail=MARKER,
        evidence_ids=[evidence.id],
        http_status=200,
        status_matches=True,
        body_matches=True,
    )
    recheck = report.model_copy(
        update={
            "id": "private-recheck",
            "created_at": at(9),
            "verification": [verification],
            "evidence": [evidence],
        }
    )
    return report, job, audit, recheck


def test_verified_patch_and_registered_recheck_are_safe_to_share(episode):
    report, job, audit, recheck = episode
    timeline = build_handoff_timeline(report, job, audit, recheck)
    assert timeline.native_accepted is True
    assert timeline.authorization == "assisted"
    assert timeline.recheck_status == "passed"
    assert (timeline.matched_checks, timeline.configured_checks) == (1, 1)
    assert [event.kind for event in timeline.events] == [
        "investigation",
        "approval",
        "native_record",
        "recheck",
    ]
    rendered = handoff_markdown(report, timeline)
    assert "登记业务复验通过" in rendered
    assert "完整业务恢复和持续观察需另行验收" in rendered
    assert "待验收" in handoff_markdown(report)
    for private in (
        MARKER,
        report.host_id,
        report.id,
        recheck.id,
        audit["job_id"],
        audit["plan_id"],
        audit["plan_digest"],
        "shop.example.com",
        "192.0.2.25",
    ):
        assert private not in rendered
        assert private not in timeline.model_dump_json()


def test_disk_diagnostic_changes_preserve_original_task_and_recheck_selection(episode, tmp_path):
    report, job, audit, recheck = episode
    assert report.target is not None
    original_target = report.target.model_copy(update={"disk_reclaim_scope_digest": "a" * 64})
    current_target = original_target.model_copy(update={"disk_reclaim_scope_digest": "b" * 64})
    original = report.model_copy(
        update={"target": original_target, "scope_hash": diagnostic_scope_for(original_target)}
    )
    current = recheck.model_copy(
        update={"target": current_target, "scope_hash": diagnostic_scope_for(current_target)}
    )
    assert current.scope_hash != original.scope_hash
    assert scope_for(current_target) == audit["host_scope"]
    assert build_handoff_timeline(original, job, audit, current).recheck_status == "passed"

    store = ReportStore(tmp_path / "reports.sqlite3")
    store.save(original)
    store.save(current)
    other_target = current_target.model_copy(update={"address": "192.0.2.40"})
    store.save(
        current.model_copy(
            update={
                "id": "other-transport-recheck",
                "target": other_target,
                "scope_hash": diagnostic_scope_for(other_target),
            }
        )
    )
    assert store.handoff_rechecks(original, host_scope=audit["host_scope"]) == [
        {"id": current.id, "at": current.created_at.isoformat()}
    ]
    with pytest.raises(ValueError):
        build_handoff_timeline(
            original, job, audit, current.model_copy(update={"scope_hash": audit["host_scope"]})
        )

    # The legacy audit can still be recomputed from its exact original disk registration.
    legacy = audit | {"host_scope": original.scope_hash}
    old_recheck = recheck.model_copy(
        update={"target": original_target, "scope_hash": original.scope_hash}
    )
    assert build_handoff_timeline(original, job, legacy, old_recheck).recheck_status == "passed"
    with pytest.raises(ValueError):
        build_handoff_timeline(original, job, legacy, current)


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("host_id", "another-host"),
        ("job_id", "a" * 32),
        ("plan_id", "b" * 32),
        ("plan_digest", "c" * 64),
        ("policy_digest", "d" * 64),
        ("host_scope", "e" * 64),
        ("mode_revision", True),
        ("authorization", "automatic"),
        ("approved_at", MARKER),
    ],
)
def test_job_and_audit_mismatch_refused_with_static_error(episode, field, replacement):
    report, job, audit, _ = episode
    with pytest.raises(ValueError, match="绑定无法核实") as failure:
        build_handoff_timeline(report, job, audit | {field: replacement})
    assert MARKER not in str(failure.value)


def test_unknown_intent_and_original_id_reconciliation_are_distinct(episode):
    report, job, audit, recheck = episode
    pending = {
        key: job[key] for key in ("host_id", "job_id", "plan_id", "plan_digest", "mode_revision")
    }
    intent = audit | {"policy_digest": None, "authorization": None, "unknown_at": at(3)}
    unknown = build_handoff_timeline(
        report, pending | {"status": "unknown", "transport_unknown": True}, intent, recheck
    )
    assert not unknown.native_accepted
    assert unknown.recheck_status == "pending"
    assert [event.kind for event in unknown.events] == ["investigation", "approval", "unknown"]
    assert "远端受理尚未核实" in handoff_markdown(report, unknown)

    with pytest.raises(ValueError, match="绑定无法核实"):
        build_handoff_timeline(
            report, job, audit | {"reconciled_at": at(5), "reconciled_revision": 8}
        )
    reconciled = build_handoff_timeline(
        report,
        job,
        audit | {"unknown_at": at(3), "reconciled_at": at(5), "reconciled_revision": 8},
        recheck,
    )
    assert [event.kind for event in reconciled.events] == [
        "investigation",
        "approval",
        "unknown",
        "native_record",
        "reconciled",
        "recheck",
    ]
    assert reconciled.recheck_status == "passed"


def test_unreconciled_unknown_overrides_cached_verified_result(episode):
    report, job, audit, recheck = episode
    timeline = build_handoff_timeline(report, job, audit | {"unknown_at": at(3)}, recheck)
    assert timeline.phase == "unknown"
    assert not timeline.native_accepted and timeline.recheck_status == "pending"
    assert [event.kind for event in timeline.events] == ["investigation", "approval", "unknown"]
    rendered = handoff_markdown(report, timeline)
    assert "任务结果未知" in rendered and "待对账" in rendered and "待验收" in rendered
    assert "补丁任务验证通过" not in rendered and "登记业务复验通过" not in rendered


def test_later_transport_loss_stays_pending_despite_earlier_query(episode):
    report, job, audit, recheck = episode
    latest = job | {
        "status": "unknown",
        "transport_unknown": True,
        "last_remote_revision": job["revision"],
    }
    latest.pop("revision")
    timeline = build_handoff_timeline(
        report,
        latest,
        audit | {"unknown_at": at(3), "reconciled_at": at(5), "reconciled_revision": 8},
        recheck,
    )
    assert timeline.phase == "unknown"
    assert not timeline.native_accepted and timeline.recheck_status == "pending"
    assert "reconciled" not in {event.kind for event in timeline.events}


@pytest.mark.parametrize("schema_version", [None, True, "1", 2])
def test_native_receipt_requires_explicit_integer_schema(episode, schema_version):
    report, job, audit, _ = episode
    with pytest.raises(ValueError, match="绑定无法核实"):
        build_handoff_timeline(report, job | {"schema_version": schema_version}, audit)


@pytest.mark.parametrize("exit_code", [None, False, "0", 1])
def test_recheck_stays_pending_without_verified_integer_install_success(episode, exit_code):
    report, job, audit, recheck = episode
    timeline = build_handoff_timeline(
        report, job | {"install_exit_code": exit_code}, audit, recheck
    )
    assert timeline.recheck_status == "pending"
    assert timeline.matched_checks == 0


@pytest.mark.parametrize(
    "update",
    [
        {"source": "replay"},
        {"host_id": "other"},
        {"scenario": "disk"},
        {"scope_hash": "a" * 64},
        {"created_at": at(4)},
        {"id": "private-original-report"},
    ],
)
def test_explicit_recheck_requires_new_matching_post_action_report(episode, update):
    report, job, audit, recheck = episode
    with pytest.raises(ValueError, match="绑定无法核实"):
        build_handoff_timeline(report, job, audit, recheck.model_copy(update=update))


@pytest.mark.parametrize(
    "evidence_update",
    [
        {"source": "replay"},
        {"target": "other"},
        {"check_id": "http_other"},
        {"collected_at": at(4)},
        {"collected_at": at(10)},
        {"truncated": True},
        {"status": "timeout"},
        {"exit_code": None},
    ],
)
def test_incomplete_or_unbound_http_evidence_stays_pending(episode, evidence_update):
    report, job, audit, recheck = episode
    evidence = recheck.evidence[0].model_copy(update=evidence_update)
    timeline = build_handoff_timeline(
        report, job, audit, recheck.model_copy(update={"evidence": [evidence]})
    )
    assert timeline.recheck_status == "pending"
    assert timeline.matched_checks == 0


def test_configured_check_failure_is_limited_to_verified_observation(episode):
    report, job, audit, recheck = episode
    failed = recheck.verification[0].model_copy(
        update={"status": "failed", "http_status": 503, "status_matches": False},
    )
    timeline = build_handoff_timeline(
        report, job, audit, recheck.model_copy(update={"verification": [failed]})
    )
    assert timeline.recheck_status == "failed"
    assert "复验未通过" in handoff_markdown(report, timeline)


def test_activation_requires_unique_bound_validated_result(episode, monkeypatch):
    report, job, audit, recheck = episode
    job = job | {"status": "installed_restart_pending"}
    raw = _raw_job(job)
    activation = {
        "host_id": audit["host_id"],
        "job_id": audit["job_id"],
        "status": "verified",
        "policy_digest": audit["policy_digest"],
        "job_digest": digest(raw),
        "scope_hash": digest(
            {
                "channel": "automatic-patch/v1",
                "host_scope": audit["host_scope"],
                "policy_digest": audit["policy_digest"],
            }
        ),
        "original_job": raw,
        "job_revision": job["revision"],
        "updated_at": at(6).isoformat(),
        "result": {"status": "verified", "completed_at": at(5).isoformat()},
    }
    invalid = build_handoff_timeline(report, job, audit, recheck, activations=[activation])
    assert invalid.recheck_status == "pending"
    checked = []
    monkeypatch.setattr(handoff_timeline.ActivationService, "validate_cached", checked.append)
    ambiguous = build_handoff_timeline(
        report, job, audit, recheck, activations=[activation, activation]
    )
    assert ambiguous.recheck_status == "pending" and not checked
    different_scope = activation | {"scope_hash": "c" * 64}
    unbound = build_handoff_timeline(report, job, audit, recheck, activations=[different_scope])
    assert unbound.recheck_status == "pending" and not checked
    valid = build_handoff_timeline(report, job, audit, recheck, activations=[activation])
    assert checked == [activation]
    assert valid.activation_verified and valid.recheck_status == "passed"
    assert "独立服务激活验证通过" in handoff_markdown(report, valid)


@pytest.fixture
def body_free_episode(episode):
    report, job, audit, _legacy = episode
    start = datetime.now(UTC) - timedelta(minutes=15)
    report = report.model_copy(update={"created_at": start})
    audit = audit | {"approved_at": start + timedelta(minutes=1)}
    job = job | {
        "created_at": start + timedelta(minutes=2),
        "updated_at": start + timedelta(minutes=3),
    }
    return (
        report,
        job,
        audit,
        BusinessHandoffRecheck(
            id="br-" + "7" * 32,
            report_id=report.id,
            host_id=report.host_id,
            job_id=audit["job_id"],
            host_scope=report.scope_hash,
            approval_digest=handoff_approval_digest(audit),
            profile_digest="6" * 64,
            started_at=start + timedelta(minutes=4),
            finished_at=start + timedelta(minutes=5),
            checks=["passed", "passed", "passed"],
        ),
    )


@pytest.mark.parametrize(
    "checks, status, matched",
    [
        (["passed", "failed", "inconclusive"], "failed", 1),
        (["passed", "uncovered", "inconclusive"], "pending", 1),
        (["passed", "passed", "passed"], "passed", 3),
    ],
)
def test_body_free_outcomes_use_the_task_timeline_without_exporting_binding_metadata(
    body_free_episode, checks, status, matched
):
    report, job, audit, recheck = body_free_episode
    recheck = recheck.model_copy(update={"checks": checks})
    recheck = BusinessHandoffRecheck.model_validate_json(recheck.model_dump_json())
    timeline = build_handoff_timeline(report, job, audit, recheck)
    assert timeline.recheck_status == status
    assert (timeline.configured_checks, timeline.matched_checks) == (3, matched)
    assert timeline.events[-1].kind == "recheck"
    assert timeline.events[-1].at == recheck.finished_at
    for private in (recheck.id, recheck.job_id, recheck.approval_digest, recheck.profile_digest):
        assert private not in timeline.model_dump_json()
        assert private not in handoff_markdown(report, timeline)


def test_body_free_old_outcomes_remain_pending_after_new_reconciliation(body_free_episode):
    report, job, audit, recheck = body_free_episode
    lost = audit | {"unknown_at": recheck.started_at}
    pending = build_handoff_timeline(report, job, lost, recheck)
    assert pending.recheck_after is None
    later = lost | {"reconciled_at": recheck.started_at, "reconciled_revision": job["revision"]}
    reconciled = build_handoff_timeline(report, job, later, recheck)
    assert reconciled.recheck_after == recheck.started_at
    for timeline in (pending, reconciled):
        assert timeline.recheck_status == "pending"
        assert (timeline.configured_checks, timeline.matched_checks) == (3, 0)
        assert "recheck" not in {event.kind for event in timeline.events}


@pytest.mark.parametrize(
    "update",
    [
        {"report_id": "another-report"},
        {"job_id": "d" * 32},
        {"host_id": "another-host"},
        {"host_scope": "d" * 64},
        {"approval_digest": "d" * 64},
    ],
)
def test_body_free_recheck_refuses_mismatched_binding(body_free_episode, update):
    report, job, audit, recheck = body_free_episode
    with pytest.raises(ValueError, match="绑定无法核实"):
        build_handoff_timeline(report, job, audit, recheck.model_copy(update=update))


def test_body_free_recheck_rejects_future_or_invalid_receipt(body_free_episode):
    report, job, audit, recheck = body_free_episode
    future = recheck.model_copy(update={"finished_at": datetime.now(UTC) + timedelta(hours=1)})
    with pytest.raises(ValueError, match="绑定无法核实"):
        build_handoff_timeline(report, job, audit, future)
    for invalid in (
        {"finished_at": recheck.started_at - timedelta(seconds=1)},
        {"started_at": recheck.started_at.replace(tzinfo=None)},
        {"checks": []},
        {"checks": ["raw-body"]},
        {"body": MARKER},
    ):
        with pytest.raises(ValueError):
            BusinessHandoffRecheck.model_validate(recheck.model_dump() | invalid)


def test_approval_digest_is_independent_of_reconciliation_and_timestamp_format(episode):
    _report, _job, audit, _recheck = episode
    original = handoff_approval_digest(audit)
    assert original == handoff_approval_digest(
        audit
        | {
            "approved_at": at(1).astimezone(timezone(timedelta(hours=8))).isoformat(),
            "unknown_at": at(3),
            "reconciled_at": at(5),
            "reconciled_revision": 8,
        }
    )
    for changed in (
        {"host_id": "different-host"},
        {"job_id": "a" * 32},
        {"plan_id": "b" * 32},
        {"host_scope": "c" * 64},
        {"plan_digest": "d" * 64},
        {"policy_digest": "e" * 64},
        {"mode_revision": 8},
        {"authorization": "automatic"},
        {"approved_at": at(2)},
    ):
        assert original != handoff_approval_digest(audit | changed)
