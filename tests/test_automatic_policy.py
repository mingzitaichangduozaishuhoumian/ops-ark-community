"""Explicit pre-authorization cannot be replaced by mode, defaults or guessed usage."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from test_control_modes import NOW, approval, change, plan, policy

from opsark.control_modes import (
    AutomaticGrant,
    ControlPolicy,
    MaintenanceWindow,
    Mode,
    automatic_window_open,
    evaluate_automatic_plan,
    evaluate_plan,
)

ROOT_POLICY = "c" * 64


def grant(**updates):
    values = {
        "enabled": True,
        "grant_id": "1" * 32,
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=23, minutes=59),
        "host_ids": ("server-a",),
        "allowed_packages": ("openssl",),
        "allowed_advisories": ("USN-8956-1",),
        "target_policy_digests": {"server-a": ROOT_POLICY},
        "maintenance_windows": [
            {"weekdays": [0, 1, 2, 3, 4, 5, 6], "start_minute": 0, "end_minute": 1440}
        ],
    }
    return AutomaticGrant.model_validate(values | updates)


def auto_policy(concrete_grant=None, **updates):
    values = policy().model_dump()
    values["automatic"] = (concrete_grant or grant()).model_dump()
    return ControlPolicy.model_validate(values | updates)


def evaluate(concrete_plan=None, concrete_policy=None, **updates):
    values = {
        "advisory_id": "USN-8956-1",
        "current_policy_digest": ROOT_POLICY,
        "jobs_today": 0,
        "total_jobs": 0,
        "latch_paused": False,
        "now": NOW,
    }
    return evaluate_automatic_plan(
        concrete_policy or auto_policy(), concrete_plan or plan(), **(values | updates)
    )


def blocked(decision):
    assert decision.action == "blocked"
    assert decision.executable is False
    assert decision.reasons


def test_general_enabled_policy_or_mode_does_not_create_a_grant():
    assert ControlPolicy().automatic is None
    blocked(evaluate(concrete_policy=policy()))
    low = plan()
    blocked(evaluate_plan(Mode.automatic, auto_policy(), low, low.state_digest, approval(low), NOW))


def test_full_evaluator_authorizes_only_the_bound_projection_without_human_approval():
    projected = plan()
    decision = evaluate(projected)
    assert decision.action == "authorized"
    assert decision.executable is True
    assert decision.mode == Mode.automatic
    assert decision.plan_digest == projected.plan_digest


def test_disabled_grant_does_not_authorize_even_when_every_scope_and_fact_matches():
    blocked(evaluate(concrete_policy=auto_policy(grant(enabled=False))))


def test_grant_roundtrip_is_json_serializable_and_bound_to_every_permission():
    original = grant()
    restored = AutomaticGrant.model_validate_json(original.model_dump_json())
    assert original == restored and len(original.grant_digest) == 64
    assert original.grant_digest != grant(max_total_jobs=2).grant_digest
    assert original.grant_digest != grant(allow_service_restart=True).grant_digest
    assert original.grant_digest != grant(allowed_risk_levels=("low", "medium")).grant_digest
    assert original.grant_digest != grant(expires_at=NOW + timedelta(hours=1)).grant_digest


def test_scope_order_is_canonical_but_duplicate_values_are_rejected():
    left = grant(
        host_ids=("server-b", "server-a"),
        target_policy_digests={"server-b": "d" * 64, "server-a": ROOT_POLICY},
        allowed_packages=("openssl", "curl"),
        allowed_advisories=("USN-8956-2", "USN-8956-1"),
        allowed_risk_levels=("medium", "low"),
    )
    right = grant(
        host_ids=("server-a", "server-b"),
        target_policy_digests={"server-a": ROOT_POLICY, "server-b": "d" * 64},
        allowed_packages=("curl", "openssl"),
        allowed_advisories=("USN-8956-1", "USN-8956-2"),
        allowed_risk_levels=("low", "medium"),
    )
    assert left.grant_digest == right.grant_digest


@pytest.mark.parametrize(
    "updates",
    [
        {"host_ids": ("server-a", "server-a")},
        {"allowed_packages": ("openssl", "openssl")},
        {"allowed_advisories": ("USN-8956-1", "USN-8956-1")},
        {"allowed_risk_levels": ("low", "low")},
        {"host_ids": ()},
        {"allowed_packages": ()},
        {"allowed_advisories": ()},
        {"maintenance_windows": ()},
        {"target_policy_digests": {}},
        {"target_policy_digests": {"server-b": ROOT_POLICY}},
        {"target_policy_digests": {"server-a": ROOT_POLICY, "server-b": ROOT_POLICY}},
        {"target_policy_digests": {"server-a": "not-a-digest"}},
        {"allowed_packages": ("openssl:amd64",)},
        {"allowed_packages": ("--allow-unauthenticated",)},
        {"allowed_advisories": ("CVE-2026-111497",)},
        {"allowed_risk_levels": ("high",)},
        {"grant_id": "../../unsafe"},
        {"schema_version": True},
        {"enabled": "true"},
        {"max_jobs_per_day": True},
        {"max_total_jobs": "1"},
        {"max_jobs_per_day": 0},
        {"max_total_jobs": 6},
        {"allow_service_restart": 1},
        {"allow_reboot": True},
        {"grant_digest": "0" * 64},
    ],
)
def test_grants_reject_incomplete_ambiguous_or_expanded_permission_inputs(updates):
    with pytest.raises(ValidationError):
        grant(**updates)


@pytest.mark.parametrize(
    "updates",
    [
        {"issued_at": NOW.replace(tzinfo=None)},
        {"expires_at": NOW.replace(tzinfo=None)},
        {"expires_at": NOW - timedelta(minutes=1)},
        {"expires_at": NOW - timedelta(minutes=2)},
        {"expires_at": NOW + timedelta(hours=23, minutes=59, seconds=1)},
    ],
)
def test_grant_lifetime_is_aware_positive_and_at_most_twenty_four_hours(updates):
    with pytest.raises(ValidationError):
        grant(**updates)


@pytest.mark.parametrize(
    "updates",
    [
        {"weekdays": []},
        {"weekdays": [2, 2]},
        {"weekdays": [True]},
        {"weekdays": [-1]},
        {"weekdays": [7]},
        {"start_minute": 1440},
        {"end_minute": 0},
        {"start_minute": 500, "end_minute": 500},
        {"start_minute": "0"},
        {"end_minute": True},
    ],
)
def test_maintenance_windows_reject_empty_or_non_strict_intervals(updates):
    values = {"weekdays": [2], "start_minute": 0, "end_minute": 1440}
    with pytest.raises(ValidationError):
        MaintenanceWindow.model_validate(values | updates)


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (NOW.replace(hour=7, minute=59, second=59), False),
        (NOW, True),
        (NOW.replace(hour=8, minute=59, second=59), True),
        (NOW.replace(hour=9), False),
        (NOW + timedelta(days=1), False),
    ],
)
def test_utc_day_window_starts_inclusively_and_ends_exclusively(at, expected):
    concrete = grant(
        issued_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=22),
        maintenance_windows=[{"weekdays": [2], "start_minute": 480, "end_minute": 540}],
    )
    assert automatic_window_open(concrete, at) is expected


@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (datetime(2026, 10, 25, 22, 59, 59, tzinfo=UTC), False),
        (datetime(2026, 10, 25, 23, 0, tzinfo=UTC), True),
        (datetime(2026, 10, 26, 0, 30, tzinfo=UTC), True),
        (datetime(2026, 10, 26, 1, 0, tzinfo=UTC), False),
    ],
)
def test_sunday_cross_midnight_belongs_to_starting_weekday(at, expected):
    concrete = grant(
        issued_at=datetime(2026, 10, 25, 20, tzinfo=UTC),
        expires_at=datetime(2026, 10, 26, 4, tzinfo=UTC),
        maintenance_windows=[{"weekdays": [6], "start_minute": 1380, "end_minute": 60}],
    )
    assert automatic_window_open(concrete, at) is expected


def test_all_day_is_explicit_and_local_timezone_does_not_move_utc_weekday():
    at = NOW.astimezone(timezone(timedelta(hours=8)))
    concrete = grant(maintenance_windows=[{"weekdays": [2], "start_minute": 0, "end_minute": 1440}])
    assert automatic_window_open(concrete, at)
    assert concrete.issued_at.tzinfo == UTC and concrete.expires_at.tzinfo == UTC


def test_future_grant_expiry_and_maintenance_window_are_not_implicit_permissions():
    future = grant(issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(hours=1))
    blocked(evaluate(concrete_policy=auto_policy(future)))
    expired = grant(issued_at=NOW - timedelta(hours=1), expires_at=NOW)
    blocked(evaluate(concrete_policy=auto_policy(expired)))
    outside = grant(maintenance_windows=[{"weekdays": [2], "start_minute": 540, "end_minute": 600}])
    blocked(evaluate(concrete_policy=auto_policy(outside)))
    with pytest.raises(ValueError):
        automatic_window_open(grant(), NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        evaluate(now=NOW.replace(tzinfo=None))


def test_target_advisory_and_current_root_policy_binding_must_all_match():
    for updates in (
        {"advisory_id": "USN-8956-2"},
        {"advisory_id": "../../notice"},
        {"advisory_id": None},
        {"current_policy_digest": "d" * 64},
        {"current_policy_digest": "C" * 64},
        {"current_policy_digest": None},
    ):
        blocked(evaluate(**updates))
    other_host = plan(host_id="server-b")
    broad = auto_policy(host_ids=("server-a", "server-b"))
    blocked(evaluate(other_host, concrete_policy=broad))
    another_package = plan(package_changes=[change(name="libssl3")])
    blocked(evaluate(another_package))


@pytest.mark.parametrize(
    "updates",
    [
        {"host_ids": ()},
        {"allowed_packages": ()},
        {"allowed_actions": ()},
    ],
)
def test_enabled_grant_cannot_expand_general_authorization_scope(updates):
    with pytest.raises(ValidationError):
        auto_policy(**updates)


def test_medium_risk_stays_medium_and_needs_explicit_risk_and_restart_permissions():
    concrete_plan = plan(risk_level="medium", requires_service_restart=True)
    allowed = auto_policy(
        grant(allowed_risk_levels=("low", "medium"), allow_service_restart=True),
        allow_service_restart=True,
    )
    assert evaluate(concrete_plan, allowed).action == "authorized"
    assert concrete_plan.risk_level == "medium"
    blocked(evaluate(concrete_plan, auto_policy(allow_service_restart=True)))
    blocked(
        evaluate(
            concrete_plan,
            auto_policy(grant(allowed_risk_levels=("low", "medium")), allow_service_restart=True),
        )
    )
    blocked(
        evaluate(
            concrete_plan,
            auto_policy(grant(allowed_risk_levels=("low", "medium"), allow_service_restart=True)),
        )
    )


@pytest.mark.parametrize("risk", ["high", "unknown"])
def test_high_or_unknown_impact_never_enters_automatic_execution(risk):
    blocked(evaluate(plan(risk_level=risk)))


def test_automatic_does_not_authorize_reboot_or_multiple_packages():
    blocked(evaluate(plan(requires_reboot=True), auto_policy(allow_reboot=True)))
    multiple = plan(package_changes=[change(), change(name="libssl3")])
    broad = auto_policy(grant(allowed_packages=("openssl", "libssl3")))
    blocked(evaluate(multiple, broad))


@pytest.mark.parametrize(
    "updates",
    [
        {"evidence_complete": False},
        {"transaction_complete_verified": False},
        {"restart_impact_verified": False},
        {"package_changes": [change(vendor_security_origin_verified=False)]},
        {"package_changes": [change(candidate_contains_fixed_verified=False)]},
        {"package_changes": [change(candidate_is_upgrade_verified=False)]},
        {"package_changes": [change(current_is_affected_verified=False)]},
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(minutes=31)},
    ],
)
def test_explicit_grant_never_bypasses_deterministic_evidence_requirements(updates):
    blocked(evaluate(plan(**updates)))


@pytest.mark.parametrize("field", ["jobs_today", "total_jobs"])
@pytest.mark.parametrize("value", [None, True, False, "0", 0.0, -1, 2**63])
def test_unknown_or_non_strict_usage_is_not_interpreted_as_zero(field, value):
    blocked(evaluate(**{field: value}))


def test_reservations_failures_and_unknown_attempts_exhaust_the_same_grant_budget():
    blocked(evaluate(jobs_today=1))
    blocked(evaluate(total_jobs=1))
    larger = auto_policy(grant(max_jobs_per_day=2, max_total_jobs=3))
    assert evaluate(concrete_policy=larger, jobs_today=1, total_jobs=2).action == "authorized"
    blocked(evaluate(concrete_policy=larger, jobs_today=2, total_jobs=2))
    blocked(evaluate(concrete_policy=larger, jobs_today=0, total_jobs=3))
    assert evaluate(concrete_policy=larger, jobs_today=0, total_jobs=0).action == "authorized"


@pytest.mark.parametrize("value", [True, None, "false", 0, 1])
def test_paused_or_unknown_latch_does_not_allow_automatic_work(value):
    blocked(evaluate(latch_paused=value))


def test_model_copy_cannot_silently_change_a_bound_grant_or_plan():
    tampered = grant().model_copy(update={"max_total_jobs": 5})
    unsafe_policy = auto_policy().model_copy(update={"automatic": tampered})
    with pytest.raises(ValidationError):
        evaluate(concrete_policy=unsafe_policy)
    projected = plan()
    with pytest.raises(ValidationError):
        evaluate(projected.model_copy(update={"risk_level": "low", "requires_reboot": True}))
    mutable = grant()
    mutable.target_policy_digests["server-a"] = "d" * 64
    with pytest.raises(ValidationError):
        automatic_window_open(mutable, NOW)


@pytest.mark.parametrize("version", ["--allow-unauthenticated", "-1", "v1.0", "~1", ".1"])
def test_version_fields_do_not_accept_option_like_or_non_debian_prefixes(version):
    with pytest.raises(ValidationError):
        change(candidate_version=version)
