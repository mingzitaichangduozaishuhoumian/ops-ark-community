"""Authorization boundaries for concrete, state-bound security upgrade plans."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from opsark.control_modes import (
    ControlPolicy,
    Mode,
    PackageChange,
    PatchPlan,
    PlanApproval,
    evaluate_plan,
)

NOW = datetime(2026, 10, 28, 8, 0, tzinfo=UTC)
STATE = "a" * 64
OTHER_STATE = "b" * 64


def change(**updates):
    values = {
        "name": "openssl",
        "current_version": "3.0.11-1~deb12u1",
        "fixed_version": "3.0.11-1~deb12u2",
        "candidate_version": "3.0.11-1~deb12u3",
        "vendor_security_origin_verified": True,
        "candidate_contains_fixed_verified": True,
        "candidate_is_upgrade_verified": True,
        "current_is_affected_verified": True,
    }
    return PackageChange.model_validate(values | updates)


def policy(**updates):
    values = {
        "enabled": True,
        "host_ids": ("server-a",),
        "allowed_actions": ("os_security_upgrade",),
        "allowed_packages": ("openssl", "libssl3"),
        "max_packages_per_job": 2,
    }
    return ControlPolicy.model_validate(values | updates)


def plan(**updates):
    values = {
        "host_id": "server-a",
        "package_changes": [change()],
        "state_digest": STATE,
        "expires_at": NOW + timedelta(minutes=10),
        "evidence_complete": True,
        "transaction_complete_verified": True,
        "restart_impact_verified": True,
        "risk_level": "low",
    }
    return PatchPlan.model_validate(values | updates)


def approval(concrete_plan=None, **updates):
    concrete_plan = concrete_plan or plan()
    values = {
        "host_id": concrete_plan.host_id,
        "plan_digest": concrete_plan.plan_digest,
        "state_digest": concrete_plan.state_digest,
        "approved_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
    }
    return PlanApproval.model_validate(values | updates)


def evaluate(concrete_plan=None, concrete_policy=None, **updates):
    return evaluate_plan(
        mode=updates.pop("mode", Mode.automatic),
        policy=concrete_policy or policy(),
        plan=concrete_plan or plan(),
        current_state_digest=updates.pop("current_state_digest", STATE),
        now=updates.pop("now", NOW),
        **updates,
    )


def assert_blocked(decision):
    assert decision.action == "blocked"
    assert decision.executable is False
    assert decision.reasons


def test_policy_defaults_do_not_authorize_any_execution():
    default = ControlPolicy()
    assert default.enabled is False
    assert default.host_ids == ()
    assert default.allowed_actions == ()
    assert default.allowed_packages == ()
    assert default.allow_reboot is False
    assert default.allow_service_restart is False
    assert_blocked(evaluate(concrete_policy=default))


@pytest.mark.parametrize("mode", [Mode.manual, "manual"])
def test_manual_mode_never_executes_even_with_an_approval(mode):
    concrete_plan = plan()
    decision = evaluate(concrete_plan, mode=mode, approval=approval(concrete_plan))
    assert decision.action == "advice_only"
    assert decision.executable is False


def test_manual_mode_can_still_explain_a_stale_out_of_scope_plan():
    decision = evaluate(
        plan(expires_at=NOW),
        concrete_policy=ControlPolicy(),
        mode=Mode.manual,
        current_state_digest=OTHER_STATE,
    )
    assert decision.action == "advice_only"
    assert decision.executable is False


def test_automatic_low_risk_cannot_bypass_the_full_grant_evaluator():
    concrete_plan = plan()
    decision = evaluate(concrete_plan)
    assert decision.action == "blocked"
    assert decision.executable is False
    assert decision.mode == Mode.automatic
    assert decision.plan_digest == concrete_plan.plan_digest


def test_assisted_mode_requires_approval_of_the_specific_plan():
    concrete_plan = plan()
    pending = evaluate(concrete_plan, mode=Mode.assisted)
    assert pending.action == "await_approval"
    assert pending.executable is False
    authorized = evaluate(concrete_plan, mode=Mode.assisted, approval=approval(concrete_plan))
    assert authorized.action == "authorized"
    assert authorized.executable is True


@pytest.mark.parametrize("field", ["transaction_complete_verified", "restart_impact_verified"])
@pytest.mark.parametrize("mode", [Mode.assisted, Mode.automatic])
def test_unverified_transaction_or_restart_impact_cannot_be_approved(field, mode):
    concrete_plan = plan(**{field: False})
    assert_blocked(evaluate(concrete_plan, mode=mode, approval=approval(concrete_plan)))


@pytest.mark.parametrize("risk", ["medium", "high"])
def test_automatic_mode_cannot_use_an_individual_approval_as_an_implicit_grant(risk):
    concrete_plan = plan(risk_level=risk)
    pending = evaluate(concrete_plan)
    assert pending.action == "blocked"
    assert pending.executable is False
    assert evaluate(concrete_plan, approval=approval(concrete_plan)).action == "blocked"


@pytest.mark.parametrize("mode", [Mode.assisted, Mode.automatic])
def test_unknown_risk_remains_pending_even_with_an_approval(mode):
    concrete_plan = plan(risk_level="unknown")
    decision = evaluate(concrete_plan, mode=mode, approval=approval(concrete_plan))
    assert decision.action == ("blocked" if mode == Mode.automatic else "await_approval")
    assert decision.executable is False


@pytest.mark.parametrize(
    "scope",
    [
        {"enabled": False},
        {"host_ids": ()},
        {"host_ids": ("server-b",)},
        {"allowed_actions": ()},
        {"allowed_packages": ()},
        {"allowed_packages": ("libssl3",)},
    ],
)
@pytest.mark.parametrize("mode", [Mode.assisted, Mode.automatic])
def test_approval_cannot_override_missing_scope_or_disabled_policy(scope, mode):
    concrete_plan = plan()
    assert_blocked(
        evaluate(
            concrete_plan,
            concrete_policy=policy(**scope),
            mode=mode,
            approval=approval(concrete_plan),
        )
    )


def test_package_count_is_checked_against_the_policy():
    concrete_plan = plan(package_changes=[change(), change(name="libssl3")])
    assert_blocked(evaluate(concrete_plan, concrete_policy=policy(max_packages_per_job=1)))


@pytest.mark.parametrize("offset", [0, -1])
def test_expired_plan_is_blocked_at_the_expiry_boundary(offset):
    concrete_plan = plan(expires_at=NOW + timedelta(seconds=offset))
    assert_blocked(evaluate(concrete_plan))


def test_a_plan_cannot_authorize_execution_far_into_the_future():
    assert_blocked(evaluate(plan(expires_at=NOW + timedelta(minutes=30, seconds=1))))
    concrete_plan = plan(expires_at=NOW + timedelta(minutes=30))
    assert (
        evaluate(concrete_plan, mode=Mode.assisted, approval=approval(concrete_plan)).action
        == "authorized"
    )


@pytest.mark.parametrize("mode", [Mode.assisted, Mode.automatic])
def test_current_state_must_match_the_state_used_to_make_the_plan(mode):
    concrete_plan = plan()
    assert_blocked(
        evaluate(
            concrete_plan,
            mode=mode,
            approval=approval(concrete_plan),
            current_state_digest=OTHER_STATE,
        )
    )


@pytest.mark.parametrize(
    "mismatch",
    [
        {"host_id": "server-b"},
        {"plan_digest": "c" * 64},
        {"state_digest": OTHER_STATE},
        {"approved_at": NOW + timedelta(seconds=1)},
        {"expires_at": NOW},
        {"expires_at": NOW - timedelta(seconds=1)},
        {"expires_at": NOW + timedelta(minutes=11)},
    ],
)
def test_assisted_approval_is_bound_to_host_plan_state_and_time(mismatch):
    concrete_plan = plan()
    assert_blocked(
        evaluate(concrete_plan, mode=Mode.assisted, approval=approval(concrete_plan, **mismatch))
    )


def test_approval_is_short_lived_from_the_time_it_was_given():
    concrete_plan = plan(expires_at=NOW + timedelta(minutes=30))
    too_long = approval(
        concrete_plan,
        approved_at=NOW - timedelta(minutes=9),
        expires_at=NOW + timedelta(minutes=1, seconds=1),
    )
    assert_blocked(evaluate(concrete_plan, mode=Mode.assisted, approval=too_long))
    at_boundary = approval(concrete_plan, approved_at=NOW, expires_at=NOW + timedelta(minutes=10))
    assert evaluate(concrete_plan, mode=Mode.assisted, approval=at_boundary).action == "authorized"


def test_an_approval_for_an_earlier_version_candidate_cannot_authorize_a_new_plan():
    old_plan = plan()
    new_plan = plan(package_changes=[change(candidate_version="3.0.11-1~deb12u4")])
    assert old_plan.plan_digest != new_plan.plan_digest
    assert_blocked(evaluate(new_plan, mode=Mode.assisted, approval=approval(old_plan)))


@pytest.mark.parametrize(
    "missing",
    [
        {"fixed_version": None},
        {"candidate_version": None},
        {"vendor_security_origin_verified": False},
        {"candidate_contains_fixed_verified": False},
        {"candidate_is_upgrade_verified": False},
        {"current_is_affected_verified": False},
    ],
)
def test_missing_vendor_or_version_evidence_blocks_even_an_approved_plan(missing):
    concrete_plan = plan(package_changes=[change(**missing)])
    assert_blocked(evaluate(concrete_plan, approval=approval(concrete_plan)))


def test_incomplete_collection_evidence_is_not_overridden_by_approval():
    concrete_plan = plan(evidence_complete=False)
    assert_blocked(evaluate(concrete_plan, approval=approval(concrete_plan)))


def test_equal_current_and_candidate_is_not_an_executable_change():
    concrete_plan = plan(package_changes=[change(candidate_version="3.0.11-1~deb12u1")])
    assert_blocked(evaluate(concrete_plan))


def test_equal_current_and_fixed_version_has_no_outstanding_fix_to_apply():
    concrete_plan = plan(package_changes=[change(fixed_version="3.0.11-1~deb12u1")])
    assert_blocked(evaluate(concrete_plan))


@pytest.mark.parametrize(
    ("plan_flag", "policy_flag"),
    [
        ("requires_reboot", "allow_reboot"),
        ("requires_service_restart", "allow_service_restart"),
    ],
)
def test_restart_side_effects_require_explicit_policy_permission(plan_flag, policy_flag):
    concrete_plan = plan(**{plan_flag: True})
    assert_blocked(evaluate(concrete_plan, approval=approval(concrete_plan)))
    decision = evaluate(
        concrete_plan,
        concrete_policy=policy(**{policy_flag: True}),
        mode=Mode.assisted,
        approval=approval(concrete_plan),
    )
    assert decision.action == "authorized"


@pytest.mark.parametrize(
    "updates",
    [
        {"host_id": "server-b"},
        {"state_digest": OTHER_STATE},
        {"expires_at": NOW + timedelta(minutes=9)},
        {"requires_reboot": True},
        {"requires_service_restart": True},
        {"evidence_complete": False},
        {"risk_level": "high"},
        {"package_changes": [change(candidate_version="3.0.11-1~deb12u4")]},
        {"package_changes": [change(vendor_security_origin_verified=False)]},
        {"package_changes": [change(candidate_contains_fixed_verified=False)]},
        {"package_changes": [change(candidate_is_upgrade_verified=False)]},
        {"package_changes": [change(current_is_affected_verified=False)]},
    ],
)
def test_digest_binds_every_authorization_relevant_part_of_the_plan(updates):
    assert plan().plan_digest != plan(**updates).plan_digest


def test_digest_is_canonical_across_key_order_and_equivalent_timezone():
    concrete_plan = plan()
    payload = concrete_plan.model_dump(exclude={"plan_digest"})
    payload["expires_at"] = concrete_plan.expires_at.astimezone(timezone(timedelta(hours=8)))
    reordered = dict(reversed(list(payload.items())))
    assert PatchPlan.model_validate(reordered).plan_digest == concrete_plan.plan_digest
    assert (
        PatchPlan.model_validate(concrete_plan.model_dump()).plan_digest
        == concrete_plan.plan_digest
    )


@pytest.mark.parametrize("digest", ["c" * 64, "A" * 64, "a" * 63, "not-a-digest"])
def test_a_supplied_digest_must_match_the_canonical_plan(digest):
    with pytest.raises(ValidationError):
        plan(plan_digest=digest)


@pytest.mark.parametrize(
    "updates",
    [
        {"host_id": "server-b"},
        {"state_digest": OTHER_STATE},
        {"risk_level": "low"},
        {"expires_at": NOW + timedelta(hours=1)},
        {"requires_reboot": False},
    ],
)
def test_model_copy_does_not_bypass_plan_digest_validation(updates):
    original = plan(risk_level="high", requires_reboot=True)
    copied = original.model_copy(update=updates)
    with pytest.raises(ValidationError):
        evaluate(copied)


def test_mutating_a_nested_package_invalidates_the_existing_plan_digest():
    concrete_plan = plan()
    concrete_plan.package_changes[0].candidate_version = "3.0.11-1~deb12u99"
    with pytest.raises(ValidationError):
        evaluate(concrete_plan)


def test_mutating_the_package_list_invalidates_the_existing_plan_digest():
    concrete_plan = plan()
    concrete_plan.package_changes.append(change(name="libssl3"))
    with pytest.raises(ValidationError):
        evaluate(concrete_plan)


def test_model_copy_does_not_bypass_strict_policy_or_approval_flags():
    copied_policy = policy().model_copy(update={"enabled": "true"})
    with pytest.raises(ValidationError):
        evaluate(concrete_policy=copied_policy)
    copied_approval = approval().model_copy(update={"approved_at": "no-time"})
    with pytest.raises(ValidationError):
        evaluate(mode=Mode.assisted, approval=copied_approval)


def test_a_claim_of_signed_metadata_cannot_replace_verified_security_origin():
    unsafe_change = change(vendor_security_origin_verified=False)
    copied = unsafe_change.model_copy(update={"signed_metadata": True})
    concrete_plan = plan(package_changes=[copied])
    assert_blocked(evaluate(concrete_plan))
    with pytest.raises(ValidationError):
        PackageChange.model_validate(unsafe_change.model_dump() | {"signed_metadata": True})


@pytest.mark.parametrize(
    "unsafe",
    ["openssl;id", "$(id)", "../openssl", "--allow-unauthenticated", "https://example.com/poc"],
)
def test_package_names_do_not_accept_shell_options_paths_or_urls(unsafe):
    with pytest.raises(ValidationError):
        change(name=unsafe)
    with pytest.raises(ValidationError):
        policy(allowed_packages=(unsafe,))


@pytest.mark.parametrize("unsafe", ["1.0;id", "1.0\ncommand", "$(id)", "1.0 /tmp/x"])
def test_opaque_versions_are_bounded_safe_tokens(unsafe):
    with pytest.raises(ValidationError):
        change(candidate_version=unsafe)


def test_debian_epochs_and_tildes_are_not_interpreted_as_semver():
    concrete_plan = plan(
        package_changes=[
            change(
                current_version="1:1.0~rc1-1",
                fixed_version="1:1.0-1+deb12u1",
                candidate_version="1:1.0-1+deb12u2",
            )
        ]
    )
    assert (
        evaluate(concrete_plan, mode=Mode.assisted, approval=approval(concrete_plan)).action
        == "authorized"
    )
    missing_comparison = plan(
        package_changes=[
            change(candidate_version="999:999.0", candidate_contains_fixed_verified=False)
        ]
    )
    assert_blocked(evaluate(missing_comparison))


@pytest.mark.parametrize(
    ("model", "fields"),
    [
        (ControlPolicy, {"enabled": "true"}),
        (ControlPolicy, {"allow_reboot": 1}),
        (ControlPolicy, {"allow_service_restart": "false"}),
        (PackageChange, {"vendor_security_origin_verified": "true"}),
        (PackageChange, {"candidate_contains_fixed_verified": 1}),
        (PackageChange, {"candidate_is_upgrade_verified": "true"}),
        (PackageChange, {"current_is_affected_verified": "true"}),
        (PatchPlan, {"evidence_complete": "true"}),
        (PatchPlan, {"requires_reboot": 1}),
        (PatchPlan, {"requires_service_restart": "false"}),
    ],
)
def test_security_boolean_fields_require_actual_booleans(model, fields):
    if model is ControlPolicy:
        payload = policy().model_dump()
    elif model is PackageChange:
        payload = change().model_dump()
    else:
        payload = plan().model_dump(exclude={"plan_digest"})
    with pytest.raises(ValidationError):
        model.model_validate(payload | fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"host_ids": tuple(f"server-{number}" for number in range(11))},
        {"allowed_packages": tuple(f"package-{number}" for number in range(21))},
        {"host_ids": ("server-a", "server-a")},
        {"allowed_packages": ("openssl", "openssl")},
        {"allowed_actions": ("os_security_upgrade", "os_security_upgrade")},
        {"allowed_actions": ("shell",)},
        {"max_packages_per_job": 0},
        {"max_packages_per_job": 6},
        {"max_packages_per_job": True},
    ],
)
def test_policy_scope_is_small_explicit_and_unambiguous(fields):
    with pytest.raises(ValidationError):
        policy(**fields)


def test_duplicate_packages_are_rejected_before_authorization():
    with pytest.raises(ValidationError):
        plan(package_changes=[change(), change()])


@pytest.mark.parametrize("key", ["command", "script", "url", "poc"])
def test_plan_is_not_a_general_command_or_exploit_container(key):
    with pytest.raises(ValidationError):
        plan(**{key: "untrusted input"})


def test_plan_approval_and_decision_times_require_timezones():
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(ValidationError):
        plan(expires_at=naive)
    with pytest.raises(ValidationError):
        approval(approved_at=naive)
    with pytest.raises(ValidationError):
        approval(expires_at=naive)
    with pytest.raises(ValueError, match="时区"):
        evaluate(now=naive)
