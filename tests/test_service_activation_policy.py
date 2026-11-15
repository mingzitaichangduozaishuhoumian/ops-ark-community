"""Independent activation permission cannot widen old modes or archived policy projections."""

import pytest

from opsark.control_modes import ControlPolicy, ServiceActivationPolicy


def configuration():
    return {
        "enabled": True,
        "host_ids": ["lab"],
        "allowed_actions": ["os_security_upgrade"],
        "allowed_packages": ["libexpat1"],
        "allow_service_restart": True,
        "service_activation": {
            "enabled": True,
            "host_ids": ["lab"],
            "allowed_packages": ["libexpat1"],
            "allowed_units": ["opsark-test.service"],
        },
    }


def test_absent_activation_permission_preserves_original_projection():
    policy = ControlPolicy()
    assert "service_activation" not in policy.model_dump()
    assert "service_activation" not in policy.model_dump(mode="json")
    assert "service_activation" not in policy.model_dump_json()
    assert policy.model_dump()["automatic_ai"] is None
    assert ControlPolicy.model_validate(policy.model_dump()).service_activation is None


def test_explicit_activation_has_independent_bounded_permission():
    policy = ControlPolicy.model_validate(configuration())
    assert policy.service_activation.enabled
    assert policy.model_dump(mode="json")["service_activation"]["allowed_units"] == [
        "opsark-test.service"
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"host_ids": ["other"]},
        {"allowed_packages": ["other"]},
        {"allowed_units": ["sshd.service"]},
        {"allowed_units": ["SSH.service"]},
        {"allowed_units": ["networking.service"]},
        {"allowed_units": ["NetworkManager.service"]},
        {"allowed_units": ["docker.service"]},
        {"allowed_units": ["name@instance.service"]},
        {"allowed_units": ["dbus.service"]},
        {"max_services_per_activation": 2},
        {"max_services_per_activation": True},
        {"enabled": "true"},
        {"allowed_units": ["opsark-test.service", "opsark-test.service"]},
    ],
)
def test_invalid_or_widened_activation_is_rejected(change):
    data = configuration()
    data["service_activation"].update(change)
    with pytest.raises(ValueError):
        ControlPolicy.model_validate(data)


@pytest.mark.parametrize("parent", [{"enabled": False}, {"allow_service_restart": False}])
def test_activation_requires_parent_permission(parent):
    data = configuration() | parent
    with pytest.raises(ValueError):
        ControlPolicy.model_validate(data)


def test_dbus_requires_explicit_critical_exception_root_will_also_require_lab_identity():
    data = configuration()
    data["service_activation"].update(
        allowed_units=["dbus.service"], allow_critical_units=["dbus.service"]
    )
    assert ControlPolicy.model_validate(data).service_activation.allow_critical_units == (
        "dbus.service",
    )
    with pytest.raises(ValueError):
        ServiceActivationPolicy(allow_critical_units=("dbus.service",))
