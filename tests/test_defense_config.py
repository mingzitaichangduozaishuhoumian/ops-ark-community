"""Defense registration is opt-in, address-free, identity-separated deployment data."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_defense_client import keyset as keyset  # noqa: F401 -- existing synthetic key fixture.
from test_defense_client import target as target  # noqa: F401 -- new owned key files only.

from opsark import defense_config as config
from opsark.config import HostConfig, Settings
from opsark.defense_client import DefenseTarget
from opsark.patch_client import PatchTarget


def document(target):
    return {
        "schema_version": 1,
        "targets": {
            target.host.public.id: {
                "root_scope_sha256": target.root_scope_sha256,
                "root_policy_sha256": target.root_policy_sha256,
                "boot_ref": target.boot_ref,
                "binding_ref": target.binding_ref,
                "roles": {
                    role: {
                        "username": credential.username,
                        "key_file": str(credential.key_file),
                        "known_hosts_file": str(credential.known_hosts_file),
                        "trusted_hosts_digest": credential.trusted_hosts_digest,
                    }
                    for role in ("readonly", "observe", "control")
                    if (credential := getattr(target, role))
                },
            }
        },
    }


def write(tmp_path, body):
    path = tmp_path / "defense-registry.json"
    path.write_bytes(json.dumps(body).encode())
    path.chmod(0o600)
    return path


def settings(tmp_path, path=None):
    return Settings(
        tmp_path / "data", "synthetic-deployment-test-token", defense_inventory_path=path
    )


def test_disabled_default_does_not_open_any_registry_or_credentials(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Absent registration must not cause credential reads")

    monkeypatch.setattr(config, "_read_file", forbidden)
    configured = settings(tmp_path)
    assert config.load_defense_targets(configured, {}, {}) == {}
    assert configured.defense_policy_path is None and not configured.defense_worker_enabled
    assert config.defense_registry_scope({}) is None


def test_registered_address_and_role_identity_are_bound_without_apt_privileges(tmp_path, target):
    path = write(tmp_path, document(target))
    repair = PatchTarget(target.host, target.other_key_files[0], "f" * 64)
    loaded = config.load_defense_targets(
        settings(tmp_path, path), {"fixture": target.host}, {"fixture": repair}
    )
    value = loaded["fixture"]
    assert type(value) is DefenseTarget
    assert value.host.public.port == 22
    assert all(getattr(value, role).port == 22423 for role in ("readonly", "observe", "control"))
    assert repair.key_file in value.other_key_files
    assert target.host.key_file in value.other_key_files
    assert config.defense_registry_scope(loaded) == config.defense_registry_scope(
        {"fixture": value}
    )
    scope = config.defense_registry_scope(loaded)
    assert scope is not None and len(scope) == 64
    assert config.defense_registry_scope(loaded) != config.defense_registry_scope(
        {"fixture": replace(value, boot_ref="f" * 64)}
    )


@pytest.mark.parametrize(
    "damage",
    ["host", "address", "command", "inline-key", "port", "collector-user", "root", "version"],
)
def test_unregistered_or_transport_control_fields_are_refused(tmp_path, target, damage):
    body = document(target)
    row = body["targets"]["fixture"]
    role = row["roles"]["control"]
    if damage == "host":
        body["targets"]["not-registered"] = body["targets"].pop("fixture")
    elif damage in {"address", "command", "inline-key"}:
        row[damage] = "synthetic-unclassified-value"
    elif damage == "port":
        role["port"] = 22
    elif damage == "collector-user":
        role["username"] = target.host.public.username
    elif damage == "root":
        role["username"] = "root"
    else:
        body["schema_version"] = True
    with pytest.raises(ValueError, match="未能核实") as error:
        config.load_defense_targets(
            settings(tmp_path, write(tmp_path, body)), {"fixture": target.host}, {}
        )
    assert "synthetic-unclassified-value" not in str(error.value)


def test_loader_passes_apt_keys_for_actual_public_identity_overlap_detection(tmp_path, target):
    path = write(tmp_path, document(target))
    # An APT entry accidentally points to a distinct path with the defense control key bytes.
    copied = tmp_path / "apt-copy"
    copied.write_bytes(target.control.key_file.read_bytes())
    copied.chmod(0o600)
    repair = PatchTarget(target.host, copied, "f" * 64)
    with pytest.raises(ValueError, match="未能核实"):
        config.load_defense_targets(
            settings(tmp_path, path), {"fixture": target.host}, {"fixture": repair}
        )


@pytest.mark.parametrize("channel", ["apt", "collector"])
def test_same_address_alias_cannot_reuse_defense_actual_key(tmp_path, target, channel):
    copied = tmp_path / "alias-copy"
    copied.write_bytes(target.control.key_file.read_bytes())
    copied.chmod(0o600)
    alias = HostConfig(
        target.host.public.model_copy(update={"id": "alias"}),
        copied if channel == "collector" else target.host.key_file,
        target.host.known_hosts_file,
    )
    repairs = {"alias": PatchTarget(alias, copied, "f" * 64)} if channel == "apt" else {}
    with pytest.raises(ValueError, match="未能核实"):
        config.load_defense_targets(
            settings(tmp_path, write(tmp_path, document(target))),
            {"fixture": target.host, "alias": alias},
            repairs,
        )


def test_same_address_alias_username_is_also_isolated(tmp_path, target):
    alias = HostConfig(
        target.host.public.model_copy(update={"id": "alias", "username": target.control.username}),
        target.other_key_files[0],
        target.host.known_hosts_file,
    )
    with pytest.raises(ValueError, match="未能核实"):
        config.load_defense_targets(
            settings(tmp_path, write(tmp_path, document(target))),
            {"fixture": target.host, "alias": alias},
            {},
        )


def test_duplicate_fields_and_relative_key_paths_are_refused(tmp_path, target):
    path = write(tmp_path, document(target))
    path.write_bytes(
        path.read_bytes().replace(
            b'"schema_version": 1', b'"schema_version": 1,"schema_version": 1'
        )
    )
    with pytest.raises(ValueError, match="未能核实"):
        config.load_defense_targets(settings(tmp_path, path), {"fixture": target.host}, {})
    body = document(target)
    body["targets"]["fixture"]["roles"]["control"]["key_file"] = "relative-key"
    write(tmp_path, body)
    with pytest.raises(ValueError, match="未能核实"):
        config.load_defense_targets(settings(tmp_path, path), {"fixture": target.host}, {})


def test_background_enable_needs_explicit_registry_and_policy(tmp_path):
    with pytest.raises(ValueError, match="后台防护"):
        Settings(tmp_path, "synthetic-only-token", defense_worker_enabled=True)
    with pytest.raises(ValueError, match="布尔"):
        Settings(tmp_path, "synthetic-only-token", defense_worker_enabled=1)  # ty: ignore[invalid-argument-type] -- actual invalid deployment type.
    with pytest.raises(ValueError, match="路径"):
        Settings(tmp_path, "synthetic-only-token", defense_inventory_path="inline")  # ty: ignore[invalid-argument-type] -- actual invalid deployment type.
    assert not Settings(
        tmp_path, "synthetic-only-token", defense_inventory_path=Path("registry")
    ).defense_worker_enabled
