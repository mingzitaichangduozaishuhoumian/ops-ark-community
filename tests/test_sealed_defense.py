"""V2 content-only handovers, synthetic public pins and ten-store history.

No native age, private key, model, network, Docker or deployment configuration is
consulted. Archive path safety/native authentication have their own existing suites.
"""

import base64
import copy
import hashlib
import io
import json
import struct
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_defense_backup_compat import OrdinaryFixturePaths, contents
from test_defense_backup_compat import history as history  # noqa: F401 -- fake ten-store fixture.
from test_store_transfer import transfer

from opsark.control_modes import ControlPolicy
from opsark.defense_models import POLICY_SHA256
from opsark.defense_policy import DefensePolicy
from opsark.defense_store import DefenseStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import _sealed_archive as archive  # noqa: E402 -- own checkout, no main import.
from tools import _sealed_defense as defense  # noqa: E402
from tools import sealed_backup as sealed  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("readonly", "observe", "control")


@pytest.mark.parametrize("new_file", [None, *sorted(defense.CONFIGS)])
def test_v1_source_collection_requires_v2_if_any_fixed_defense_file_exists(monkeypatch, new_file):
    plan, documents = bundle(registered=False)
    plan["schema_version"] = 1
    del plan["ssh_defense"]
    documents["handover.json"] = raw_json(plan)
    snapshot, config = Path("X:/synthetic-snapshot"), Path("X:/synthetic-config")
    physical = {config / name: raw for name, raw in documents.items()}
    physical.update(
        {snapshot / name.removeprefix("stores/"): b"fake-owned" for name in archive.CORE}
    )
    if new_file is not None:
        _, full = bundle()
        physical[config / new_file] = full[new_file]
    opened = []

    @contextmanager
    def held(path, _limit, **_options):
        opened.append(path)
        raw = physical[path]
        yield SimpleNamespace(
            handle=io.BytesIO(raw), permissions={}, size=len(raw), verify=lambda: None
        )

    monkeypatch.setattr(sealed.paths, "held_file", held)
    monkeypatch.setattr(sealed.paths, "private_directory", lambda path: path)
    monkeypatch.setattr(sealed, "_exists", lambda path: path in physical)
    with ExitStack() as stack:
        if new_file is not None:
            with pytest.raises(sealed.BackupError, match="defense_configuration_requires_v2"):
                sealed._sources(stack, snapshot, "observer-handover-v1", config)
            assert config / new_file not in opened  # Metadata refusal, not content collection.
        else:
            sources, rows, image = sealed._sources(stack, snapshot, "observer-handover-v1", config)
            manifest = archive.make_manifest("sb-" + "3" * 32, "observer-handover-v1", rows, image)
            assert manifest["schema_version"] == 1
            assert not any("config-original/" + name in sources for name in defense.CONFIGS)
            assert sealed._proof(manifest, "4" * 64, 123)["configuration_included"]


def raw_json(value):
    return json.dumps(value, ensure_ascii=True, indent=2).encode("ascii") + b"\n"


def pin(address="192.0.2.10", port=22423):
    algorithm = b"ssh-ed25519"
    blob = struct.pack(">I", len(algorithm)) + algorithm + struct.pack(">I", 32) + bytes(range(32))
    endpoint = address if port == 22 else f"[{address}]:{port}"
    return f"{endpoint} ssh-ed25519 ".encode() + base64.b64encode(blob) + b"\n"


def bundle(*, registered=True):
    """Explicit fixture independent of the production validator's builders."""
    image = "sha256:" + "a" * 64
    plan = {
        "schema_version": 2,
        "compose_files": ["compose.yaml", "compose.release.yaml"],
        "env_files": ["observer.env"],
        "configuration_files": ["secrets/inventory.toml", "secrets/known_hosts"],
        "unregistered_configuration_sources": False,
        "external_environment_overrides": False,
        "operator_confirmed_configuration_complete": True,
        "credential_files_included": False,
        "remote_root_state_included": False,
        "image": {
            "image_id": image,
            "runtime_sha256": "b" * 64,
            "material": "identity_only",
            "archive_sha256": None,
        },
        "ssh_defense": None,
    }
    documents = {
        "compose.yaml": (ROOT / "deploy/observer/compose.yaml").read_bytes(),
        "compose.release.yaml": raw_json({"services": {"observer": {"image": image}}}),
        "observer.env": b"OPSARK_OBSERVE_HOSTS=node-a\nOPSARK_OBSERVE_INTERVAL=60\n",
        "secrets/inventory.toml": (
            '[credentials.collector]\nkey_file = "/run/opsark/node-a-key"\n'
            'known_hosts_file = "/run/opsark/known_hosts"\n\n'
            '[[hosts]]\nid = "node-a"\naddress = "192.0.2.10"\n'
            'username = "opsark-readonly"\ncredential = "collector"\n'
            'site_domain = "fixture.invalid"\n'
        ).encode("ascii"),
        "secrets/known_hosts": pin(port=22),
    }
    if registered:
        pins = {role: f"secrets/defense-{role}-known_hosts" for role in ROLES}
        plan["ssh_defense"] = {
            "inventory_file": "secrets/defense-targets.json",
            "policy_file": "secrets/defense-policy.json",
            "role_known_hosts_files": pins,
            "compose_file": "compose.defense.yaml",
        }
        plan["compose_files"].append("compose.defense.yaml")
        plan["configuration_files"].extend(
            ["secrets/defense-targets.json", "secrets/defense-policy.json", *pins.values()]
        )
        documents["compose.defense.yaml"] = raw_json(
            {
                "services": {
                    "observer": {
                        "environment": {
                            "OPSARK_DEFENSE_INVENTORY": "/run/opsark/defense-targets.json",
                            "OPSARK_DEFENSE_POLICY": "/run/opsark/defense-policy.json",
                            "OPSARK_DEFENSE_WORKER_ENABLED": "false",
                        }
                    }
                }
            }
        )
        record = {
            "root_scope_sha256": "1" * 64,
            "root_policy_sha256": POLICY_SHA256,
            "boot_ref": "2" * 64,
            "binding_ref": "3" * 64,
            "roles": {},
        }
        for role, name in pins.items():
            documents[name] = pin()
            record["roles"][role] = {
                "username": "opsark-defense-" + role,
                "key_file": f"/run/opsark/defense-{role}.key",
                "known_hosts_file": "/run/opsark/" + name.split("/")[-1],
                "trusted_hosts_digest": hashlib.sha256(documents[name]).hexdigest(),
            }
        documents["secrets/defense-targets.json"] = raw_json(
            {"schema_version": 1, "targets": {"node-a": record}}
        )
        grant = {
            "v": 1,
            "enabled": True,
            "grant_ref": "4" * 32,
            "issued_at": "2026-11-06T00:00:00Z",
            "expires_at": "2026-11-06T01:00:00Z",
            "host_ids": ["node-a"],
            "target_scope_sha256": {"node-a": record["root_scope_sha256"]},
            "target_policy_sha256": {"node-a": POLICY_SHA256},
            "windows": [{"weekdays": [4], "start_minute": 0, "end_minute": 1440}],
        }
        policy = {
            "v": 1,
            "enabled": True,
            "profile": "private-198.18.241.0/28",
            "action": "block-single-source",
            "ttl_ms": 60000,
            "source_aliases": ["fixture-a", "fixture-b"],
            "observation": grant,
            "execution": grant
            | {
                "grant_ref": "5" * 32,
                "root_grant_refs": {"node-a": "6" * 32},
                "boot_refs": {"node-a": record["boot_ref"]},
                "binding_refs": {"node-a": record["binding_ref"]},
                "wire_revisions": [2],
                "source_aliases": ["fixture-a"],
                "max_actions_per_day": 1,
                "max_total_actions": 1,
            },
            "ai": {
                "enabled": False,
                "provider_fingerprint": None,
                "max_analyses_per_day": 1,
                "max_total_analyses": 1,
                "requires_ai": True,
            },
        }
        documents["secrets/defense-policy.json"] = raw_json(policy)
    documents["handover.json"] = raw_json(plan)
    return plan, documents


def checked(plan, documents):
    documents = documents | {"handover.json": raw_json(plan)}
    parsed, names = archive.handover_plan(
        documents["handover.json"], expected_profile="observer-handover-v2"
    )
    assert parsed == plan
    defense.validate_bundle(parsed, documents)
    assert names == set(documents)


@pytest.mark.parametrize("registered", [False, True])
def test_explicit_null_and_registered_v2_are_closed(registered):
    plan, documents = bundle(registered=registered)
    before = copy.deepcopy(documents)
    checked(plan, documents)
    assert documents == before
    assert not any(name.endswith(".key") or "requests.json" in name for name in documents)
    assert defense.PROFILE == "observer-handover-v2"


def test_policy_fixture_also_satisfies_current_application_dto():
    _, documents = bundle()
    policy = DefensePolicy.model_validate_json(documents["secrets/defense-policy.json"])
    assert policy.execution is not None and policy.execution.max_total_actions == 1


def round_trip(history, tmp_path, monkeypatch, plan, documents):
    """Production content envelope, synthetic paths, complete SQLite history."""
    checked(plan, documents)
    all_bytes = {"stores/" + p.name: p.read_bytes() for p in history.snapshot.iterdir()}
    all_bytes.update({"config-original/" + name: raw for name, raw in documents.items()})
    rows = [
        {
            "name": name,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "permissions": {"synthetic": True},
        }
        for name, raw in sorted(all_bytes.items())
    ]
    manifest = archive.make_manifest("sb-" + "7" * 32, defense.PROFILE, rows, False)
    assert manifest["schema_version"] == 2
    proof = sealed._proof(manifest, "9" * 64, 12345)
    assert proof["schema_version"] == 2 and proof["configuration_included"]
    assert proof["inline_config_secrets_may_be_present"]
    assert not proof["credential_files_included"] and not proof["remote_root_state_included"]
    sources = {
        name: SimpleNamespace(handle=io.BytesIO(raw), verify=lambda: None)
        for name, raw in all_bytes.items()
    }
    buffer = io.BytesIO()
    archive.write_archive(buffer, manifest, sources)
    destination = tmp_path / "restored"
    destination.mkdir(mode=0o700)
    monkeypatch.setattr(sealed, "paths", OrdinaryFixturePaths)
    buffer.seek(0)
    assert sealed._extract_archive(buffer, destination) == manifest
    for name, expected in all_bytes.items():
        assert (destination / name).read_bytes() == expected
    assert (
        archive.strict_json((destination / "config-original/handover.json").read_bytes())[
            "compose_files"
        ]
        == plan["compose_files"]
    )
    restored = destination / "stores"
    assert transfer.verify_snapshot(restored)["database_count"] == 10
    expected_security = contents(history.snapshot / "security.sqlite3")
    recovered = DefenseStore(restored / "security.sqlite3")
    assert contents(recovered.path) == expected_security
    assert recovered.transaction(history.action.rid).query_required
    assert recovered.latched(history.action.context.host_id, history.action.context.defense_scope)
    assert recovered.ai_permit(analysis_id=history.permit.analysis_id) == history.permit
    assert recovered.usage(history.permit.intent_key).state == "unknown"
    assert (restored / "automation.sqlite3").read_bytes() == (
        history.snapshot / "automation.sqlite3"
    ).read_bytes()
    assert not list(destination.rglob("*.key"))
    assert not list(destination.rglob("access-token"))
    return destination


@pytest.mark.parametrize("registered", [False, True])
def test_v2_archive_round_trip_preserves_raw_order_history_and_never_activates(
    history, tmp_path, monkeypatch, registered
):
    round_trip(history, tmp_path, monkeypatch, *bundle(registered=registered))


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 1},
        {"schema_version": True},
        {"unknown": False},
        {"credential_files_included": True},
        {"remote_root_state_included": True},
        {"external_environment_overrides": True},
        {"operator_confirmed_configuration_complete": False},
        {"ssh_defense": {}},
        {"ssh_defense": True},
    ],
)
def test_handover_version_scope_and_unknown_fields_refused(change):
    plan, documents = bundle()
    plan.update(change)
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("field", ["inventory_file", "policy_file", "compose_file"])
def test_defense_artifact_paths_are_fixed(field):
    plan, documents = bundle()
    plan["ssh_defense"][field] = "../../outside"
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("role", ROLES)
def test_each_declared_pin_is_required_and_bound(role):
    plan, documents = bundle()
    del documents[f"secrets/defense-{role}-known_hosts"]
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("change", ["digest", "address", "private", "malformed", "wrong_algorithm"])
def test_public_pin_digest_endpoint_and_wire_shape_close(change):
    plan, documents = bundle()
    name = "secrets/defense-readonly-known_hosts"
    documents[name] = {
        "digest": documents[name] + b"\n",
        "address": pin("192.0.2.11"),
        "private": b"-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-only\n",
        "malformed": b"[192.0.2.10]:22423 ssh-ed25519 YWJj\n",
        "wrong_algorithm": pin().replace(b"ssh-ed25519 ", b"ssh-rsa "),
    }[change]
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "inline_key",
        "key_path",
        "pin_path",
        "root_user",
        "unregistered_host",
        "duplicate_address",
        "root_policy",
    ],
)
def test_registry_cannot_expand_identity_references_or_include_key_material(change):
    plan, documents = bundle()
    registry = json.loads(documents["secrets/defense-targets.json"])
    record = registry["targets"]["node-a"]
    role = record["roles"]["readonly"]
    if change == "unknown":
        registry["command"] = "synthetic-only"
    elif change == "inline_key":
        role["key"] = "synthetic-private-key"
    elif change == "key_path":
        role["key_file"] = "/elsewhere/customer.key"
    elif change == "pin_path":
        role["known_hosts_file"] = "/elsewhere/known_hosts"
    elif change == "root_user":
        role["username"] = "root"
    elif change == "unregistered_host":
        registry["targets"]["outside"] = registry["targets"].pop("node-a")
    elif change == "duplicate_address":
        registry["targets"]["alias"] = copy.deepcopy(record)
        documents["secrets/inventory.toml"] += (
            b'\n[[hosts]]\nid="alias"\naddress="192.0.2.10"\nusername="opsark-readonly"\n'
            b'credential="collector"\nsite_domain="fixture.invalid"\n'
        )
    else:
        record["root_policy_sha256"] = "0" * 64
    documents["secrets/defense-targets.json"] = raw_json(registry)
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize(
    "change",
    [
        "root_scope",
        "boot",
        "binding",
        "host_set",
        "ttl",
        "unknown",
        "grant_time",
        "window",
        "revision_bool",
        "source_alias",
        "quota",
    ],
)
def test_policy_grants_cannot_change_fixed_scope_time_or_budget_contract(change):
    plan, documents = bundle()
    policy = json.loads(documents["secrets/defense-policy.json"])
    execution = policy["execution"]
    if change == "root_scope":
        execution["target_scope_sha256"]["node-a"] = "0" * 64
    elif change == "boot":
        execution["boot_refs"]["node-a"] = "0" * 64
    elif change == "binding":
        execution["binding_refs"]["node-a"] = "0" * 64
    elif change == "host_set":
        execution["host_ids"] = ["outside"]
    elif change == "ttl":
        policy["ttl_ms"] = 60001
    elif change == "unknown":
        policy["shell"] = "synthetic-only"
    elif change == "grant_time":
        execution["expires_at"] = "2026-11-08T01:00:00Z"
    elif change == "window":
        execution["windows"][0]["end_minute"] = 0
    elif change == "revision_bool":
        execution["wire_revisions"] = [True]
    elif change == "source_alias":
        execution["source_aliases"] = ["outside"]
    else:
        execution["max_actions_per_day"] = 9
    documents["secrets/defense-policy.json"] = raw_json(policy)
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize(
    "raw",
    [
        b"OPSARK_AI_KEY=synthetic-only\n",
        b"OPSARK_AI_KEY=\n",
        b"OPSARK_TOKEN=synthetic-only\n",
        b"UNCLASSIFIED=synthetic-only\n",
        b"export OPSARK_OBSERVE_HOSTS=node-a\n",
        b"OPSARK_OBSERVE_HOSTS=$(synthetic)\n",
        b"OPSARK_OBSERVE_HOSTS=${OUTSIDE}\n",
        b"OPSARK_AI_KEY_FILE=../../customer.key\n",
        b"OPSARK_AI_BASE_URL=https://user:synthetic@provider.invalid/v1\n",
        b"OPSARK_OBSERVE_INTERVAL=60\nOPSARK_OBSERVE_INTERVAL=61\n",
    ],
)
def test_legacy_environment_is_preserved_as_opaque_bytes_and_never_interpreted(raw):
    plan, documents = bundle()
    documents["observer.env"] = raw
    before = copy.deepcopy(documents)
    checked(plan, documents)
    assert documents == before


@pytest.mark.parametrize(
    "which",
    ["base", "release_tag", "release_command", "defense_true", "defense_extra", "defense_yaml"],
)
def test_compose_is_audited_base_and_fixed_json_overlay_only(which):
    plan, documents = bundle()
    if which == "base":
        documents["compose.yaml"] += b"# changed custom source\n"
    elif which.startswith("release"):
        value = json.loads(documents["compose.release.yaml"])
        if which == "release_tag":
            value["services"]["observer"]["image"] = "synthetic:latest"
        else:
            value["services"]["observer"]["command"] = ["/bin/sh"]
        documents["compose.release.yaml"] = raw_json(value)
    elif which == "defense_yaml":
        documents["compose.defense.yaml"] = b"services:\n  observer:\n    privileged: true\n"
    else:
        value = json.loads(documents["compose.defense.yaml"])
        if which == "defense_true":
            value["services"]["observer"]["environment"]["OPSARK_DEFENSE_WORKER_ENABLED"] = "true"
        else:
            value["services"]["observer"]["environment"]["OPSARK_AI_KEY"] = "synthetic-only"
        documents["compose.defense.yaml"] = raw_json(value)
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("which", ["registry", "policy", "overlay"])
def test_duplicate_json_fields_are_not_silently_collapsed(which):
    plan, documents = bundle()
    name = {
        "registry": "secrets/defense-targets.json",
        "policy": "secrets/defense-policy.json",
        "overlay": "compose.defense.yaml",
    }[which]
    raw = documents[name]
    documents[name] = b'{"unknown":1,"unknown":2,' + raw.lstrip()[1:]
    with pytest.raises(ValueError):
        checked(plan, documents)


def test_v1_does_not_accept_v2_record_or_new_members():
    plan, documents = bundle()
    with pytest.raises(ValueError):
        archive.handover_plan(raw_json(plan), expected_profile="observer-handover-v1")
    legacy = copy.deepcopy(plan)
    legacy["schema_version"] = 1
    del legacy["ssh_defense"]
    with pytest.raises(ValueError):
        archive.handover_plan(raw_json(legacy), expected_profile="observer-handover-v1")
    # A forged v1 outer header must not widen its member allowlist either.
    members = {"stores/manifest.json": b"{}"}
    members.update({"stores/" + name: b"synthetic" for name in archive.DATABASES})
    members.update({"config-original/" + name: raw for name, raw in documents.items()})
    rows = [
        {
            "name": name,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "permissions": {},
        }
        for name, raw in members.items()
    ]
    with pytest.raises(ValueError):
        archive.make_manifest("sb-" + "2" * 32, "observer-handover-v1", rows, False)


def test_unregistered_documents_and_partial_defense_cannot_claim_complete():
    plan, documents = bundle(registered=False)
    documents["secrets/defense-policy.json"] = b"{}"
    with pytest.raises(ValueError):
        defense.validate_bundle(plan, documents)
    plan, documents = bundle()
    plan["configuration_files"].remove("secrets/defense-policy.json")
    del documents["secrets/defense-policy.json"]
    with pytest.raises(ValueError):
        checked(plan, documents)


def test_valid_bundle_never_opens_referenced_credentials(monkeypatch):
    plan, documents = bundle()
    documents["observer.env"] += (
        b"OPSARK_AI_KEY_FILE=/run/opsark/provider-api-key\n"
        b"OPSARK_AI_PROVIDER=openai\nOPSARK_AI_BASE_URL=https://provider.invalid/v1\n"
        b"OPSARK_AI_MODEL=synthetic-model\n"
    )

    def refuse_read(*_args, **_kwargs):
        raise AssertionError("No filesystem lookup is permitted during in-memory validation")

    # Restore global pathlib before pytest formats a possible failure; otherwise
    # the framework's own traceback/cache inspection would also be intercepted.
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", refuse_read)
        patch.setattr(Path, "read_bytes", refuse_read)
        patch.setattr(Path, "stat", refuse_read)
        patch.setattr(Path, "lstat", refuse_read)
        defense.validate_bundle(plan, documents)


def test_new_defense_pin_cannot_add_an_unregistered_endpoint_even_with_updated_digest():
    plan, documents = bundle()
    name = "secrets/defense-readonly-known_hosts"
    documents[name] += pin("192.0.2.99")
    value = json.loads(documents["secrets/defense-targets.json"])
    value["targets"]["node-a"]["roles"]["readonly"]["trusted_hosts_digest"] = hashlib.sha256(
        documents[name]
    ).hexdigest()
    documents["secrets/defense-targets.json"] = raw_json(value)
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("literal", ["3221225994", "true", '"192.0.2.10\\n"'])
def test_inventory_ip_must_be_literal_text_not_a_coerced_integer_or_boolean(literal):
    plan, documents = bundle()
    documents["secrets/inventory.toml"] = documents["secrets/inventory.toml"].replace(
        b'address = "192.0.2.10"', ("address = " + literal).encode()
    )
    with pytest.raises(ValueError):
        checked(plan, documents)


@pytest.mark.parametrize("value", [True, False, 0, 1, "False", "0", ""])
def test_worker_overlay_accepts_only_literal_string_false(value):
    plan, documents = bundle()
    overlay = json.loads(documents["compose.defense.yaml"])
    overlay["services"]["observer"]["environment"]["OPSARK_DEFENSE_WORKER_ENABLED"] = value
    documents["compose.defense.yaml"] = raw_json(overlay)
    with pytest.raises(ValueError):
        checked(plan, documents)


def test_v1_record_stays_compatible_and_v2_never_rewrites_expired_grants():
    plan, documents = bundle(registered=False)
    legacy = copy.deepcopy(plan)
    legacy["schema_version"] = 1
    del legacy["ssh_defense"]
    parsed, names = archive.handover_plan(raw_json(legacy), expected_profile="observer-handover-v1")
    assert parsed == legacy and names == set(documents)
    plan, documents = bundle()
    policy = json.loads(documents["secrets/defense-policy.json"])
    for grant in (policy["observation"], policy["execution"]):
        grant["issued_at"] = "2020-01-01T00:00:00Z"
        grant["expires_at"] = "2020-01-01T01:00:00Z"
    documents["secrets/defense-policy.json"] = raw_json(policy)
    before = copy.deepcopy(documents)
    checked(plan, documents)
    assert documents == before


@pytest.mark.parametrize("registered", [False, True])
def test_known_source_crlf_and_registered_empty_env_are_preserved(registered):
    plan, documents = bundle(registered=registered)
    documents["compose.yaml"] = (
        documents["compose.yaml"].replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    )
    documents["observer.env"] = b""
    before = copy.deepcopy(documents)
    checked(plan, documents)
    assert documents == before


@pytest.mark.parametrize("opaque_legacy_extension", [False, True])
def test_apt_and_defense_co_deployment_keeps_old_raw_configuration_without_activation(
    history, tmp_path, monkeypatch, opaque_legacy_extension
):
    plan, documents = bundle()
    plan["configuration_files"].extend(
        ["secrets/patch-targets.json", "secrets/automation-policy.json"]
    )
    documents["secrets/patch-targets.json"] = (
        b' { "schema_version" : 1, "targets" : { "node-a" : {\r\n'
        b' "key_file" : "/run/opsark/synthetic-apt-inline-canary.key",\r\n'
        b' "policy_digest" : "' + b"b" * 64 + b'" } } } \r\n'
    )
    legacy_policy = {
        "enabled": False,
        "host_ids": ["node-a"],
        "allowed_actions": ["os_security_upgrade"],
        "allowed_packages": ["synthetic-inline-canary"],
    }
    # One sample is an actual current ControlPolicy. The other deliberately
    # includes an opaque legacy extension: backup must preserve it rather than
    # pretend to validate or activate that application's deployment semantics.
    assert not ControlPolicy.model_validate(legacy_policy).enabled
    if opaque_legacy_extension:
        legacy_policy["legacy_opaque"] = "SYNTHETIC-OLD-INLINE-CANARY"
    documents["secrets/automation-policy.json"] = b" \r\n" + raw_json(legacy_policy) + b" \r\n"
    documents["observer.env"] += (
        b"OPSARK_PATCH_INVENTORY=/run/opsark/patch-targets.json\r\n"
        b"OPSARK_AUTOMATION_POLICY=/run/opsark/automation-policy.json\r\n"
        b"OPSARK_AI_KEY=fakeOnly-inline-canary\r\n"
        b"UNKNOWN_OLD_CONFIGURATION='quoted $VALUE $(never-run)'\r\n"
    )
    documents["secrets/inventory.toml"] += (
        '\nname="中文测试节点"\nhealth_checks=[]\nlegacy_metadata="SYNTHETIC-OLD-INLINE-CANARY"\n'
    ).encode()
    documents["secrets/known_hosts"] += (
        b"# Existing collector trust retains unrelated original entries.\r\n"
        + pin("192.0.2.99", port=22)
    )
    documents["handover.json"] = raw_json(plan)
    original = copy.deepcopy(documents)
    # Only in-memory config bytes are inspected. In particular the APT key,
    # three role keys and provider key are not stat'ed or opened by validation.
    with monkeypatch.context() as patch:

        def refuse_reference(*_args, **_kwargs):
            raise AssertionError("A referenced credential was consulted")

        patch.setattr(Path, "open", refuse_reference)
        patch.setattr(Path, "stat", refuse_reference)
        patch.setattr(Path, "lstat", refuse_reference)
        checked(plan, documents)
    assert documents == original
    destination = round_trip(history, tmp_path, monkeypatch, plan, documents)
    for name, raw in original.items():
        assert (destination / "config-original" / name).read_bytes() == raw
    assert b"fakeOnly-inline-canary" in (destination / "config-original/observer.env").read_bytes()
    assert not list(destination.rglob("synthetic-apt-inline-canary.key"))


def test_existing_collector_trust_is_raw_while_new_defense_trust_stays_strict():
    plan, documents = bundle()
    documents["secrets/known_hosts"] += b"# old collector source is not reclassified\r\n" + pin(
        "192.0.2.99", port=22
    )
    original = copy.deepcopy(documents)
    checked(plan, documents)
    assert documents == original
