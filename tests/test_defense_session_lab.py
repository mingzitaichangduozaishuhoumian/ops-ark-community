"""Synthetic filesystem/dispatch checks only; no SSH, Docker, model or server I/O."""

import copy
import hashlib
import io
import json
import shutil
from contextlib import contextmanager
from pathlib import Path

import pytest
import ssh_defense_session_lab as lab


@pytest.fixture
def filesystem(monkeypatch):
    monkeypatch.setattr(
        lab.base, "read_json", lambda path, limit=8192: json.loads(path.read_bytes())
    )
    monkeypatch.setattr(
        lab.base,
        "write_new",
        lambda path, value: path.open("xb").write(lab.native.canonical(value) + b"\n"),
    )
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit: path.read_bytes())
    monkeypatch.setattr(lab, "sync_directory", lambda directory: None)

    def copy_source(source, destination, **_kwargs):
        assert not destination.exists()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    monkeypatch.setattr(lab.business, "copy_source", copy_source)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(lab.native.canonical(value) + b"\n")


def authority(directory, profile):
    metadata = lab.profile_metadata(profile)
    deployment = {
        "defense_grants": [
            {"mode": "auto", "mode_revision": 2, "max_uses": 1, "source_aliases": ["fixture-a"]}
        ]
    }
    write(directory / lab.PROFILE_FILE, metadata)
    write(directory / "deployment.json", deployment)
    write(directory / "lab-case.json", {"case": metadata["fixture_case"]})
    return metadata, deployment


@pytest.mark.parametrize(
    "profile,case,ack",
    [
        ("auto-ack", "root-auto", "direct_ack"),
        ("auto-apply-loss", lab.native.SOCKET_CASE, "exact_apply_socket_loss"),
    ],
)
def test_profiles_bind_real_auto_authority_and_distinct_transport(profile, case, ack):
    metadata = lab.profile_metadata(profile)
    assert metadata["grant_mode"] == "auto" and metadata["wire_revision"] == 2
    assert metadata["max_uses"] == 1
    assert metadata["fixture_case"] == case and metadata["ack_behavior"] == ack
    unsigned = {key: value for key, value in metadata.items() if key != "session_profile_sha256"}
    assert metadata["session_profile_sha256"] == lab.native.digest(unsigned)
    assert (case in lab.native.FAULT_CASES) is (profile == "auto-apply-loss")


@pytest.mark.parametrize(
    "change",
    [
        {"session_profile": "semi"},
        {"grant_mode": "semi"},
        {"wire_revision": True},
        {"wire_revision": 3},
        {"max_uses": True},
        {"max_uses": 2},
        {"ack_behavior": "exact_apply_socket_loss"},
        {"fixture_case": lab.native.SOCKET_CASE},
        {"session_profile_sha256": "0" * 64},
        {"unclassified": "private"},
    ],
)
def test_profile_rejects_modified_types_semantics_and_unknown_fields(change):
    with pytest.raises(lab.native.LabError):
        lab.validate_profile(lab.profile_metadata("auto-ack") | change)


@pytest.mark.parametrize("profile", tuple(lab.PROFILES))
def test_fresh_factory_once_preserves_deployment_and_seals_before_runtime(
    tmp_path, monkeypatch, filesystem, profile
):
    root = Path(lab.__file__).resolve().parents[1]
    calls = []
    original_deployment = []
    old_stage_paths = {"tests/ssh_defense_controller_lab.py", "tests/ssh_defense_business_lab.py"}
    old_stage_paths |= {"deploy/readonly/" + name for name in lab.business.READONLY_SHA256}

    def native_stage(workspace, case):
        calls.append(case)
        directories = [
            workspace / name
            for name in ("code", "client", "management", "authority", "ready", "state")
        ]
        for directory in directories:
            directory.mkdir()
        code, _keys, _management, auth, *_ = directories
        for relative in set(lab.FROZEN_SOURCE_SHA256) - old_stage_paths:
            destination = code / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, destination)
        _meta, deployment = authority(auth, "auto-ack")
        (auth / lab.PROFILE_FILE).unlink()  # Native factory does not know the new profile.
        original_deployment.append((auth / "deployment.json").read_bytes())
        return (*directories, deployment, {"root": "synthetic"})

    def business_stage(workspace, _policy):
        staged = lab.native.stage(workspace, lab.native.SOCKET_CASE)
        code, _keys, _management, auth, *_ = staged
        # This must already be sealed before even collector provisioning begins.
        assert lab.read_profile(auth)["session_profile"] == profile
        for relative in old_stage_paths - {"tests/ssh_defense_business_lab.py"}:
            destination = code / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, destination)
        return staged

    monkeypatch.setattr(lab.native, "stage", native_stage)
    monkeypatch.setattr(lab.business, "stage_business", business_stage)
    expected = lab.profile_metadata(profile)
    staged = lab.stage_session(tmp_path, tmp_path / "fake-policy", expected)
    code, _keys, _management, auth, *_ = staged
    assert calls == ["root-auto"]
    assert (auth / "deployment.json").read_bytes() == original_deployment[0]
    assert lab.validate_authority(auth, expected) == staged[6]
    assert len(lab.verify_source_closure(code)) == 15
    assert not any(staged[5].iterdir())
    # Reusing a workspace must fail before another grant is issued.
    with pytest.raises(lab.native.LabError):
        lab.stage_session(tmp_path, tmp_path / "fake-policy", expected)
    assert calls == ["root-auto"]


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "semi"},
        {"mode_revision": True},
        {"max_uses": 2},
        {"source_aliases": ["foreign"]},
    ],
)
def test_sealed_authority_rejects_mutated_grant(tmp_path, filesystem, change):
    metadata, deployment = authority(tmp_path, "auto-ack")
    deployment["defense_grants"][0].update(change)
    write(tmp_path / "deployment.json", deployment)
    with pytest.raises(lab.native.LabError):
        lab.validate_authority(tmp_path, metadata)


def test_sealed_authority_rejects_profile_switch_and_fault_on_ack(tmp_path, filesystem):
    metadata, _ = authority(tmp_path, "auto-ack")
    with pytest.raises(lab.native.LabError):
        lab.validate_authority(tmp_path, lab.profile_metadata("auto-apply-loss"))
    write(tmp_path / "lab-case.json", {"case": lab.native.SOCKET_CASE})
    with pytest.raises(lab.native.LabError):
        lab.validate_authority(tmp_path, metadata)


def test_frozen_old_fourteen_sources_and_exact_bounds_remain_unchanged():
    root = Path(lab.__file__).resolve().parents[1]
    assert len(lab.FROZEN_SOURCE_SHA256) == 14
    for relative, expected in lab.FROZEN_SOURCE_SHA256.items():
        raw = (root / relative).read_bytes()
        assert b"\r\n" not in raw and hashlib.sha256(raw).hexdigest() == expected
    assert (lab.base.LIFETIME_SECONDS, lab.base.WORK_SECONDS, lab.base.CLEANUP_SECONDS) == (
        600,
        480,
        120,
    )
    assert lab.base.MAX_COMMANDS == 16
    assert lab.native.SUBNET == "198.18.241.0/28"
    assert lab.native.ADDRESSES == {
        "candidate": "198.18.241.3",
        "management": "198.18.241.4",
        "alternate": "198.18.241.5",
    }
    assert lab.business.STATE_PROFILE["target_bind_count"] == 3
    assert lab.business.STATE_PROFILE["container_restart_supported"] is False


def test_bound_entrypoint_restores_all_three_modules_after_error():
    before = [module.SELF for module in (lab.business, lab.base, lab.native)]
    with pytest.raises(RuntimeError), lab.bound_entrypoint():
        assert all(module.SELF == lab.SELF for module in (lab.business, lab.base, lab.native))
        raise RuntimeError("fake")
    assert [module.SELF for module in (lab.business, lab.base, lab.native)] == before


@pytest.mark.parametrize("profile", tuple(lab.PROFILES))
def test_internal_projection_uses_frozen_profile_and_original_projection(
    tmp_path, monkeypatch, filesystem, profile
):
    metadata, _ = authority(tmp_path, profile)
    calls = []
    monkeypatch.setattr(lab.native, "AUTHORITY", str(tmp_path))
    monkeypatch.setattr(lab.native, "internal_modules", lambda: calls.append("gate"))
    monkeypatch.setattr(lab.base, "internal_projection", lambda: calls.append("projection") or 0)
    assert lab.internal_dispatch("projection", "fake") == 0
    assert calls == ["gate", "projection"]
    assert lab.read_profile(tmp_path) == metadata


@pytest.mark.parametrize("entry", ["control_wrapper", "ss_close", "fault_proof"])
def test_direct_ack_has_no_internal_fault_entrypoints(tmp_path, monkeypatch, filesystem, entry):
    authority(tmp_path, "auto-ack")
    monkeypatch.setattr(lab.native, "AUTHORITY", str(tmp_path))
    monkeypatch.setattr(lab.native, "internal_modules", lambda: None)
    monkeypatch.setattr(lab.base, "controller_control_wrapper", lambda: pytest.fail("fault ran"))
    with pytest.raises(lab.native.LabError):
        lab.internal_dispatch(entry, "fake")


def test_loss_uses_unchanged_identity_bound_wrapper(tmp_path, monkeypatch, filesystem):
    authority(tmp_path, "auto-apply-loss")
    monkeypatch.setattr(lab.native, "AUTHORITY", str(tmp_path))
    monkeypatch.setattr(lab.native, "internal_modules", lambda: None)
    calls = []
    monkeypatch.setattr(lab.base, "controller_control_wrapper", lambda: calls.append("old") or 23)
    assert lab.internal_dispatch("control_wrapper", "fake") == 23
    assert calls == ["old"]


@pytest.mark.parametrize("operation", ["status", "snapshot", "stimulate", "stop"])
def test_existing_cli_refuses_profile_replacement_before_any_server_action(
    tmp_path, monkeypatch, operation, capsys
):
    monkeypatch.setattr(lab, "existing_profile", lambda root: pytest.fail("read existing stage"))
    assert (
        lab.main(
            [
                operation,
                "--root",
                str(tmp_path),
                "--image",
                "sha256:" + "a" * 64,
                "--confirm-isolated",
                "--session-profile",
                "auto-ack",
            ]
        )
        == 1
    )
    assert "could not be confirmed" in capsys.readouterr().err


@pytest.mark.parametrize("profile", tuple(lab.PROFILES))
def test_proof_transport_labels_do_not_claim_ack_or_service_acceptance(
    monkeypatch, profile, filesystem
):
    output = io.BytesIO()
    proof = lab.ProfileProof(output, lab.profile_metadata(profile))
    proof.write(lab.native.canonical({"completed": True, "console_and_ai_verified": False}))
    value = json.loads(output.getvalue())
    assert value["schema"] == "opsark-session-controller-fixture-proof/v1"
    assert value["ack_behavior"] == lab.PROFILES[profile]
    assert value["console_and_ai_verified"] is False
    assert "ack_accepted" not in value
    assert len(value["source_sha256"]) == 15
    with pytest.raises(lab.native.LabError):
        proof.write(b"{}")


def test_existing_ready_profile_bound_to_original_root_and_authority(
    tmp_path, monkeypatch, filesystem
):
    metadata, _ = authority(tmp_path / "fresh/authority", "auto-ack")
    write(tmp_path / lab.PROFILE_FILE, metadata)
    root = Path(lab.__file__).resolve().parents[1]
    closure = lab.verify_source_closure(root)
    monkeypatch.setattr(lab, "verify_source_closure", lambda path: closure)
    ready = metadata | {
        "schema": "opsark-controller-fixture-ready/v1",
        "workspace": str(tmp_path / "fresh"),
        "source_sha256": closure,
    }
    write(tmp_path / "controller-ready.json", ready)
    assert lab.existing_profile(tmp_path) == metadata
    altered = copy.deepcopy(ready)
    altered["workspace"] = str(tmp_path.parent / "foreign")
    write(tmp_path / "controller-ready.json", altered)
    with pytest.raises(lab.native.LabError):
        lab.existing_profile(tmp_path)


def test_stopped_original_mailbox_remains_readable_without_recreating_authority(
    tmp_path, monkeypatch, filesystem
):
    metadata = lab.profile_metadata("auto-apply-loss")
    write(tmp_path / lab.PROFILE_FILE, metadata)
    closure = {"synthetic": "a" * 64}
    monkeypatch.setattr(lab, "verify_source_closure", lambda path: closure)
    write(
        tmp_path / "controller-ready.json",
        metadata
        | {
            "schema": "opsark-controller-fixture-ready/v1",
            "workspace": str(tmp_path / "removed-owned-workspace"),
            "source_sha256": closure,
        },
    )
    write(tmp_path / "supervisor.json", {"synthetic": True})
    monkeypatch.setattr(lab.business, "supervisor_alive", lambda record: False)
    assert lab.existing_profile(tmp_path) == metadata
    assert not (tmp_path / "removed-owned-workspace").exists()
    monkeypatch.setattr(lab.business, "supervisor_alive", lambda record: True)
    with pytest.raises(lab.native.LabError):
        lab.existing_profile(tmp_path)


def test_existing_ready_source_change_and_cross_profile_are_rejected(
    tmp_path, monkeypatch, filesystem
):
    metadata, _ = authority(tmp_path / "fresh/authority", "auto-ack")
    write(tmp_path / lab.PROFILE_FILE, metadata)
    monkeypatch.setattr(lab, "verify_source_closure", lambda path: {"fake": "a" * 64})
    ready = metadata | {
        "schema": "opsark-controller-fixture-ready/v1",
        "workspace": str(tmp_path / "fresh"),
        "source_sha256": {"fake": "b" * 64},
    }
    write(tmp_path / "controller-ready.json", ready)
    with pytest.raises(lab.native.LabError):
        lab.existing_profile(tmp_path)
    ready["source_sha256"] = {"fake": "a" * 64}
    ready.update(
        {
            key: value
            for key, value in lab.profile_metadata("auto-apply-loss").items()
            if key != "schema"
        }
    )
    write(tmp_path / "controller-ready.json", ready)
    with pytest.raises(lab.native.LabError):
        lab.existing_profile(tmp_path)


def test_serve_seals_profile_before_old_runtime_and_preserves_ready_deployment_index(
    tmp_path, monkeypatch, filesystem
):
    monkeypatch.setattr(lab.native, "require_root", lambda root: None)
    monkeypatch.setattr(lab, "verify_source_closure", lambda root: {"fake": "a" * 64})
    calls = []
    metadata, deployment = authority(tmp_path / "fresh/authority", "auto-ack")
    monkeypatch.setattr(lab.business, "ready_value", lambda *args: {"fixture_id": "fake"})

    @contextmanager
    def original_proof(root, proof):
        yield io.BytesIO()

    monkeypatch.setattr(lab.native, "proof_file", original_proof)

    def original_serve(root, image, proof, policy):
        assert lab.read_profile(root) == metadata
        calls.append((image, proof, policy))
        value = lab.business.ready_value(
            root, root / "fresh", None, None, None, "pin", deployment, {"root": "fake"}, {}, {}
        )
        assert value["session_profile"] == "auto-ack"
        assert value["schema"] == "opsark-controller-fixture-ready/v1"
        assert value["fault_scope"] == "none_direct_ack"
        assert lab.native.SELF == lab.SELF
        return 0

    monkeypatch.setattr(lab.business, "serve", original_serve)
    assert (
        lab.serve(tmp_path, "fake", tmp_path / "proof.json", tmp_path / "policy.json", "auto-ack")
        == 0
    )
    assert len(calls) == 1
    with pytest.raises(lab.native.LabError):
        lab.serve(tmp_path, "fake", tmp_path / "other.json", tmp_path / "policy.json", "auto-ack")
    assert len(calls) == 1
