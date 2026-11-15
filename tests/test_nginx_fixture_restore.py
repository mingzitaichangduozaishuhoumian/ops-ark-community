"""Exercise isolated restore authorization, exact disk identity and durable replay behavior."""

import importlib
import json
import os
import stat
import sys
from datetime import timedelta

import pytest
from test_nginx_fixture_action import (
    CREATED,
    IMAGE,
    OTHER_RUNTIME,
    RUNTIME,
    Interrupted,
    apply,
    observe,
    reconcile,
    unexpected,
)
from test_nginx_fixture_action import (
    fixture_lab as fixture_lab,
)
from test_nginx_fixture_action import (
    module as module,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux fixture trust rules")


@pytest.fixture
def restore_module(fixture_lab, monkeypatch):
    restore = importlib.import_module("deploy.nginx.fixture_restore")
    calls = []

    def syntax(data, image):
        assert data == fixture_lab.action.ORIGINAL and image == IMAGE
        calls.append("original syntax")
        return "passed"

    monkeypatch.setattr(restore.config_snapshot, "_docker_syntax", syntax)
    return restore, calls


def apply_candidate(lab, callback=lambda: True):
    return apply(lab, callback, preflight=lambda: True, runtime_fingerprint=lambda: RUNTIME)


def approve(lab, restore, *, output=None, **overrides):
    options = {
        "runtime_fingerprint": lambda: RUNTIME,
        "verify_candidate": lambda: True,
        "now": CREATED,
        "confirm": True,
        **overrides,
    }
    return restore.approve_restore(
        lab.workspace,
        lab.id,
        lab.approval,
        restore._ORIGINAL_SHA256,
        output or lab.workspace / "restore-approval",
        **options,
    )


def execute(lab, restore, receipt, callback=lambda: True, **overrides):
    options = {
        "runtime_fingerprint": lambda: RUNTIME,
        "verify_candidate": lambda: True,
        "now": CREATED,
        "confirm": True,
        **overrides,
    }
    return restore.restore_fixture(
        lab.workspace,
        lab.workspace / "restore-approval",
        receipt["approval_id"],
        receipt["original_sha256"],
        reload_and_verify=callback,
        **options,
    )


def inspect(lab, restore, **overrides):
    options = {
        "runtime_fingerprint": lambda: RUNTIME,
        "verify_candidate": lambda: True,
        "now": CREATED,
        **overrides,
    }
    return restore.inspect_restore_approval(
        lab.workspace, lab.workspace / "restore-approval", **options
    )


def test_restore_has_a_separate_approval_and_immutable_single_use_action(
    fixture_lab, restore_module
):
    lab = fixture_lab
    restore, syntax = restore_module
    applied = apply_candidate(lab)
    original_records = {p: p.read_bytes() for p in (lab.workspace / "actions").glob("*.json")}
    approval = approve(lab, restore)
    assert syntax == ["original syntax"] and lab.site.read_bytes() == lab.action.CANDIDATE
    assert (
        approval["restore_action_id"]
        == restore.restore_action_id(lab.workspace, lab.workspace / "restore-approval")
        != applied["action_id"]
    )
    assert inspect(lab, restore) == approval
    assert str(lab.workspace) not in json.dumps(approval)
    assert "opsark-original" not in json.dumps(approval)
    receipt_path = lab.workspace / "restore-approval/restore-approval.json"
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600

    before = lab.site.stat()
    calls = []

    def reload():
        calls.append("reload")
        assert lab.site.read_bytes() == lab.action.ORIGINAL
        assert observe(lab, approval["restore_action_id"])["status"] == "unknown"
        return True

    result = execute(lab, restore, approval, reload)
    restored = lab.site.stat()
    assert result["status"] == "verified" and result["disk_status"] == "preimage"
    assert result["action"] == "restore" and result["action_id"] == approval["restore_action_id"]
    assert stat.S_IMODE(restored.st_mode) == stat.S_IMODE(before.st_mode)
    assert (restored.st_uid, restored.st_gid) == (before.st_uid, before.st_gid)
    assert restored.st_ino != before.st_ino
    assert {p: p.read_bytes() for p in original_records} == original_records
    assert observe(lab)["status"] == "verified"
    assert inspect(lab, restore)["approval_status"] == "consumed"
    assert (
        execute(
            lab,
            restore,
            approval,
            unexpected,
            runtime_fingerprint=unexpected,
            verify_candidate=unexpected,
            now=CREATED + timedelta(hours=1),
        )
        == result
    )
    assert calls == ["reload"] and lab.site.stat().st_ino == restored.st_ino


@pytest.mark.parametrize(
    "reason", ["no_confirm", "different_runtime", "same_bytes_other_inode", "bad_backup"]
)
def test_restore_approval_refuses_unproven_inputs_before_isolated_syntax(
    fixture_lab, restore_module, reason
):
    lab = fixture_lab
    restore, syntax = restore_module
    apply_candidate(lab)
    options = {"verify_candidate": unexpected}
    if reason == "no_confirm":
        options["confirm"] = False
    elif reason == "different_runtime":
        options["runtime_fingerprint"] = lambda: OTHER_RUNTIME
    elif reason == "same_bytes_other_inode":
        replacement = lab.site.with_suffix(".replacement")
        replacement.write_bytes(lab.action.CANDIDATE)
        replacement.chmod(0o640)
        os.replace(replacement, lab.site)
    else:
        (lab.backup / "nginx.conf").write_bytes(b"unreviewed content")
    with pytest.raises(restore.config_snapshot.SnapshotError):
        approve(lab, restore, **options)
    assert not syntax
    assert not (lab.workspace / "restore-approval").exists()
    assert lab.site.read_bytes() == lab.action.CANDIDATE


def test_reconciled_apply_can_restore_but_interruption_never_reloads_again(
    fixture_lab, restore_module
):
    lab = fixture_lab
    restore, _syntax = restore_module
    assert apply_candidate(lab, lambda: False)["status"] == "unknown"
    with pytest.raises(restore.config_snapshot.SnapshotError):
        approve(lab, restore, verify_candidate=unexpected)
    assert reconcile(lab, lambda: True)["reconciliation_status"] == "verified"
    approval = approve(lab, restore)
    assert observe(lab)["status"] == "unknown"

    def interrupt():
        assert lab.site.read_bytes() == lab.action.ORIGINAL
        raise Interrupted

    with pytest.raises(Interrupted):
        execute(lab, restore, approval, interrupt)
    result = observe(lab, approval["restore_action_id"])
    assert result["status"] == "unknown" and result["disk_status"] == "preimage"
    assert execute(lab, restore, approval, unexpected, verify_candidate=unexpected) == result
    original = observe(lab)
    assert original["status"] == "unknown" and original["reconciliation_status"] == "verified"


def test_expired_or_mutated_restore_receipt_does_not_admit_writes(fixture_lab, restore_module):
    lab = fixture_lab
    restore, _syntax = restore_module
    apply_candidate(lab)
    approval = approve(lab, restore)
    expiry = CREATED + timedelta(minutes=5)
    assert (
        inspect(lab, restore, now=expiry, verify_candidate=unexpected)["approval_status"]
        == "expired"
    )
    with pytest.raises(restore.config_snapshot.SnapshotError):
        execute(lab, restore, approval, unexpected, now=expiry, verify_candidate=unexpected)
    approval_file = lab.workspace / "restore-approval/restore-approval.json"
    approval_file.write_text("tampered")
    assert inspect(lab, restore, verify_candidate=unexpected)["approval_status"] == "tampered"
    assert observe(lab, approval["restore_action_id"])["status"] == "missing"
    assert lab.site.read_bytes() == lab.action.CANDIDATE


def test_restore_refuses_same_bytes_on_new_inode_after_approval(fixture_lab, restore_module):
    lab = fixture_lab
    restore, _syntax = restore_module
    apply_candidate(lab)
    approval = approve(lab, restore)
    replacement = lab.site.with_suffix(".replacement")
    replacement.write_bytes(lab.action.CANDIDATE)
    replacement.chmod(0o640)
    os.replace(replacement, lab.site)
    new_inode = lab.site.stat().st_ino
    with pytest.raises(restore.config_snapshot.SnapshotError):
        execute(lab, restore, approval, unexpected, verify_candidate=unexpected)
    assert inspect(lab, restore, verify_candidate=unexpected)["approval_status"] == "drift"
    assert observe(lab, approval["restore_action_id"])["status"] == "missing"
    assert lab.site.stat().st_ino == new_inode and lab.site.read_bytes() == lab.action.CANDIDATE


def test_restore_runtime_change_during_reload_keeps_unknown_result(fixture_lab, restore_module):
    lab = fixture_lab
    restore, _syntax = restore_module
    apply_candidate(lab)
    approval = approve(lab, restore)
    runtime = RUNTIME

    def reload():
        nonlocal runtime
        assert lab.site.read_bytes() == lab.action.ORIGINAL
        runtime = OTHER_RUNTIME
        return True

    result = execute(lab, restore, approval, reload, runtime_fingerprint=lambda: runtime)
    assert result["status"] == "unknown" and result["disk_status"] == "preimage"
    assert observe(lab)["status"] == "verified"
    assert execute(lab, restore, approval, unexpected, runtime_fingerprint=unexpected) == result
