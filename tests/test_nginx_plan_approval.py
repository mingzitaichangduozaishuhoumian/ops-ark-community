"""Exercise local Nginx approval without Docker, a service action, or a real target."""

import json
import re
import stat
import sys
from datetime import timedelta

import pytest
from test_nginx_config_plan import CREATED, PLAN_CANARY, inspect, prepare
from test_nginx_config_plan import plan_files as plan_files
from test_nginx_config_snapshot import CANARY, CONTENT, snapshot_tool
from test_nginx_config_snapshot import tree as tree
from test_nginx_plan_validation import IMAGE, LAB_CANDIDATE
from test_nginx_plan_validation import prepared_lab as prepared_lab

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux directory and file trust rules"
)


def approve(files, output, **overrides):
    plan = inspect(files)
    options = {
        "expected_plan_id": plan["plan_id"],
        "expected_candidate_sha256": plan["candidate_sha256"],
        "confirm": True,
        "policy": files.policy,
        "now": CREATED,
        **overrides,
    }
    return snapshot_tool.approve_plan(files.output, IMAGE, output=output, **options)


def record_inputs(files):
    paths = [files.source, files.candidate, *files.output.iterdir(), *files.backup.iterdir()]
    return {path: path.read_bytes() for path in paths}


def test_approval_is_private_and_requires_a_fresh_exact_syntax_check(
    prepared_lab, monkeypatch, capsys
):
    files = prepared_lab
    approval = files.output.parent / "approval"
    calls = []
    before = record_inputs(files)
    source_stat = files.source.stat()

    def syntax(data, image):
        calls.append((data, image))
        return "passed"

    def unexpected_process(*_args, **_options):
        pytest.fail("approval attempted an unmocked subprocess or service action")

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", syntax)
    monkeypatch.setattr(snapshot_tool.subprocess, "run", unexpected_process)
    result = approve(files, approval)
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    assert result == snapshot_tool.inspect_approval(approval, policy=files.policy, now=CREATED)
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    plan = inspect(files)
    assert result == {
        "schema_version": 1,
        "approval_status": "approved",
        "syntax_status": "passed",
        "approval_id": result["approval_id"],
        "plan_id": plan["plan_id"],
        "candidate_sha256": plan["candidate_sha256"],
        "image_sha256": IMAGE,
        "expires_at": plan["expires_at"],
    }
    assert re.fullmatch(r"[0-9a-f]{32}", result["approval_id"])
    assert plan["approval_status"] == "not_approved"
    assert record_inputs(files) == before
    assert files.source.stat().st_ino == source_stat.st_ino
    assert files.source.stat().st_mtime_ns == source_stat.st_mtime_ns
    assert {path.name for path in approval.iterdir()} == {"approval.json"}
    assert stat.S_IMODE(approval.stat().st_mode) == 0o700
    receipt = approval / "approval.json"
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    raw = receipt.read_bytes()
    assert CANARY.encode() not in raw and b"opsark-candidate" not in raw
    stdout, stderr = capsys.readouterr()
    public = json.dumps(result) + stdout + stderr
    assert all(
        str(value) not in public
        for value in (
            CANARY,
            "opsark-candidate",
            files.source,
            files.backup,
            files.candidate,
            approval,
        )
    )
    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, approval)
    assert receipt.read_bytes() == raw and record_inputs(files) == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirm": False},
        {"expected_plan_id": "0" * 32},
        {"expected_candidate_sha256": "0" * 64},
    ],
)
def test_approval_mismatch_refuses_before_syntax(prepared_lab, monkeypatch, overrides):
    files = prepared_lab
    output = files.output.parent / "approval"
    before = record_inputs(files)

    def unexpected(*_args):
        pytest.fail("unapproved plan reached the validator")

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", unexpected)
    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, output, **overrides)
    assert not output.exists() and record_inputs(files) == before


def test_approval_cannot_bypass_the_validator_input_boundary(plan_files, monkeypatch):
    files = plan_files
    prepare(files)
    output = files.output.parent / "approval"

    def unexpected(*_args):
        pytest.fail("unsupported candidate reached the validator")

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", unexpected)
    with pytest.raises(snapshot_tool.SnapshotError) as error:
        approve(files, output)
    assert PLAN_CANARY not in str(error.value)
    assert not output.exists() and files.source.read_bytes() == CONTENT


@pytest.mark.parametrize(
    "cause", ["failed", "unavailable", "drift_after_validation", "expired_after_validation"]
)
def test_approval_refuses_unsuccessful_or_stale_validation(prepared_lab, monkeypatch, cause):
    files = prepared_lab
    output = files.output.parent / "approval"
    before = record_inputs(files)
    calls = []
    current = CREATED

    def syntax(data, image):
        nonlocal current
        calls.append((data, image))
        if cause == "drift_after_validation":
            changed = CONTENT + b"# an independent admin changed the file\n"
            files.source.write_bytes(changed)
            before[files.source] = changed
        elif cause == "expired_after_validation":
            current += timedelta(minutes=10)
        return cause if cause in {"failed", "unavailable"} else "passed"

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", syntax)
    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, output, now=lambda: current)
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    assert not output.exists() and record_inputs(files) == before


def test_approval_refuses_drift_at_final_receipt_publication(prepared_lab, monkeypatch):
    files = prepared_lab
    output = files.output.parent / "approval"
    monkeypatch.setattr(snapshot_tool, "_docker_syntax", lambda *_args: "passed")
    original_write = snapshot_tool._write
    changed = CONTENT + b"# edit during approval publication\n"

    def write_and_change_source(parent, name, data):
        original_write(parent, name, data)
        if name == ".manifest.pending":
            files.source.write_bytes(changed)

    monkeypatch.setattr(snapshot_tool, "_write", write_and_change_source)
    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, output)
    assert not output.exists() and files.source.read_bytes() == changed


def test_approval_inspection_retains_history_and_hides_tampered_fields(prepared_lab, monkeypatch):
    files = prepared_lab
    output = files.output.parent / "approval"
    monkeypatch.setattr(snapshot_tool, "_docker_syntax", lambda *_args: "passed")
    approved = approve(files, output)
    receipt = output / "approval.json"
    original = receipt.read_bytes()

    def unexpected(*_args):
        pytest.fail("approval inspection attempted another syntax or service action")

    monkeypatch.setattr(snapshot_tool, "_docker_syntax", unexpected)
    expired = snapshot_tool.inspect_approval(
        output, policy=files.policy, now=CREATED + timedelta(minutes=10)
    )
    assert expired == {**approved, "approval_status": "expired"}
    files.source.write_bytes(CONTENT + b"# out of band edit\n")
    drifted = snapshot_tool.inspect_approval(output, policy=files.policy, now=CREATED)
    assert drifted == {**approved, "approval_status": "drift"}
    assert receipt.read_bytes() == original
    (files.output / "candidate.conf").write_bytes(b"# no longer the approved candidate")
    assert snapshot_tool.inspect_approval(output, policy=files.policy, now=CREATED) == {
        **approved,
        "approval_status": "unavailable",
    }
    receipt.write_bytes(original.replace(approved["approval_id"].encode(), b"0" * 32))
    tampered = snapshot_tool.inspect_approval(output, policy=files.policy, now=CREATED)
    assert tampered == {
        "schema_version": 1,
        "approval_status": "tampered",
        "syntax_status": "not_checked",
    }
