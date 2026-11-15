"""Verify dependency context bindings without launching a validator or a service."""

import hashlib
import json
import sys

import pytest
from test_nginx_config_plan import CREATED
from test_nginx_config_plan import plan_files as plan_files
from test_nginx_config_snapshot import snapshot_tool
from test_nginx_config_snapshot import tree as tree
from test_nginx_plan_validation import IMAGE, LAB_CANDIDATE

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux directory and file trust rules"
)
CONTEXT = "a" * 64
CHANGED = "b" * 64


def prepare(files, context_reader):
    files.candidate.write_bytes(LAB_CANDIDATE)
    return snapshot_tool.prepare(
        files.backup,
        files.candidate,
        hashlib.sha256(LAB_CANDIDATE).hexdigest(),
        files.output,
        policy=files.policy,
        now=CREATED,
        context_reader=context_reader,
    )


def approve(files, plan, output, context_reader, syntax_check):
    return snapshot_tool.approve_plan(
        files.output,
        IMAGE,
        plan["plan_id"],
        plan["candidate_sha256"],
        output,
        confirm=True,
        policy=files.policy,
        now=CREATED,
        context_reader=context_reader,
        syntax_check=syntax_check,
    )


def test_prepare_refuses_context_drift_at_publication(plan_files):
    reads = iter((CONTEXT, CHANGED))
    with pytest.raises(snapshot_tool.SnapshotError):
        prepare(plan_files, lambda: next(reads))
    assert not plan_files.output.exists()


def test_bound_approval_requires_both_hooks_and_same_live_context(plan_files, monkeypatch):
    files = plan_files

    def read():
        return CONTEXT

    plan = prepare(files, read)
    approval = files.output.parent / "approval"
    assert plan["context_sha256"] == CONTEXT

    def unexpected(*_args):
        pytest.fail("Unbound plan reached the validator")

    monkeypatch.setattr(snapshot_tool, "_fixture_syntax", unexpected)
    for reader, checker in ((None, None), (read, None), (lambda: CHANGED, unexpected)):
        with pytest.raises(snapshot_tool.SnapshotError):
            approve(files, plan, approval, reader, checker)
        assert not approval.exists()
    calls = []

    def syntax(data, image):
        calls.append((data, image))
        return "passed"

    result = approve(files, plan, approval, read, syntax)
    assert result["context_sha256"] == CONTEXT
    assert result["approval_status"] == "approved"
    assert calls == [(LAB_CANDIDATE, IMAGE)]
    check = {"policy": files.policy, "now": CREATED}
    assert snapshot_tool.inspect_approval(approval, **check)["approval_status"] == "unavailable"
    assert snapshot_tool.inspect_approval(approval, context_reader=read, **check) == result
    assert (
        snapshot_tool.inspect_approval(approval, context_reader=lambda: CHANGED, **check)[
            "approval_status"
        ]
        == "drift"
    )
    assert calls == [(LAB_CANDIDATE, IMAGE)]

    receipt_path = approval / "approval.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt.pop("manifest_sha256")
    receipt.pop("context_sha256")
    receipt["manifest_sha256"] = snapshot_tool._sha(snapshot_tool._json(receipt))
    receipt_path.write_bytes(snapshot_tool._json(receipt) + b"\n")
    assert (
        snapshot_tool.inspect_approval(approval, context_reader=read, **check)["approval_status"]
        == "unavailable"
    )


@pytest.mark.parametrize("operation", ("validate", "approve"))
def test_bound_syntax_result_cannot_escape_context_drift(plan_files, operation):
    files = plan_files
    context = CONTEXT

    def read():
        return context

    plan = prepare(files, read)

    def syntax(data, image):
        nonlocal context
        assert (data, image) == (LAB_CANDIDATE, IMAGE)
        context = CHANGED
        return "passed"

    if operation == "validate":
        result = snapshot_tool.validate_plan(
            files.output,
            IMAGE,
            policy=files.policy,
            now=CREATED,
            context_reader=read,
            syntax_check=syntax,
        )
        assert result["plan_status"] == "drift" and result["syntax_status"] == "not_checked"
    else:
        output = files.output.parent / "approval"
        with pytest.raises(snapshot_tool.SnapshotError):
            approve(files, plan, output, read, syntax)
        assert not output.exists()


def test_legacy_plan_rejects_injected_context_or_validator(plan_files):
    files = plan_files
    plan = prepare(files, None)
    output = files.output.parent / "approval"

    def unexpected(*_args):
        pytest.fail("A legacy plan used an injected context or validator")

    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, plan, output, unexpected, unexpected)
    with pytest.raises(snapshot_tool.SnapshotError):
        approve(files, plan, output, None, unexpected)
    assert not output.exists()
