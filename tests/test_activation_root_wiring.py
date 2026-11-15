"""Fixed activation RPC admission and shared mutation serialization; no system changes."""

import copy
import io
import json
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from test_patch_agent import JOB, prepare, request, submission
from test_patch_agent import remote as remote
from test_patch_install_safety import bootstrap as bootstrap

ACTIVATION = "d" * 32
DIGEST = "e" * 64
CONTEXT = "f" * 64
BUSY = (
    "queued",
    "preflight",
    "restarting",
    "running_overdue",
    "verifying",
    "awaiting_transport_verification",
    "unknown",
    "failed",
    "unrecognized_state",
)


def activation_request(remote, operation):
    fields = {
        "activation_prepare": {"job_id": JOB, "mode_revision": 0, "context_digest": CONTEXT},
        "activation_submit": {
            "activation_id": ACTIVATION,
            "activation_digest": DIGEST,
            "mode_revision": 0,
            "context_digest": CONTEXT,
        },
        "activation_status": {"activation_id": ACTIVATION},
    }
    return request(remote, operation, **fields[operation])


def retained(remote, status, *, value=None):
    folder = remote.path / "activations" / ACTIVATION
    folder.mkdir(parents=True)
    record = {"schema_version": 1, "activation_id": ACTIVATION, "status": status}
    path = folder / "activation.json"
    path.write_bytes(remote.core.canonical(record if value is None else value))
    return path


@pytest.mark.parametrize(
    "operation", ["activation_prepare", "activation_submit", "activation_status"]
)
def test_fixed_rpc_shapes_never_accept_caller_units_or_shell(remote, operation):
    body = activation_request(remote, operation)
    assert remote.agent.validate_request(body) == body
    for forbidden in ("unit", "command", "environment", "verified"):
        with pytest.raises(remote.core.Rejected, match="Unexpected request fields"):
            remote.agent.validate_request(body | {forbidden: "private-untrusted-input"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("activation_id", "../foreign"),
        ("activation_id", True),
        ("activation_digest", "untrusted"),
        ("activation_digest", [DIGEST]),
        ("context_digest", "not-a-digest"),
        ("mode_revision", True),
    ],
)
def test_activation_rpc_requires_exact_identity_and_mode_types(remote, field, value):
    with pytest.raises(remote.core.Rejected):
        remote.agent.validate_request(
            activation_request(remote, "activation_submit") | {field: value}
        )


@pytest.mark.parametrize(
    "operation", ["activation_prepare", "activation_submit", "activation_status"]
)
def test_dispatch_passes_only_the_validated_request_and_current_policy(
    remote, monkeypatch, operation
):
    calls = []
    module = SimpleNamespace(
        prepare=lambda body, policy: (
            calls.append(("prepare", body, policy)) or {"status": "prepared"}
        ),
        submit=lambda body, policy: calls.append(("submit", body, policy)) or {"status": "queued"},
        status=lambda identifier, policy: (
            calls.append(("status", identifier, policy))
            or {"status": "awaiting_transport_verification"}
        ),
    )
    monkeypatch.setitem(sys.modules, "activation", module)
    body = activation_request(remote, operation)
    result = remote.agent.dispatch(body)
    assert len(calls) == 1
    assert calls[0][1] == (ACTIVATION if operation == "activation_status" else body)
    assert calls[0][2] == remote.policy
    assert result["host_id"] == remote.policy["host_id"]
    assert result["policy_digest"] == remote.core.policy_digest(remote.policy)
    assert remote.commands == []


def test_policy_is_reloaded_after_rpc_lock_before_any_activation(remote, monkeypatch):
    events = []
    changed = remote.policy | {"allowed_packages": ["different-package"]}
    policies = iter([copy.deepcopy(remote.policy), changed])

    def load():
        events.append("policy")
        return next(policies)

    @contextmanager
    def lock(name):
        events.append(name)
        yield

    monkeypatch.setattr(remote.core, "load_policy", load)
    monkeypatch.setattr(remote.core, "lock", lock)
    monkeypatch.setitem(
        sys.modules,
        "activation",
        SimpleNamespace(prepare=lambda *_args: pytest.fail("Old capability must not be admitted")),
    )
    with pytest.raises(remote.core.Rejected, match="binding changed"):
        remote.agent.dispatch(activation_request(remote, "activation_prepare"))
    assert events == ["policy", "rpc", "policy"]
    assert not remote.commands


@pytest.mark.parametrize("status", BUSY)
def test_queued_or_uncertain_activation_blocks_a_new_patch_before_intent(remote, status):
    plan = prepare(remote)
    path = retained(remote, status)
    before = path.read_bytes()
    with pytest.raises(remote.core.Rejected, match="active or uncertain activation"):
        remote.agent.submit(submission(remote, plan), remote.policy)
    assert not (remote.path / "jobs" / JOB).exists()
    assert remote.commands == [] and path.read_bytes() == before


def test_original_patch_status_remains_queryable_during_an_activation(remote):
    plan = prepare(remote)
    body = submission(remote, plan)
    original = remote.agent.submit(body, remote.policy)
    retained(remote, "restarting")
    commands = list(remote.commands)
    duplicate = remote.agent.submit(body, remote.policy)
    assert duplicate["job_id"] == original["job_id"] and duplicate["status"] == "queued"
    assert remote.commands == commands


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"activation_id": ACTIVATION, "status": "verified"},
        {"schema_version": True, "activation_id": ACTIVATION, "status": "verified"},
        {"schema_version": 1, "activation_id": "a" * 32, "status": "verified"},
        {"schema_version": 1, "activation_id": ACTIVATION, "status": ["verified"]},
    ],
)
def test_malformed_activation_ledger_is_not_treated_as_an_empty_slot(remote, value):
    retained(remote, "verified", value=value)
    with pytest.raises(remote.core.Rejected, match="active or uncertain activation"):
        remote.core.assert_no_activation()


@pytest.mark.parametrize("operation", ["recovery_prepare", "recovery_submit"])
def test_new_recovery_does_not_cross_an_activation_intent(remote, monkeypatch, operation):
    retained(remote, "queued")
    monkeypatch.setitem(
        sys.modules,
        "recovery",
        SimpleNamespace(
            prepare=lambda *_args: pytest.fail("Do not start reconciliation during restart"),
            submit=lambda *_args: pytest.fail("Do not change safety during restart"),
        ),
    )
    body = (
        request(remote, operation, job_id=JOB)
        if operation == "recovery_prepare"
        else request(remote, operation, recovery_id=ACTIVATION, recovery_digest=DIGEST)
    )
    body.update(mode_revision=0, context_digest=CONTEXT)
    with pytest.raises(remote.core.Rejected, match="active or uncertain activation"):
        remote.agent.dispatch(body)


def test_lost_activation_start_acknowledgement_returns_the_same_durable_intent(remote, monkeypatch):
    body = activation_request(remote, "activation_submit")
    saved = {
        "schema_version": 1,
        "activation_id": ACTIVATION,
        "activation_digest": DIGEST,
        "mode_revision": 0,
        "context_digest": CONTEXT,
        "status": "unknown",
    }
    path = retained(remote, "unknown", value=saved)
    before = path.read_bytes()
    output = io.BytesIO()

    def lost(_body):
        raise remote.core.Rejected("A startup acknowledgement was lost")

    with monkeypatch.context() as local:
        local.setattr(remote.agent, "read_request", lambda: body)
        local.setattr(remote.agent, "dispatch", lost)
        local.setattr(remote.agent.os, "geteuid", lambda: 0, raising=False)
        local.setattr(remote.agent.sys, "argv", ["agent.py"])
        local.setattr(remote.agent.sys, "stdout", SimpleNamespace(buffer=output))
        assert remote.agent.main() == 0
    result = json.loads(output.getvalue())
    assert result["activation_id"] == ACTIVATION and result["status"] == "unknown"
    assert path.read_bytes() == before and not remote.commands


@pytest.mark.parametrize("status", BUSY)
def test_upgrade_rejects_unsettled_activation_after_both_mutation_locks(bootstrap, status):
    folder = bootstrap.state / "activations" / ACTIVATION
    folder.mkdir(parents=True)
    path = folder / "activation.json"
    path.write_text(
        json.dumps({"schema_version": 1, "activation_id": ACTIVATION, "status": status})
    )
    before = path.read_bytes()
    with bootstrap.module.upgrade_locks():
        assert bootstrap.held == {"rpc", "worker"}
        with pytest.raises(ValueError, match="active or uncertain activation"):
            bootstrap.module.reject_unfinished_jobs()
    assert path.read_bytes() == before


@pytest.mark.parametrize("status", ["verified", "rejected", "verification_failed"])
def test_terminal_activation_ledger_is_preserved_during_upgrade_check(bootstrap, status):
    folder = bootstrap.state / "activations" / ACTIVATION
    folder.mkdir(parents=True)
    path = folder / "activation.json"
    path.write_text(
        json.dumps({"schema_version": 1, "activation_id": ACTIVATION, "status": status})
    )
    before = path.read_bytes()
    with bootstrap.module.upgrade_locks():
        bootstrap.module.reject_unfinished_jobs()
    assert path.read_bytes() == before


def test_installer_source_pin_includes_the_reviewed_activation_module(bootstrap, remote):
    assert "activation.py" in remote.core.SOURCE_FILES
    assert bootstrap.module.FILES == remote.core.SOURCE_FILES
