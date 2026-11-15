"""The repair transport accepts references, never service names or caller proof flags."""

import json

import pytest
from test_patch_client import POLICY
from test_patch_client import server_key as server_key
from test_patch_client import target as target

from opsark import patch_client


def request(op):
    base = {"schema_version": 1, "policy_digest": POLICY, "op": op}
    if op == "activation_prepare":
        return base | {"job_id": "1" * 32, "mode_revision": 2, "context_digest": "2" * 64}
    if op == "activation_submit":
        return base | {
            "activation_id": "3" * 32,
            "activation_digest": "4" * 64,
            "mode_revision": 2,
            "context_digest": "2" * 64,
        }
    return base | {"activation_id": "3" * 32}


@pytest.mark.parametrize("op", ["activation_prepare", "activation_submit", "activation_status"])
def test_activation_fixed_operations_serialize_only_exact_references(target, op):
    value = request(op)
    assert json.loads(patch_client._request_bytes(target, value)) == value


@pytest.mark.parametrize(
    "extra",
    [
        {"unit": "sshd.service"},
        {"command": "private"},
        {"verified": True},
        {"fresh_ssh": True},
        {"force": True},
    ],
)
def test_activation_never_accepts_remote_execution_or_proof_parameters(target, extra):
    with pytest.raises(ValueError):
        patch_client._request_bytes(target, request("activation_submit") | extra)


@pytest.mark.parametrize(
    "changed",
    [
        {"activation_id": "../private"},
        {"activation_digest": "invalid"},
        {"mode_revision": True},
        {"mode_revision": -1},
        {"context_digest": None},
    ],
)
def test_activation_references_and_revision_are_strict(target, changed):
    with pytest.raises(ValueError):
        patch_client._request_bytes(target, request("activation_submit") | changed)


def test_only_submit_is_a_service_restart_mutation():
    assert "activation_submit" in patch_client.MUTATIONS
    assert "activation_status" not in patch_client.MUTATIONS
    assert "activation_prepare" not in patch_client.MUTATIONS
    error = patch_client.UnknownPatchResult("activation_submit", "3" * 32)
    assert error.job_id == "3" * 32 and "原激活 ID" in str(error)
