"""The new recovery transport accepts immutable references, never caller proof."""

import json

import pytest
from test_patch_client import POLICY
from test_patch_client import client as client
from test_patch_client import server_key as server_key
from test_patch_client import target as target

from opsark import patch_client


def request(operation):
    common = {"schema_version": 1, "op": operation, "policy_digest": POLICY}
    if operation == "activation_recovery_prepare":
        return common | {
            "job_id": "1" * 32,
            "activation_id": "2" * 32,
            "context_digest": "3" * 64,
            "mode_revision": 1,
        }
    if operation == "activation_recovery_submit":
        return common | {
            "recovery_id": "4" * 32,
            "recovery_digest": "5" * 64,
            "context_digest": "3" * 64,
            "mode_revision": 1,
        }
    return common | {"recovery_id": "4" * 32}


@pytest.mark.parametrize("suffix", ["prepare", "submit", "status"])
def test_fixed_reference_shape_roundtrips(target, suffix):
    body = request("activation_recovery_" + suffix)
    assert json.loads(patch_client._request_bytes(target, body)) == body


@pytest.mark.parametrize("suffix", ["prepare", "submit", "status"])
@pytest.mark.parametrize(
    "extra",
    [
        {"force": True},
        {"verified": True},
        {"clear_all": True},
        {"unit": "sshd.service"},
        {"reset_quota": True},
        {"shell": "private"},
    ],
)
def test_no_connection_for_any_caller_authority_or_proof(target, client, suffix, extra):
    with pytest.raises(ValueError):
        patch_client.invoke(target, request("activation_recovery_" + suffix) | extra)
    assert not client.connect_calls


@pytest.mark.parametrize(
    "change",
    [
        {"recovery_id": "../other"},
        {"recovery_id": True},
        {"recovery_digest": "bad"},
        {"mode_revision": True},
        {"mode_revision": -1},
        {"context_digest": None},
    ],
)
def test_strict_approval_identity_before_transport(target, client, change):
    with pytest.raises(ValueError):
        patch_client.invoke(target, request("activation_recovery_submit") | change)
    assert not client.connect_calls


def test_lost_approval_receipt_keeps_original_recovery_id_and_one_send(target, client):
    client.channel.fail_send = True
    with pytest.raises(patch_client.UnknownPatchResult) as caught:
        patch_client.invoke(target, request("activation_recovery_submit"))
    assert caught.value.op == "activation_recovery_submit"
    assert caught.value.job_id == "4" * 32
    assert "原恢复 ID" in str(caught.value) and "private" not in str(caught.value)
    assert len(client.connect_calls) == len(client.exec_calls) == len(client.channel.sent) == 1


@pytest.mark.parametrize("suffix", ["prepare", "status"])
def test_lost_read_does_not_claim_pause_was_resolved(target, client, suffix):
    client.channel.fail_send = True
    with pytest.raises(patch_client.PatchClientError) as caught:
        patch_client.invoke(target, request("activation_recovery_" + suffix))
    assert not isinstance(caught.value, patch_client.UnknownPatchResult)
    assert len(client.exec_calls) == 1


def test_only_explicit_approval_is_recovery_mutation():
    assert "activation_recovery_submit" in patch_client.MUTATIONS
    assert "activation_recovery_prepare" not in patch_client.MUTATIONS
    assert "activation_recovery_status" not in patch_client.MUTATIONS
