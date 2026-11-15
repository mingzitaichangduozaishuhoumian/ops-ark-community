"""Recovery RPCs retain the same identity and one-send uncertainty boundary."""

import pytest
from test_patch_client import POLICY
from test_patch_client import client as client
from test_patch_client import server_key as server_key
from test_patch_client import target as target

from opsark.patch_client import PatchClientError, UnknownPatchResult, invoke


def request(op="recovery_submit", **changes):
    fields = {
        "recovery_prepare": {"job_id": "1" * 32, "mode_revision": 2, "context_digest": "2" * 64},
        "recovery_submit": {
            "recovery_id": "3" * 32,
            "recovery_digest": "4" * 64,
            "mode_revision": 2,
            "context_digest": "2" * 64,
        },
        "recovery_status": {"recovery_id": "3" * 32},
    }[op]
    return {"schema_version": 1, "op": op, "policy_digest": POLICY, **fields, **changes}


@pytest.mark.parametrize("operation", ["recovery_prepare", "recovery_submit", "recovery_status"])
def test_fixed_recovery_operations_do_not_add_a_shell(operation, target, client):
    assert invoke(target, request(operation)) == {"status": "complete"}
    assert client.exec_calls[0][0] == "opsark-patch-v1"
    assert len(client.exec_calls) == len(client.channel.sent) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"command": "apt-get upgrade"},
        {"context_digest": "bad"},
        {"recovery_digest": "bad"},
        {"recovery_id": "../unsafe"},
        {"mode_revision": True},
        {"mode_revision": -1},
        {"mode_revision": 2**53},
    ],
)
def test_recovery_submit_fields_are_bound_before_any_transport(changes, target, client):
    with pytest.raises(ValueError):
        invoke(target, request(**changes))
    assert not client.connect_calls and not client.exec_calls


def test_recovery_submit_transport_loss_is_unknown_and_never_resent(target, client):
    client.channel.fail_send = True
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request())
    assert caught.value.op == "recovery_submit"
    assert len(client.connect_calls) == len(client.exec_calls) == len(client.channel.sent) == 1


def test_recovery_status_transport_loss_is_a_read_failure(target, client):
    client.channel.fail_send = True
    with pytest.raises(PatchClientError) as caught:
        invoke(target, request("recovery_status"))
    assert not isinstance(caught.value, UnknownPatchResult)
    assert len(client.exec_calls) == 1
