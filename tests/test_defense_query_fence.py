"""Query cancellation and atomic observation fences use tmp-only fake receipts."""

import hashlib
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from test_defense_api import NOW, ready, stamp
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.defense_client import DefenseClientError
from opsark.defense_store import DefenseConflict


def image(path):
    hasher = hashlib.sha256()
    with closing(sqlite3.connect(path)) as db, db:
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'defense_%' "
            "AND name!='defense_worker_lease' ORDER BY name"
        ):
            quoted = '"' + name.replace('"', '""') + '"'
            hasher.update(name.encode())
            for row in db.execute("SELECT rowid,* FROM " + quoted + " ORDER BY rowid"):  # noqa: S608 -- quoted names from the owned SQLite catalog only.
                hasher.update(repr(row).encode())
    return hasher.hexdigest()


def reject():
    raise DefenseConflict("Synthetic read-only admission expired")


def test_initial_query_admission_denial_has_no_rpc_or_observation(harness):
    h = harness
    *_, action = ready(h)
    before, sent = image(h.store.path), tuple(h.root.sent)
    with pytest.raises(DefenseConflict):
        h.service.query_with_observation("fixture", action["request_id"], admit=reject)
    assert image(h.store.path) == before and tuple(h.root.sent) == sent


def test_wrapped_client_admission_denial_does_not_become_root_unavailable(harness):
    h = harness
    *_, action = ready(h)
    before, sent = image(h.store.path), tuple(h.root.sent)
    admitted = True

    def guard():
        if not admitted:
            reject()

    def normalized_client(*_args, admit=None):
        nonlocal admitted
        admitted = False
        try:
            assert admit is not None
            admit()
        except DefenseConflict:
            raise DefenseClientError() from None

    h.service.invoker = normalized_client
    with pytest.raises(DefenseConflict):
        h.service.query_with_observation("fixture", action["request_id"], admit=guard)
    assert image(h.store.path) == before and tuple(h.root.sent) == sent


@pytest.mark.parametrize("transport_failed", [False, True])
def test_lease_lost_during_rpc_never_records_success_or_unavailable(harness, transport_failed):
    h = harness
    *_, action = ready(h)
    before = image(h.store.path)
    admitted = True

    def guard():
        if not admitted:
            reject()

    def late_client(*args, **kwargs):
        nonlocal admitted
        result = h.root(*args, **kwargs)
        admitted = False
        if transport_failed:
            raise RuntimeError("Synthetic transport failure")
        return result

    h.service.invoker = late_client
    with pytest.raises(DefenseConflict):
        h.service.query_with_observation("fixture", action["request_id"], admit=guard)
    assert image(h.store.path) == before
    assert h.root.sent[-1] == ("query", action["request_id"])


@pytest.mark.parametrize("transport_failed", [False, True])
def test_atomic_commit_fence_rolls_back_both_observation_paths(harness, transport_failed):
    h = harness
    *_, action = ready(h)
    before = image(h.store.path)
    called = []

    def fence(connection):
        assert connection.in_transaction
        called.append(True)
        reject()

    if transport_failed:

        def unavailable(*_args, **_kwargs):
            raise RuntimeError("Synthetic transport failure")

        h.service.invoker = unavailable
    with pytest.raises(DefenseConflict):
        h.service.query_with_observation("fixture", action["request_id"], commit_guard=fence)
    assert called == [True] and image(h.store.path) == before


def test_atomic_fence_closes_swap_after_last_precommit_checkpoint(harness, monkeypatch):
    h = harness
    *_, action = ready(h)
    before = image(h.store.path)
    lease = h.store.acquire_worker(
        "synthetic-a", expires_at=stamp(NOW + timedelta(seconds=30)), now=NOW
    )
    assert lease is not None

    def fence(connection):
        assert connection.in_transaction
        current = connection.execute("SELECT owner,epoch FROM defense_worker_lease").fetchone()
        if current["owner"] != lease.owner or current["epoch"] != lease.epoch:
            reject()

    record = h.store.record_reply

    def swap_before_write(*args, **kwargs):
        newer = h.store.acquire_worker(
            "synthetic-b",
            expires_at=stamp(NOW + timedelta(seconds=90)),
            now=NOW + timedelta(seconds=31),
        )
        assert newer is not None and newer.epoch > lease.epoch
        return record(*args, **kwargs)

    monkeypatch.setattr(h.store, "record_reply", swap_before_write)
    with pytest.raises(DefenseConflict):
        h.service.query_with_observation("fixture", action["request_id"], commit_guard=fence)
    assert image(h.store.path) == before


def test_valid_query_fences_append_one_exact_observation(harness):
    h = harness
    *_, action = ready(h)
    checkpoints, commits = [], []

    def guard():
        checkpoints.append(True)

    def fence(connection):
        assert connection.in_transaction
        commits.append(True)

    before = len(h.store.observations(action["request_id"]))
    observation, reply = h.service.query_with_observation(
        "fixture", action["request_id"], admit=guard, commit_guard=fence
    )
    assert reply is not None and observation.accepted and observation.op == "query"
    assert observation.rid == action["request_id"] and len(checkpoints) == 3
    assert commits == [True] and len(h.store.observations(action["request_id"])) == before + 1


def test_observation_fence_cannot_be_used_as_mutation_admission(harness):
    h = harness
    *_, action = ready(h)
    before = image(h.store.path)
    with pytest.raises(DefenseConflict):
        h.store.record_unavailable(
            action["request_id"], "apply", commit_guard=lambda _connection: None, now=NOW
        )
    assert image(h.store.path) == before
