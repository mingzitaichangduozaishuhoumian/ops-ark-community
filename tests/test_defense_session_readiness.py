"""Local observation hints never compare a Root UTC deadline with the browser clock."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from fastapi.encoders import jsonable_encoder
from test_defense_api import NOW, ArmRequest, ready
from test_defense_api import harness as harness
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.automation_store import ModeChange
from opsark.control_modes import Mode
from opsark.defense_api import DefenseService
from opsark.defense_models import utc
from opsark.defense_store import DefenseStore


def ledger_digest(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db, db:
        db.execute("PRAGMA query_only=ON")
        return hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()


def arm(h):
    mode = h.coordinator.change_mode(ModeChange(mode=Mode.automatic, expected_revision=0))
    return h.service.arm(
        "fixture", ArmRequest(expected_mode_revision=mode["revision"], confirm_arm=True)
    )["request_id"]


def test_root_clock_offset_does_not_extend_local_window(harness):
    h = harness
    h.root.clock = lambda: h.clock[0] + timedelta(hours=7)
    rid = arm(h)
    before, sent = ledger_digest(h.store.path), tuple(h.root.sent)
    original = h.service.transaction("fixture", rid)
    local = original["controller_observation"]
    assert local == {
        "owned_by_current_boot": True,
        "deadline_at": h.store.transaction(rid).deadline_at,
        "remaining_ms": 120000,
    }
    assert utc(original["current_result"]["deadline_at"]) > utc(local["deadline_at"])
    h.clock[0] += timedelta(seconds=120)
    expired = h.service.transaction("fixture", rid)
    assert expired["controller_observation"]["remaining_ms"] == 0
    assert expired["current_result"]["deadline_at"] == original["current_result"]["deadline_at"]
    assert ledger_digest(h.store.path) == before and tuple(h.root.sent) == sent


@pytest.mark.parametrize("seconds,expected", [(0.001, 119999), (40, 80000), (121, 0), (-1, 0)])
def test_observation_hint_is_bounded_and_readonly(harness, seconds, expected):
    h = harness
    rid = arm(h)
    before, sent = ledger_digest(h.store.path), tuple(h.root.sent)
    h.clock[0] = NOW + timedelta(seconds=seconds)
    value = h.service.transaction("fixture", rid)
    assert type(value["controller_observation"]["remaining_ms"]) is int
    assert value["controller_observation"]["remaining_ms"] == expected
    assert ledger_digest(h.store.path) == before and tuple(h.root.sent) == sent


def test_new_boot_reads_original_local_deadline_without_claiming_ownership(harness):
    h = harness
    rid = arm(h)
    before = ledger_digest(h.store.path)

    def no_transport(*_args, **_kwargs):
        pytest.fail("Reading historical readiness cannot query Root")

    restarted = DefenseService(
        h.service.settings,
        h.service.targets,
        DefenseStore(h.store.path),
        h.automation,
        coordinator=h.coordinator,
        policy=h.service.policy,
        mode_lock=h.service.mode_lock,
        invoker=no_transport,
        clock=h.service.clock,
    )
    value = restarted.transaction("fixture", rid)
    assert value["controller_observation"]["owned_by_current_boot"] is False
    assert value["controller_observation"]["deadline_at"] == h.store.transaction(rid).deadline_at
    rendered = json.dumps(jsonable_encoder(value))
    assert h.service.owner not in rendered and restarted.owner not in rendered
    assert ledger_digest(h.store.path) == before


def test_action_is_not_presented_as_an_observation_window(harness):
    h = harness
    _revision, _cursor, _body, action = ready(h)
    sent = tuple(h.root.sent)
    assert h.service.transaction("fixture", action["request_id"])["controller_observation"] is None
    assert tuple(h.root.sent) == sent
