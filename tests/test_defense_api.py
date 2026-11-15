"""Owned fake keys, temporary stores and a strict, bounded fake Root only."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Lock
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.automation_store import AutomationStore, ModeChange
from opsark.config import Settings
from opsark.control_modes import ControlPolicy, Mode
from opsark.defense_api import (
    ApplyRequest,
    ArmRequest,
    DefenseService,
    DefenseServiceError,
    PrepareRequest,
    RevokeRequest,
    defense_service_scope,
    register_defense_routes,
)
from opsark.defense_client import _call_context, _validate_reply
from opsark.defense_models import (
    POLICY_SHA256,
    ActionBody,
    ArmBody,
    DefenseReply,
    DefenseRequest,
    ModeBody,
    PrepareBody,
    canonical,
    digest,
    rebuild_manifest,
    utc,
)
from opsark.defense_policy import DefensePolicy, load_policy
from opsark.defense_store import DefenseConflict, DefenseStore
from opsark.mode_coordinator import ModeCoordinator, ModeParticipant, supplemental_scope
from opsark.patch_api import ModeSynchronizationError

NOW = datetime(2026, 11, 6, 2, tzinfo=UTC)
SOURCE, EVIDENCE = "c" * 32, "d" * 64


def stamp(value=NOW):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def policy(target, **changes):
    common = {
        "enabled": True,
        "grant_ref": "e" * 32,
        "issued_at": stamp(NOW - timedelta(minutes=1)),
        "expires_at": stamp(NOW + timedelta(seconds=120)),
        "host_ids": ["fixture"],
        "target_scope_sha256": {"fixture": target.root_scope_sha256},
        "target_policy_sha256": {"fixture": POLICY_SHA256},
        "windows": [{"weekdays": [NOW.weekday()], "start_minute": 0, "end_minute": 1440}],
    }
    value = {
        "enabled": True,
        "observation": common | {"grant_ref": "a" * 32},
        "execution": common
        | {
            "root_grant_refs": {"fixture": "f" * 32},
            "boot_refs": {"fixture": target.boot_ref},
            "binding_refs": {"fixture": target.binding_ref},
            "wire_revisions": [1, 2, 3, 4, 5],
            "source_aliases": ["fixture-a", "fixture-b"],
            "max_actions_per_day": 8,
            "max_total_actions": 8,
        },
    }
    value.update(changes)
    return DefensePolicy.model_validate_json(canonical(value))


class FakeRoot:
    def __init__(self, target, clock):
        self.target, self.clock = target, clock
        self.mode, self.revision = "manual", 1
        self.records, self.sent = {}, []
        self.before_admit, self.lose = None, None
        self.break_reply = None

    def __call__(self, target, call, role, *, admit=None):
        call = _call_context(target, call)
        request = DefenseRequest.parse(call.request.wire_bytes())
        if self.before_admit is not None:
            callback, self.before_admit = self.before_admit, None
            callback()
        if admit is not None:
            admit()
        assert role == (
            "observe" if request.op == "arm" else "readonly" if request.op == "query" else "control"
        )
        self.sent.append((request.op, request.request_id))
        op, rid, body = request.op, request.request_id, request.body
        if op == "mode_sync":
            assert isinstance(body, ModeBody)
            self.mode, self.revision = body.mode, body.mode_revision
            self.records[rid] = {"kind": "mode"}
        elif op == "arm":
            assert isinstance(body, ArmBody)
            assert body.observation_grant_ref == "a" * 32
            self.records[rid] = {
                "kind": "cursor",
                "cursor_id": digest(rid)[:32],
                "deadline_at": stamp(self.clock() + timedelta(seconds=120)),
                "state": "armed",
            }
        elif op == "prepare":
            assert isinstance(body, PrepareBody)
            assert self.mode != "manual" and (body.mode, body.mode_revision) == (
                self.mode,
                self.revision,
            )
            assert (body.controller_grant_ref, body.root_grant_ref) == ("e" * 32, "f" * 32)
            cursor = next(
                record
                for record in self.records.values()
                if record.get("cursor_id") == body.cursor_id
            )
            assert self.clock() < datetime.fromisoformat(cursor["deadline_at"])
            self.records[rid] = {
                "kind": "action",
                "prepare": request,
                "action_id": digest(rid)[:32],
                "cursor_id": body.cursor_id,
                "deadline_at": cursor["deadline_at"],
                "state": "ready",
            }
            cursor["state"] = "attached"
        elif op in {"apply", "revoke"}:
            assert isinstance(body, ActionBody)
            record = self.records[rid]
            assert self.mode != "manual" and body.manifest_sha256 == record["manifest"].sha256
            if op == "revoke" or record["manifest"].mode == "semi":
                assert body.approval is not None and body.approval.purpose == op
            else:
                assert body.approval is None
            record["state"] = "active" if op == "apply" else "revoked"
            if op == "apply":
                record["active_until"] = self.clock() + timedelta(seconds=60)
        reply = self.reply(request)
        if self.lose == op:
            self.lose = None
            raise OSError("fake secret must never escape")
        raw = canonical(reply) + b"\n"
        if self.break_reply:
            raw = self.break_reply(raw)
        return _validate_reply(target, call, raw)

    def reply(self, request):
        record = self.records[request.request_id]
        value = {
            "v": 1,
            "op": request.op,
            "request_id": request.request_id,
            "scope_sha256": self.target.root_scope_sha256,
            "policy_sha256": POLICY_SHA256,
            "boot_ref": self.target.boot_ref,
            "binding_ref": self.target.binding_ref,
            "mode": self.mode,
            "mode_revision": self.revision,
            "state": "synced",
            "action_id": None,
            "cursor_id": None,
            "manifest_sha256": None,
            "deadline_at": None,
            "remaining_ms": None,
            "reason_code": "ok",
            "candidates": [],
        }
        if record["kind"] == "cursor":
            value.update(
                state=record["state"],
                cursor_id=record["cursor_id"],
                deadline_at=record["deadline_at"],
            )
            if request.op == "query":
                value["candidates"] = [
                    {
                        "source_ref": SOURCE,
                        "source_alias": "fixture-a",
                        "classification": "eligible",
                        "distinct_failure_ports": 5,
                        "evidence_sha256": EVIDENCE,
                    },
                    {
                        "source_ref": "b" * 32,
                        "source_alias": "fixture-b",
                        "classification": "insufficient",
                        "distinct_failure_ports": 0,
                        "evidence_sha256": None,
                    },
                ]
        elif record["kind"] == "action":
            original = record["prepare"]
            value.update(
                state=record["state"],
                action_id=record["action_id"],
                cursor_id=record["cursor_id"],
                deadline_at=record["deadline_at"],
                manifest_sha256="0" * 64,
                mode=original.body.mode,
                mode_revision=original.body.mode_revision,
            )
            manifest = rebuild_manifest(
                original,
                DefenseReply.model_validate(
                    value | {"remaining_ms": 60000 if record["state"] == "active" else None}
                ),
            )
            record["manifest"] = manifest
            value["manifest_sha256"] = manifest.sha256
            if record["state"] == "active":
                value["remaining_ms"] = max(
                    1, int((record["active_until"] - self.clock()).total_seconds() * 1000)
                )
        return DefenseReply.model_validate(value)


@pytest.fixture
def harness(tmp_path, target):
    clock = [NOW]
    deployment = policy(target)
    scope = defense_service_scope({"fixture": target}, deployment)
    assert scope is not None
    participant = ModeParticipant("ssh-defense", scope, lambda _snapshot: False)
    automation = AutomationStore(
        tmp_path / "automation.sqlite3",
        ControlPolicy(),
        supplemental_scope=supplemental_scope((participant,)),
    )
    store, lock = DefenseStore(tmp_path / "security.sqlite3"), Lock()
    root = FakeRoot(target, lambda: clock[0])
    service = DefenseService(
        Settings(tmp_path, "newfake-defense-service-test-token"),
        {"fixture": target},
        store,
        automation,
        policy=deployment,
        mode_lock=lock,
        invoker=root,
        clock=lambda: clock[0],
    )
    channel = service.participant()
    assert channel is not None
    coordinator = ModeCoordinator(automation, lock, (channel,))
    service.coordinator = coordinator
    return SimpleNamespace(
        service=service,
        root=root,
        clock=clock,
        automation=automation,
        coordinator=coordinator,
        store=store,
        target=target,
    )


def ready(h, mode=Mode.assisted):
    result = h.coordinator.change_mode(
        ModeChange(mode=mode, expected_revision=h.automation.status()["revision"])
    )
    rev = result["revision"]
    cursor = h.service.arm("fixture", ArmRequest(expected_mode_revision=rev, confirm_arm=True))
    body = PrepareRequest(
        cursor_request_id=cursor["request_id"],
        source_ref=SOURCE,
        expected_evidence_sha256=EVIDENCE,
        expected_mode_revision=rev,
    )
    action = h.service.prepare("fixture", body)
    return rev, cursor, body, action


def apply(h, rev, action):
    return h.service.apply(
        "fixture",
        action["request_id"],
        ApplyRequest(
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_mode_revision=rev,
            confirm_execute=True,
        ),
    )


def test_real_store_coordinator_prepare_exact_apply_revoke(harness):
    h = harness
    rev, cursor, body, action = ready(h)
    assert action["phase"] == "ready" and action["manifest"]["ttl_ms"] == 60000
    assert h.service.prepare("fixture", body)["request_id"] == action["request_id"]
    active = apply(h, rev, action)
    assert active["phase"] == "active"
    assert apply(h, rev, action)["phase"] == "active"
    revoked = h.service.revoke(
        "fixture",
        action["request_id"],
        RevokeRequest(
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_mode_revision=rev,
            confirm_revoke=True,
        ),
    )
    assert revoked["phase"] == "revoked" and revoked["last_confirmed"].state == "revoked"
    assert [op for op, _ in h.root.sent].count("prepare") == 1
    assert [op for op, _ in h.root.sent].count("apply") == 1
    assert [op for op, _ in h.root.sent].count("revoke") == 1
    assert h.automation.driver_scope is None and not h.automation.policy.enabled
    assert cursor["request_id"] != h.root.records[cursor["request_id"]]["cursor_id"]


def test_default_disabled_and_none_policy_never_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "opsark.defense_policy._read_file", lambda *_args, **_kw: pytest.fail("read")
    )
    deployment = load_policy(None)
    assert deployment.enabled is False
    store = DefenseStore(tmp_path / "security.sqlite3")
    automation = AutomationStore(tmp_path / "mode.sqlite3", ControlPolicy())
    service = DefenseService(
        Settings(tmp_path, "newfake-disabled-test-token"), {}, store, automation
    )
    assert service.status()["disabled"] is True
    with pytest.raises(DefenseServiceError):
        service.arm("fixture", ArmRequest(expected_mode_revision=0, confirm_arm=True))


def test_manual_only_explicit_arm_and_no_action(harness):
    h = harness
    h.coordinator.sync_mode()
    cursor = h.service.arm("fixture", ArmRequest(expected_mode_revision=0, confirm_arm=True))
    h.service.query("fixture", cursor["request_id"])
    with pytest.raises(DefenseConflict):
        h.service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=cursor["request_id"],
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=0,
            ),
        )
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)
    assert h.automation.driver_scope is None


@pytest.mark.parametrize("displacement", [-30.000001, 30.000001])
def test_execution_candidate_over_deadline_displacement_budget_never_prepares(
    harness, displacement
):
    h = harness
    h.root.clock = lambda: h.clock[0] + timedelta(seconds=displacement)
    changed = h.coordinator.change_mode(ModeChange(mode=Mode.automatic, expected_revision=0))
    revision = changed["revision"]
    cursor = h.service.arm("fixture", ArmRequest(expected_mode_revision=revision, confirm_arm=True))
    with pytest.raises(DefenseConflict):
        h.service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=cursor["request_id"],
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=revision,
            ),
        )
    assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)


def test_root_behind_does_not_rewrite_or_extend_assisted_approval_utc(harness):
    h = harness
    h.root.clock = lambda: h.clock[0] - timedelta(seconds=30)
    revision = h.coordinator.change_mode(ModeChange(mode=Mode.assisted, expected_revision=0))[
        "revision"
    ]
    cursor = h.service.arm("fixture", ArmRequest(expected_mode_revision=revision, confirm_arm=True))
    h.clock[0] = NOW + timedelta(seconds=100)
    action = h.service.prepare(
        "fixture",
        PrepareRequest(
            cursor_request_id=cursor["request_id"],
            source_ref=SOURCE,
            expected_evidence_sha256=EVIDENCE,
            expected_mode_revision=revision,
        ),
    )
    original_local = h.store.transaction(cursor["request_id"])
    manifest = h.store.manifest(action["request_id"])
    assert utc(manifest.deadline_at) == NOW + timedelta(seconds=90)
    assert utc(original_local.deadline_at) == NOW + timedelta(seconds=120)
    # This explicit approval cannot fit the original Root UTC deadline. Do not
    # backdate approved_at or move Root's deadline to make the statement valid.
    with pytest.raises(ValueError):
        apply(h, revision, action)
    assert not any(op == "apply" for op, _ in h.root.sent)
    assert h.store.manifest(action["request_id"]).deadline_at == manifest.deadline_at


@pytest.mark.parametrize(
    "field,value",
    [
        ("confirm_arm", 1),
        ("confirm_arm", "true"),
        ("expected_mode_revision", True),
        ("address", "sensitive"),
    ],
)
def test_strict_input_references(field, value):
    body = {"expected_mode_revision": 0, "confirm_arm": True, field: value}
    with pytest.raises(ValidationError):
        ArmRequest.model_validate(body)


def test_api_protection_fixed_errors_and_history(harness):
    h = harness
    authenticated = [False]

    def protected():
        if not authenticated[0]:
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI()
    register_defense_routes(app, h.service, [Depends(protected)])
    client = TestClient(app)
    assert client.get("/api/ssh-defense/status").status_code == 401
    authenticated[0] = True
    response = client.post(
        "/api/hosts/fixture/ssh-defense/arm",
        json={"expected_mode_revision": 0, "confirm_arm": True, "command": "sensitive-secret"},
    )
    assert response.status_code == 422 and "sensitive-secret" not in response.text
    rev, _, _, action = ready(h)
    response = client.get(f"/api/hosts/fixture/ssh-defense/transactions/{action['request_id']}")
    assert response.status_code == 200 and response.json()["history"]
    assert "request_bytes" not in response.text and "key_file" not in response.text
    assert client.get("/api/hosts/fixture/ssh-defense/transactions").json()["transactions"]
    response = client.post(
        f"/api/hosts/fixture/ssh-defense/transactions/{action['request_id']}/apply",
        json={
            "expected_mode_revision": rev,
            "expected_manifest_sha256": "0" * 64,
            "confirm_execute": True,
        },
    )
    assert response.status_code == 409


def test_unknown_local_task_remains_readable_to_a_reconnected_client(harness):
    h = harness
    rev, _, _, action = ready(h)
    rid = action["request_id"]
    app = FastAPI()
    register_defense_routes(app, h.service, [])
    original = TestClient(app)
    h.root.lose = "apply"
    response = original.post(
        f"/api/hosts/fixture/ssh-defense/transactions/{rid}/apply",
        json={
            "expected_mode_revision": rev,
            "expected_manifest_sha256": action["manifest"]["sha256"],
            "confirm_execute": True,
        },
    )
    assert response.status_code == 503 and response.json()["query_required"]
    before = tuple(h.root.sent)
    reconnected = TestClient(app)
    local = reconnected.get(f"/api/hosts/fixture/ssh-defense/transactions/{rid}")
    assert local.status_code == 200
    assert local.json()["request_id"] == rid and local.json()["query_required"]
    assert local.json()["reason_code"] == "unavailable"
    assert local.json()["current_result"] is None
    assert any(row["state"] == "unavailable" for row in local.json()["history"])
    listed = reconnected.get("/api/hosts/fixture/ssh-defense/transactions")
    assert listed.status_code == 200
    assert any(row["request_id"] == rid for row in listed.json()["transactions"])
    assert tuple(h.root.sent) == before
    queried = reconnected.post(f"/api/hosts/fixture/ssh-defense/transactions/{rid}/query", json={})
    assert queried.status_code == 200 and queried.json()["current_result"]["state"] == "active"
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_retired_target_keeps_local_history_readable_without_reopening_transport(harness):
    h = harness
    _, _, _, action = ready(h)
    rid = action["request_id"]
    h.service.targets.clear()
    before = tuple(h.root.sent)
    app = FastAPI()
    register_defense_routes(app, h.service, [])
    client = TestClient(app)
    result = client.get(f"/api/hosts/fixture/ssh-defense/transactions/{rid}")
    assert result.status_code == 200 and result.json()["request_id"] == rid
    listing = client.get("/api/hosts/fixture/ssh-defense/transactions")
    assert listing.status_code == 200
    assert any(row["request_id"] == rid for row in listing.json()["transactions"])
    assert client.get(f"/api/hosts/other/ssh-defense/transactions/{rid}").status_code == 409
    assert (
        client.post(f"/api/hosts/fixture/ssh-defense/transactions/{rid}/query", json={}).status_code
        == 409
    )
    assert tuple(h.root.sent) == before


def test_recheck_query_returns_this_unavailable_observation_instead_of_old_active(harness):
    h = harness
    rev, _, _, action = ready(h)
    assert apply(h, rev, action)["phase"] == "active"
    rid = action["request_id"]
    confirmed = h.store.last_confirmed(rid)
    assert confirmed is not None and confirmed.state == "active"
    h.root.lose = "query"
    observation, result = h.service.query_with_observation("fixture", rid)
    assert result is None and observation.state == "unavailable"
    assert observation.op == "query" and not observation.accepted
    assert h.store.observations(rid)[-1] == observation
    assert h.store.last_confirmed(rid) == confirmed
    assert h.store.transaction(rid).query_required
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_each_read_only_query_has_its_own_observation_even_at_the_same_timestamp(harness):
    h = harness
    _, _, _, action = ready(h)
    first, first_reply = h.service.query_with_observation("fixture", action["request_id"])
    second, second_reply = h.service.query_with_observation("fixture", action["request_id"])
    assert first_reply is not None and second_reply is not None
    assert first.accepted and second.accepted
    assert first.observed_at == second.observed_at
    assert first.observation_id != second.observation_id
    assert h.store.observations(action["request_id"])[-1] == second
    assert not any(op == "apply" for op, _ in h.root.sent)


@pytest.mark.parametrize("change", ["evidence", "source", "revision", "expired"])
def test_stale_prepare_is_stopped(harness, change):
    h = harness
    rev, _, body, _ = ready(h)
    before = sum(op == "prepare" for op, _ in h.root.sent)
    values = body.model_dump()
    if change == "evidence":
        values["expected_evidence_sha256"] = "0" * 64
    elif change == "source":
        values["source_ref"] = "0" * 32
    elif change == "revision":
        values["expected_mode_revision"] = rev - 1
    else:
        h.clock[0] += timedelta(seconds=121)
    with pytest.raises(DefenseConflict):
        h.service.prepare("fixture", PrepareRequest.model_validate(values))
    assert sum(op == "prepare" for op, _ in h.root.sent) == before


def test_duplicate_workers_send_one_apply(harness):
    h = harness
    rev, _, _, action = ready(h)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: apply(h, rev, action), range(2)))
    assert all(result["request_id"] == action["request_id"] for result in results)
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_commit_failure_has_zero_send(harness, monkeypatch):
    h = harness
    rev, _, _, action = ready(h)
    original = h.store.begin_sendable

    def fail_commit(*args, **kwargs):
        def fail(_connection):
            raise OSError("fake sensitive commit error")

        monkeypatch.setattr(h.store, "_commit", fail)
        return original(*args, **kwargs)

    monkeypatch.setattr(h.store, "begin_sendable", fail_commit)
    with pytest.raises(OSError):
        apply(h, rev, action)
    assert not any(op == "apply" for op, _ in h.root.sent)


def test_final_admit_changed_mode_has_zero_send(harness):
    h = harness
    rev, _, _, action = ready(h)
    h.root.before_admit = lambda: h.coordinator.change_mode(
        ModeChange(mode=Mode.manual, expected_revision=rev)
    )
    result = apply(h, rev, action)
    assert result["query_required"] and result["phase"] == "unknown"
    assert not any(op == "apply" for op, _ in h.root.sent)


def test_lost_reply_restart_queries_original_never_replays(harness):
    h = harness
    rev, _, _, action = ready(h)
    h.root.lose = "apply"
    unknown = apply(h, rev, action)
    assert unknown["query_required"] and unknown["last_confirmed"].state == "ready"
    restarted = DefenseService(
        h.service.settings,
        h.service.targets,
        DefenseStore(h.store.path),
        h.automation,
        h.coordinator,
        h.service.policy,
        invoker=h.root,
        clock=lambda: h.clock[0],
    )
    result = restarted.apply(
        "fixture",
        action["request_id"],
        ApplyRequest(
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_mode_revision=rev,
            confirm_execute=True,
        ),
    )
    assert result["phase"] == "active" and sum(op == "apply" for op, _ in h.root.sent) == 1
    assert h.store.latched(
        "fixture", h.store.transaction(action["request_id"]).context.defense_scope
    )


def test_fresh_generation_queries_mode_rid_without_resend(harness):
    h = harness
    ready(h)
    first = [rid for op, rid in h.root.sent if op == "mode_sync"]
    h.coordinator.sync_mode()
    assert [rid for op, rid in h.root.sent if op == "mode_sync"] == first
    status = h.service.status()
    assert status["mode_sync_complete"] and status["sync_generation"] == 2
    assert status["targets"][0]["mode_ack"].context.epoch == 2


def test_auto_requires_durable_ai_proposal_and_separate_entry(harness):
    h = harness
    rev, _, _, action = ready(h, Mode.automatic)
    with pytest.raises(DefenseConflict):
        apply(h, rev, action)
    result = h.service.automatic_apply("fixture", action["request_id"], expected_mode_revision=rev)
    assert result["phase"] == "active"
    assert h.store.request(action["request_id"], "apply").body.approval is None


def test_arm_double_worker_and_restart_reuses_live_cursor(harness):
    h = harness
    h.coordinator.sync_mode()
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(
            workers.map(
                lambda _: h.service.arm(
                    "fixture", ArmRequest(expected_mode_revision=0, confirm_arm=True)
                ),
                range(2),
            )
        )
    assert results[0]["request_id"] == results[1]["request_id"]
    assert sum(op == "arm" for op, _ in h.root.sent) == 1


def test_independent_arm_worker_recovers_original_when_bounded_list_misses_it(harness, monkeypatch):
    h = harness
    h.coordinator.sync_mode()
    body = ArmRequest(expected_mode_revision=0, confirm_arm=True)
    original = h.service.arm("fixture", body)
    independent_store = DefenseStore(h.store.path)
    # The UI listing is bounded. Durable grant/context identity must also protect
    # separate processes whose initial listing did not include the original.
    monkeypatch.setattr(independent_store, "transactions", lambda *_: ())
    restarted = DefenseService(
        h.service.settings,
        {"fixture": h.target},
        independent_store,
        h.automation,
        policy=h.service.policy,
        mode_lock=Lock(),
        invoker=h.root,
        clock=lambda: h.clock[0],
    )
    before = tuple(h.root.sent)
    recovered = restarted.arm("fixture", body)
    assert recovered["request_id"] == original["request_id"]
    assert tuple(h.root.sent[len(before) :]) == (("query", original["request_id"]),)
    assert sum(op == "arm" for op, _ in h.root.sent) == 1


def test_only_mode_query_acknowledges_and_new_epoch_blocks_old_action(harness):
    h = harness
    rev, _, _, action = ready(h)
    h.automation.mark_sync_pending(rev)
    assert not h.automation.status()["mode_sync_complete"]
    h.service.query("fixture", action["request_id"])
    assert not h.automation.status()["mode_sync_complete"]
    h.coordinator.sync_mode()
    with pytest.raises(DefenseConflict):
        apply(h, rev, action)
    assert not any(op == "apply" for op, _ in h.root.sent)


def test_late_independent_revoke_after_cursor_and_execution_grant_expire(harness):
    h = harness
    rev, _, _, action = ready(h)
    h.clock[0] += timedelta(seconds=119)
    assert apply(h, rev, action)["phase"] == "active"
    original = h.store.transaction(action["request_id"])
    h.clock[0] += timedelta(seconds=2)
    result = h.service.revoke(
        "fixture",
        action["request_id"],
        RevokeRequest(
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_mode_revision=rev,
            confirm_revoke=True,
        ),
    )
    assert result["phase"] == "revoked"
    assert h.store.transaction(action["request_id"]).context == original.context
    assert h.store.transaction(action["request_id"]).deadline_at == original.deadline_at


def test_lost_apply_then_fresh_active_query_allows_only_exact_revoke(harness):
    h = harness
    rev, _, body, action = ready(h)
    h.root.lose = "apply"
    assert apply(h, rev, action)["phase"] == "unknown"
    result = h.service.revoke(
        "fixture",
        action["request_id"],
        RevokeRequest(
            expected_manifest_sha256=action["manifest"]["sha256"],
            expected_mode_revision=rev,
            confirm_revoke=True,
        ),
    )
    assert result["phase"] == "revoked"
    assert h.store.latched(
        "fixture", h.store.transaction(action["request_id"]).context.defense_scope
    )
    with pytest.raises(DefenseConflict):
        h.service.prepare("fixture", body)
    assert sum(op == "apply" for op, _ in h.root.sent) == 1


def test_new_revoke_forbidden_in_manual(harness):
    h = harness
    rev, _, _, action = ready(h)
    apply(h, rev, action)
    mode = h.coordinator.change_mode(ModeChange(mode=Mode.manual, expected_revision=rev))
    with pytest.raises(DefenseConflict):
        h.service.revoke(
            "fixture",
            action["request_id"],
            RevokeRequest(
                expected_manifest_sha256=action["manifest"]["sha256"],
                expected_mode_revision=mode["revision"],
                confirm_revoke=True,
            ),
        )
    assert not any(op == "revoke" for op, _ in h.root.sent)


def test_all_network_operations_release_shared_lock(harness):
    h = harness
    original = h.service.invoker

    def checked(*args, **kwargs):
        assert h.service.mode_lock.acquire(blocking=False)
        h.service.mode_lock.release()
        return original(*args, **kwargs)

    h.service.invoker = checked
    rev, _, _, action = ready(h)
    assert apply(h, rev, action)["phase"] == "active"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(enabled=1),
        lambda value: value.update(ttl_ms=60001),
        lambda value: value.update(command="secret"),
        lambda value: value["execution"].update(max_total_actions=9),
        lambda value: value["execution"].update(wire_revisions=[True]),
        lambda value: value["execution"].update(root_grant_refs={}),
        lambda value: value["observation"].update(expires_at=stamp(NOW - timedelta(seconds=60))),
    ],
)
def test_deployment_policy_rejects_broad_or_malformed_authority(target, mutate):
    value = policy(target).model_dump(mode="json")
    mutate(value)
    with pytest.raises(ValidationError):
        DefensePolicy.model_validate_json(canonical(value))


def test_load_policy_uses_only_new_private_file(tmp_path, target):
    path = tmp_path / "fake-policy.json"
    deployment = policy(target)
    path.write_bytes(canonical(deployment))
    path.chmod(0o600)
    assert load_policy(path) == deployment
    path.write_bytes(b'{"enabled":false,"enabled":true}')
    with pytest.raises(ValueError, match="could not be verified"):
        load_policy(path)


@pytest.mark.parametrize("mode", [Mode.assisted, Mode.automatic])
def test_requires_ai_without_validator_cannot_prepare(tmp_path, target, mode):
    deployment = policy(target, ai={"enabled": False, "requires_ai": True})
    scope = defense_service_scope({"fixture": target}, deployment)
    assert scope is not None
    participant = ModeParticipant("ssh-defense", scope, lambda _: False)
    automation = AutomationStore(
        tmp_path / "mode.sqlite3",
        ControlPolicy(),
        supplemental_scope=supplemental_scope((participant,)),
    )
    store, lock = DefenseStore(tmp_path / "security.sqlite3"), Lock()
    root = FakeRoot(target, lambda: NOW)
    service = DefenseService(
        Settings(tmp_path, "newfake-required-ai-test-token"),
        {"fixture": target},
        store,
        automation,
        policy=deployment,
        mode_lock=lock,
        invoker=root,
        clock=lambda: NOW,
    )
    channel = service.participant()
    assert channel is not None
    coordinator = ModeCoordinator(automation, lock, (channel,))
    rev = coordinator.change_mode(ModeChange(mode=mode, expected_revision=0))["revision"]
    cursor = service.arm("fixture", ArmRequest(expected_mode_revision=rev, confirm_arm=True))
    with pytest.raises(DefenseServiceError, match="cannot be admitted") as error:
        service.prepare(
            "fixture",
            PrepareRequest(
                cursor_request_id=cursor["request_id"],
                source_ref=SOURCE,
                expected_evidence_sha256=EVIDENCE,
                expected_mode_revision=rev,
            ),
        )
    assert error.value.code == "ai_required"
    assert not any(op in {"prepare", "apply"} for op, _ in root.sent)


def test_mode_sync_response_is_not_ack_and_retry_is_only_query(harness):
    h = harness
    h.root.lose = "query"
    with pytest.raises(ModeSynchronizationError):
        h.coordinator.change_mode(ModeChange(mode=Mode.assisted, expected_revision=0))
    assert not h.automation.status()["mode_sync_complete"]
    assert h.service.status()["targets"][0]["mode_ack"].status == "unknown"
    original = [rid for op, rid in h.root.sent if op == "mode_sync"]
    h.coordinator.sync_mode()
    assert [rid for op, rid in h.root.sent if op == "mode_sync"] == original
    assert h.service.status()["targets"][0]["mode_ack"].status == "confirmed"


def test_unsent_mode_intent_cross_epoch_is_not_replaced_or_sent(harness):
    h = harness
    h.automation.mark_sync_pending(0)
    context = h.service._context("fixture")
    transaction = h.store.create_transaction(
        kind="mode",
        context=context,
        owner="fake-owner",
        deadline_at=stamp(NOW + timedelta(seconds=120)),
        now=NOW,
    )
    h.store.register_mode_pending(transaction.rid, now=NOW)
    h.store.save_request(
        transaction.rid,
        DefenseRequest(
            v=1,
            op="mode_sync",
            request_id=transaction.rid,
            scope_sha256=context.root_scope,
            body=ModeBody(mode="manual", mode_revision=1, policy_sha256=POLICY_SHA256),
        ),
    )
    with pytest.raises(ModeSynchronizationError):
        h.coordinator.sync_mode()
    assert not h.root.sent
    assert len(h.store.transactions()) == 1
    assert h.store.mode_rid(h.service._context("fixture")) == transaction.rid


@pytest.mark.parametrize("kind", ["extra", "bool", "manifest"])
def test_service_revalidates_complete_root_reply_before_authorizing(harness, kind):
    import json

    h = harness
    rev, _, _, action = ready(h)

    def malformed(raw):
        value = json.loads(raw)
        if kind == "extra":
            value["root_secret"] = "never-reflect"
        elif kind == "bool":
            value["mode_revision"] = True
        else:
            value["manifest_sha256"] = "0" * 64
        return canonical(value) + b"\n"

    h.root.break_reply = malformed
    result = apply(h, rev, action)
    assert result["phase"] == "unknown" and result["current_result"] is None
    assert result["last_confirmed"].state == "ready"
    assert "never-reflect" not in str(result)


@pytest.mark.parametrize("after_query", ["unavailable", "unknown", "stale", "ttl_exhausted"])
def test_latched_revoke_requires_latest_fresh_live_query(harness, monkeypatch, after_query):
    h = harness
    rev, _, _, action = ready(h)
    rid = action["request_id"]
    h.root.lose = "apply"
    assert apply(h, rev, action)["phase"] == "unknown"
    context = h.store.transaction(rid).context
    assert h.store.latched("fixture", context.defense_scope)
    if after_query == "ttl_exhausted":
        h.root.records[rid]["active_until"] = h.clock[0] + timedelta(milliseconds=1)
    original = h.service.query

    def query_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        if after_query == "unavailable":
            h.store.record_unavailable(rid, "query", context=context, now=h.clock[0])
        elif after_query == "unknown":
            reply = h.store.latest_reply(rid).model_copy(
                update={"state": "unknown", "remaining_ms": None, "reason_code": "result_unknown"}
            )
            h.store.record_reply(rid, "query", reply, context=context, now=h.clock[0])
        else:
            h.clock[0] += (
                timedelta(seconds=6) if after_query == "stale" else timedelta(milliseconds=2)
            )
        return result

    monkeypatch.setattr(h.service, "query", query_then_change)
    with pytest.raises(DefenseConflict):
        h.service.revoke(
            "fixture",
            rid,
            RevokeRequest(
                expected_manifest_sha256=action["manifest"]["sha256"],
                expected_mode_revision=rev,
                confirm_revoke=True,
            ),
        )
    assert not any(op == "revoke" for op, _ in h.root.sent)
    assert h.store.latched("fixture", context.defense_scope)
    assert h.store.last_confirmed(rid).state == "active"
