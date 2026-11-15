"""Global mode boundaries cover independent execution channels without network-held locks."""

import sqlite3
from threading import Event, Lock, Thread

import pytest

from opsark.automation_store import AutomationStore, ModeChange, StaleModeError
from opsark.control_modes import ControlPolicy
from opsark.mode_coordinator import (
    ModeCoordinator,
    ModeParticipant,
    ModeSnapshot,
    supplemental_scope,
)
from opsark.patch_api import ModeSynchronizationError, PatchService
from opsark.patch_store import PatchStore


def coordinator(tmp_path, callbacks, *, apt=False):
    lock = Lock()
    participants = tuple(
        ModeParticipant(name, str(index + 1) * 64, callback)
        for index, (name, callback) in enumerate(callbacks.items())
    )
    store = AutomationStore(
        tmp_path / "automation.sqlite3",
        ControlPolicy(),
        driver_scope=participants[0].scope if apt else None,
        supplemental_scope=supplemental_scope(participants),
    )
    return ModeCoordinator(store, lock, participants), store, lock


def test_legacy_absent_channel_keeps_existing_scope_revision_and_disabled_execution(tmp_path):
    path = tmp_path / "automation.sqlite3"
    before = AutomationStore(path, ControlPolicy()).status()
    after = AutomationStore(path, ControlPolicy(), supplemental_scope=None).status()
    assert before == after
    assert after["mode"] == "manual" and after["revision"] == 0
    assert after["mode_sync_complete"] and not after["execution_available"]


def test_defense_only_has_real_pending_boundary_without_granting_apt(tmp_path):
    observed = []

    def acknowledge(snapshot):
        assert lock.acquire(blocking=False), "The mode admission lock must not span network work"
        lock.release()
        observed.append((snapshot.mode, snapshot.revision, snapshot.wire_revision))
        assert not store.status()["mode_sync_complete"]
        return True

    service, store, lock = coordinator(tmp_path, {"ssh-defense": acknowledge})
    assert not store.status()["mode_sync_complete"]
    status = service.change_mode(ModeChange(mode="assisted", expected_revision=0))
    assert observed == [("assisted", 1, 2)]
    assert status["mode_sync_complete"] and status["mode"] == "assisted"
    assert store.driver_scope is None and not status["execution_available"]
    assert status["policy"]["enabled"] is False


def test_downgrade_attempts_all_channels_and_partial_ack_never_opens_admission(tmp_path):
    calls = []

    def offline(snapshot):
        calls.append(("apt", snapshot.mode))
        raise OSError("synthetic sensitive diagnostic must not be reflected")

    def defense(snapshot):
        calls.append(("defense", snapshot.mode))
        return True

    service, store, _ = coordinator(
        tmp_path, {"ubuntu-apt": offline, "ssh-defense": defense}, apt=True
    )
    with pytest.raises(ModeSynchronizationError, match="已停止新动作") as error:
        service.change_mode(ModeChange(mode="assisted", expected_revision=0))
    assert "sensitive" not in str(error.value)
    assert calls == [("apt", "assisted"), ("defense", "assisted")]
    assert not store.status()["mode_sync_complete"]
    calls.clear()
    with pytest.raises(ModeSynchronizationError):
        service.change_mode(ModeChange(mode="manual", expected_revision=1))
    assert calls == [("apt", "manual"), ("defense", "manual")]
    assert store.status()["mode"] == "manual" and not store.status()["mode_sync_complete"]


def test_confirmed_all_channels_only_finishes_after_last_ack(tmp_path):
    seen = []

    def apt(snapshot):
        seen.append("apt")
        assert not store.status()["mode_sync_complete"]
        return True

    def defense(snapshot):
        seen.append("defense")
        assert not store.status()["mode_sync_complete"]
        return True

    service, store, _ = coordinator(tmp_path, {"ubuntu-apt": apt, "ssh-defense": defense}, apt=True)
    assert service.sync_mode()["mode_sync_complete"]
    assert seen == ["apt", "defense"]


def test_old_blocked_sync_cannot_delay_local_manual_or_confirm_new_revision(tmp_path):
    entered, release = Event(), Event()
    errors = []
    remote = {"revision": 0, "mode": "manual"}

    def native(snapshot):
        if snapshot.revision == 1:
            entered.set()
            assert release.wait(5)
        if snapshot.revision < remote["revision"]:
            return False
        remote.update(revision=snapshot.revision, mode=snapshot.mode)
        return True

    service, store, _ = coordinator(tmp_path, {"ssh-defense": native})

    def old_change():
        try:
            service.change_mode(ModeChange(mode="automatic", expected_revision=0))
        except Exception as error:
            errors.append(error)

    worker = Thread(target=old_change, daemon=True)
    worker.start()
    try:
        assert entered.wait(5)
        assert store.status()["mode"] == "automatic"
        status = service.change_mode(ModeChange(mode="manual", expected_revision=1))
        assert status["mode"] == "manual" and status["revision"] == 2
        assert status["mode_sync_complete"]
        assert remote == {"revision": 2, "mode": "manual"}
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and len(errors) == 1 and isinstance(errors[0], StaleModeError)
    assert store.status()["mode_sync_complete"] and store.status()["revision"] == 2


@pytest.mark.parametrize("newer_finishes", [False, True])
def test_same_revision_old_ack_cannot_clear_new_pending_or_failure(tmp_path, newer_finishes):
    entered, release = Event(), Event()
    errors = []

    def old_ack(_snapshot):
        entered.set()
        assert release.wait(5)
        return True

    first, store, _ = coordinator(tmp_path, {"ssh-defense": old_ack})
    # A second coordinator is deliberately a distinct lock and SQLite object.
    other = AutomationStore(
        store.path, ControlPolicy(), supplemental_scope=store.supplemental_scope
    )
    second = ModeCoordinator(
        other, Lock(), (ModeParticipant("ssh-defense", "1" * 64, lambda _: False),)
    )

    def run_first():
        try:
            first.sync_mode()
        except Exception as error:
            errors.append(error)

    worker = Thread(target=run_first, daemon=True)
    worker.start()
    try:
        assert entered.wait(5)
        if newer_finishes:
            with pytest.raises(ModeSynchronizationError):
                second.sync_mode()
        else:
            second._begin(None)
        current_generation = other.status()["sync_generation"]
        assert current_generation >= 2 and not other.status()["mode_sync_complete"]
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and len(errors) == 1 and isinstance(errors[0], StaleModeError)
    assert not other.status()["mode_sync_complete"]
    assert other.status()["sync_generation"] == current_generation
    with pytest.raises(StaleModeError):
        other.finish_sync(0)


def test_coordinator_manual_change_does_not_wait_for_legacy_rpc_lock(tmp_path):
    service, store, _ = coordinator(tmp_path, {"ssh-defense": lambda _: True})
    patch = PatchService({}, PatchStore(tmp_path / "patches.sqlite3"), store)
    patch.mode_coordinator = service
    # Old repair/activation paths may hold this lock over already-admitted RPC.
    with patch.mode_lock:
        status = patch.change_mode(ModeChange(mode="assisted", expected_revision=0))
        assert status["mode"] == "assisted"
        status = patch.change_mode(ModeChange(mode="manual", expected_revision=1))
        assert status["mode"] == "manual" and status["revision"] == 2
    service.mode_lock = patch.mode_lock
    with pytest.raises(ValueError, match="旧 RPC 执行锁"):
        patch.sync_mode()


def test_local_commit_failure_never_calls_any_transport(tmp_path, monkeypatch):
    calls = []
    service, store, _ = coordinator(tmp_path, {"ssh-defense": lambda s: calls.append(s) or True})

    def fail(_revision):
        raise sqlite3.OperationalError("synthetic write failure")

    monkeypatch.setattr(store, "mark_sync_pending", fail)
    with pytest.raises(sqlite3.OperationalError):
        service.change_mode(ModeChange(mode="assisted", expected_revision=0))
    assert calls == [] and not store.status()["mode_sync_complete"]


def test_new_channel_scope_resets_to_manual_and_old_store_is_stale(tmp_path):
    service, old, _ = coordinator(tmp_path, {"ssh-defense": lambda _: True})
    service.change_mode(ModeChange(mode="automatic", expected_revision=0))
    changed = AutomationStore(old.path, ControlPolicy(), supplemental_scope="f" * 64)
    assert changed.status()["mode"] == "manual" and changed.status()["revision"] == 2
    with pytest.raises(StaleModeError):
        service.sync_mode()


def test_wrong_participants_cannot_omit_or_add_an_apt_authority(tmp_path):
    apt = ModeParticipant("ubuntu-apt", "1" * 64, lambda _: True)
    defense = ModeParticipant("ssh-defense", "2" * 64, lambda _: True)
    registry = supplemental_scope((defense,))
    store = AutomationStore(
        tmp_path / "a.sqlite3", ControlPolicy(), driver_scope=apt.scope, supplemental_scope=registry
    )
    with pytest.raises(ValueError, match="补丁通道"):
        ModeCoordinator(store, Lock(), (defense,))
    store = AutomationStore(tmp_path / "b.sqlite3", ControlPolicy(), supplemental_scope=registry)
    with pytest.raises(ValueError, match="补丁通道"):
        ModeCoordinator(store, Lock(), (apt, defense))
    with pytest.raises(ValueError, match="不能重复"):
        supplemental_scope((defense, defense))


@pytest.mark.parametrize("ack", [None, {}, {"ok": True}, 1, "true"])
def test_truthy_or_malformed_ack_does_not_complete_sync(tmp_path, ack):
    service, store, _ = coordinator(tmp_path, {"ssh-defense": lambda _: ack})
    with pytest.raises(ModeSynchronizationError):
        service.sync_mode()
    assert not store.status()["mode_sync_complete"]


@pytest.mark.parametrize("revision", [2**31 - 1, -1])
def test_positive_wire_revision_is_bounded(revision):
    with pytest.raises(ValueError):
        _ = ModeSnapshot("1" * 64, "manual", revision).wire_revision
