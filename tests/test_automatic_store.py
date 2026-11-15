import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from opsark.automatic_store import AutomaticStore

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)


def candidate(store, *, host="server-a", scope="a" * 64, index=1, grant="b" * 32, scan=None):
    return store.claim_candidate(
        host_id=host,
        scope_hash=scope,
        finding_id=f"{index:064x}",
        package="libbrotli1",
        current_version="1.1.0-2build2",
        candidate_version="1.1.0-2ubuntu0.1",
        grant_id=grant,
        grant_digest="c" * 64,
        scan_id=scan or f"{index:032x}",
        owner="d" * 32,
        now=NOW,
    )


def reserve(store, value, *, daily=5, total=5, now=NOW):
    plan = {
        "host_id": value["host_id"],
        "plan_id": value["job_id"],
        "plan_digest": "e" * 64,
        "mode_revision": 3,
    }
    return store.reserve_submission(
        value["id"], plan, 3, daily_limit=daily, total_limit=total, now=now
    )


def result(value, status="verified", revision=1):
    return {
        "host_id": value["host_id"],
        "job_id": value["job_id"],
        "plan_id": value["plan_id"],
        "status": status,
        "revision": revision,
    }


def test_closes_connection_when_database_permission_setup_fails(tmp_path, monkeypatch):
    store = AutomaticStore(tmp_path / "automatic.db")
    chmod = Path.chmod

    def deny_database_permissions(path, mode, **kwargs):
        if path == store.path:
            raise PermissionError("database permission setup failed")
        return chmod(path, mode, **kwargs)

    with closing(sqlite3.connect(store.path)) as connection, monkeypatch.context() as setup:
        setup.setattr(sqlite3, "connect", lambda *_args, **_kwargs: connection)
        setup.setattr(Path, "chmod", deny_database_permissions)
        with pytest.raises(PermissionError, match="database permission setup failed"):
            store.list_attempts()
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_intent_identity_is_durable_and_cannot_replay_after_verified_or_new_grant(tmp_path):
    path = tmp_path / "automatic.db"
    store = AutomaticStore(path)
    value = reserve(store, candidate(store))
    assert len(value["job_id"]) == 32
    assert store.quotas("server-a", "b" * 32, now=NOW) == {"daily_used": 1, "total_used": 1}
    store.record_result(value["id"], result(value), now=NOW)
    restarted = AutomaticStore(path)
    assert candidate(restarted) is None
    assert candidate(restarted, scan="f" * 32, grant="f" * 32) is None
    assert restarted.get(value["id"])["job_id"] == value["job_id"]


def test_explicit_prepare_rejection_can_replan_only_from_a_new_scan(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    first = candidate(store)
    store.defer(first["id"], "fresh evidence needed", now=NOW)
    assert candidate(store) is None
    newer = candidate(store, scan="f" * 32)
    assert newer["id"] == first["id"] and newer["job_id"] == first["job_id"]
    assert newer["scan_id"] != first["scan_id"]


def test_unsubmitted_deferred_candidate_can_use_a_new_grant_only_after_a_new_scan(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    first = candidate(store)
    store.defer(first["id"], "new authorization needed", now=NOW)
    assert candidate(store, grant="f" * 32) is None
    replanned = candidate(store, grant="f" * 32, scan="f" * 32)
    assert replanned["id"] == first["id"] and replanned["grant_id"] == "f" * 32
    reserved = reserve(store, replanned)
    assert store.quotas("server-a", "b" * 32, now=NOW)["total_used"] == 0
    assert store.quotas("server-a", "f" * 32, now=NOW)["total_used"] == 1
    assert reserved["job_id"] == first["job_id"]


@pytest.mark.parametrize(
    "failure",
    [
        "unknown",
        "failed",
        "verification_failed",
        "reboot_pending",
        "installed_restart_pending",
        "rejected",
        "running_overdue",
    ],
)
def test_safety_latch_survives_process_scope_grant_and_later_success(tmp_path, failure):
    path = tmp_path / "automatic.db"
    store = AutomaticStore(path)
    value = reserve(store, candidate(store))
    store.record_result(value["id"], result(value, failure), now=NOW)
    store.record_result(value["id"], result(value, "verified", 2), now=NOW)
    restarted = AutomaticStore(path)
    assert restarted.latch("server-a")["reason"] == failure
    assert candidate(restarted, scope="f" * 64, grant="f" * 32, index=2) is None
    assert restarted.get(value["id"])["status"] == "verified"


def test_daily_host_quota_crosses_grants_and_scope_but_grant_total_crosses_hosts(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    first = reserve(store, candidate(store))
    store.record_result(first["id"], result(first), now=NOW)
    next_grant = candidate(store, grant="f" * 32, scope="f" * 64, index=2)
    assert reserve(store, next_grant, daily=1) is None
    other = candidate(store, host="server-b", index=3)
    assert reserve(store, other, total=1) is None
    assert store.quotas("server-a", "b" * 32, now=NOW + timedelta(days=1)) == {
        "daily_used": 0,
        "total_used": 1,
    }


def test_independent_service_authorization_requires_exact_persisted_intent(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    value = reserve(store, candidate(store))
    fields = dict(
        host_id=value["host_id"],
        job_id=value["job_id"],
        plan_id=value["plan_id"],
        plan_digest=value["plan_digest"],
        mode_revision=3,
        grant_id=value["grant_id"],
        grant_digest=value["grant_digest"],
        now=NOW,
    )
    authorized = store.authorize_intent(**fields)
    assert authorized["daily_used_before"] == authorized["total_used_before"] == 0
    for changed in (
        {"job_id": "f" * 32},
        {"plan_digest": "f" * 64},
        {"mode_revision": 4},
        {"grant_id": "f" * 32},
        {"grant_digest": "f" * 64},
        {"host_id": "other"},
    ):
        with pytest.raises(ValueError):
            store.authorize_intent(**(fields | changed))
    store.mark_unknown(value["id"], now=NOW)
    with pytest.raises(ValueError):
        store.authorize_intent(**fields)


def test_one_atomic_quota_reservation_for_simultaneous_hosts(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    values = [candidate(store, host=f"host-{i}", index=i) for i in (1, 2)]
    with ThreadPoolExecutor(max_workers=2) as workers:
        reserved = list(workers.map(lambda value: reserve(store, value, total=1), values))
    assert sum(value is not None for value in reserved) == 1
    assert store.quotas("host-1", "b" * 32, now=NOW)["total_used"] == 1


def test_monitor_lease_and_interrupted_planning_need_new_scan_and_never_install(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    value = candidate(store)
    assert store.claim_monitor("d" * 32, now=NOW)
    assert not store.claim_monitor("f" * 32, now=NOW)
    assert store.claim_monitor("f" * 32, now=NOW + timedelta(minutes=4))
    store.recover_interrupted_plans("f" * 32, now=NOW + timedelta(minutes=4))
    assert store.get(value["id"])["state"] == "deferred"
    assert candidate(store) is None
    assert store.active_attempts() == []


def test_store_deletion_does_not_silently_reset_quota_or_latches(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    store.path.unlink()
    with pytest.raises(ValueError, match="disappeared"):
        store.quotas("server-a", "b" * 32, now=NOW)


def test_store_refuses_a_linked_sqlite_sidecar(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    target = tmp_path / "ordinary"
    target.write_text("not a SQLite journal")
    try:
        (tmp_path / "automatic.db-journal").symlink_to(target)
    except OSError:
        pytest.skip("Creating symbolic links requires a Windows developer-mode privilege")
    with pytest.raises(ValueError, match="symbolic"):
        store.quotas("server-a", "b" * 32, now=NOW)


@pytest.mark.parametrize("bad", [True, None, -1, 0, 6, "1"])
def test_unknown_or_unbounded_quota_is_never_a_zero_usage_authorization(tmp_path, bad):
    store = AutomaticStore(tmp_path / "automatic.db")
    with pytest.raises(ValueError):
        reserve(store, candidate(store), daily=bad)


def test_old_or_wrong_remote_result_cannot_change_registered_identity(tmp_path):
    store = AutomaticStore(tmp_path / "automatic.db")
    value = reserve(store, candidate(store))
    store.record_result(value["id"], result(value, "verified", 3), now=NOW)
    unchanged = store.record_result(value["id"], result(value, "applying", 2), now=NOW)
    assert unchanged["status"] == "verified" and store.latch("server-a") is None
    with pytest.raises(ValueError):
        store.record_result(value["id"], result(value) | {"plan_id": "f" * 32}, now=NOW)
    with pytest.raises(ValueError, match="Conflicting"):
        store.record_result(value["id"], result(value, "failed", 3), now=NOW)
