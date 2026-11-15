import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

from opsark import patch_store
from opsark.patch_store import PatchStore

JOB = "a" * 32
PLAN = "b" * 32


def job(status="queued", revision=0, **fields):
    return {"job_id": JOB, "status": status, "revision": revision} | fields


def test_scan_latest_is_durable_separate_per_host_and_not_caller_mutable(tmp_path):
    path = tmp_path / "patch.db"
    store = PatchStore(path)
    scan = {"findings": [{"id": "CVE-example", "affected": True}]}
    store.save_scan("host-a", scan)
    scan["findings"].clear()
    store.save_scan("host-b", {"findings": []})
    restored = PatchStore(path)
    assert len(restored.latest_scan("host-a")["findings"]) == 1
    assert restored.latest_scan("host-b")["findings"] == []
    assert restored.latest_scan("unscanned") is None
    store.save_scan("host-a", {"findings": [], "coverage": "complete"})
    assert restored.latest_scan("host-a")["findings"] == []


def test_remote_plan_is_immutable_and_host_bound(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    payload = {"plan_id": PLAN, "plan_digest": "d" * 64, "packages": ["leaf"]}
    store.save_plan("host-a", payload)
    before = store.get_plan("host-a", PLAN)
    store.save_plan("host-a", payload)
    assert store.get_plan("host-a", PLAN) == before
    assert store.get_plan("host-b", PLAN) is None
    with pytest.raises(ValueError, match="immutable"):
        store.save_plan("host-a", payload | {"packages": ["extra-package"]})
    with pytest.raises(ValueError, match="different host"):
        store.save_plan("host-b", payload | {"host_id": "host-a"})


@pytest.mark.parametrize("status", sorted(patch_store.TERMINAL_STATES))
def test_terminal_notice_is_emitted_once_across_polling_and_restart(tmp_path, status):
    path = tmp_path / "patch.db"
    store = PatchStore(path)
    assert store.save_job("host-a", job())["notification_due"] is False
    first = store.save_job("host-a", job(status, 1))
    assert first["notification_due"] is True and first["notification_count"] == 1
    for _ in range(3):
        repeated = PatchStore(path).save_job("host-a", job(status, 1))
        assert repeated["notification_due"] is False
        assert repeated["notification_count"] == 1
        assert repeated["last_notified_at"] == first["last_notified_at"]
    assert store.get_job("host-a", JOB)["notification_due"] is False
    assert store.list_jobs()[0]["notification_due"] is False


def test_terminal_status_changes_notice_but_nonterminal_changes_do_not(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    for revision, status in enumerate(sorted(patch_store.ACTIVE_STATES)):
        assert store.save_job("host-a", job(status, revision))["notification_due"] is False
    first = store.save_job("host-a", job("unknown", 10))
    assert first["notification_count"] == 1
    resolved = store.save_job("host-a", job("verified", 11))
    assert resolved["notification_due"] is True and resolved["notification_count"] == 2
    assert store.save_job("host-b", job("verified", 11))["notification_count"] == 1


def test_old_or_conflicting_revision_cannot_replace_newer_authoritative_result(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    store.save_job("host-a", job("verified", 3))
    assert store.save_job("host-a", job("applying", 2))["status"] == "verified"
    missing_revision = {"job_id": JOB, "status": "applying"}
    assert store.save_job("host-a", missing_revision)["status"] == "verified"
    with pytest.raises(ValueError, match="Conflicting"):
        store.save_job("host-a", job("failed", 3))
    assert store.get_job("host-a", JOB)["status"] == "verified"


def test_concurrent_pollers_emit_one_notice(tmp_path):
    path = tmp_path / "patch.db"
    stores = [PatchStore(path) for _ in range(6)]
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(lambda store: store.save_job("host-a", job("verified")), stores)
        )
    assert sum(result["notification_due"] for result in results) == 1
    assert all(result["notification_count"] == 1 for result in results)


def test_retention_does_not_drop_active_jobs(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_store, "MAX_JOBS", 3)
    store = PatchStore(tmp_path / "patch.db")
    store.save_job("host-a", job("verified", job_id="1" * 32))
    for index in (2, 3, 4):
        store.save_job("host-a", job(job_id=str(index) * 32))
    assert store.get_job("host-a", "1" * 32) is None
    assert len(store.list_jobs()) == 3
    with pytest.raises(ValueError, match="active jobs"):
        store.save_job("host-a", job(job_id="5" * 32))
    assert store.get_job("host-a", "5" * 32) is None
    assert {item["job_id"] for item in store.list_jobs()} == {str(i) * 32 for i in (2, 3, 4)}


def test_scan_and_plan_counts_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_store, "MAX_SCANS", 2)
    monkeypatch.setattr(patch_store, "MAX_PLANS", 2)
    store = PatchStore(tmp_path / "patch.db")
    for index in range(4):
        store.save_scan(f"host-{index}", {"findings": []})
        store.save_plan("host-a", {"plan_id": f"{index:032x}"})
    with closing(sqlite3.connect(store.path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM patch_scans").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM patch_plans").fetchone()[0] == 2


def test_payload_limits_count_utf8_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_store, "MAX_SCAN_BYTES", 100)
    monkeypatch.setattr(patch_store, "MAX_RECORD_BYTES", 100)
    store = PatchStore(tmp_path / "patch.db")
    with pytest.raises(ValueError, match="budget"):
        store.save_scan("host-a", {"text": "字" * 35})
    with pytest.raises(ValueError, match="budget"):
        store.save_plan("host-a", {"plan_id": PLAN, "text": "x" * 100})
    with pytest.raises(ValueError, match="budget"):
        store.save_job("host-a", job(text="x" * 100))


@pytest.mark.parametrize(
    "payload",
    [
        job("fabricated"),
        job(revision=True),
        job(revision=-1),
        job(job_id="../other"),
        job(host_id="other-host"),
        job(extra=float("nan")),
    ],
)
def test_invalid_job_cannot_enter_the_cache(tmp_path, payload):
    store = PatchStore(tmp_path / "patch.db")
    with pytest.raises(ValueError):
        store.save_job("host-a", payload)
    assert store.list_jobs() == []


@pytest.mark.parametrize("limit", [0, 101, True, "10"])
def test_list_limit_is_strict_and_bounded(tmp_path, limit):
    store = PatchStore(tmp_path / "patch.db")
    with pytest.raises(ValueError):
        store.list_jobs(limit=limit)


def test_paths_and_identifiers_are_not_accepted_as_query_ids(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    for value in ("../host", "host'; DROP TABLE patch_jobs;--", ""):
        with pytest.raises(ValueError):
            store.latest_scan(value)
    with pytest.raises(ValueError):
        store.get_job("host-a", "/root/job")


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions and symbolic links")
def test_database_private_permissions_and_symlink_refusal(tmp_path):
    private = tmp_path / "private"
    store = PatchStore(private / "patch.db")
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    linked = tmp_path / "linked.db"
    linked.symlink_to(store.path)
    with pytest.raises(ValueError, match="links"):
        PatchStore(linked)
    sidecar = private / "patch.db-journal"
    sidecar.symlink_to(tmp_path / "unrelated")
    with pytest.raises(ValueError, match="links"):
        store.latest_scan("host-a")


def test_hard_linked_database_is_refused(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    linked = tmp_path / "hardlink.db"
    try:
        os.link(store.path, linked)
    except OSError:
        pytest.skip("Filesystem does not allow hard links")
    with pytest.raises(ValueError, match="single-link"):
        PatchStore(linked)


def test_submission_intent_survives_restart_and_prevents_a_second_dispatch(tmp_path):
    path = tmp_path / "patch.db"
    store = PatchStore(path)
    assert store.register_submission("host-a", JOB, PLAN, "c" * 64, 2) is True
    restarted = PatchStore(path)
    assert restarted.register_submission("host-a", JOB, PLAN, "c" * 64, 2) is False
    intent = restarted.get_job("host-a", JOB)
    assert intent["status"] == "unknown" and intent["job_id"] == JOB
    assert restarted.pollable_jobs()[0]["job_id"] == JOB
    assert restarted.list_jobs()[0]["job_id"] == JOB
    with pytest.raises(ValueError, match="another plan"):
        restarted.register_submission("host-a", JOB, "d" * 32, "c" * 64, 2)
    saved = restarted.save_job("host-a", job("verified", 1, plan_id=PLAN))
    assert saved["notification_due"] is True
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM patch_submit_intents").fetchone()[0] == 0


def test_unknown_transport_keeps_last_remote_revision_and_can_be_reconciled(tmp_path):
    store = PatchStore(tmp_path / "patch.db")
    store.save_job("host-a", job("applying", 5, plan_id=PLAN))
    unknown = store.mark_unknown("host-a", JOB, PLAN)
    assert unknown["status"] == "unknown" and "revision" not in unknown
    assert unknown["last_remote_revision"] == 5
    assert store.save_job("host-a", job("preflight", 3, plan_id=PLAN))["status"] == "unknown"
    recovered = store.save_job("host-a", job("applying", 5, plan_id=PLAN))
    assert recovered["status"] == "applying" and recovered["revision"] == 5


def test_pollable_lease_has_one_owner_and_release_is_scoped(tmp_path):
    first = PatchStore(tmp_path / "patch.db")
    second = PatchStore(tmp_path / "patch.db")
    assert first.claim_monitor("a" * 32)
    assert first.claim_monitor("a" * 32)
    assert second.claim_monitor("b" * 32) is False
    second.release_monitor("b" * 32)
    assert second.claim_monitor("b" * 32) is False
    first.release_monitor("a" * 32)
    assert second.claim_monitor("b" * 32)
