"""Private generation equality survives SQLite backup without entering public report DTOs."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest
from test_storage import make_report
from test_store_transfer import directory_digests, make_directory, transfer

from opsark.baselines import diagnostic_scope_for
from opsark.compose_generation import _Witness
from opsark.compose_generation_store import _TABLE, ComposeGenerationStore
from opsark.models import BaselineInfo, HostPublic
from opsark.report_handoff import handoff_markdown
from opsark.storage import ReportStore

AT = datetime(2026, 6, 10, tzinfo=UTC)


def report(report_id, elapsed=0, *, scope_change=False):
    host = HostPublic(
        id="private-lab",
        name="Lab",
        address="192.0.2.5",
        source="ssh",
        trusted_hosts_digest="d" * 64,
        disk_reclaim_scope_digest="a" * 64 if scope_change else None,
    )
    return make_report().model_copy(
        update={
            "id": report_id,
            "host_id": host.id,
            "source": "ssh",
            "scenario": "container_restart",
            "created_at": AT + timedelta(seconds=elapsed),
            "scope_hash": diagnostic_scope_for(host),
            "target": host,
        }
    )


def witness(elapsed=0, **changes):
    return _Witness.model_validate(
        {
            "binding": "01" * 32,
            "key_epoch": "23" * 32,
            "container": "45" * 32,
            "image": "67" * 32,
            "configuration": "89" * 32,
            "compose_version": "ab" * 32,
            "observed_at": AT + timedelta(seconds=elapsed),
        }
        | changes
    )


def baseline(original):
    return BaselineInfo(
        id="baseline-original",
        report_id=original.id,
        host_id=original.host_id,
        source="ssh",
        scenario="container_restart",
        created_at=AT + timedelta(seconds=1),
        scope_hash=original.scope_hash,
        features={},
        references={},
    )


def database(directory, *reports):
    store = ReportStore(directory / "reports.sqlite3")
    for item in reports:
        store.save(item)
    return store, ComposeGenerationStore(store)


def close_offline(*directories):
    for directory in directories:
        with closing(sqlite3.connect(directory / "reports.sqlite3")) as db:
            assert db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"


def test_lazy_storage_original_report_and_customer_summary_omit_private_markers(tmp_path):
    original, current = report("original"), report("current", 2)
    reports, generation = database(tmp_path, original, current)
    assert generation.compare_to_baseline(current.id, baseline(original)).status == "unavailable"
    with reports._connection() as db:
        assert db.execute("SELECT 1 FROM sqlite_schema WHERE name=?", (_TABLE,)).fetchone() is None
    before, after = witness(), witness(2, container="ef" * 32, image="12" * 32)
    generation.save(original.id, before)
    generation.save(original.id, before)
    generation.save(current.id, after)
    reopened = ComposeGenerationStore(ReportStore(reports.path))
    result = reopened.compare_to_baseline(current.id, baseline(original))
    assert (result.container, result.image, result.compose_configuration) == (
        "changed",
        "changed",
        "unchanged",
    )
    assert (
        result.status == "observed"
        and result.actor == result.deployment_source == result.changed_at == "unknown"
    )
    saved = reports.get(current.id)
    assert saved == current
    public = saved.model_dump_json() + handoff_markdown(saved) + result.model_dump_json()
    for private in (
        before.binding,
        before.key_epoch,
        before.image,
        after.image,
        after.container,
        before.configuration,
    ):
        assert private not in public
    with pytest.raises(ValueError, match="inconsistent"):
        generation.save(current.id, witness(2, container="ff" * 32))


@pytest.mark.parametrize("mismatch", ["scope", "key", "binding", "time", "future_baseline"])
def test_pair_drift_and_reversed_observation_never_compare(tmp_path, mismatch):
    original, current = report("original"), report("current", 2, scope_change=mismatch == "scope")
    _, generation = database(tmp_path, original, current)
    generation.save(original.id, witness())
    changes = (
        {"key_epoch": "44" * 32}
        if mismatch == "key"
        else {"binding": "44" * 32}
        if mismatch == "binding"
        else {}
    )
    generation.save(current.id, witness(-1 if mismatch == "time" else 2, **changes))
    anchor = baseline(original)
    if mismatch == "future_baseline":
        anchor = anchor.model_copy(update={"created_at": AT + timedelta(seconds=3)})
    assert generation.compare_to_baseline(current.id, anchor).status == "unavailable"


def test_save_revalidates_parent_time_and_cascades_retention(tmp_path):
    original = report("original")
    replay = report("replay").model_copy(update={"source": "replay"})
    reports, generation = database(tmp_path, original, replay)
    for identifier, item in (
        ("absent", witness()),
        (replay.id, witness()),
        (original.id, witness(121)),
        (original.id, witness().model_copy(update={"configuration": None})),
        (original.id, witness().model_copy(update={"key_epoch": "canary"})),
    ):
        with pytest.raises(ValueError, match="inconsistent"):
            generation.save(identifier, item)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _i: generation.save(original.id, witness()), range(2))) == [
            None,
            None,
        ]
    with reports._connection() as db:
        assert db.execute("SELECT count(*) FROM compose_generation_witnesses_v1").fetchone()[0] == 1
        db.execute("DELETE FROM reports WHERE id=?", (original.id,))
        assert db.execute("SELECT count(*) FROM compose_generation_witnesses_v1").fetchone()[0] == 0
    assert generation.compare_to_baseline(original.id, baseline(original)).status == "unavailable"
    with pytest.raises(ValueError):
        generation.save(original.id, witness())


@pytest.mark.parametrize("primary_new", [True, False])
def test_offline_merge_old_and_new_catalogs_then_read_original_pair(tmp_path, primary_new):
    primary, extra = (make_directory(tmp_path / name) for name in ("primary", "extra"))
    original, current = report("original"), report("current", 2)
    _, a = database(primary, original, current)
    _, b = database(extra, original, current)
    enabled = a if primary_new else b
    enabled.save(original.id, witness())
    enabled.save(current.id, witness(2, container="ef" * 32))
    close_offline(primary, extra)
    before = [directory_digests(folder) for folder in (primary, extra)]
    output = tmp_path / "merged"
    result = transfer.merge_report_baseline_snapshots(primary, extra, output)
    assert set(result["databases"]) == {"reports.sqlite3"}
    assert result["databases"]["reports.sqlite3"]["tables"][_TABLE]["rows"] == 2
    assert [directory_digests(folder) for folder in (primary, extra)] == before
    reopened = ComposeGenerationStore(ReportStore(output / "reports.sqlite3"))
    assert reopened.compare_to_baseline(current.id, baseline(original)).container == "changed"


@pytest.mark.parametrize("damage", ["conflict", "catalog", "witness", "parent", "scope"])
def test_offline_merge_refuses_changed_witness_schema_or_parent(tmp_path, damage):
    primary, extra = (make_directory(tmp_path / name) for name in ("primary", "extra"))
    original = report("original", scope_change=True)
    _, a = database(primary, original)
    reports, b = database(extra, original)
    a.save(original.id, witness())
    b.save(original.id, witness(container="fe" * 32) if damage == "conflict" else witness())
    with reports._connection() as db:
        if damage == "catalog":
            db.execute(
                "CREATE INDEX extra_generation_index ON compose_generation_witnesses_v1(host_id)"
            )
        elif damage == "witness":
            db.execute(
                "UPDATE compose_generation_witnesses_v1 SET witness_json=?", ('{"raw":"CANARY"}',)
            )
        elif damage == "parent":
            db.execute("UPDATE reports SET payload=json_set(payload,'$.source','replay')")
        elif damage == "scope":
            db.execute(
                "UPDATE reports SET payload=json_remove(payload, "
                "'$.target.disk_reclaim_scope_digest')"
            )
    close_offline(primary, extra)
    before = [directory_digests(folder) for folder in (primary, extra)]
    output = tmp_path / "merged"
    with pytest.raises(transfer.TransferError):
        transfer.merge_report_baseline_snapshots(primary, extra, output)
    assert not (output / "reports.sqlite3").exists()
    assert [directory_digests(folder) for folder in (primary, extra)] == before
    assert "CANARY" not in (output / "manifest.json").read_text(encoding="utf-8")


def test_exact_ten_store_rehearsal_preserves_private_equality_without_witness_values(tmp_path):
    source = make_directory(tmp_path / "source")
    original, current = report("original"), report("current", 2)
    _, generation = database(source, original, current)
    generation.save(original.id, witness())
    generation.save(current.id, witness(2, container="ef" * 32))
    for name in transfer.DATABASES:
        if name != "reports.sqlite3":
            path = source / name
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE synthetic(id TEXT PRIMARY KEY)")
            path.chmod(0o600)
    snapshot, recovered = tmp_path / "snapshot", tmp_path / "recovered"
    manifest = transfer.snapshot(source, snapshot)
    assert all(
        value not in json.dumps(manifest) for value in (witness().binding, witness().key_epoch)
    )
    proof = transfer.rehearse(snapshot, recovered)
    assert (
        proof["database_count"] == 10
        and transfer.verify_snapshot(recovered)["database_count"] == 10
    )
    assert all(
        value not in json.dumps(proof)
        for value in (witness().binding, witness().key_epoch, witness().image)
    )
    reopened = ComposeGenerationStore(ReportStore(recovered / "reports.sqlite3"))
    assert reopened.compare_to_baseline(current.id, baseline(original)).container == "changed"


def test_snapshot_validates_generation_before_publication_and_allows_clean_retry(tmp_path):
    source = make_directory(tmp_path / "source")
    original = report("original")
    reports, generation = database(source, original)
    generation.save(original.id, witness())
    with reports._connection() as db:
        prior = db.execute("SELECT witness_json FROM compose_generation_witnesses_v1").fetchone()[0]
        db.execute("UPDATE compose_generation_witnesses_v1 SET witness_json='{}'")
    output = tmp_path / "snapshot"
    with pytest.raises(transfer.TransferError):
        transfer.snapshot(source, output)
    assert not tuple(output.iterdir())
    with reports._connection() as db:
        db.execute("UPDATE compose_generation_witnesses_v1 SET witness_json=?", (prior,))
    result = transfer.snapshot(source, output)
    assert result["databases"]["reports.sqlite3"]["tables"][_TABLE]["rows"] == 1
