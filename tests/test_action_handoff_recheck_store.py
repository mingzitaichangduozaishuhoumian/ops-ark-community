from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier

import pytest
from pydantic import ValidationError

from opsark import action_handoff_recheck_store as ledger
from opsark.baselines import diagnostic_scope_for, scope_for
from opsark.models import HostPublic, Report
from opsark.storage import ReportStore

AT = datetime(2026, 5, 8, 10, 0, tzinfo=UTC)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    reports = ReportStore(tmp_path / "reports.sqlite3")
    store = ledger.ActionHandoffRecheckStore(reports)
    host = HostPublic(id="test.host", name="Fixture", address="192.0.2.2", source="ssh")
    report = Report(
        id="test_report",
        host_id=host.id,
        host_name=host.name,
        scenario="web_502",
        source="ssh",
        created_at=AT - timedelta(minutes=3),
        status="inconclusive",
        title="Synthetic",
        summary="Synthetic",
        facts=[],
        candidates=[],
        missing=[],
        evidence=[],
        next_steps=[],
        scope_hash=diagnostic_scope_for(host),
        target=host,
    )
    reports.save(report)
    binding = ledger.ActionRecheckBinding(
        report_id=report.id,
        kind="nginx",
        plan_id="0" * 32,
        host_id=host.id,
        host_scope=scope_for(host),
        target_scope="a" * 64,
        approval_digest="b" * 64,
        execution_digest="c" * 64,
        profile_digest="d" * 64,
        configured_checks=3,
        execution_at=AT - timedelta(seconds=1),
    )
    monkeypatch.setattr(ledger, "_now", lambda: AT)
    return reports, store, report, binding


def test_failure_pending_and_success_stay_selectable_after_reopen(fixture):
    reports, store, original, binding = fixture
    failed = store.start(binding)
    first = store.finish(binding, failed.id, checks=("passed", "failed", "uncovered"))
    assert first.verdict == "failed"
    interrupted = store.start(binding)
    uncovered = store.start(binding)
    assert (
        store.finish(binding, uncovered.id, checks=("passed", "uncovered", "passed")).verdict
        == "pending"
    )
    passed = store.start(binding)
    last = store.finish(binding, passed.id, checks=("passed", "passed", "passed"))
    assert last.verdict == "passed"
    reopened = ledger.ActionHandoffRecheckStore(ReportStore(reports.path))
    assert [row.intent.id for row in reopened.list(binding)] == [
        passed.id,
        uncovered.id,
        interrupted.id,
        failed.id,
    ]
    assert reopened.get(binding, failed.id) == first
    unfinished = reopened.get(binding, interrupted.id)
    assert unfinished is not None and unfinished.result is None and unfinished.verdict == "pending"
    assert reopened.get(binding, passed.id) == last and reports.get(original.id) == original
    with pytest.raises(ValueError, match="inconsistent"):
        reopened.finish(binding, passed.id, checks=("failed", "failed", "failed"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("report_id", "different"),
        ("kind", "container_restart"),
        ("plan_id", "1" * 32),
        ("host_id", "different"),
        ("host_scope", "e" * 64),
        ("target_scope", "e" * 64),
        ("approval_digest", "e" * 64),
        ("execution_digest", "e" * 64),
        ("profile_digest", "e" * 64),
        ("configured_checks", 2),
        ("execution_at", AT - timedelta(seconds=2)),
    ],
)
def test_every_original_field_is_required_to_recover_or_finish(fixture, field, value):
    _, store, _, binding = fixture
    run = store.start(binding)
    changed = binding.model_copy(update={field: value})
    assert store.get(changed, run.id) is None and store.list(changed) == []
    with pytest.raises(ValueError, match="inconsistent"):
        store.finish(changed, run.id, checks=("passed", "passed", "passed"))
    assert store.get(binding, run.id).result is None


def test_legacy_host_scope_only_matches_its_captured_digest(fixture):
    reports, store, report, binding = fixture
    host = report.target.model_copy(update={"disk_reclaim_scope_digest": "a" * 64})
    historical = binding.model_copy(update={"host_scope": scope_for(host)})
    # Early captures can contain the transport scope, later ones the disk-inclusive digest.
    for number, scope in enumerate((scope_for(host), diagnostic_scope_for(host))):
        row = report.model_copy(
            update={"id": f"with-target-{number}", "scope_hash": scope, "target": host}
        )
        reports.save(row)
        assert store.start(historical.model_copy(update={"report_id": row.id}))
    legacy = report.model_copy(update={"id": "legacy", "target": None})
    reports.save(legacy)
    assert store.start(binding.model_copy(update={"report_id": legacy.id}))
    with pytest.raises(ValueError, match="inconsistent"):
        store.start(binding.model_copy(update={"report_id": legacy.id, "host_scope": "e" * 64}))


def test_replay_report_and_wrong_chronology_cannot_start(fixture, monkeypatch):
    reports, store, report, binding = fixture
    reports.save(report.model_copy(update={"id": "replay_fixture", "source": "replay"}))
    for changed in (
        binding.model_copy(update={"report_id": "replay_fixture"}),
        binding.model_copy(update={"execution_at": report.created_at}),
        binding.model_copy(update={"execution_at": AT}),
    ):
        with pytest.raises(ValueError, match="inconsistent"):
            store.start(changed)
    original = store.start(binding)
    monkeypatch.setattr(ledger, "_now", lambda: AT - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="inconsistent"):
        store.finish(binding, original.id, checks=("passed", "passed", "passed"))
    assert store.get(binding, original.id).result is None


def test_slots_and_identifiers_are_strict_and_aware(fixture):
    _, store, _, binding = fixture
    for changes in (
        {"plan_id": "A" * 32},
        {"host_id": "host id"},
        {"target_scope": "bad"},
        {"execution_at": AT.replace(tzinfo=None)},
        {"kind": "patch"},
        {"extra": "data"},
    ):
        with pytest.raises(ValidationError):
            ledger.ActionRecheckBinding.model_validate(binding.model_dump() | changes)
    offset = timezone(timedelta(hours=8))
    equivalent = ledger.ActionRecheckBinding.model_validate(
        binding.model_dump() | {"execution_at": binding.execution_at.astimezone(offset)}
    )
    run = store.start(binding)
    assert store.get(equivalent, run.id).intent == run
    for checks in (
        ("passed",),
        ("passed", "failed", "timeout"),
        ("passed", "failed", "uncovered", "failed"),
    ):
        with pytest.raises(ValidationError):
            store.finish(binding, run.id, checks=checks)
    assert store.get(binding, run.id).result is None


def test_late_finish_cannot_turn_an_abandoned_attempt_into_a_pass(fixture, monkeypatch):
    _, store, _, binding = fixture
    stale = store.start(binding)
    boundary = store.start(binding)
    monkeypatch.setattr(ledger, "_now", lambda: AT + timedelta(seconds=120))
    assert (
        store.finish(binding, boundary.id, checks=("passed", "passed", "passed")).verdict
        == "passed"
    )
    monkeypatch.setattr(ledger, "_now", lambda: AT + timedelta(seconds=121))
    with pytest.raises(ValueError, match="inconsistent"):
        store.finish(binding, stale.id, checks=("passed", "passed", "passed"))
    fresh = store.start(binding)
    assert (
        store.finish(binding, fresh.id, checks=("passed", "passed", "passed")).verdict == "passed"
    )
    retained = store.get(binding, stale.id)
    assert retained is not None and retained.verdict == "pending"


@pytest.mark.parametrize("count", [1, 2])
def test_only_configured_slots_affect_the_verdict(fixture, count):
    _, store, _, binding = fixture
    binding = binding.model_copy(update={"configured_checks": count})
    first = store.start(binding)
    good = ("passed", "uncovered", "uncovered") if count == 1 else ("passed", "passed", "uncovered")
    assert store.finish(binding, first.id, checks=good).verdict == "passed"
    second = store.start(binding)
    with pytest.raises(ValueError, match="inconsistent"):
        store.finish(binding, second.id, checks=("passed", "passed", "failed"))
    assert (
        store.finish(binding, second.id, checks=("uncovered", "uncovered", "uncovered")).verdict
        == "pending"
    )


def test_same_run_has_one_winning_finish(fixture):
    _, store, _, binding = fixture
    run = store.start(binding)
    barrier = Barrier(2, timeout=5)

    def attempt(status):
        barrier.wait()
        try:
            return store.finish(binding, run.id, checks=(status, status, status)).verdict
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, ("passed", "failed")))
    assert results.count("refused") == 1
    assert store.get(binding, run.id).verdict in {"passed", "failed"}


def test_schema_is_created_only_with_first_valid_intent(fixture):
    reports, store, _, binding = fixture
    fake = "ar-" + "a" * 32
    assert store.get(binding, fake) is None and store.list(binding) == []
    with pytest.raises(ValueError, match="inconsistent"):
        store.finish(binding, fake, checks=("passed", "passed", "passed"))
    with pytest.raises(ValueError, match="inconsistent"):
        store.start(binding.model_copy(update={"host_scope": "e" * 64}))
    with reports._connection() as db:
        assert not ledger._has_schema(db)
    first = store.start(binding)
    assert store.get(binding, first.id) is not None
    with reports._connection() as db:
        assert ledger._has_schema(db)


def test_list_is_bounded_and_direct_lookup_reads_older_attempt(fixture):
    _, store, _, binding = fixture
    intents = [store.start(binding) for _ in range(22)]
    assert [row.intent for row in store.list(binding)] == list(reversed(intents[-20:]))
    assert store.get(binding, intents[0].id).intent == intents[0]


def test_original_selection_keeps_captured_binding_and_does_not_cross_plan(fixture):
    _, store, _, binding = fixture
    assert store.latest(binding) is None
    first = store.start(binding)
    sealed = store.finish(binding, first.id, checks=("passed", "failed", "uncovered"))
    latest = store.start(binding)
    assert store.latest(binding).intent == latest
    changed = binding.model_copy(update={"profile_digest": "e" * 64})
    assert store.get(changed, first.id) is None and store.latest(changed) is None
    assert store.get_original(binding.report_id, binding.kind, binding.plan_id, first.id) == sealed
    assert (
        store.get_original(binding.report_id, "container_restart", binding.plan_id, first.id)
        is None
    )
    assert store.get_original(binding.report_id, binding.kind, "f" * 32, first.id) is None
    assert store.get_original("other", binding.kind, binding.plan_id, first.id) is None


def test_modified_result_cannot_be_used_as_evidence(fixture):
    reports, store, _, binding = fixture
    run = store.start(binding)
    store.finish(binding, run.id, checks=("failed", "passed", "passed"))
    with reports._connection() as db:
        db.execute(
            "UPDATE action_handoff_recheck_results_v1 "
            "SET result_json=replace(result_json, 'failed', 'passed') WHERE id=?",
            (run.id,),
        )
    with pytest.raises(ValueError, match="inconsistent"):
        store.get(binding, run.id)
