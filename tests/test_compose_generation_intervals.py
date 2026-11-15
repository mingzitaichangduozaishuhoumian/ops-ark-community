"""Show only differences between compatible, report-linked observations."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_compose_generation_store import AT, baseline, database, report, witness

from opsark.compose_generation_store import ChangeObservation, change_observation
from opsark.models import BaselineComparison, Evidence


def originals(tmp_path, *, scope_change=False, projected_changes=None):
    previous = report("original")
    current = report("current", 10, scope_change=scope_change)
    bound = baseline(previous)
    current.comparison = BaselineComparison(
        baseline_id=bound.id,
        baseline_report_id=bound.report_id,
        baseline_created_at=bound.created_at,
        status="compared",
    )
    reports, generation = database(tmp_path, previous, current)
    if projected_changes is not None:
        generation.save(previous.id, witness())
        generation.save(current.id, witness(9, **projected_changes))
    baselines = SimpleNamespace(for_report=Mock(return_value=bound))
    return reports, generation, baselines, previous, current, bound


def test_intervals_are_changed_fields_from_same_exact_pair_without_reloading_original(tmp_path):
    reports, generation, baselines, previous, current, bound = originals(
        tmp_path, projected_changes={"container": "e" * 64, "configuration": "f" * 64}
    )
    output = []
    inherited = reports._connection
    from contextlib import contextmanager

    @contextmanager
    def traced():
        with inherited() as connection:
            connection.set_trace_callback(output.append)
            yield connection

    reports._connection = traced
    result = change_observation(current, baselines, generation).model_dump(mode="json")
    baselines.for_report.assert_called_once_with(previous.id)
    assert result == {
        "current_at": "2026-06-10T00:00:09Z",
        "baseline_status": "compared",
        "changes": [
            {"field": field, "from_at": "2026-06-10T00:00:00Z", "to_at": "2026-06-10T00:00:09Z"}
            for field in ("container", "compose_configuration")
        ],
    }
    assert [query.rsplit("WHERE ", 1)[-1] for query in output if "FROM reports" in query] == [
        "id='original'"
    ]
    old = generation.compare_to_baseline(current.id, bound)
    assert old.changed_at == old.actor == old.deployment_source == "unknown"
    assert all(
        value not in str(result) for value in ("f" * 64, "e" * 64, "private-lab", "key_epoch")
    )


def test_stock_post_report_observations_can_bound_a_change(tmp_path):
    _, generation, baselines, previous, current, bound = originals(tmp_path)
    # Investigate produces the report before its second, retained SSH observation.
    # A baseline can only be saved once the whole first investigation returns.
    bound.created_at = AT + timedelta(seconds=3)
    current.comparison.baseline_created_at = bound.created_at
    generation.save(previous.id, witness(2))
    generation.save(current.id, witness(12, container="e" * 64))
    result = change_observation(current, baselines, generation)
    assert result.model_dump(mode="json") == {
        "current_at": "2026-06-10T00:00:12Z",
        "baseline_status": "compared",
        "changes": [
            {
                "field": "container",
                "from_at": "2026-06-10T00:00:02Z",
                "to_at": "2026-06-10T00:00:12Z",
            }
        ],
    }


def test_witness_outside_stock_report_time_window_is_never_stored(tmp_path):
    _, generation, baselines, previous, current, _ = originals(tmp_path)
    generation.save(previous.id, witness(2))
    with pytest.raises(ValueError, match="inconsistent"):
        generation.save(current.id, witness(131, container="e" * 64))
    assert change_observation(current, baselines, generation) == ChangeObservation()


@pytest.mark.parametrize(
    ("alter", "status", "fields"),
    (
        ("steady", "compared", []),
        ("missing_configuration", "incomplete", ["container", "image"]),
        ("compose_version", "incomplete", ["container", "image"]),
        ("key_epoch", "scope_changed", []),
        ("binding", "scope_changed", []),
        ("scope", "scope_changed", []),
        ("time", "incomplete", []),
        ("impossible_same_container", "incomplete", []),
        ("missing_baseline_witness", "incomplete", []),
        ("missing_current_witness", "incomplete", []),
    ),
)
def test_interval_comparability_uses_existing_matcher(tmp_path, alter, status, fields):
    _, generation, baselines, previous, current, _ = originals(
        tmp_path, scope_change=alter == "scope"
    )
    if alter != "missing_baseline_witness":
        generation.save(previous.id, witness())
    comparable = {"container": "e" * 64, "image": "f" * 64}
    variants = {
        "steady": {},
        "missing_configuration": comparable | {"configuration": None, "compose_version": None},
        "compose_version": comparable | {"compose_version": "ac" * 32},
        "key_epoch": comparable | {"key_epoch": "de" * 32},
        "binding": comparable | {"binding": "ef" * 32},
        "impossible_same_container": {"image": "ae" * 32},
    }
    if alter != "missing_current_witness":
        selected_at = -1 if alter == "time" else 9
        generation.save(current.id, witness(selected_at, **variants.get(alter, comparable)))
    result = change_observation(current, baselines, generation)
    assert result.baseline_status == status
    assert [row.field for row in result.changes] == fields


@pytest.mark.parametrize("mismatch", ["id", "report", "time", "missing", "same_report"])
def test_never_uses_unbound_baseline(tmp_path, mismatch):
    _, generation, baselines, _, current, bound = originals(
        tmp_path, projected_changes={"container": "f" * 64}
    )
    if mismatch == "missing":
        baselines.for_report.return_value = None
    elif mismatch == "same_report":
        current.comparison.baseline_report_id = current.id
    else:
        values = {
            "id": {"id": "alternate"},
            "report": {"report_id": "alternate"},
            "time": {"created_at": bound.created_at + timedelta(seconds=1)},
        }
        baselines.for_report.return_value = bound.model_copy(update=values[mismatch])
    result = change_observation(current, baselines, generation)
    assert result.baseline_status == "incomplete" and result.changes == []
    assert result.current_at == AT + timedelta(seconds=9)


def test_first_observation_or_successful_original_check_has_no_baseline_interval(tmp_path):
    _, generation, baselines, _, current, _ = originals(tmp_path)
    current.comparison = BaselineComparison()
    generation.save(current.id, witness(9))
    assert change_observation(current, baselines, generation) == ChangeObservation(
        baseline_status="no_baseline", current_at=AT + timedelta(seconds=9)
    )
    current.scenario = "web_502"
    evidence = Evidence(
        id="E-LISTENERS",
        check_id="listeners",
        target=current.host_id,
        source="ssh",
        collected_at=AT + timedelta(seconds=7),
        status="ok",
        output="synthetic",
        exit_code=0,
    )
    current.evidence = [
        evidence,
        evidence.model_copy(update={"target": "other", "collected_at": AT + timedelta(seconds=8)}),
        evidence.model_copy(update={"truncated": True, "collected_at": AT + timedelta(seconds=9)}),
        evidence.model_copy(update={"collected_at": AT + timedelta(seconds=11)}),
    ]
    assert change_observation(current, baselines, generation) == ChangeObservation(
        baseline_status="no_baseline", current_at=AT + timedelta(seconds=7)
    )
    current.scope_hash = "0" * 64
    assert change_observation(current, baselines, generation) == ChangeObservation(
        baseline_status="no_baseline"
    )
    baselines.for_report.assert_not_called()


def test_tampered_witness_cannot_create_an_interval(tmp_path):
    reports, generation, baselines, _, current, _ = originals(
        tmp_path, projected_changes={"container": "f" * 64}
    )
    with reports._connection() as connection:
        connection.execute(
            "UPDATE compose_generation_witnesses_v1 SET witness_sha256='' WHERE id=?", (current.id,)
        )
    with pytest.raises(ValueError, match="inconsistent"):
        change_observation(current, baselines, generation)
