"""Linux observation semantics and output safety, with no remote hosts or services."""

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / "tools/capacity_guest_probe.py"
SPEC = importlib.util.spec_from_file_location("capacity_guest_probe", PATH)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_meminfo_kernel_kb_means_1024_bytes_and_no_swap_is_not_missing():
    values, gaps = probe.parse_memory(
        "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"),
    )
    assert values == {
        "MemTotal": 1_024_000,
        "MemAvailable": 256_000,
        "SwapTotal": 0,
        "SwapFree": 0,
    }
    assert not gaps


@pytest.mark.parametrize(
    "text",
    [
        "MemTotal: 100 MB",
        "MemTotal: -1 kB",
        "MemTotal: 0 kB",
        "MemTotal: broken kB",
        "MemTotal: 1 kB\nMemTotal: 2 kB",
        "unrelated: 300 kB",
    ],
)
def test_bad_or_absent_memory_is_unknown_instead_of_zero(text):
    values, gaps = probe.parse_memory(text, ("MemTotal",))
    assert values["MemTotal"] is None and gaps


def test_available_memory_cannot_exceed_observed_total():
    values, gaps = probe.parse_memory(
        "MemTotal: 5 kB\nMemAvailable: 6 kB", ("MemTotal", "MemAvailable")
    )
    assert values["MemTotal"] == 5120
    assert values["MemAvailable"] is None and gaps


def test_cpu_does_not_double_count_guest_ticks():
    values, gaps = probe.parse_cpu("cpu  10 2 3 20 4 1 5 6 8 1\ncpu0 1 2 3 4 5 6 7 8")
    assert values["total"] == 51 and values["idle_and_iowait"] == 24
    assert not gaps
    values, gaps = probe.parse_cpu("cpu  1 2 corrupted 4 5 6 7 8")
    assert values["total"] is None and gaps


def test_oom_and_swap_counter_missing_is_not_a_zero_success():
    values, gaps = probe.parse_counters("oom_kill 0\npgmajfault 9\npswpin wrong\n")
    assert values == {"oom_kill": 0, "pgmajfault": 9, "pswpin": None, "pswpout": None}
    assert len(gaps) == 2


def test_reset_is_not_a_negative_rate_but_other_counters_remain_usable():
    result, gaps = probe.counter_changes({"oom": 5, "faults": 10}, {"oom": 1, "faults": 16}, 2)
    assert result["deltas"] == {"oom": None, "faults": 6}
    assert result["per_second"] == {"oom": None, "faults": 3.0}
    assert gaps == ["oom:counter_reset"]


@pytest.mark.parametrize("elapsed", [0, -1, float("nan"), float("inf")])
def test_bad_sample_interval_never_yields_a_rate(elapsed):
    values, gaps = probe.counter_changes({"count": 1}, {"count": 2}, elapsed)
    assert values["per_second"]["count"] is None and gaps


def test_psi_preserves_units_and_marks_unsupported_full_row():
    values, gaps = probe.parse_pressure("some avg10=1.50 avg60=0.25 avg300=0.05 total=12345")
    assert values["some"] == {
        "avg10": 1.5,
        "avg60": 0.25,
        "avg300": 0.05,
        "total_microseconds": 12345,
    }
    assert values["full"] is None and gaps == ["full:missing"]


@pytest.mark.parametrize(
    "line",
    [
        "some avg10=nan avg60=0 avg300=0 total=1",
        "some avg10=101 avg60=0 avg300=0 total=1",
        "some avg10=0 avg10=0 avg300=0 total=1",
        "some avg10=0 avg60=0 avg300=0 total=-1",
    ],
)
def test_corrupt_psi_is_unknown(line):
    values, gaps = probe.parse_pressure(line)
    assert values["some"] is None and gaps


@pytest.mark.parametrize("text", ["", "0.1 broken 0.3", "nan 0 0", "1 -2 3"])
def test_invalid_load_does_not_become_zero(text):
    assert probe.parse_load(text)[0] is None


def test_phase_is_short_plain_text_and_invalid_contents_are_not_echoed(tmp_path):
    path = tmp_path / "phase.txt"
    path.write_bytes(b"patch:preflight\r\n")
    assert probe.read_phase(path) == ("patch:preflight", [])
    path.write_text("API_KEY=do-not-copy-this-secret\n", encoding="ascii")
    value = probe.read_phase(path)
    assert value[0] is None and "do-not-copy" not in json.dumps(value)
    path.unlink()
    assert probe.read_phase(path)[0] is None


def test_hardlinked_phase_is_not_read(tmp_path):
    original, alias = tmp_path / "phase", tmp_path / "alias"
    original.write_text("install", encoding="ascii")
    try:
        os.link(original, alias)
    except OSError:
        pytest.skip("Hard links unavailable on this filesystem")
    assert probe.read_phase(alias)[0] is None


def test_vm_detection_uses_only_the_fixed_readonly_command_and_is_not_budget_proof(monkeypatch):
    calls = []

    def command(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"kvm\n", stderr=b"")

    monkeypatch.setattr(probe.subprocess, "run", command)
    value, gaps = probe.vm_detection()
    assert value == {"status": "vm_detected", "kind": "kvm"} and not gaps
    assert calls[0][0] == ["/usr/bin/systemd-detect-virt", "--vm"]
    assert calls[0][1]["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    monkeypatch.setattr(probe, "_read", lambda _p: 'ID=ubuntu\nVERSION_ID="24.04"\n')
    monkeypatch.setattr(
        probe.os, "uname", lambda: SimpleNamespace(release="test", machine="test"), raising=False
    )
    start = probe.startup(10, 1)
    assert start["budget_configuration_verified"] is False
    assert start["sample_atomic"] is False and start["limitations"]


def test_bad_detection_output_never_logs_its_contents(monkeypatch):
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *_a, **_k: SimpleNamespace(
            returncode=2, stdout=b"credential=do-not-print", stderr=b"hidden-value"
        ),
    )
    result = probe.vm_detection()
    assert result[0]["kind"] is None
    assert "do-not-print" not in json.dumps(result) and "hidden-value" not in json.dumps(result)


def test_missing_sources_are_explicit_gaps(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "filesystem_sample", lambda _p: (None, ["unavailable_or_invalid"]))
    sample = probe.collect_sample(proc_root=tmp_path)
    assert all(value is None for value in sample["memory_bytes"].values())
    assert all(value is None for value in sample["vmstat_counters"].values())
    assert sample["sampler_rss_bytes"] is None and sample["root_filesystem"] is None
    assert sample["derived"]["baseline"] and sample["coverage_gaps"]


@pytest.mark.parametrize("argument", ["0", "-1", "3601", "nan", "1.5"])
def test_duration_is_bounded(argument):
    with pytest.raises(argparse.ArgumentTypeError):
        probe.duration_argument(argument)


@pytest.mark.parametrize("argument", ["0", "-1", "0.999", "nan", "inf"])
def test_interval_cannot_create_fast_or_nonfinite_sampling(argument):
    with pytest.raises(argparse.ArgumentTypeError):
        probe.interval_argument(argument)


def test_invalid_cli_does_not_create_output(tmp_path):
    path = tmp_path / "samples.jsonl"
    with pytest.raises(SystemExit) as error:
        probe.main(["--output", str(path), "--duration", "3601"])
    assert error.value.code == 2 and not path.exists()


def test_existing_output_is_untouched_before_any_probe(tmp_path, monkeypatch):
    path = tmp_path / "samples.jsonl"
    path.write_bytes(b"prior evidence\n")
    monkeypatch.setattr(probe.sys, "platform", "linux")
    monkeypatch.setattr(
        probe, "startup", lambda *_a: pytest.fail("Do not probe before exclusive create")
    )
    with pytest.raises(FileExistsError):
        probe.run(path, duration=1, interval=1)
    assert path.read_bytes() == b"prior evidence\n"


def test_jsonl_output_finishes_with_coverage_and_does_not_sample_faster_at_deadline(
    tmp_path, monkeypatch
):
    path = tmp_path / "samples.jsonl"
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(probe.sys, "platform", "linux")
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(probe.time, "monotonic_ns", lambda: int(clock.now * 1_000_000_000))
    monkeypatch.setattr(
        probe.time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds)
    )
    monkeypatch.setattr(
        probe,
        "startup",
        lambda *_a: {"record_type": "start", "budget_configuration_verified": False},
    )
    samples = []

    def sample(previous, **_kwargs):
        samples.append(clock.now)
        return {"record_type": "sample", "coverage_gaps": ["memory:unavailable_or_invalid"]}

    monkeypatch.setattr(probe, "collect_sample", sample)
    assert probe.run(path, duration=3, interval=2) == 0
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert samples == [0.0, 2.0]  # No extra sample at t=3, only one second after t=2.
    assert [row["record_type"] for row in rows] == ["start", "sample", "sample", "end"]
    assert rows[-1]["elapsed_seconds"] == 3 and rows[-1]["samples"] == 2
    assert rows[-1]["coverage_gap_counts"] == {"memory:unavailable_or_invalid": 2}
    assert rows[-1]["budget_configuration_verified"] is False


def test_standalone_source_has_python312_compatible_syntax():
    ast.parse(PATH.read_text(encoding="utf-8"), feature_version=(3, 12))
