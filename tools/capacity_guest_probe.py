#!/usr/bin/env python3
"""Observe a Linux guest without changing its services, limits or credentials.

Only the explicitly new JSONL output is written. VM detection and observations do
not prove that a hypervisor actually configured a particular CPU/memory budget.
This standard-library script also runs under Ubuntu's system Python 3.12.
"""

import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

MEMORY_FIELDS = (
    "MemTotal",
    "MemAvailable",
    "MemFree",
    "Buffers",
    "Cached",
    "SwapTotal",
    "SwapFree",
)
COUNTERS = ("oom_kill", "pgmajfault", "pswpin", "pswpout")
CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
PHASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
MAX_READ_BYTES = 262_144


def _read(path, *, limit=MAX_READ_BYTES, single_link=False):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if single_link:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or single_link and metadata.st_nlink != 1:
            raise ValueError("Source is not an ordinary file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Source exceeds its observation budget")
        return raw.decode("ascii")
    finally:
        os.close(descriptor)


def parse_memory(text, fields=MEMORY_FIELDS):
    values = dict.fromkeys(fields)
    seen, gaps = set(), []
    for line in text.splitlines():
        key, separator, raw = line.partition(":")
        if key not in values:
            continue
        parts = raw.split()
        if (
            key in seen
            or separator != ":"
            or len(parts) != 2
            or parts[1] != "kB"
            or not parts[0].isdecimal()
        ):
            values[key] = None
            gaps.append(key + ":invalid_or_duplicate")
        else:
            values[key] = int(parts[0]) * 1024
        seen.add(key)
    gaps.extend(key + ":missing" for key in fields if key not in seen)
    for key in ("MemTotal", "VmRSS"):
        if key in values and values[key] == 0:
            values[key] = None
            gaps.append(key + ":nonpositive")
    for free, total in (("MemAvailable", "MemTotal"), ("SwapFree", "SwapTotal")):
        if (
            free in values
            and total in values
            and values[free] is not None
            and values[total] is not None
            and values[free] > values[total]
        ):
            values[free] = None
            gaps.append(free + ":exceeds_total")
    return values, gaps


def parse_counters(text):
    result, seen, gaps = dict.fromkeys(COUNTERS), set(), []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in result:
            continue
        name = parts[0]
        if name in seen or len(parts) != 2 or not parts[1].isdecimal():
            result[name] = None
            gaps.append(name + ":invalid_or_duplicate")
        else:
            result[name] = int(parts[1])
        seen.add(name)
    gaps.extend(name + ":missing" for name in COUNTERS if name not in seen)
    return result, gaps


def parse_cpu(text):
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith("cpu ")]
    if len(rows) != 1 or len(rows[0]) < 8 or not all(part.isdecimal() for part in rows[0][:8]):
        return dict.fromkeys((*CPU_FIELDS, "total", "idle_and_iowait")), [
            "aggregate:invalid_or_missing"
        ]
    values = dict(zip(CPU_FIELDS, map(int, rows[0][:8]), strict=True))
    # guest/guest_nice are already included in user/nice; never count them twice.
    values.update(total=sum(values.values()), idle_and_iowait=values["idle"] + values["iowait"])
    return values, []


def parse_pressure(text):
    result, seen, gaps = {"some": None, "full": None}, set(), []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in result:
            continue
        name = parts[0]
        try:
            pairs = [part.split("=", 1) for part in parts[1:]]
            if name in seen or len(pairs) != 4 or any(len(pair) != 2 for pair in pairs):
                raise ValueError
            fields = dict(pairs)
            if (
                set(fields) != {"avg10", "avg60", "avg300", "total"}
                or not fields["total"].isdecimal()
            ):
                raise ValueError
            averages = {key: float(fields[key]) for key in ("avg10", "avg60", "avg300")}
            if any(
                not math.isfinite(value) or not 0 <= value <= 100 for value in averages.values()
            ):
                raise ValueError
            result[name] = {**averages, "total_microseconds": int(fields["total"])}
        except (ValueError, OverflowError):
            result[name] = None
            gaps.append(name + ":invalid_or_duplicate")
        seen.add(name)
    gaps.extend(name + ":missing" for name in result if name not in seen)
    return result, gaps


def parse_load(text):
    try:
        parts = text.split()
        if len(parts) < 3:
            raise ValueError
        values = [float(part) for part in parts[:3]]
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError
        return values, []
    except (ValueError, OverflowError):
        return None, ["invalid_or_missing"]


def counter_changes(previous, current, elapsed):
    deltas, rates, gaps = {}, {}, []
    for name in current:
        before, after = previous.get(name), current[name]
        if type(before) is not int or type(after) is not int:
            deltas[name] = rates[name] = None
            gaps.append(name + ":missing_baseline_or_current")
        elif elapsed <= 0 or not math.isfinite(elapsed):
            deltas[name] = rates[name] = None
            gaps.append(name + ":invalid_interval")
        elif after < before:
            deltas[name] = rates[name] = None
            gaps.append(name + ":counter_reset")
        else:
            deltas[name] = after - before
            rates[name] = round((after - before) / elapsed, 6)
    return {"deltas": deltas, "per_second": rates}, gaps


def read_phase(path):
    if path is None:
        return None, []
    try:
        value = _read(path, limit=66, single_link=True).removesuffix("\r\n").removesuffix("\n")
        if PHASE.fullmatch(value) is None:
            raise ValueError
        return value, []
    except (OSError, UnicodeError, ValueError):
        return None, ["phase:missing_or_invalid"]


def filesystem_sample(path):
    try:
        value = os.statvfs(path)
        if (
            value.f_frsize <= 0
            or min(value.f_blocks, value.f_bavail, value.f_files, value.f_favail) < 0
        ):
            raise ValueError
        result = {
            "total_bytes": value.f_blocks * value.f_frsize,
            "available_bytes": value.f_bavail * value.f_frsize,
            "total_inodes": value.f_files or None,
            "available_inodes": value.f_favail if value.f_files else None,
        }
        gaps = [] if value.f_files else ["inodes:unavailable"]
        if result["available_bytes"] > result["total_bytes"] or value.f_favail > value.f_files:
            raise ValueError
        return result, gaps
    except (OSError, AttributeError, ValueError):
        return None, ["unavailable_or_invalid"]


def vm_detection():
    try:
        result = subprocess.run(  # noqa: S603 -- one fixed, local, read-only executable/argument.
            ["/usr/bin/systemd-detect-virt", "--vm"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        kind = result.stdout.decode("ascii").strip()
        if len(result.stdout) > 64 or len(result.stderr) > 1024:
            raise ValueError
        if result.returncode == 0 and re.fullmatch(r"[a-z0-9_-]{1,32}", kind) and kind != "none":
            return {"status": "vm_detected", "kind": kind}, []
        if result.returncode == 1 and kind in {"", "none"}:
            return {"status": "vm_not_detected", "kind": None}, []
        raise ValueError
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "kind": None}, ["vm_detection:unavailable_or_invalid"]


def startup(duration, interval):
    detection, gaps = vm_detection()
    identity = {"ID": None, "VERSION_ID": None}
    try:
        for line in _read(Path("/etc/os-release")).splitlines():
            name, separator, value = line.partition("=")
            if separator and name in identity:
                value = value.strip('"')
                if (
                    identity[name] is not None
                    or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value) is None
                ):
                    raise ValueError
                identity[name] = value
        gaps.extend(
            "os_release:" + key + ":missing" for key, value in identity.items() if value is None
        )
    except (OSError, UnicodeError, ValueError):
        identity = {"ID": None, "VERSION_ID": None}
        gaps.append("os_release:unavailable_or_invalid")
    try:
        uname = os.uname()
        kernel_release, machine = uname.release, uname.machine
    except (OSError, AttributeError):
        kernel_release = machine = None
        gaps.append("kernel_identity:unavailable")
    logical_cpus = os.cpu_count()
    if logical_cpus is None:
        gaps.append("logical_cpu_count:unavailable")
    try:
        affinity_cpus = len(os.sched_getaffinity(0))
    except (OSError, AttributeError):
        affinity_cpus = None
        gaps.append("affinity_cpu_count:unavailable")
    return {
        "schema_version": 1,
        "record_type": "start",
        "utc": datetime.now(UTC).isoformat(),
        "monotonic_ns": time.monotonic_ns(),
        "duration_seconds": duration,
        "interval_seconds": interval,
        "os_release": identity,
        "kernel_release": kernel_release,
        "machine": machine,
        "logical_cpu_count": logical_cpus,
        "affinity_cpu_count": affinity_cpus,
        "vm_detection": detection,
        "budget_configuration_verified": False,
        "classification": "guest_observation_not_hypervisor_budget_proof",
        "sample_atomic": False,
        "limitations": [
            "Proc totals may describe a containing system when this runs inside a container.",
            "VM detection does not prove RAM/vCPU/swap configuration; retain hypervisor evidence.",
        ],
        "counter_units": {
            "oom_kill": "events",
            "pgmajfault": "faults",
            "pswpin": "pages",
            "pswpout": "pages",
            "cpu": "kernel_ticks",
        },
        "coverage_gaps": gaps,
    }


def collect_sample(previous=None, *, phase_file=None, proc_root=Path("/proc"), root=Path("/")):
    gaps = []

    def source(label, path, parser, empty):
        try:
            value, missing = parser(_read(path))
            gaps.extend(label + ":" + item for item in missing)
            return value
        except (OSError, UnicodeError, ValueError):
            gaps.append(label + ":unavailable_or_invalid")
            return empty

    memory = source("memory", proc_root / "meminfo", parse_memory, dict.fromkeys(MEMORY_FIELDS))
    counters = source("vmstat", proc_root / "vmstat", parse_counters, dict.fromkeys(COUNTERS))
    cpu = source(
        "cpu",
        proc_root / "stat",
        parse_cpu,
        dict.fromkeys((*CPU_FIELDS, "total", "idle_and_iowait")),
    )
    pressure = {
        name: source(
            "psi_" + name,
            proc_root / "pressure" / name,
            parse_pressure,
            {"some": None, "full": None},
        )
        for name in ("cpu", "memory", "io")
    }
    load = source("load", proc_root / "loadavg", parse_load, None)
    rss = source(
        "self_rss",
        proc_root / "self/status",
        lambda text: parse_memory(text, ("VmRSS",)),
        {"VmRSS": None},
    )["VmRSS"]
    filesystem, missing = filesystem_sample(root)
    gaps.extend("root_filesystem:" + item for item in missing)
    phase, missing = read_phase(phase_file)
    gaps.extend(missing)
    at = time.monotonic_ns()
    derived = {
        "baseline": previous is None,
        "elapsed_seconds": None,
        "vmstat": None,
        "cpu_busy_percent_total_capacity": None,
    }
    if previous is not None:
        elapsed = (at - previous["monotonic_ns"]) / 1_000_000_000
        derived["elapsed_seconds"] = elapsed
        changes, missing = counter_changes(previous["vmstat_counters"], counters, elapsed)
        derived["vmstat"] = changes
        gaps.extend("delta_vmstat:" + item for item in missing)
        changes, missing = counter_changes(previous["cpu_ticks"], cpu, elapsed)
        gaps.extend("delta_cpu:" + item for item in missing)
        delta = changes["deltas"]
        if (
            all(value is not None for value in delta.values())
            and delta["total"] > 0
            and 0 <= delta["idle_and_iowait"] <= delta["total"]
        ):
            derived["cpu_busy_percent_total_capacity"] = round(
                100 * (1 - delta["idle_and_iowait"] / delta["total"]), 4
            )
    return {
        "schema_version": 1,
        "record_type": "sample",
        "utc": datetime.now(UTC).isoformat(),
        "monotonic_ns": at,
        "phase": phase,
        "memory_bytes": memory,
        "vmstat_counters": counters,
        "pressure": pressure,
        "cpu_ticks": cpu,
        "load_average_1_5_15_minutes": load,
        "root_filesystem": filesystem,
        "sampler_rss_bytes": rss,
        "derived": derived,
        "coverage_gaps": sorted(set(gaps)),
    }


def duration_argument(value):
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Duration must be an integer from 1 to 3600") from None
    if not 1 <= parsed <= 3600:
        raise argparse.ArgumentTypeError("Duration must be an integer from 1 to 3600")
    return parsed


def interval_argument(value):
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Interval must be finite and at least one second"
        ) from None
    if not math.isfinite(parsed) or parsed < 1:
        raise argparse.ArgumentTypeError("Interval must be finite and at least one second")
    return parsed


def run(output, *, duration, interval, phase_file=None):
    if sys.platform != "linux":
        raise ValueError("Linux /proc observations are required")
    duration = duration_argument(str(duration))
    interval = interval_argument(str(interval))
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:

        def emit(value):
            handle.write(
                json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
            )
            handle.flush()

        emit(startup(duration, interval))
        started = time.monotonic()
        deadline = started + duration
        previous, count, reason, observed_gaps = None, 0, "duration_complete", Counter()
        try:
            while True:
                previous = collect_sample(previous, phase_file=phase_file)
                emit(previous)
                count += 1
                observed_gaps.update(previous["coverage_gaps"])
                now = time.monotonic()
                if now >= deadline:
                    break
                remaining = deadline - now
                time.sleep(min(interval, remaining))
                if remaining < interval:
                    break  # Do not create a final sub-interval burst at the deadline.
        except KeyboardInterrupt:
            reason = "interrupted"
        emit(
            {
                "schema_version": 1,
                "record_type": "end",
                "utc": datetime.now(UTC).isoformat(),
                "monotonic_ns": time.monotonic_ns(),
                "elapsed_seconds": time.monotonic() - started,
                "samples": count,
                "reason": reason,
                "coverage_gap_counts": dict(observed_gaps),
                "budget_configuration_verified": False,
            }
        )
        os.fsync(handle.fileno())
    return 0 if reason == "duration_complete" else 130


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, type=Path, help="New JSONL file; never overwritten"
    )
    parser.add_argument("--duration", type=duration_argument, default=60, help="Seconds, 1..3600")
    parser.add_argument(
        "--interval", type=interval_argument, default=2.0, help="Seconds, at least 1"
    )
    parser.add_argument("--phase-file", type=Path, help="Read only one short ASCII phase label")
    args = parser.parse_args(argv)
    try:
        return run(
            args.output, duration=args.duration, interval=args.interval, phase_file=args.phase_file
        )
    except (OSError, ValueError) as error:
        # No source contents, credentials, phase contents or untrusted path/error text.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
