"""Read-only Root/PID1 property proof with the deployed system Python.

Run as sudo /usr/bin/python3 -I tests/native_systemd_property_probe.py on Linux.
No pytest, mock, broker, service mutation, package operation or model is used.
The actual repository core and activation implementations supply every check.
"""

import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MISSING = frozenset({"EnvironmentFiles", "ExecStop", "ExecStopPost"})
ABSENT_UNIT = "opsark-no-such-proof.service"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Native probe source could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def descriptor_count():
    # Path.iterdir closes its own directory stream before this function returns.
    return len(list(Path("/proc/self/fd").iterdir()))


def dbus_state(core):
    # Query only the existing positive-control service. The absent negative unit
    # below is sent exclusively to production's Manager.GetUnit, never LoadUnit.
    result = subprocess.run(  # noqa: S603 -- fixed read-only systemctl argv.
        [
            "/usr/bin/systemctl",
            "show",
            "dbus.service",
            "--all",
            "--no-pager",
            "--property=Id,ActiveState,SubState,MainPID",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=dict(core.ENV),
        timeout=8,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Existing service state could not be read")
    rows = [line.split("=", 1) for line in result.stdout.splitlines()]
    if any(len(row) != 2 for row in rows) or len({row[0] for row in rows}) != len(rows):
        raise RuntimeError("Existing service state was not structured")
    state = dict(rows)
    if (
        set(state) != {"Id", "ActiveState", "SubState", "MainPID"}
        or state["Id"] != "dbus.service"
        or state["ActiveState"] != "active"
        or state["SubState"] != "running"
        or not state["MainPID"].isdecimal()
        or int(state["MainPID"]) <= 1
    ):
        raise RuntimeError("Positive-control service must already be active")
    return state


def run():
    if sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0:
        raise RuntimeError("This probe requires Linux root and the deployed system Python")
    if sys.executable != "/usr/bin/python3":
        raise RuntimeError("The deployed fixed system Python is required")
    core_path = ROOT / "deploy/vulnerability/core.py"
    activation_path = ROOT / "deploy/vulnerability/activation.py"
    core = load_module("core", core_path)
    activation = load_module("native_property_probe_activation", activation_path)
    if activation.core is not core:
        raise RuntimeError("The real Root core alias was not used")

    before = dbus_state(core)
    count_before = descriptor_count()
    activation._prove_empty_properties("dbus.service", MISSING)
    count_after_positive = descriptor_count()
    if count_after_positive > count_before:
        raise RuntimeError("Positive property query retained a descriptor")

    rejected = False
    try:
        activation._prove_empty_properties(ABSENT_UNIT, MISSING)
    except core.Rejected:
        rejected = True
    if not rejected:
        raise RuntimeError("An absent unit was accepted as typed-empty evidence")
    count_after_negative = descriptor_count()
    if count_after_negative > count_before:
        raise RuntimeError("Failed GetUnit retained a descriptor")

    after = dbus_state(core)
    if before != after:
        raise RuntimeError("Read-only property queries changed the existing service identity")
    if descriptor_count() > count_before:
        raise RuntimeError("Completed native probe retained a descriptor")
    return {
        "schema_version": 1,
        "classification": "real_root_private_pid1_property_probe_no_mock",
        "runtime": {
            "executable": sys.executable,
            "python": platform.python_version(),
            "platform": sys.platform,
            "machine": platform.machine(),
            "effective_uid": os.geteuid(),
        },
        "core_source_sha256": hashlib.sha256(core_path.read_bytes()).hexdigest(),
        "activation_source_sha256": hashlib.sha256(activation_path.read_bytes()).hexdigest(),
        "positive": {
            "unit": "dbus.service",
            "production_typed_empty_checks_passed": True,
            "required_property_signatures": {
                key: activation.EMPTY_COMPLEX_PROPERTIES[key] for key in sorted(MISSING)
            },
            "empty_arrays_proved": len(MISSING),
        },
        "negative": {
            "unit": ABSENT_UNIT,
            "production_get_unit_rejected": rejected,
            "load_or_start_requested": False,
        },
        "descriptor_counts": {
            "before": count_before,
            "after_positive": count_after_positive,
            "after_negative": count_after_negative,
        },
        "descriptor_growth": False,
        "dbus_before": before,
        "dbus_after": after,
        "same_existing_pid_and_active_state": True,
        "production_paths_abi_or_metadata_modified": False,
        "service_actions": 0,
        "package_changes": 0,
        "model_calls": 0,
        "passed": True,
    }


if __name__ == "__main__":
    try:
        evidence = run()
    except Exception as error:
        # No C/D-Bus error strings, property values, environment or command output.
        print(json.dumps({"passed": False, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(evidence, sort_keys=True))
