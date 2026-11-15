"""Root-owned read-only snapshots around real Web approval; no service action here."""

import hashlib
import json
import platform
import sys
from pathlib import Path

sys.path.insert(0, "/opt/opsark-activation-lab")
import fixture as lab  # noqa: E402

lab.configure_adapter()
import activation  # noqa: E402
import core  # noqa: E402
import worker  # noqa: E402


def snapshot():
    folder = lab.STATE / "jobs" / lab.JOB
    paths = [folder / n for n in ("job.json", "plan.json", "runtime-files-before.json")]
    paths.append(lab.STATE / "automatic-state.json")
    pid = int(lab.command(["/usr/bin/systemctl", "show", lab.UNIT, "--value", "-p", "MainPID"]))
    records = [core.read_json(p) for p in (lab.STATE / "activations").glob("*/activation.json")]
    return {
        "os": platform.freedesktop_os_release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "systemd": lab.command(["/usr/bin/systemctl", "--version"]).splitlines()[0],
        "openssh": lab.command(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "openssh-server"]),
        "policy": lab.policy(),
        "job": core.read_json(folder / "job.json"),
        "plan": core.read_json(folder / "plan.json"),
        "safety": core.read_json(lab.STATE / "automatic-state.json"),
        "parent_sha256": {str(p): lab.sha(p) for p in paths},
        "inventory_digest": core.digest(lab.inventory()),
        "pid": pid,
        "process": activation._unit_evidence(lab.UNIT)["main_process"],
        "raw_maps": Path(f"/proc/{pid}/maps").read_text(),
        "runtime": worker.runtime_maps([str(lab.MAPPING)] + worker.package_files("zlib1g")),
        "health": core.health(lab.policy()),
        "activations": records,
        "rpc": [core.read_json(p) for p in (lab.STATE / "lab-rpc").glob("*.json")],
        "restart_intents": len(list((lab.STATE / "activations").glob("*/restart-intent.json"))),
        "mode": core.read_json(lab.STATE / "mode.json"),
        "source_sha256": {
            name: hashlib.sha256((lab.LIB / name).read_bytes()).hexdigest()
            for name in core.SOURCE_FILES
        },
    }


if __name__ == "__main__":
    value = snapshot()
    print(json.dumps(value, sort_keys=True))
