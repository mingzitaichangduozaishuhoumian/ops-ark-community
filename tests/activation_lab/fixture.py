"""Debian activation-only adapter. Never installed by the production installer.

The parent transaction and vendor finding are synthetic. Inventory reads real
dpkg/APT state. Activation, locks, /proc, PID1, health and SSH remain production
implementations. No package is upgraded, downgraded or claimed to be repaired.
"""

import ctypes
import hashlib
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

LIB = Path("/usr/local/libexec/opsark-patch")
HERE = Path("/opt/opsark-activation-lab")
STATE = Path("/var/lib/opsark-patch")
UNIT = "activation-fixture.service"
MAPPING = Path("/usr/local/lib/opsark-activation-fixture.so")
JOB = "a" * 32
CONTEXT = "c" * 64
FINDING = "f" * 64
sys.path.insert(0, str(LIB))
import core  # noqa: E402


def command(argv):
    return subprocess.check_output(  # noqa: S603 -- fixed lab argv, no shell.
        argv, env=dict(core.ENV), text=True, timeout=20
    ).strip()


def check(value, detail):
    if not value:
        raise RuntimeError(detail)


def owned_guest():
    check(os.geteuid() == 0 and sys.platform == "linux", "Linux guest root required")
    marker = core.read_json(HERE / "owned.json")
    check(
        marker["machine_id"] == hashlib.sha256(Path("/etc/machine-id").read_bytes()).hexdigest()
        and Path("/proc/1/comm").read_text().strip() == "systemd"
        and Path("/run/systemd/container").read_text().strip() == "docker",
        "Owned disposable systemd guest required",
    )
    check(core.source_digest() == marker["source_digest"], "Root source changed")


def policy():
    owned_guest()
    value = core.read_json(HERE / "policy.json")
    check(value["driver_source_digest"] == core.source_digest(), "Policy source changed")
    return value


def inventory():
    # Debian inventory adapter only; does not bypass the production Ubuntu gate.
    packages = command(
        ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Architecture}\t${Version}\n"]
    )
    config = command(["/usr/bin/apt-config", "dump"])
    return {
        "packages": [
            dict(zip(("name", "architecture", "installed_version"), row.split("\t"), strict=True))
            for row in packages.splitlines()
        ],
        "apt_state_digest": core.digest(
            {"packages": packages, "config": config, "status": sha(Path("/var/lib/dpkg/status"))}
        ),
        # This is an explicit fixture projection, not production source validation.
        "apt_configuration_safe": True,
    }


def vendor_fixture(*_args, **_kwargs):
    return {
        "scan_id": "e" * 32,
        "findings": [
            {
                "finding_id": FINDING,
                "affected": False,
                "vendor_evidence_fresh": True,
                "finding_evidence_complete": True,
            }
        ],
        "coverage": {"status": "partial"},
        "gaps": ["synthetic_vendor_finding_no_debian_remediation_acceptance"],
    }


def native_observation_scan():
    """Read actual guest state; deliberately make no Debian vendor/CVE judgment."""
    owned_guest()
    check((HERE / "rescan-mode.json").is_file(), "Rescan lab not enabled")
    with core.lock("scan", wait_seconds=2):
        for _ in range(300):
            verified = any(
                core.read_json(p).get("status") == "verified"
                for p in (STATE / "activations").glob("*/activation.json")
            )
            if not verified or not (HERE / "rescan-hold.json").exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Bounded rescan hold was not released")
        import activation
        import worker

        current = inventory()
        package = next(p for p in current["packages"] if p["name"] == "zlib1g")
        facts = {
            "package": package,
            "apt_state_digest": current["apt_state_digest"],
            "runtime": worker.runtime_maps([str(MAPPING)] + worker.package_files("zlib1g")),
            "health": core.health(policy()),
            "process": activation._unit_evidence(UNIT)["main_process"],
        }
        value = {
            "schema_version": 1,
            "host_id": policy()["host_id"],
            "scan_id": secrets.token_hex(16),
            "collected_at": core.stamp(),
            "policy_digest": core.policy_digest(policy()),
            "driver_source_digest": core.source_digest(),
            "evidence_origin": "controlled_lab",
            "coverage": {
                "status": "partial",
                "all_installed_cves_checked": False,
                "installed_package_count": len(current["packages"]),
                "finding_count": 0,
                "evaluated_finding_count": 0,
            },
            "findings": [],
            "providers": [],
            "gaps": [
                "debian_vendor_assessment_not_implemented",
                "synthetic_parent_activation_precondition",
            ],
            "collection_evidence": {
                "schema_version": 1,
                "collection_kind": "native_probe",
                "assessment_kind": "not_evaluated",
                "facts": facts,
                "facts_digest": core.digest(facts),
            },
        }
        folder = STATE / "lab-scans"
        folder.mkdir(mode=0o700, exist_ok=True)
        core.write_json(folder / (value["scan_id"] + ".json"), value)
        return value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configure_adapter():
    owned_guest()
    core.load_policy = policy
    core.inventory = inventory
    core.scan_packages = vendor_fixture


def setup():
    check(os.environ.get("OPSARK_DISPOSABLE_ACTIVATION_LAB") == "1", "Explicit opt-in required")
    check(not (HERE / "owned.json").exists() and not STATE.exists(), "Refusing guest reuse")
    HERE.chmod(0o700)
    STATE.mkdir(mode=0o700)
    if os.environ.get("OPSARK_ACTIVATION_RESCAN_LAB") == "1":
        core.write_json(HERE / "rescan-mode.json", {"purpose": "activation_rescan_acceptance"})
    core.write_json(
        HERE / "owned.json",
        {
            "machine_id": sha(Path("/etc/machine-id")),
            "source_digest": core.source_digest(),
        },
    )
    owned_guest()
    for name in ("jobs", "plans"):
        (STATE / name).mkdir(mode=0o700)
    for name in core.NATIVE_PACKAGE_LOCKS:
        Path(name).touch(mode=0o640, exist_ok=True)
    installed = next(p for p in inventory()["packages"] if p["name"] == "zlib1g")
    candidates = command(["/usr/bin/dpkg-query", "-L", "zlib1g"]).splitlines()
    library = next(Path(p) for p in candidates if Path(p).name.startswith("libz.so.1."))
    shutil.copyfile(library, MAPPING)
    MAPPING.chmod(0o644)
    (Path("/etc/systemd/system") / UNIT).write_text(
        "[Unit]\nDescription=OpsArk disposable activation fixture\n"
        "[Service]\nType=simple\nKillMode=control-group\n"
        "ExecStart=/usr/bin/python3 -I /opt/opsark-activation-lab/fixture.py serve\n"
        "Restart=no\n"
    )
    # Only the worker entry is adapted; its production single-dispatch implementation is unchanged.
    worker = (LIB / "opsark-activation@.service").read_text()
    worker = worker.replace(
        "/usr/local/libexec/opsark-patch/activation.py %i",
        "/opt/opsark-activation-lab/fixture.py worker %i",
    )
    Path("/etc/systemd/system/opsark-activation@.service").write_text(worker)
    command(["/usr/bin/systemctl", "daemon-reload"])
    command(["/usr/bin/systemctl", "start", UNIT])
    for _ in range(100):
        try:
            probe = {
                "id": "fixture",
                "domain": "localhost",
                "port": 18880,
                "path": "/healthz",
                "expected_status": 200,
                "expected_body": "OPSARK_ACTIVATION_LAB_OK",
            }
            if core.http_health(probe)["passed"]:
                break
        except OSError:
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError("Fixture service did not become healthy")
    # Atomic replacement produces a genuine deleted library mapping without APT/dpkg writes.
    replacement = MAPPING.with_suffix(".new")
    shutil.copyfile(library, replacement)
    replacement.chmod(0o644)
    os.replace(replacement, MAPPING)
    value = {
        "schema_version": 1,
        "driver": "activation-fixture/v1",
        "driver_source_digest": core.source_digest(),
        "host_id": "debian-activation-lab",
        "asset_kind": "controlled_lab",
        "enabled": True,
        "allowed_packages": ["zlib1g"],
        "allow_service_restart": True,
        "allow_reboot": False,
        "services": ["ssh.service"],
        "health_checks": [
            {
                "id": "fixture",
                "domain": "localhost",
                "port": 18880,
                "path": "/healthz",
                "expected_status": 200,
                "expected_body": "OPSARK_ACTIVATION_LAB_OK",
            }
        ],
        "activation": {
            "schema_version": 1,
            "enabled": True,
            "allowed_packages": ["zlib1g"],
            "allowed_units": [UNIT],
            "allow_critical_units": [],
        },
    }
    core.write_json(HERE / "policy.json", value)
    set_mode("manual", 0)
    folder = STATE / "jobs" / JOB
    folder.mkdir(mode=0o700)
    plan = {
        "plan_id": "b" * 32,
        "host_id": value["host_id"],
        "finding": {"package": "zlib1g", "advisory": "USN-0-1", "finding_id": FINDING},
        "package_changes": [
            {
                "name": "zlib1g",
                "architecture": installed["architecture"],
                "current_version": "0",  # Synthetic historical parent, never installed.
                "candidate_version": installed["installed_version"],
            }
        ],
    }
    plan["plan_digest"] = core.digest(plan)
    core.write_json(folder / "plan.json", plan)
    manifest = {
        "schema_version": 1,
        "job_id": JOB,
        "package": "zlib1g",
        "architecture": installed["architecture"],
        "version": "0",
        "paths": [str(MAPPING)],
    }
    core.write_json(folder / "runtime-files-before.json", manifest)
    core.write_json(
        folder / "job.json",
        {
            "job_id": JOB,
            "host_id": value["host_id"],
            "authorization": "automatic",
            "evidence_provenance": {
                "classification": "synthetic_fixture",
                "installation": "not_executed",
                "vendor_assessment": "synthetic_fixture",
            },
            "created_at": core.stamp(),
            "automatic_grant_id": "9" * 32,  # Synthetic historical identity; no grant is enabled.
            "status": "installed_restart_pending",
            "revision": 7,
            "plan_id": plan["plan_id"],
            "plan_digest": plan["plan_digest"],
            "install_exit_code": 0,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "runtime_files_before_sha256": sha(folder / "runtime-files-before.json"),
            "verification": {
                **{
                    k: {"passed": True}
                    for k in ("exact_package_version", "vendor_rescan", "health", "fresh_ssh")
                },
                "runtime": {"status": "complete", "outdated_process_count": 1},
            },
        },
    )
    core.write_json(
        STATE / "automatic-state.json",
        {
            "schema_version": 1,
            "paused": True,
            "job_id": JOB,
            "reason": "automatic_job_installed_restart_pending",
            "updated_at": core.stamp(),
        },
    )
    command(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(HERE / "client")])
    public = (HERE / "client.pub").read_text().strip()
    ssh_dir = Path("/home/opsark-repair/.ssh")
    ssh_dir.mkdir(mode=0o700)
    auth = ssh_dir / "authorized_keys"
    bridge = (LIB / "ssh_entry.py").read_text()
    original_argv = '["/usr/bin/sudo", "-n", "--", "/usr/local/libexec/opsark-patch/agent.py"]'
    check(bridge.count(original_argv) == 1, "Production SSH bridge template changed")
    bridge = bridge.replace(
        original_argv,
        '["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", '
        '"/opt/opsark-activation-lab/fixture.py", "rpc"]',
    )
    bridge_path = Path("/usr/local/libexec/opsark-activation-lab-ssh.py")
    bridge_path.write_text(bridge)
    bridge_path.chmod(0o755)
    auth.write_text('restrict,command="' + str(bridge_path) + '" ' + public + "\n")
    command(["/usr/bin/chown", "-R", "opsark-repair:opsark-repair", str(ssh_dir)])
    auth.chmod(0o600)
    Path("/etc/sudoers.d/opsark-activation-lab").write_text(
        "opsark-repair ALL=(root) NOPASSWD: /usr/bin/python3 -I "
        "/opt/opsark-activation-lab/fixture.py rpc\n"
    )
    Path("/etc/sudoers.d/opsark-activation-lab").chmod(0o440)
    Path("/etc/ssh/sshd_config.d/00-opsark-activation-lab.conf").write_text(
        "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "AllowUsers opsark-repair\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\n"
    )
    command(["/usr/sbin/sshd", "-t"])
    command(["/usr/bin/systemctl", "reload", "ssh.service"])
    host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().split()
    (HERE / "known_hosts").write_text("127.0.0.1 " + " ".join(host_key[:2]) + "\n")


def set_mode(mode, revision):
    core.write_json(
        STATE / "mode.json",
        {
            "mode": mode,
            "revision": revision,
            "policy_digest": core.policy_digest(policy()),
            "updated_at": core.stamp(),
        },
    )


def serve():
    loaded = ctypes.CDLL(str(MAPPING))
    loaded.zlibVersion.restype = ctypes.c_char_p
    check(bool(loaded.zlibVersion()), "Library did not load")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/healthz" else 404)
            self.end_headers()
            self.wfile.write(b"OPSARK_ACTIVATION_LAB_OK")

        def log_message(self, *_args):
            pass

    with http.server.HTTPServer(("127.0.0.1", 18880), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        serve()
    elif sys.argv[1:] == ["setup"]:
        setup()
    elif sys.argv[1:] in (["rescan-hold"], ["rescan-release"]):
        owned_guest()
        check((HERE / "rescan-mode.json").is_file(), "Rescan lab not enabled")
        if sys.argv[1] == "rescan-hold":
            core.write_json(HERE / "rescan-hold.json", {"purpose": "observe_incomplete_export"})
        else:
            (HERE / "rescan-hold.json").unlink()
    else:
        configure_adapter()
        import activation
        import agent

        if len(sys.argv) == 3 and sys.argv[1] == "worker":
            gate = HERE / "worker-gate.json"
            if gate.exists():
                # One bounded, owned fault gate before the unchanged worker's revalidation.
                core.write_json(HERE / "worker-gate-ready.json", {"activation_id": sys.argv[2]})
                for _ in range(200):
                    if not gate.exists():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Lab worker gate was not released")
            activation.run(sys.argv[2])
        elif sys.argv[1:] == ["rpc"]:
            lineage = []
            parent = os.getppid()
            for _ in range(16):
                if parent <= 1:
                    break
                fields = Path(f"/proc/{parent}/stat").read_text().rsplit(")", 1)[1].split()
                lineage.append(
                    {
                        "pid": parent,
                        "exe": os.readlink(f"/proc/{parent}/exe"),
                        "starttime_ticks": int(fields[19]),
                    }
                )
                parent = int(fields[1])
            ready = STATE / "lab-ssh"
            ready.mkdir(mode=0o700, exist_ok=True)
            core.write_json(ready / (str(os.getpid()) + ".json"), {"ancestors": lineage})
            # Only activation, mode synchronization and read-only safety are admitted.
            request = agent.read_request()
            check(
                request["op"]
                in {
                    "activation_prepare",
                    "activation_submit",
                    "activation_status",
                    "set_mode",
                    "automatic_status",
                }
                or request["op"] == "scan"
                and (HERE / "rescan-mode.json").is_file(),
                "Unsupported lab RPC",
            )
            audit = STATE / "lab-rpc"
            audit.mkdir(mode=0o700, exist_ok=True)
            audit_path = audit / (str(os.getpid()) + ".json")
            core.write_json(audit_path, {"request": request, "received_at": core.stamp()})
            try:
                if request["op"] == "scan":
                    with core.lock("rpc"):
                        check(
                            request["policy_digest"] == core.policy_digest(policy()),
                            "Policy changed",
                        )
                        result = native_observation_scan()
                else:
                    result = agent.dispatch(request)
            except core.Rejected:
                result = {
                    "schema_version": 1,
                    "status": "rejected",
                    "ok": False,
                    "error": "rejected",
                    "detail": "Controlled lab RPC rejected",
                }
            except Exception as error:
                core.write_json(
                    HERE / "failure.json",
                    {"type": type(error).__name__, "detail": str(error), "op": request["op"]},
                )
                raise
            core.write_json(
                audit_path,
                {"request": request, "status": result.get("status"), "completed_at": core.stamp()},
            )
            print(json.dumps(result, sort_keys=True))
        else:
            raise SystemExit(126)
