"""Native guest acceptance with explicitly synthetic patch/vendor prerequisites."""

import copy
import json
import os
import platform
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, "/opt/opsark-activation-lab")
import fixture as lab  # noqa: E402

lab.configure_adapter()
import activation  # noqa: E402
import core  # noqa: E402
import scan  # noqa: E402
import worker  # noqa: E402


def ssh_argv():
    return [
        "/usr/bin/ssh",
        "-T",
        "-F",
        "/dev/null",
        "-i",
        str(lab.HERE / "client"),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(lab.HERE / "known_hosts"),
        "-o",
        "ConnectTimeout=5",
        "opsark-repair@127.0.0.1",
        "opsark-patch-v1",
    ]


def payload(request):
    return json.dumps(
        {"schema_version": 1, "policy_digest": core.policy_digest(lab.policy()), **request}
    )


def ssh(request):
    result = subprocess.run(  # noqa: S603 -- fixed loopback identity and forced command.
        ssh_argv(),
        input=payload(request),
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(core.ENV),
        check=False,
    )
    lab.check(result.returncode == 0, "Restricted SSH RPC failed: " + result.stderr[:400])
    return json.loads(result.stdout)


def prepare(revision=0):
    value = ssh(
        {
            "op": "activation_prepare",
            "job_id": lab.JOB,
            "mode_revision": revision,
            "context_digest": lab.CONTEXT,
        }
    )
    lab.check(value.get("status") == "activation_prepared", "Preview rejected: " + str(value))
    return value


def submission(plan):
    return {
        "op": "activation_submit",
        **{
            key: plan[key]
            for key in ("activation_id", "activation_digest", "mode_revision", "context_digest")
        },
    }


def pid():
    return int(lab.command(["/usr/bin/systemctl", "show", lab.UNIT, "--value", "-p", "MainPID"]))


@contextmanager
def external_lock(path, *, flock=False):
    program = (
        "import fcntl,sys; f=open(sys.argv[1],'r+'); "
        + ("fcntl.flock" if flock else "fcntl.lockf")
        + "(f,fcntl.LOCK_EX|fcntl.LOCK_NB);print('locked',flush=True);sys.stdin.readline()"
    )
    with subprocess.Popen(  # noqa: S603 -- fixed child code, guest-owned lock.
        ["/usr/bin/python3", "-I", "-c", program, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as child:
        try:
            lab.check(child.stdout.readline().strip() == "locked", "Lock child failed")
            yield
        finally:
            child.communicate("release\n", timeout=5)


def run():
    began = time.monotonic()
    checks = {}
    release = platform.freedesktop_os_release()
    lab.check(
        release["ID"] == "debian"
        and release["VERSION_ID"] == os.environ["OPSARK_ACTIVATION_EXPECTED_VERSION"],
        "Unexpected actual guest release",
    )
    checks["actual_debian_release_matches_matrix"] = True
    paths = [
        lab.STATE / "jobs" / lab.JOB / name
        for name in ("job.json", "plan.json", "runtime-files-before.json")
    ] + [lab.STATE / "automatic-state.json"]
    original = {str(p): p.read_bytes() for p in paths}
    inventory_before = lab.inventory()
    before = pid()
    maps_before = activation._outdated([str(lab.MAPPING)])
    lab.check(
        len(maps_before) == 1 and maps_before[0]["pid"] == before,
        "Fixture did not create exactly one real deleted mapping",
    )
    checks["real_deleted_mapping"] = True
    core.write_json(
        lab.HERE / "native-before.json",
        {
            "processes": maps_before,
            "raw_maps": Path(f"/proc/{before}/maps").read_text(),
            "parent_sha256": {str(p): lab.sha(p) for p in paths},
            "inventory_digest": core.digest(inventory_before),
        },
    )
    forbidden = ssh_argv()
    forbidden[-1] = "id"
    refused = subprocess.run(  # noqa: S603 -- actual forced-command boundary on guest loopback.
        forbidden,
        input=payload(
            {
                "op": "activation_prepare",
                "job_id": lab.JOB,
                "mode_revision": 0,
                "context_digest": lab.CONTEXT,
            }
        ),
        capture_output=True,
        text=True,
        timeout=15,
        env=dict(core.ENV),
        check=False,
    )
    lab.check(
        refused.returncode == 126 and not refused.stdout and pid() == before,
        "Unexpected SSH command escaped the fixed bridge",
    )
    checks["arbitrary_ssh_command_denied"] = True
    # Production inventory must keep rejecting Debian; no supported-platform expansion.
    try:
        scan.collect_inventory()
    except ValueError:
        checks["production_debian_patch_gate_closed"] = True
    else:
        raise RuntimeError("Production inventory unexpectedly admitted Debian")

    def rejected(name, request):
        lab.check(ssh(request).get("status") == "rejected", name + " was accepted")
        lab.check(pid() == before, name + " restarted the service")
        lab.check(
            not list((lab.STATE / "activations").glob("*/restart-intent.json")),
            name + " persisted a restart intent",
        )
        checks[name] = True

    preview = prepare()
    lab.check(pid() == before, "Preview changed PID")
    checks["preview_read_only"] = True
    rejected("manual_submit_denied", submission(preview))
    lab.set_mode("assisted", 1)
    rejected("stale_mode_denied", submission(preview))
    preview = prepare(1)
    changed = submission(preview)
    changed["activation_digest"] = "0" * 64
    rejected("wrong_digest_denied", changed)
    changed = submission(preview)
    changed["context_digest"] = "0" * 64
    rejected("wrong_context_denied", changed)

    # Expiry is an explicitly resealed test prerequisite; no clock or TTL is patched.
    expired = copy.deepcopy(preview)
    expired["created_at"] = (core.now() - timedelta(minutes=6)).isoformat()
    expired["expires_at"] = (core.now() - timedelta(minutes=1)).isoformat()
    expired["activation_digest"] = core.digest(
        {k: v for k, v in expired.items() if k != "activation_digest"}
    )
    saved_plan = lab.STATE / "activation-plans" / (preview["activation_id"] + ".json")
    core.write_json(saved_plan, expired)
    rejected("expired_plan_denied", submission(expired))
    core.write_json(saved_plan, preview)

    lab.command(["/usr/bin/systemctl", "set-environment", "OPSARK_ACTIVATION_LAB_DRIFT=1"])
    try:
        rejected("manager_environment_drift_denied", submission(preview))
    finally:
        lab.command(["/usr/bin/systemctl", "unset-environment", "OPSARK_ACTIVATION_LAB_DRIFT"])
    unit = Path("/etc/systemd/system") / lab.UNIT
    raw_unit = unit.read_bytes()
    unit.write_bytes(raw_unit + b"\n# controlled drift\n")
    try:
        rejected("unit_file_drift_denied", submission(preview))
    finally:
        unit.write_bytes(raw_unit)
        lab.command(["/usr/bin/systemctl", "daemon-reload"])
    parent = paths[0]
    changed_parent = core.read_json(parent)
    changed_parent["revision"] += 1
    core.write_json(parent, changed_parent)
    try:
        rejected("parent_ledger_drift_denied", submission(preview))
    finally:
        parent.write_bytes(original[str(parent)])
    with external_lock(lab.STATE / "worker.lock", flock=True):
        rejected("worker_lock_denied", submission(preview))
    for index, filename in enumerate(core.NATIVE_PACKAGE_LOCKS):
        with external_lock(filename):
            rejected("native_package_lock_" + str(index) + "_denied", submission(preview))
    permission = copy.deepcopy(lab.policy())
    permission["activation"]["allowed_units"] = ["ssh.service"]
    try:
        activation.validate_policy(permission)
    except core.Rejected:
        checks["critical_ssh_denied"] = True
    else:
        raise RuntimeError("Critical SSH unit admitted")
    lab.check(
        all(
            activation._hard_critical("web.service", executable)
            for executable in (
                "/usr/sbin/sshd",
                "/usr/lib/openssh/sshd-session",
                "/usr/lib/openssh/sshd-auth",
            )
        ),
        "Split OpenSSH executable admitted under an ordinary unit name",
    )

    gate = lab.HERE / "worker-gate.json"
    core.write_json(gate, {"purpose": "execution_context_drift"})
    gated = prepare(1)
    ssh(submission(gated))
    for _ in range(100):
        if (lab.HERE / "worker-gate-ready.json").exists():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Native worker did not reach the bounded fault gate")
    lab.command(["/usr/bin/systemctl", "set-environment", "OPSARK_ACTIVATION_LAB_DRIFT=1"])
    try:
        gate.unlink()
        for _ in range(100):
            gated_result = activation.status(gated["activation_id"], lab.policy())
            if gated_result["status"] == "rejected":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Execution-context drift did not reject the queued approval")
        lab.check(
            pid() == before and gated_result["restart_evidence"] is None,
            "Drifted worker dispatched a restart",
        )
        checks["queued_approval_revalidated_before_restart"] = True
    finally:
        lab.command(["/usr/bin/systemctl", "unset-environment", "OPSARK_ACTIVATION_LAB_DRIFT"])

    # A genuinely received submit reply is deliberately discarded by this client.
    # Subsequent reconciliation sends only status for the original activation ID.
    preview = prepare(1)
    ready_before = set((lab.STATE / "lab-ssh").iterdir())
    old_connection = subprocess.Popen(  # noqa: S603 -- fixed restricted loopback SSH.
        ssh_argv(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(core.ENV),
    )
    for _ in range(100):
        if set((lab.STATE / "lab-ssh").iterdir()) - ready_before:
            break
        time.sleep(0.05)
    else:
        old_connection.communicate(timeout=5)
        raise RuntimeError("Old SSH connection was not ready before activation")
    ssh(submission(preview))
    identifier = preview["activation_id"]
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        value = activation.status(identifier, lab.policy())
        if value["status"] == "awaiting_transport_verification":
            break
        lab.check(
            value["status"] not in {"unknown", "rejected", "verification_failed"},
            "Worker did not complete: " + json.dumps(value),
        )
        time.sleep(0.2)
    else:
        raise RuntimeError("Activation did not finish within 90 seconds")
    lab.check(value["local_result"] == "verified", "Native local checks failed")
    checks["no_ssh_cannot_verify"] = value["status"] == "awaiting_transport_verification"
    old_reply, old_error = old_connection.communicate(
        payload({"op": "activation_status", "activation_id": identifier}),
        timeout=15,
    )
    lab.check(old_connection.returncode == 0, "Old SSH failed: " + old_error)
    lab.check(
        json.loads(old_reply)["status"] == "awaiting_transport_verification",
        "Old SSH connection was accepted as fresh",
    )
    checks["real_old_ssh_connection_cannot_verify"] = True
    time.sleep(0.05)  # Ensure the new connection starts after the recorded kernel tick.
    final = ssh({"op": "activation_status", "activation_id": identifier})
    core.write_json(lab.HERE / "final-receipt.json", final)
    lab.check(final["status"] == "verified", "Fresh SSH did not verify: " + json.dumps(final))
    checks["approved_once_and_lost_reply_reconciled"] = True
    after = pid()
    lab.check(after != before, "No new service PID")
    checks["new_process_identity"] = final["verification"]["new_process"]["passed"]
    # Explicit adversarial replay: the production worker and duplicate submit must be no-ops.
    activation.run(identifier)
    replay = ssh(submission(preview))
    lab.check(replay["status"] == "verified" and pid() == after, "Duplicate replay changed service")
    checks["duplicate_submit_and_worker_no_replay"] = True
    lab.check(
        len(list((lab.STATE / "activations").glob("*/restart-intent.json"))) == 1,
        "More than one durable restart",
    )
    lab.check(all(p.read_bytes() == original[str(p)] for p in paths), "Parent ledger changed")
    checks["parent_plan_manifest_and_pause_byte_identical"] = True
    lab.check(inventory_before == lab.inventory(), "Package/APT state changed")
    checks["no_package_changes"] = True
    runtime = worker.runtime_maps([str(lab.MAPPING)] + worker.package_files("zlib1g"))
    lab.check(
        runtime["status"] == "complete" and runtime["outdated_process_count"] == 0,
        "Old mappings remain",
    )
    checks["no_old_mappings_after"] = True
    checks["registered_http_and_services"] = final["verification"]["health"]["passed"]
    checks["fresh_ssh_verified"] = final["verification"]["fresh_ssh"]["passed"]
    checks["no_reboot_pending"] = final["verification"]["health"]["reboot_required"] is False
    lab.set_mode("manual", 2)
    lab.check(all(checks.values()), "One or more native checks failed")
    return {
        "schema_version": 1,
        "evidence_origin": "controlled_lab",
        "classification": "native_debian_activation_with_synthetic_parent_and_vendor_finding",
        "os": platform.freedesktop_os_release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "systemd": lab.command(["/usr/bin/systemctl", "--version"]).splitlines()[0],
        "openssh": lab.command(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "openssh-server"]),
        "package": next(p for p in inventory_before["packages"] if p["name"] == "zlib1g"),
        "source_sha256": {name: lab.sha(lab.LIB / name) for name in core.SOURCE_FILES},
        "checks": checks,
        "passed": True,
        "check_count": len(checks),
        "before_pid": before,
        "after_pid": after,
        "restart_intents": 1,
        "approved_submissions": 2,
        "deliberate_duplicate_submissions": 1,
        "parent_sha256_after": {str(p): lab.sha(p) for p in paths},
        "activation_id": identifier,
        "final_status": final["status"],
        "runtime": runtime,
        "elapsed_seconds": round(time.monotonic() - began, 3),
        "limitations": [
            "synthetic_parent_transaction",
            "synthetic_vendor_finding",
            "fixture_inventory_adapter",
            "no_debian_patch_execution_acceptance",
            "client_discarded_reply_not_real_network_failure",
            "resealed_expired_fixture_not_elapsed_ttl_test",
            "shared_host_kernel",
        ],
    }


if __name__ == "__main__":
    try:
        result = run()
    except Exception as error:
        core.write_json(
            lab.HERE / "failure.json", {"type": type(error).__name__, "detail": str(error)}
        )
        raise
    core.write_json(lab.HERE / "result.json", result)
    print(json.dumps(result, sort_keys=True))
