"""Actual Docker workload diagnostics through a strict, temporary SSH harness."""

import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import paramiko
from docker_lab.ssh_server import DockerLabSSH
from fastapi.testclient import TestClient

from opsark.collector import commands_for
from opsark.config import HostConfig, Settings
from opsark.models import HostPublic

IMAGE = "python:3.13-slim"
LABEL = "opsark.test.docker-lab"
MEMORY_BYTES = 64 * 1024 * 1024
OOM_READY = "OPSARK_LAB_MEMCG_READY"
OOM_SCRIPT = f"""import signal
import sys
import time

armed = False
def arm(_signal, _frame):
    global armed
    armed = True

signal.signal(signal.SIGUSR1, arm)
print('{OOM_READY}', flush=True)
deadline = time.monotonic() + 120
while not armed:
    if time.monotonic() >= deadline:
        raise SystemExit(71)
    time.sleep(0.01)
chunks = []
try:
    for _ in range(128):
        chunk = bytearray(1024 * 1024)
        for offset in range(0, len(chunk), 4096):
            chunk[offset] = 90
        chunks.append(chunk)
        time.sleep(0.01)
except MemoryError:
    raise SystemExit(70) from None
raise SystemExit(72)
"""
CGROUP_PROBE = """import json
from pathlib import Path
print(json.dumps({name: (Path('/sys/fs/cgroup') / name).read_text().strip()
                  for name in ('memory.max', 'memory.swap.max')}))
"""


def selected_image() -> str:
    value = os.environ.get("OPSARK_DOCKER_LAB_IMAGE", IMAGE)
    if value != IMAGE and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("The workload image must be the existing CI image or a pinned local ID")
    return value


def isolated_app_factory(directory: Path):
    """Keep the imported default app away from the runner's deployment configuration."""
    previous = {name: value for name, value in os.environ.items() if name.startswith("OPSARK_")}
    for name in previous:
        os.environ.pop(name)
    os.environ["OPSARK_DATA_DIR"] = str(directory / "bootstrap")
    try:
        from opsark.main import create_app
    finally:
        os.environ.pop("OPSARK_DATA_DIR", None)
        os.environ.update(previous)
    return create_app


def trigger_memcg_oom(name: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if docker("logs", "--tail", "1", name) == OOM_READY:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("The bounded OOM workload did not become ready")
    limits = json.loads(docker("exec", name, "python3", "-I", "-c", CGROUP_PROBE))
    if limits != {"memory.max": str(MEMORY_BYTES), "memory.swap.max": "0"}:
        raise RuntimeError("The OOM fixture does not have the exact native memory and swap limits")
    state = inspect(name)
    if (
        state["HostConfig"]["Memory"] != MEMORY_BYTES
        or state["HostConfig"]["MemorySwap"] != MEMORY_BYTES
    ):
        raise RuntimeError("Docker did not retain the fixture's memory and swap budgets")
    docker("kill", "--signal", "USR1", name)
    killed = wait_for(name, status="exited", seconds=30)
    if killed["State"]["ExitCode"] != 137 or killed["State"]["OOMKilled"] is not True:
        raise RuntimeError("The positive fixture did not produce a native memcg OOM kill")
    return limits


def docker(*arguments: str, timeout: float = 15) -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeError("The local Docker CLI is required for this optional lab")
    environment = os.environ.copy()
    for name in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ):
        environment.pop(name, None)
    result = subprocess.run(  # noqa: S603 -- fixed Docker CLI, fixture-owned names and actions.
        [executable, "--host", "unix:///var/run/docker.sock", *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
        env=environment,
    )
    return result.stdout.strip()


def inspect(name: str, *, timeout: float = 15) -> dict:
    data = json.loads(docker("inspect", name, timeout=timeout))
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise RuntimeError("Docker returned an unexpected fixture inspection")
    return data[0]


def wait_for(name: str, *, status: str, count: int = 0, seconds: float = 50) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        state = inspect(name, timeout=min(3, remaining))
        if state["State"]["Status"] == status and state["RestartCount"] == count:
            return state
        time.sleep(0.25)
    raise RuntimeError(f"Fixture {name} did not reach {status} with restart count {count}")


def assert_boundaries(report: dict) -> None:
    if report["source"] != "ssh" or report["action"]["executable"]:
        raise RuntimeError("Actual Docker evidence must remain an SSH read-only report")
    if report["comparison"]["restore_capable"]:
        raise RuntimeError("An observation must not become a rollback configuration")
    if any(item["status"] == "passed" for item in report["verification"]):
        raise RuntimeError("Container inspection must not certify business recovery")


def state_evidence(report: dict) -> dict:
    evidence = [item for item in report["evidence"] if item["check_id"] == "container_state"]
    if len(evidence) != 1 or evidence[0]["status"] != "ok" or evidence[0]["truncated"]:
        raise RuntimeError("A complete, successful actual Docker inspection was not collected")
    return json.loads(evidence[0]["output"])


def verify_harness_restrictions(harness: DockerLabSSH, directory: Path) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(str(harness.known_hosts_file))
    try:
        client.connect(
            "127.0.0.1",
            port=harness.port,
            username="opsark-lab",
            key_filename=str(harness.key_file),
            look_for_keys=False,
            allow_agent=False,
            timeout=3,
        )
        marker = directory / "arbitrary-command-must-not-run"
        try:
            client.exec_command("touch " + str(marker), timeout=3)
        except paramiko.SSHException:
            pass
        else:
            raise RuntimeError("The SSH fixture accepted an arbitrary shell command")
        if marker.exists() or not harness.rejected:
            raise RuntimeError("The SSH fixture did not reject the arbitrary command")
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("The SSH fixture unexpectedly disconnected")
        channel = transport.open_session(timeout=3)
        try:
            channel.invoke_subsystem("sftp")
        except paramiko.SSHException:
            pass
        else:
            raise RuntimeError("The SSH fixture accepted SFTP")
        finally:
            channel.close()
    finally:
        client.close()


def run_lab(directory: Path) -> None:
    create_app = isolated_app_factory(directory)
    configuration = directory / "docker-config"
    configuration.mkdir(mode=0o700)
    os.environ["DOCKER_CONFIG"] = str(configuration)
    nonce = secrets.token_hex(8)
    names = {
        kind: f"opsark-docker-lab-{nonce}-{kind}" for kind in ("ok", "restart", "signal", "oom")
    }
    image = selected_image()
    version = docker("version", "--format", "{{.Server.Version}}")
    metadata = docker(
        "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
    ).split()
    if (
        len(metadata) != 2
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata[0])
        or metadata[1] not in {"null", "{}"}
    ):
        raise RuntimeError("The workload image must be local and declare no volumes")
    runtime_image = metadata[0]
    common = [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "64m",
        "--memory-swap",
        "64m",
        "--cpus",
        "0.25",
        "--cgroupns",
        "private",
        "--pids-limit",
        "32",
        "--label",
        f"{LABEL}={nonce}",
    ]
    # Only these unpredictable names can be created or cleaned up by this run.
    attempted: list[str] = []

    def start(kind: str, script: str, *options: str) -> None:
        name = names[kind]
        attempted.append(name)
        identifier = docker(
            "run",
            "-d",
            "--pull",
            "never",
            "--name",
            name,
            *common,
            *options,
            "--entrypoint",
            "python3",
            runtime_image,
            "-u",
            "-c",
            script,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise RuntimeError("Docker did not return a fixture container ID")

    try:
        start("ok", "import time; print('OPSARK_LAB_HEALTHY'); time.sleep(300)")
        # Each attempt runs for >10 seconds before failure, honoring Docker's
        # documented successful-start condition for restart-policy monitoring.
        start(
            "restart",
            "import sys,time; print('OPSARK_LAB_EXIT42_STDOUT'); "
            "print('OPSARK_LAB_EXIT42_STDERR',file=sys.stderr); time.sleep(11); sys.exit(42)",
            "--restart",
            "on-failure:2",
        )
        start("signal", "import time; print('OPSARK_LAB_EXTERNAL_SIGNAL'); time.sleep(300)")
        start("oom", OOM_SCRIPT, "--restart", "no")
        wait_for(names["ok"], status="running")
        wait_for(names["signal"], status="running")
        # Controlled SIGKILL, not memory pressure: this is the negative OOM case.
        docker("kill", "--signal", "KILL", names["signal"])
        killed = wait_for(names["signal"], status="exited")
        limits = trigger_memcg_oom(names["oom"])
        restarted = wait_for(names["restart"], status="exited", count=2)
        if killed["State"]["ExitCode"] != 137 or killed["State"]["OOMKilled"] is not False:
            raise RuntimeError("The controlled signal fixture did not produce non-OOM exit 137")
        if restarted["State"]["ExitCode"] != 42 or restarted["State"]["OOMKilled"] is not False:
            raise RuntimeError("The restart fixture did not produce the intended non-OOM failure")

        hosts = {
            kind: HostConfig(
                public=HostPublic(
                    id=f"docker-lab-{kind}",
                    name=f"Actual Docker workload {kind}",
                    address="127.0.0.1",
                    username="opsark-lab",
                    container_name=name,
                    source="ssh",
                ),
                key_file=directory / "pending",
                known_hosts_file=directory / "pending",
            )
            for kind, name in names.items()
        }
        commands = {
            command
            for host in hosts.values()
            for command in commands_for(host, "container_restart").values()
        }
        with DockerLabSSH(directory, commands) as harness:
            verify_harness_restrictions(harness, directory)
            inventory = directory / "inventory.toml"
            lines = [
                "[credentials.lab]",
                "key_file = " + json.dumps(str(harness.key_file)),
                "known_hosts_file = " + json.dumps(str(harness.known_hosts_file)),
            ]
            for kind, name in names.items():
                lines.extend(
                    [
                        "[[hosts]]",
                        f'id = "docker-lab-{kind}"',
                        f'name = "Actual Docker workload {kind}"',
                        'address = "127.0.0.1"',
                        f"port = {harness.port}",
                        'username = "opsark-lab"',
                        'credential = "lab"',
                        'site_domain = "fixture.example.com"',
                        f'container_name = "{name}"',
                    ]
                )
            inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
            settings = Settings(
                data_dir=directory / "reports",
                token=secrets.token_urlsafe(32),
                inventory_path=inventory,
            )
            headers = {"Authorization": "Bearer " + settings.token}
            reports: dict[str, dict] = {}
            with TestClient(create_app(settings)) as client:
                for kind in names:
                    response = client.post(
                        "/api/investigations",
                        headers=headers,
                        json={
                            "source": "ssh",
                            "scenario": "container_restart",
                            "host_id": f"docker-lab-{kind}",
                        },
                    )
                    if response.status_code != 200:
                        raise RuntimeError(f"Docker investigation failed: {response.status_code}")
                    reports[kind] = response.json()
                    assert_boundaries(reports[kind])

            ok_state = state_evidence(reports["ok"])
            restart_state = state_evidence(reports["restart"])
            signal_state = state_evidence(reports["signal"])
            oom_state = state_evidence(reports["oom"])
            if ok_state["State"]["Status"] != "running" or ok_state["RestartCount"] != 0:
                raise RuntimeError("The healthy workload's actual state was not preserved")
            if restart_state["RestartCount"] != 2 or restart_state["State"]["ExitCode"] != 42:
                raise RuntimeError("Actual restart count and failure code were not preserved")
            restart_logs = next(
                item
                for item in reports["restart"]["evidence"]
                if item["check_id"] == "container_logs"
            )
            if restart_logs["status"] != "ok" or any(
                marker not in restart_logs["output"]
                for marker in ("OPSARK_LAB_EXIT42_STDOUT", "OPSARK_LAB_EXIT42_STDERR")
            ):
                raise RuntimeError("Actual Docker application stdout/stderr logs were not retained")
            if signal_state["State"]["ExitCode"] != 137 or signal_state["State"]["OOMKilled"]:
                raise RuntimeError("The real non-OOM 137 evidence changed during investigation")
            signal_candidates = "\n".join(item["text"] for item in reports["signal"]["candidates"])
            if "退出码 137 尚不能区分" not in signal_candidates:
                raise RuntimeError("Exit 137 was not kept as an uncertain signal candidate")
            if any(
                "内存终止是有状态证据支持" in item["text"]
                for item in reports["signal"]["candidates"]
            ):
                raise RuntimeError("Exit 137 was incorrectly diagnosed as proven OOM")
            if reports["restart"]["status"] != "needs_attention":
                raise RuntimeError("Actual repeated nonzero exits did not receive attention")
            if (
                oom_state["State"]["ExitCode"] != 137
                or oom_state["State"]["OOMKilled"] is not True
                or oom_state["MemoryLimit"] != MEMORY_BYTES
                or oom_state["RestartCount"] != 0
            ):
                raise RuntimeError("Native OOM state was not preserved in actual SSH evidence")
            candidates = [
                item
                for item in reports["oom"]["candidates"]
                if "内存终止是有状态证据支持" in item["text"]
            ]
            if len(candidates) != 1 or candidates[0]["evidence_ids"] != ["E-CONTAINER-STATE"]:
                raise RuntimeError("The native OOM candidate lost its direct state evidence")
            if reports["oom"]["status"] != "needs_attention":
                raise RuntimeError("The native OOM report did not retain its attention state")
            memory_event = next(
                item for item in reports["oom"]["evidence"] if item["check_id"] == "memory_events"
            )
            if memory_event["status"] == "ok":
                raise RuntimeError("The lab unexpectedly read an unrelated host kernel journal")
            print(
                json.dumps(
                    {
                        "lab_only": True,
                        "docker_server_version": version,
                        "workload_image": image,
                        "workload_image_id": ok_state["Image"],
                        "healthy_state": ok_state["State"]["Status"],
                        "actual_restart_count": restart_state["RestartCount"],
                        "actual_restart_exit_code": restart_state["State"]["ExitCode"],
                        "actual_signal_exit_code": signal_state["State"]["ExitCode"],
                        "signal_oom_killed": signal_state["State"]["OOMKilled"],
                        "stdout_and_stderr_collected": True,
                        "arbitrary_command_rejected": True,
                        "sftp_rejected": True,
                        "docker_workload_diagnostics_verified": True,
                        "actual_oom_fault_verified": True,
                        "actual_oom_exit_code": oom_state["State"]["ExitCode"],
                        "oom_killed": oom_state["State"]["OOMKilled"],
                        "memory_max_bytes": int(limits["memory.max"]),
                        "memory_swap_max_bytes": int(limits["memory.swap.max"]),
                        "host_kernel_journal_uncovered": True,
                        "production_openssh_account_verified": False,
                        "production_vps_verified": False,
                        "recovery_incident_closed": False,
                    }
                )
            )
    finally:
        for name in attempted:
            with contextlib.suppress(subprocess.SubprocessError, ValueError, KeyError):
                data = inspect(name)
                if (
                    data.get("Config", {}).get("Labels", {}).get(LABEL) == nonce
                    and data.get("Name") == "/" + name
                    and re.fullmatch(r"[0-9a-f]{64}", data.get("Id", ""))
                ):
                    docker("rm", "--force", data["Id"])


if __name__ == "__main__":
    if sys.platform != "linux" or not Path("/var/run/docker.sock").exists():
        raise SystemExit(
            "This optional lab requires a disposable Linux runner's local Docker Engine"
        )
    if os.environ.get("OPSARK_DISPOSABLE_DOCKER_LAB") != "1":
        raise SystemExit(
            "Set OPSARK_DISPOSABLE_DOCKER_LAB=1 only on a disposable, authorized runner"
        )
    with tempfile.TemporaryDirectory(prefix="opsark-docker-lab-") as temporary:
        run_lab(Path(temporary))
