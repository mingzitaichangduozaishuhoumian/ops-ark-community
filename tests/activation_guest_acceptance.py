"""Create an owned, disposable Debian systemd guest using the local Docker engine."""

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ("debian:12", "debian:13")
LABEL = "io.opsark.activation-lab.run"


def docker(argv, *, timeout=30, capture=True, report_errors=True):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_")}
    endpoint = (
        "npipe:////./pipe/dockerDesktopLinuxEngine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeError("Docker CLI is required")
    try:
        return subprocess.run(  # noqa: S603 -- fixed local engine and owned identifiers.
            [executable, "--host", endpoint, *argv],
            env=environment,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        if capture and report_errors and error.stderr:
            print(error.stderr[-8000:], file=sys.stderr)
        raise


def inspect_owned(identifier, token):
    value = json.loads(docker(["inspect", identifier]))[0]
    if value["Id"] != identifier or value["Config"]["Labels"].get(LABEL) != token:
        raise RuntimeError("Guest ownership changed; refusing to mutate it")
    return value


def verify_isolation(value):
    host = value["HostConfig"]
    if not (
        host["NetworkMode"] == "none"
        and not host["Privileged"]
        and host["CgroupnsMode"] == "private"
        and host["PidMode"] == ""
        and host["IpcMode"] == "private"
        and not host.get("PortBindings")
        and not value["Mounts"]
        and not host.get("Binds")
        and host["RestartPolicy"]["Name"] == "no"
        and host["Memory"] == 1_073_741_824
        and host["NanoCpus"] == 1_000_000_000
        and host["PidsLimit"] == 256
        and {cap.removeprefix("CAP_") for cap in host["CapAdd"]} == {"SYS_ADMIN", "SYS_PTRACE"}
    ):
        raise RuntimeError("Disposable guest isolation differs from the reviewed lab scope")


def export_evidence(identifier, directory):
    # No client private key or authorized_keys is exported.
    missing = []
    for source, name in (
        ("/opt/opsark-activation-lab/result.json", "result.json"),
        ("/opt/opsark-activation-lab/failure.json", "failure.json"),
        ("/opt/opsark-activation-lab/final-receipt.json", "final-receipt.json"),
        ("/opt/opsark-activation-lab/native-before.json", "native-before.json"),
        ("/var/lib/opsark-patch", "root-state"),
    ):
        try:
            docker(["cp", identifier + ":" + source, str(directory / name)], report_errors=False)
        except subprocess.CalledProcessError:
            missing.append(name)
    (directory / "evidence-export.json").write_text(
        json.dumps({"missing": missing}), encoding="utf-8"
    )
    (directory / "journal.txt").write_text(
        docker(
            [
                "exec",
                identifier,
                "/usr/bin/journalctl",
                "--no-pager",
                "-o",
                "short-monotonic",
                "-u",
                "opsark-activation@*",
                "-u",
                "activation-fixture.service",
            ]
        ),
        encoding="utf-8",
    )


def run(image, output, *, web_browser=None, activation_rescan=False):
    if image not in IMAGES:
        raise ValueError("Only Debian 12 and Debian 13 are in this acceptance matrix")
    if activation_rescan and web_browser is None:
        raise ValueError("Activation rescan acceptance requires the real Web path")
    if os.environ.get("OPSARK_DISPOSABLE_ACTIVATION_LAB") != "1":
        raise RuntimeError("Set OPSARK_DISPOSABLE_ACTIVATION_LAB=1 on an authorized lab runner")
    if json.loads(docker(["info", "--format", "{{json .OSType}}"])) != "linux":
        raise RuntimeError("A local Linux Docker engine is required")
    token = secrets.token_hex(8)
    name = "opsark-activation-" + token
    tag = name + ":lab"
    output = output.resolve() / (image.replace(":", "-") + "-" + token)
    output.mkdir(parents=True, exist_ok=False)
    identifier = None
    image_built = False
    success = False
    try:
        # The build context includes reviewed fixture/Root files, never workspace credentials.
        with tempfile.TemporaryDirectory(prefix="opsark-activation-build-") as temporary:
            context = Path(temporary)
            for source in (ROOT / "tests/activation_lab").iterdir():
                if source.is_file() and source.suffix in {".py", ".sh", ""}:
                    shutil.copyfile(source, context / source.name)
            shutil.copytree(
                ROOT / "deploy/vulnerability",
                context / "root",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            docker(
                [
                    "build",
                    "--label",
                    LABEL + "=" + token,
                    "--build-arg",
                    "BASE_IMAGE=" + image,
                    "-t",
                    tag,
                    str(context),
                ],
                timeout=600,
                capture=False,
            )
            image_built = True
        image_info = json.loads(docker(["image", "inspect", tag]))[0]
        identifier = docker(
            [
                "create",
                "--name",
                name,
                "--label",
                LABEL + "=" + token,
                "--network",
                "none",
                "--cgroupns",
                "private",
                "--cap-add",
                "SYS_ADMIN",
                "--cap-add",
                "SYS_PTRACE",
                "--security-opt",
                "apparmor=unconfined",
                "--memory",
                "1g",
                "--cpus",
                "1",
                "--pids-limit",
                "256",
                "--restart",
                "no",
                "--stop-timeout",
                "60",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "--tmpfs",
                "/tmp",  # noqa: S108 -- private tmpfs inside the disposable guest.
                "--env",
                "OPSARK_DISPOSABLE_ACTIVATION_LAB=1",
                "--env",
                "OPSARK_ACTIVATION_EXPECTED_VERSION=" + image.split(":")[1],
                "--env",
                "OPSARK_ACTIVATION_RESCAN_LAB=" + ("1" if activation_rescan else "0"),
                tag,
            ]
        ).strip()
        value = inspect_owned(identifier, token)
        (output / "isolation-inspect.json").write_text(
            json.dumps({"host_config": value["HostConfig"], "mounts": value["Mounts"]}, indent=2),
            encoding="utf-8",
        )
        verify_isolation(value)
        (output / "provenance.json").write_text(
            json.dumps(
                {
                    "image_requested": image,
                    "observed_at": datetime.now(UTC).isoformat(),
                    "image_id": image_info["Id"],
                    "container_id": identifier,
                    "run_id": token,
                    "isolation": {
                        "network": "none",
                        "ports": [],
                        "mounts": [],
                        "privileged": False,
                        "memory_mib": 1024,
                        "cpus": 1,
                        "pids": 256,
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        docker(["start", identifier])
        for _ in range(90):
            try:
                docker(
                    ["exec", identifier, "/usr/bin/systemctl", "is-active", "ssh.service"],
                    report_errors=False,
                )
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
        else:
            raise RuntimeError("Guest systemd/SSH did not start")
        docker(
            [
                "exec",
                identifier,
                "/usr/bin/python3",
                "-I",
                "/opt/opsark-activation-lab/fixture.py",
                "setup",
            ],
            timeout=90,
        )
        if web_browser is not None:
            sys.path.insert(0, str(ROOT / "src"))
            from activation_web_acceptance import run_web

            run_web(
                identifier,
                output,
                image=image,
                browser_name=web_browser,
                activation_rescan=activation_rescan,
            )
        else:
            print(
                docker(
                    [
                        "exec",
                        identifier,
                        "/usr/bin/python3",
                        "-I",
                        "/opt/opsark-activation-lab/acceptance.py",
                    ],
                    timeout=180,
                ),
                flush=True,
            )
        success = True
    finally:
        try:
            if identifier is not None:
                value = inspect_owned(identifier, token)
                # Export even on failure, then remove only this exact owned guest.
                try:
                    if value["State"]["Running"]:
                        export_evidence(identifier, output)
                    (output / "container.log").write_text(
                        docker(["logs", identifier]), encoding="utf-8"
                    )
                finally:
                    docker(["stop", identifier], timeout=90)
                    docker(["rm", identifier])
                    (output / "cleanup.json").write_text(
                        json.dumps(
                            {
                                "container_removed": True,
                                "run_id": token,
                                "acceptance_passed": success,
                            }
                        ),
                        encoding="utf-8",
                    )
        finally:
            if image_built:
                image_info = json.loads(docker(["image", "inspect", tag]))[0]
                if image_info["Config"]["Labels"].get(LABEL) != token:
                    raise RuntimeError("Image ownership changed; refusing cleanup")
                docker(["image", "rm", tag])
    if success and activation_rescan:
        from activation_web_acceptance import offline_exports

        offline_exports(output)
    print("Evidence: " + str(output), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, choices=IMAGES)
    parser.add_argument("--output", type=Path, default=ROOT / "data/activation-guest-acceptance")
    parser.add_argument(
        "--web-browser",
        choices=("chromium", "firefox", "webkit"),
        help="Run real Web approval through the unchanged controller and SSH client",
    )
    parser.add_argument(
        "--activation-rescan",
        action="store_true",
        help="Include independent native observation and evidence export acceptance",
    )
    arguments = parser.parse_args()
    run(
        arguments.image,
        arguments.output,
        web_browser=arguments.web_browser,
        activation_rescan=arguments.activation_rescan,
    )
