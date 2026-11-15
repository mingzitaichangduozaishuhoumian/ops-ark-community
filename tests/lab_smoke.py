"""Actual SSH and Nginx integration against a disposable, loopback-only lab."""

import json
import os
import secrets
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from opsark.config import Settings
from opsark.main import create_app

ROOT = Path(__file__).resolve().parents[1]
TARGET_IMAGES = {
    "ubuntu:24.04": ("ubuntu", "24.04"),
    "debian:12": ("debian", "12"),
    "debian:13": ("debian", "13"),
}


def control(action: str) -> dict | None:
    environment = os.environ.copy()
    for name in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ):
        environment.pop(name, None)
    command = [
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "compose",
        "-p",
        "opsark-lab",
        "-f",
        str(ROOT / "tests/lab/compose.yaml"),
        "exec",
        "-T",
        "target",
        "python3",
        "/opt/opsark-lab/control.py",
        action,
    ]
    result = subprocess.run(  # noqa: S603 -- fixed actions against this disposable lab only.
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
        env=environment,
    )
    return json.loads(result.stdout) if action == "probe" else None


def site_status(report: dict) -> str:
    checks = [
        item for item in report["verification"] if "E-HTTP-SHOP" in item.get("evidence_ids", [])
    ]
    if len(checks) != 1:
        raise RuntimeError("Expected one evidence-linked site check from real SSH collection")
    return checks[0]["status"]


def assert_readonly(report: dict) -> None:
    if report["source"] != "ssh" or report["action"]["executable"]:
        raise RuntimeError("The lab report lost its real SSH source or read-only boundary")
    if report["comparison"]["restore_capable"]:
        raise RuntimeError("An observation snapshot must not become a configuration rollback")
    if not any(item["status"] in {"not_run", "uncovered"} for item in report["verification"]):
        raise RuntimeError("A site check must not silently complete all recovery verification")


def target_platform(report: dict, image: str) -> dict:
    """Verify the selected image against metadata derived from actual SSH evidence."""
    compatibility = report["compatibility"]
    expected_id, expected_version = TARGET_IMAGES[image]
    if compatibility["status"] != "compatible":
        raise RuntimeError("The actual target did not pass its OS and tool preflight")
    if (compatibility["os_id"], compatibility["version_id"]) != (expected_id, expected_version):
        raise RuntimeError("Actual SSH operating-system evidence differs from the selected image")
    if compatibility["architecture"] not in {"x86_64", "aarch64"}:
        raise RuntimeError("The actual target architecture is outside the current adapter range")
    required_refs = {"E-OS-RELEASE", "E-PLATFORM-TOOLS"}
    if not required_refs <= set(compatibility["evidence_ids"]):
        raise RuntimeError("The platform assessment lost its actual SSH evidence references")
    for ref in required_refs:
        evidence = next(item for item in report["evidence"] if item["id"] == ref)
        if evidence["status"] != "ok" or evidence["exit_code"] != 0 or evidence["truncated"]:
            raise RuntimeError("An incomplete platform probe was treated as compatible")
    return {
        "os_id": compatibility["os_id"],
        "version_id": compatibility["version_id"],
        "architecture": compatibility["architecture"],
        "evidence_ids": sorted(required_refs),
        "source": "ssh",
    }


def run() -> None:
    image = os.environ.get("OPSARK_LAB_BASE_IMAGE", "ubuntu:24.04")
    if image not in TARGET_IMAGES:
        raise RuntimeError("Unsupported lab image; only the fixed Ubuntu/Debian matrix is allowed")
    directory = Path(os.environ["OPSARK_LAB_KEY_DIR"]).resolve()
    port = int(os.environ.get("OPSARK_LAB_SSH_PORT", "22220"))
    inventory = directory / "inventory.toml"
    inventory.write_text(
        "\n".join(
            [
                "[credentials.lab]",
                "key_file = " + json.dumps(str(directory / "client_key")),
                "known_hosts_file = " + json.dumps(str(directory / "known_hosts")),
                "[[hosts]]",
                'id = "lab-web-01"',
                'name = "Isolated Ubuntu or Debian Nginx fixture"',
                'address = "127.0.0.1"',
                f"port = {port}",
                'username = "opsark-readonly"',
                'credential = "lab"',
                'site_domain = "shop.example.com"',
                'container_name = "api"',
                "expected_upstream_port = 8081",
                'nginx_config_path = "/etc/nginx/conf.d/shop.conf"',
                "[[hosts.health_checks]]",
                'id = "shop"',
                'domain = "shop.example.com"',
                'path = "/healthz"',
                "port = 8080",
                "expected_status = 200",
                'expected_body = "ok"',
                "read_only_confirmed = true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(
        data_dir=directory / "app-data",
        token=secrets.token_urlsafe(32),
        inventory_path=inventory,
    )
    headers = {"Authorization": "Bearer " + settings.token}
    with TestClient(create_app(settings)) as client:

        def investigate() -> dict:
            response = client.post(
                "/api/investigations",
                headers=headers,
                json={
                    "source": "ssh",
                    "scenario": "web_502",
                    "host_id": "lab-web-01",
                },
            )
            if response.status_code != 200:
                raise RuntimeError(f"Lab investigation failed with HTTP {response.status_code}")
            report = response.json()
            assert_readonly(report)
            target_platform(report, image)
            return report

        healthy = investigate()
        if site_status(healthy) != "passed":
            raise RuntimeError("Initial real Nginx site check did not pass")
        saved = client.post(
            f"/api/reports/{healthy['id']}/baseline",
            headers=headers,
            json={
                "confirm_observation_only": True,
            },
        )
        if saved.status_code not in {200, 201} or saved.json()["restore_capable"]:
            raise RuntimeError("Could not save an observation-only baseline from real evidence")

        control("stop")
        if control("probe") != {"status": 502, "fixture_only": True}:
            raise RuntimeError("The isolated fault did not produce an actual Nginx 502")
        failed = investigate()
        if site_status(failed) != "failed":
            raise RuntimeError("The failed upstream was not reflected by real site verification")
        nginx_error = next(
            item for item in failed["evidence"] if item["check_id"] == "nginx_errors"
        )
        if "Connection refused" not in nginx_error["output"] or "8081" not in nginx_error["output"]:
            raise RuntimeError("Missing actual Nginx upstream-refusal evidence")

        control("start")
        recovered = investigate()
        if site_status(recovered) != "passed":
            raise RuntimeError("Restored upstream did not pass the configured current-site check")
        if recovered["action"]["executable"]:
            raise RuntimeError("A passing site check must not enable write operations")

        control("drift")
        changed = investigate()
        if site_status(changed) != "passed":
            raise RuntimeError(
                "Changing only disk configuration unexpectedly changed the live site"
            )
        hash_changes = [
            item
            for item in changed["comparison"]["changes"]
            if "E-NGINX-CONFIG-HASH" in item.get("evidence_ids", [])
            and item["before"] != item["after"]
        ]
        if not hash_changes:
            raise RuntimeError("The real disk configuration hash change was not recorded")
        if changed["comparison"]["baseline_report_id"] != healthy["id"]:
            raise RuntimeError("The comparison lost its actual observation baseline reference")
        print("PASS: real SSH, real Nginx 502, current-site checks and observation baseline.")
        print(
            json.dumps(
                {
                    "lab_only": True,
                    "target_image": image,
                    "target_platform": target_platform(healthy, image),
                    "site_checks": [
                        site_status(item) for item in (healthy, failed, recovered, changed)
                    ],
                    "config_hash_change_detected": True,
                    "rollback_available": False,
                    "docker_workload_diagnostics_verified": False,
                    "production_vps_verified": False,
                    "recovery_incident_closed": False,
                }
            )
        )


if __name__ == "__main__":
    run()
