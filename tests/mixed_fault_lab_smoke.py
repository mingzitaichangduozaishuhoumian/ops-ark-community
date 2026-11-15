#!/usr/bin/env python3
"""Exercise independent upstream and inode faults through one registered SSH target."""

import argparse
import json
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from docker_lab.ssh_server import DockerLabSSH  # noqa: E402 -- trusted standalone harness paths.
from fastapi.testclient import TestClient  # noqa: E402
from filesystem_lab_smoke import Fixture, app_factory, evidence, require  # noqa: E402

from opsark.collector import commands_for  # noqa: E402
from opsark.config import HostConfig, Settings  # noqa: E402
from opsark.diagnostics import _df  # noqa: E402
from opsark.models import HealthCheck, HostPublic  # noqa: E402

MIXED_SCRIPT = "/fixture-state/mixed.py"
PUBLIC_ID = "mixed-fault-lab"
SCENARIOS = ("web_502", "disk")
UNAVAILABLE = {"nginx_status", "container_state"}


def install_mixed(target: Fixture) -> None:
    program = """import os
import sys
data = sys.stdin.buffer.read(65537)
assert 0 < len(data) <= 65536
fd = os.open('/fixture-state/mixed.py',
             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as handle:
    handle.write(data)
    handle.flush()
    os.fsync(handle.fileno())
"""
    target.call(
        "exec",
        "-i",
        str(target.identity),
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        program,
        payload=(ROOT / "tests/mixed_lab/target.py").read_bytes(),
    )


def control(target: Fixture, mode: str) -> dict:
    value = json.loads(
        target.call(
            "exec", str(target.identity), "/usr/bin/python3", "-I", "-B", MIXED_SCRIPT, mode
        )
    )
    require(
        isinstance(value, dict)
        and set(value) == {"nginx_running", "upstream_running"}
        and all(type(item) is bool for item in value.values()),
        "Invalid mixed fixture state",
    )
    require(
        value["nginx_running"] is (mode != "stop"), "The real Nginx fixture changed unexpectedly"
    )
    return value


def health(report: dict, check: str, passed: bool) -> None:
    item = evidence(report, "http_" + check)
    results = [value for value in report["verification"] if item["id"] in value["evidence_ids"]]
    require(len(results) == 1, "No unique real HTTP verification in mixed report")
    result = results[0]
    require(
        result["evidence_ids"] == [item["id"]]
        and result["status"] == ("passed" if passed else "failed")
        and result["http_status"] == (200 if passed else 502)
        and result["status_matches"] is passed,
        "The current target or shared-control HTTP result was incorrect",
    )
    if passed:
        require(
            result["body_matches"] is True, "The successful HTTP response lost its origin marker"
        )


def report_boundaries(report: dict) -> None:
    require(
        report["host_id"] == PUBLIC_ID
        and report["source"] == "ssh"
        and report["action"]["executable"] is False
        and report["comparison"]["restore_capable"] is False
        and report["compatibility"]["status"] == "compatible",
        "The mixed report lost its registered read-only source",
    )
    names = {item["name"]: item["status"] for item in report["verification"]}
    require(
        names.get("业务状态与正常访问") == "not_run"
        and names.get("持续观察与未覆盖业务") == "uncovered",
        "A component check was presented as full incident recovery",
    )
    if report["scenario"] == "web_502":
        for check in UNAVAILABLE:
            values = [item for item in report["evidence"] if item["check_id"] == check]
            require(
                len(values) == 1
                and values[0]["status"] == "unavailable"
                and values[0]["exit_code"] is None,
                "Missing systemctl or Docker was replaced by invented evidence",
            )
        require(
            not any("inode" in item["text"] for item in report["facts"] + report["candidates"]),
            "The web investigation invented a shared inode root cause",
        )
    else:
        require(
            not any("上游" in item["text"] for item in report["facts"] + report["candidates"]),
            "The disk investigation invented a shared upstream root cause",
        )


def disk_state(report: dict, *, exhausted: bool) -> None:
    capacity = _df(evidence(report, "disk_bytes")["output"])
    inode = _df(evidence(report, "disk_inodes")["output"], inode=True)
    if capacity is None or inode is None:
        raise RuntimeError("The mixed fixture native df output was not parseable")
    require(
        capacity[2] * 1024 > 1024**3 and capacity[3] < 25,
        "The inode-only fixture acquired unrelated byte pressure",
    )
    candidates = [item for item in report["candidates"] if "inode 使用率偏高" in item["text"]]
    require(
        not any("根分区空间已达到" in item["text"] for item in report["candidates"]),
        "The inode-only report acquired a byte-capacity candidate",
    )
    if exhausted:
        require(
            inode[2] <= 1
            and len(candidates) == 1
            and candidates[0]["evidence_ids"] == ["E-DISK-INODES"]
            and report["status"] == "needs_attention",
            "The independent inode fault was lost",
        )
    else:
        require(
            inode[2] > 0 and inode[3] < 90 and not candidates,
            "The restored disk retained an unsupported inode fault",
        )


def run_lab(directory: Path, image: str) -> dict[str, bool]:
    create_app = app_factory(directory)
    with Fixture(directory, image, inode=True, web=True) as target:
        target.state("initialize")
        install_mixed(target)
        control(target, "start")
        public = HostPublic(
            id=PUBLIC_ID,
            name="Private mixed tmpfs fixture",
            address="127.0.0.1",
            source="ssh",
            username="opsark-lab",
            site_domain="shop.opsark.invalid",
            expected_upstream_port=18081,
            health_checks=[
                HealthCheck(
                    id=check,
                    domain=domain,
                    port=18080,
                    path="/healthz",
                    expected_body=marker,
                    read_only_confirmed=True,
                )
                for check, domain, marker in (
                    ("target", "shop.opsark.invalid", "OPSARK_MIXED_TARGET_OK"),
                    ("control", "blog.opsark.invalid", "OPSARK_MIXED_CONTROL_OK"),
                )
            ],
        )
        registered = HostConfig(public, directory / "pending", directory / "pending")
        commands = {scenario: commands_for(registered, scenario) for scenario in SCENARIOS}
        union = set().union(*(set(values.values()) for values in commands.values()))
        with DockerLabSSH(directory, union) as bridge:
            bridge.allowed = {
                "LC_ALL=C " + command: [
                    *target.base,
                    "exec",
                    "--env",
                    "LC_ALL=C",
                    str(target.identity),
                    "/usr/sbin/chroot",
                    "/fixture-root",
                    *shlex.split(command),
                ]
                for command in union
            }
            inventory = directory / "inventory.toml"
            lines = [
                "[credentials.fixture]",
                "key_file = " + json.dumps(str(bridge.key_file)),
                "known_hosts_file = " + json.dumps(str(bridge.known_hosts_file)),
                "[[hosts]]",
                f'id = "{PUBLIC_ID}"',
                'name = "Private mixed tmpfs fixture"',
                'address = "127.0.0.1"',
                f"port = {bridge.port}",
                'username = "opsark-lab"',
                'site_domain = "shop.opsark.invalid"',
                'credential = "fixture"',
                "expected_upstream_port = 18081",
            ]
            for check in public.health_checks:
                lines.extend(
                    [
                        "[[hosts.health_checks]]",
                        "id = " + json.dumps(check.id),
                        "domain = " + json.dumps(check.domain),
                        "port = 18080",
                        'path = "/healthz"',
                        "expected_status = 200",
                        "expected_body = " + json.dumps(check.expected_body),
                        "read_only_confirmed = true",
                    ]
                )
            inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
            settings = Settings(
                data_dir=directory / "reports",
                token=secrets.token_urlsafe(32),
                inventory_path=inventory,
            )
            auth = {"Authorization": "Bearer " + settings.token}
            with TestClient(create_app(settings)) as client:
                reports, baselines = [], {}
                scope = None

                def pair(*, upstream: bool, inodes: bool) -> None:
                    nonlocal scope
                    if not upstream:
                        target.call(
                            "exec",
                            str(target.identity),
                            "/usr/sbin/chroot",
                            "/fixture-root",
                            *shlex.split(commands["web_502"]["http_target"]),
                        )
                    for scenario in SCENARIOS:
                        before = len(bridge.executed)
                        response = client.post(
                            "/api/investigations",
                            headers=auth,
                            json={
                                "source": "ssh",
                                "scenario": scenario,
                                "host_id": PUBLIC_ID,
                            },
                        )
                        require(
                            response.status_code == 200, "The normal mixed investigation API failed"
                        )
                        report = response.json()
                        expected = [
                            "LC_ALL=C " + value
                            for name, value in commands[scenario].items()
                            if name not in UNAVAILABLE
                        ]
                        require(
                            bridge.executed[before:] == expected,
                            "The mixed SSH bridge executed an unexpected command",
                        )
                        report_boundaries(report)
                        health(report, "target", upstream)
                        health(report, "control", True)
                        if scope is None:
                            scope = report["scope_hash"]
                        require(
                            report["scope_hash"] == scope,
                            "The mixed target or SSH identity changed",
                        )
                        if scenario == "disk":
                            disk_state(report, exhausted=inodes)
                        elif not upstream:
                            raw = evidence(report, "nginx_errors")
                            require(
                                "Connection refused" in raw["output"]
                                and "18081" in raw["output"]
                                and any(
                                    "上游连接被拒绝" in item["text"]
                                    and item["evidence_ids"] == ["E-NGINX-ERRORS"]
                                    for item in report["facts"]
                                ),
                                "The upstream fault lost its independent native log evidence",
                            )
                        if scenario not in baselines:
                            result = client.post(
                                f"/api/reports/{report['id']}/baseline",
                                headers=auth,
                                json={"confirm_observation_only": True},
                            )
                            require(
                                result.status_code in (200, 201)
                                and result.json()["restore_capable"] is False,
                                "The mixed observation baseline could not be saved",
                            )
                            baselines[scenario] = report["id"]
                        else:
                            require(
                                report["comparison"]["baseline_report_id"] == baselines[scenario]
                                and report["comparison"]["status"] in {"compared", "incomplete"},
                                "The mixed report lost its own scenario's baseline",
                            )
                        reports.append(report)

                pair(upstream=True, inodes=False)
                control(target, "stop-upstream")
                control(target, "state")
                fault = target.state("inodes")
                require(
                    fault["enospc"] is True, "The mixed inode fault did not reach native ENOSPC"
                )
                pair(upstream=False, inodes=True)
                control(target, "start-upstream")
                pair(upstream=True, inodes=True)
                control(target, "stop-upstream")
                target.state("reset")
                control(target, "state")
                pair(upstream=False, inodes=False)
                control(target, "start-upstream")
                pair(upstream=True, inodes=False)
                require(len(reports) == 10, "Missing mixed phase reports")
                for report in reports:
                    old = client.get(f"/api/reports/{report['id']}", headers=auth)
                    require(
                        old.status_code == 200 and old.json() == report,
                        "A later recovery overwrote a historical mixed report",
                    )
                require(
                    len(client.get("/api/reports", headers=auth).json()) == 10,
                    "The mixed report history was not retained",
                )
        control(target, "stop")
    return {
        "mixed_fault_diagnosis_verified": True,
        "same_root_and_ssh_identity": True,
        "actual_upstream_and_inode_faults_coexisted": True,
        "upstream_only_recovery_left_inode_fault": True,
        "disk_only_recovery_left_target_502": True,
        "shared_control_passed_throughout": True,
        "missing_systemctl_and_docker_honest": True,
        "native_log_and_df_evidence_preserved": True,
        "two_scenario_baselines_and_ten_reports_retained": True,
        "no_shared_root_cause_or_global_recovery_claim": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        require(
            sys.platform == "linux" and Path("/var/run/docker.sock").is_socket(),
            "A disposable Linux runner's local Docker Engine is required",
        )
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "Use a pinned local mixed image")
        with tempfile.TemporaryDirectory(prefix="opsark-mixed-") as temporary:
            result = run_lab(Path(temporary), args.image)
        print(json.dumps(result, sort_keys=True))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("The isolated mixed fault experiment could not be verified.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
