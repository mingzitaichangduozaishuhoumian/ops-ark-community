"""Verify real application configuration failures through normal SSH investigations."""

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from docker_lab.ssh_server import DockerLabSSH
from docker_lab_smoke import (
    MEMORY_BYTES,
    assert_boundaries,
    docker,
    inspect,
    isolated_app_factory,
    selected_image,
    state_evidence,
    verify_harness_restrictions,
    wait_for,
)
from fastapi.testclient import TestClient

from opsark.collector import commands_for
from opsark.config import HostConfig, Settings
from opsark.models import HostPublic

LABEL = "opsark.test.docker-config-lab"
CONFIG_ENV = "OPSARK_LAB_CONFIG_JSON"
ACCEPTED = "OPSARK_LAB_CONFIGURATION_ACCEPTED"
REJECTED = "OPSARK_LAB_SCHEMA_ERROR field=listen_port expected=integer"
PHASES = ("valid", "invalid", "corrected")
APPLICATION = f"""import json,os,sys,time
try:
    raw=os.environ.get('{CONFIG_ENV}','')
    config=json.loads(raw) if 0 < len(raw) <= 128 else None
    valid=(type(config) is dict and set(config)=={{'listen_port'}}
           and type(config['listen_port']) is int and 1 <= config['listen_port'] <= 65535)
except (ValueError,TypeError):
    valid=False
if not valid:
    print('{REJECTED}',file=sys.stderr,flush=True)
    raise SystemExit(78)
print('{ACCEPTED}',flush=True)
time.sleep(180)
"""


def require(condition: object, stage: str) -> None:
    if not condition:
        raise RuntimeError(stage)


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def configuration_private(value: object) -> None:
    pending = [value]
    configurations = ('{"listen_port":8081}', '{"listen_port":"invalid"}')
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            require(
                CONFIG_ENV not in item and all(raw not in item for raw in configurations),
                "configuration_values_not_collected",
            )


def save_ledger(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(raw) <= 16_384, "private_ledger_budget")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def run_lab(directory: Path, ledger_path: Path) -> dict[str, object]:
    configuration = directory / "docker-config"
    configuration.mkdir(mode=0o700)
    previous_config = os.environ.get("DOCKER_CONFIG")
    os.environ["DOCKER_CONFIG"] = str(configuration)
    try:
        return _run_lab(directory, ledger_path)
    finally:
        if previous_config is None:
            os.environ.pop("DOCKER_CONFIG", None)
        else:
            os.environ["DOCKER_CONFIG"] = previous_config


def _run_lab(directory: Path, ledger_path: Path) -> dict[str, object]:
    create_app = isolated_app_factory(directory)
    nonce = secrets.token_hex(8)
    name = "opsark-config-lab-" + nonce
    image = selected_image()
    image_data = docker(
        "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
    ).split()
    require(
        len(image_data) == 2
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image_data[0])
        and image_data[1] in {"null", "{}"},
        "fixed_image_without_volumes",
    )
    image = image_data[0]
    ledger: dict = {
        "schema_version": 1,
        "container_name": name,
        "nonce": nonce,
        "image_id": image,
        "application_sha256": hashlib.sha256(APPLICATION.encode("ascii")).hexdigest(),
        "stages": [],
        "reports": [],
        "baseline_sha256": None,
        "all_owned_containers_removed": False,
    }
    created: list[dict] = []

    def owned(record: dict) -> dict:
        current = inspect(record["container_id"])
        limits = current["HostConfig"]
        require(
            current["Id"] == record["container_id"]
            and current["Name"] == "/" + name
            and current["Config"]["Labels"].get(LABEL) == nonce
            and current["Image"] == image
            and current["Mounts"] == []
            and limits["NetworkMode"] == "none"
            and limits["Privileged"] is False
            and limits["ReadonlyRootfs"] is True
            and limits["CapDrop"] == ["ALL"]
            and limits["CapAdd"] in (None, [])
            and limits["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges:true"])
            and limits["Memory"] == MEMORY_BYTES
            and limits["MemorySwap"] == MEMORY_BYTES
            and limits["NanoCpus"] == 250_000_000
            and limits["PidsLimit"] == 32
            and limits["RestartPolicy"]["Name"] == "no",
            "fixture_identity_or_limits",
        )
        return current

    def remove(record: dict) -> None:
        if not record["removed"]:
            owned(record)
            docker("rm", "--force", record["container_id"])
            record["removed"] = True

    def start(phase: str) -> dict:
        if created:
            remove(created[-1])
        value = {"listen_port": "invalid" if phase == "invalid" else 8081}
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
        identity = docker(
            "create",
            "--pull",
            "never",
            "--name",
            name,
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
            "--pids-limit",
            "32",
            "--cgroupns",
            "private",
            "--restart",
            "no",
            "--no-healthcheck",
            "--label",
            f"{LABEL}={nonce}",
            "--log-driver",
            "json-file",
            "--log-opt",
            "max-size=64k",
            "--log-opt",
            "max-file=1",
            "--env",
            CONFIG_ENV + "=" + raw,
            "--entrypoint",
            "python3",
            image,
            "-u",
            "-c",
            APPLICATION,
        )
        require(re.fullmatch(r"[0-9a-f]{64}", identity), "created_container_identity")
        record = {
            "phase": phase,
            "container_id": identity,
            "input_sha256": hashlib.sha256(raw.encode("ascii")).hexdigest(),
            "input_field_type": "string" if phase == "invalid" else "integer",
            "removed": False,
        }
        created.append(record)
        ledger["stages"].append(record)
        current = owned(record)
        supplied = [
            entry[len(CONFIG_ENV) + 1 :]
            for entry in current["Config"]["Env"]
            if entry.startswith(CONFIG_ENV + "=")
        ]
        require(supplied == [raw], "synthetic_input_binding")
        docker("start", identity)
        wait_for(identity, status="exited" if phase == "invalid" else "running", seconds=15)
        if phase != "invalid":
            deadline = time.monotonic() + 5
            while ACCEPTED not in docker("logs", "--tail", "1", identity):
                require(time.monotonic() < deadline, "application_readiness")
                time.sleep(0.1)
        current = owned(record)
        state = current["State"]
        require(
            state["Status"] == ("exited" if phase == "invalid" else "running")
            and state["ExitCode"] == (78 if phase == "invalid" else 0)
            and state["OOMKilled"] is False
            and current["RestartCount"] == 0,
            "native_application_outcome",
        )
        record.update(status=state["Status"], exit_code=state["ExitCode"], oom_killed=False)
        return record

    try:
        host = HostConfig(
            public=HostPublic(
                id="config-lab",
                name="Configuration fixture",
                address="127.0.0.1",
                username="opsark-lab",
                container_name=name,
                source="ssh",
            ),
            key_file=directory / "pending",
            known_hosts_file=directory / "pending",
        )
        commands = set(commands_for(host, "container_restart").values())
        with DockerLabSSH(directory, commands) as harness:
            verify_harness_restrictions(harness, directory)
            inventory = directory / "inventory.toml"
            inventory.write_text(
                "[credentials.lab]\nkey_file="
                + json.dumps(str(harness.key_file))
                + "\nknown_hosts_file="
                + json.dumps(str(harness.known_hosts_file))
                + "\n[[hosts]]\nid='config-lab'\nname='Configuration fixture'\naddress='127.0.0.1'"
                + f"\nport={harness.port}\nusername='opsark-lab'\ncredential='lab'"
                + "\nsite_domain='fixture.invalid'\ncontainer_name="
                + json.dumps(name)
                + "\n",
                encoding="utf-8",
            )
            settings = Settings(
                data_dir=directory / "reports",
                token=secrets.token_urlsafe(32),
                inventory_path=inventory,
            )
            headers = {"Authorization": "Bearer " + settings.token}
            reports: list[dict] = []
            baseline = None
            with TestClient(create_app(settings)) as client:
                for phase in PHASES:
                    record = start(phase)
                    response = client.post(
                        "/api/investigations",
                        headers=headers,
                        json={
                            "source": "ssh",
                            "scenario": "container_restart",
                            "host_id": "config-lab",
                        },
                    )
                    require(response.status_code == 200, "normal_investigation_api")
                    report = response.json()
                    owned(record)
                    assert_boundaries(report)
                    data = state_evidence(report)
                    require(
                        data["State"]["Status"] == record["status"]
                        and data["State"]["ExitCode"] == record["exit_code"]
                        and data["State"]["OOMKilled"] is False
                        and data["RestartCount"] == 0
                        and data["MemoryLimit"] == MEMORY_BYTES
                        and data["Image"] == image,
                        "ssh_preserved_native_state",
                    )
                    logs = [
                        item for item in report["evidence"] if item["check_id"] == "container_logs"
                    ]
                    require(
                        len(logs) == 1
                        and logs[0]["status"] == "ok"
                        and logs[0]["exit_code"] == 0
                        and not logs[0]["truncated"]
                        and (REJECTED if phase == "invalid" else ACCEPTED) in logs[0]["output"],
                        "actual_application_log_evidence",
                    )
                    require(
                        any("缺少已核实的配置变更" in gap for gap in report["missing"])
                        and not any(
                            "内存终止是有状态证据支持" in finding["text"]
                            for finding in report["candidates"]
                        ),
                        "unproven_configuration_cause_retained",
                    )
                    configuration_private(report)
                    if phase == "valid":
                        saved = client.post(
                            f"/api/reports/{report['id']}/baseline",
                            headers=headers,
                            json={"confirm_observation_only": True},
                        )
                        require(saved.status_code == 200, "save_original_baseline")
                        baseline = saved.json()
                        require(
                            baseline["features"]["container.status"] == "running"
                            and baseline["purpose"] == "observation_only"
                            and baseline["restore_capable"] is False,
                            "baseline_scope",
                        )
                        ledger["baseline_sha256"] = digest(baseline)
                    else:
                        require(baseline is not None, "original_baseline_missing")
                        comparison = report["comparison"]
                        require(
                            comparison["baseline_report_id"] == reports[0]["id"]
                            and report["scope_hash"] == reports[0]["scope_hash"],
                            "stable_origin",
                        )
                        changes = {item["field"]: item for item in comparison["changes"]}
                        if phase == "invalid":
                            require(
                                report["status"] == "needs_attention"
                                and changes.get("container.status")
                                == {
                                    "field": "container.status",
                                    "before": "running",
                                    "after": "exited",
                                    "evidence_ids": ["E-CONTAINER-STATE"],
                                },
                                "invalid_state_difference",
                            )
                            require(
                                any(
                                    "最近退出码为 78" in item["text"]
                                    and item["evidence_ids"] == ["E-CONTAINER-STATE"]
                                    for item in report["facts"]
                                ),
                                "application_exit_fact",
                            )
                        else:
                            require("container.status" not in changes, "corrected_state_difference")
                    reports.append(report)
                    ledger["reports"].append(
                        {
                            "phase": phase,
                            "report_id": report["id"],
                            "scope_hash": report["scope_hash"],
                            "sha256": digest(report),
                        }
                    )
                require(
                    len({row["container_id"] for row in created}) == 3,
                    "distinct_container_generations",
                )
                for original in reports:
                    saved = client.get(f"/api/reports/{original['id']}", headers=headers)
                    require(
                        saved.status_code == 200 and digest(saved.json()) == digest(original),
                        "original_reports_unchanged",
                    )
                require(baseline is not None, "original_baseline_missing")
                saved = client.post(
                    f"/api/reports/{reports[0]['id']}/baseline",
                    headers=headers,
                    json={"confirm_observation_only": True},
                )
                require(
                    saved.status_code == 200 and digest(saved.json()) == digest(baseline),
                    "original_baseline_unchanged",
                )
                listing = client.get("/api/reports", headers=headers)
                require(
                    listing.status_code == 200 and len(listing.json()) == 3, "three_reports_only"
                )
                listing = client.get("/api/baselines", headers=headers)
                require(
                    listing.status_code == 200 and len(listing.json()) == 1, "one_baseline_only"
                )
        ledger["acceptance_passed"] = True
    finally:
        cleanup_ok = True
        for record in reversed(created):
            try:
                remove(record)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                cleanup_ok = False
        try:
            require(
                not docker(
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    f"label={LABEL}={nonce}",
                    "--format",
                    "{{.ID}}",
                ),
                "fixture_containers_remain",
            )
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            cleanup_ok = False
        ledger["all_owned_containers_removed"] = cleanup_ok
        save_ledger(ledger_path, ledger)
        require(cleanup_ok, "strict_fixture_cleanup")
    return {
        "stage_count": 3,
        "distinct_container_ids": 3,
        "actual_application_schema_error_verified": True,
        "normal_ssh_diagnostics_verified": True,
        "original_baseline_preserved": True,
        "original_reports_preserved": True,
        "configuration_values_not_collected": True,
        "configuration_edit_causality_proven": False,
        "all_owned_containers_removed": True,
        "production_openssh_account_verified": False,
        "business_recovery_closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    try:
        require(
            sys.platform == "linux" and Path("/var/run/docker.sock").exists(),
            "local_docker_required",
        )
        require(
            os.environ.get("OPSARK_DISPOSABLE_DOCKER_LAB") == "1", "disposable_fixture_required"
        )
        os.umask(0o077)
        if args.evidence_dir is not None:
            path = args.evidence_dir
            require(
                path.is_absolute() and path.resolve() == path and not path.is_symlink(),
                "new_private_evidence_directory_required",
            )
            path.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="opsark-docker-config-") as temporary:
            directory = Path(temporary)
            evidence = args.evidence_dir or directory
            result = run_lab(directory, evidence / "config-fixture.private.json")
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print("The isolated application configuration lab could not complete.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
