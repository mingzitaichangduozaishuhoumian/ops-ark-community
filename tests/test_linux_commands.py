"""On the Linux runner, verify real GNU command output matches the parsers."""

import os
import platform
import shlex
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from opsark.collector import commands_for
from opsark.config import HostConfig
from opsark.diagnostics import diagnose
from opsark.models import CheckResult, Collection, HostPublic


@pytest.mark.skipif(sys.platform != "linux", reason="Requires the Ubuntu/Debian Linux command set")
def test_real_linux_capacity_and_inode_outputs_are_interpretable():
    if platform.freedesktop_os_release().get("ID") not in {"ubuntu", "debian"}:
        pytest.skip("Only the initial Ubuntu/Debian targets are supported")
    host = HostPublic(id="linux-tool-test", name="Linux command output", address="192.0.2.10")
    config = HostConfig(public=host, key_file=Path("unused"), known_hosts_file=Path("unused"))
    results = []
    for name, command in commands_for(config, "disk").items():
        if name == "disk_directories":
            results.append(CheckResult(name=name, status="unavailable", exit_code=None))
            continue
        process = subprocess.run(  # noqa: S603 -- only fixed, read-only command argv is used.
            shlex.split(command),
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
            timeout=8,
        )
        assert process.returncode == 0
        results.append(CheckResult(name=name, stdout=process.stdout, stderr=process.stderr))
    report = diagnose(
        "disk",
        host,
        Collection(
            host_id=host.id,
            source="replay",
            started_at=datetime.now(UTC),
            checks=results,
        ),
    )
    text = "\n".join(finding.text for finding in report.facts)
    assert "根分区容量快照" in text
    assert "根分区 inode" in text
    assert report.action.executable is False


@pytest.mark.skipif(sys.platform != "linux", reason="Requires a local Linux Docker Engine")
def test_actual_docker_cli_prefix_ignores_remote_context_and_tls_environment():
    if shutil.which("docker") is None or not Path("/var/run/docker.sock").exists():
        pytest.skip("The optional local Docker Engine is not available")
    host = HostPublic(id="docker-prefix-test", name="Docker prefix test", address="192.0.2.10")
    config = HostConfig(public=host, key_file=Path("unused"), known_hosts_file=Path("unused"))
    command = commands_for(config, "container_restart")["container_state"]
    argv = shlex.split(command)
    argv = argv[: argv.index("inspect")] + ["version", "--format", "{{.Server.Version}}"]
    environment = {
        **os.environ,
        "DOCKER_HOST": "tcp://192.0.2.1:2376",
        "DOCKER_CONTEXT": "nonexistent-opsark-test-context",
        "DOCKER_TLS": "1",
        "DOCKER_TLS_VERIFY": "1",
        "DOCKER_CERT_PATH": "/nonexistent-opsark-test-certs",
    }
    result = subprocess.run(  # noqa: S603 -- generated fixed prefix, read-only version command.
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=8,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()
