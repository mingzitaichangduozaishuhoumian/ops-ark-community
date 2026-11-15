"""Exercise the bodyless log result through collection, storage and report exports."""

import json
import runpy
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest
from fastapi.testclient import TestClient

from opsark import collector, main
from opsark.ai import explanation_input
from opsark.config import HostConfig, Settings
from opsark.models import CheckResult, Collection, HostPublic
from opsark.nginx_error_window import CHECK, SCHEMA, log_window_command
from opsark.platforms import TOOLS

AUTH = {"Authorization": "Bearer synthetic-nginx-window-console-token"}
HOST = "nginx-fixture"
SITE = "fixture.invalid"
MARKER = "synthetic-unclassified-helper-output"
ROOT = Path(__file__).resolve().parents[1]


def host(tmp_path, *, enabled=True):
    return HostConfig(
        HostPublic(id=HOST, name=HOST, address="192.0.2.1", source="ssh", site_domain=SITE),
        tmp_path / "reference",
        tmp_path / "trust-reference",
        nginx_error_window_enabled=enabled,
    )


def test_registered_policy_switch_is_exact(tmp_path, monkeypatch):
    scope = host(tmp_path)
    command = log_window_command(SITE)
    assert collector.commands_for(scope, "web_502")[CHECK] == command
    assert "nginx_errors" not in collector.commands_for(scope, "web_502")
    assert CHECK not in collector.commands_for(scope, "container_restart")
    legacy = host(tmp_path, enabled=False)
    assert "nginx_errors" in collector.commands_for(legacy, "web_502")
    exporter = runpy.run_path(str(ROOT / "deploy/readonly/export_policy.py"))["export_policy"]
    monkeypatch.setitem(exporter.__globals__, "load_hosts", lambda _: {HOST: scope})
    policy_path = tmp_path / "policy.json"
    exporter(tmp_path / "inventory.toml", HOST, policy_path)
    commands = json.loads(policy_path.read_bytes())["commands"]
    assert commands["LC_ALL=C " + command] == command.split()
    assert not any("/var/log/nginx/error.log" in key for key in commands)


def test_install_rejects_mixed_legacy_policy_without_writing(monkeypatch, tmp_path):
    tool = runpy.run_path(str(ROOT / "deploy/readonly/install_nginx_error_window.py"))
    action = tool["install"]
    raw = b"synthetic helper"
    argv = log_window_command(SITE).split()
    legacy = tool["RAW_LOG"]
    commands = {"LC_ALL=C " + " ".join(argv): argv, "LC_ALL=C " + " ".join(legacy): legacy}
    writes = []

    def read(path, _limit):
        if path == tool["POLICY"]:
            return json.dumps({"schema_version": 1, "commands": commands}).encode()
        assert path == tmp_path / "nginx_error_window.py"
        return raw

    monkeypatch.setattr(tool["os"], "geteuid", lambda: 0, raising=False)
    monkeypatch.setitem(
        action.__globals__, "TARGET", PurePosixPath("/usr/local/libexec/opsark-nginx-error-window")
    )
    monkeypatch.setitem(
        action.__globals__, "installer", lambda _: (read, lambda *x: writes.append(x))
    )
    with pytest.raises(ValueError, match="still admits"):
        action(tmp_path, SITE, tool["digest"](raw))
    assert writes == []


@pytest.mark.parametrize(
    ("status", "reason", "counts", "message"),
    [
        ("observed", None, (0, 0), "匹配上游连接拒绝 0 条、超时 0 条"),
        ("observed", None, (1, 2), "匹配上游连接拒绝 1 条、超时 2 条"),
        ("permission_denied", None, (None, None), "权限不足"),
        ("source_missing", None, (None, None), "登记日志文件缺失"),
        ("inconclusive", "coverage_unconfirmed", (None, None), "日志窗口证据不足"),
        ("malformed", None, (None, None), "日志窗口证据不足"),
    ],
)
def test_report_keeps_only_the_closed_log_projection(
    tmp_path, monkeypatch, status, reason, counts, message
):
    scope = host(tmp_path)
    monkeypatch.setattr(main, "load_hosts", lambda _: {HOST: scope})

    def transport(_host, commands):
        assert CHECK in commands and "nginx_errors" not in commands
        at = datetime.now(UTC)
        row = {
            "schema": SCHEMA,
            "status": status,
            "reason": reason,
            "window_seconds": 900,
            "observed_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "matching_refused": counts[0],
            "matching_timeout": counts[1],
        }
        if status == "malformed":
            row.update(status="observed", matching_refused=1, matching_timeout=1, extra=MARKER)
        tools = "OPSARK_ARCH=x86_64\n" + "".join(f"OPSARK_TOOL_{name}=1\n" for name in TOOLS)
        return Collection(
            host_id=HOST,
            source="ssh",
            started_at=at,
            checks=[
                CheckResult(name="os_release", stdout="ID=ubuntu\nVERSION_ID=24.04\n"),
                CheckResult(name="platform_tools", stdout=tools),
                CheckResult(name="nginx_status", stdout="active\n"),
                CheckResult(name=CHECK, stdout=json.dumps(row) + "\n"),
            ],
        )

    monkeypatch.setattr(collector, "_collect", transport)
    settings = Settings(tmp_path, AUTH["Authorization"].removeprefix("Bearer "))
    with TestClient(main.create_app(settings)) as client:
        response = client.post(
            "/api/investigations",
            headers=AUTH,
            json={"source": "ssh", "host_id": HOST, "scenario": "web_502"},
        )
        assert response.status_code == 200 and MARKER not in response.text
        report = response.json()
        assert report["nginx_error_window"]["status"] == (
            "inconclusive" if status == "malformed" else status
        )
        assert report["nginx_error_window"]["matching_refused"] == counts[0]
        assert report["nginx_error_window"]["matching_timeout"] == counts[1]
        assert report["ai_egress_block_reason"] == (
            "unclassified_payload" if status == "malformed" else None
        )
        if counts[0]:
            assert report["status"] == "needs_attention" and len(report["facts"]) >= 2
        else:
            assert report["status"] == "inconclusive"
        path = f"/api/reports/{report['id']}"
        assert client.get(path, headers=AUTH).json() == report
        for ending in ("/export", "/handoff"):
            export = client.get(path + ending, headers=AUTH)
            assert (
                export.status_code == 200 and message in export.text and MARKER not in export.text
            )
        saved = client.app.state.store.get(report["id"])
        if status == "malformed":
            with pytest.raises(ValueError, match="Diagnosis source rejected"):
                explanation_input(saved)
        else:
            summary = json.dumps(explanation_input(saved), ensure_ascii=False)
            assert not any(value in summary for value in (MARKER, "matching_refused", SITE))
