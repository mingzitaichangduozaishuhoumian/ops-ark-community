import copy
import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest

from opsark.config import HostConfig
from opsark.models import CheckResult, HostPublic
from opsark.web_security_events import (
    SECURITY_WEB_COMMAND,
    collect_web_security,
    parse_observation,
    scope_for_web,
)

ROOT = Path(__file__).resolve().parents[1]


def asset(name):
    spec = importlib.util.spec_from_file_location(
        "web_" + name, ROOT / "deploy/web" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader, installer, probe = asset("read_journal"), asset("install"), asset("probe")
END = 1_793_160_000_000_000
START = END - reader.WINDOW_US
NOW = datetime.fromtimestamp(END // 1_000_000, UTC)
PROFILE_VALUE = {
    "schema_version": 1,
    "sites": [
        {
            "id": "lab",
            "domain": "opsark-lab.invalid",
            "origin": "controlled_web_probe",
            "trusted_proxies": [],
            "forwarded_header": "x-forwarded-for",
            "expected_error_statuses": [],
        }
    ],
}
DIGEST = hashlib.sha256(json.dumps(PROFILE_VALUE).encode()).hexdigest()


def target(tmp_path=None):
    public = HostPublic(id="lab", name="Lab", address="192.0.2.10", source="ssh").model_copy(
        update={"web_profile_digest": DIGEST}
    )
    known = Path("unused")
    if tmp_path:
        known = tmp_path / "known"
        known.write_bytes(b"trusted-reference")
        public.trusted_hosts_digest = hashlib.sha256(known.read_bytes()).hexdigest()
    return HostConfig(public=public, key_file=Path("unused-key"), known_hosts_file=known)


def record(**changes):
    message = {
        "schema_version": 1,
        "site_id": "lab",
        "msec": f"{END // 1_000_000 - 1}.000",
        "peer_ip": "127.0.0.1",
        "xff": "",
        "xff_present": "0",
        "cf_ip": "",
        "cf_present": "0",
        "method": "GET",
        "status": 404,
        "path_class": "secret_probe",
        "client_class": "other",
        "request_time": "0.003",
        "bytes_sent": 10,
        "request_id": "b" * 32,
    }
    message.update(changes)
    return {
        "__CURSOR": "s=test;i=1",
        "__REALTIME_TIMESTAMP": str(END - 1_000_000),
        "_BOOT_ID": "a" * 32,
        "_SYSTEMD_UNIT": "nginx.service",
        "_EXE": "/usr/sbin/nginx",
        "_COMM": "nginx",
        "SYSLOG_IDENTIFIER": "opsark_web",
        "MESSAGE": json.dumps(message),
    }


def payload(rows=None, profile=None):
    raw = b"\n".join(json.dumps(row).encode() for row in (rows or []))
    return reader.build_payload(
        raw, START, END, reader.validate_profile(profile or PROFILE_VALUE), DIGEST
    )


def parsed(value, **changes):
    return parse_observation(
        target(), CheckResult(name="web", stdout=json.dumps(value), **changes), collected_at=NOW
    )


def test_complete_projection_is_stable_and_contains_no_raw_request_material():
    value = payload([record()])
    first, second = parsed(value), parsed(value)
    assert first.status == "complete"
    assert first.events == second.events and first.events[0].id == second.events[0].id
    assert first.id != second.id
    assert first.scope_hash == scope_for_web(target().public)
    event = first.events[0]
    assert event.origin == "controlled_web_probe" and event.request_time_ms == 3
    assert event.source_ip == event.peer_ip == "127.0.0.1"
    for forbidden in ("MESSAGE", "Cookie", "Authorization", "User-Agent", "request_uri"):
        assert forbidden not in first.model_dump_json()


@pytest.mark.parametrize(
    "field,value",
    [
        ("_COMM", "logger"),
        ("_EXE", "/usr/bin/logger"),
        ("_SYSTEMD_UNIT", "user@1000.service"),
        ("SYSLOG_IDENTIFIER", "nginx"),
    ],
)
def test_a_forged_syslog_tag_cannot_supply_trusted_web_events(field, value):
    row = record()
    row[field] = value
    observation = parsed(payload([row]))
    assert observation.status == "degraded" and not observation.events
    assert observation.gaps == ["untrusted_web_metadata"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("uri", "/login?token=private-marker"),
        ("cookie", "secret-cookie"),
        ("user_agent", "private-agent"),
        ("authorization", "Bearer private-token"),
    ],
)
def test_extra_sensitive_fields_are_rejected_without_being_exported(field, value):
    row = record(**{field: value})
    observation = parsed(payload([row]))
    assert observation.status == "degraded" and not observation.events
    assert "private-" not in observation.model_dump_json()
    assert "secret-cookie" not in observation.model_dump_json()


def test_direct_forwarded_headers_are_ignored_for_attribution():
    observation = parsed(
        payload([record(xff="198.51.100.5", xff_present="1", cf_ip="203.0.113.8", cf_present="1")])
    )
    event = observation.events[0]
    assert event.source_ip == event.peer_ip == "127.0.0.1"
    assert event.source_trust == "forwarded_ignored"
    assert "198.51.100.5" not in observation.model_dump_json()


def test_explicit_trusted_proxy_can_supply_canonical_single_source():
    profile = copy.deepcopy(PROFILE_VALUE)
    profile["sites"][0]["trusted_proxies"] = ["127.0.0.1/32"]
    observation = parsed(payload([record(xff="198.51.100.5", xff_present="1")], profile))
    assert observation.events[0].source_trust == "trusted_proxy"
    assert observation.events[0].source_ip == "198.51.100.5"


@pytest.mark.parametrize(
    "candidate,present", [("", "0"), ("bad-value", "1"), ("198.51.100.1,203.0.113.1", "1")]
)
def test_unresolved_proxy_never_blames_the_proxy_as_a_client(candidate, present):
    profile = copy.deepcopy(PROFILE_VALUE)
    profile["sites"][0]["trusted_proxies"] = ["127.0.0.1/32"]
    observation = parsed(payload([record(xff=candidate, xff_present=present)], profile))
    assert observation.events[0].source_trust == "unresolved_proxy"
    assert observation.events[0].source_ip is None
    assert observation.status == "degraded"


def test_expected_maintenance_error_is_derived_from_profile_not_the_message():
    profile = copy.deepcopy(PROFILE_VALUE)
    profile["sites"][0]["expected_error_statuses"] = [503]
    assert parsed(payload([record(status=503)], profile)).events[0].expected_error is True
    assert parsed(payload([record(status=503)])).events[0].expected_error is False
    assert not parsed(payload([record(status=503, expected_error=True)], profile)).events


@pytest.mark.parametrize(
    "changes",
    [
        {"trusted_proxies": ["0.0.0.0/0"]},
        {"trusted_proxies": ["::/0"]},
        {"trusted_proxies": ["127.0.0.2/24"]},
        {"domain": "bad;domain"},
        {"origin": "actual_hacker"},
        {"forwarded_header": "authorization"},
        {"expected_error_statuses": [True]},
    ],
)
def test_unsafe_root_profile_is_refused(changes):
    profile = copy.deepcopy(PROFILE_VALUE)
    profile["sites"][0].update(changes)
    with pytest.raises(ValueError):
        reader.validate_profile(profile)


def test_duplicate_and_conflicting_cursors_do_not_count_twice():
    row = record()
    identical = parsed(payload([row, row]))
    assert len(identical.events) == 1 and identical.status == "degraded"
    changed = record(status=500)
    conflicting = parsed(payload([row, changed]))
    assert conflicting.status == "degraded" and not conflicting.events


def test_profile_digest_changes_stop_the_controller_before_counting():
    value = payload([record()])
    value["profile_digest"] = "e" * 64
    observation = parsed(value)
    assert observation.status == "unavailable" and not observation.events
    assert observation.gaps == ["web_profile_changed"]


@pytest.mark.parametrize(
    "change",
    [{"status": "error", "exit_code": 1}, {"truncated": True}, {"stderr": "private-path-marker"}],
)
def test_incomplete_transport_never_exposes_partial_evidence_as_complete(change):
    observation = parsed(payload([record()]), **change)
    assert observation.status == "unavailable" and not observation.events
    assert "private-path-marker" not in observation.model_dump_json()


def test_bounded_output_drops_oldest_with_explicit_gap():
    rows = []
    for index in range(100):
        row = record()
        row["__CURSOR"] = f"s=test;i={index}"
        rows.append(row)
    value = payload(rows)
    assert len(reader.encode(value)) + 1 <= reader.MAX_OUTPUT_BYTES
    assert value["status"] == "degraded"
    assert "projection_event_limit" in value["gaps"]
    assert len(value["events"]) <= 80


@pytest.mark.parametrize(
    "change",
    [{"__REALTIME_TIMESTAMP": str(START - 1)}, {"__CURSOR": "$(evil)"}, {"_BOOT_ID": "invalid"}],
)
def test_malformed_time_and_identity_are_not_events(change):
    row = record()
    row.update(change)
    observation = parsed(payload([row]))
    assert observation.status == "degraded" and not observation.events


def test_declared_crawler_keeps_suspicious_class_and_does_not_gain_trust():
    event = parsed(
        payload([record(client_class="declared_crawler", path_class="repo_probe")])
    ).events[0]
    assert event.client_class == "declared_crawler" and event.path_class == "repo_probe"
    assert event.origin == "controlled_web_probe" and event.source_trust == "direct_peer"


def test_log_format_only_exports_reduced_fields():
    text = (ROOT / "deploy/web/nginx-format.conf").read_text()
    logged = text.split("log_format opsark_web_json escape=json", 1)[1]
    for forbidden in (
        "$request_uri",
        "$uri",
        "$args",
        "$http_user_agent",
        "$http_cookie",
        "$http_authorization",
        "$request_body",
        "$http_referer",
        "$http_host",
    ):
        assert forbidden not in logged
    assert "$realip_remote_addr" in logged and "$request_id" in logged
    assert 'default ""' in text


def test_installer_cas_and_foreign_vhost_are_refused_before_mutation(monkeypatch):
    original = (ROOT / "deploy/vps_lab/fixture.py").read_text()
    assert "access_log off;" in original
    monkeypatch.setattr(installer, "trusted", lambda path: b"unrelated server")
    with pytest.raises(installer.InstallError, match="compare_and_swap"):
        installer.install("a" * 64)
    with pytest.raises(installer.InstallError, match="unowned_vhost"):
        installer.modified_vhost(b"server {}", False)


def test_probe_targets_and_budget_cannot_be_overridden():
    assert probe.HOST == "127.0.0.1" and probe.PORT == 18880
    assert all(0 < len(requests) <= 30 for requests in probe.CASES.values())
    with pytest.raises(ValueError):
        probe.run("https://third-party.invalid")


def install_fixture(tmp_path, monkeypatch):
    directory = tmp_path / "lab"
    directory.mkdir()
    backup = tmp_path / "backups"
    backup.mkdir()
    for name in ("VHOST", "FORMAT", "PROFILE", "READER", "MARKER"):
        monkeypatch.setattr(installer, name, directory / name)
    original = (
        installer.VHOST_MARKER + b"server {\n    listen 127.0.0.1:18880;\n"
        b"    server_name opsark-lab.invalid;\n    access_log off;\n}\n"
    )
    installer.VHOST.write_bytes(original)
    monkeypatch.setattr(installer, "trusted", lambda path: path.read_bytes())
    monkeypatch.setattr(installer, "load_marker", lambda: None)
    monkeypatch.setattr(
        installer, "Path", lambda value: backup if value == "/root" else Path(value)
    )

    def write(path, value, mode):
        path.write_bytes(value)

    monkeypatch.setattr(installer, "write", write)
    return original


def test_invalid_nginx_configuration_is_restored_without_reload(tmp_path, monkeypatch):
    original = install_fixture(tmp_path, monkeypatch)
    calls = []

    def command(argv):
        calls.append(argv)
        if argv[-1] == "-V":
            return SimpleNamespace(returncode=0, stderr="--with-http_realip_module")
        if argv[-1] == "-t" and installer.FORMAT.exists():
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer, "call", command)
    with pytest.raises(installer.InstallError, match="syntax_failed"):
        installer.install(installer.sha(original))
    assert installer.VHOST.read_bytes() == original
    assert not installer.FORMAT.exists() and not installer.PROFILE.exists()
    assert not any(argv[-1] == "reload" for argv in calls)


def test_external_edit_during_prepare_is_not_overwritten_by_rollback(tmp_path, monkeypatch):
    original = install_fixture(tmp_path, monkeypatch)
    external = original + b"# external change\n"
    ordinary = installer.write

    def write(path, value, mode):
        ordinary(path, value, mode)
        if path == installer.FORMAT:
            installer.VHOST.write_bytes(external)

    monkeypatch.setattr(installer, "write", write)
    monkeypatch.setattr(
        installer,
        "call",
        lambda argv: SimpleNamespace(returncode=0, stderr="--with-http_realip_module"),
    )
    with pytest.raises(installer.InstallError, match="changed_during_prepare"):
        installer.install(installer.sha(original))
    assert installer.VHOST.read_bytes() == external
    assert not installer.FORMAT.exists()


def test_successful_install_records_profile_digest_and_tests_before_reload(tmp_path, monkeypatch):
    original = install_fixture(tmp_path, monkeypatch)
    calls = []

    def command(argv):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr="--with-http_realip_module")

    monkeypatch.setattr(installer, "call", command)
    result = installer.install(installer.sha(original))
    assert result["profile_digest"] == installer.sha(installer.PROFILE.read_bytes())
    assert installer.ACCESS in installer.VHOST.read_bytes()
    assert installer.SITE in installer.VHOST.read_bytes()
    assert calls.index(["/usr/sbin/nginx", "-t"]) < calls.index(["/usr/sbin/nginx", "-s", "reload"])
    assert result["only_lab_vhost_changed"] is True
    assert json.loads(installer.MARKER.read_text())["owner"] == installer.OWNER


def test_owned_legacy_logger_migrates_exactly_to_local_syslog_nohostname():
    current = (
        installer.VHOST_MARKER + b"server {\n    listen 127.0.0.1:18880;\n"
        b"    server_name opsark-lab.invalid;\n" + installer.SITE + installer.LEGACY_ACCESS + b"}\n"
    )
    digest = installer.sha(current)
    updated = installer.modified_vhost(current, True, owned_vhost_digest=digest)
    assert updated == current.replace(installer.LEGACY_ACCESS, installer.ACCESS)
    assert b",nohostname," in updated
    assert (
        installer.modified_vhost(updated, True, owned_vhost_digest=installer.sha(updated))
        == updated
    )


@pytest.mark.parametrize("marker_digest", [None, "0" * 64])
def test_legacy_logger_upgrade_requires_matching_owned_vhost_digest(marker_digest):
    current = (
        installer.VHOST_MARKER + b"server {\n    listen 127.0.0.1:18880;\n"
        b"    server_name opsark-lab.invalid;\n" + installer.SITE + installer.LEGACY_ACCESS + b"}\n"
    )
    with pytest.raises(installer.InstallError, match="owned_vhost_changed"):
        installer.modified_vhost(current, True, owned_vhost_digest=marker_digest)
    with pytest.raises(installer.InstallError, match="access_log_changed"):
        installer.modified_vhost(current, False)


def test_unknown_owned_logger_is_not_rewritten_even_with_a_matching_digest():
    current = (
        installer.VHOST_MARKER + b"server {\n    listen 127.0.0.1:18880;\n"
        b"    server_name opsark-lab.invalid;\n"
        + installer.SITE
        + installer.LEGACY_ACCESS.replace(b"facility=local5", b"facility=local6")
        + b"}\n"
    )
    with pytest.raises(installer.InstallError, match="access_log_changed"):
        installer.modified_vhost(current, True, owned_vhost_digest=installer.sha(current))


@pytest.mark.parametrize("matching_marker", [True, False])
def test_install_migrates_only_the_marker_owned_legacy_access_line(
    tmp_path, monkeypatch, matching_marker
):
    load_marker = installer.load_marker
    original = install_fixture(tmp_path, monkeypatch)
    legacy = original.replace(b"    access_log off;\n", installer.SITE + installer.LEGACY_ACCESS)
    installer.VHOST.write_bytes(legacy)
    installer.FORMAT.write_bytes((ROOT / "deploy/web/nginx-format.conf").read_bytes())
    installer.READER.write_bytes((ROOT / "deploy/web/read_journal.py").read_bytes())
    installer.PROFILE.write_bytes(
        (
            json.dumps(installer.DEFAULT_PROFILE, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
    )
    digest = installer.sha(installer.PROFILE.read_bytes())
    marker = {
        "owner": installer.OWNER,
        "sha256": {
            str(path): installer.sha(path.read_bytes())
            for path in (installer.FORMAT, installer.PROFILE, installer.READER, installer.VHOST)
        },
        "profile_digest": digest,
        "backup": "/root/opsark-web-backup-fixture",
    }
    if not matching_marker:
        marker["sha256"][str(installer.VHOST)] = "0" * 64
    installer.MARKER.write_text(json.dumps(marker))
    monkeypatch.setattr(installer, "load_marker", load_marker)
    calls = []

    def command(argv):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr="--with-http_realip_module")

    monkeypatch.setattr(installer, "call", command)
    if not matching_marker:
        with pytest.raises(installer.InstallError, match="owned_vhost_changed"):
            installer.install(installer.sha(legacy))
        assert installer.VHOST.read_bytes() == legacy
        assert not any(argv[-1] == "reload" for argv in calls)
    else:
        result = installer.install(installer.sha(legacy))
        assert installer.VHOST.read_bytes() == legacy.replace(
            installer.LEGACY_ACCESS, installer.ACCESS
        )
        assert result["profile_digest"] == digest
        assert json.loads(installer.MARKER.read_text())["sha256"][
            str(installer.VHOST)
        ] == installer.sha(installer.VHOST.read_bytes())


def test_changed_trust_file_prevents_connecting(tmp_path, monkeypatch):
    host = target(tmp_path)
    host.known_hosts_file.write_bytes(b"changed")

    class Client:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            raise AssertionError("No connection allowed")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    assert collect_web_security(host).status == "unavailable"


def test_single_fixed_collection_command_and_safe_ssh_settings(tmp_path, monkeypatch):
    host = target(tmp_path)
    calls = {}

    class Client:
        def set_missing_host_key_policy(self, policy):
            assert isinstance(policy, paramiko.RejectPolicy)

        def load_host_keys(self, path):
            pass

        def connect(self, **kwargs):
            calls.update(kwargs)

        def close(self):
            calls["closed"] = True

    def run(client, name, command, budget):
        calls["command"] = command
        return CheckResult(name=name, stdout="not JSON")

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    monkeypatch.setattr("opsark.web_security_events.run_check", run)
    observation = collect_web_security(host)
    assert calls["command"] == SECURITY_WEB_COMMAND
    assert (
        calls["username"] == "opsark-readonly"
        and not calls["look_for_keys"]
        and not calls["allow_agent"]
    )
    assert calls["closed"] and observation.status == "unavailable"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux selector and process budgets")
def test_reader_real_process_output_and_wall_budgets(monkeypatch):
    monkeypatch.setattr(
        reader,
        "journal_command",
        lambda *args: [
            sys.executable,
            "-I",
            "-c",
            "import sys;sys.stdout.buffer.write(b'x'*300000)",
        ],
    )
    raw, gaps, _ = reader.read_bounded(START, END)
    assert len(raw) <= reader.MAX_RAW_BYTES and "journal_output_limit" in gaps
    monkeypatch.setattr(reader, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(
        reader,
        "journal_command",
        lambda *args: [sys.executable, "-I", "-c", "import time;time.sleep(2)"],
    )
    _, gaps, _ = reader.read_bounded(START, END)
    assert "journal_timeout" in gaps
