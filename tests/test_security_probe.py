"""Administrator probe ownership and service isolation; never opens SSH or changes a host."""

import hashlib
import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("security_probe", ROOT / "deploy/security/probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def completed(code=0, output=""):
    return SimpleNamespace(returncode=code, stdout=output, stderr="not-for-export")


@pytest.fixture
def paths(tmp_path, monkeypatch):
    locations = {
        "SOURCE": tmp_path / "sshd",
        "BINARY": tmp_path / "libexec/opsark-sshd-lab",
        "CONFIG_DIR": tmp_path / "etc/opsark/security-probe",
        "CONFIG": tmp_path / "etc/opsark/security-probe/sshd_config",
        "UNIT": tmp_path / "systemd/opsark-security-probe.service",
        "MARKER": tmp_path / "etc/opsark/security-probe-owned.json",
    }
    for name, path in locations.items():
        monkeypatch.setattr(probe, name, path)
    for key in ("BINARY", "UNIT", "MARKER"):
        locations[key].parent.mkdir(parents=True, exist_ok=True)
    return locations


def planned():
    return {
        str(probe.BINARY): b"sshd-binary",
        str(probe.CONFIG): b"config",
        str(probe.UNIT): b"unit",
    }


def marker(state="complete"):
    return {
        "owner": probe.OWNER,
        "state": state,
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in planned().items()},
    }


def test_configuration_and_unit_expose_only_fixed_loopback_probe():
    assert "ListenAddress 127.0.0.1\n" in probe.CONFIG_TEXT
    assert "Port 23999\n" in probe.CONFIG_TEXT
    assert "AllowUsers opsark-readonly\n" in probe.CONFIG_TEXT
    assert "PermitRootLogin no\n" in probe.CONFIG_TEXT
    assert "AllowTcpForwarding no\n" in probe.CONFIG_TEXT
    assert "PasswordAuthentication no\n" in probe.CONFIG_TEXT
    assert "KbdInteractiveAuthentication no\n" in probe.CONFIG_TEXT
    assert "HostKey /etc/ssh/ssh_host_ed25519_key\n" in probe.CONFIG_TEXT
    assert "SyslogFacility LOCAL6\n" in probe.CONFIG_TEXT
    assert "ExecStart=/usr/local/libexec/opsark-sshd-lab -D -e -f " in probe.UNIT_TEXT
    assert "SyslogIdentifier=opsark-security-probe\n" in probe.UNIT_TEXT
    for limit in ("RuntimeMaxSec=900", "MemoryMax=128M", "TasksMax=32", "CPUQuota=20%"):
        assert limit in probe.UNIT_TEXT
    assert "[Install]" not in probe.UNIT_TEXT


def test_copy_payload_only_reads_system_binary_not_host_private_key(monkeypatch):
    reads = []

    def read(path, limit):
        reads.append(path)
        return b"binary"

    monkeypatch.setattr(probe, "read_trusted", read)
    result = probe.expected_payloads()
    assert reads == [probe.SOURCE]
    assert result[str(probe.BINARY)] == b"binary"
    assert set(result) == {str(probe.BINARY), str(probe.CONFIG), str(probe.UNIT)}


@pytest.mark.parametrize(
    "mode,uid", [(stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o777, 0), (stat.S_IFDIR | 0o755, 1000)]
)
def test_untrusted_directory_ancestry_is_rejected(mode, uid):
    fake = SimpleNamespace(parents=(), lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=uid))
    with pytest.raises(probe.ProbeError, match="untrusted_deployment_directory"):
        probe.trusted_directory(fake)


@pytest.mark.parametrize("foreign", ["BINARY", "CONFIG_DIR", "CONFIG", "UNIT"])
def test_unmarked_existing_objects_are_never_adopted(paths, foreign):
    path = paths[foreign]
    path.parent.mkdir(parents=True, exist_ok=True)
    if foreign == "CONFIG_DIR":
        path.mkdir()
    else:
        path.write_bytes(b"foreign")
    with pytest.raises(probe.ProbeError, match="refusing_unowned_probe_paths"):
        probe.verify_existing(planned(), None)


def test_missing_installation_cannot_start(paths):
    with pytest.raises(probe.ProbeError, match="probe_not_installed"):
        probe.verify_existing(planned(), None, require_complete=True)


def test_source_upgrade_or_changed_plan_requires_new_review(paths):
    previous = marker()
    changed = planned()
    changed[str(probe.BINARY)] = b"new-sshd-binary"
    with pytest.raises(probe.ProbeError, match="configuration_changed_review_required"):
        probe.verify_existing(changed, previous)


def test_complete_installation_cannot_silently_recreate_missing_file(paths, monkeypatch):
    monkeypatch.setattr(probe, "trusted_directory", lambda path: None)
    with pytest.raises(probe.ProbeError, match="owned_probe_file_missing"):
        probe.verify_existing(planned(), marker())


def test_interrupted_owned_install_can_resume_but_tamper_cannot(paths, monkeypatch):
    monkeypatch.setattr(probe, "trusted_directory", lambda path: None)
    paths["BINARY"].write_bytes(b"sshd-binary")
    monkeypatch.setattr(probe, "read_trusted", lambda path, limit: path.read_bytes())
    probe.verify_existing(planned(), marker("installing"))
    paths["BINARY"].write_bytes(b"tampered")
    with pytest.raises(probe.ProbeError, match="owned_probe_file_changed"):
        probe.verify_existing(planned(), marker("installing"))


def test_install_only_validates_and_daemon_reloads_without_start(paths, monkeypatch):
    writes, calls = [], []
    monkeypatch.setattr(probe, "trusted_directory", lambda path: None)
    monkeypatch.setattr(probe, "expected_payloads", planned)
    monkeypatch.setattr(probe, "marker_state", lambda: None)
    monkeypatch.setattr(probe.os, "chown", lambda *args: None, raising=False)

    def write(path, data, mode):
        writes.append((path, data, mode))
        path.write_bytes(data)

    monkeypatch.setattr(probe, "write_owned", write)
    monkeypatch.setattr(probe, "execute", lambda argv: calls.append(argv) or completed())
    result = probe.install()
    assert result["installed"] and result["started"] is False
    assert calls == [
        [str(probe.BINARY), "-t", "-f", str(probe.CONFIG)],
        ["/usr/bin/systemctl", "daemon-reload"],
    ]
    assert json.loads(writes[0][1])["state"] == "installing"
    assert json.loads(writes[-1][1])["state"] == "complete"
    assert all("enable" not in argv and "start" not in argv for argv in calls)
    assert all("ssh.service" not in argv and "nginx" not in argv for argv in calls)


def test_syntax_failure_never_starts_or_reloads_service(paths, monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "verify_installation", lambda: planned())
    monkeypatch.setattr(probe, "active_state", lambda: "inactive")
    monkeypatch.setattr(probe, "port_available", lambda: True)
    monkeypatch.setattr(probe, "execute", lambda argv: calls.append(argv) or completed(1))
    with pytest.raises(probe.ProbeError, match="probe_syntax_check_failed"):
        probe.start()
    assert calls == [[str(probe.BINARY), "-t", "-f", str(probe.CONFIG)]]


def test_occupied_loopback_port_does_not_replace_or_stop_its_owner(monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "verify_installation", lambda: planned())
    monkeypatch.setattr(probe, "active_state", lambda: "inactive")
    monkeypatch.setattr(probe, "port_available", lambda: False)
    monkeypatch.setattr(probe, "execute", lambda argv: calls.append(argv) or completed())
    with pytest.raises(probe.ProbeError, match="probe_loopback_port_occupied"):
        probe.start()
    assert not calls


def test_already_active_owned_probe_is_not_restarted(monkeypatch):
    monkeypatch.setattr(probe, "verify_installation", lambda: planned())
    monkeypatch.setattr(probe, "active_state", lambda: "active")
    monkeypatch.setattr(probe, "execute", lambda argv: pytest.fail("must not restart active unit"))
    assert probe.start()["already_active"] is True


def test_successful_start_targets_only_probe_service(monkeypatch):
    calls, states = [], iter(("inactive", "active"))
    monkeypatch.setattr(probe, "verify_installation", lambda: planned())
    monkeypatch.setattr(probe, "active_state", lambda: next(states))
    monkeypatch.setattr(probe, "port_available", lambda: True)
    monkeypatch.setattr(probe, "execute", lambda argv: calls.append(argv) or completed())
    assert probe.start()["active_state"] == "active"
    assert calls[-1] == ["/usr/bin/systemctl", "start", "opsark-security-probe.service"]


def test_stop_never_clears_journal_or_changes_main_services(monkeypatch):
    calls = []
    monkeypatch.setattr(probe, "verify_installation", lambda: planned())
    monkeypatch.setattr(probe, "active_state", lambda: "inactive")
    monkeypatch.setattr(probe, "execute", lambda argv: calls.append(argv) or completed())
    result = probe.stop()
    assert result["journal_not_cleared"]
    assert calls == [["/usr/bin/systemctl", "stop", "opsark-security-probe.service"]]


def test_status_exports_only_metadata_not_raw_authentication_text(monkeypatch):
    row = {
        "__REALTIME_TIMESTAMP": "123",
        "_COMM": "opsark-sshd-lab",
        "_EXE": "/usr/local/libexec/opsark-sshd-lab",
        "_SYSTEMD_UNIT": probe.SERVICE,
        "SYSLOG_IDENTIFIER": "opsark-security-probe",
        "MESSAGE": "private-message-marker",
    }
    monkeypatch.setattr(probe, "verify_installation", planned)
    monkeypatch.setattr(probe, "active_state", lambda: "active")
    monkeypatch.setattr(probe, "read_trusted", lambda *args: b"sshd-binary")
    calls = []
    monkeypatch.setattr(
        probe, "execute", lambda argv: calls.append(argv) or completed(output=json.dumps(row))
    )
    result = probe.status()
    assert "private-message-marker" not in json.dumps(result)
    assert result["binary_sha256"] == result["system_sshd_sha256"]
    assert result["protection_rules_checked"] is False
    assert "--lines=3" in calls[0]
    assert result["journal_metadata"][0]["_COMM"] == "opsark-sshd-lab"


def test_non_root_cannot_execute_probe_actions(monkeypatch, capsys):
    monkeypatch.setattr(probe.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(sys, "argv", ["probe.py", "start"])
    monkeypatch.setattr(probe, "start", lambda: pytest.fail("non-root must not execute"))
    assert probe.main() == 1
    assert json.loads(capsys.readouterr().out)["error"] == "administrator_root_required"


def test_unknown_action_or_extra_arguments_never_executes(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["probe.py", "start", "ssh.service"])
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2
