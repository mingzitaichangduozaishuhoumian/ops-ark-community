"""Security projections must remain bounded, time-bound and resistant to log spoofing."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import textwrap
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import paramiko
import pytest

from opsark.baselines import scope_for
from opsark.config import HostConfig
from opsark.models import CheckResult, HostPublic
from opsark.security_events import SECURITY_COMMAND, collect_security, event_id, parse_observation

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "security_reader", ROOT / "deploy/security/read_journal.py"
)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
END = int(NOW.timestamp()) * 1_000_000
START = END - reader.WINDOW_US


def host(tmp_path=None):
    known = Path("unused-known-hosts") if tmp_path is None else tmp_path / "known"
    if tmp_path is not None:
        known.write_bytes(b"trusted-profile")
    return HostConfig(
        public=HostPublic(
            id="registered",
            name="Registered",
            address="192.0.2.10",
            source="ssh",
            trusted_hosts_digest=hashlib.sha256(b"trusted-profile").hexdigest(),
        ),
        key_file=Path("unused-independent-key"),
        known_hosts_file=known,
    )


def record(**changes):
    return {
        "__CURSOR": "s=fixture;i=1;b=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "__REALTIME_TIMESTAMP": str(END - 1_000_000),
        "_BOOT_ID": "a" * 32,
        "_SYSTEMD_UNIT": "ssh.service",
        "SYSLOG_IDENTIFIER": "sshd",
        "_COMM": "sshd",
        "_EXE": "/usr/sbin/sshd",
        "MESSAGE": "Failed publickey for invalid user fixture from 192.0.2.50 port 34567 ssh2",
        **changes,
    }


def payload(records=None, **kwargs):
    raw = b"\n".join(json.dumps(item).encode() for item in (records or []))
    return reader.build_payload(raw, START, END, **kwargs)


def parse(value):
    return parse_observation(
        host(),
        CheckResult(name="security_events", stdout=reader.encode(value).decode()),
        collected_at=NOW,
    )


def test_actual_auth_record_is_reduced_without_account_or_raw_log():
    raw = record(
        MESSAGE=(
            "Accepted publickey for alice@example.com from 2001:db8::1 port 1234 ssh2: "
            "ED25519 SHA256:private-fingerprint-marker"
        )
    )
    wire = payload([raw])
    event = parse(wire).events[0]
    assert event.origin == "system_ssh"
    assert event.kind == "authentication_accepted"
    assert event.account_type == "other"
    assert event.source_ip == "2001:db8::1"
    assert event.unit == "ssh.service"
    assert event.occurred_at.tzinfo == UTC
    assert "alice" not in json.dumps(wire)
    assert "private-fingerprint-marker" not in json.dumps(wire)
    assert "MESSAGE" not in json.dumps(wire)


def test_overlap_and_controller_restart_keep_stable_evidence_id():
    wire = payload([record()])
    first, second = parse(wire), parse(wire)
    assert first.id != second.id
    assert first.events[0].id == second.events[0].id
    assert first.events[0].id == event_id(scope_for(host().public), record()["__CURSOR"])


def test_target_or_trust_scope_changes_event_identity():
    wire = payload([record()])
    original = parse(wire).events[0]
    target = host()
    target.public.trusted_hosts_digest = "b" * 64
    changed = parse_observation(
        target, CheckResult(name="security_events", stdout=json.dumps(wire)), collected_at=NOW
    )
    assert changed.events[0].id != original.id


def test_controlled_probe_unit_cannot_be_presented_as_system_attack():
    wire = payload(
        [
            record(
                _SYSTEMD_UNIT="opsark-security-probe.service",
                SYSLOG_IDENTIFIER="opsark-security-probe",
                _EXE="/usr/local/libexec/opsark-sshd-lab",
                _COMM="opsark-sshd-lab",
            )
        ]
    )
    event = parse(wire).events[0]
    assert event.origin == "controlled_probe"
    assert event.unit == "opsark-security-probe.service"
    wire["events"][0]["origin"] = "system_ssh"
    refused = parse(wire)
    assert refused.status == "unavailable" and not refused.events


@pytest.mark.parametrize(
    "changes",
    [
        {"_EXE": "/usr/sbin/sshd", "_COMM": "sshd"},
        {"_EXE": "/usr/local/libexec/opsark-sshd-lab", "_COMM": "sshd"},
        {"_EXE": "/usr/bin/logger", "_COMM": "opsark-sshd-lab"},
    ],
)
def test_probe_metadata_never_falls_back_to_real_sshd_or_logger(changes):
    result = parse(
        payload(
            [
                record(
                    _SYSTEMD_UNIT="opsark-security-probe.service",
                    SYSLOG_IDENTIFIER="opsark-security-probe",
                    **changes,
                )
            ]
        )
    )
    assert not result.events and result.status == "degraded"
    assert result.gaps == ["untrusted_auth_metadata"]


def test_lab_binary_cannot_produce_system_ssh_evidence():
    result = parse(
        payload([record(_EXE="/usr/local/libexec/opsark-sshd-lab", _COMM="opsark-sshd-lab")])
    )
    assert not result.events and result.status == "degraded"


@pytest.mark.parametrize(
    "changes",
    [
        {"_SYSTEMD_UNIT": "session-123.scope"},
        {"_EXE": "/usr/bin/logger"},
        {"_COMM": "logger"},
        {"_SYSTEMD_UNIT": ["ssh.service"]},
        {"_EXE": ["/usr/sbin/sshd"]},
        {"SYSLOG_IDENTIFIER": ["sshd"]},
        {"_COMM": None},
    ],
)
def test_logger_style_spoofed_identifier_is_not_authentication_evidence(changes):
    result = parse(payload([record(**changes)]))
    assert not result.events
    assert result.status == "degraded"
    assert result.gaps == ["untrusted_auth_metadata"]


@pytest.mark.parametrize(
    "message",
    [
        "Invalid user fixture from 192.0.2.50 port 34567",
        "Connection closed by authenticating user fixture 192.0.2.50 port 34567 [preauth]",
        "application said: Failed password for root from 192.0.2.50 port 34567 ssh2",
        "Server listening on 0.0.0.0 port 22.",
        "Accepted key ED25519 SHA256:fixture found at /var/lib/fixture/authorized_keys:1",
        "Accepted certificate ID fixture signed by ED25519 SHA256:fixture via /etc/ssh/auth",
        "Failed to open authorized keys '/var/lib/fixture/authorized_keys': Permission denied",
        "Failed publickey test: no authentication result was produced",
    ],
)
def test_normal_messages_and_embedded_untrusted_text_do_not_add_failures(message):
    result = parse(payload([record(MESSAGE=message)]))
    assert not result.events
    assert result.status == "complete"


@pytest.mark.parametrize(
    "message",
    [
        "Failed password for root from 192.0.2.50 port 22 ssh2\n"
        "Accepted password for root from 192.0.2.50 port 22 ssh2",
        "Accepted password for invalid user fixture from 192.0.2.50 port 22 ssh2",
        "Failed password for root from not-an-ip port 22 ssh2",
        "Failed password for root from 192.0.2.50 port 0 ssh2",
        "Failed none for root from 192.0.2.50 port 22 ssh2",
        "Failed gssapi-with-mic for root from 192.0.2.50 port 22 ssh2",
        "Accepted hostbased for root from 192.0.2.50 port 22 ssh2",
    ],
)
def test_invalid_or_unsupported_auth_records_are_visible_gaps(message):
    result = parse(payload([record(MESSAGE=message)]))
    assert not result.events and result.status == "degraded"
    assert result.gaps


@pytest.mark.parametrize(
    "message,method,kind,account",
    [
        (
            "Failed password for root from 192.0.2.50 port 22 ssh2",
            "password",
            "authentication_failed",
            "root",
        ),
        (
            "Failed keyboard-interactive/pam for fixture from 192.0.2.50 port 22 ssh2 [preauth]",
            "keyboard-interactive",
            "authentication_failed",
            "other",
        ),
        (
            "Accepted password for root from 192.0.2.50 port 22 ssh2",
            "password",
            "authentication_accepted",
            "root",
        ),
    ],
)
def test_supported_auth_formats_are_counted_once(message, method, kind, account):
    event = parse(payload([record(MESSAGE=message)])).events[0]
    assert (event.method, event.kind, event.account_type) == (method, kind, account)


def test_duplicate_cursor_does_not_double_count_and_conflict_drops_both():
    result = parse(payload([record(), record()]))
    assert len(result.events) == 1
    assert result.status == "degraded"
    assert result.gaps == ["duplicate_journal_cursor"]
    result = parse(
        payload(
            [record(), record(MESSAGE="Accepted password for root from 192.0.2.50 port 22 ssh2")]
        )
    )
    assert not result.events and result.status == "degraded"
    assert result.gaps == ["conflicting_journal_cursor"]


def test_controller_defends_against_duplicate_projection_even_if_reader_broken():
    wire = payload([record()])
    wire["events"].append(dict(wire["events"][0]))
    wire["raw_records_seen"] = 2
    observation = parse(wire)
    assert len(observation.events) == 1 and observation.status == "degraded"
    wire["events"][1]["source_ip"] = "192.0.2.90"
    observation = parse(wire)
    assert not observation.events and "conflicting_journal_cursor" in observation.gaps


@pytest.mark.parametrize(
    "change",
    [
        {"__CURSOR": "cursor\nforged"},
        {"__REALTIME_TIMESTAMP": True},
        {"_BOOT_ID": "not-a-boot"},
        {"__REALTIME_TIMESTAMP": str(START - 1)},
        {"__REALTIME_TIMESTAMP": str(END + 1)},
    ],
)
def test_bad_or_out_of_window_metadata_cannot_be_counted(change):
    observation = parse(payload([record(**change)]))
    assert observation.status == "degraded" and not observation.events


def test_empty_successful_window_is_complete_not_missing_transport():
    observation = parse(payload())
    assert observation.status == "complete" and not observation.events and not observation.gaps
    assert observation.window_ended_at - observation.window_started_at == timedelta(minutes=15)


@pytest.mark.parametrize("delta", [-121, 121])
def test_remote_clock_skew_cannot_generate_current_events(delta):
    value = payload([record()])
    observation = parse_observation(
        host(),
        CheckResult(name="security_events", stdout=json.dumps(value)),
        collected_at=NOW + timedelta(seconds=delta),
    )
    assert observation.status == "unavailable" and not observation.events
    assert observation.gaps == ["remote_clock_outside_budget"]


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"extra": "private-marker"},
        {"gaps": ["password=private-marker"]},
        {"raw_records_seen": False},
        {"window_started_us": "-1"},
        {"window_ended_us": "99999999999999999999"},
        {"status": "degraded"},
        {"raw_records_seen": 0},
    ],
)
def test_malformed_wire_schema_is_not_accepted_or_reflected(change):
    value = payload([record()])
    value.update(change)
    observation = parse(value)
    assert observation.status == "unavailable" and not observation.events
    assert "private-marker" not in observation.model_dump_json()


@pytest.mark.parametrize(
    "changes",
    [
        {"truncated": True},
        {"stderr": "private-key-path-marker"},
        {"exit_code": 1},
        {"status": "permission_denied"},
        {"stdout": "not-json"},
        {"stdout": "x" * 13000},
    ],
)
def test_incomplete_transport_never_becomes_empty_healthy_window(changes):
    result = CheckResult(name="security_events", stdout=json.dumps(payload()))
    result = result.model_copy(update=changes)
    observation = parse_observation(host(), result, collected_at=NOW)
    assert observation.status == "unavailable" and not observation.events
    assert "private-key-path-marker" not in observation.model_dump_json()


def test_duplicate_wire_json_fields_are_rejected():
    observation = parse_observation(
        host(),
        CheckResult(name="security_events", stdout='{"schema_version":1,"schema_version":1}'),
        collected_at=NOW,
    )
    assert observation.status == "unavailable"
    wire = b'{"MESSAGE":"old","MESSAGE":"Failed password for root from 192.0.2.50 port 22 ssh2"}'
    assert reader.build_payload(wire, START, END)["gaps"] == ["malformed_journal_record"]


def test_flooded_window_is_capped_and_visibly_degraded_without_partial_json():
    records = [
        record(__CURSOR=f"s=fixture;i={index}", __REALTIME_TIMESTAMP=str(END - index * 1_000_000))
        for index in range(200)
    ]
    value = payload(records)
    encoded = reader.encode(value)
    assert len(encoded) + 1 <= reader.MAX_OUTPUT_BYTES
    assert 1 <= len(value["events"]) <= reader.MAX_EVENTS
    assert value["status"] == "degraded"
    assert "journal_record_limit" in value["gaps"]
    assert "projection_event_limit" in value["gaps"]
    assert "projection_output_limit" in value["gaps"]
    assert len(parse(value).events) == len(value["events"])


def test_reader_access_failure_keeps_no_events_and_exposes_gap():
    value = payload([record()], gaps=["journal_unavailable"], available=False)
    observation = parse(value)
    assert observation.status == "unavailable" and not observation.events
    assert observation.gaps == ["journal_unavailable"]


def test_fixed_journal_argv_never_reads_user_or_raw_extra_fields():
    argv = reader.journal_command(START, END)
    assert argv[:5] == ["/usr/bin/timeout", "-k", "1s", "3s", "/usr/bin/journalctl"]
    assert "--system" in argv and "--lines=200" in argv
    assert "--unit=ssh.service" in argv and "--unit=opsark-security-probe.service" in argv
    assert "--all" not in argv and "--user" not in argv
    assert "--since=@" in " ".join(argv) and "--until=@" in " ".join(argv)


def test_trust_record_change_stops_before_connect(tmp_path, monkeypatch):
    target = host(tmp_path)
    target.known_hosts_file.write_bytes(b"changed-profile")

    class Client:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            raise AssertionError("must not connect")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    observation = collect_security(target)
    assert observation.status == "unavailable"
    assert observation.gaps == ["security_trust_record_changed"]


def test_dedicated_ssh_connection_executes_exact_single_security_command(tmp_path, monkeypatch):
    target = host(tmp_path)
    called = {}

    class Client:
        def set_missing_host_key_policy(self, policy):
            assert isinstance(policy, paramiko.RejectPolicy)

        def load_host_keys(self, path):
            called["known"] = path

        def connect(self, **kwargs):
            called["connect"] = kwargs

        def close(self):
            called["closed"] = True

    def execute(client, name, command, budget):
        called["command"] = command
        return CheckResult(
            name=name,
            stdout=json.dumps(
                reader.build_payload(
                    b"",
                    int(datetime.now(UTC).timestamp()) * 1_000_000 - reader.WINDOW_US,
                    int(datetime.now(UTC).timestamp()) * 1_000_000,
                )
            ),
        )

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    monkeypatch.setattr("opsark.security_events.run_check", execute)
    observation = collect_security(target)
    assert observation.status == "complete"
    assert called["command"] == SECURITY_COMMAND
    assert called["connect"]["username"] == "opsark-readonly"
    assert called["connect"]["allow_agent"] is False and called["connect"]["look_for_keys"] is False
    assert called["closed"]


def test_transport_exception_is_not_reflected_into_observation(tmp_path, monkeypatch):
    class Client:
        def set_missing_host_key_policy(self, policy):
            pass

        def load_host_keys(self, path):
            pass

        def connect(self, **kwargs):
            raise paramiko.AuthenticationException("private-path-marker")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    observation = collect_security(host(tmp_path))
    assert observation.status == "unavailable"
    assert "private-path-marker" not in observation.model_dump_json()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux selector pipe and process-group budgets")
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
    output, gaps, _ = reader.read_bounded(START, END)
    assert len(output) <= reader.MAX_RAW_BYTES
    assert "journal_output_limit" in gaps
    monkeypatch.setattr(reader, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(
        reader,
        "journal_command",
        lambda *args: [sys.executable, "-I", "-c", "import time;time.sleep(2)"],
    )
    _, gaps, _ = reader.read_bounded(START, END)
    assert "journal_timeout" in gaps


@pytest.mark.skipif(sys.platform != "linux", reason="Actual proc fd discovery and Linux flock")
def test_nested_journal_process_keeps_guard_lock_after_reader_is_killed(tmp_path):
    import fcntl

    tmp_path.chmod(0o700)
    lock, ready, stopped = (
        tmp_path / "guard.lock",
        tmp_path / "journal-ready",
        tmp_path / "journal-terminated",
    )
    child_code = (
        "from pathlib import Path; import os,signal,sys,time; "
        f"stopped=Path({str(stopped)!r}); "
        "signal.signal(signal.SIGTERM,lambda *args:(stopped.write_text('term'),sys.exit(0))); "
        "os.closerange(3,256); "
        f"Path({str(ready)!r}).write_text('ready'); time.sleep(10)"
    )
    script_path = ROOT / "deploy/security/read_journal.py"
    outer_code = (
        "import importlib.util,fcntl,os,pathlib,sys; "
        f"spec=importlib.util.spec_from_file_location('reader',{str(script_path)!r}); "
        "reader=importlib.util.module_from_spec(spec); spec.loader.exec_module(reader); "
        f"lock=open({str(lock)!r},'w'); os.chmod({str(lock)!r},0o600); "
        "fcntl.flock(lock,fcntl.LOCK_EX); discover=reader.inherited_guard_fds; "
        f"reader.inherited_guard_fds=lambda:discover(pathlib.Path({str(lock)!r}),"
        f"owner_uid=os.geteuid(),trusted_ancestor=pathlib.Path({str(tmp_path)!r})); "
        "reader.journal_command=lambda *args:['/usr/bin/timeout','-k','1s','3s',"
        f"sys.executable,'-I','-c',{child_code!r}]; "
        "reader.read_bounded(0,1)"
    )
    outer = subprocess.Popen(  # noqa: S603 -- exact local fixture process, never a target host.
        [sys.executable, "-I", "-c", outer_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            assert outer.poll() is None
            time.sleep(0.02)
        assert ready.exists()
        outer.kill()
        outer.wait(timeout=2)
        with lock.open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            deadline = time.monotonic() + 6
            while True:
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
        # The simulated journal closes all inherited fds itself. Its timeout
        # supervisor, rather than the reader or journal, retained the lock and
        # terminated the command on its own deadline; no child is manually killed.
        assert stopped.read_text() == "term"
    finally:
        if outer.poll() is None:
            outer.kill()
            outer.wait(timeout=2)


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux proc fd discovery")
def test_fd_discovery_only_keeps_matching_inode_and_can_run_without_guard(tmp_path):
    # The real reader starts with the guard's passed descriptor. Other pytest fixtures
    # can fill its bounded scan if this test opens the lock in the shared process.
    child_code = textwrap.dedent("""
        import os
        import runpy
        import sys
        from pathlib import Path

        discover = runpy.run_path(sys.argv[1])["inherited_guard_fds"]
        directory = Path(sys.argv[2])
        directory.chmod(0o700)
        lock, other = directory / "guard.lock", directory / "other-file"
        options = {"owner_uid": os.geteuid(), "trusted_ancestor": directory}
        assert discover(lock, **options) == ()
        with lock.open("w") as descriptor, other.open("w") as unrelated:
            lock.chmod(0o600)
            found = discover(lock, **options)
            assert found == (descriptor.fileno(),)
            assert unrelated.fileno() not in found
        assert discover(lock, **options) == ()
    """)
    subprocess.run(  # noqa: S603 -- fixed local reader fixture in a fresh process.
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            child_code,
            str(ROOT / "deploy/security/read_journal.py"),
            str(tmp_path),
        ],
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=True,
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Actual GNU timeout exit classification")
def test_independent_journal_deadline_is_recorded_as_timeout(monkeypatch):
    monkeypatch.setattr(
        reader,
        "journal_command",
        lambda *args: [
            "/usr/bin/timeout",
            "-k",
            "1s",
            "0.1s",
            sys.executable,
            "-I",
            "-c",
            "import time;time.sleep(10)",
        ],
    )
    _, gaps, code = reader.read_bounded(START, END)
    assert code == 124
    assert "journal_timeout" in gaps


@pytest.mark.skipif(sys.platform != "linux", reason="Actual Linux metadata rejection")
@pytest.mark.parametrize("kind", ["symlink", "mode", "owner", "hardlink", "writable_parent"])
def test_fd_discovery_rejects_untrusted_guard_lock_before_child_launch(tmp_path, kind):
    tmp_path.chmod(0o700)
    lock = tmp_path / "guard.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    owner = os.geteuid()
    if kind == "symlink":
        linked = tmp_path / "linked.lock"
        linked.symlink_to(lock)
        lock = linked
    elif kind == "mode":
        lock.chmod(0o644)
    elif kind == "owner":
        owner += 1
    elif kind == "hardlink":
        os.link(lock, tmp_path / "second-link.lock")
    else:
        tmp_path.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="Untrusted guard lock"):
            reader.inherited_guard_fds(lock, owner_uid=owner, trusted_ancestor=tmp_path)
    finally:
        tmp_path.chmod(0o700)
