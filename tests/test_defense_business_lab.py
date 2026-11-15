"""Pure/fake business-fixture checks; no native process, account or remote I/O."""

import ast
import copy
import hashlib
import inspect
import io
import json
import os
import stat
import sys
import textwrap
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import cast

import pytest
import ssh_defense_business_lab as lab

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.readonly.guard import parse_policy  # noqa: E402 -- reviewed standalone module.
from opsark.business_readiness import commands_for_business  # noqa: E402
from opsark.config import HostConfig  # noqa: E402
from opsark.models import BusinessCheck  # noqa: E402

OLD_SSHD = """AddressFamily inet
ListenAddress 198.18.241.2:22422
PidFile /run/opsark-ssh-defense/sshd.pid
HostKey /run/opsark-ssh-defense/host
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers opsark-ssh-lab
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
DisableForwarding yes
PermitTTY no
PermitUserRC no
ForceCommand /usr/bin/true
LogLevel VERBOSE
"""


@pytest.fixture(autouse=True)
def no_deployment_diagnostic_state(monkeypatch):
    monkeypatch.setattr(lab, "_diagnostic_path", None)
    monkeypatch.setattr(lab, "_diagnostic_record", None)


def diagnostic(**changes):
    return {
        "schema": lab.DIAGNOSTIC_SCHEMA,
        "surface": "target",
        "step": "installer_exec",
        "state": "enter",
        "sequence": 1,
        "error_category": "none",
        "tool": None,
    } | changes


@pytest.mark.parametrize(
    "change",
    [
        {"step": "arbitrary-secret"},
        {"error_category": "private-path"},
        {"sequence": True},
        {"sequence": 257},
        {"state": "failed"},
        {"surface": "other"},
        {"stdout": "raw"},
        {"request": "raw"},
        {"policy": "raw"},
        {"api_key": "raw"},
        {
            "tool": {
                "returncode": 0,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_category": "none",
                "stderr_category": "none",
                "raw": "raw",
            }
        },
    ],
)
def test_bootstrap_diagnostic_rejects_unknown_fields_types_and_classifications(change):
    with pytest.raises(lab.native.LabError):
        lab.validate_diagnostic(diagnostic(**change))


def test_diagnostic_counts_and_known_categories_do_not_copy_captured_output(tmp_path, monkeypatch):
    saved = []
    monkeypatch.setattr(lab, "_diagnostic_path", tmp_path / "fake-diagnostic.json")
    monkeypatch.setattr(lab, "_diagnostic_record", diagnostic())
    monkeypatch.setattr(
        lab, "save_diagnostic", lambda path, record: saved.append(lab.validate_diagnostic(record))
    )
    private = b"FAKE_PRIVATE_CANARY -----BEGIN PRIVATE KEY-----"
    result = SimpleNamespace(
        returncode=1,
        stdout=private,
        stderr=b"Refusing to adopt an existing unrelated account: " + private,
    )
    lab.diagnostic_step("installer_exec", result=result)
    lab.diagnostic_failed(RuntimeError(private.decode()))
    final = saved[-1]
    assert final["state"] == "failed" and final["error_category"] == "tool_failed"
    assert final["tool"]["stdout_bytes"] == len(private)
    assert final["tool"]["stderr_category"] == "account_conflict"
    encoded = json.dumps(final)
    assert "FAKE_PRIVATE_CANARY" not in encoded and "PRIVATE KEY" not in encoded
    assert set(final["tool"]) == {
        "returncode",
        "stdout_bytes",
        "stderr_bytes",
        "stdout_category",
        "stderr_category",
    }


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"", "none"),
        (b"Permission denied (publickey).", "publickey_refused"),
        (b"OpsArk restricted collector refused this request.", "guard_refused"),
        (b"PAM_OPEN_SESSION failed", "pam_error"),
        (b"Bad configuration option: private-value", "sshd_config_error"),
        (
            b"Refusing to overwrite an existing unrelated deployment file: private",
            "deployment_conflict",
        ),
        (b"opaque unknown private bytes", "unclassified"),
    ],
)
def test_stderr_diagnostic_only_emits_closed_categories(raw, expected):
    assert lab.stderr_category(raw) == expected


def test_host_failure_exports_target_projection_before_temporary_workspace_disappears(
    tmp_path, monkeypatch
):
    report, errors = {}, []
    monkeypatch.setattr(lab, "diagnostic_failed", lambda error: errors.append(type(error).__name__))
    monkeypatch.setattr(lab, "read_json", lambda path, limit=8192: json.loads(path.read_bytes()))
    monkeypatch.setattr(
        lab, "write_new", lambda path, value: path.write_bytes(lab.native.canonical(value) + b"\n")
    )
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit: path.read_bytes())
    with TemporaryDirectory(dir=tmp_path) as temporary:
        readiness = Path(temporary)
        source = readiness / lab.TARGET_DIAGNOSTIC
        source.write_bytes(
            lab.native.canonical(diagnostic(state="failed", error_category="unconfirmed")) + b"\n"
        )
        with (
            pytest.raises(RuntimeError),
            lab.capture_target_diagnostic(tmp_path, readiness, report),
        ):
            raise RuntimeError("synthetic private failure")
        exported = tmp_path / lab.TARGET_EXPORTED_DIAGNOSTIC
        assert exported.is_file() and source.is_file()
    assert not readiness.exists() and exported.is_file()
    reference = report["target_bootstrap_diagnostic"]
    assert reference["available"] and reference["file"] == lab.TARGET_EXPORTED_DIAGNOSTIC
    assert reference["sha256"] == hashlib.sha256(exported.read_bytes()).hexdigest()
    assert errors == ["RuntimeError"]


def test_unclassified_target_mailbox_is_wholly_blocked_from_export(tmp_path, monkeypatch):
    readiness = tmp_path / "ready"
    readiness.mkdir()
    (readiness / lab.TARGET_DIAGNOSTIC).write_text(json.dumps(diagnostic(api_key="FAKE_PRIVATE")))
    monkeypatch.setattr(lab, "read_json", lambda path, limit=8192: json.loads(path.read_bytes()))
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit: path.read_bytes())
    report = {}
    with lab.capture_target_diagnostic(tmp_path, readiness, report):
        pass
    assert not (tmp_path / lab.TARGET_EXPORTED_DIAGNOSTIC).exists()
    assert report["target_bootstrap_diagnostic"] == {
        "available": False,
        "reason_code": "unavailable",
    }


def test_three_policy_entries_equal_formal_business_commands_and_guard_grammar():
    checks = tuple(BusinessCheck.model_validate(check) for check in lab.business_checks())
    host = cast(HostConfig, SimpleNamespace(business_checks=checks))
    formal = commands_for_business(host)
    expected = lab.expected_policy()
    assert set(expected["commands"]) == {"LC_ALL=C " + command for command in formal.values()}
    raw = lab.native.canonical(expected) + b"\n"
    assert parse_policy(raw) == expected["commands"] and len(parse_policy(raw)) == 3
    assert lab.validate_policy(raw) == hashlib.sha256(raw).hexdigest()
    assert all(check.read_only_confirmed for check in checks)


@pytest.mark.parametrize(
    "change", ["extra", "unknown_path", "status", "boolean_version", "helper", "duplicate"]
)
def test_policy_cannot_select_new_path_command_status_or_helper(change):
    value = copy.deepcopy(lab.expected_policy())
    if change == "extra":
        value["extra"] = "unsafe"
    elif change == "boolean_version":
        value["schema_version"] = True
    elif change == "duplicate":
        raw = b'{"schema_version":1,"schema_version":1,"commands":{}}\n'
        with pytest.raises(lab.native.LabError):
            lab.validate_policy(raw)
        return
    else:
        command = next(iter(value["commands"]))
        argv = value["commands"][command]
        argv[-3 if change == "unknown_path" else -2 if change == "status" else 7] = (
            "/unregistered"
            if change == "unknown_path"
            else "503"
            if change == "status"
            else "/bin/sh"
        )
    with pytest.raises(lab.native.LabError):
        lab.validate_policy(lab.native.canonical(value) + b"\n")


def test_collector_config_keeps_protected_listener_and_locks_original_user_command():
    configured = lab.restricted_ssh_config(OLD_SSHD)
    assert "AllowUsers opsark-ssh-lab opsark-readonly@198.18.241.4\n" in configured
    assert "UsePAM yes\n" in configured and "UsePAM no\n" not in configured
    assert configured.endswith("Match User opsark-ssh-lab\n    ForceCommand /usr/bin/true\n")
    assert "ListenAddress 198.18.241.2:22422\n" in configured
    for constraint in (
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin no",
        "DisableForwarding yes",
        "PermitTTY no",
        "PermitUserRC no",
    ):
        assert constraint + "\n" in configured
    assert configured.count("ForceCommand") == 1
    assert "Match User opsark-readonly" not in configured


@pytest.mark.parametrize(
    "original",
    [
        OLD_SSHD.replace("UsePAM no", "UsePAM yes"),
        OLD_SSHD + "Match User other\n",
        OLD_SSHD.replace("ForceCommand /usr/bin/true", "ForceCommand /bin/sh"),
        OLD_SSHD.replace("AllowUsers opsark-ssh-lab", "AllowUsers other"),
    ],
)
def test_unexpected_original_daemon_configuration_is_refused(original):
    with pytest.raises(lab.native.LabError):
        lab.restricted_ssh_config(original)


@pytest.mark.parametrize("phase", sorted(lab.PHASES))
def test_three_fixed_business_responses_have_real_timeout_and_explicit_status_failure(phase):
    results = {key: lab.business_reply(phase, path) for key, path in lab.PATHS.items()}
    assert results["health"] == (200, lab.BODIES["health"], 0)
    assert results["application"][0] == (503 if phase == "mixed" else 200)
    assert results["dependency"][2] == (3 if phase != "restored" else 0)
    for key, (status, body, delay) in results.items():
        if phase == "restored":
            expected = next(check for check in lab.business_checks() if check["id"] == key)
            assert status == 200 and delay == 0
            assert hashlib.sha256(body).hexdigest() == expected["expected_body_sha256"]
    assert lab.business_reply(phase, "/unregistered") == (404, b"", 0)


def test_phase_is_fixed_and_not_an_arbitrary_url_or_command():
    for phase in ("http://example.com", "/bin/sh", "healthy", True, None):
        with pytest.raises(lab.native.LabError):
            lab.business_reply(phase, "/healthz")
    assert set(lab.PHASE_OPERATIONS) == {"business-mixed", "business-timeout", "business-restored"}


def test_phase_mailbox_rejects_extra_parameters_and_no_code_execution():
    command = {
        "schema": "opsark-controller-command/v1",
        "request_id": "a" * 32,
        "fixture_id": "b" * 16,
        "operation": "business-mixed",
    }
    assert lab.checked_command(command) == command
    for extra in (
        {"url": "http://example.com"},
        {"phase": "other"},
        {"argv": ["/bin/sh"]},
        {"operation": "business-any"},
    ):
        with pytest.raises(lab.native.LabError):
            lab.checked_command(command | extra)


def test_official_four_scripts_and_old_root_sources_remain_frozen():
    root = Path(__file__).resolve().parents[1]
    for name, expected in lab.READONLY_SHA256.items():
        assert (
            hashlib.sha256((root / "deploy/readonly" / name).read_bytes()).hexdigest() == expected
        )
    for name, expected in lab.CORE_SHA256.items():
        assert hashlib.sha256((root / "deploy/defense" / name).read_bytes()).hexdigest() == expected


def test_new_network_security_profile_matches_old_controller_exactly():
    first = ast.parse(textwrap.dedent(inspect.getsource(lab.BusinessNetwork.start)))
    second = ast.parse(textwrap.dedent(inspect.getsource(lab.base.ControllerNetwork.start)))
    assert ast.dump(first) == ast.dump(second)
    old_native, old_base = lab.native.SELF, lab.base.SELF
    with lab.bound_self():
        assert lab.native.SELF == lab.SELF and lab.base.SELF == lab.SELF
        assert lab.native.CONTAINER_SECONDS == 180
    assert old_native == lab.native.SELF and old_base == lab.base.SELF


def test_installer_is_unmodified_and_configuration_precedes_daemon_validation(
    tmp_path, monkeypatch
):
    calls = []
    config = tmp_path / "sshd_config"
    config.write_text(OLD_SSHD)
    root = Path(__file__).resolve().parents[1]
    policy = lab.native.canonical(lab.expected_policy()) + b"\n"

    def read(path, _limit):
        return (
            policy
            if path.name == "collector-policy.json"
            else (root / "deploy/readonly" / path.name).read_bytes()
        )

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        if args[0] == "/usr/sbin/sshd":
            assert "UsePAM yes" in config.read_text()
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        receipt = {
            "account": lab.COLLECTOR,
            "allowed_commands": 3,
            "policy_sha256": hashlib.sha256(policy).hexdigest(),
            "installation_state": "complete",
            "docker_group_membership": False,
            "journal_group_membership": False,
        }
        return SimpleNamespace(returncode=0, stdout=json.dumps(receipt).encode(), stderr=b"")

    monkeypatch.setattr(lab.native, "owned_read", read)
    monkeypatch.setattr(lab.native, "run", run)
    lab.install_collector(config)
    assert calls[0][0] == (
        "/usr/bin/python3",
        "-I",
        "-B",
        "/fixture-code/deploy/readonly/install.py",
        "--policy",
        "/fixture-authority/collector-policy.json",
        "--public-key",
        "/fixture-authority/collector.pub",
    )
    assert calls[1][0] == ("/usr/sbin/sshd", "-t", "-f", str(config))
    assert not any(
        "usermod" in str(arg) or "--unlock" in str(arg) for args, _ in calls for arg in args
    )


def test_bootstrap_requires_three_real_receipts_and_three_independent_rejections():
    calls = []

    def execute(client, *args):
        calls.append((client, args))
        if client == "candidate" or args[args.index("-i") + 1].endswith("/control"):
            return SimpleNamespace(returncode=255, stdout=b"", stderr=b"Permission denied")
        if args[-1] == "/usr/bin/true":
            return SimpleNamespace(returncode=126, stdout=b"", stderr=b"Guard refused")
        return SimpleNamespace(
            returncode=0, stdout=b"OPSARK_HTTP_READINESS_V1 200 match\n", stderr=b""
        )

    network = SimpleNamespace(execute=execute)
    assert all(
        lab.bootstrap_collector(
            network, {"management": "management", "candidate": "candidate"}
        ).values()
    )
    assert len(calls) == 6 and calls[-1][0] == "candidate"
    assert calls[-1][1][-2] == "opsark-readonly@198.18.241.2"
    assert calls[-1][1][calls[-1][1].index("-i") + 1].endswith("/collector")


def test_phase_replacement_is_atomic_and_scoped_to_own_ready_directory(tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(
        lab, "trusted_directory", lambda path, private=False: writes.append((path, private))
    )
    monkeypatch.setattr(lab, "write_new", lambda path, data: path.write_text(json.dumps(data)))
    monkeypatch.setattr(lab, "read_json", lambda path: json.loads(path.read_text()))
    monkeypatch.setattr(
        lab,
        "os",
        SimpleNamespace(
            replace=os.replace,
            open=lambda *_args: 1,
            fsync=lambda _fd: None,
            close=lambda _fd: None,
            O_RDONLY=os.O_RDONLY,
        ),
    )
    result = lab.write_phase(tmp_path, "mixed", "a" * 32)
    assert result["phase"] == "mixed" and result["phase_ref"] == "a" * 32
    assert json.loads((tmp_path / lab.PHASE_FILE).read_text()) == {
        "phase": "mixed",
        "request_id": "a" * 32,
    }
    assert not list(tmp_path.glob("*.pending")) and writes == [(tmp_path, True)]
    with pytest.raises(lab.native.LabError):
        lab.write_phase(tmp_path, "unknown", "b" * 32)


def test_describe_does_not_consult_docker_sources_or_credentials(monkeypatch, capsys):
    monkeypatch.setattr(
        lab.native, "run", lambda *_args, **_kw: pytest.fail("No process is permitted")
    )
    assert lab.main(["describe"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed == {"checks": lab.business_checks(), "policy": lab.expected_policy()}


def test_business_handler_holds_timeout_response_and_closes_exact_body(monkeypatch):
    handler = SimpleNamespace()
    handler.headers = {"Host": lab.DOMAIN}
    handler.path = "/dependency"
    handler.wfile = io.BytesIO()
    events = []
    handler.send_response = lambda code: events.append(("status", code))
    handler.send_header = lambda key, value: events.append((key, value))
    handler.end_headers = lambda: events.append(("headers_done", True))
    monkeypatch.setattr(
        lab, "read_json", lambda path: {"phase": "timeout_only", "request_id": "a" * 32}
    )
    monkeypatch.setattr(
        lab, "time", SimpleNamespace(sleep=lambda seconds: events.append(("sleep", seconds)))
    )
    lab.BusinessHandler.do_GET(cast(lab.BusinessHandler, handler))
    assert events[0] == ("sleep", 3) and events[1] == ("status", 200)
    assert ("Content-Length", str(len(lab.BODIES["dependency"]))) in events
    assert ("Connection", "close") in events and handler.close_connection
    assert handler.wfile.getvalue() == lab.BODIES["dependency"]


def test_wrong_host_never_reads_phase_or_sleeps(monkeypatch):
    handler = SimpleNamespace()
    handler.headers = {"Host": "other.example"}
    handler.path = "/dependency"
    handler.wfile = io.BytesIO()
    statuses = []
    handler.send_response = statuses.append
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None
    monkeypatch.setattr(
        lab, "read_json", lambda *_args: pytest.fail("Wrong host cannot select phase")
    )
    monkeypatch.setattr(
        lab, "time", SimpleNamespace(sleep=lambda _seconds: pytest.fail("Wrong host cannot sleep"))
    )
    lab.BusinessHandler.do_GET(cast(lab.BusinessHandler, handler))
    assert statuses == [404] and handler.wfile.getvalue() == b""


def traversal(monkeypatch, *, blocked):
    calls = []

    def lstat(path):
        calls.append(("lstat", path))
        index = next(
            index for index, item in enumerate(lab.TRAVERSAL_COMPONENTS) if item[1] == path
        )
        if blocked and index > 1:
            raise PermissionError("fake inaccessible child")
        mode = (
            stat.S_IFREG | 0o644
            if index == 4
            else stat.S_IFDIR | (0o700 if blocked and index == 1 else 0o755)
        )
        return SimpleNamespace(st_mode=mode, st_uid=0)

    def access(path, mode):
        calls.append(("access", path, mode))
        index = next(
            index for index, item in enumerate(lab.TRAVERSAL_COMPONENTS) if item[1] == path
        )
        return not blocked or index == 0

    monkeypatch.setattr(lab, "os", SimpleNamespace(lstat=lstat, access=access, X_OK=1, R_OK=4))
    return lab.traversal_projection(), calls


@pytest.mark.parametrize("blocked", [True, False])
def test_collector_projection_only_stats_and_checks_fixed_public_authorization_paths(
    monkeypatch, blocked
):
    value, calls = traversal(monkeypatch, blocked=blocked)
    assert value["all_accessible"] is not blocked
    assert value["first_blocker"] == ("var_lib" if blocked else None)
    assert len(calls) == 10
    assert [item[1] for item in calls[::2]] == [item[1] for item in lab.TRAVERSAL_COMPONENTS]
    assert all(item[0] in {"lstat", "access"} for item in calls)
    assert all(
        "shadow" not in str(item) and "id_rsa" not in str(item) and "id_ed25519" not in str(item)
        for item in calls
    )
    if blocked:
        assert value["components"][1]["mode"] == 0o700
        assert value["components"][1]["access_allowed"] is False
        assert all(row["stat_category"] == "permission_denied" for row in value["components"][2:])
    encoded = json.dumps(value)
    assert "/var" not in encoded and "private" not in encoded


def test_traversal_runs_after_unchanged_official_uid_drop(monkeypatch, capsys):
    from deploy.readonly import http_readiness

    order = []
    monkeypatch.setattr(lab.native, "internal_modules", lambda: order.append("gate"))
    monkeypatch.setattr(http_readiness, "_drop_privileges", lambda: order.append("drop"))
    monkeypatch.setattr(
        lab, "traversal_projection", lambda: order.append("project") or {"fake": True}
    )
    assert lab.internal_collector_traversal() == 0
    assert order == ["gate", "drop", "project"]
    assert json.loads(capsys.readouterr().out) == {"fake": True}


def test_blocked_traversal_is_saved_then_fails_without_chmod_or_unlock(monkeypatch):
    value, _calls = traversal(monkeypatch, blocked=True)
    emitted, subprocesses = [], []

    def run(*args, **kwargs):
        subprocesses.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=lab.native.canonical(value) + b"\n", stderr=b"")

    monkeypatch.setattr(lab.native, "run", run)
    monkeypatch.setattr(lab, "write_new", lambda path, record: emitted.append((path, record)))
    with pytest.raises(lab.native.LabError):
        lab.collector_traversal_preflight("sha256:" + "a" * 64)
    assert len(emitted) == 1 and emitted[0][1] == value
    assert emitted[0][0].name == lab.TRAVERSAL_TARGET_FILE
    assert len(subprocesses) == 1 and "--internal-collector-traversal" in subprocesses[0][0]
    assert subprocesses[0][1]["timeout"] == 8 and subprocesses[0][1]["limit"] == 4096
    assert all("chmod" not in str(arg) and "usermod" not in str(arg) for arg in subprocesses[0][0])
    assert lab.stdout_category(lab.native.canonical(value) + b"\n") == "collector_path_blocked"


@pytest.mark.parametrize(
    "change", ["extra", "component", "conclusion", "mode_bool", "identity", "raw_path"]
)
def test_traversal_projection_rejects_unknown_or_inconsistent_metadata(monkeypatch, change):
    value, _calls = traversal(monkeypatch, blocked=True)
    if change == "extra":
        value["raw"] = "FAKE_PRIVATE"
    elif change == "component":
        value["components"][0]["component"] = "unregistered"
    elif change == "conclusion":
        value["all_accessible"] = True
    elif change == "mode_bool":
        value["components"][0]["mode"] = True
    elif change == "identity":
        value["collector_identity_verified"] = False
    else:
        value["components"][0]["path"] = "/etc/shadow"
    with pytest.raises(lab.native.LabError):
        lab.validate_traversal(value)


def test_path_projection_is_exported_before_owned_workspace_is_removed(tmp_path, monkeypatch):
    value, _calls = traversal(monkeypatch, blocked=True)
    monkeypatch.setattr(lab, "read_json", lambda path, limit=8192: json.loads(path.read_bytes()))
    monkeypatch.setattr(lab.native, "owned_read", lambda path, limit: path.read_bytes())
    monkeypatch.setattr(
        lab,
        "write_new",
        lambda path, record: path.write_bytes(lab.native.canonical(record) + b"\n"),
    )
    report = {}
    with TemporaryDirectory(dir=tmp_path) as temporary:
        ready = Path(temporary)
        (ready / lab.TRAVERSAL_TARGET_FILE).write_bytes(lab.native.canonical(value) + b"\n")
        with lab.capture_target_diagnostic(tmp_path, ready, report):
            pass
    exported = tmp_path / lab.TRAVERSAL_EXPORTED_FILE
    assert not ready.exists() and exported.is_file()
    assert json.loads(exported.read_bytes()) == value
    assert report["collector_traversal_preflight"] == {
        "available": True,
        "file": lab.TRAVERSAL_EXPORTED_FILE,
        "sha256": hashlib.sha256(exported.read_bytes()).hexdigest(),
    }


def mount_records(workspace, *, management=False):
    mounts = (
        [
            (workspace / "code", lab.native.CODE, True),
            (workspace / "management", lab.native.CLIENT, True),
        ]
        if management
        else lab.target_mounts(workspace)
    )
    return [
        {
            "Source": str(source),
            "Destination": destination,
            "RW": not readonly,
            "Type": "bind",
            "Propagation": "rprivate",
        }
        for source, destination, readonly in mounts
    ]


def test_three_bind_profile_has_no_var_lib_and_preserves_management_two_ro_binds(tmp_path):
    mounts = lab.target_mounts(tmp_path)
    assert [(destination, readonly) for _source, destination, readonly in mounts] == [
        ("/fixture-code", True),
        ("/fixture-authority", True),
        ("/fixture-ready", False),
    ]
    assert all(destination != "/var/lib" for _source, destination, _readonly in mounts)
    assert lab.validate_business_mounts({"Mounts": mount_records(tmp_path)}, tmp_path)
    assert lab.validate_business_mounts(
        {"Mounts": mount_records(tmp_path, management=True)}, tmp_path, management=True
    )
    assert (
        lab.STATE_PROFILE["persistence"] == "same_container_cli_and_controller_process_restart_only"
    )
    assert all(
        lab.STATE_PROFILE[key] is False
        for key in (
            "container_restart_supported",
            "container_rebuild_supported",
            "sshd_restart_supported",
            "host_restart_supported",
        )
    )


@pytest.mark.parametrize(
    "change", ["old_varlib", "rw_code", "foreign_source", "volume", "shared", "duplicate"]
)
def test_business_mount_validator_refuses_old_or_changed_target_profile(tmp_path, change):
    mounts = mount_records(tmp_path)
    if change == "old_varlib":
        mounts.append(
            {
                "Source": str(tmp_path / "state"),
                "Destination": "/var/lib",
                "RW": True,
                "Type": "bind",
                "Propagation": "rprivate",
            }
        )
    elif change == "rw_code":
        mounts[0]["RW"] = True
    elif change == "foreign_source":
        mounts[0]["Source"] = "/var/lib"
    elif change == "volume":
        mounts[0]["Type"] = "volume"
    elif change == "shared":
        mounts[0]["Propagation"] = "shared"
    else:
        mounts[2] = dict(mounts[0])
    with pytest.raises(lab.native.LabError):
        lab.validate_business_mounts({"Mounts": mounts}, tmp_path)


@pytest.mark.parametrize("exists,symlink", [(True, False), (False, True)])
def test_fresh_layout_refuses_any_existing_or_symlinked_deployment(monkeypatch, exists, symlink):
    checked = []
    monkeypatch.setattr(lab, "trusted_directory", lambda path: checked.append(str(path)))
    monkeypatch.setattr(
        lab.native,
        "REQUEST_ROOT",
        SimpleNamespace(exists=lambda: exists, is_symlink=lambda: symlink),
    )
    with pytest.raises(lab.native.LabError):
        lab.require_fresh_root_storage()
    assert checked == [str(Path("/var")), str(Path("/var/lib"))]


def test_fresh_layout_does_not_create_chmod_or_adopt_state(monkeypatch):
    checked = []
    monkeypatch.setattr(lab, "trusted_directory", lambda path: checked.append(str(path)))
    monkeypatch.setattr(
        lab.native, "REQUEST_ROOT", SimpleNamespace(exists=lambda: False, is_symlink=lambda: False)
    )
    lab.require_fresh_root_storage()
    assert len(checked) == 2


@pytest.mark.parametrize(
    "change", [None, "directory_mode", "file_mode", "owner", "hardlink", "symlink"]
)
def test_root_cli_created_directory_and_file_remain_private(monkeypatch, change):
    directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
    ledger = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
    if change == "directory_mode":
        directory.st_mode = stat.S_IFDIR | 0o755
    elif change == "file_mode":
        ledger.st_mode = stat.S_IFREG | 0o644
    elif change == "owner":
        ledger.st_uid = 1001
    elif change == "hardlink":
        ledger.st_nlink = 2
    elif change == "symlink":
        ledger.st_mode = stat.S_IFLNK | 0o777

    class RootPath:
        def resolve(self, *, strict):
            return self

        def lstat(self):
            return directory

        def __truediv__(self, name):
            assert name == "requests.json"
            return SimpleNamespace(lstat=lambda: ledger)

    monkeypatch.setattr(lab.native, "REQUEST_ROOT", RootPath())
    if change is None:
        lab.verify_private_root_storage()
    else:
        with pytest.raises(lab.native.LabError):
            lab.verify_private_root_storage()


def test_live_business_resources_recheck_exact_target_and_management_mounts(tmp_path, monkeypatch):
    calls = []
    ready = {
        "state_profile": dict(lab.STATE_PROFILE),
        "workspace": str(tmp_path),
        "container_ids": {"target": "a" * 64, "management": "b" * 64},
    }
    monkeypatch.setattr(lab.base, "live_resources", lambda value: calls.append("base") or True)

    def run(*args, **_kwargs):
        calls.append(args)
        identity = args[-1]
        return SimpleNamespace(
            returncode=0,
            stderr=b"",
            stdout=json.dumps(
                [
                    {
                        "Id": identity,
                        "Mounts": mount_records(tmp_path, management=identity == "b" * 64),
                    }
                ]
            ).encode(),
        )

    monkeypatch.setattr(lab.native, "run", run)
    assert lab.live_resources(ready) and calls[0] == "base" and len(calls) == 3
    assert all(item[-2] == "inspect" for item in calls[1:])


@pytest.mark.parametrize(
    "change",
    [
        {"container_restart_supported": 0},
        {"target_bind_count": "3"},
        {"root_file_mode": 0o644},
        {"extra": "unknown"},
    ],
)
def test_state_profile_is_fixed_and_type_exact(change):
    with pytest.raises(lab.native.LabError):
        lab.validate_state_profile(dict(lab.STATE_PROFILE) | change)
