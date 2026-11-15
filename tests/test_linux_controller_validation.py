"""Pure acceptance-boundary tests; no Docker, real network or private data."""

import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import httpx
import linux_controller_validation as validation
import paramiko
import pytest
from linux_controller_validation import (
    CRITICAL,
    EMPTY_TRANSPORT_AUDIT,
    EXPECTED_CASES,
    FILES,
    MAX_SECONDS,
    NODES,
    PLATFORM_EXCLUSIONS,
    SCOPE,
    SSH_WIRE_CASES,
    ValidationError,
    _offline_transports,
    _spawn_kind,
    classify_junit,
    clean_environment,
    scope_manifest,
    transport_audit_accepted,
    validate_declaration,
    verify_sources,
)


def junit(tmp_path, *, skipped=None, failed=None, duplicate=False, omit=None):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    names = [*CRITICAL, ("synthetic_validation", "test_other")]
    if duplicate:
        names.append(CRITICAL[0])
    for module, name in names:
        if module == omit:
            continue
        case = ET.SubElement(suite, "testcase", {"classname": "tests." + module, "name": name})
        if module == skipped or (module, name) == skipped:
            ET.SubElement(case, "skipped", {"message": "synthetic missing dependency"})
        if module == failed:
            ET.SubElement(case, "failure", {"message": "synthetic failure"})
    path = tmp_path / "junit.xml"
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


def test_junit_acceptance_requires_all_actual_critical_nodes(tmp_path):
    count = len(CRITICAL) + 1
    result = classify_junit(junit(tmp_path), 0, expected_cases=count)
    assert result == {
        "testcases": count,
        "passed": count,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "critical_nodes_passed": True,
        "accepted": True,
    }


@pytest.mark.parametrize("critical", CRITICAL)
def test_critical_skip_cannot_become_green_even_when_pytest_exits_zero(tmp_path, critical):
    result = classify_junit(junit(tmp_path, skipped=critical), 0, expected_cases=len(CRITICAL) + 1)
    assert not result["accepted"] and not result["critical_nodes_passed"]
    assert result["skipped"] == 1


def test_missing_failure_and_nonzero_exit_are_separate_incomplete_results(tmp_path):
    count = len(CRITICAL) + 1
    result = classify_junit(junit(tmp_path, failed="synthetic_validation"), 1, expected_cases=count)
    assert result["failed"] == 1 and not result["accepted"]
    result = classify_junit(junit(tmp_path), 2, expected_cases=count)
    assert result["passed"] == count and not result["accepted"]
    result = classify_junit(junit(tmp_path, omit=CRITICAL[0][0]), 0, expected_cases=count - 1)
    assert not result["critical_nodes_passed"] and not result["accepted"]


def test_duplicate_critical_identity_is_refused(tmp_path):
    with pytest.raises(ValidationError, match="critical_case_duplicated"):
        classify_junit(junit(tmp_path, duplicate=True), 0, expected_cases=len(CRITICAL) + 2)


def test_junit_cannot_expand_declared_entities(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_bytes(b'<!DOCTYPE test [<!ENTITY value "unsafe">]><testsuites/>')
    with pytest.raises(ValidationError, match="junit_declaration_refused"):
        classify_junit(path, 0, expected_cases=0)
    path.write_bytes('<!DOCTYPE test [<!ENTITY value "unsafe">]><testsuites/>'.encode("utf-16"))
    with pytest.raises(UnicodeDecodeError):
        classify_junit(path, 0, expected_cases=0)


def test_source_and_candidate_have_independent_pinned_digests(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    archive, identity, candidate = (
        tmp_path / name for name in ("source.tar.gz", "identity.json", "candidate.tar.gz")
    )
    archive.write_bytes(b"synthetic git archive")
    identity.write_bytes(b"{}")
    candidate.write_bytes(b"synthetic official candidate")
    source_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    candidate_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    validate_declaration(source, archive, identity, candidate, "a" * 40, source_sha, candidate_sha)
    candidate.write_bytes(b"changed bytes")
    with pytest.raises(ValidationError, match="candidate_digest_changed"):
        validate_declaration(
            source, archive, identity, candidate, "a" * 40, source_sha, candidate_sha
        )
    with pytest.raises(ValidationError, match="commit_invalid"):
        validate_declaration(
            source, archive, identity, candidate, "HEAD", source_sha, candidate_sha
        )


def test_child_configuration_discards_ambient_opsark_authority(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_AI_KEY", "synthetic-private-key-do-not-propagate")
    monkeypatch.setenv("OPSARK_DEFENSE_WORKER_ENABLED", "true")
    monkeypatch.setenv("OPSARK_DEFENSE_TASK_WATCH_ENABLED", "true")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/synthetic-public-browser-cache")
    result = clean_environment(tmp_path)
    assert set(key for key in result if key.startswith("OPSARK_")) == {
        "OPSARK_DATA_DIR",
        "OPSARK_TOKEN",
    }
    assert result["PLAYWRIGHT_BROWSERS_PATH"] == "/synthetic-public-browser-cache"
    assert result["PYTHONDONTWRITEBYTECODE"] == "1"


def test_selection_names_an_explicit_frozen_scope_instead_of_all_tests():
    assert EXPECTED_CASES == 1667 and len(FILES) == 69 and len(NODES) == 70
    assert len(set(NODES)) == len(NODES) and len(set(FILES)) == len(FILES)
    assert MAX_SECONDS == 1800 and SCOPE == "ssh-defense-session-ai-privacy-linux/v2"
    assert all(name.startswith("tests/") and ".." not in name for name in NODES)
    assert "tests/test_defense_task_watch_native_driver.py" in NODES
    assert not any(name.startswith("tests/lab/") or "guest_acceptance" in name for name in NODES)
    for filename in (
        "test_defense_session_receipt.py",
        "test_defense_session_receipt_web.py",
        "test_defense_session_receipt_history_driver.py",
        "test_defense_session_readiness.py",
        "test_defense_session_native_driver.py",
        "test_defense_session_refresh.py",
        "test_defense_session_mutation_fence.py",
        "test_defense_session_worker.py",
        "test_defense_transport_lab.py",
        "test_defense_transport_restart_driver.py",
        "test_ai_egress.py",
        "test_ai_provider.py",
        "test_claude_provider.py",
    ):
        assert "tests/" + filename in NODES
    assert PLATFORM_EXCLUSIONS == (
        "tests/test_defense_client.py::test_windows_everyone_read_access_is_rejected",
    )
    assert "tests/test_defense_client.py" in NODES
    assert "tests/test_linux_commands.py::" + CRITICAL[1][1] in NODES
    assert len(SSH_WIRE_CASES) == 6
    assert all(("test_ssh_transport", name) in CRITICAL for name in SSH_WIRE_CASES)


def test_scope_lists_every_uncovered_file_and_the_node_only_module(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in (*FILES, "test_linux_commands.py", "test_outside_this_matrix.py"):
        (tests / name).write_bytes(b"# synthetic public source\n")
    result = scope_manifest(tmp_path)
    assert result["id"] == SCOPE and result["full_product_suite"] is False
    assert result["expected_cases"] == 1667 and result["maximum_seconds"] == 1800
    assert len(result["complete_test_files"]) == 69
    assert result["node_only_test_files"] == ["tests/test_linux_commands.py"]
    assert result["uncovered_test_files"] == ["tests/test_outside_this_matrix.py"]
    assert [item["node"] for item in result["platform_exclusions"]] == list(PLATFORM_EXCLUSIONS)
    (tests / FILES[0]).unlink()
    with pytest.raises(ValidationError, match="matrix_test_file_missing"):
        scope_manifest(tmp_path)


@pytest.mark.parametrize(
    "changed", ["linux_controller_validation.py", "linux_controller_package.py"]
)
def test_outside_validators_must_match_the_frozen_source_package(tmp_path, monkeypatch, changed):
    source, outside = tmp_path / "source", tmp_path / "validators"
    (source / "tests").mkdir(parents=True)
    outside.mkdir()
    for name in ("linux_controller_validation.py", "linux_controller_package.py"):
        (source / "tests" / name).write_bytes(b"# reviewed synthetic validator\n")
        (outside / name).write_bytes(b"# reviewed synthetic validator\n")
    archive, candidate, identity = (
        tmp_path / name for name in ("source.gz", "candidate.gz", "identity.json")
    )
    archive.write_bytes(b"synthetic source package")
    candidate.write_bytes(b"synthetic runtime candidate")
    source_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    candidate_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    identity.write_text(
        json.dumps(
            {
                "commit": "a" * 40,
                "source_archive_sha256": source_sha,
                "candidate_archive_sha256": candidate_sha,
            }
        ),
        encoding="ascii",
    )
    args = SimpleNamespace(
        source=source,
        source_archive=archive,
        candidate=candidate,
        identity=identity,
        expected_commit="a" * 40,
        expected_source_sha256=source_sha,
        expected_candidate_sha256=candidate_sha,
    )
    helper = SimpleNamespace(
        verify_package=lambda *_: None,
        verify_source_tree=lambda *_: {"source": True},
        verify_candidate=lambda *_: {"candidate": True},
    )
    loaded = []

    def load_helper():
        loaded.append(True)
        return helper

    monkeypatch.setattr(validation, "__file__", str(outside / "linux_controller_validation.py"))
    monkeypatch.setattr(validation, "_package_helper", load_helper)
    assert verify_sources(args) == {"source": {"source": True}, "runtime": {"candidate": True}}
    (source / "tests" / changed).write_bytes(b"# uncommitted runtime change\n")
    with pytest.raises(ValidationError, match="validator_source_mismatch"):
        verify_sources(args)
    assert loaded == [True]


@pytest.mark.parametrize(
    "arguments,kind",
    [
        (["/usr/bin/docker", "ps"], "real_docker_attempts"),
        (["/usr/bin/timeout", "1", "/usr/bin/docker", "info"], "real_docker_attempts"),
        (["sudo", "-n", "ssh", "synthetic.invalid"], "nonloopback_ssh_attempts"),
        (["sh", "-c", "exec ssh synthetic.invalid"], "nonloopback_ssh_attempts"),
        ("scp synthetic-only", "nonloopback_ssh_attempts"),
        (["/usr/bin/python3", "-c", "print('/usr/bin/docker')"], None),
        (["/usr/bin/ssh-keygen", "-V"], None),
        (["df", "-Pi"], None),
    ],
)
def test_only_real_remote_client_spawns_are_classified(arguments, kind):
    assert _spawn_kind(arguments) == kind
    assert _spawn_kind(["python3"], executable="/usr/bin/ssh") == "nonloopback_ssh_attempts"


def test_remote_guards_block_actual_clients_but_keep_mock_loopback_available(monkeypatch):
    original = lambda self, request: httpx.Response(200, request=request)  # noqa: E731 -- fixed synthetic transport.
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", original)
    local_calls = []
    monkeypatch.setattr(
        paramiko.SSHClient, "connect", lambda self, hostname, **kw: local_calls.append(hostname)
    )
    ssh_connect = paramiko.SSHClient.connect
    popen_init = subprocess.Popen.__init__
    with _offline_transports() as attempts:
        assert attempts == EMPTY_TRANSPORT_AUDIT
        with pytest.raises(ValidationError, match="nonloopback_ssh_forbidden"):
            paramiko.SSHClient().connect("synthetic.invalid")
        with pytest.raises(ValidationError, match="nonloopback_ssh_forbidden"):
            paramiko.SSHClient().connect("localhost")
        paramiko.SSHClient().connect("127.0.0.1")
        paramiko.SSHClient().connect("::1")
        assert local_calls == ["127.0.0.1", "::1"]
        with pytest.raises(ValidationError, match="real_remote_client_forbidden"):
            subprocess.Popen(args=["/usr/bin/docker", "ps"])
        with httpx.HTTPTransport() as transport:
            with pytest.raises(ValidationError, match="nonloopback_http_forbidden"):
                transport.handle_request(httpx.Request("GET", "https://synthetic.invalid"))
            with pytest.raises(ValidationError, match="nonloopback_http_forbidden"):
                transport.handle_request(httpx.Request("GET", "http://localhost/only-fake"))
            assert (
                transport.handle_request(
                    httpx.Request("GET", "http://127.0.0.1/only-fake")
                ).status_code
                == 200
            )
        assert attempts == {
            "nonloopback_http_attempts": 2,
            "loopback_http_attempts": 1,
            "nonloopback_ssh_attempts": 2,
            "loopback_ssh_attempts": 2,
            "real_docker_attempts": 1,
        }
    assert paramiko.SSHClient.connect is ssh_connect and subprocess.Popen.__init__ is popen_init
    assert httpx.HTTPTransport.handle_request is original


def test_transport_audit_requires_no_egress_and_observed_six_local_wire_attempts():
    accepted = EMPTY_TRANSPORT_AUDIT | {"loopback_ssh_attempts": 6, "loopback_http_attempts": 3}
    assert transport_audit_accepted(accepted)
    assert not transport_audit_accepted(EMPTY_TRANSPORT_AUDIT)
    for key in ("nonloopback_http_attempts", "nonloopback_ssh_attempts", "real_docker_attempts"):
        assert not transport_audit_accepted(accepted | {key: 1})
    assert not transport_audit_accepted(accepted | {"loopback_ssh_attempts": True})
    assert not transport_audit_accepted(accepted | {"unclassified": 0})
