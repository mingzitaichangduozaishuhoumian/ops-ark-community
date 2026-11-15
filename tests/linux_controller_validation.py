"""Offline Linux Controller acceptance in an operator-owned disposable container.

This file is a test harness, never a deployment command. The operator supplies
immutable source/candidate packages and enforces the container's resource and
mount limits. Only bounded metadata is printed; pytest output stays private.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import secrets
import shlex
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path

FILES = (
    "test_ai_egress.py",
    "test_ai_provider.py",
    "test_ai_provider_boundaries.py",
    "test_ai_provider_metadata.py",
    "test_ai_thinking_config.py",
    "test_automation.py",
    "test_browser_defense_business_smoke.py",
    "test_browser_defense_native_smoke.py",
    "test_claude_provider.py",
    "test_config.py",
    "test_control_modes.py",
    "test_defense_abrupt_process.py",
    "test_defense_ai.py",
    "test_defense_ai_api.py",
    "test_defense_api.py",
    "test_defense_application.py",
    "test_defense_backup_compat.py",
    "test_defense_browser_application.py",
    "test_defense_business_lab.py",
    "test_defense_business_relay.py",
    "test_defense_client.py",
    "test_defense_config.py",
    "test_defense_controller_lab.py",
    "test_defense_handoff.py",
    "test_defense_intent_process_crash.py",
    "test_defense_live_process.py",
    "test_defense_native_relay.py",
    "test_defense_query_fence.py",
    "test_defense_recheck.py",
    "test_defense_recheck_api.py",
    "test_defense_recheck_application.py",
    "test_defense_recheck_backup.py",
    "test_defense_recheck_browser_application.py",
    "test_defense_recheck_process_restart.py",
    "test_defense_recheck_store.py",
    "test_defense_recheck_web.py",
    "test_defense_requests.py",
    "test_defense_session_ai.py",
    "test_defense_session_backup.py",
    "test_defense_session_coordinator.py",
    "test_defense_session_integration.py",
    "test_defense_session_lab.py",
    "test_defense_session_mutation_fence.py",
    "test_defense_session_native_driver.py",
    "test_defense_session_readiness.py",
    "test_defense_session_receipt.py",
    "test_defense_session_receipt_history_driver.py",
    "test_defense_session_receipt_web.py",
    "test_defense_session_refresh.py",
    "test_defense_session_service.py",
    "test_defense_session_store.py",
    "test_defense_session_web.py",
    "test_defense_session_worker.py",
    "test_defense_status_restore.py",
    "test_defense_store.py",
    "test_defense_task_watch.py",
    "test_defense_task_watch_backup.py",
    "test_defense_task_watch_integration.py",
    "test_defense_task_watch_native_driver.py",
    "test_defense_task_watch_web.py",
    "test_defense_transport_lab.py",
    "test_defense_transport_restart_driver.py",
    "test_defense_web.py",
    "test_defense_worker_lease.py",
    "test_mode_coordinator.py",
    "test_process_fixture_publish.py",
    "test_shared_mode_admission.py",
    "test_ssh_defense_status.py",
    "test_ssh_transport.py",
)
SSH_WIRE_CASES = (
    "test_actual_authenticated_ssh_collection_uses_fixed_read_commands",
    "test_actual_unknown_host_key_is_refused_before_exec",
    "test_unsupported_system_stops_before_tools_and_scenario_commands",
    "test_missing_tool_skips_affected_checks_but_keeps_other_evidence",
    "test_unknown_architecture_stops_before_scenario_commands",
    "test_malformed_probe_cannot_enable_scenario_commands",
)
CRITICAL = (
    (
        "test_defense_client",
        "test_credential_change_before_reopen_fails_without_connect[permissions]",
    ),
    ("test_linux_commands", "test_real_linux_capacity_and_inode_outputs_are_interpretable"),
) + tuple(("test_ssh_transport", name) for name in SSH_WIRE_CASES)
NODES = tuple("tests/" + name for name in FILES) + tuple(
    "tests/" + module + ".py::" + name for module, name in CRITICAL if module + ".py" not in FILES
)
PLATFORM_EXCLUSIONS = (
    "tests/test_defense_client.py::test_windows_everyone_read_access_is_rejected",
)
SCOPE = "ssh-defense-session-ai-privacy-linux/v2"
EXPECTED_CASES = 1667
MAX_SECONDS = 1800
EMPTY_TRANSPORT_AUDIT = {
    "nonloopback_http_attempts": 0,
    "loopback_http_attempts": 0,
    "nonloopback_ssh_attempts": 0,
    "loopback_ssh_attempts": 0,
    "real_docker_attempts": 0,
}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class ValidationError(RuntimeError):
    """Its message is always a fixed phase code, never exception input."""


def require(condition, code):
    if not condition:
        raise ValidationError(code)


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _write_json(path, value):
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12))
    try:
        with temporary.open("x", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_declaration(
    source, source_archive, identity, candidate, commit, source_sha, candidate_sha
):
    require(type(commit) is str and bool(_COMMIT.fullmatch(commit)), "commit_invalid")
    require(
        all(type(value) is str and _HEX.fullmatch(value) for value in (source_sha, candidate_sha)),
        "package_digest_invalid",
    )
    require(source.is_absolute() and source.is_dir(), "source_missing")
    require(not source.is_symlink() and source.resolve() == source, "linked_source")
    for path in (source_archive, identity, candidate):
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), "package_missing")
    require(_sha(source_archive) == source_sha, "source_archive_digest_changed")
    require(_sha(candidate) == candidate_sha, "candidate_digest_changed")


def _package_helper():
    # The operator binds the reviewed validator pair outside /app. Neither
    # helper comes from a potentially mutated runtime checkout.
    helper = Path(__file__).resolve().with_name("linux_controller_package.py")
    require(helper.is_file() and not helper.is_symlink(), "package_validator_missing")
    spec = importlib.util.spec_from_file_location("opsark_linux_package_validator", helper)
    require(spec is not None and spec.loader is not None, "package_validator_unavailable")
    if spec is None or spec.loader is None:
        raise ValidationError("package_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_sources(args):
    validate_declaration(
        args.source,
        args.source_archive,
        args.identity,
        args.candidate,
        args.expected_commit,
        args.expected_source_sha256,
        args.expected_candidate_sha256,
    )
    require(args.identity.stat().st_size <= 2 * 1024 * 1024, "identity_too_large")
    identity = json.loads(args.identity.read_bytes())
    require(identity.get("commit") == args.expected_commit, "identity_commit_changed")
    require(
        identity.get("source_archive_sha256") == args.expected_source_sha256
        and identity.get("candidate_archive_sha256") == args.expected_candidate_sha256,
        "identity_digest_changed",
    )
    for name in ("linux_controller_validation.py", "linux_controller_package.py"):
        outside = Path(__file__).resolve().with_name(name)
        packaged = args.source / "tests" / name
        require(
            packaged.is_file() and not packaged.is_symlink() and _sha(outside) == _sha(packaged),
            "validator_source_mismatch",
        )
    helper = _package_helper()
    helper.verify_package(args.source_archive, identity)
    source_result = helper.verify_source_tree(args.source, identity)
    runtime = helper.verify_candidate(args.candidate, args.source, identity)
    return {"source": source_result, "runtime": runtime}


def scope_manifest(source):
    """Declare this matrix and every public test file it does not cover."""
    complete = set(FILES)
    partial = {module + ".py" for module, _name in CRITICAL} - complete
    available = {path.name for path in (source / "tests").glob("test_*.py") if path.is_file()}
    require(complete | partial <= available, "matrix_test_file_missing")
    return {
        "id": SCOPE,
        "expected_cases": EXPECTED_CASES,
        "complete_test_files": ["tests/" + name for name in FILES],
        "node_only_test_files": ["tests/" + name for name in sorted(partial)],
        "nodes": list(NODES),
        "critical_nodes": ["tests/" + module + ".py::" + name for module, name in CRITICAL],
        "platform_exclusions": [
            {"node": node, "reason": "Windows DACL contract; Linux POSIX node remains required"}
            for node in PLATFORM_EXCLUSIONS
        ],
        "uncovered_test_files": [
            "tests/" + name for name in sorted(available - complete - partial)
        ],
        "full_product_suite": False,
        "maximum_seconds": MAX_SECONDS,
        "transport_policy": {
            "literal_loopback_http_ssh_allowed": True,
            "loopback_literals": ["127.0.0.1", "::1"],
            "nonloopback_http_ssh_allowed": False,
            "docker_client_allowed": False,
            "audit_coverage": "pytest_parent_httpx_paramiko_popen",
        },
    }


def linux_metadata():
    require(sys.platform == "linux" and sys.version_info[:2] == (3, 13), "linux_python_required")
    require(os.geteuid() == 10001, "unprivileged_uid_required")
    status = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        name, _, value = line.partition(":")
        status[name] = value.strip()
    require(int(status["CapEff"], 16) == 0, "capabilities_present")
    require(status["NoNewPrivs"] == "1", "no_new_privileges_required")
    devices = sorted(path.name for path in Path("/sys/class/net").iterdir())
    require(devices == ["lo"], "loopback_network_only_required")
    require(not Path("/var/run/docker.sock").exists(), "docker_socket_present")
    distro = platform.freedesktop_os_release()
    require(distro.get("ID") in {"debian", "ubuntu"}, "unsupported_linux_family")
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "distribution": distro.get("ID"),
        "distribution_version": distro.get("VERSION_ID"),
        "uid": os.geteuid(),
        "effective_capabilities": "0",
        "no_new_privileges": True,
        "network_devices": devices,
        "playwright_package": importlib.metadata.version("playwright"),
        "pytest_package": importlib.metadata.version("pytest"),
    }


@contextmanager
def _loopback_server():
    import uvicorn

    async def application(scope, receive, send):
        require(scope["type"] == "http", "preflight_scope_changed")
        body = b"<!doctype html><title>OpsArk Linux preflight</title><p id=ready>ready</p>"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/html")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            loop="asyncio",
            http="h11",
            ws="none",
            lifespan="off",
            access_log=False,
            log_level="critical",
            timeout_graceful_shutdown=2,
        )
    )
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            require(thread.is_alive() and time.monotonic() < deadline, "preflight_server_failed")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(5)
        listener.close()
        require(not thread.is_alive(), "preflight_server_stop_failed")


def browser_preflight():
    from playwright.sync_api import sync_playwright

    with _loopback_server() as base, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            requests = []
            page.on("request", lambda request: requests.append(request.url))
            response = page.goto(base, wait_until="load", timeout=15000)
            require(response is not None and response.status == 200, "preflight_response_failed")
            require(page.locator("#ready").inner_text() == "ready", "preflight_dom_failed")
            require(
                all(url.startswith(base + "/") for url in requests), "preflight_external_request"
            )
            return {"chromium": browser.version, "real_loopback_page_verified": True}
        finally:
            browser.close()


def classify_junit(path, exit_code, *, expected_cases=EXPECTED_CASES):
    require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, "junit_missing_or_large")
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    require(
        "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(),
        "junit_declaration_refused",
    )
    tree = ET.fromstring(text)  # noqa: S314 -- bounded UTF-8 own JUnit; DTD/entity declarations rejected.
    cases = list(tree.iter("testcase"))
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    critical = {module + "::" + name: False for module, name in CRITICAL}
    critical_seen = set()
    for case in cases:
        outcome = (
            "failed"
            if case.find("failure") is not None
            else "errors"
            if case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed"
        )
        counts[outcome] += 1
        for module, name in CRITICAL:
            if case.get("classname", "").split(".")[-1] == module and case.get("name") == name:
                require(module + "::" + name not in critical_seen, "critical_case_duplicated")
                critical_seen.add(module + "::" + name)
                critical[module + "::" + name] = outcome == "passed"
    return {
        "testcases": len(cases),
        **counts,
        "critical_nodes_passed": all(critical.values()),
        "accepted": (
            exit_code == 0
            and len(cases) == expected_cases
            and counts["passed"] == expected_cases
            and all(critical.values())
        ),
    }


def clean_environment(output):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPSARK_")}
    environment.update(
        {
            "OPSARK_DATA_DIR": str(output / "bootstrap-data"),
            "OPSARK_TOKEN": "synthetic-linux-controller-validation-token-only",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
    )
    return environment


def _spawn_kind(arguments, executable=None):
    """Identify real SSH/container clients without inspecting Python source arguments."""
    try:
        tokens = (
            shlex.split(os.fsdecode(arguments))
            if isinstance(arguments, (str, bytes, os.PathLike))
            else [os.fsdecode(value) for value in arguments]
        )
        if executable is not None:
            tokens.insert(0, os.fsdecode(executable))
    except (ValueError, TypeError):
        return None
    if not tokens:
        return None
    program = Path(tokens[0]).name.casefold()
    if program in {"sh", "bash", "dash"} and "-c" in tokens:
        index = tokens.index("-c") + 1
        return _spawn_kind(tokens[index]) if index < len(tokens) else None
    if program == "exec":
        return _spawn_kind(tokens[1:])
    names = (
        {Path(token).name.casefold() for token in tokens}
        if program in {"timeout", "env", "sudo"}
        else {program}
    )
    if names & {"docker", "podman", "nerdctl"}:
        return "real_docker_attempts"
    if names & {"ssh", "scp", "sftp", "ssh-keyscan", "sshpass"}:
        return "nonloopback_ssh_attempts"
    return None


@contextmanager
def _offline_transports():
    """Allow literal loopback synthetic wire tests; refuse remote clients/models."""
    import httpx
    import paramiko

    attempts = dict(EMPTY_TRANSPORT_AUDIT)
    original_async = httpx.AsyncHTTPTransport.handle_async_request
    original_sync = httpx.HTTPTransport.handle_request
    original_ssh = paramiko.SSHClient.connect
    popen_class = subprocess.Popen
    original_popen_init = popen_class.__init__

    def permit(request):
        if request.url.host not in {"127.0.0.1", "::1"}:
            attempts["nonloopback_http_attempts"] += 1
            raise ValidationError("nonloopback_http_forbidden")
        attempts["loopback_http_attempts"] += 1

    async def guarded_async(self, request):
        permit(request)
        return await original_async(self, request)

    def guarded_sync(self, request):
        permit(request)
        return original_sync(self, request)

    def guarded_ssh(self, hostname=None, *args, **kwargs):
        if type(hostname) is not str or hostname not in {"127.0.0.1", "::1"}:
            attempts["nonloopback_ssh_attempts"] += 1
            raise ValidationError("nonloopback_ssh_forbidden")
        attempts["loopback_ssh_attempts"] += 1
        return original_ssh(self, hostname, *args, **kwargs)

    def guarded_popen(self, args, *positionals, **kwargs):
        kind = _spawn_kind(args, kwargs.get("executable"))
        if kind is not None:
            attempts[kind] += 1
            raise ValidationError("real_remote_client_forbidden")
        return original_popen_init(self, args, *positionals, **kwargs)

    httpx.AsyncHTTPTransport.handle_async_request = guarded_async
    httpx.HTTPTransport.handle_request = guarded_sync
    paramiko.SSHClient.connect = guarded_ssh
    popen_class.__init__ = guarded_popen
    try:
        yield attempts
    finally:
        httpx.AsyncHTTPTransport.handle_async_request = original_async
        httpx.HTTPTransport.handle_request = original_sync
        paramiko.SSHClient.connect = original_ssh
        popen_class.__init__ = original_popen_init


def transport_audit_accepted(value):
    return (
        type(value) is dict
        and set(value) == set(EMPTY_TRANSPORT_AUDIT)
        and all(type(count) is int and count >= 0 for count in value.values())
        and all(
            value[key] == 0
            for key in (
                "nonloopback_http_attempts",
                "nonloopback_ssh_attempts",
                "real_docker_attempts",
            )
        )
        and value["loopback_ssh_attempts"] >= len(SSH_WIRE_CASES)
    )


def _pytest_child(source, output):
    environment = clean_environment(output)
    os.environ.clear()
    os.environ.update(environment)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(source / "src"), str(source / "tests")]
    import pytest

    with _offline_transports() as attempts:
        try:
            return pytest.main(
                [
                    *NODES,
                    *("--deselect=" + node for node in PLATFORM_EXCLUSIONS),
                    "-q",
                    "--junitxml=" + str(output / "junit.xml"),
                    "--basetemp=/tmp/opsark-linux-pytest-" + secrets.token_hex(12),
                    "-o",
                    "cache_dir=" + str(output / "pytest-cache"),
                ]
            )
        finally:
            _write_json(output / "http-audit.json", attempts)


def _run_pytest(args, remaining):
    output = args.output
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--pytest-child",
        str(args.source),
        str(output),
    ]
    with (output / "pytest.private.log").open("xb") as log:
        process = subprocess.Popen(  # noqa: S603 -- fixed owned Python entry and validated local paths.
            command,
            cwd=args.source,
            env=clean_environment(output),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            # The operator also bounds this entire private PID namespace. This
            # group is created here and contains only this validation's children.
            if process.poll() is None and os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise ValidationError("pytest_deadline_exceeded") from None


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source", type=Path, required=True)
    result.add_argument("--source-archive", type=Path, required=True)
    result.add_argument("--identity", type=Path, required=True)
    result.add_argument("--candidate", type=Path, required=True)
    result.add_argument("--expected-commit", required=True)
    result.add_argument("--expected-source-sha256", required=True)
    result.add_argument("--expected-candidate-sha256", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def run(args):
    began = time.monotonic()
    require(
        args.output.is_absolute()
        and args.output.is_dir()
        and not args.output.is_symlink()
        and not any(args.output.iterdir()),
        "fresh_output_directory_required",
    )
    for key in tuple(os.environ):
        if key.startswith("OPSARK_"):
            del os.environ[key]
    os.environ.update(clean_environment(args.output))
    sys.dont_write_bytecode = True
    record = {
        "schema": "opsark-linux-controller-validation/v1",
        "completed": False,
        "phase": "starting",
        "validator_sha256": _sha(Path(__file__).resolve()),
        "package_validator_sha256": _sha(
            Path(__file__).resolve().with_name("linux_controller_package.py")
        ),
    }
    try:
        record["phase"] = "source_verification"
        before = verify_sources(args)
        record["source_before"] = before
        record["scope"] = scope_manifest(args.source)
        record["platform"] = linux_metadata()
        record["phase"] = "chromium_loopback_preflight"
        record["browser_preflight"] = browser_preflight()
        record["phase"] = "pytest"
        remaining = MAX_SECONDS - (time.monotonic() - began)
        require(remaining > 0, "validation_deadline_exceeded")
        code = _run_pytest(args, remaining)
        record["pytest_exit_code"] = code
        record["pytest"] = classify_junit(args.output / "junit.xml", code)
        audit = json.loads((args.output / "http-audit.json").read_bytes())
        require(transport_audit_accepted(audit), "remote_transport_attempted_or_wire_missing")
        record["http_audit"] = audit
        after = verify_sources(args)
        require(before == after, "source_changed_during_validation")
        record["source_after"] = after
        record["source_unchanged"] = True
        require(record["pytest"]["accepted"], "pytest_acceptance_incomplete")
        require(time.monotonic() - began <= MAX_SECONDS, "validation_deadline_exceeded")
        record["completed"], record["phase"] = True, "verified"
    except Exception as error:
        with (args.output / "runner.private.log").open("x", encoding="utf-8") as stream:
            traceback.print_exception(error, file=stream)
        record["failure_type"] = type(error).__name__
        record["failure_code"] = (
            str(error) if type(error) is ValidationError else "phase_not_confirmed"
        )
    record["elapsed_seconds"] = round(time.monotonic() - began, 3)
    _write_json(args.output / "proof.json", record)
    return record


def main():
    if sys.argv[1:2] == ["--pytest-child"]:
        require(len(sys.argv) == 4, "child_declaration_invalid")
        return int(_pytest_child(Path(sys.argv[2]), Path(sys.argv[3])))
    args = parser().parse_args()
    record = run(args)
    print(json.dumps({"completed": record["completed"], "phase": record["phase"]}, sort_keys=True))
    return 0 if record["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
