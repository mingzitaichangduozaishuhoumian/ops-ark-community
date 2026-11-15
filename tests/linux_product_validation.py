"""Closed offline Linux controller, observation and root-policy acceptance scopes.

The operator supplies reviewed immutable packages in a disposable container with
no host socket, keys, credentials or normal data mounts. This runner never builds
an image or connects to an external service. Collection freezes the Linux node
identities before a separate process executes the entire selected scope.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

FILES = (
    "test_ai.py",
    "test_api.py",
    "test_baselines.py",
    "test_collector.py",
    "test_collector_exec_deadline.py",
    "test_diagnostics.py",
    "test_health.py",
    "test_host_onboarding.py",
    "test_host_preflight.py",
    "test_platforms.py",
    "test_readonly_guard.py",
    "test_redaction.py",
    "test_replay.py",
    "test_compose_discovery.py",
    "test_compose_discovery_api.py",
    "test_nginx_dependencies.py",
    "test_nginx_dependencies_api.py",
    "test_nginx_dependency_scope.py",
)
OBSERVATION_PROFILE = "security-observation-nonroot"
OBSERVATION_FILES = (
    "test_observation_api.py",
    "test_security_ai.py",
    "test_security_events.py",
    "test_security_monitor.py",
    "test_security_probe.py",
    "test_security_store.py",
    "test_web_integration.py",
    "test_web_security_events.py",
    "test_web_security_store.py",
)
ROOT_NODES = (
    "tests/test_readonly_guard.py::test_actual_policy_symlink_permissions_and_parent_trust",
)
FLOCK_NODE = (
    "tests/test_readonly_guard.py::test_child_keeps_execution_lock_after_guard_process_is_killed"
)
NATIVE_CURL_NODES = tuple(
    "tests/test_health.py::" + name
    for name in (
        "test_native_curl_loopback_body_and_host_header_match_registration",
        "test_native_curl_does_not_follow_redirects",
        "test_native_curl_ignores_curlrc_extra_url_and_headers",
        "test_native_curl_large_body_is_a_collection_error_not_a_success",
    )
)
LOOPBACK_SSH_NODES = (
    "tests/test_compose_discovery.py::test_actual_loopback_ssh_uses_fixed_metadata_only_and_requires_host_pin",
)
OBSERVATION_NATIVE_NODES = (
    "tests/test_security_events.py::test_reader_real_process_output_and_wall_budgets",
    "tests/test_security_events.py::test_nested_journal_process_keeps_guard_lock_after_reader_is_killed",
    "tests/test_security_events.py::test_fd_discovery_only_keeps_matching_inode_and_can_run_without_guard",
    "tests/test_security_events.py::test_independent_journal_deadline_is_recorded_as_timeout",
    *(
        "tests/test_security_events.py::test_fd_discovery_rejects_untrusted_guard_lock_before_child_launch["
        + kind
        + "]"
        for kind in ("symlink", "mode", "owner", "hardlink", "writable_parent")
    ),
    "tests/test_web_security_events.py::test_reader_real_process_output_and_wall_budgets",
    "tests/test_security_store.py::test_observation_symlink_refused",
)
PROFILES = {
    "general-controller-nonroot": "general-controller-onboard-platform-privacy-linux/v2",
    "readonly-policy-root": "readonly-policy-metadata-root-linux/v1",
    OBSERVATION_PROFILE: "security-observation-web-events-linux/v1",
}
MAX_SECONDS = 900
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_NODE_ID_LENGTH = 16_384
CGROUP_LIMITS = {
    "cpu.max": "100000 100000",
    "memory.max": "1073741824",
    "memory.swap.max": "0",
    "pids.max": "256",
}


class ValidationError(RuntimeError):
    """Only fixed public phase codes escape a validation failure."""


def require(condition, code):
    if not condition:
        raise ValidationError(code)


def _sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _write_json(path, value):
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12))
    try:
        with temporary.open("xb") as stream:
            stream.write(_canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path):
    require(
        path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON_BYTES,
        "metadata_missing_or_large",
    )
    return json.loads(path.read_bytes())


def _controller_helper():
    helper = Path(__file__).resolve().with_name("linux_controller_validation.py")
    require(helper.is_file() and not helper.is_symlink(), "controller_validator_missing")
    spec = importlib.util.spec_from_file_location("opsark_controller_acceptance", helper)
    require(spec is not None and spec.loader is not None, "controller_validator_missing")
    if spec is None or spec.loader is None:
        raise ValidationError("controller_validator_missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_sources(args):
    """Preserve the established exact source/runtime contract and bind this runner."""
    outside = Path(__file__).resolve()
    packaged = args.source / "tests" / outside.name
    require(
        outside.name == "linux_product_validation.py"
        and outside.is_file()
        and not outside.is_symlink()
        and packaged.is_file()
        and not packaged.is_symlink()
        and _sha(outside) == _sha(packaged),
        "product_validator_source_mismatch",
    )
    # The reviewed outside controller helper verifies its own/package-helper
    # bytes, source archive/tree, official candidate archive and runtime closure.
    return _controller_helper().verify_sources(args)


def selection(profile):
    require(profile in PROFILES, "profile_invalid")
    if profile == "readonly-policy-root":
        return ROOT_NODES, ()
    if profile == OBSERVATION_PROFILE:
        return tuple("tests/" + name for name in OBSERVATION_FILES), ()
    return tuple("tests/" + name for name in FILES), ROOT_NODES


def scope_manifest(source, profile):
    selected, exclusions = selection(profile)
    available = {path.name for path in (source / "tests").glob("test_*.py") if path.is_file()}
    files = OBSERVATION_FILES if profile == OBSERVATION_PROFILE else FILES
    require(set(files) <= available, "matrix_test_file_missing")
    partial = set() if profile == OBSERVATION_PROFILE else {"test_readonly_guard.py"}
    covered = set(files) if profile != "readonly-policy-root" else partial
    return {
        "id": PROFILES[profile],
        "profile": profile,
        "complete_test_files": ["tests/" + name for name in files if name in covered - partial],
        "partial_test_files": ["tests/" + name for name in sorted(partial)],
        "selectors": list(selected),
        "root_only_nodes": list(ROOT_NODES),
        "required_linux_flock_node": FLOCK_NODE
        if profile == "general-controller-nonroot"
        else OBSERVATION_NATIVE_NODES[1]
        if profile == OBSERVATION_PROFILE
        else None,
        "required_native_nodes": list(OBSERVATION_NATIVE_NODES)
        if profile == OBSERVATION_PROFILE
        else [],
        "required_loopback_ssh_nodes": list(LOOPBACK_SSH_NODES)
        if profile == "general-controller-nonroot"
        else [],
        "required_native_curl_nodes": list(NATIVE_CURL_NODES)
        if profile == "general-controller-nonroot"
        else [],
        "excluded_nodes": [
            {"node": node, "reason": "geteuid()==0 decorator; separate root profile required"}
            for node in exclusions
        ],
        "partial_file_selection": (
            "every collected sibling except the declared root-only node"
            if profile == "general-controller-nonroot"
            else "every collected node in the fixed observation files; no exclusions"
            if profile == OBSERVATION_PROFILE
            else "only the declared root-only node; every sibling remains uncovered"
        ),
        "uncovered_test_files": ["tests/" + name for name in sorted(available - covered)],
        "full_product_suite": False,
        "expected_cases": "frozen from this scope in the same Linux environment",
        "maximum_seconds": MAX_SECONDS,
        "resource_limits": dict(CGROUP_LIMITS),
        "transport_policy": {
            "loopback_literals": ["127.0.0.1", "::1"],
            "nonloopback_allowed": False,
            "docker_client_allowed": False,
            "audit_coverage": (
                "pytest_parent_httpx_paramiko_popen_native_curl_and_fixed_timeout_python"
            ),
        },
        "browser_preflight_required": False,
        "native_curl_required": profile == "general-controller-nonroot",
        "native_timeout_required": profile == OBSERVATION_PROFILE,
    }


def linux_metadata(profile):
    require(profile in PROFILES, "profile_invalid")
    require(sys.platform == "linux" and sys.version_info[:2] == (3, 13), "linux_python_required")
    status = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        name, _, value = line.partition(":")
        status[name] = value.strip()
    uid = 0 if profile == "readonly-policy-root" else 10001
    require(
        os.geteuid() == uid
        and os.getegid() == uid
        and set(status["Uid"].split()) == {str(uid)}
        and set(status["Gid"].split()) == {str(uid)},
        "isolated_profile_identity_required",
    )
    require(
        all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd")),
        "capabilities_present",
    )
    require(status["NoNewPrivs"] == "1", "no_new_privileges_required")
    devices = sorted(path.name for path in Path("/sys/class/net").iterdir())
    require(devices == ["lo"], "loopback_network_only_required")
    require(
        not any(Path(name).exists() for name in ("/var/run/docker.sock", "/run/docker.sock")),
        "docker_socket_present",
    )
    root_mounts = [
        line.split()
        for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
        if len(line.split()) > 5 and line.split()[4] == "/"
    ]
    require(
        len(root_mounts) == 1 and "ro" in root_mounts[0][5].split(","),
        "readonly_root_required",
    )
    limits = {
        name: (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii").strip()
        for name in CGROUP_LIMITS
    }
    require(limits == CGROUP_LIMITS, "fixed_cgroup_limits_required")
    base = _controller_helper()
    # The legacy nonroot metadata contract includes the exact Linux family and
    # package versions; the root profile differs only in its required UID.
    distro = base.platform.freedesktop_os_release()
    require(distro.get("ID") in {"debian", "ubuntu"}, "unsupported_linux_family")
    return {
        "system": base.platform.system(),
        "machine": base.platform.machine(),
        "python": base.platform.python_version(),
        "sqlite": base.sqlite3.sqlite_version,
        "distribution": distro.get("ID"),
        "distribution_version": distro.get("VERSION_ID"),
        "pytest_package": base.importlib.metadata.version("pytest"),
        "httpx_package": base.importlib.metadata.version("httpx"),
        "paramiko_package": base.importlib.metadata.version("paramiko"),
        "uid": uid,
        "gid": uid,
        "effective_capabilities": "0",
        "no_new_privileges": True,
        "readonly_root": True,
        "network_devices": devices,
        "resource_limits": limits,
    }


def clean_environment(output):
    environment = _controller_helper().clean_environment(output)
    # PYTEST_ADDOPTS could shrink the fixed scope or stop after the first result.
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "PYTHONSTARTUP"):
        environment.pop(key, None)
    environment.update({"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0"})
    return environment


def native_curl_preflight(profile):
    require(profile in PROFILES, "profile_invalid")
    if profile != "general-controller-nonroot":
        return {"required": False}
    binary = shutil.which("curl")
    if binary is None:
        raise ValidationError("native_curl_required")
    result = subprocess.run(  # noqa: S603 -- fixed native tool version, no URL or network.
        [binary, "--disable", "--version"],
        capture_output=True,
        check=False,
        timeout=5,
        env={key: value for key, value in os.environ.items() if not key.startswith("CURL_")},
    )
    require(
        result.returncode == 0
        and len(result.stdout) <= 32768
        and result.stdout.startswith(b"curl "),
        "native_curl_preflight_failed",
    )
    return {"required": True, "binary_sha256": _sha(Path(binary)), "available": True}


def native_timeout_preflight(profile):
    """The observation fixtures require this exact GNU executable, never a skip."""
    require(profile in PROFILES, "profile_invalid")
    if profile != OBSERVATION_PROFILE:
        return {"required": False}
    binary = "/usr/bin/timeout"
    require(Path(binary).is_file(), "native_timeout_required")
    result = subprocess.run(  # noqa: S603 -- fixed GNU version probe; no command or network.
        [binary, "--version"],
        capture_output=True,
        check=False,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0
        and not result.stderr
        and len(result.stdout) <= 32768
        and result.stdout.startswith(b"timeout (GNU coreutils) "),
        "native_timeout_preflight_failed",
    )
    return {"required": True, "binary_sha256": _sha(Path(binary)), "available": True}


def _timeout_python_fixture(arguments, executable=None):
    """Only the two fixed local reader fixtures; never arbitrary timeout/native argv."""
    return (
        isinstance(arguments, (list, tuple))
        and len(arguments) == 8
        and list(arguments[:3]) == ["/usr/bin/timeout", "-k", "1s"]
        and type(arguments[3]) is str
        and arguments[3] in {"0.1s", "3s"}
        and list(arguments[4:7]) == [sys.executable, "-I", "-c"]
        and type(arguments[7]) is str
        and len(arguments[7]) <= 8192
        and executable in (None, "/usr/bin/timeout")
    )


def _curl_is_loopback(arguments):
    """Admit the native health fixture's bounded GET, without config/routing options."""
    if not isinstance(arguments, (list, tuple)) or len(arguments) < 3:
        return False
    args = list(arguments[1:])
    if args[0] != "--disable" or args.count("--") != 1 or args[-2] != "--":
        return False
    options = {"--silent", "--show-error", "--globoff"}
    values = {
        "--connect-timeout": {"2"},
        "--max-time": {"4"},
        "--max-filesize": {"8192"},
        "--max-redirs": {"0"},
        "--noproxy": {"*"},
        "--proto": {"=http"},
        "--request": {"GET"},
    }
    seen = set()
    index = 1
    while index < len(args) - 2:
        name = args[index]
        if name in options and name not in seen:
            seen.add(name)
            index += 1
        elif name in values and name not in seen and index + 1 < len(args) - 2:
            if args[index + 1] not in values[name]:
                return False
            seen.add(name)
            index += 2
        elif name in {"--header", "--write-out"} and index + 1 < len(args) - 2:
            index += 2
        else:
            return False
    try:
        url = urlsplit(args[-1])
    except ValueError:
        return False
    return (
        seen == options | set(values)
        and url.scheme == "http"
        and url.hostname in {"127.0.0.1", "::1"}
        and url.username is None
        and url.password is None
    )


@contextmanager
def offline_transports(profile="general-controller-nonroot"):
    """Reuse parent HTTPX/Paramiko/client denial and close native curl routing."""
    require(profile in PROFILES, "profile_invalid")
    base = _controller_helper()
    with base._offline_transports() as attempts:
        attempts.update(
            {
                "native_loopback_http_attempts": 0,
                "unapproved_native_attempts": 0,
                "local_timeout_attempts": 0,
            }
        )
        original = subprocess.Popen.__init__

        def guarded(self, args, *positionals, **kwargs):
            kind = base._spawn_kind(args, kwargs.get("executable"))
            if kind is not None:
                return original(self, args, *positionals, **kwargs)
            program = args[0] if isinstance(args, (list, tuple)) and args else None
            effective = kwargs.get("executable", program)
            if effective is not None and Path(os.fsdecode(effective)).name == "curl":
                if not _curl_is_loopback(args) or kwargs.get("shell", False):
                    attempts["nonloopback_http_attempts"] += 1
                    raise ValidationError("native_nonloopback_http_forbidden")
                attempts["native_loopback_http_attempts"] += 1
            elif (
                profile == OBSERVATION_PROFILE
                and not kwargs.get("shell", False)
                and _timeout_python_fixture(args, kwargs.get("executable"))
            ):
                attempts["local_timeout_attempts"] += 1
            elif effective != sys.executable or kwargs.get("shell", False):
                attempts["unapproved_native_attempts"] += 1
                raise ValidationError("unapproved_native_client_forbidden")
            return original(self, args, *positionals, **kwargs)

        subprocess.Popen.__init__ = guarded
        try:
            yield attempts
        finally:
            subprocess.Popen.__init__ = original


def transport_audit_accepted(value, profile, *, collection=False):
    expected = set(_controller_helper().EMPTY_TRANSPORT_AUDIT) | {
        "native_loopback_http_attempts",
        "unapproved_native_attempts",
        "local_timeout_attempts",
    }
    return (
        profile in PROFILES
        and type(value) is dict
        and set(value) == expected
        and all(type(count) is int and count >= 0 for count in value.values())
        and all(
            value[key] == 0
            for key in (
                "nonloopback_http_attempts",
                "nonloopback_ssh_attempts",
                "real_docker_attempts",
                "unapproved_native_attempts",
            )
        )
        and (
            collection
            or profile == "readonly-policy-root"
            or profile == OBSERVATION_PROFILE
            and value["local_timeout_attempts"] >= 1
            or profile == "general-controller-nonroot"
            and value["loopback_ssh_attempts"] >= 1
            and value["native_loopback_http_attempts"] >= 4
        )
    )


def freeze_collection(profile, nodes, deselected, environment):
    selectors, exclusions = selection(profile)
    require(
        type(nodes) is list
        and bool(nodes)
        and all(
            type(node) is str and len(node) <= MAX_NODE_ID_LENGTH and "::" in node for node in nodes
        )
        and len(set(nodes)) == len(nodes),
        "collected_nodes_invalid",
    )
    require(sorted(deselected) == sorted(exclusions), "exclusion_set_changed")
    if profile == "readonly-policy-root":
        require(nodes == list(ROOT_NODES), "root_scope_changed")
    elif profile == OBSERVATION_PROFILE:
        require(
            {node.split("::", 1)[0] for node in nodes} == set(selectors)
            and set(OBSERVATION_NATIVE_NODES) <= set(nodes),
            "observation_scope_changed",
        )
    else:
        require(
            {node.split("::", 1)[0] for node in nodes} == set(selectors)
            and not set(nodes) & set(ROOT_NODES)
            and {FLOCK_NODE, *NATIVE_CURL_NODES, *LOOPBACK_SSH_NODES} <= set(nodes),
            "general_scope_changed",
        )
    payload = {
        "schema": "opsark-linux-product-frozen-nodes/v1",
        "scope": PROFILES[profile],
        "profile": profile,
        "nodes": nodes,
        "excluded_nodes": list(exclusions),
        "environment": environment,
    }
    frozen = payload | {"sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
    require(len(_canonical(frozen)) <= MAX_JSON_BYTES, "frozen_manifest_too_large")
    return frozen


def validate_frozen(value, profile, environment):
    require(
        type(value) is dict
        and set(value)
        == {"schema", "scope", "profile", "nodes", "excluded_nodes", "environment", "sha256"},
        "frozen_manifest_invalid",
    )
    require(
        value == freeze_collection(profile, value["nodes"], value["excluded_nodes"], environment),
        "frozen_collection_changed",
    )
    return value


class CollectionPlugin:
    def __init__(self, profile, environment, expected=None):
        self.profile = profile
        self.environment = environment
        self.expected = expected
        self.deselected = []
        self.frozen = None

    def pytest_deselected(self, items):
        self.deselected.extend(item.nodeid for item in items)

    def pytest_collection_finish(self, session):
        self.frozen = freeze_collection(
            self.profile, [item.nodeid for item in session.items], self.deselected, self.environment
        )
        if self.expected is not None:
            require(self.frozen == self.expected, "execution_collection_changed")
        for item in session.items:
            item.user_properties.append(("validation_nodeid", item.nodeid))


def classify_junit(path, exit_code, frozen):
    require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, "junit_missing_or_large")
    raw = path.read_bytes().decode("utf-8")
    require(
        "<!DOCTYPE" not in raw.upper() and "<!ENTITY" not in raw.upper(),
        "junit_declaration_refused",
    )
    tree = ET.fromstring(raw)  # noqa: S314 -- bounded own UTF-8 JUnit, DTD/entities rejected.
    cases = list(tree.iter("testcase"))
    identities = []
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for case in cases:
        nodeids = [
            prop.get("value")
            for prop in case.findall("./properties/property")
            if prop.get("name") == "validation_nodeid"
        ]
        require(len(nodeids) == 1, "junit_node_identity_missing_or_duplicated")
        identities.extend(nodeids)
        outcome = next(
            (
                name
                for tag, name in (
                    ("failure", "failed"),
                    ("error", "errors"),
                    ("skipped", "skipped"),
                )
                if case.find(tag) is not None
            ),
            "passed",
        )
        counts[outcome] += 1
    expected = frozen["nodes"]
    exact = len(identities) == len(set(identities)) and set(identities) == set(expected)
    ordered = identities == expected
    return {
        "testcases": len(cases),
        **counts,
        "frozen_nodes_sha256": frozen["sha256"],
        "exact_frozen_nodes_executed": exact,
        "ordered_frozen_nodes_executed": ordered,
        "accepted": exit_code == 0 and exact and ordered and counts["passed"] == len(expected),
    }


def _pytest_child(source, output, profile, mode):
    environment = clean_environment(output)
    os.environ.clear()
    os.environ.update(environment)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(source / "src"), str(source / "tests"), str(source)]
    platform = linux_metadata(profile)
    expected = (
        validate_frozen(_read_json(output / "frozen-nodes.json"), profile, platform)
        if mode == "execute"
        else None
    )
    import pytest

    plugin = CollectionPlugin(profile, platform, expected)
    selectors, exclusions = selection(profile)
    arguments = [
        *selectors,
        *("--deselect=" + node for node in exclusions),
        "-q",
        "-o",
        "addopts=",
        "-o",
        "cache_dir=" + str(output / "pytest-cache"),
        "--basetemp=/tmp/opsark-linux-product-" + secrets.token_hex(12),
    ]
    arguments += (
        ["--collect-only"] if mode == "collect" else ["--junitxml=" + str(output / "junit.xml")]
    )
    with offline_transports(profile) as attempts:
        try:
            code = int(pytest.main(arguments, plugins=[plugin]))
            require(plugin.frozen is not None, "collection_not_completed")
            if mode == "collect":
                require(code == 0, "collection_failed")
                _write_json(output / "frozen-nodes.json", plugin.frozen)
            return code
        finally:
            _write_json(output / (mode + "-audit.json"), attempts)


def _run_child(args, mode, remaining):
    require(remaining > 0, "validation_deadline_exceeded")
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--pytest-child",
        str(args.source),
        str(args.output),
        args.profile,
        mode,
    ]
    with (args.output / (mode + ".private.log")).open("xb") as log:
        process = subprocess.Popen(  # noqa: S603 -- owned interpreter, fixed selectors and local paths.
            command,
            cwd=args.source,
            env=clean_environment(args.output),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            if process.poll() is None and os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise ValidationError("pytest_deadline_exceeded") from None


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-archive", "identity", "candidate", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    for name in ("commit", "source-sha256", "candidate-sha256"):
        result.add_argument("--expected-" + name, required=True)
    result.add_argument("--profile", choices=tuple(PROFILES), required=True)
    return result


def run(args):
    began = time.monotonic()
    require(
        args.output.is_absolute()
        and args.output.is_dir()
        and not args.output.is_symlink()
        and args.output.resolve() == args.output
        and not any(args.output.iterdir())
        and not args.output.is_relative_to(args.source),
        "fresh_external_output_directory_required",
    )
    environment = clean_environment(args.output)
    os.environ.clear()
    os.environ.update(environment)
    sys.dont_write_bytecode = True
    record = {
        "schema": "opsark-linux-product-validation/v1",
        "completed": False,
        "phase": "starting",
        "validator_sha256": _sha(Path(__file__).resolve()),
    }
    before = None
    try:
        record["phase"] = "source_verification"
        before = verify_sources(args)
        record["source_before"] = before
        record["scope"] = scope_manifest(args.source, args.profile)
        record["platform"] = linux_metadata(args.profile)
        record["native_curl_preflight"] = native_curl_preflight(args.profile)
        record["native_timeout_preflight"] = native_timeout_preflight(args.profile)
        record["phase"] = "linux_collection"
        code = _run_child(args, "collect", MAX_SECONDS - (time.monotonic() - began))
        require(code == 0, "collection_failed")
        frozen = validate_frozen(
            _read_json(args.output / "frozen-nodes.json"), args.profile, record["platform"]
        )
        record["collection"] = {"nodes": len(frozen["nodes"]), "sha256": frozen["sha256"]}
        audit = _read_json(args.output / "collect-audit.json")
        require(transport_audit_accepted(audit, args.profile, collection=True), "collection_egress")
        record["collection_audit"] = audit
        require(verify_sources(args) == before, "source_changed_during_collection")
        record["phase"] = "pytest"
        code = _run_child(args, "execute", MAX_SECONDS - (time.monotonic() - began))
        record["pytest_exit_code"] = code
        record["pytest"] = classify_junit(args.output / "junit.xml", code, frozen)
        audit = _read_json(args.output / "execute-audit.json")
        require(transport_audit_accepted(audit, args.profile), "remote_transport_or_missing_wire")
        record["http_audit"] = audit
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
    finally:
        # Even a failed/aborted test phase must leave source and runtime intact.
        if before is not None:
            try:
                after = verify_sources(args)
                require(before == after, "source_changed_during_validation")
                record["source_after"], record["source_unchanged"] = after, True
            except Exception:
                record["completed"], record["phase"] = False, "source_verification_failed"
                record["failure_code"] = "source_changed_or_unverifiable_after_validation"
    elapsed = time.monotonic() - began
    if elapsed > MAX_SECONDS:
        record["completed"], record["phase"] = False, "validation_deadline_exceeded"
        record["failure_code"] = "validation_deadline_exceeded"
    record["elapsed_seconds"] = round(elapsed, 3)
    _write_json(args.output / "proof.json", record)
    return record


def main():
    if sys.argv[1:2] == ["--pytest-child"]:
        require(
            len(sys.argv) == 6
            and sys.argv[4] in PROFILES
            and sys.argv[5] in {"collect", "execute"},
            "child_declaration_invalid",
        )
        return _pytest_child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5])
    args = parser().parse_args()
    record = run(args)
    print(json.dumps({"completed": record["completed"], "phase": record["phase"]}, sort_keys=True))
    return 0 if record["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
