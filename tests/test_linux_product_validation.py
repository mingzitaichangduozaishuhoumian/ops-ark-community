"""Pure boundary checks and a synthetic pytest plugin round trip; no real Linux proof."""

import ast
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import httpx
import linux_product_validation as validation
import paramiko
import pytest

GENERAL = "general-controller-nonroot"
ROOT = "readonly-policy-root"
OBSERVATION = validation.OBSERVATION_PROFILE
ENVIRONMENT = {"synthetic_environment": True}


def nodes(profile=GENERAL):
    if profile == OBSERVATION:
        return [
            *("tests/" + name + "::test_synthetic" for name in validation.OBSERVATION_FILES),
            *validation.OBSERVATION_NATIVE_NODES,
        ]
    return [
        *("tests/" + name + "::test_synthetic" for name in validation.FILES),
        validation.FLOCK_NODE,
        *validation.NATIVE_CURL_NODES,
        *validation.LOOPBACK_SSH_NODES,
    ]


def frozen(profile=GENERAL):
    return validation.freeze_collection(
        profile,
        list(validation.ROOT_NODES) if profile == ROOT else nodes(profile),
        list(validation.ROOT_NODES) if profile == GENERAL else [],
        ENVIRONMENT,
    )


def junit(path, manifest, *, skip=None, fail=None, omit=None, duplicate=None, identities=True):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    selected = [node for node in manifest["nodes"] if node != omit]
    if duplicate is not None:
        selected.append(duplicate)
    for node in selected:
        case = ET.SubElement(suite, "testcase", {"name": node.split("::")[-1]})
        if identities:
            props = ET.SubElement(case, "properties")
            ET.SubElement(props, "property", {"name": "validation_nodeid", "value": node})
        if node == skip:
            ET.SubElement(case, "skipped")
        if node == fail:
            ET.SubElement(case, "failure")
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


def empty_audit():
    return validation._controller_helper().EMPTY_TRANSPORT_AUDIT | {
        "native_loopback_http_attempts": 0,
        "unapproved_native_attempts": 0,
        "local_timeout_attempts": 0,
    }


def passing_audit():
    return empty_audit() | {"loopback_ssh_attempts": 1, "native_loopback_http_attempts": 4}


def curl_arguments(url="http://127.0.0.1:1234/healthz"):
    return [
        "/synthetic/curl",
        "--disable",
        "--silent",
        "--show-error",
        "--globoff",
        "--connect-timeout",
        "2",
        "--max-time",
        "4",
        "--max-filesize",
        "8192",
        "--max-redirs",
        "0",
        "--noproxy",
        "*",
        "--proto",
        "=http",
        "--request",
        "GET",
        "--header",
        "Host: fixture.example",
        "--header",
        "Accept-Encoding: identity",
        "--write-out",
        "\nOPSARK_HTTP_STATUS:%{http_code}\n",
        "--",
        url,
    ]


def test_closed_scope_keeps_linux_flock_nonroot_and_only_actual_decorator_node_root(tmp_path):
    assert len(validation.FILES) == 18 and len(set(validation.FILES)) == 18
    assert {
        "test_nginx_dependencies.py",
        "test_nginx_dependencies_api.py",
        "test_nginx_dependency_scope.py",
    } <= set(validation.FILES)
    assert all("browser" not in name and "source_gate" not in name for name in validation.FILES)
    assert validation.MAX_SECONDS == 900
    assert validation.CGROUP_LIMITS == {
        "cpu.max": "100000 100000",
        "memory.max": "1073741824",
        "memory.swap.max": "0",
        "pids.max": "256",
    }
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in (*validation.FILES, "test_outside.py"):
        (tests / name).write_text("# synthetic public source\n")
    general = validation.scope_manifest(tmp_path, GENERAL)
    root = validation.scope_manifest(tmp_path, ROOT)
    assert general["full_product_suite"] is False and root["full_product_suite"] is False
    assert len(general["complete_test_files"]) == 17
    assert general["partial_test_files"] == ["tests/test_readonly_guard.py"]
    assert general["required_linux_flock_node"] == validation.FLOCK_NODE
    assert [entry["node"] for entry in general["excluded_nodes"]] == list(validation.ROOT_NODES)
    assert general["uncovered_test_files"] == ["tests/test_outside.py"]
    assert root["selectors"] == list(validation.ROOT_NODES)
    assert root["complete_test_files"] == [] and root["excluded_nodes"] == []
    assert len(root["uncovered_test_files"]) == 18
    assert general["browser_preflight_required"] is False
    assert general["native_curl_required"] is True and root["native_curl_required"] is False
    (tests / validation.FILES[0]).unlink()
    with pytest.raises(validation.ValidationError, match="matrix_test_file_missing"):
        validation.scope_manifest(tmp_path, GENERAL)


def test_observation_scope_is_exact_nine_complete_files_without_root_browser_or_git(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in (
        *validation.FILES,
        *validation.OBSERVATION_FILES,
        "test_nginx_dependencies_source_gate.py",
    ):
        (tests / name).write_text("# public synthetic scope\n")
    scope = validation.scope_manifest(tmp_path, OBSERVATION)
    assert len(scope["complete_test_files"]) == len(validation.OBSERVATION_FILES) == 9
    assert scope["selectors"] == ["tests/" + name for name in validation.OBSERVATION_FILES]
    assert scope["partial_test_files"] == scope["excluded_nodes"] == []
    assert scope["required_native_nodes"] == list(validation.OBSERVATION_NATIVE_NODES)
    assert scope["required_loopback_ssh_nodes"] == scope["required_native_curl_nodes"] == []
    assert scope["native_timeout_required"] is True and scope["native_curl_required"] is False
    assert scope["browser_preflight_required"] is False and scope["full_product_suite"] is False
    assert "tests/test_nginx_dependencies_source_gate.py" in scope["uncovered_test_files"]


@pytest.mark.parametrize("required", validation.OBSERVATION_NATIVE_NODES)
def test_observation_cannot_remove_real_selector_flock_pipe_process_or_symlink_node(required):
    selected = nodes(OBSERVATION)
    selected.remove(required)
    with pytest.raises(validation.ValidationError, match="observation_scope_changed"):
        validation.freeze_collection(OBSERVATION, selected, [], ENVIRONMENT)


def test_observation_cannot_add_exclusions_or_borrow_general_nodes():
    with pytest.raises(validation.ValidationError, match="exclusion_set_changed"):
        validation.freeze_collection(
            OBSERVATION, nodes(OBSERVATION), list(validation.ROOT_NODES), ENVIRONMENT
        )
    with pytest.raises(validation.ValidationError, match="observation_scope_changed"):
        validation.freeze_collection(
            OBSERVATION, nodes(OBSERVATION) + [validation.FLOCK_NODE], [], ENVIRONMENT
        )


def test_source_verification_binds_new_runner_and_delegates_complete_existing_contract(
    tmp_path, monkeypatch
):
    source, outside = tmp_path / "source", tmp_path / "validators"
    (source / "tests").mkdir(parents=True)
    outside.mkdir()
    name = "linux_product_validation.py"
    for parent in (source / "tests", outside):
        (parent / name).write_bytes(b"# reviewed synthetic validator\n")
    calls = []
    args = SimpleNamespace(source=source)
    result = {"source": {"files": 123}, "runtime": {"files": 100}}
    monkeypatch.setattr(validation, "__file__", str(outside / name))
    monkeypatch.setattr(
        validation,
        "_controller_helper",
        lambda: SimpleNamespace(verify_sources=lambda value: calls.append(value) or result),
    )
    assert validation.verify_sources(args) == result and calls == [args]
    (source / "tests" / name).write_bytes(b"# changed uncommitted bytes\n")
    with pytest.raises(validation.ValidationError, match="product_validator_source_mismatch"):
        validation.verify_sources(args)
    assert calls == [args]


def test_environment_clears_ambient_authority_and_pytest_scope_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("OPSARK_AI_KEY", "synthetic-do-not-propagate")
    monkeypatch.setenv("OPSARK_DEFENSE_WORKER_ENABLED", "true")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k only-one-test --maxfail=1")
    monkeypatch.setenv("PYTEST_PLUGINS", "synthetic_unreviewed_plugin")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    result = validation.clean_environment(tmp_path)
    assert {key for key in result if key.startswith("OPSARK_")} == {
        "OPSARK_TOKEN",
        "OPSARK_DATA_DIR",
    }
    assert result["OPSARK_DATA_DIR"] == str(tmp_path / "bootstrap-data")
    assert result["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert result["PYTHONDONTWRITEBYTECODE"] == "1"
    assert not {"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"} & result.keys()


@pytest.mark.parametrize("profile", [GENERAL, ROOT, OBSERVATION])
def test_collection_is_frozen_by_exact_nodes_environment_and_digest(profile):
    value = frozen(profile)
    payload = {key: item for key, item in value.items() if key != "sha256"}
    assert value["sha256"] == hashlib.sha256(validation._canonical(payload)).hexdigest()
    assert validation.validate_frozen(value, profile, ENVIRONMENT) == value
    changed = value | {"nodes": value["nodes"][:-1]}
    with pytest.raises(validation.ValidationError):
        validation.validate_frozen(changed, profile, ENVIRONMENT)
    with pytest.raises(validation.ValidationError, match="frozen_collection_changed"):
        validation.validate_frozen(value, profile, {"different_image": True})


def test_long_parameterized_node_keeps_exact_identity_through_frozen_and_junit(tmp_path):
    selected = nodes()
    # The real Linux collection included a 5,094-character parameterized node.
    # Use synthetic text, preserving the entire identity rather than truncating it.
    prefix = "tests/test_ai.py::test_synthetic["
    long_node = prefix + "x" * (5094 - len(prefix) - 1) + "]"
    selected[0] = long_node
    value = validation.freeze_collection(
        GENERAL, selected, list(validation.ROOT_NODES), ENVIRONMENT
    )
    assert value["nodes"][0] == long_node
    decoded = json.loads(validation._canonical(value))
    assert validation.validate_frozen(decoded, GENERAL, ENVIRONMENT) == value
    result = validation.classify_junit(junit(tmp_path / "long.xml", value), 0, value)
    assert result["accepted"] and result["testcases"] == len(selected)
    changed = value | {"nodes": [long_node[:-1] + "changed]", *selected[1:]]}
    with pytest.raises(validation.ValidationError, match="frozen_collection_changed"):
        validation.validate_frozen(changed, GENERAL, ENVIRONMENT)


def test_collection_still_bounds_individual_identity_and_complete_manifest():
    selected = nodes()
    selected[0] += "x" * validation.MAX_NODE_ID_LENGTH
    with pytest.raises(validation.ValidationError, match="collected_nodes_invalid"):
        validation.freeze_collection(GENERAL, selected, list(validation.ROOT_NODES), ENVIRONMENT)
    selected = nodes() + [
        "tests/test_ai.py::test_synthetic[" + str(index) + "x" * 12_000 + "]"
        for index in range(180)
    ]
    assert all(len(node) < validation.MAX_NODE_ID_LENGTH for node in selected)
    with pytest.raises(validation.ValidationError, match="frozen_manifest_too_large"):
        validation.freeze_collection(GENERAL, selected, list(validation.ROOT_NODES), ENVIRONMENT)


@pytest.mark.parametrize(
    "change", ["duplicate", "file", "flock", "native", "ssh", "exclude", "root"]
)
def test_nonroot_collection_cannot_shrink_or_change_the_declarative_scope(change):
    selected, excluded = nodes(), list(validation.ROOT_NODES)
    if change == "duplicate":
        selected.append(selected[0])
    elif change == "file":
        selected = [node for node in selected if not node.startswith("tests/test_ai.py::")]
    elif change == "flock":
        selected.remove(validation.FLOCK_NODE)
    elif change == "native":
        selected.remove(validation.NATIVE_CURL_NODES[-1])
    elif change == "ssh":
        selected.remove(validation.LOOPBACK_SSH_NODES[0])
    elif change == "exclude":
        excluded = []
    else:
        selected.extend(validation.ROOT_NODES)
    with pytest.raises(validation.ValidationError):
        validation.freeze_collection(GENERAL, selected, excluded, ENVIRONMENT)


def test_collection_hook_requires_identical_execution_order_and_nodes():
    manifest = frozen()
    plugin = validation.CollectionPlugin(GENERAL, ENVIRONMENT, manifest)
    plugin.pytest_deselected([SimpleNamespace(nodeid=node) for node in validation.ROOT_NODES])
    items = [SimpleNamespace(nodeid=node, user_properties=[]) for node in manifest["nodes"]]
    plugin.pytest_collection_finish(SimpleNamespace(items=items))
    assert all(item.user_properties == [("validation_nodeid", item.nodeid)] for item in items)
    with pytest.raises(validation.ValidationError, match="execution_collection_changed"):
        plugin.pytest_collection_finish(SimpleNamespace(items=list(reversed(items))))


@pytest.mark.parametrize("profile", [GENERAL, ROOT, OBSERVATION])
def test_junit_requires_all_frozen_identities_and_zero_skips(tmp_path, profile):
    manifest = frozen(profile)
    path = tmp_path / "junit.xml"
    assert validation.classify_junit(junit(path, manifest), 0, manifest)["accepted"]
    node = manifest["nodes"][0]
    for kwargs in ({"skip": node}, {"fail": node}, {"omit": node}, {"duplicate": node}):
        result = validation.classify_junit(junit(path, manifest, **kwargs), 0, manifest)
        assert not result["accepted"]
    assert not validation.classify_junit(junit(path, manifest), 1, manifest)["accepted"]
    reordered = manifest | {"nodes": list(reversed(manifest["nodes"]))}
    order_result = validation.classify_junit(junit(path, reordered), 0, manifest)
    assert order_result["ordered_frozen_nodes_executed"] is (profile == ROOT)
    assert order_result["accepted"] is (profile == ROOT)
    with pytest.raises(validation.ValidationError, match="junit_node_identity"):
        validation.classify_junit(junit(path, manifest, identities=False), 0, manifest)
    path.write_text('<!DOCTYPE test [<!ENTITY value "unsafe">]><testsuites/>')
    with pytest.raises(validation.ValidationError, match="junit_declaration_refused"):
        validation.classify_junit(path, 0, manifest)


def test_transport_audit_requires_native_and_ssh_wire_for_general_scope():
    assert validation.transport_audit_accepted(passing_audit(), GENERAL)
    assert validation.transport_audit_accepted(empty_audit(), GENERAL, collection=True)
    assert validation.transport_audit_accepted(empty_audit(), ROOT)
    assert not validation.transport_audit_accepted(empty_audit(), GENERAL)
    assert not validation.transport_audit_accepted(
        passing_audit() | {"native_loopback_http_attempts": 3}, GENERAL
    )
    for key in (
        "nonloopback_http_attempts",
        "nonloopback_ssh_attempts",
        "real_docker_attempts",
        "unapproved_native_attempts",
    ):
        assert not validation.transport_audit_accepted(passing_audit() | {key: 1}, GENERAL)
    assert not validation.transport_audit_accepted(
        passing_audit() | {"loopback_ssh_attempts": True}, GENERAL
    )
    assert not validation.transport_audit_accepted(passing_audit() | {"unknown": 0}, GENERAL)


def test_observation_audit_needs_real_local_timeout_not_fictional_ssh_or_native_http():
    audit = empty_audit() | {"local_timeout_attempts": 1}
    assert audit["loopback_ssh_attempts"] == audit["native_loopback_http_attempts"] == 0
    assert validation.transport_audit_accepted(audit, OBSERVATION)
    assert validation.transport_audit_accepted(empty_audit(), OBSERVATION, collection=True)
    assert not validation.transport_audit_accepted(empty_audit(), OBSERVATION)
    for key in (
        "nonloopback_http_attempts",
        "nonloopback_ssh_attempts",
        "real_docker_attempts",
        "unapproved_native_attempts",
    ):
        assert not validation.transport_audit_accepted(audit | {key: 1}, OBSERVATION)
    assert not validation.transport_audit_accepted(
        audit | {"local_timeout_attempts": True}, OBSERVATION
    )


def timeout_arguments():
    return [
        "/usr/bin/timeout",
        "-k",
        "1s",
        "0.1s",
        sys.executable,
        "-I",
        "-c",
        "import time;time.sleep(10)",
    ]


def test_observation_timeout_permission_is_narrow_and_other_profiles_keep_it_denied(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess.Popen, "__del__", lambda self: None)
    monkeypatch.setattr(subprocess.Popen, "__init__", lambda self, args, **kw: calls.append(args))
    with validation.offline_transports(OBSERVATION) as audit:
        subprocess.Popen(timeout_arguments())  # noqa: S603 -- fake constructor only.
        assert audit["local_timeout_attempts"] == 1
        assert audit["native_loopback_http_attempts"] == audit["loopback_ssh_attempts"] == 0
    for profile in (GENERAL, ROOT):
        with (
            validation.offline_transports(profile),
            pytest.raises(RuntimeError, match="unapproved_native_client_forbidden"),
        ):
            subprocess.Popen(timeout_arguments())  # noqa: S603 -- denied before fake constructor.
    assert len(calls) == 1


@pytest.mark.parametrize(
    "change", ["path", "duration", "kill", "interpreter", "flags", "extra", "shell", "executable"]
)
def test_timeout_wrapper_cannot_authorize_other_commands_or_parameters(monkeypatch, change):
    monkeypatch.setattr(subprocess.Popen, "__del__", lambda self: None)
    monkeypatch.setattr(
        subprocess.Popen, "__init__", lambda *args, **kw: pytest.fail("unapproved spawn")
    )
    arguments, kwargs = timeout_arguments(), {}
    if change == "path":
        arguments[0] = "/unapproved/timeout"
    elif change == "duration":
        arguments[3] = "300s"
    elif change == "kill":
        arguments[2] = "10s"
    elif change == "interpreter":
        arguments[4] = "/synthetic/curl"
    elif change == "flags":
        arguments[5] = "-m"
    elif change == "extra":
        arguments.append("extra")
    else:
        kwargs[change] = True if change == "shell" else "/unapproved/timeout"
    with validation.offline_transports(OBSERVATION), pytest.raises(RuntimeError):
        subprocess.Popen(arguments, **kwargs)  # noqa: S603 -- blocked before fake constructor.


@pytest.mark.parametrize("url", ["http://127.0.0.1:1234/healthz", "http://[::1]:1234/healthz"])
def test_native_curl_admits_only_literal_loopback_bounded_get(url):
    assert validation._curl_is_loopback(curl_arguments(url))


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:1234/",
        "https://127.0.0.1/",
        "http://example.invalid/",
        "http://127.1/",
        "http://2130706433/",
        "file:///etc/passwd",
        "http://user@127.0.0.1/",
    ],
)
def test_native_curl_rejects_aliases_external_urls_and_other_protocols(url):
    assert not validation._curl_is_loopback(curl_arguments(url))


@pytest.mark.parametrize(
    "arguments",
    [
        ["--proxy", "http://127.0.0.1:8888"],
        ["--connect-to", "::external.invalid:"],
        ["--location"],
        ["--config", "/synthetic/untrusted-curlrc"],
    ],
)
def test_native_curl_rejects_route_config_and_redirect_overrides(arguments):
    original = curl_arguments()
    assert not validation._curl_is_loopback(original[:-2] + arguments + original[-2:])


def test_parent_transport_guards_refuse_real_clients_and_restore_all_hooks(monkeypatch):
    calls = []
    # Prevent destructors from examining fake uninitialized Popen instances.
    monkeypatch.setattr(subprocess.Popen, "__del__", lambda self: None)
    monkeypatch.setattr(subprocess.Popen, "__init__", lambda self, args, **kw: calls.append(args))
    monkeypatch.setattr(
        paramiko.SSHClient, "connect", lambda self, hostname, **kw: calls.append(hostname)
    )
    monkeypatch.setattr(
        httpx.HTTPTransport, "handle_request", lambda self, req: httpx.Response(200)
    )
    before = (
        subprocess.Popen.__init__,
        paramiko.SSHClient.connect,
        httpx.HTTPTransport.handle_request,
    )
    with validation.offline_transports() as audit:
        # Construct only fake objects: patched Popen never launches a process.
        subprocess.Popen(curl_arguments())  # noqa: S603 -- patched fake Popen; no process.
        subprocess.Popen([sys.executable, "-I", "-c", "pass"])
        paramiko.SSHClient().connect("127.0.0.1")
        with pytest.raises(RuntimeError, match="native_nonloopback_http_forbidden"):
            subprocess.Popen(curl_arguments("http://localhost/"))  # noqa: S603 -- denied before fake Popen.
        with pytest.raises(RuntimeError, match="real_remote_client_forbidden"):
            subprocess.Popen(["/synthetic/docker", "ps"])
        with pytest.raises(RuntimeError, match="real_remote_client_forbidden"):
            subprocess.Popen(["/synthetic/ssh", "127.0.0.1"])
        with pytest.raises(RuntimeError, match="unapproved_native_client_forbidden"):
            subprocess.Popen(["/synthetic/sh", "-c", "curl http://example.invalid/"])
        with pytest.raises(RuntimeError, match="nonloopback_ssh_forbidden"):
            paramiko.SSHClient().connect("localhost")
        with (
            httpx.HTTPTransport() as transport,
            pytest.raises(RuntimeError, match="nonloopback_http_forbidden"),
        ):
            transport.handle_request(httpx.Request("GET", "http://example.invalid/"))
        assert audit["native_loopback_http_attempts"] == 1
        assert audit["loopback_ssh_attempts"] == 1
        assert audit["nonloopback_http_attempts"] == 2
        assert audit["real_docker_attempts"] == 1
        assert audit["nonloopback_ssh_attempts"] == 2
        assert audit["unapproved_native_attempts"] == 1
    assert before == (
        subprocess.Popen.__init__,
        paramiko.SSHClient.connect,
        httpx.HTTPTransport.handle_request,
    )


def fake_linux(monkeypatch, *, profile=GENERAL, changes=None):
    uid = 0 if profile == ROOT else 10001
    paths = {
        "/proc/self/status": (
            f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            "CapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nCapBnd:\t0\nNoNewPrivs:\t1\n"
        ),
        "/proc/self/mountinfo": "1 0 0:1 / / ro - overlay overlay ro\n",
        **{"/sys/fs/cgroup/" + key: value for key, value in validation.CGROUP_LIMITS.items()},
    }
    paths.update(changes or {})
    monkeypatch.setattr(validation.sys, "platform", "linux")
    monkeypatch.setattr(validation.sys, "version_info", (3, 13))
    monkeypatch.setattr(validation.os, "geteuid", lambda: uid, raising=False)
    monkeypatch.setattr(validation.os, "getegid", lambda: uid, raising=False)
    monkeypatch.setattr(Path, "read_text", lambda self, **kw: paths[self.as_posix()])
    monkeypatch.setattr(Path, "iterdir", lambda self: iter([Path("lo")]))
    monkeypatch.setattr(Path, "exists", lambda self: False)
    base = SimpleNamespace(
        platform=SimpleNamespace(
            freedesktop_os_release=lambda: {"ID": "debian", "VERSION_ID": "13"},
            system=lambda: "Linux",
            machine=lambda: "synthetic",
            python_version=lambda: "3.13.9",
        ),
        sqlite3=SimpleNamespace(sqlite_version="synthetic"),
        importlib=SimpleNamespace(metadata=SimpleNamespace(version=lambda name: "synthetic")),
    )
    monkeypatch.setattr(validation, "_controller_helper", lambda: base)


@pytest.mark.parametrize("profile", [GENERAL, ROOT, OBSERVATION])
def test_platform_contract_checks_actual_uid_capabilities_cgroups_and_readonly_root(
    monkeypatch, profile
):
    fake_linux(monkeypatch, profile=profile)
    result = validation.linux_metadata(profile)
    assert result["uid"] == (0 if profile == ROOT else 10001)
    assert result["resource_limits"] == validation.CGROUP_LIMITS
    assert result["effective_capabilities"] == "0" and result["readonly_root"] is True


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"/sys/fs/cgroup/cpu.max": "max 100000"}, "fixed_cgroup_limits_required"),
        ({"/sys/fs/cgroup/memory.max": "2147483648"}, "fixed_cgroup_limits_required"),
        ({"/sys/fs/cgroup/memory.swap.max": "max"}, "fixed_cgroup_limits_required"),
        ({"/sys/fs/cgroup/pids.max": "max"}, "fixed_cgroup_limits_required"),
        (
            {"/proc/self/mountinfo": "1 0 0:1 / / rw - overlay overlay rw\n"},
            "readonly_root_required",
        ),
    ],
)
def test_unbounded_or_changed_container_resources_are_refused(monkeypatch, changes, code):
    fake_linux(monkeypatch, changes=changes)
    with pytest.raises(validation.ValidationError, match=code):
        validation.linux_metadata(GENERAL)


def test_missing_native_curl_is_a_failed_preflight_never_a_skip(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: None)
    with pytest.raises(validation.ValidationError, match="native_curl_required"):
        validation.native_curl_preflight(GENERAL)
    assert validation.native_curl_preflight(ROOT) == {"required": False}
    assert validation.native_curl_preflight(OBSERVATION) == {"required": False}


def test_observation_requires_actual_fixed_gnu_timeout_preflight_without_install_or_skip(
    monkeypatch,
):
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    with pytest.raises(validation.ValidationError, match="native_timeout_required"):
        validation.native_timeout_preflight(OBSERVATION)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(validation, "_sha", lambda _: "a" * 64)
    calls = []

    def probe(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"timeout (GNU coreutils) 9.5\n", stderr=b"")

    monkeypatch.setattr(subprocess, "run", probe)
    assert validation.native_timeout_preflight(OBSERVATION) == {
        "required": True,
        "binary_sha256": "a" * 64,
        "available": True,
    }
    assert calls[0][0] == ["/usr/bin/timeout", "--version"] and calls[0][1]["timeout"] == 5
    assert validation.native_timeout_preflight(GENERAL) == {"required": False}
    assert validation.native_timeout_preflight(ROOT) == {"required": False}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=b"BusyBox timeout", stderr=b""
        ),
    )
    with pytest.raises(validation.ValidationError, match="native_timeout_preflight_failed"):
        validation.native_timeout_preflight(OBSERVATION)


def test_parser_has_no_arbitrary_selectors_or_resource_overrides():
    destinations = {action.dest for action in validation.parser()._actions}
    assert destinations == {
        "help",
        "source",
        "source_archive",
        "identity",
        "candidate",
        "output",
        "expected_commit",
        "expected_source_sha256",
        "expected_candidate_sha256",
        "profile",
    }


@pytest.mark.parametrize(
    "skip,change_source,over_budget",
    [(False, False, False), (True, False, False), (False, True, False), (False, False, True)],
)
def test_run_verifies_source_runtime_before_after_collection_and_even_failed_execution(
    tmp_path, monkeypatch, skip, change_source, over_budget
):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    args = SimpleNamespace(source=source, output=output, profile=GENERAL)
    snapshot = {"source": {"sha256": "synthetic"}, "runtime": {"sha256": "synthetic"}}
    verifications, modes = [], []

    def verify(_args):
        verifications.append(True)
        return snapshot if not change_source or len(verifications) < 3 else {"changed": True}

    manifest = frozen()

    def child(_args, mode, remaining):
        assert 0 < remaining <= 900
        modes.append(mode)
        if mode == "collect":
            validation._write_json(output / "frozen-nodes.json", manifest)
            validation._write_json(output / "collect-audit.json", empty_audit())
        else:
            junit(output / "junit.xml", manifest, skip=manifest["nodes"][0] if skip else None)
            validation._write_json(output / "execute-audit.json", passing_audit())
        return 0

    monkeypatch.setattr(validation, "verify_sources", verify)
    monkeypatch.setattr(validation, "scope_manifest", lambda *_: {"id": "synthetic"})
    monkeypatch.setattr(validation, "linux_metadata", lambda *_: ENVIRONMENT)
    monkeypatch.setattr(validation, "native_curl_preflight", lambda *_: {"synthetic": True})
    monkeypatch.setattr(validation, "_run_child", child)
    # run() is a standalone process entry; isolate its environment mutations here.
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    if over_budget:
        ticks = iter([0.0, 1.0, 2.0, 3.0, 901.0])
        monkeypatch.setattr(validation.time, "monotonic", lambda: next(ticks, 901.0))
    record = validation.run(args)
    assert modes == ["collect", "execute"] and len(verifications) == 3
    assert record["completed"] is (not skip and not change_source and not over_budget)
    assert json.loads((output / "proof.json").read_bytes()) == record
    if change_source:
        assert record["failure_code"] == "source_changed_or_unverifiable_after_validation"
    else:
        assert record["source_before"] == record["source_after"] == snapshot
        assert record["source_unchanged"] is True
    if over_budget:
        assert record["failure_code"] == "validation_deadline_exceeded"


def test_actual_pytest_plugin_round_trip_uses_only_synthetic_test_code(tmp_path):
    source = tmp_path / "source"
    tests = source / "tests"
    tests.mkdir(parents=True)
    (tests / "test_readonly_guard.py").write_text(
        "def test_actual_policy_symlink_permissions_and_parent_trust():\n    assert True\n"
    )
    code = (
        "import importlib.util,sys; from pathlib import Path; "
        f"spec=importlib.util.spec_from_file_location('validation',{validation.__file__!r}); "
        "v=importlib.util.module_from_spec(spec); spec.loader.exec_module(v); import pytest; "
        f"plugin=v.CollectionPlugin({ROOT!r},{ENVIRONMENT!r}); "
        f"result=pytest.main([{validation.ROOT_NODES[0]!r},'-q','--rootdir=.',"
        "'--junitxml=junit.xml',"
        "'-o','addopts='],plugins=[plugin]); "
        "v._write_json(Path('frozen.json'),plugin.frozen); sys.exit(int(result))"
    )
    environment = validation.clean_environment(tmp_path)
    result = subprocess.run(  # noqa: S603 -- own Python and synthetic local test only.
        [sys.executable, "-I", "-B", "-c", code],
        cwd=source,
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((source / "frozen.json").read_bytes())
    assert manifest == frozen(ROOT)
    assert validation.classify_junit(source / "junit.xml", 0, manifest)["accepted"]


def _child_import_setup():
    tree = ast.parse(Path(validation.__file__).read_bytes())
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_pytest_child"
    )
    return next(
        node
        for node in function.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "path"
            and isinstance(target.value.value, ast.Name)
            and target.value.value.id == "sys"
            for target in node.targets
        )
    )


def _isolated_import_fixture(tmp_path):
    source, ambient = tmp_path / "verified-source", tmp_path / "ambient"
    for path in (
        source / "src",
        source / "tests",
        source / "deploy/readonly",
        ambient / "deploy/readonly",
    ):
        path.mkdir(parents=True, exist_ok=True)
    (source / "pyproject.toml").write_text('[tool.pytest.ini_options]\npythonpath=["src"]\n')
    (source / "deploy/readonly/fixture.py").write_text('ORIGIN="verified-source"\n')
    (ambient / "deploy/__init__.py").write_text('raise RuntimeError("ambient-import-forbidden")\n')
    (source / "src/import_priority.py").write_text('ORIGIN="src"\n')
    (source / "tests/import_priority.py").write_text('ORIGIN="tests"\n')
    (source / "import_priority.py").write_text('ORIGIN="source-root"\n')
    (source / "tests/sibling_priority.py").write_text('ORIGIN="tests"\n')
    (source / "sibling_priority.py").write_text('ORIGIN="source-root"\n')
    (source / "tests/test_import_probe.py").write_text(
        "from deploy.readonly import fixture\n"
        "def test_verified_deployment_import():\n"
        ' assert fixture.ORIGIN=="verified-source"\n'
    )
    return source, ambient


def _isolated_probe(source, ambient, setup, cwd, *, collect=False):
    code = (
        "# isolated_import_probe\nimport json,sys\nfrom pathlib import Path\n"
        + f"source=Path({str(source)!r})\n"
        + ast.unparse(setup)
        + "\n"
        + "result={'isolated':sys.flags.isolated}\ntry:\n"
        " from deploy.readonly import fixture\n import import_priority,sibling_priority\n"
        " result.update(imported=True,origin=fixture.ORIGIN,"
        "src_first=import_priority.ORIGIN,tests_first=sibling_priority.ORIGIN,"
        "unique_root=sys.path.count(str(source)),"
        "verified_file=Path(fixture.__file__).resolve()=="
        "source/'deploy/readonly/fixture.py')\n"
        "except ModuleNotFoundError as error:\n"
        " result.update(imported=False,error_type=type(error).__name__,"
        "missing_name=error.name)\n"
    )
    if collect:
        code += (
            "import pytest\nresult['collect_exit']=int(pytest.main("
            "['tests/test_import_probe.py','--collect-only','-q','--rootdir=.',"
            "'-o','addopts=','--basetemp=' + str(source/'owned-pytest-temp')]))\n"
        )
    code += "print('OPSARK_IMPORT_REGRESSION '+json.dumps(result,sort_keys=True))\n"
    environment = validation.clean_environment(source / "unused-output")
    environment["PYTHONPATH"] = str(ambient)  # -I must ignore this poison root.
    result = subprocess.run(  # noqa: S603 -- own interpreter and entirely synthetic packages.
        [sys.executable, "-I", "-B", "-c", code],
        cwd=cwd,
        env=environment,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = [
        line
        for line in result.stdout.decode().splitlines()
        if line.startswith("OPSARK_IMPORT_REGRESSION ")
    ]
    assert len(lines) == 1
    return json.loads(lines[0].removeprefix("OPSARK_IMPORT_REGRESSION "))


def test_previous_src_tests_only_prefix_cannot_import_deployment_package_under_isolation(tmp_path):
    source, ambient = _isolated_import_fixture(tmp_path)
    setup = _child_import_setup()
    assert isinstance(setup.value, ast.List) and len(setup.value.elts) == 3
    setup.value.elts = setup.value.elts[:2]  # Negative control: the old exact prefix.
    value = _isolated_probe(source, ambient, setup, source)
    assert value == {
        "isolated": 1,
        "imported": False,
        "error_type": "ModuleNotFoundError",
        "missing_name": "deploy",
    }


@pytest.mark.parametrize("cwd_kind", ["source", "ambient"])
def test_actual_child_prefix_imports_only_verified_root_after_src_and_tests(tmp_path, cwd_kind):
    source, ambient = _isolated_import_fixture(tmp_path)
    value = _isolated_probe(
        source, ambient, _child_import_setup(), source if cwd_kind == "source" else ambient
    )
    assert value == {
        "isolated": 1,
        "imported": True,
        "origin": "verified-source",
        "src_first": "src",
        "tests_first": "tests",
        "unique_root": 1,
        "verified_file": True,
    }


def test_isolated_pytest_collection_resolves_verified_deploy_namespace_with_src_only_config(
    tmp_path,
):
    source, ambient = _isolated_import_fixture(tmp_path)
    value = _isolated_probe(source, ambient, _child_import_setup(), source, collect=True)
    assert value["isolated"] == 1 and value["collect_exit"] == 0
    assert value["imported"] is True and value["verified_file"] is True
