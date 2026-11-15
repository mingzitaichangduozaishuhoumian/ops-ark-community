#!/usr/bin/env python3
"""Fresh bounded defense fixture plus the unchanged formal read-only collector.

This administrator laboratory changes no host service. Business responses are
fixed synthetic data on target loopback; only registered status receipts leave it.
The target has three exact binds. Its private Root request ledger lives in the
owned container writable layer: same-container CLI/controller-process restart
only, never container rebuild, daemon restart, or host recovery. Restart is off.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import sys
import time
from contextlib import ExitStack, contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssh_defense_controller_lab as base  # noqa: E402 -- fixed owned sibling for -I.
from ssh_defense_controller_lab import (  # noqa: E402 -- unchanged immutable profile helpers.
    CAPS,
    CLEANUP_SECONDS,
    CORE_SHA256,
    FAULT_SCOPE,
    LABEL,
    LIFETIME_SECONDS,
    MAX_COMMANDS,
    WORK_SECONDS,
    capabilities_match,
    native,
    process_identity,
    projection,
    read_json,
    require,
    trusted_directory,
    write_new,
)

SELF = "/fixture-code/tests/ssh_defense_business_lab.py"
DOMAIN = "business.opsark.invalid"
HTTP_PORT = 42180
COLLECTOR = "opsark-readonly"
PHASE_FILE = "business-phase.json"
PHASES = frozenset({"mixed", "timeout_only", "restored"})
PHASE_OPERATIONS = {
    "business-mixed": "mixed",
    "business-timeout": "timeout_only",
    "business-restored": "restored",
}
OPERATIONS = base.OPERATIONS | frozenset(PHASE_OPERATIONS)
BODIES = {
    "health": b"OPSARK_FAKE_HEALTH_READY_V1\n",
    "application": b"OPSARK_FAKE_APPLICATION_READY_V1\n",
    "dependency": b"OPSARK_FAKE_DEPENDENCY_READY_V1\n",
}
PATHS = {"health": "/healthz", "application": "/application", "dependency": "/dependency"}
READONLY_SHA256 = {
    "install.py": "0b17c2667a409cd62b836d4b930a6bb5bdc6d244354205093198851cc98a0634",
    "guard.py": "9017b4508d3a62771bbe26a7692152b34dbb60bf02c91116b05c00e65f6aa28d",
    "ssh_entry.py": "ea9fdc35f31de54d8875ac3f90b35591613d1e4c5bfa008fe8f34e23a8a2cfaa",
    "http_readiness.py": "28694f1c5f31de00831a57fd179c84dd0c1bb2875c092189647c2080be5b9718",
}
STATE_PROFILE = {
    "profile": "owned_container_writable_layer_v1",
    "target_bind_count": 3,
    "root_directory_mode": 0o700,
    "root_file_mode": 0o600,
    "persistence": "same_container_cli_and_controller_process_restart_only",
    "container_restart_supported": False,
    "container_rebuild_supported": False,
    "sshd_restart_supported": False,
    "host_restart_supported": False,
}
DIAGNOSTIC_SCHEMA = "opsark-business-bootstrap-diagnostic/v1"
TARGET_DIAGNOSTIC = "business-bootstrap-diagnostic.json"
TARGET_EXPORTED_DIAGNOSTIC = "business-target-bootstrap-diagnostic.safe.json"
HOST_DIAGNOSTIC = "business-host-bootstrap-diagnostic.safe.json"
TRAVERSAL_SCHEMA = "opsark-collector-traversal-preflight/v1"
TRAVERSAL_TARGET_FILE = "collector-traversal-preflight.json"
TRAVERSAL_EXPORTED_FILE = "collector-traversal-preflight.safe.json"
TRAVERSAL_COMPONENTS = (
    ("var", "/var", "directory"),
    ("var_lib", "/var/lib", "directory"),
    ("collector_home", "/var/lib/opsark-readonly", "directory"),
    ("collector_ssh", "/var/lib/opsark-readonly/.ssh", "directory"),
    ("authorized_keys", "/var/lib/opsark-readonly/.ssh/authorized_keys", "file"),
)
DIAGNOSTIC_STEPS = frozenset(
    {
        "prepare",
        "fresh_state_preflight",
        "source_verify",
        "policy_verify",
        "installer_exec",
        "collector_traversal_preflight",
        "config_validate",
        "protected_sshd_start",
        "nft_init",
        "root_init",
        "root_storage_verify",
        "root_roles_prepare",
        "root_roles_start",
        "http_start_protected",
        "http_start_business",
        "publish_ready",
        "target_runtime",
        "host_prepare",
        "host_source_verify",
        "host_target_start",
        "host_target_ready",
        "host_general_candidate",
        "host_general_management",
        "host_general_alternate",
        "host_receipt_health",
        "host_receipt_application",
        "host_receipt_dependency",
        "host_reject_command",
        "host_reject_role_key",
        "host_reject_source",
        "host_publish_ready",
        "host_runtime",
    }
)
ERROR_CATEGORIES = frozenset(
    {
        "none",
        "permission_denied",
        "missing_path",
        "invalid_data",
        "tool_failed",
        "timeout",
        "unconfirmed",
        "unknown_error",
    }
)
STDERR_CATEGORIES = frozenset(
    {
        "none",
        "account_conflict",
        "deployment_conflict",
        "helper_conflict",
        "group_conflict",
        "required_tool_missing",
        "permission_denied",
        "publickey_refused",
        "guard_refused",
        "pam_error",
        "sshd_config_error",
        "invalid_policy",
        "unclassified",
    }
)
STDOUT_CATEGORIES = frozenset(
    {
        "none",
        "readiness_match",
        "readiness_inconclusive",
        "readiness_mismatch",
        "initialization_ack",
        "collector_path_blocked",
        "collector_path_traversable",
        "unclassified",
    }
)
_diagnostic_path = None
_diagnostic_record: dict[str, Any] | None = None


def stderr_category(raw):
    if not raw:
        return "none"
    lowered = raw.lower()
    for marker, category in (
        (b"refusing to adopt an existing unrelated account", "account_conflict"),
        (b"refusing to overwrite an existing unrelated deployment file", "deployment_conflict"),
        (b"refusing an unrelated http readiness helper", "helper_conflict"),
        (b"dedicated account must not have supplementary privileged groups", "group_conflict"),
        (b"required system tool missing", "required_tool_missing"),
        (b"no such file or directory", "required_tool_missing"),
        (b"permission denied (publickey)", "publickey_refused"),
        (b"opsark restricted collector refused this request", "guard_refused"),
        (b"operation not permitted", "permission_denied"),
        (b"permission denied", "permission_denied"),
        (b"pam_open_session", "pam_error"),
        (b"pam: authentication", "pam_error"),
        (b"bad configuration option", "sshd_config_error"),
        (b"not allowed within a match block", "sshd_config_error"),
        (b"invalid policy schema", "invalid_policy"),
        (b"invalid fixed command", "invalid_policy"),
    ):
        if marker in lowered:
            return category
    return "unclassified"


def stdout_category(raw):
    if not raw:
        return "none"
    if raw == b"OPSARK_HTTP_READINESS_V1 200 match\n":
        return "readiness_match"
    if raw == b"OPSARK_HTTP_READINESS_V1 inconclusive\n":
        return "readiness_inconclusive"
    if re.fullmatch(
        rb"OPSARK_HTTP_READINESS_V1 [2-5][0-9]{2} (?:body_mismatch|status_mismatch)\n", raw
    ):
        return "readiness_mismatch"
    if raw in (b'{"status":"initialized"}\n', b'{"v":1,"state":"initialized"}\n'):
        return "initialization_ack"
    try:
        projected = validate_traversal(native.decode(raw, 4096))
        return (
            "collector_path_traversable"
            if projected["all_accessible"]
            else "collector_path_blocked"
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        pass
    return "unclassified"


def traversal_projection():
    """Run only after permanent UID drop; inspect metadata/access, never file contents."""
    components = []
    for name, path, expected_kind in TRAVERSAL_COMPONENTS:
        try:
            metadata = os.lstat(path)
            kind = (
                "directory"
                if stat.S_ISDIR(metadata.st_mode)
                else "file"
                if stat.S_ISREG(metadata.st_mode)
                else "symlink"
                if stat.S_ISLNK(metadata.st_mode)
                else "other"
            )
            category, mode, root_owner = "ok", stat.S_IMODE(metadata.st_mode), metadata.st_uid == 0
        except PermissionError:
            category, kind, mode, root_owner = "permission_denied", None, None, None
        except FileNotFoundError:
            category, kind, mode, root_owner = "missing", None, None, None
        except OSError:
            category, kind, mode, root_owner = "os_error", None, None, None
        access = os.access(path, os.X_OK if expected_kind == "directory" else os.R_OK)
        components.append(
            {
                "component": name,
                "stat_category": category,
                "kind": kind,
                "mode": mode,
                "root_owner": root_owner,
                "access_allowed": access,
                "passed": category == "ok" and kind == expected_kind and access,
            }
        )
    blocker = next((item["component"] for item in components if not item["passed"]), None)
    return validate_traversal(
        {
            "schema": TRAVERSAL_SCHEMA,
            "collector_identity_verified": True,
            "all_accessible": blocker is None,
            "first_blocker": blocker,
            "components": components,
        }
    )


def validate_traversal(value):
    names = [item[0] for item in TRAVERSAL_COMPONENTS]
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "collector_identity_verified",
            "all_accessible",
            "first_blocker",
            "components",
        }
        and value["schema"] == TRAVERSAL_SCHEMA
        and value["collector_identity_verified"] is True
        and type(value["all_accessible"]) is bool
        and (
            value["first_blocker"] is None
            or type(value["first_blocker"]) is str
            and value["first_blocker"] in names
        )
        and type(value["components"]) is list
        and len(value["components"]) == len(names),
        "Invalid closed collector traversal projection",
    )
    for item, (name, _path, expected_kind) in zip(
        value["components"], TRAVERSAL_COMPONENTS, strict=True
    ):
        require(
            type(item) is dict
            and set(item)
            == {
                "component",
                "stat_category",
                "kind",
                "mode",
                "root_owner",
                "access_allowed",
                "passed",
            }
            and item["component"] == name
            and type(item["stat_category"]) is str
            and item["stat_category"] in {"ok", "permission_denied", "missing", "os_error"}
            and (
                item["kind"] is None
                or type(item["kind"]) is str
                and item["kind"] in {"directory", "file", "symlink", "other"}
            )
            and (item["mode"] is None or type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777)
            and (item["root_owner"] is None or type(item["root_owner"]) is bool)
            and type(item["access_allowed"]) is bool
            and type(item["passed"]) is bool
            and (item["stat_category"] == "ok")
            == (
                item["mode"] is not None
                and item["kind"] is not None
                and item["root_owner"] is not None
            )
            and item["passed"]
            == (
                item["stat_category"] == "ok"
                and item["kind"] == expected_kind
                and item["access_allowed"]
            ),
            "Invalid closed collector path component",
        )
    blocker = next((item["component"] for item in value["components"] if not item["passed"]), None)
    require(
        value["first_blocker"] == blocker and value["all_accessible"] == (blocker is None),
        "Collector traversal conclusion changed",
    )
    return json.loads(native.canonical(value))


def internal_collector_traversal():
    native.internal_modules()
    from deploy.readonly import http_readiness

    # This unchanged helper verifies real/effective/saved UID/GID and groups.
    # It consults the public passwd entry, never Shadow or an SSH key file.
    http_readiness._drop_privileges()
    print(native.canonical(traversal_projection()).decode("ascii"))
    return 0


def collector_traversal_preflight(image):
    diagnostic_step("collector_traversal_preflight")
    result = native.run(
        "/usr/bin/python3",
        "-I",
        "-B",
        SELF,
        "--internal-collector-traversal",
        "--image",
        image,
        "--confirm-isolated",
        timeout=8,
        limit=4096,
    )
    diagnostic_step("collector_traversal_preflight", result=result)
    require(
        result.returncode == 0 and not result.stderr,
        "Collector UID traversal preflight was unavailable",
    )
    projected = validate_traversal(native.decode(result.stdout, 4096))
    write_new(Path("/fixture-ready") / TRAVERSAL_TARGET_FILE, projected)
    require(projected["all_accessible"], "Collector UID cannot traverse its authorized path")
    diagnostic_step("collector_traversal_preflight", "ok")


def validate_diagnostic(value):
    require(
        type(value) is dict
        and set(value)
        == {"schema", "surface", "step", "state", "sequence", "error_category", "tool"}
        and value["schema"] == DIAGNOSTIC_SCHEMA
        and type(value["surface"]) is str
        and value["surface"] in {"target", "host"}
        and type(value["step"]) is str
        and value["step"] in DIAGNOSTIC_STEPS
        and type(value["state"]) is str
        and value["state"] in {"enter", "ok", "failed"}
        and type(value["sequence"]) is int
        and 1 <= value["sequence"] <= 256
        and type(value["error_category"]) is str
        and value["error_category"] in ERROR_CATEGORIES
        and (value["state"] == "failed") == (value["error_category"] != "none"),
        "Invalid closed bootstrap diagnostic",
    )
    tool = value["tool"]
    if tool is not None:
        require(
            type(tool) is dict
            and set(tool)
            == {"returncode", "stdout_bytes", "stderr_bytes", "stdout_category", "stderr_category"}
            and type(tool["returncode"]) is int
            and -255 <= tool["returncode"] <= 255
            and all(
                type(tool[name]) is int and 0 <= tool[name] <= 65536
                for name in ("stdout_bytes", "stderr_bytes")
            )
            and type(tool["stdout_category"]) is str
            and tool["stdout_category"] in STDOUT_CATEGORIES
            and type(tool["stderr_category"]) is str
            and tool["stderr_category"] in STDERR_CATEGORIES,
            "Invalid closed tool diagnostic",
        )
    # A fresh deep projection prevents accidentally preserving unvalidated objects.
    return json.loads(native.canonical(value))


def save_diagnostic(path, value):
    projected = validate_diagnostic(value)
    trusted_directory(path.parent, private=True)
    if path.exists():
        validate_diagnostic(read_json(path, 4096))
    pending = path.with_name(path.name + ".pending")
    native.owned_create(pending, native.canonical(projected) + b"\n")
    os.replace(pending, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def begin_diagnostic(surface, path):
    global _diagnostic_path, _diagnostic_record
    require(
        surface in {"target", "host"} and not path.exists(), "Bootstrap diagnostic is single-use"
    )
    trusted_directory(path.parent, private=True)
    _diagnostic_path = path
    _diagnostic_record = {
        "schema": DIAGNOSTIC_SCHEMA,
        "surface": surface,
        "step": "prepare" if surface == "target" else "host_prepare",
        "state": "enter",
        "sequence": 1,
        "error_category": "none",
        "tool": None,
    }
    save_diagnostic(path, _diagnostic_record)


def diagnostic_step(step, state="enter", result=None):
    global _diagnostic_record
    require(
        step in DIAGNOSTIC_STEPS and state in {"enter", "ok"}, "Unknown bootstrap diagnostic step"
    )
    if _diagnostic_path is None or _diagnostic_record is None:
        return
    tool = _diagnostic_record["tool"] if _diagnostic_record["step"] == step else None
    if result is not None:
        tool = {
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
            "stdout_category": stdout_category(result.stdout),
            "stderr_category": stderr_category(result.stderr),
        }
    _diagnostic_record = validate_diagnostic(
        {
            **_diagnostic_record,
            "step": step,
            "state": state,
            "tool": tool,
            "sequence": _diagnostic_record["sequence"] + 1,
            "error_category": "none",
        }
    )
    save_diagnostic(_diagnostic_path, _diagnostic_record)


def diagnostic_failed(error):
    global _diagnostic_record
    if (
        _diagnostic_path is None
        or _diagnostic_record is None
        or _diagnostic_record["state"] == "failed"
    ):
        return
    if isinstance(error, PermissionError):
        category = "permission_denied"
    elif isinstance(error, FileNotFoundError):
        category = "missing_path"
    elif isinstance(error, (TimeoutError, native.subprocess.TimeoutExpired)):
        category = "timeout"
    elif isinstance(error, (ValueError, TypeError, KeyError)):
        category = "invalid_data"
    elif _diagnostic_record["tool"] is not None and _diagnostic_record["tool"]["returncode"] != 0:
        category = "tool_failed"
    elif isinstance(error, RuntimeError):
        category = "unconfirmed"
    else:
        category = "unknown_error"
    _diagnostic_record = validate_diagnostic(
        {
            **_diagnostic_record,
            "state": "failed",
            "error_category": category,
            "sequence": _diagnostic_record["sequence"] + 1,
        }
    )
    save_diagnostic(_diagnostic_path, _diagnostic_record)


def diagnostic_reference(path):
    try:
        raw = native.owned_read(path, 4096)
        validate_diagnostic(native.decode(raw))
        return {"available": True, "file": path.name, "sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        return {"available": False, "reason_code": "unavailable"}


def traversal_reference(path):
    try:
        raw = native.owned_read(path, 4096)
        validate_traversal(native.decode(raw, 4096))
        return {"available": True, "file": path.name, "sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        return {"available": False, "reason_code": "unavailable"}


@contextmanager
def capture_target_diagnostic(root, readiness, report):
    try:
        yield
    except BaseException as error:
        diagnostic_failed(error)
        raise
    finally:
        # This runs before both ExitStack resource cleanup and TemporaryDirectory
        # removal. Never read a now-reused pathname after the fixture is gone.
        source = readiness / TARGET_DIAGNOSTIC
        destination = root / TARGET_EXPORTED_DIAGNOSTIC
        try:
            projected = validate_diagnostic(read_json(source, 4096))
            require(projected["surface"] == "target", "Unexpected diagnostic surface")
            write_new(destination, projected)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            pass
        report["target_bootstrap_diagnostic"] = diagnostic_reference(destination)
        traversal_destination = root / TRAVERSAL_EXPORTED_FILE
        with suppress(OSError, RuntimeError, ValueError, TypeError, KeyError):
            projected = validate_traversal(read_json(readiness / TRAVERSAL_TARGET_FILE, 4096))
            write_new(traversal_destination, projected)
        report["collector_traversal_preflight"] = traversal_reference(traversal_destination)


class BusinessNetwork(base.ControllerNetwork):
    def start(self, role, address, mounts, *, target=False):
        entry = ("/usr/bin/timeout", "-k", "2s", f"{LIFETIME_SECONDS}s")
        arguments = (
            (
                "/usr/bin/python3",
                "-I",
                "-B",
                SELF,
                "--internal-target",
                "--image",
                self.image,
                "--confirm-isolated",
            )
            if target
            else ("/bin/sleep", "infinity")
        )
        options = []
        for source, destination, readonly in mounts:
            trusted_directory(source, private=True)
            require(source.parent == self.workspace, "A fixture mount escaped its owned workspace")
            options.extend(
                (
                    "--mount",
                    f"type=bind,src={source},dst={destination}" + (",readonly" if readonly else ""),
                )
            )
        capabilities = [part for cap in CAPS for part in ("--cap-add", cap)] if target else []
        privileges = [] if target else ["--read-only", "--security-opt", "no-new-privileges:true"]
        identity = self.identifier(
            self.command(
                "create",
                "--pull",
                "never",
                "--name",
                f"{self.name}-{role}",
                "--label",
                f"{LABEL}={self.fixture}",
                "--network",
                self.name,
                "--ip",
                address,
                "--user",
                "0:0",
                "--ipc",
                "private",
                "--cgroupns",
                "private",
                "--cap-drop",
                "ALL",
                *capabilities,
                *privileges,
                "--no-healthcheck",
                "--restart",
                "no",
                "--stop-timeout",
                "3",
                "--pids-limit",
                "96",
                "--memory",
                "192m",
                "--memory-swap",
                "192m",
                "--cpus",
                "0.5",
                "--ulimit",
                "nofile=256:256",
                "--ulimit",
                "core=0:0",
                "--log-driver",
                "none",
                *options,
                "--entrypoint",
                entry[0],
                self.image,
                *entry[1:],
                *arguments,
            )
        )
        self.owned.add(identity)
        self.cleanup.callback(self.remove, "container", identity)
        observed = self.inspect("container", identity)
        config, host = observed["Config"], observed["HostConfig"]
        require(
            observed["Image"] == self.image
            and config["User"] == "0:0"
            and config["Labels"] == self.container_labels
            and config["Entrypoint"] == [entry[0]]
            and config["Cmd"] == [*entry[1:], *arguments]
            and not host["Privileged"]
            and host["CapDrop"] == ["ALL"]
            and capabilities_match(host["CapAdd"], CAPS if target else ())
            and host["ReadonlyRootfs"] == (not target)
            and (host["SecurityOpt"] or []) == ([] if target else ["no-new-privileges:true"])
            and host["NetworkMode"] == self.name
            and not host["PidMode"]
            and host["IpcMode"] == "private"
            and host["CgroupnsMode"] == "private"
            and not host["UTSMode"]
            and not host["UsernsMode"]
            and not host["Devices"]
            and not host.get("DeviceRequests")
            and not host["PortBindings"]
            and not host["PublishAllPorts"]
            and not host["VolumesFrom"]
            and host["PidsLimit"] == 96
            and host["Memory"] == 192 * 1024**2
            and host["MemorySwap"] == host["Memory"]
            and host["NanoCpus"] == 500_000_000
            and {(item["Name"], item["Soft"], item["Hard"]) for item in host["Ulimits"]}
            == {("core", 0, 0), ("nofile", 256, 256)}
            and host["LogConfig"]["Type"] == "none"
            and host["RestartPolicy"]["Name"] == "no",
            "A fixture container did not have the exact bounded security profile",
        )
        actual = {
            (item["Source"], item["Destination"], not item["RW"], item["Type"], item["Propagation"])
            for item in observed["Mounts"]
        }
        require(
            actual
            == {
                (str(source), destination, readonly, "bind", "rprivate")
                for source, destination, readonly in mounts
            },
            "A fixture container had unexpected storage or a socket mount",
        )
        self.command("start", identity)
        networks = self.inspect("container", identity)["NetworkSettings"]["Networks"]
        require(
            set(networks) == {self.name}
            and networks[self.name]["NetworkID"] == self.identity
            and networks[self.name]["IPAddress"] == address,
            "A fixture container joined an unexpected network",
        )
        return identity


def business_checks():
    return [
        {
            "id": name,
            "domain": DOMAIN,
            "port": HTTP_PORT,
            "path": PATHS[name],
            "expected_status": 200,
            "expected_body_sha256": hashlib.sha256(body).hexdigest(),
            "read_only_confirmed": True,
        }
        for name, body in BODIES.items()
    ]


def expected_policy():
    commands = {}
    for check in business_checks():
        argv = [
            "timeout",
            "-k",
            "1s",
            "5s",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/usr/local/libexec/opsark-http-readiness",
            check["domain"],
            str(check["port"]),
            check["path"],
            str(check["expected_status"]),
            check["expected_body_sha256"],
        ]
        commands["LC_ALL=C " + shlex.join(argv)] = argv
    return {"schema_version": 1, "commands": commands}


def validate_policy(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "Unbounded collector policy")
    value = json.loads(raw, object_pairs_hook=native.strict_pairs)
    require(
        type(value) is dict
        and type(value.get("schema_version")) is int
        and value == expected_policy(),
        "The collector policy is not the three registered probes",
    )
    return hashlib.sha256(raw).hexdigest()


def target_mounts(workspace):
    """The whole host /var/lib and the old private state directory are never bound."""
    return [
        (workspace / "code", native.CODE, True),
        (workspace / "authority", native.AUTHORITY, True),
        (workspace / "ready", "/fixture-ready", False),
    ]


def validate_state_profile(value):
    require(
        type(value) is dict
        and set(value) == set(STATE_PROFILE)
        and all(
            type(value[key]) is type(expected) and value[key] == expected
            for key, expected in STATE_PROFILE.items()
        ),
        "Business fixture state profile changed",
    )
    return True


def validate_business_mounts(container, workspace, *, management=False):
    expected = (
        [(workspace / "code", native.CODE, True), (workspace / "management", native.CLIENT, True)]
        if management
        else target_mounts(workspace)
    )
    mounts = container["Mounts"]
    require(
        type(mounts) is list and len(mounts) == len(expected),
        "Business fixture mount count changed",
    )
    observed = {
        (item["Source"], item["Destination"], not item["RW"], item["Type"], item["Propagation"])
        for item in mounts
    }
    require(
        observed
        == {
            (str(source), destination, readonly, "bind", "rprivate")
            for source, destination, readonly in expected
        },
        "Business fixture mount profile changed",
    )
    return True


def require_fresh_root_storage():
    """Do not adopt, chmod, migrate, or delete a pre-existing Root deployment."""
    diagnostic_step("fresh_state_preflight")
    trusted_directory(Path("/var"))
    trusted_directory(Path("/var/lib"))
    require(
        not native.REQUEST_ROOT.exists() and not native.REQUEST_ROOT.is_symlink(),
        "A fresh container Root request deployment is required",
    )
    diagnostic_step("fresh_state_preflight", "ok")


def verify_private_root_storage():
    diagnostic_step("root_storage_verify")
    directory = native.REQUEST_ROOT
    require(directory.resolve(strict=True) == directory, "Root request path changed")
    metadata = directory.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and stat.S_IMODE(metadata.st_mode) == STATE_PROFILE["root_directory_mode"],
        "Root request directory is not private",
    )
    ledger = (directory / "requests.json").lstat()
    require(
        stat.S_ISREG(ledger.st_mode)
        and ledger.st_uid == 0
        and ledger.st_nlink == 1
        and stat.S_IMODE(ledger.st_mode) == STATE_PROFILE["root_file_mode"],
        "Root request file is not private",
    )
    diagnostic_step("root_storage_verify", "ok")


@contextmanager
def bound_self():
    original, original_base = native.SELF, base.SELF
    native.SELF = SELF  # ty: ignore[invalid-assignment] -- scoped laboratory entrypoint.
    base.SELF = SELF  # ty: ignore[invalid-assignment] -- scoped laboratory entrypoint.
    try:
        yield
    finally:
        native.SELF, base.SELF = original, original_base


def checked_command(value):
    require(
        type(value) is dict
        and set(value) == {"schema", "request_id", "operation", "fixture_id"}
        and value["schema"] == "opsark-controller-command/v1"
        and type(value["request_id"]) is str
        and re.fullmatch("[0-9a-f]{32}", value["request_id"])
        and type(value["fixture_id"]) is str
        and re.fullmatch("[0-9a-f]{16}", value["fixture_id"])
        and type(value["operation"]) is str
        and value["operation"] in OPERATIONS,
        "Invalid fixed business laboratory command",
    )
    return value


def copy_source(source, destination, *, sha256=None):
    trusted_directory(source.parent)
    info = source.lstat()
    require(
        source.is_file()
        and not source.is_symlink()
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and info.st_nlink == 1,
        "Untrusted business fixture source",
    )
    raw = source.read_bytes()
    require(0 < len(raw) <= 262144 and b"\r\n" not in raw, "Source must be bounded canonical LF")
    require(
        sha256 is None or hashlib.sha256(raw).hexdigest() == sha256,
        "Formal collector source changed",
    )
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not destination.exists(), "A source destination already exists")
    destination.write_bytes(raw)
    destination.chmod(0o600)


def write_phase(directory, phase, request_id):
    require(phase in PHASES and re.fullmatch("[0-9a-f]{32}", request_id), "Unknown business phase")
    trusted_directory(directory, private=True)
    path = directory / PHASE_FILE
    if path.exists():
        previous = read_json(path)
        require(previous["phase"] in PHASES, "Unexpected business phase file")
    pending = directory / ("business-phase-" + request_id + ".pending")
    write_new(pending, {"phase": phase, "request_id": request_id})
    os.replace(pending, path)
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "phase": phase,
        "phase_ref": request_id,
        "phase_sha256": native.digest({"phase": phase, "request_id": request_id}),
    }


def stage_business(workspace, policy_path):
    staged = native.stage(workspace, native.SOCKET_CASE)
    code, keys, management, authority, readiness, _state, _deployment, _grants = staged
    copy_source(Path(base.__file__).resolve(), code / "tests/ssh_defense_controller_lab.py")
    root = Path(__file__).resolve().parents[1]
    for name, expected in READONLY_SHA256.items():
        copy_source(
            root / "deploy/readonly" / name, code / "deploy/readonly" / name, sha256=expected
        )
    raw = native.owned_read(policy_path, 16384)
    validate_policy(raw)
    native.owned_create(authority / "collector-policy.json", raw)
    require(
        native.run(
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(management / "collector"),
        ).returncode
        == 0,
        "Synthetic collector key generation failed",
    )
    shutil.copyfile(management / "collector.pub", authority / "collector.pub")
    (authority / "collector.pub").chmod(0o600)
    # A correct synthetic key is deliberately offered from an unprotected source
    # before the cursor exists, proving source restriction rather than wrong-key rejection.
    shutil.copyfile(management / "collector", keys / "collector")
    (keys / "collector").chmod(0o600)
    write_phase(readiness, "restored", secrets.token_hex(16))
    return staged


def collector_argv(command, *, wrong_role=False):
    argv = list(native.ssh_argv())
    argv[argv.index("-i") + 1] = (
        f"{native.CLIENT}/control" if wrong_role else f"{native.CLIENT}/collector"
    )
    argv[-2:] = [f"{COLLECTOR}@{native.TARGET}", command]
    return tuple(argv)


def bootstrap_collector(network, clients):
    for name, command in zip(BODIES, expected_policy()["commands"], strict=True):
        step = "host_receipt_" + name
        diagnostic_step(step)
        receipt = network.execute(clients["management"], *collector_argv(command))
        diagnostic_step(step, result=receipt)
        require(
            receipt.returncode == 0
            and not receipt.stderr
            and receipt.stdout == b"OPSARK_HTTP_READINESS_V1 200 match\n",
            "A formal collector bootstrap receipt did not pass",
        )
        diagnostic_step(step, "ok")
    diagnostic_step("host_reject_command")
    denied = network.execute(clients["management"], *collector_argv("/usr/bin/true"))
    diagnostic_step("host_reject_command", result=denied)
    require(
        denied.returncode == 126 and not denied.stdout,
        "An unregistered collector command was accepted",
    )
    diagnostic_step("host_reject_command", "ok")
    command = next(iter(expected_policy()["commands"]))
    diagnostic_step("host_reject_role_key")
    wrong_key = network.execute(clients["management"], *collector_argv(command, wrong_role=True))
    diagnostic_step("host_reject_role_key", result=wrong_key)
    require(
        wrong_key.returncode == 255 and not wrong_key.stdout,
        "A Root role key authenticated as collector",
    )
    diagnostic_step("host_reject_role_key", "ok")
    diagnostic_step("host_reject_source")
    wrong_source = network.execute(clients["candidate"], *collector_argv(command))
    diagnostic_step("host_reject_source", result=wrong_source)
    require(
        wrong_source.returncode == 255 and not wrong_source.stdout,
        "An unprotected source authenticated as collector",
    )
    diagnostic_step("host_reject_source", "ok")
    return {
        "initial_probe_passed": True,
        "wrong_command_refused": True,
        "wrong_role_key_refused": True,
        "unprotected_source_refused": True,
    }


def ready_value(
    root, workspace, network, target, clients, pin, deployment, grants, metadata, bootstrap
):
    value = base.ready_value(
        root, workspace, network, target, clients, pin, deployment, grants, metadata
    )
    value["state_profile"] = dict(STATE_PROFILE)
    known_hosts = workspace / "management/collector_known_hosts"
    native.owned_create(known_hosts, f"[{native.TARGET}]:{native.PORT} {pin}\n".encode("ascii"))
    value["collector"] = {
        "username": COLLECTOR,
        "ssh_port": 22422,
        "source_address": native.ADDRESSES["management"],
        "key_file": str(workspace / "management/collector"),
        "known_hosts_file": str(known_hosts),
        "policy_sha256": hashlib.sha256(
            native.owned_read(workspace / "authority/collector-policy.json", 16384)
        ).hexdigest(),
        "checks": business_checks(),
        **bootstrap,
    }
    return value


def process_command(command, root, network, target, clients):
    checked_command(command)
    require(command["fixture_id"] == network.fixture, "Business command scope changed")
    if command["operation"] in PHASE_OPERATIONS:
        return write_phase(
            network.workspace / "ready",
            PHASE_OPERATIONS[command["operation"]],
            command["request_id"],
        )
    return base.process_command(command, root, network, target, clients)


def restricted_ssh_config(text):
    require(
        text.count("AllowUsers opsark-ssh-lab\n") == 1
        and text.count("UsePAM no\n") == 1
        and text.count("ForceCommand /usr/bin/true\n") == 1
        and "Match " not in text,
        "The original protected SSH configuration changed",
    )
    return (
        text.replace(
            "AllowUsers opsark-ssh-lab\n",
            "AllowUsers opsark-ssh-lab opsark-readonly@198.18.241.4\n",
        )
        .replace("UsePAM no\n", "UsePAM yes\n")
        .replace("ForceCommand /usr/bin/true\n", "")
        + "Match User opsark-ssh-lab\n    ForceCommand /usr/bin/true\n"
    )


def install_collector(config):
    diagnostic_step("source_verify")
    for name, expected in READONLY_SHA256.items():
        require(
            hashlib.sha256(
                native.owned_read(Path(native.CODE) / "deploy/readonly" / name, 65536)
            ).hexdigest()
            == expected,
            "Formal collector source changed",
        )
    diagnostic_step("source_verify", "ok")
    diagnostic_step("policy_verify")
    policy = native.owned_read(Path(native.AUTHORITY) / "collector-policy.json", 16384)
    policy_sha = validate_policy(policy)
    diagnostic_step("policy_verify", "ok")
    diagnostic_step("installer_exec")
    result = native.run(
        "/usr/bin/python3",
        "-I",
        "-B",
        f"{native.CODE}/deploy/readonly/install.py",
        "--policy",
        f"{native.AUTHORITY}/collector-policy.json",
        "--public-key",
        f"{native.AUTHORITY}/collector.pub",
        timeout=30,
        limit=8192,
    )
    diagnostic_step("installer_exec", result=result)
    require(result.returncode == 0 and not result.stderr, "Formal collector installation failed")
    installed = json.loads(result.stdout)
    require(
        installed["account"] == COLLECTOR
        and installed["allowed_commands"] == 3
        and installed["policy_sha256"] == policy_sha
        and installed["installation_state"] == "complete"
        and installed["docker_group_membership"] is False
        and installed["journal_group_membership"] is False,
        "Formal collector installation receipt did not match",
    )
    diagnostic_step("installer_exec", "ok")
    diagnostic_step("config_validate")
    config.write_text(restricted_ssh_config(config.read_text(encoding="ascii")), encoding="ascii")
    result = native.run("/usr/sbin/sshd", "-t", "-f", str(config))
    diagnostic_step("config_validate", result=result)
    require(result.returncode == 0, "Business SSH configuration failed")
    diagnostic_step("config_validate", "ok")


def business_reply(phase, path):
    require(phase in PHASES, "Unknown fixed business response phase")
    name = next((key for key, value in PATHS.items() if value == path), None)
    if name is None:
        return 404, b"", 0
    if phase == "mixed" and name == "application":
        return 503, b"OPSARK_FAKE_UNAVAILABLE_V1\n", 0
    return (
        200,
        BODIES[name],
        3 if phase in {"mixed", "timeout_only"} and name == "dependency" else 0,
    )


class BusinessHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self):
        if self.headers.get("Host") != DOMAIN:
            code, body, delay = 404, b"", 0
        else:
            phase = read_json(Path("/fixture-ready") / PHASE_FILE)
            require(set(phase) == {"phase", "request_id"}, "Business phase metadata changed")
            code, body, delay = business_reply(phase["phase"], self.path)
        if delay:
            time.sleep(delay)
        self.close_connection = True
        try:
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def business_internal_target(image):
    target, _ = native.internal_modules()
    # The existing private-namespace/CAP gate runs before any diagnostic write.
    begin_diagnostic("target", Path("/fixture-ready") / TARGET_DIAGNOSTIC)
    require_fresh_root_storage()
    config, host_key = target.prepare_ssh(
        target.public_key(target.read_fixture_file(Path(native.AUTHORITY) / "client.pub", 256))
    )
    diagnostic_step("prepare", "ok")
    # Official locked account and PAM-compatible configuration are complete before
    # either the protected listener or its immutable Root binding is initialized.
    install_collector(config)
    collector_traversal_preflight(image)
    diagnostic_step("root_roles_prepare")
    request_config = native.provision_roles(target, image)
    diagnostic_step("root_roles_prepare", "ok")
    diagnostic_step("protected_sshd_start")
    with target.sshd(config), ExitStack() as cleanup:
        diagnostic_step("protected_sshd_start", "ok")
        diagnostic_step("nft_init")
        result = native.run(
            "/usr/bin/python3",
            "-I",
            "-B",
            f"{native.CODE}/deploy/defense/ssh_fixture.py",
            "--profile",
            "private",
            "initialize",
        )
        diagnostic_step("nft_init", result=result)
        require(
            result.returncode == 0 and native.decode(result.stdout) == {"status": "initialized"},
            "Native private nft initialization failed",
        )
        diagnostic_step("nft_init", "ok")
        diagnostic_step("root_init")
        deployment = target.read_fixture_file(Path(native.AUTHORITY) / "deployment.json", 4096)
        result = native.run(
            "/usr/bin/python3", "-I", "-B", native.INSTALLED, "--initialize", input_bytes=deployment
        )
        diagnostic_step("root_init", result=result)
        require(
            result.returncode == 0
            and native.decode(result.stdout) == {"v": 1, "state": "initialized"},
            "Fresh Root initialization failed",
        )
        diagnostic_step("root_init", "ok")
        verify_private_root_storage()
        native.install_faults(native.fixture_case(), image)
        log = Path("/run/opsark-ssh-defense/requests-sshd.log")
        log.touch(mode=0o600, exist_ok=False)
        diagnostic_step("root_roles_start")
        process = cleanup.enter_context(
            native.subprocess.Popen(
                ["/usr/sbin/sshd", "-D", "-E", str(log), "-f", str(request_config)],
                stdin=native.subprocess.DEVNULL,
                stdout=native.subprocess.DEVNULL,
                stderr=native.subprocess.DEVNULL,
                env=native.ENV,
            )
        )
        cleanup.callback(process.terminate)
        for _ in range(50):
            if Path("/run/opsark-ssh-defense/requests-sshd.pid").is_file():
                break
            require(process.poll() is None, "Fixed Root-role SSH stopped")
            time.sleep(0.1)
        else:
            raise native.LabError("Fixed Root-role SSH did not start")
        diagnostic_step("root_roles_start", "ok")
        for address, port, handler in (
            (native.TARGET, 22480, target.HealthHandler),
            ("127.0.0.1", HTTP_PORT, BusinessHandler),
        ):
            step = "http_start_business" if address == "127.0.0.1" else "http_start_protected"
            diagnostic_step(step)
            server = cleanup.enter_context(ThreadingHTTPServer((address, port), handler))
            Thread(target=server.serve_forever, daemon=True).start()
            cleanup.callback(server.shutdown)
            diagnostic_step(step, "ok")
        diagnostic_step("publish_ready")
        target.publish_ready(host_key)
        diagnostic_step("publish_ready", "ok")
        diagnostic_step("target_runtime")
        while process.poll() is None:
            native.process_socket_interruption(image)
            time.sleep(0.05)
    return 0


def serve(root, image, proof, collector_policy):
    native.require_root(root)
    begin_diagnostic("host", root / HOST_DIAGNOSTIC)
    native._deadline = time.monotonic() + WORK_SECONDS
    native._overall_deadline = time.monotonic() + LIFETIME_SECONDS
    for name in (
        "controller-ready.json",
        "supervisor.json",
        "controller-commands",
        "controller-results",
    ):
        require(not (root / name).exists(), "The controller laboratory is single-use")
    commands, results, claims = [
        root / n for n in ("controller-commands", "controller-results", "controller-claims")
    ]
    for directory in (commands, results, claims):
        directory.mkdir(mode=0o700)
    identity = process_identity(os.getpid())
    write_new(root / "supervisor.json", identity)
    report = {
        "schema": "opsark-business-controller-fixture-proof/v1",
        "completed": False,
        "fault_scope": FAULT_SCOPE,
        "root_source_sha256": CORE_SHA256,
        "readonly_source_sha256": READONLY_SHA256,
        "state_profile": dict(STATE_PROFILE),
        "work_budget_seconds": WORK_SECONDS,
        "cleanup_budget_seconds": CLEANUP_SECONDS,
        "container_timeout_seconds": LIFETIME_SECONDS,
        "operations": [],
        "owned_resources_removed": False,
        "console_and_ai_verified": False,
    }
    with native.proof_file(root, proof) as output:
        try:
            with (
                TemporaryDirectory(prefix="controller-", dir=root) as temporary,
                ExitStack() as cleanup,
                bound_self(),
            ):
                workspace = Path(temporary)
                code, keys, management, authority, readiness, state, deployment, grants = (
                    stage_business(workspace, collector_policy)
                )
                diagnostic_step("host_prepare", "ok")
                diagnostic_step("host_source_verify")
                own_source = Path(__file__).resolve()
                trusted_directory(own_source.parent)
                info = own_source.lstat()
                require(
                    info.st_uid == 0 and not info.st_mode & 0o022 and info.st_nlink == 1,
                    "Untrusted controller harness source",
                )
                (code / "tests" / own_source.name).write_bytes(own_source.read_bytes())
                (code / "tests" / own_source.name).chmod(0o600)
                for name, expected in CORE_SHA256.items():
                    require(
                        hashlib.sha256((code / "deploy/defense" / name).read_bytes()).hexdigest()
                        == expected,
                        "Root source changed",
                    )
                diagnostic_step("host_source_verify", "ok")
                diagnostic_step("host_target_start")
                with capture_target_diagnostic(root, readiness, report):
                    network = BusinessNetwork(workspace, image, cleanup)
                    target = network.start(
                        "target",
                        native.TARGET,
                        target_mounts(workspace),
                        target=True,
                    )
                    validate_business_mounts(network.inspect("container", target), workspace)
                    diagnostic_step("host_target_start", "ok")
                    diagnostic_step("host_target_ready")
                    pin = native.ready(network, target, readiness / "ready.json")
                    diagnostic_step("host_target_ready", "ok")
                    for directory in (keys, management):
                        (directory / "known_hosts").write_text(
                            f"[{native.TARGET}]:{native.PORT} {pin}\n"
                            f"[{native.TARGET}]:{native.REQUEST_PORT} {pin}\n",
                            encoding="ascii",
                        )
                        (directory / "known_hosts").chmod(0o600)
                    clients = {}
                    for role, address in native.ADDRESSES.items():
                        selected = management if role == "management" else keys
                        clients[role] = network.start(
                            role,
                            address,
                            [(code, native.CODE, True), (selected, native.CLIENT, True)],
                        )
                        if role == "management":
                            validate_business_mounts(
                                network.inspect("container", clients[role]),
                                workspace,
                                management=True,
                            )
                        diagnostic_step("host_general_" + role)
                        native.login(network, clients[role])
                        diagnostic_step("host_general_" + role, "ok")
                    bootstrap = bootstrap_collector(network, clients)
                    initial = native.snapshot(network, target)
                    require(
                        initial["records"] == {}
                        and initial["usage_count"] == 0
                        and not initial["kernel_active"],
                        "Controller fixture was not fresh",
                    )
                    metadata = projection(network, target)
                    require(
                        metadata["mode"] == {"mode": "manual", "mode_revision": 1}
                        and metadata["cursor_count"] == 0,
                        "Root mode was not fresh manual",
                    )
                    diagnostic_step("host_publish_ready")
                    write_new(
                        root / "controller-ready.json",
                        ready_value(
                            root,
                            workspace,
                            network,
                            target,
                            clients,
                            pin,
                            deployment,
                            grants,
                            metadata,
                            bootstrap,
                        ),
                    )
                    diagnostic_step("host_publish_ready", "ok")
                    diagnostic_step("host_runtime")
                    stopping = False
                    while time.monotonic() < native._deadline and not stopping:
                        entries = sorted(commands.iterdir())
                        require(
                            len(entries) <= MAX_COMMANDS
                            and all(
                                re.fullmatch("[0-9a-f]{32}\\.json", entry.name) for entry in entries
                            ),
                            "Unbounded controller mailbox",
                        )
                        for entry in entries:
                            request_id = entry.stem
                            if (results / entry.name).exists():
                                continue
                            command = checked_command(read_json(entry))
                            require(
                                command["request_id"] == request_id
                                and command["fixture_id"] == network.fixture,
                                "Controller mailbox binding changed",
                            )
                            claim = {
                                "command_sha256": native.digest(command),
                                "request_id": request_id,
                            }
                            write_new(claims / entry.name, claim)
                            try:
                                value = process_command(command, root, network, target, clients)
                                result = {
                                    "request_id": request_id,
                                    "operation": command["operation"],
                                    "command_sha256": claim["command_sha256"],
                                    "completed": True,
                                    "result": value,
                                }
                            except (OSError, RuntimeError, ValueError, TypeError, KeyError):
                                result = {
                                    "request_id": request_id,
                                    "operation": command["operation"],
                                    "command_sha256": claim["command_sha256"],
                                    "completed": False,
                                    "reason_code": "unavailable_no_retry",
                                }
                            write_new(results / entry.name, result)
                            report["operations"].append(result)
                            stopping = command["operation"] == "stop"
                            if stopping:
                                break
                        time.sleep(0.05)
                    report["stop_requested"] = stopping
                    report["timed_out"] = not stopping
            report["owned_resources_removed"] = True
            report["completed"] = True
        except BaseException as error:
            diagnostic_failed(error)
            raise
        finally:
            report["host_bootstrap_diagnostic"] = diagnostic_reference(root / HOST_DIAGNOSTIC)
            output.write(native.canonical(report) + b"\n")
            output.flush()
            os.fsync(output.fileno())
    return 0


def command(root, operation, request_id):
    native.require_root(root)
    require(
        operation in OPERATIONS and re.fullmatch("[0-9a-f]{32}", request_id or ""),
        "An explicit original command identity is required",
    )
    ready = read_json(root / "controller-ready.json")
    value = checked_command(
        {
            "schema": "opsark-controller-command/v1",
            "request_id": request_id,
            "operation": operation,
            "fixture_id": ready["fixture_id"],
        }
    )
    path = root / "controller-commands" / (request_id + ".json")
    result = root / "controller-results" / path.name
    if path.exists():
        require(read_json(path) == value, "The original command declaration changed")
        if result.exists():
            answer = read_json(result, 32768)
            require(
                answer.get("request_id") == request_id
                and answer.get("operation") == operation
                and answer.get("command_sha256") == native.digest(value)
                and type(answer.get("completed")) is bool,
                "Original command result binding changed",
            )
            return answer
    else:
        require(
            supervisor_alive(read_json(root / "supervisor.json")) and live_resources(ready),
            "The original controller laboratory is no longer live",
        )
        write_new(path, value)
    if not supervisor_alive(read_json(root / "supervisor.json")):
        return {
            "request_id": request_id,
            "completed": False,
            "reason_code": "supervisor_unavailable_no_retry",
        }
    return {"request_id": request_id, "pending": True}


def live_resources(ready):
    validate_state_profile(ready.get("state_profile"))
    base.live_resources(ready)
    workspace = Path(ready["workspace"])
    for role in ("target", "management"):
        identity = ready["container_ids"][role]
        require(
            re.fullmatch("[0-9a-f]{64}", identity), "A full original container identity is required"
        )
        result = native.run(
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(workspace),
            "container",
            "inspect",
            identity,
            timeout=5,
            limit=65536,
        )
        require(result.returncode == 0 and not result.stderr, "Business fixture inspection failed")
        observed = json.loads(result.stdout)
        require(
            type(observed) is list and len(observed) == 1 and observed[0]["Id"] == identity,
            "Original business container changed",
        )
        validate_business_mounts(observed[0], workspace, management=role == "management")
    return True


def supervisor_alive(record):
    return base.supervisor_alive(record)


def status(root):
    native.require_root(root)
    live = supervisor_alive(read_json(root / "supervisor.json"))
    ready_path = root / "controller-ready.json"
    ready = read_json(ready_path) if live and ready_path.exists() else None
    if ready is not None:
        live_resources(ready)
    return {"supervisor_live": live, "ready": ready is not None, "fixture": ready}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", choices=("describe", "serve", "status", *sorted(OPERATIONS))
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--collector-policy", type=Path)
    parser.add_argument("--request-id")
    parser.add_argument("--confirm-isolated", action="store_true")
    group = parser.add_mutually_exclusive_group()
    for name in (
        "target",
        "control-wrapper",
        "ss-close",
        "snapshot",
        "fault-proof",
        "projection",
        "stimulus-gate",
        "collector-traversal",
    ):
        group.add_argument("--internal-" + name, action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.action == "describe":
            require(
                not any(
                    (args.root, args.image, args.proof, args.collector_policy, args.request_id)
                ),
                "Description accepts no deployment operands",
            )
            print(
                native.canonical({"checks": business_checks(), "policy": expected_policy()}).decode(
                    "ascii"
                )
            )
            return 0
        require(
            args.confirm_isolated
            and args.image is not None
            and re.fullmatch("sha256:[0-9a-f]{64}", args.image),
            "Explicit isolated mode and pinned image are required",
        )
        with bound_self():
            dispatch = {
                "target": lambda: business_internal_target(args.image),
                "control_wrapper": base.controller_control_wrapper,
                "ss_close": native.internal_ss_close,
                "snapshot": native.internal_snapshot,
                "fault_proof": native.internal_fault_proof,
                "projection": base.internal_projection,
                "stimulus_gate": lambda: base.internal_projection(stimulus=True),
                "collector_traversal": internal_collector_traversal,
            }
            for name, function in dispatch.items():
                if getattr(args, "internal_" + name):
                    require(args.action is None, "Internal entrypoints accept no action")
                    return function()
            require(args.root is not None, "A fixed private root is required")
            if args.action == "serve":
                require(
                    args.proof is not None and args.collector_policy is not None,
                    "Original proof and collector policy are required",
                )
                require(
                    args.collector_policy.parent == args.root
                    and args.collector_policy.resolve() == args.collector_policy,
                    "Collector policy must be a direct trusted stage child",
                )
                signal.signal(signal.SIGTERM, native.interrupted)
                signal.signal(signal.SIGINT, native.interrupted)
                return serve(args.root, args.image, args.proof, args.collector_policy)
            value = (
                status(args.root)
                if args.action == "status"
                else command(args.root, args.action, args.request_id)
            )
            print(native.canonical(value).decode("ascii"))
            return 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
        if _diagnostic_record is not None and _diagnostic_record["surface"] == "target":
            with suppress(OSError, RuntimeError, ValueError, TypeError, KeyError):
                diagnostic_failed(error)
        print("The isolated business fixture could not be confirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
