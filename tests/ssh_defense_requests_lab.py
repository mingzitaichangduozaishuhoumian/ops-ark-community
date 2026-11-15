#!/usr/bin/env python3
"""Run the fixed RID protocol through real SSH in owned disposable Docker fixtures.

This is an administrator-operated Linux laboratory, not a deployment tool.  It never
selects a real host, source address, command, policy, or request storage location.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

SOURCE = Path(__file__).resolve().parents[1]
LAB_ROOT = Path("/var/lib/opsark-release-lab")
LABEL = "io.opsark.ssh-defense-requests"
SUBNET = "198.18.241.0/28"
TARGET = "198.18.241.2"
ADDRESSES = {"candidate": "198.18.241.3", "management": "198.18.241.4", "alternate": "198.18.241.5"}
PORT = "22422"
REQUEST_PORT = "22423"
CODE = "/fixture-code"
AUTHORITY = "/fixture-authority"
CLIENT = "/fixture-client"
SELF = f"{CODE}/tests/ssh_defense_requests_lab.py"
INSTALLED = "/usr/local/libexec/opsark-defense/deploy/defense/ssh_requests.py"
REQUEST_ROOT = Path("/var/lib/opsark-ssh-defense-requests")
FAULT_ROOT = Path("/run/opsark-ssh-defense/faults")
DIAGNOSTIC_ROOT = FAULT_ROOT / "diagnostics"
REAL_NFT = Path("/usr/sbin/opsark-nft-real")
SS = "/usr/bin/ss"
PROBE_CASE = "ssh-session-layout"
SOCKET_CASE = "socket-interruption"
SOCKET_PROBE_CASE = "ssh-socket-layout"
SOCKET_CASES = {SOCKET_CASE, SOCKET_PROBE_CASE}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
CONTAINER_SECONDS = 180
CAPS = (
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "KILL",
    "NET_ADMIN",
    "SETGID",
    "SETUID",
    "SYS_CHROOT",
)
CAP_BITS = (29, 0, 1, 3, 5, 12, 6, 7, 18)
FROZEN = {
    "ssh_requests.py": "51149482ab202bbde8bbef5c5ce5a980430db6a71603095b7f56c02884ffd0ee",
    "request_protocol.py": "ebf2884f2bfdbc2f74de3b11179a6024e56b1c77a60a9eeea1a5f58668422ac9",
}
DEFENSE_FILES = (*FROZEN, "ssh_fixture.py", "ssh_fixture_evidence.py", "ssh_fixture_nft.py")
CASES = (
    "positive",
    "revoke",
    "root-auto",
    "four-failures",
    "same-port",
    "success-seen",
    "missing-evidence",
    "manual",
    "missing-observation",
    "missing-controller",
    "missing-root",
    "expired-grant",
    "ssh-session-loss",
    "intent-before-add",
    "intent-after-add",
    SOCKET_CASE,
)
INTENT_CASES = {"intent-before-add", "intent-after-add"}
FAULT_CASES = {*INTENT_CASES, "ssh-session-loss", PROBE_CASE, *SOCKET_CASES}
CASE_SECONDS = {
    case: 150
    if case in {"positive", "ssh-session-loss", "intent-after-add", SOCKET_CASE}
    else 90
    if case in {"revoke", "root-auto", "intent-before-add"}
    else 60
    for case in CASES
}
CLEANUP_SECONDS = 120
REPLY_FIELDS = {
    "v",
    "op",
    "request_id",
    "scope_sha256",
    "policy_sha256",
    "boot_ref",
    "binding_ref",
    "mode",
    "mode_revision",
    "state",
    "action_id",
    "cursor_id",
    "manifest_sha256",
    "deadline_at",
    "remaining_ms",
    "reason_code",
    "candidates",
}
_deadline = float("inf")
_overall_deadline = float("inf")
_last_diagnostic = None
_trace_ref = None
_trace_request_ref = None
_trace_operation = "unparsed"
_trace_order = 0
_trace_sequence = 0
_trace_step = "wrapper_enter"
DIAGNOSTIC_STEPS = {
    "wrapper_enter",
    "target_gate",
    "case_gate",
    "request_read",
    "request_parse",
    "root_cli_run",
    "root_receipt_validate",
    "session_drop_request",
    "session_master_read",
    "session_master_verify",
    "session_ancestry",
    "session_candidate",
    "session_program_verify",
    "session_connections",
    "session_socket_owner",
    "session_marker_write",
    "session_pidfd_pin",
    "session_signal",
    "wrapper_reply",
    "probe_layout",
    "socket_scope",
    "socket_ancestry",
    "socket_tuple",
    "socket_ss_read",
    "socket_marker",
    "socket_destroy",
    "socket_after_absence",
}
FIXED_ERRORS = {
    "The target capability set differs": "target_capabilities_refused",
    "The exact root fixture process could not be identified": "process_program_refused",
    "The fixed SSH process ancestry could not be proven": "session_ancestry_refused",
    "The SSH process ancestry exceeded the fixed bound": "session_ancestry_refused",
    "The control wrapper was not below the request SSH master": "session_ancestry_refused",
    "The exact SSH connection monitor could not be selected": "session_candidate_refused",
    "The request SSH connection was not uniquely scoped": "session_connection_refused",
    "The request socket did not belong to the exact SSH monitor": "session_socket_owner_refused",
    "The pinned fixture process identity changed": "process_identity_changed",
    "The exact fixture process did not terminate": "process_termination_unconfirmed",
    "Unsafe owned fault fixture file": "owned_metadata_refused",
    "Owned fault fixture file changed": "owned_metadata_refused",
    "The original RID or reply grammar differed": "root_receipt_refused",
    "The isolated native request laboratory could not be verified.": "internal_exception",
    "The exact SSH socket was not destroyed": "socket_destroy_unconfirmed",
    "The exact read-only ss filter did not match one SSH socket": "socket_filter_refused",
    "The bound SSH socket changed before interruption": "socket_binding_changed",
    "The cached laboratory image lacks a trusted ss executable": "socket_tool_unavailable",
    "The exact socket scope binding changed": "socket_scope_refused",
    "The exact socket scope declaration changed": "socket_scope_refused",
    "The exact socket close helper had a foreign parent": "socket_parent_refused",
    "The socket helper parent could not be verified": "socket_parent_refused",
    "The socket close helper could not bind its lifetime": "socket_lifetime_refused",
    "The socket close helper had no one-shot claim": "socket_claim_refused",
}
ERROR_CATEGORIES = {
    *FIXED_ERRORS.values(),
    "none",
    "unclassified_stderr",
    "proc_or_file_permission_denied",
    "proc_or_file_missing",
    "process_missing",
    "command_timeout",
    "fixed_tool_check_refused",
    "protocol_or_metadata_refused",
    "os_error",
    "runtime_refused",
}
PROGRAM_CLASSES = {"sshd_master", "sshd_session", "sshd_auth", "python", "other", "unreadable"}
SAFE_OBSERVATIONS = {
    "uid_is_root",
    "same_netns",
    "program_class",
    "proc_access_category",
    "ancestor_count",
    "root_ancestor_count",
    "candidate_count",
    "connection_count",
    "socket_owned",
    "socket_fd_count",
    "root_returncode",
    "root_stdout_bytes",
    "root_stderr_category",
    "receipt_state",
    "ss_returncode",
    "ss_stdout_bytes",
    "ss_stderr_category",
    "tuple_sha256",
    "inode_sha256",
    "ss_sha256",
    "after_absence",
}


def case_budget(case):
    return 60 if case in {PROBE_CASE, SOCKET_PROBE_CASE} else CASE_SECONDS[case]


def error_category(error):
    if isinstance(error, PermissionError):
        return "proc_or_file_permission_denied"
    if isinstance(error, FileNotFoundError):
        return "proc_or_file_missing"
    if isinstance(error, ProcessLookupError):
        return "process_missing"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command_timeout"
    if isinstance(error, LabError):
        return FIXED_ERRORS.get(str(error), "fixed_tool_check_refused")
    if isinstance(error, (ValueError, TypeError, KeyError, StopIteration)):
        return "protocol_or_metadata_refused"
    return "os_error" if isinstance(error, OSError) else "runtime_refused"


def stderr_category(raw):
    if type(raw) is not bytes:
        return "unclassified_stderr"
    if raw == b"":
        return "none"
    return next(
        (
            category
            for message, category in FIXED_ERRORS.items()
            if raw == message.encode("ascii") + b"\n"
        ),
        "unclassified_stderr",
    )


def safe_observations(value):
    if type(value) is not dict or not set(value).issubset(SAFE_OBSERVATIONS):
        return False
    for key, item in value.items():
        if key in {"uid_is_root", "same_netns", "socket_owned", "after_absence"}:
            if type(item) is not bool:
                return False
        elif key == "program_class":
            if type(item) is not str or item not in PROGRAM_CLASSES:
                return False
        elif key in {"proc_access_category", "root_stderr_category", "ss_stderr_category"}:
            if type(item) is not str or item not in ERROR_CATEGORIES:
                return False
        elif key in {"tuple_sha256", "inode_sha256", "ss_sha256"}:
            if type(item) is not str or re.fullmatch(r"[0-9a-f]{64}", item) is None:
                return False
        elif key == "receipt_state":
            if type(item) is not str or item not in {
                "ready",
                "ready_expired",
                "active",
                "rejected",
                "not_found",
                "synced",
                "unknown",
                "expired",
                "revoked",
                "invalid",
                "armed",
                "attached",
                "consumed",
            }:
                return False
        elif type(item) is not int or not -255 <= item <= 8192:
            return False
    return True


def diagnostic_step(step, status, observations=None, category="none"):
    global _trace_sequence, _trace_step
    if _trace_ref is None:
        return
    values = {} if observations is None else observations
    require(
        step in DIAGNOSTIC_STEPS
        and status in {"enter", "ok", "refused"}
        and category in ERROR_CATEGORIES
        and safe_observations(values),
        "Unsafe diagnostic metadata was refused",
    )
    _trace_step = step
    _trace_sequence += 1
    require(_trace_sequence <= 64, "The owned diagnostic event budget was exhausted")
    event = {
        "trace_ref": _trace_ref,
        "trace_order": _trace_order,
        "sequence": _trace_sequence,
        "request_ref": _trace_request_ref,
        "operation": _trace_operation,
        "step": step,
        "status": status,
        "error_category": category,
        "observations": values,
    }
    owned_create(
        DIAGNOSTIC_ROOT / f"{_trace_ref}-{_trace_sequence:03}.json", canonical(event) + b"\n"
    )


def diagnostic_failure(error):
    with suppress(OSError, RuntimeError, ValueError, TypeError, KeyError):
        diagnostic_step(_trace_step, "refused", category=error_category(error))


def program_observations(record):
    process = Path("/proc") / str(record["pid"])
    value = {
        "uid_is_root": record["uid"] == 0,
        "same_netns": False,
        "program_class": "unreadable",
        "proc_access_category": "none",
    }
    try:
        executable = (process / "exe").resolve(strict=True)
        classes = {
            "/usr/sbin/sshd": "sshd_master",
            "/usr/lib/openssh/sshd-session": "sshd_session",
            "/usr/libexec/openssh/sshd-session": "sshd_session",
            "/usr/lib/openssh/sshd-auth": "sshd_auth",
            "/usr/libexec/openssh/sshd-auth": "sshd_auth",
        }
        value["program_class"] = (
            "python"
            if executable == Path("/usr/bin/python3").resolve(strict=True)
            else classes.get(str(executable), "other")
        )
        value["same_netns"] = os.path.samestat(
            (process / "ns/net").stat(), Path("/proc/self/ns/net").stat()
        )
    except OSError as error:
        value["proc_access_category"] = error_category(error)
    return value


class LabError(RuntimeError):
    """A safe, bounded laboratory failure without captured command output."""


def require(condition, message):
    if not condition:
        raise LabError(message)


def capabilities_match(observed, expected):
    """Accept Docker's two spellings without changing the fixed capability set."""
    if observed is None:
        observed = []
    if type(observed) is not list or len(observed) > len(CAPS):
        return False
    if any(type(name) is not str for name in observed):
        return False
    normalized = [name.removeprefix("CAP_") for name in observed]
    return (
        len(normalized) == len(set(normalized))
        and set(normalized).issubset(CAPS)
        and set(normalized) == set(expected)
    )


def fake_capability_regression():
    """Reproduce inspect gate cases without Docker, processes, or fixture resources."""
    bare, prefixed = list(CAPS), [f"CAP_{name}" for name in CAPS]
    cases = (
        (bare, CAPS, True),
        (prefixed, CAPS, True),
        ([prefixed[0], *bare[1:]], CAPS, True),
        (None, (), True),
        ([], (), True),
        (None, CAPS, False),
        ([], CAPS, False),
        (bare[:-1], CAPS, False),
        (prefixed[:-1], CAPS, False),
        ([*bare, "SYS_ADMIN"], CAPS, False),
        ([*prefixed[:-1], "CAP_SYS_ADMIN"], CAPS, False),
        ([*bare[:-1], "CAP_CAP_SYS_CHROOT"], CAPS, False),
        ([*bare[:-1], bare[0]], CAPS, False),
        ([*bare[:-1], prefixed[0]], CAPS, False),
        ([*bare[:-1], None], CAPS, False),
        ([*bare[:-1], 12], CAPS, False),
        ([*bare[:-1], True], CAPS, False),
        ("CAP_CHOWN", CAPS, False),
        (tuple(bare), CAPS, False),
        (["CHOWN"], (), False),
        (["CAP_CHOWN"], (), False),
    )
    for observed, expected, accepted in cases:
        require(
            capabilities_match(observed, expected) is accepted,
            "The fixed capability inspection regression failed",
        )
    return {"checks": len(cases), "docker_calls": 0}


def ipam_config_matches(observed):
    """Allow only the fixed subnet/gateway and Docker's optional empty IPRange."""
    if type(observed) is not list or len(observed) != 1 or type(observed[0]) is not dict:
        return False
    config = observed[0]
    required = {"Subnet": SUBNET, "Gateway": "198.18.241.1"}
    if any(type(key) is not str for key in config):
        return False
    if set(config) not in (set(required), {*required, "IPRange"}):
        return False
    return all(
        type(config[key]) is str and config[key] == value for key, value in required.items()
    ) and ("IPRange" not in config or type(config["IPRange"]) is str and config["IPRange"] == "")


def fake_ipam_regression():
    """Check legacy metadata compatibility without Docker or fixture resources."""
    required = {"Subnet": SUBNET, "Gateway": "198.18.241.1"}
    cases = [
        ([required], True),
        ([{**required, "IPRange": ""}], True),
        (None, False),
        ({}, False),
        (required, False),
        ((required,), False),
        ([], False),
        ([required, required], False),
        ([None], False),
        ([list(required)], False),
        ([{}], False),
        ([{"Subnet": SUBNET}], False),
        ([{"Gateway": "198.18.241.1"}], False),
        ([{**required, "Unknown": ""}], False),
        ([{**required, "IPRange": "", "Unknown": ""}], False),
        ([{**required, "iprange": ""}], False),
        ([{**required, 1: ""}], False),
    ]
    cases.extend(
        ([{**required, "IPRange": value}], False)
        for value in (None, "198.18.241.0/29", " ", "0.0.0.0/0", 0, False, [], {})
    )
    cases.extend(
        ([{**required, "Subnet": value}], False)
        for value in (None, "198.18.241.0/29", "198.18.242.0/28", "", 0, False, [], {})
    )
    cases.extend(
        ([{**required, "Gateway": value}], False)
        for value in (None, "198.18.241.2", "198.18.242.1", "", 0, False, [], {})
    )
    for observed, accepted in cases:
        require(
            ipam_config_matches(observed) is accepted,
            "The fixed network IPAM inspection regression failed",
        )
    return {"checks": len(cases), "docker_calls": 0}


def interrupted(_signal, _frame):
    raise LabError("The native laboratory was interrupted; owned cleanup is required")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_pairs(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), "Repeated JSON field")
    return value


def decode(raw, limit=4096):
    require(
        0 < len(raw) <= limit and raw.endswith(b"\n") and raw.count(b"\n") == 1,
        "Unbounded or incorrectly framed fixture JSON",
    )
    return json.loads(raw, object_pairs_hook=strict_pairs)


def run(*argv, input_bytes=None, timeout=30, limit=65_536, cleanup=False, parent_death=False):
    """Bound both captured streams; never forward a subprocess diagnostic."""
    end = _overall_deadline if cleanup else min(_deadline, _overall_deadline)
    remaining = min(timeout, end - time.monotonic())
    require(remaining > 0, "Laboratory wall-clock limit reached")
    require(input_bytes is None or len(input_bytes) <= 4096, "Oversized fixture input")
    arm = None
    if parent_death:
        require(
            sys.platform == "linux" and argv[0] == str(REAL_NFT),
            "Parent-death binding is fixed to the private native nft tool",
        )
        expected_parent = os.getpid()

        def arm():
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:  # ty: ignore[unresolved-attribute] -- Linux-only PR_SET_PDEATHSIG
                os._exit(1)

    with ExitStack() as streams:
        incoming = subprocess.DEVNULL
        if input_bytes is not None:
            read_descriptor, write_descriptor = os.pipe()
            incoming = streams.enter_context(os.fdopen(read_descriptor, "rb"))
            with os.fdopen(write_descriptor, "wb") as writer:
                writer.write(input_bytes)
        with subprocess.Popen(  # noqa: S603 -- fixed tools and owned fixture operands only.
            argv,
            stdin=incoming,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENV,
            start_new_session=True,
            preexec_fn=arm,
        ) as process:
            output = {"stdout": bytearray(), "stderr": bytearray()}
            try:
                assert process.stdout is not None and process.stderr is not None
                end = time.monotonic() + remaining
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout.fileno(), selectors.EVENT_READ, "stdout")
                    selector.register(process.stderr.fileno(), selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        events = selector.select(max(0, end - time.monotonic()))
                        require(events, "A fixed fixture command timed out")
                        for key, _ in events:
                            chunk = os.read(key.fd, 4096)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                output[key.data].extend(chunk)
                                require(
                                    len(output[key.data]) <= limit, "Fixture output limit reached"
                                )
                code = process.wait(timeout=max(0.01, end - time.monotonic()))
                return subprocess.CompletedProcess(
                    argv, code, bytes(output["stdout"]), bytes(output["stderr"])
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)  # ty: ignore[unresolved-attribute] -- Linux-only
                    process.wait(timeout=3)


def trusted_directory(path, *, private=False):
    require(
        path.is_absolute() and path.resolve(strict=True) == path,
        "Use an absolute trusted directory",
    )
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "An administrator-owned directory is required",
        )
    if private:
        require(stat.S_IMODE(path.stat().st_mode) == 0o700, "A root-private directory is required")


def require_root(root):
    require(
        sys.platform == "linux" and os.geteuid() == 0,
        "Run as root on a disposable Linux laboratory server",
    )
    require(
        root != LAB_ROOT and root.is_relative_to(LAB_ROOT),
        "Use a child of the fixed laboratory root",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_./-]+", str(root)),
        "Use a laboratory path without Docker mount delimiters",
    )
    trusted_directory(root, private=True)
    require(
        not Path("/.dockerenv").exists(),
        "The orchestrator must use the local laboratory Docker daemon",
    )


@contextmanager
def proof_file(root, path):
    require(
        path.parent == root and path.is_absolute(),
        "Proof must be a new direct child of the private laboratory root",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,100}\.json", path.name),
        "Use a simple new JSON proof filename",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW  # ty: ignore[unresolved-attribute] -- Linux-only
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        yield handle


def stage(workspace, case):
    trusted_directory(SOURCE)
    code, keys, management, authority, ready, state = [
        workspace / name for name in ("code", "client", "management", "authority", "ready", "state")
    ]
    for directory in (code, keys, management, authority, ready, state):
        directory.mkdir(mode=0o700)
    files = [
        *(f"deploy/defense/{name}" for name in DEFENSE_FILES),
        "tests/ssh_defense_requests_lab.py",
        "tests/ssh_defense_private_target.py",
        "tests/ssh_defense_lab.py",
    ]
    for relative in files:
        original = SOURCE / relative
        require(original.is_file() and not original.is_symlink(), "Missing trusted fixture source")
        trusted_directory(original.parent)
        info = original.lstat()
        require(
            info.st_uid == 0 and not info.st_mode & 0o022 and info.st_nlink == 1,
            "Fixture sources must be administrator-owned and immutable to other users",
        )
        if original.name in FROZEN:
            require(
                hashlib.sha256(original.read_bytes()).hexdigest() == FROZEN[original.name],
                "Frozen request source hash differs",
            )
        destination = code / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        destination.chmod(0o600)
    for name in ("valid", *(f"invalid-{index}" for index in range(5))):
        result = run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keys / name))
        require(result.returncode == 0, "Synthetic fixture key generation failed")
    shutil.copyfile(keys / "valid.pub", authority / "client.pub")
    for name in ("valid", "valid.pub"):
        shutil.copyfile(keys / name, management / name)
        (management / name).chmod(0o600)
    for role in ("readonly", "observe", "control"):
        result = run(
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(management / role)
        )
        require(result.returncode == 0, "Synthetic role key generation failed")
        shutil.copyfile(management / f"{role}.pub", authority / f"{role}.pub")
    now = datetime.now(UTC)

    def iso(value):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    grants = {
        "observation": secrets.token_hex(16),
        "controller": secrets.token_hex(16),
        "root": secrets.token_hex(16),
    }
    deployment = {
        "v": 1,
        "scope_sha256": digest(["opsark-native-requests-lab/v1", secrets.token_hex(32)]),
        "policy_sha256": policy_sha(),
        "observation_grant": {
            "grant_ref": grants["observation"],
            "not_before": iso(now - timedelta(seconds=5)),
            "deadline_at": iso(now + timedelta(seconds=300)),
        },
        "defense_grants": [
            {
                "root_grant_ref": grants["root"],
                "controller_grant_ref": grants["controller"],
                "mode": "auto" if case == "root-auto" else "semi",
                "mode_revision": 2,
                "not_before": iso(now - timedelta(seconds=120)),
                "deadline_at": iso(now + timedelta(seconds=-1 if case == "expired-grant" else 300)),
                "max_uses": 1,
                "source_aliases": ["fixture-a"],
            }
        ],
    }
    (authority / "deployment.json").write_bytes(canonical(deployment) + b"\n")
    (authority / "lab-case.json").write_bytes(canonical({"case": case}) + b"\n")
    for file in authority.iterdir():
        file.chmod(0o600)
    return code, keys, management, authority, ready, state, deployment, grants


def policy_sha():
    return hashlib.sha256(
        b"opsark-defense-requests/v1;private;198.18.241.0/28;target=.2:22422;"
        b"sources=.3,.5;management=.4;arm=120s;ttl=60000ms;ports=5;"
        b"success=deny;capacity=8;single-element;no-retry-after-intent"
    ).hexdigest()


class Network:
    def __init__(self, workspace, image, cleanup):
        self.workspace = workspace
        self.removing = False
        self.image, self.fixture = image, secrets.token_hex(8)
        self.name = "opsark-requests-" + self.fixture
        self.base = (
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(workspace),
        )
        self.owned = set()
        inspected = self.inspect("image", image)
        self.container_labels = {**(inspected["Config"].get("Labels") or {}), LABEL: self.fixture}
        require(
            inspected["Id"] == image and not inspected["Config"].get("Volumes"),
            "Fixture image must be pinned and declare no volumes",
        )
        self.identity = self.identifier(
            self.command(
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--subnet",
                SUBNET,
                "--gateway",
                "198.18.241.1",
                "--label",
                f"{LABEL}={self.fixture}",
                self.name,
            )
        )
        cleanup.callback(self.remove, "network", self.identity)
        observed = self.inspect("network", self.identity)
        require(
            observed["Name"] == self.name
            and observed["Driver"] == "bridge"
            and observed["Internal"]
            and not observed["EnableIPv6"]
            and ipam_config_matches(observed["IPAM"]["Config"])
            and observed["Labels"] == {LABEL: self.fixture}
            and not observed.get("Containers"),
            "The new fixture network was not exactly isolated",
        )
        self.cleanup = cleanup

    @staticmethod
    def identifier(raw):
        value = raw.decode("ascii").strip()
        require(re.fullmatch(r"[0-9a-f]{64}", value), "Docker did not return a complete fixture ID")
        return value

    def command(self, *args):
        result = run(*self.base, *args, cleanup=self.removing, timeout=10 if self.removing else 30)
        require(result.returncode == 0, "A fixed fixture Docker operation failed")
        return result.stdout

    def inspect(self, kind, identity):
        value = json.loads(self.command(kind, "inspect", identity))
        require(
            type(value) is list and len(value) == 1 and value[0]["Id"] == identity,
            "Docker inspection identity differed",
        )
        return value[0]

    def remove(self, kind, identity):
        # Cleanup retains its own short deadline after the experiment wall clock expires.
        self.removing = True
        try:
            self._remove(kind, identity)
        finally:
            self.removing = False

    def _remove(self, kind, identity):
        observed = self.inspect(kind, identity)
        labels = observed["Config"]["Labels"] if kind == "container" else observed["Labels"]
        expected = self.container_labels if kind == "container" else {LABEL: self.fixture}
        require(labels == expected, "Cleanup refused a foreign resource label")
        if kind == "network":
            require(
                set(observed.get("Containers", {})).issubset(self.owned),
                "Cleanup refused foreign network endpoints",
            )
        self.command(kind, "rm", *(("-f",) if kind == "container" else ()), identity)

    def start(self, role, address, mounts, *, target=False):
        entry = ("/usr/bin/timeout", "-k", "2s", f"{CONTAINER_SECONDS}s")
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

    def execute(self, identity, *args, input_bytes=None, timeout=30):
        require(identity in self.owned, "Execution refused a foreign container")
        return run(
            *self.base,
            "exec",
            "-i",
            identity,
            *args,
            input_bytes=input_bytes,
            timeout=timeout,
            limit=8192,
        )


def ssh_argv(*, role=None, valid=True, same_port=False):
    identity = role if role else "valid" if valid else "invalid-0"
    keys = (
        [f"{CLIENT}/invalid-{index}" for index in range(5)]
        if same_port
        else [f"{CLIENT}/{identity}"]
    )
    return (
        "/usr/bin/timeout",
        "-k",
        "1s",
        "25s",
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-oBatchMode=yes",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oGlobalKnownHostsFile=/dev/null",
        f"-oUserKnownHostsFile={CLIENT}/known_hosts",
        "-oStrictHostKeyChecking=yes",
        "-oUpdateHostKeys=no",
        "-oPreferredAuthentications=publickey",
        "-oConnectionAttempts=1",
        "-oConnectTimeout=2",
        "-oLogLevel=ERROR",
        *(part for key in keys for part in ("-i", key)),
        "-p",
        REQUEST_PORT if role else PORT,
        f"opsark-defense-{role}@{TARGET}" if role else f"opsark-ssh-lab@{TARGET}",
        "opsark-defense-request-v1" if role else "/usr/bin/true",
    )


def login(network, client, *, valid=True, blocked=False, same_port=False):
    result = network.execute(client, *ssh_argv(valid=valid, same_port=same_port))
    if blocked:
        require(
            result.returncode == 255
            and b"Connection timed out" in result.stderr
            and not result.stdout,
            "Candidate SSH did not time out at the TCP layer",
        )
    elif valid:
        require(result.returncode == 0 and not result.stdout, "Pinned native SSH did not pass")
    else:
        require(
            result.returncode == 255
            and b"Permission denied (publickey)" in result.stderr
            and not result.stdout,
            "Expected a real rejected public-key authentication",
        )


def http_health(network, client):
    probe = (
        "import http.client;c=http.client.HTTPConnection('198.18.241.2',22480,timeout=3);"
        "c.request('GET','/health');r=c.getresponse();print(r.status);c.close()"
    )
    result = network.execute(client, "/usr/bin/python3", "-I", "-B", "-c", probe)
    require(result.returncode == 0 and result.stdout == b"204\n", "Same-source HTTP was affected")


def frame(scope, op, rid, body):
    return {"v": 1, "op": op, "request_id": rid, "scope_sha256": scope, "body": body}


def validate_reply(payload, request):
    require(
        type(payload) is dict
        and set(payload) == REPLY_FIELDS
        and payload["v"] == 1
        and payload["op"] == request["op"]
        and payload["request_id"] == request["request_id"]
        and payload["scope_sha256"] == request["scope_sha256"]
        and payload["policy_sha256"] == policy_sha(),
        "The original RID or reply grammar differed",
    )
    require(
        payload["remaining_ms"] is None
        or type(payload["remaining_ms"]) is int
        and 0 < payload["remaining_ms"] <= 60_000,
        "Kernel TTL exceeded the fixed bound",
    )
    return payload


def rpc(network, management, request, role="control"):
    result = network.execute(
        management, *ssh_argv(role=role), input_bytes=canonical(request) + b"\n"
    )
    require(
        result.returncode == 0 and not result.stderr,
        "The fixed SSH JSON dispatcher did not return a bounded receipt",
    )
    return validate_reply(decode(result.stdout), request)


def dropped_rpc(network, management, request):
    result = network.execute(
        management,
        "/usr/bin/python3",
        "-I",
        "-B",
        SELF,
        "--internal-drop",
        "--image",
        network.image,
        "--confirm-isolated",
        input_bytes=canonical(request) + b"\n",
        timeout=32,
    )
    require(
        result.returncode == 0 and not result.stderr, "The native SSH receipt-drop fixture failed"
    )
    proof = decode(result.stdout)
    require(
        set(proof) == {"tcp_reset", "fault_layer", "identity_binding_sha256"}
        and proof["tcp_reset"] is True
        and proof["fault_layer"] == "management_loopback_after_native_ssh"
        and re.fullmatch(r"[0-9a-f]{64}", proof["identity_binding_sha256"]),
        "The reset was not confirmed at the declared layer",
    )
    return proof


def fault_proof(network, target, request):
    result = network.execute(
        target,
        "/usr/bin/python3",
        "-I",
        "-B",
        SELF,
        "--internal-fault-proof",
        "--image",
        network.image,
        "--confirm-isolated",
        input_bytes=canonical(request) + b"\n",
    )
    require(
        result.returncode == 0 and not result.stderr,
        "The owned target fault proof was not confirmed",
    )
    proof = decode(result.stdout)
    require(
        proof["request_ref"] == request["request_id"]
        and proof["ssh_session_terminated"]
        and proof["request_master_preserved"]
        and proof["native_listener_preserved"],
        "The original SSH fault scope could not be confirmed",
    )
    return proof


def session_dropped_rpc(network, target, management, request):
    global _last_diagnostic
    result = network.execute(
        management, *ssh_argv(role="control"), input_bytes=canonical(request) + b"\n"
    )
    if result.returncode != 255 or result.stdout:
        _last_diagnostic = session_failure_diagnostic(network, target, request, result)
    require(
        result.returncode == 255 and not result.stdout,
        "The actual target SSH session did not terminate without a JSON acknowledgement",
    )
    try:
        proof = fault_proof(network, target, request)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        _last_diagnostic = session_failure_diagnostic(network, target, request, result)
        raise
    proof["ssh_exit_code"] = result.returncode
    return proof


def session_failure_diagnostic(network, target, request, result):
    diagnostic = {
        "operation": request["op"],
        "ssh_returncode": result.returncode,
        "ssh_stdout_bytes": len(result.stdout),
        "stderr_category": stderr_category(result.stderr),
        "target_metadata": {"metadata_category": "unavailable"},
    }
    try:
        exported = network.execute(
            target,
            "/usr/bin/python3",
            "-I",
            "-B",
            SELF,
            "--internal-diagnostics",
            "--image",
            network.image,
            "--confirm-isolated",
            input_bytes=canonical(request) + b"\n",
            timeout=5,
        )
        if exported.returncode == 0 and not exported.stderr:
            metadata = decode(exported.stdout, 6144)
            require(diagnostic_export_valid(metadata), "Unsafe diagnostic export was refused")
            diagnostic["target_metadata"] = metadata
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    return diagnostic


def diagnostic_export_valid(value):
    if type(value) is not dict or set(value) != {
        "schema",
        "trace_ref",
        "event_count",
        "events",
        "ledger",
    }:
        return False
    if value["schema"] != "opsark-session-diagnostics/v1" or type(value["trace_ref"]) is not str:
        return False
    if (
        re.fullmatch(r"[0-9a-f]{16}", value["trace_ref"]) is None
        or type(value["event_count"]) is not int
    ):
        return False
    if (
        not 0 <= value["event_count"] <= 64
        or type(value["events"]) is not list
        or len(value["events"]) > 24
    ):
        return False
    for event in value["events"]:
        if type(event) is not dict or set(event) != {
            "sequence",
            "step",
            "status",
            "error_category",
            "observations",
        }:
            return False
        if type(event["sequence"]) is not int or not 1 <= event["sequence"] <= 64:
            return False
        if (
            type(event["step"]) is not str
            or event["step"] not in DIAGNOSTIC_STEPS
            or type(event["status"]) is not str
            or event["status"] not in {"enter", "ok", "refused"}
            or type(event["error_category"]) is not str
            or event["error_category"] not in ERROR_CATEGORIES
            or not safe_observations(event["observations"])
        ):
            return False
    ledger = value["ledger"]
    return (
        type(ledger) is dict
        and set(ledger) == {"phase", "record_count", "usage_count", "ledger_sha256"}
        and type(ledger["phase"]) is str
        and ledger["phase"]
        in {
            "not_found",
            "armed",
            "attached",
            "consumed",
            "ready",
            "intent",
            "active",
            "revoke_intent",
            "revoked",
            "rejected",
            "synced",
            "invalid_state",
        }
        and type(ledger["record_count"]) is int
        and 0 <= ledger["record_count"] <= 48
        and type(ledger["usage_count"]) is int
        and 0 <= ledger["usage_count"] <= 8
        and type(ledger["ledger_sha256"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", ledger["ledger_sha256"]) is not None
    )


def fake_diagnostic_regression():
    checks = 0
    message = "The exact root fixture process could not be identified"
    for raw, expected in (
        (b"", "none"),
        (message.encode("ascii") + b"\n", "process_program_refused"),
        (message.encode("ascii") + b"\nsynthetic-private", "unclassified_stderr"),
        (b"synthetic-private", "unclassified_stderr"),
    ):
        require(
            stderr_category(raw) == expected, "The closed stderr classification regression failed"
        )
        checks += 1
    for value, accepted in (
        ({}, True),
        ({"program_class": "sshd_session", "same_netns": True}, True),
        ({"raw_stderr": "synthetic-private"}, False),
        ({"private_key": "synthetic-private"}, False),
        ({"program_class": "/unexpected/raw/path"}, False),
        ({"same_netns": 1}, False),
        ({"root_returncode": True}, False),
        ({"root_stdout_bytes": 8193}, False),
        ({"receipt_state": []}, False),
    ):
        require(
            safe_observations(value) is accepted,
            "The closed observation metadata regression failed",
        )
        checks += 1
    valid = {
        "schema": "opsark-session-diagnostics/v1",
        "trace_ref": "1" * 16,
        "event_count": 1,
        "events": [
            {
                "sequence": 1,
                "step": "session_program_verify",
                "status": "enter",
                "error_category": "none",
                "observations": {"program_class": "sshd_session", "uid_is_root": True},
            }
        ],
        "ledger": {
            "phase": "ready",
            "record_count": 3,
            "usage_count": 0,
            "ledger_sha256": "2" * 64,
        },
    }
    require(diagnostic_export_valid(valid), "Valid safe diagnostic metadata was refused")
    checks += 1
    for changes in (
        {"schema": "synthetic-private"},
        {"raw_stderr": "synthetic-private"},
        {"trace_ref": "bad"},
        {"event_count": 65},
        {"event_count": True},
        {"events": None},
    ):
        value = {**valid, **changes}
        require(not diagnostic_export_valid(value), "Unsafe diagnostic envelope was accepted")
        checks += 1
    for changes in (
        {"step": "arbitrary-step"},
        {"status": []},
        {"error_category": "synthetic-private"},
        {"observations": {"stdout": "synthetic-private"}},
        {"sequence": True},
        {"sequence": 65},
    ):
        value = {**valid, "events": [{**valid["events"][0], **changes}]}
        require(not diagnostic_export_valid(value), "Unsafe diagnostic event was accepted")
        checks += 1
    for changes in (
        {"phase": "synthetic-private"},
        {"phase": []},
        {"record_count": True},
        {"usage_count": 9},
        {"ledger_sha256": "bad"},
    ):
        require(
            not diagnostic_export_valid({**valid, "ledger": {**valid["ledger"], **changes}}),
            "Unsafe diagnostic ledger metadata was accepted",
        )
        checks += 1

    class RefusedMetadataNetwork:
        image = "sha256:" + "0" * 64

        @staticmethod
        def execute(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                ("fixed-fake",), 1, b"synthetic-private", b"synthetic-private"
            )

    result = session_failure_diagnostic(
        RefusedMetadataNetwork(),
        "fixed-fake-target",
        {"op": "prepare"},
        subprocess.CompletedProcess(("fixed-fake",), 1, b"synthetic-private", b"synthetic-private"),
    )
    require(
        b"synthetic-private" not in canonical(result)
        and result["ssh_stdout_bytes"] == 17
        and result["ssh_returncode"] == 1
        and result["stderr_category"] == "unclassified_stderr",
        "Failed SSH diagnostics leaked captured output",
    )
    require(
        PROBE_CASE not in CASES and case_budget(PROBE_CASE) == 60,
        "The read-only session probe entered the mutation suite",
    )
    checks += 2
    return {"checks": checks, "docker_calls": 0}


def exercise_layout_probe(network, target, management, scope, initial):
    global _last_diagnostic
    request = frame(scope, "query", secrets.token_hex(16), {"kind": "mode"})
    result = network.execute(
        management, *ssh_argv(role="control"), input_bytes=canonical(request) + b"\n"
    )
    if result.returncode != 0:
        _last_diagnostic = session_failure_diagnostic(network, target, request, result)
    require(
        result.returncode == 0 and not result.stderr,
        "The read-only SSH session layout probe did not pass its strict gate",
    )
    value = decode(result.stdout)
    require(
        set(value) == {"schema", "request_ref", "layout_proven", "master_ref", "monitor_ref"}
        and value["schema"] == "opsark-ssh-session-layout/v1"
        and value["request_ref"] == request["request_id"]
        and value["layout_proven"] is True
        and re.fullmatch(r"[0-9a-f]{64}", value["master_ref"])
        and re.fullmatch(r"[0-9a-f]{64}", value["monitor_ref"]),
        "The SSH layout probe did not return fixed safe metadata",
    )
    final = snapshot(network, target)
    require(final == initial, "The query-only SSH layout probe changed initialized state")
    return {
        "case": PROBE_CASE,
        "state": "observed",
        "strict_layout_proven": True,
        "root_prepare_or_apply_executed": False,
        "session_signal_sent": False,
        "ledger_unchanged": True,
        "master_ref": value["master_ref"],
        "monitor_ref": value["monitor_ref"],
        "owned_resources_removed": True,
    }


def identity_binding(reply):
    return digest({key: reply[key] for key in ("action_id", "manifest_sha256", "cursor_id")})


def snapshot(network, target):
    result = network.execute(
        target,
        "/usr/bin/python3",
        "-I",
        "-B",
        SELF,
        "--internal-snapshot",
        "--image",
        network.image,
        "--confirm-isolated",
    )
    require(
        result.returncode == 0 and not result.stderr, "The private ledger proof was unavailable"
    )
    value = decode(result.stdout)
    require(
        set(value)
        == {
            "ledger_sha256",
            "records",
            "usage_count",
            "intents",
            "kernel_active",
            "candidate_failure_events",
            "candidate_success_events",
        },
        "Unexpected private ledger proof",
    )
    return value


def approval(request_id, manifest, purpose, deadline):
    now = datetime.now(UTC)
    expires = min(
        datetime.fromisoformat(deadline.replace("Z", "+00:00")), now + timedelta(seconds=100)
    )
    return {
        "approval_id": secrets.token_hex(16),
        "purpose": purpose,
        "request_id": request_id,
        "manifest_sha256": manifest,
        "approved_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
    }


def ready(network, target, path):
    for _ in range(100):
        if path.exists():
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and 0 < info.st_size <= 256,
                "The readiness marker was not private",
            )
            value = json.loads(path.read_bytes(), object_pairs_hook=strict_pairs)
            require(
                set(value) == {"status", "host_public_key"}
                and value["status"] == "ready"
                and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", value["host_public_key"]),
                "The native target host pin was invalid",
            )
            return value["host_public_key"]
        require(
            network.inspect("container", target)["State"]["Running"],
            "The target stopped during fixed provisioning",
        )
        time.sleep(0.1)
    raise LabError("The native target did not become ready")


def exercise_socket_probe(network, target, management, scope, initial):
    global _last_diagnostic
    request = frame(scope, "query", secrets.token_hex(16), {"kind": "mode"})
    result = network.execute(
        management, *ssh_argv(role="control"), input_bytes=canonical(request) + b"\n"
    )
    if result.returncode != 0:
        _last_diagnostic = session_failure_diagnostic(network, target, request, result)
    require(
        result.returncode == 0 and not result.stderr,
        "The read-only SSH socket layout probe did not pass",
    )
    value = decode(result.stdout)
    require(
        set(value)
        == {
            "schema",
            "request_ref",
            "tuple_sha256",
            "inode_sha256",
            "ss_sha256",
            "master_ref",
            "scope_bound",
            "namespace_bound",
            "ss_read_matched",
            "destroy_invoked",
        }
        and value["schema"] == "opsark-ssh-socket-layout/v1"
        and value["request_ref"] == request["request_id"]
        and value["scope_bound"] is True
        and value["namespace_bound"] is True
        and value["ss_read_matched"] is True
        and value["destroy_invoked"] is False
        and all(
            type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
            for key in ("tuple_sha256", "inode_sha256", "ss_sha256", "master_ref")
        ),
        "The SSH socket probe did not return fixed safe metadata",
    )
    require(
        snapshot(network, target) == initial,
        "The query-only SSH socket probe changed initialized state",
    )
    return {
        "case": SOCKET_PROBE_CASE,
        "state": "observed",
        "scope_and_namespace_bound": True,
        "unique_exact_tuple_and_ss_read_matched": True,
        "root_prepare_or_apply_executed": False,
        "destroy_invoked": False,
        "session_signal_sent": False,
        "ledger_unchanged": True,
        "tuple_sha256": value["tuple_sha256"],
        "inode_sha256": value["inode_sha256"],
        "ss_sha256": value["ss_sha256"],
        "owned_resources_removed": True,
    }


def exercise_intent_fault(network, target, clients, case, prepared, prepare, apply, query):
    candidate, management, alternate = [clients[role] for role in ADDRESSES]
    lost = session_dropped_rpc(network, target, management, apply)
    require(
        lost["root_cli_killed"]
        and lost["shim_terminated"]
        and lost["phase"] == "intent"
        and lost["usage_count"] == 1
        and not lost["expiry_bound_present"]
        and lost["real_add_count"] == (1 if case == "intent-after-add" else 0),
        "The durable intent boundary was not the requested deterministic fault",
    )
    observed = rpc(network, management, query, "readonly")
    expected = "active" if case == "intent-after-add" else "unknown"
    require(
        observed["state"] == expected and identity_binding(observed) == identity_binding(prepared),
        "A restarted Root CLI did not reconcile the original intent RID",
    )
    before = snapshot(network, target)
    require(
        before["usage_count"] == 1
        and before["intents"] == 1
        and before["kernel_active"] == (case == "intent-after-add")
        and before["ledger_sha256"] == lost["ledger_sha256"],
        "The fault recovery changed durable intent state",
    )
    for _ in range(2):
        login(network, candidate, blocked=case == "intent-after-add")
        login(network, management)
        login(network, alternate)
        http_health(network, candidate)
        latest = rpc(network, management, query)
        repeated_prepare = rpc(network, management, prepare)
        repeated_apply = rpc(network, management, apply)
        require(
            all(
                value["state"] == expected and identity_binding(value) == identity_binding(prepared)
                for value in (latest, repeated_prepare, repeated_apply)
            ),
            "An exact repeated request changed the original ambiguous action",
        )
        if expected == "active":
            require(
                repeated_apply["remaining_ms"] <= observed["remaining_ms"],
                "An ambiguous intent refreshed the kernel TTL",
            )
        current = snapshot(network, target)
        require(
            all(
                current[key] == before[key]
                for key in ("ledger_sha256", "records", "usage_count", "intents", "kernel_active")
            )
            and fault_proof(network, target, apply)
            == {key: value for key, value in lost.items() if key != "ssh_exit_code"},
            "Queries or repeated requests wrote state, replenished quota, or repeated native add",
        )
    if case == "intent-after-add":
        until = time.monotonic() + repeated_apply["remaining_ms"] / 1000 + 0.5
        while time.monotonic() < until:
            login(network, management)
            login(network, alternate)
            http_health(network, candidate)
            time.sleep(max(0, min(3, until - time.monotonic())))
        # No dispatcher/nft call during the wait: real SSH first demonstrates kernel expiry.
        login(network, candidate)
    else:
        time.sleep(1)
    final = rpc(network, management, query, "readonly")
    require(
        final["state"] == "unknown"
        and final["reason_code"] == "result_unknown"
        and final["remaining_ms"] is None
        and identity_binding(final) == identity_binding(prepared),
        "An intent without persistent active bound was incorrectly promoted to a finished result",
    )
    require(rpc(network, management, apply)["state"] == "unknown", "A crashed intent was rearmed")
    final_snapshot = snapshot(network, target)
    final_fault = fault_proof(network, target, apply)
    require(
        final_snapshot["ledger_sha256"] == before["ledger_sha256"]
        and final_snapshot["usage_count"] == 1
        and not final_snapshot["kernel_active"]
        and final_fault == {key: value for key, value in lost.items() if key != "ssh_exit_code"},
        "The final ambiguous intent changed quota or attempted another native write",
    )
    login(network, candidate)
    return {
        "case": case,
        "state": "unknown",
        "scope_sha256": query["scope_sha256"],
        "request_ref": query["request_id"],
        "action_ref": prepared["action_id"],
        "manifest_sha256": prepared["manifest_sha256"],
        "fault": final_fault,
        "root_cli_restarted_by_new_ssh_queries": True,
        "original_rid_binding_preserved": True,
        "duplicate_requests_no_ledger_write_or_new_add": True,
        "quota_remained_consumed": True,
        "management_and_contrast_ssh_preserved": True,
        "same_source_http_preserved": True,
        "kernel_recovered_independently": case == "intent-after-add",
        "ledger": final_snapshot,
        "owned_resources_removed": True,
    }


def exercise_case(root, image, case):
    with TemporaryDirectory(prefix="requests-", dir=root) as temporary, ExitStack() as cleanup:
        workspace = Path(temporary)
        staged = stage(workspace, case)
        code, keys, management_keys, authority, readiness, state, deployment, grants = staged
        network = Network(workspace, image, cleanup)
        target = network.start(
            "target",
            TARGET,
            [
                (code, CODE, True),
                (authority, AUTHORITY, True),
                (readiness, "/fixture-ready", False),
                (state, "/var/lib", False),
            ],
            target=True,
        )
        pin = ready(network, target, readiness / "ready.json")
        for directory in (keys, management_keys):
            (directory / "known_hosts").write_text(
                f"[{TARGET}]:{PORT} {pin}\n[{TARGET}]:{REQUEST_PORT} {pin}\n", encoding="ascii"
            )
            (directory / "known_hosts").chmod(0o600)
        clients = {}
        for role, address in ADDRESSES.items():
            selected = management_keys if role == "management" else keys
            clients[role] = network.start(
                role, address, [(code, CODE, True), (selected, CLIENT, True)]
            )
        candidate, management, alternate = [clients[role] for role in ADDRESSES]
        login(network, candidate)
        login(network, alternate)
        login(network, management)
        scope = deployment["scope_sha256"]
        baseline = rpc(
            network,
            management,
            frame(scope, "query", secrets.token_hex(16), {"kind": "mode"}),
            "readonly",
        )
        require(
            baseline["state"] == "not_found" and baseline["mode"] == "manual",
            "Default role or mode was not readonly/manual",
        )
        http_health(network, candidate)
        initial = snapshot(network, target)
        require(
            initial["records"] == {}
            and initial["usage_count"] == 0
            and not initial["kernel_active"],
            "The target was not a fresh initialized fixture",
        )
        if case == PROBE_CASE:
            return exercise_layout_probe(network, target, management, scope, initial)
        if case == SOCKET_PROBE_CASE:
            return exercise_socket_probe(network, target, management, scope, initial)
        mode = frame(
            scope,
            "mode_sync",
            secrets.token_hex(16),
            {
                "mode": "auto" if case == "root-auto" else "semi",
                "mode_revision": 2,
                "policy_sha256": policy_sha(),
            },
        )
        denied = rpc(network, management, mode, "readonly")
        require(
            denied["state"] == "rejected"
            and denied["reason_code"] == "authorization_denied"
            and snapshot(network, target) == initial,
            "Readonly mutation changed the initialized target",
        )
        if case != "manual":
            require(
                rpc(network, management, mode)["state"] == "synced",
                "Mode synchronization did not confirm",
            )
        arm_id = secrets.token_hex(16)
        arm = frame(
            scope,
            "arm",
            arm_id,
            {
                "observation_grant_ref": secrets.token_hex(16)
                if case == "missing-observation"
                else grants["observation"],
                "policy_sha256": policy_sha(),
            },
        )
        armed = rpc(network, management, arm, "observe")
        if case == "missing-observation":
            require(
                armed["state"] == "rejected" and armed["reason_code"] == "authorization_denied",
                "Missing observation authorization was accepted",
            )
            final = snapshot(network, target)
            require(
                not final["kernel_active"] and final["intents"] == 0,
                "A rejected observation produced an action",
            )
            return {
                "case": case,
                "state": "rejected",
                "reason_code": armed["reason_code"],
                "native_action_absent": True,
                "owned_resources_removed": True,
                "ledger": final,
            }
        require(
            armed["state"] == "armed" and re.fullmatch(r"[0-9a-f]{32}", armed["cursor_id"]),
            "The 120-second observation did not arm",
        )
        failures = (
            0
            if case == "missing-evidence"
            else 4
            if case == "four-failures"
            else 1
            if case == "same-port"
            else 5
        )
        for _ in range(failures):
            login(network, candidate, valid=False, same_port=case == "same-port")
        if case == "success-seen":
            login(network, candidate)
        cursor = rpc(
            network, management, frame(scope, "query", arm_id, {"kind": "cursor"}), "readonly"
        )
        require(
            cursor["cursor_id"] == armed["cursor_id"] and len(cursor["candidates"]) == 2,
            "Original cursor identity was not preserved",
        )
        evidence = next(
            item for item in cursor["candidates"] if item["source_alias"] == "fixture-a"
        )
        expected_ports = 1 if case == "same-port" else failures
        require(
            evidence["distinct_failure_ports"] == expected_ports,
            "Native authentication did not produce the expected distinct source-port count",
        )
        observed_events = snapshot(network, target)
        require(
            observed_events["candidate_failure_events"] == (5 if case == "same-port" else failures)
            and observed_events["candidate_success_events"] == (1 if case == "success-seen" else 0),
            "Native authentication event counts did not match the fixture attempts",
        )
        rid = secrets.token_hex(16)
        prepare = frame(
            scope,
            "prepare",
            rid,
            {
                "cursor_id": armed["cursor_id"],
                "source_ref": evidence["source_ref"],
                "evidence_sha256": evidence["evidence_sha256"] or "0" * 64,
                "policy_sha256": policy_sha(),
                "mode": "auto" if case == "root-auto" else "semi",
                "mode_revision": 2,
                "controller_grant_ref": secrets.token_hex(16)
                if case == "missing-controller"
                else grants["controller"],
                "root_grant_ref": secrets.token_hex(16)
                if case == "missing-root"
                else grants["root"],
            },
        )
        query = frame(scope, "query", rid, {"kind": "action"})
        before_prepare = snapshot(network, target)
        readonly = rpc(network, management, prepare, "readonly")
        require(
            readonly["state"] == "rejected"
            and readonly["reason_code"] == "authorization_denied"
            and snapshot(network, target) == before_prepare,
            "Readonly prepare caused a write",
        )
        if case not in {"positive", "revoke", "root-auto", *FAULT_CASES}:
            rejected = rpc(network, management, prepare)
            reason = {
                "four-failures": "evidence_gap",
                "same-port": "evidence_gap",
                "success-seen": "success_seen",
                "missing-evidence": "evidence_gap",
                "manual": "mode_unsynced",
                "missing-controller": "authorization_denied",
                "missing-root": "authorization_denied",
                "expired-grant": "authorization_denied",
            }[case]
            require(
                rejected["state"] == "rejected" and rejected["reason_code"] == reason,
                "A negative admission case was not refused",
            )
            final = snapshot(network, target)
            require(
                final["intents"] == 0 and final["usage_count"] == 0 and not final["kernel_active"],
                "A refused prepare produced a native action",
            )
            login(network, candidate)
            http_health(network, candidate)
            return {
                "case": case,
                "state": "rejected",
                "reason_code": reason,
                "distinct_failure_ports": expected_ports,
                "native_action_absent": True,
                "owned_resources_removed": True,
                "ledger": final,
            }
        if case in INTENT_CASES:
            prepared_directly = rpc(network, management, prepare)
            require(
                prepared_directly["state"] == "ready", "The intent fault action did not prepare"
            )
            prepare_drop = {"identity_binding_sha256": identity_binding(prepared_directly)}
        elif case in {"ssh-session-loss", SOCKET_CASE}:
            prepare_drop = session_dropped_rpc(network, target, management, prepare)
            require(
                prepare_drop["root_cli_completed"],
                "The prepare SSH loss preceded a committed Root receipt",
            )
        else:
            prepare_drop = dropped_rpc(network, management, prepare)
        prepared = rpc(network, management, query)
        require(
            prepared["state"] == "ready"
            and identity_binding(prepared) == prepare_drop["identity_binding_sha256"]
            and prepared["cursor_id"] == armed["cursor_id"],
            "Original prepare RID did not recover the same action and manifest",
        )
        readback = snapshot(network, target)
        require(
            readback["records"] == {"cursor": 1, "mode": 1, "action": 1}
            and readback["usage_count"] == 0,
            "Prepare recovery created another cursor or action",
        )
        manifest = prepared["manifest_sha256"]
        declaration = (
            None
            if case == "root-auto"
            else approval(rid, manifest, "apply", prepared["deadline_at"])
        )
        apply = frame(scope, "apply", rid, {"manifest_sha256": manifest, "approval": declaration})
        missing_approval = frame(
            scope, "apply", rid, {"manifest_sha256": manifest, "approval": None}
        )
        if case != "root-auto":
            refused = rpc(network, management, missing_approval)
            require(
                refused["state"] == "rejected"
                and refused["reason_code"] == "authorization_denied"
                and snapshot(network, target) == readback,
                "A missing exact apply declaration caused a write",
            )
        refused = rpc(network, management, apply, "readonly")
        require(
            refused["state"] == "rejected" and snapshot(network, target) == readback,
            "Readonly apply caused a write",
        )
        if case in INTENT_CASES:
            return exercise_intent_fault(
                network, target, clients, case, prepared, prepare, apply, query
            )
        if case in {"ssh-session-loss", SOCKET_CASE}:
            apply_drop = session_dropped_rpc(network, target, management, apply)
            require(
                apply_drop["root_cli_completed"],
                "The apply SSH loss preceded the committed Root receipt",
            )
        else:
            apply_drop = dropped_rpc(network, management, apply)
        active = rpc(network, management, query)
        require(
            active["state"] == "active"
            and identity_binding(active) == identity_binding(prepared)
            and identity_binding(active) == apply_drop["identity_binding_sha256"],
            "Original apply RID did not recover the confirmed native action",
        )
        if case in {"ssh-session-loss", SOCKET_CASE}:
            require(
                active["remaining_ms"] <= apply_drop["remaining_ms_before_loss"],
                "SSH recovery raised the committed native TTL",
            )
        applied = snapshot(network, target)
        require(
            applied["usage_count"] == 1 and applied["intents"] == 1 and applied["kernel_active"],
            "The native action did not have exactly one admitted intent",
        )
        for _ in range(2):
            login(network, candidate, blocked=True)
            login(network, management)
            # Both management and the independent attack contrast retain authenticated SSH access.
            require(
                rpc(network, management, query, "readonly")["state"] == "active",
                "Management SSH became unavailable",
            )
            login(network, alternate)
            http_health(network, candidate)
        after_recovery = rpc(network, management, query)
        require(
            after_recovery["remaining_ms"] < active["remaining_ms"]
            and snapshot(network, target) == applied,
            "Query recovery changed the ledger or raised the TTL",
        )
        # This is a separate explicit duplicate test, after query-only recovery completed.
        duplicate = rpc(network, management, apply)
        require(
            duplicate["state"] == "active"
            and duplicate["remaining_ms"] <= after_recovery["remaining_ms"]
            and snapshot(network, target) == applied,
            "Duplicate apply wrote state or refreshed TTL",
        )
        result = {
            "case": case,
            "scope_sha256": scope,
            "request_ref": rid,
            "cursor_ref": prepared["cursor_id"],
            "action_ref": prepared["action_id"],
            "manifest_sha256": manifest,
            "evidence_sha256": evidence["evidence_sha256"],
            "distinct_failure_ports": 5,
            "prepare_recovered_by_original_rid": True,
            "apply_recovered_by_query_only": True,
            "fault_layer": prepare_drop["fault_layer"],
            "readonly_mutations_no_write": True,
            "duplicate_apply_ledger_unchanged": True,
            "duplicate_apply_ttl_not_increased": True,
            "management_and_contrast_ssh_preserved": True,
            "same_source_http_preserved": True,
        }
        if case in {"ssh-session-loss", SOCKET_CASE}:
            result.update(
                prepare_ssh_exit_255_no_json=True,
                apply_ssh_exit_255_no_json=True,
                request_master_and_native_listener_preserved=True,
            )
            if case == SOCKET_CASE:
                result.update(
                    target_exact_socket_interruption=True,
                    session_signal_sent=False,
                    prepare_before_tuple_sha256=prepare_drop["before_tuple_sha256"],
                    apply_before_tuple_sha256=apply_drop["before_tuple_sha256"],
                    exact_after_absence_verified=True,
                    ss_sha256=apply_drop["ss_sha256"],
                )
            else:
                result["target_session_terminated_after_root_receipt"] = True
        else:
            result.update(prepare_tcp_reset=True, apply_tcp_reset=True)
        if case == "root-auto":
            result["root_auto_preauthorized_null_approval"] = True
        else:
            result["missing_apply_declaration_no_write"] = True
        if case in {"revoke", "root-auto"}:
            revoke = frame(
                scope,
                "revoke",
                rid,
                {
                    "manifest_sha256": manifest,
                    "approval": approval(rid, manifest, "revoke", prepared["deadline_at"]),
                },
            )
            revoked = rpc(network, management, revoke)
            require(
                revoked["state"] == "revoked"
                and identity_binding(revoked) == identity_binding(prepared),
                "Exact independent-fixture revoke did not confirm",
            )
            revoked_snapshot = snapshot(network, target)
            require(
                rpc(network, management, revoke)["state"] == "revoked"
                and snapshot(network, target) == revoked_snapshot,
                "Duplicate revoke changed the ledger",
            )
            login(network, candidate)
            result.update(state="revoked", exact_revoke_restored_ssh=True)
        else:
            # During this wait no request dispatcher, nft command, or rearm is invoked.
            until = time.monotonic() + duplicate["remaining_ms"] / 1000 + 0.5
            while time.monotonic() < until:
                time.sleep(max(0, min(1, until - time.monotonic())))
            login(network, candidate)
            expired = rpc(network, management, query)
            require(
                expired["state"] == "expired"
                and expired["remaining_ms"] is None
                and snapshot(network, target)["ledger_sha256"] == applied["ledger_sha256"],
                "The original native action did not expire independently",
            )
            require(
                rpc(network, management, apply)["state"] == "expired",
                "Expired RID reapplied a native action",
            )
            login(network, candidate)
            result.update(
                state="expired",
                native_ttl_expired_without_dispatcher=True,
                expired_rid_cannot_reapply=True,
            )
        result["ledger"] = snapshot(network, target)
    result["owned_resources_removed"] = True
    return result


def internal_modules():
    # These imports include Linux-only fcntl; --help remains usable on the workstation.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import ssh_defense_private_target as target

    from deploy.defense import ssh_fixture_nft as nft

    target.validate_network()
    caps = next(
        line.split()[1]
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    require(int(caps, 16) == sum(1 << bit for bit in CAP_BITS), "The target capability set differs")
    return target, nft


def owned_read(path, limit, *, private=True):
    trusted_directory(path.parent)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK  # ty: ignore[unresolved-attribute] -- Linux-only
    with os.fdopen(os.open(path, flags), "rb") as handle:
        before = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1
            and not before.st_mode & (0o077 if private else 0o022)
            and 0 < before.st_size <= limit,
            "Unsafe owned fault fixture file",
        )
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        require(
            len(raw) == before.st_size
            and (before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns),
            "Owned fault fixture file changed",
        )
        return raw


def owned_create(path, raw, *, mode=0o600):
    trusted_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW  # ty: ignore[unresolved-attribute] -- Linux-only
    with os.fdopen(os.open(path, flags, mode), "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fixture_case():
    value = decode(owned_read(Path(AUTHORITY) / "lab-case.json", 256))
    require(
        set(value) == {"case"} and value["case"] in {*CASES, PROBE_CASE, SOCKET_PROBE_CASE},
        "Unknown fixed laboratory case",
    )
    return value["case"]


def process_record(pid):
    require(type(pid) is int and pid > 1, "Unsafe fixture process identity")
    process = Path("/proc") / str(pid)
    fields = (process / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
    return {
        "pid": pid,
        "ppid": int(fields[1]),
        "start": int(fields[19]),
        "uid": process.stat().st_uid,
        "state": fields[0],
    }


def process_identity(record):
    return {key: record[key] for key in ("pid", "ppid", "start", "uid")}


def process_alive(record):
    try:
        current = process_record(record["pid"])
        return current["start"] == record["start"] and current["state"] not in {"Z", "X"}
    except FileNotFoundError:
        return False


def verify_program(record, executable):
    process = Path("/proc") / str(record["pid"])
    require(
        record["uid"] == 0
        and (process / "exe").resolve(strict=True) == Path(executable).resolve(strict=True)
        and os.path.samestat((process / "ns/net").stat(), Path("/proc/self/ns/net").stat()),
        "The exact root fixture process could not be identified",
    )


def kill_exact(record, executable):
    require(record["pid"] != os.getpid(), "The fixture cannot target its own control process")
    diagnostic_step("session_pidfd_pin", "enter", program_observations(record))
    descriptor = os.pidfd_open(record["pid"])  # ty: ignore[unresolved-attribute] -- Linux-only
    try:
        require(
            process_identity(process_record(record["pid"])) == process_identity(record),
            "The pinned fixture process identity changed",
        )
        verify_program(record, executable)
        diagnostic_step("session_pidfd_pin", "ok")
        diagnostic_step("session_signal", "enter")
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)  # ty: ignore[unresolved-attribute] -- Linux-only
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            require(selector.select(0.5), "The exact fixture process did not terminate")
        diagnostic_step("session_signal", "ok")
    finally:
        os.close(descriptor)


def request_master():
    diagnostic_step("session_master_read", "enter")
    raw = owned_read(Path("/run/opsark-ssh-defense/requests-sshd.pid"), 16, private=False)
    require(re.fullmatch(rb"[1-9][0-9]{0,8}\n", raw), "Unsafe request SSH master identity")
    record = process_record(int(raw))
    diagnostic_step("session_master_read", "ok", program_observations(record))
    diagnostic_step("session_master_verify", "enter")
    verify_program(record, "/usr/sbin/sshd")
    diagnostic_step("session_master_verify", "ok")
    return record


def request_connections():
    local = socket.inet_aton(TARGET)[::-1].hex().upper() + f":{int(REQUEST_PORT):04X}"
    peer = socket.inet_aton(ADDRESSES["management"])[::-1].hex().upper() + ":"
    return [
        fields
        for line in Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        if (fields := line.split())[1] == local and fields[2].startswith(peer) and fields[3] == "01"
    ]


def request_socket_tuple(rows):
    """Parse one kernel row for the fixed owned request connection."""
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not list:
        return None
    row = rows[0]
    if not 10 <= len(row) <= 32 or any(type(field) is not str for field in row):
        return None
    local = socket.inet_aton(TARGET)[::-1].hex().upper() + f":{int(REQUEST_PORT):04X}"
    remote = socket.inet_aton(ADDRESSES["management"])[::-1].hex().upper()
    if (
        row[1] != local
        or row[3] != "01"
        or re.fullmatch(remote + r":[0-9A-F]{4}", row[2]) is None
        or re.fullmatch(r"[1-9][0-9]{0,19}", row[9]) is None
    ):
        return None
    port, inode = int(row[2][-4:], 16), int(row[9])
    if not 1 <= port <= 65535 or not 1 <= inode < 2**64:
        return None
    return {
        "peer_port": port,
        "inode": inode,
        "tuple_sha256": digest(
            ["tcp", "inet", TARGET, int(REQUEST_PORT), ADDRESSES["management"], port]
        ),
    }


def ss_destroy_argv(peer_port):
    """Build the only permitted socket destruction command, without a shell."""
    require(
        type(peer_port) is int and 1 <= peer_port <= 65535,
        "The proposed socket filter requires one exact kernel-derived port",
    )
    expression = (
        f"( src = {TARGET} and sport = :{REQUEST_PORT} and "
        f"dst = {ADDRESSES['management']} and dport = :{peer_port} )"
    )
    return ("/usr/bin/ss", "-4", "-n", "-t", "-K", "state", "established", expression)


def ss_destroy_argv_matches(arguments, peer_port):
    if type(peer_port) is not int or not 1 <= peer_port <= 65535:
        return False
    return (
        type(arguments) is tuple
        and all(type(argument) is str for argument in arguments)
        and arguments == ss_destroy_argv(peer_port)
    )


def ss_read_argv(peer_port):
    arguments = ss_destroy_argv(peer_port)
    return (*arguments[:4], "-H", *arguments[5:])


def ss_read_reply_matches(raw, plan):
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        return False
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return False
    if len(lines) != 1:
        return False
    fields = lines[0].split()
    if fields[:1] == ["ESTAB"]:
        fields = fields[1:]
    return (
        len(fields) == 4
        and all(re.fullmatch(r"[0-9]{1,10}", field) for field in fields[:2])
        and fields[2:]
        == [f"{TARGET}:{REQUEST_PORT}", f"{ADDRESSES['management']}:{plan['peer_port']}"]
    )


def socket_tuple_absent(rows, plan):
    """Require absence of both the old full tuple and inode, in every TCP state."""
    if (
        type(rows) is not list
        or type(plan) is not dict
        or set(plan) != {"peer_port", "inode", "tuple_sha256"}
        or type(plan["peer_port"]) is not int
        or not 1 <= plan["peer_port"] <= 65535
        or type(plan["inode"]) is not int
        or not 1 <= plan["inode"] < 2**64
        or type(plan["tuple_sha256"]) is not str
    ):
        return False
    expected_hash = digest(
        ["tcp", "inet", TARGET, int(REQUEST_PORT), ADDRESSES["management"], plan["peer_port"]]
    )
    if plan["tuple_sha256"] != expected_hash:
        return False
    local = socket.inet_aton(TARGET)[::-1].hex().upper() + f":{int(REQUEST_PORT):04X}"
    remote = (
        socket.inet_aton(ADDRESSES["management"])[::-1].hex().upper() + f":{plan['peer_port']:04X}"
    )
    for row in rows:
        if (
            type(row) is not list
            or not 10 <= len(row) <= 32
            or any(type(field) is not str for field in row)
            or re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{4}", row[1]) is None
            or re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{4}", row[2]) is None
            or re.fullmatch(r"[0-9A-F]{2}", row[3]) is None
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", row[9]) is None
        ):
            return False
        if int(row[9]) >= 2**64:
            return False
        if (row[1] == local and row[2] == remote) or int(row[9]) == plan["inode"]:
            return False
    return True


def fake_socket_grammar_regression():
    row = ["0:", "02F112C6:5797", "04F112C6:AFC9", "01", "0:0", "0:0", "0", "0", "0", "12345"]
    port = 45001
    plan = request_socket_tuple([row])
    require(
        plan is not None and plan["peer_port"] == port, "The proposed exact tuple grammar failed"
    )
    checks = 1
    for rows in (
        None,
        (),
        [],
        [row, row],
        [None],
        [row[:9]],
        [[*row[:1], "02F112C6:5796", *row[2:]]],
        [[*row[:1], "03F112C6:5797", *row[2:]]],
        [[*row[:2], "05F112C6:AFC9", *row[3:]]],
        [[*row[:2], "04F112C6:0000", *row[3:]]],
        [[*row[:3], "0A", *row[4:]]],
        [row[:9] + ["0"]],
        [row[:9] + ["01"]],
        [row[:9] + [str(2**64)]],
        [row[:9] + [12345]],
    ):
        require(
            request_socket_tuple(rows) is None,
            "A broad or malformed proposed socket tuple was accepted",
        )
        checks += 1
    for peer_port in (0, -1, 65536, True, "45001", "45001 or sport = :22422", None, 45001.0):
        try:
            ss_destroy_argv(peer_port)
        except LabError:
            checks += 1
        else:
            raise LabError("An invalid proposed socket filter operand was accepted")
    expected = (
        "/usr/bin/ss",
        "-4",
        "-n",
        "-t",
        "-K",
        "state",
        "established",
        "( src = 198.18.241.2 and sport = :22423 and dst = 198.18.241.4 and dport = :45001 )",
    )
    require(
        ss_destroy_argv(port) == expected and ss_destroy_argv_matches(expected, port),
        "The proposed ss command grammar widened",
    )
    checks += 1
    for arguments in (
        list(expected),
        (*expected[:4], "-a", *expected[5:]),
        (*expected[:4], "-N", *expected[5:]),
        (*expected[:-1], expected[-1].replace("45001", "*")),
        (*expected[:-1], expected[-1].replace("22423", "22422")),
        (*expected[:-1], expected[-1].replace("198.18.241.4", "198.18.241.3")),
        (*expected[:-1], expected[-1] + " or true"),
        (*expected, "extra"),
    ):
        require(
            not ss_destroy_argv_matches(arguments, port),
            "An extra or broad proposed ss operand was accepted",
        )
        checks += 1
    for rows, absent in (
        ([], True),
        ([row], False),
        ([[*row[:3], "06", *row[4:]]], False),
        ([[*row[:2], "04F112C6:AFCA", *row[3:]]], False),
        ([[*row[:2], "04F112C6:AFCA", *row[3:9], "54321"]], True),
        ([[*row[:3], "06", *row[4:9], "0"]], False),
        ([row[:9]], False),
        (None, False),
    ):
        require(
            socket_tuple_absent(rows, plan) is absent,
            "The proposed after-absence grammar failed closed",
        )
        checks += 1
    for bad_plan in (
        {**plan, "inode": True},
        {**plan, "peer_port": "45001"},
        {**plan, "tuple_sha256": "0" * 64},
        {**plan, "extra": True},
    ):
        require(
            not socket_tuple_absent([], bad_plan),
            "An invalid proposed absence binding was accepted",
        )
        checks += 1
    require(
        ss_read_argv(port)[4] == "-H" and "-K" not in ss_read_argv(port),
        "The socket probe acquired a destroy flag",
    )
    for raw, accepted in (
        (b"0 0 198.18.241.2:22423 198.18.241.4:45001\n", True),
        (b"ESTAB 0 12 198.18.241.2:22423 198.18.241.4:45001\n", True),
        (b"0 0 198.18.241.2:22422 198.18.241.4:45001\n", False),
        (b"0 0 198.18.241.2:22423 198.18.241.3:45001\n", False),
        (b"0 0 198.18.241.2:22423 198.18.241.4:45002\n", False),
        (b"State Recv-Q Send-Q Local Address:Port Peer Address:Port\n", False),
        (b"0 0 198.18.241.2:22423 198.18.241.4:45001\nextra\n", False),
        (b"", False),
    ):
        require(
            ss_read_reply_matches(raw, plan) is accepted,
            "The exact read-only ss reply grammar failed",
        )
        checks += 1
    return {"checks": checks + 1, "docker_calls": 0}


def kernel_tcp_rows():
    with Path("/proc/self/net/tcp").open("rb") as handle:
        raw = handle.read(65_537)
    require(0 < len(raw) <= 65_536 and raw.endswith(b"\n"), "The owned TCP table was not bounded")
    lines = raw.decode("ascii").splitlines()
    require("local_address" in lines[0] and len(lines) <= 513, "The owned TCP table format changed")
    rows = [line.split() for line in lines[1:]]
    for row in rows:
        require(
            10 <= len(row) <= 32
            and re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{4}", row[1])
            and re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{4}", row[2])
            and re.fullmatch(r"[0-9A-F]{2}", row[3])
            and re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", row[9])
            and int(row[9]) < 2**64,
            "The owned TCP row format changed",
        )
    return rows


def unique_request_socket():
    local = socket.inet_aton(TARGET)[::-1].hex().upper() + f":{int(REQUEST_PORT):04X}"
    peer = socket.inet_aton(ADDRESSES["management"])[::-1].hex().upper() + ":"
    rows = [
        row
        for row in kernel_tcp_rows()
        if row[1] == local and row[2].startswith(peer) and row[3] == "01"
    ]
    plan = request_socket_tuple(rows)
    require(plan is not None, "The bound SSH socket changed before interruption")
    return plan


def socket_scope():
    internal_modules()
    from deploy.defense import ssh_fixture as fixture

    case = fixture_case()
    require(case in SOCKET_CASES, "The exact socket gate is restricted to its owned fixture")
    plan = decode(owned_read(FAULT_ROOT / "socket-plan.json", 4096))
    require(
        set(plan) == {"case", "scope_sha256", "boot_ref", "binding_ref", "ss_sha256", "supervisor"}
        and plan["case"] == case,
        "The exact socket scope declaration changed",
    )
    _, state = fault_ledger()
    boot = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    require(
        len(boot) == 37
        and boot.endswith(b"\n")
        and hashlib.sha256(boot).hexdigest() == plan["boot_ref"] == state["boot_ref"]
        and state["deployment"]["scope_sha256"] == plan["scope_sha256"]
        and state["binding_ref"] == digest(state["binding"]) == plan["binding_ref"],
        "The exact socket scope binding changed",
    )
    with fixture._locked() as directory:
        require(
            fixture._bound_listener(directory, "private") == state["binding"],
            "The protected native SSH listener changed",
        )
    native = owned_read(Path(SS), 8 * 1024**2, private=False)
    require(
        native.startswith(b"\x7fELF") and hashlib.sha256(native).hexdigest() == plan["ss_sha256"],
        "The cached laboratory image lacks a trusted ss executable",
    )
    return state, request_master(), plan["ss_sha256"]


def socket_wrapper_ancestry(master):
    diagnostic_step("socket_ancestry", "enter")
    chain, seen, parent = [], {os.getpid()}, os.getppid()
    for _ in range(16):
        require(
            parent > 1 and parent not in seen, "The fixed SSH process ancestry could not be proven"
        )
        if parent == master["pid"]:
            break
        seen.add(parent)
        record = process_record(parent)
        chain.append(record)
        parent = record["ppid"]
    else:
        raise LabError("The SSH process ancestry exceeded the fixed bound")
    require(
        parent == master["pid"] and session_monitor_candidate(chain, master) is not None,
        "The control wrapper was not below the request SSH master",
    )
    diagnostic_step("socket_ancestry", "ok", {"ancestor_count": len(chain)})


def socket_preflight(request):
    diagnostic_step("socket_scope", "enter")
    state, master, binary_sha = socket_scope()
    require(
        request["scope_sha256"] == state["deployment"]["scope_sha256"],
        "The exact socket scope binding changed",
    )
    socket_wrapper_ancestry(master)
    diagnostic_step("socket_scope", "ok", {"ss_sha256": binary_sha})
    diagnostic_step("socket_tuple", "enter")
    plan = unique_request_socket()
    diagnostic_step(
        "socket_tuple", "ok", {"connection_count": 1, "tuple_sha256": plan["tuple_sha256"]}
    )
    diagnostic_step("socket_ss_read", "enter")
    result = run(*ss_read_argv(plan["peer_port"]), timeout=2, limit=4096)
    diagnostic_step(
        "socket_ss_read",
        "ok" if result.returncode == 0 else "refused",
        {
            "ss_returncode": result.returncode,
            "ss_stdout_bytes": len(result.stdout),
            "ss_stderr_category": stderr_category(result.stderr),
        },
    )
    require(
        result.returncode == 0 and not result.stderr and ss_read_reply_matches(result.stdout, plan),
        "The exact read-only ss filter did not match one SSH socket",
    )
    require(unique_request_socket() == plan, "The bound SSH socket changed before interruption")
    return state, master, plan, binary_sha


def publish_socket_signal(path):
    # Visibility is mode-gated: the referenced JSON is durable before this signal is readable.
    owned_create(path, b"ready\n", mode=0o000)
    os.chmod(path, 0o600, follow_symlinks=False)


def socket_signal_ready(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) in {0o000, 0o600},
        "Unsafe socket completion signal",
    )
    return stat.S_IMODE(info.st_mode) == 0o600


def socket_paths(operation):
    require(operation in {"prepare", "apply"}, "Unknown one-shot socket interruption operation")
    return {
        name: FAULT_ROOT / f"socket-{operation}.{name}"
        for name in ("json", "ready", "claimed", "executed", "result", "done")
    }


def socket_result_valid(value):
    return (
        type(value) is dict
        and set(value)
        == {
            "ss_invoked",
            "ss_returncode",
            "ss_stdout_bytes",
            "ss_stderr_category",
            "after_absence",
            "error_category",
        }
        and type(value["ss_invoked"]) is bool
        and type(value["after_absence"]) is bool
        and (
            value["ss_returncode"] is None
            or type(value["ss_returncode"]) is int
            and -255 <= value["ss_returncode"] <= 255
        )
        and type(value["ss_stdout_bytes"]) is int
        and 0 <= value["ss_stdout_bytes"] <= 4096
        and type(value["ss_stderr_category"]) is str
        and value["ss_stderr_category"] in ERROR_CATEGORIES
        and type(value["error_category"]) is str
        and value["error_category"] in ERROR_CATEGORIES
    )


def socket_result_success(value):
    return (
        socket_result_valid(value)
        and value["ss_invoked"] is True
        and value["ss_returncode"] == 0
        and value["after_absence"] is True
        and value["error_category"] == "none"
    )


def request_socket_interruption(request, binding, remaining):
    paths = socket_paths(request["op"])
    if paths["json"].exists():
        previous = decode(owned_read(paths["json"], 4096))
        require(
            previous["request_sha256"] == digest(request),
            "The one-shot SSH fault declaration changed",
        )
        return False
    state, master, plan, binary_sha = socket_preflight(request)
    _, actual = fault_action(state, request["request_id"])
    require(digest(actual) == digest(binding), "The persisted fault action binding changed")
    namespace_ref = digest([state["boot_ref"], state["binding"][:2]])
    marker = {
        "request_ref": request["request_id"],
        "request_sha256": digest(request),
        "scope_sha256": request["scope_sha256"],
        "operation": request["op"],
        "identity_binding_sha256": digest(binding),
        "remaining_ms": remaining,
        "tuple": plan,
        "inode_sha256": digest([namespace_ref, plan["inode"]]),
        "namespace_ref": namespace_ref,
        "master": process_identity(master),
        "ss_sha256": binary_sha,
    }
    diagnostic_step(
        "socket_marker",
        "enter",
        {"tuple_sha256": plan["tuple_sha256"], "inode_sha256": marker["inode_sha256"]},
    )
    owned_create(paths["json"], canonical(marker) + b"\n")
    publish_socket_signal(paths["ready"])
    diagnostic_step("socket_marker", "ok")
    for _ in range(400):
        if socket_signal_ready(paths["done"]):
            result = decode(owned_read(paths["result"], 4096))
            require(socket_result_valid(result), "Unsafe socket completion metadata was refused")
            observations = {
                "ss_stdout_bytes": result["ss_stdout_bytes"],
                "ss_stderr_category": result["ss_stderr_category"],
                "after_absence": result["after_absence"],
            }
            if type(result["ss_returncode"]) is int:
                observations["ss_returncode"] = result["ss_returncode"]
            diagnostic_step(
                "socket_destroy",
                "ok"
                if result["after_absence"]
                and result["ss_returncode"] == 0
                and result["error_category"] == "none"
                else "refused",
                observations,
                result["error_category"],
            )
            require(
                socket_result_success(result),
                "The exact SSH socket was not destroyed",
            )
            os._exit(1)
        time.sleep(0.01)
    raise LabError("The exact SSH socket was not destroyed")


def process_socket_interruption(image):
    """One fixed mailbox, serviced by the existing target main process, not the SSH tree."""
    if fixture_case() != SOCKET_CASE:
        return
    for operation in ("prepare", "apply"):
        paths = socket_paths(operation)
        if not socket_signal_ready(paths["ready"]) or paths["claimed"].exists():
            continue
        owned_create(paths["claimed"], b'{"claimed":true}\n')
        result = {
            "ss_invoked": False,
            "ss_returncode": None,
            "ss_stdout_bytes": 0,
            "ss_stderr_category": "none",
            "after_absence": False,
            "error_category": "none",
        }
        try:
            marker = decode(owned_read(paths["json"], 4096))
            require(
                set(marker)
                == {
                    "request_ref",
                    "request_sha256",
                    "scope_sha256",
                    "operation",
                    "identity_binding_sha256",
                    "remaining_ms",
                    "tuple",
                    "inode_sha256",
                    "namespace_ref",
                    "master",
                    "ss_sha256",
                }
                and marker["operation"] == operation,
                "The exact socket scope declaration changed",
            )
            state, master, binary_sha = socket_scope()
            record, binding = fault_action(state, marker["request_ref"])
            require(
                marker["scope_sha256"] == state["deployment"]["scope_sha256"]
                and marker["identity_binding_sha256"] == digest(binding)
                and marker["namespace_ref"] == digest([state["boot_ref"], state["binding"][:2]])
                and marker["ss_sha256"] == binary_sha
                and marker["master"] == process_identity(master)
                and record["phase"] == ("ready" if operation == "prepare" else "active")
                and marker["tuple"] == unique_request_socket(),
                "The bound SSH socket changed before interruption",
            )
            result["ss_invoked"] = True
            closed = run(
                "/usr/bin/python3",
                "-I",
                "-B",
                SELF,
                "--internal-ss-close",
                "--image",
                image,
                "--confirm-isolated",
                input_bytes=canonical({"operation": operation}) + b"\n",
                timeout=2,
                limit=4096,
            )
            result.update(
                ss_returncode=closed.returncode,
                ss_stdout_bytes=len(closed.stdout),
                ss_stderr_category=stderr_category(closed.stderr),
            )
            require(
                closed.returncode == 0 and not closed.stderr,
                "The exact SSH socket was not destroyed",
            )
            for _ in range(100):
                if socket_tuple_absent(kernel_tcp_rows(), marker["tuple"]):
                    result["after_absence"] = True
                    break
                time.sleep(0.01)
            require(result["after_absence"], "The exact SSH socket was not destroyed")
            _, preserved, preserved_binary = socket_scope()
            require(
                process_identity(preserved) == marker["master"] and preserved_binary == binary_sha,
                "The exact socket scope binding changed",
            )
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            StopIteration,
            subprocess.SubprocessError,
        ) as error:
            result["error_category"] = error_category(error)
        owned_create(paths["result"], canonical(result) + b"\n")
        publish_socket_signal(paths["done"])


def internal_ss_close():
    """Single-thread child: arm parent-death before exec, without threaded preexec_fn."""
    import ctypes

    state, master, _ = socket_scope()
    require(fixture_case() == SOCKET_CASE, "The read-only socket probe cannot close a connection")
    request = decode(sys.stdin.buffer.read(4097))
    require(set(request) == {"operation"}, "Unknown one-shot socket interruption operation")
    paths = socket_paths(request["operation"])
    require(
        socket_signal_ready(paths["ready"])
        and decode(owned_read(paths["claimed"], 256)) == {"claimed": True},
        "The socket close helper had no one-shot claim",
    )
    marker = decode(owned_read(paths["json"], 4096))
    plan = decode(owned_read(FAULT_ROOT / "socket-plan.json", 4096))
    parent = process_record(os.getppid())
    require(
        process_identity(parent) == plan["supervisor"],
        "The exact socket close helper had a foreign parent",
    )
    try:
        verify_program(parent, "/usr/bin/python3")
    except OSError:
        raise LabError("The socket helper parent could not be verified") from None
    libc = ctypes.CDLL(None, use_errno=True)
    require(
        libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent["pid"],  # ty: ignore[unresolved-attribute] -- Linux-only PR_SET_PDEATHSIG
        "The socket close helper could not bind its lifetime",
    )
    record, binding = fault_action(state, marker["request_ref"])
    require(
        marker["scope_sha256"] == state["deployment"]["scope_sha256"]
        and marker["identity_binding_sha256"] == digest(binding)
        and marker["master"] == process_identity(master)
        and record["phase"] == ("ready" if request["operation"] == "prepare" else "active")
        and marker["tuple"] == unique_request_socket(),
        "The bound SSH socket changed before interruption",
    )
    arguments = ss_destroy_argv(marker["tuple"]["peer_port"])
    require(
        ss_destroy_argv_matches(arguments, marker["tuple"]["peer_port"]),
        "The exact socket command changed",
    )
    owned_create(
        paths["executed"],
        canonical(
            {
                "request_sha256": marker["request_sha256"],
                "tuple_sha256": marker["tuple"]["tuple_sha256"],
                "argv_sha256": digest(list(arguments)),
            }
        )
        + b"\n",
    )
    os.execv(SS, list(arguments))  # noqa: S606 -- one validated exact IPv4 TCP tuple; no shell or namespace switch.


def socket_fault_proof(request):
    state, master, binary_sha = socket_scope()
    paths = socket_paths(request["op"])
    for _ in range(400):
        if socket_signal_ready(paths["done"]):
            break
        time.sleep(0.01)
    require(socket_signal_ready(paths["done"]), "The exact SSH socket was not destroyed")
    marker = decode(owned_read(paths["json"], 4096))
    result = decode(owned_read(paths["result"], 4096))
    require(socket_result_valid(result), "Unsafe socket completion metadata was refused")
    executed = decode(owned_read(paths["executed"], 4096))
    record, binding = fault_action(state, request["request_id"])
    require(
        marker["request_sha256"] == digest(request)
        and marker["identity_binding_sha256"] == digest(binding)
        and marker["scope_sha256"] == request["scope_sha256"] == state["deployment"]["scope_sha256"]
        and marker["namespace_ref"] == digest([state["boot_ref"], state["binding"][:2]])
        and marker["inode_sha256"] == digest([marker["namespace_ref"], marker["tuple"]["inode"]])
        and marker["master"] == process_identity(master)
        and marker["ss_sha256"] == binary_sha
        and executed
        == {
            "request_sha256": digest(request),
            "tuple_sha256": marker["tuple"]["tuple_sha256"],
            "argv_sha256": digest(list(ss_destroy_argv(marker["tuple"]["peer_port"]))),
        }
        and socket_result_success(result)
        and socket_tuple_absent(kernel_tcp_rows(), marker["tuple"]),
        "The exact SSH socket was not destroyed",
    )
    raw, _ = fault_ledger()
    return {
        "request_ref": request["request_id"],
        "identity_binding_sha256": digest(binding),
        "fault_layer": "target_exact_ssh_socket_interruption",
        "ssh_session_terminated": True,
        "request_master_preserved": True,
        "native_listener_preserved": True,
        "root_cli_completed": True,
        "remaining_ms_before_loss": marker["remaining_ms"],
        "phase": record["phase"],
        "usage_count": len(state["usage"]),
        "expiry_bound_present": record["payload"]["expiry_bound"] is not None,
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "before_tuple_sha256": marker["tuple"]["tuple_sha256"],
        "before_inode_sha256": marker["inode_sha256"],
        "after_absence": True,
        "ss_sha256": binary_sha,
        "ss_returncode": result["ss_returncode"],
        "socket_close_exec_count": 1,
        "session_signal_sent": False,
    }


def fake_socket_worker_regression():
    """Exercise the actual one-shot worker against RAM-only scope/table/tool doubles."""
    from types import SimpleNamespace

    @contextmanager
    def replace_globals(values):
        original = {key: globals()[key] for key in values}
        globals().update(values)
        try:
            yield
        finally:
            globals().update(original)

    checks = 0
    row = ["0:", "02F112C6:5797", "04F112C6:AFC9", "01", "0:0", "0:0", "0", "0", "0", "12345"]
    tuple_plan = request_socket_tuple([row])
    require(tuple_plan is not None, "The worker fake tuple was invalid")
    rid = "1" * 32
    manifest = {"v": 1, "request_id": rid}
    record = {
        "kind": "action",
        "phase": "ready",
        "payload": {"action_id": "2" * 32, "cursor_id": "3" * 32, "manifest": manifest},
    }
    state = {
        "records": {rid: record},
        "deployment": {"scope_sha256": "4" * 64},
        "boot_ref": "5" * 64,
        "binding": [1, 2, 3, 4, 5, 6, 7, 8],
    }
    master = {"pid": 10, "ppid": 2, "start": 3, "uid": 0}
    _, binding = fault_action(state, rid)
    for mode in (
        "supported",
        "silent_skip",
        "tool_denied",
        "tuple_changed",
        "master_changed_after",
    ):
        files, ready, tool_calls, current_rows = {}, {"prepare.ready"}, [], [row]
        scope_calls = []

        class RamPath:
            def __init__(self, name):
                self.name = name

            def exists(self, _files=files):
                return self.name in _files

        def paths(operation):
            return {
                name: RamPath(f"{operation}.{name}")
                for name in ("json", "ready", "claimed", "result", "done")
            }

        def create(path, raw, _files=files, **_kwargs):
            if path.name in _files:
                raise FileExistsError
            _files[path.name] = raw

        def scope(_mode=mode, _calls=scope_calls):
            _calls.append(True)
            selected = (
                {**master, "pid": 11}
                if _mode == "master_changed_after" and len(_calls) > 1
                else master
            )
            return state, selected, "6" * 64

        def native(*arguments, _mode=mode, _calls=tool_calls, _rows=current_rows, **kwargs):
            _calls.append(arguments)
            require(
                "--internal-ss-close" in arguments
                and decode(kwargs["input_bytes"]) == {"operation": "prepare"},
                "The worker launched an unapproved socket helper",
            )
            if _mode in {"supported", "master_changed_after"}:
                _rows.clear()
            return subprocess.CompletedProcess(
                arguments,
                1 if _mode == "tool_denied" else 0,
                b"",
                b"synthetic-private-error" if _mode == "tool_denied" else b"",
            )

        selected_tuple = (
            {**tuple_plan, "peer_port": 45002} if mode == "tuple_changed" else tuple_plan
        )
        namespace_ref = digest([state["boot_ref"], state["binding"][:2]])
        marker = {
            "request_ref": rid,
            "request_sha256": "7" * 64,
            "scope_sha256": "4" * 64,
            "operation": "prepare",
            "identity_binding_sha256": digest(binding),
            "remaining_ms": None,
            "tuple": selected_tuple,
            "inode_sha256": digest([namespace_ref, tuple_plan["inode"]]),
            "namespace_ref": namespace_ref,
            "master": master,
            "ss_sha256": "6" * 64,
        }
        files["prepare.json"] = canonical(marker) + b"\n"
        with replace_globals(
            {
                "fixture_case": lambda: SOCKET_CASE,
                "socket_paths": paths,
                "socket_signal_ready": lambda path, _ready=ready: path.name in _ready,
                "owned_create": create,
                "owned_read": lambda path, *_args, _files=files, **_kwargs: _files[path.name],
                "socket_scope": scope,
                "unique_request_socket": lambda: tuple_plan,
                "kernel_tcp_rows": lambda _rows=current_rows: _rows,
                "run": native,
                "publish_socket_signal": lambda path, _ready=ready: _ready.add(path.name),
                "time": SimpleNamespace(sleep=lambda _seconds: None),
            },
        ):
            process_socket_interruption("sha256:" + "0" * 64)
            result = decode(files["prepare.result"])
            require(socket_result_valid(result), "The worker fake result was not closed metadata")
            accepted = socket_result_success(result)
            require(
                accepted == (mode == "supported"),
                "A silent skip, scope change, or tool failure became socket success",
            )
            require(
                len(tool_calls) == (0 if mode == "tuple_changed" else 1),
                "The worker invoked a broad or duplicate socket close",
            )
            process_socket_interruption("sha256:" + "0" * 64)
            require(
                len(tool_calls) == (0 if mode == "tuple_changed" else 1),
                "A claimed socket close retried",
            )
            require(
                b"synthetic-private-error" not in files["prepare.result"],
                "The worker persisted raw ss diagnostics",
            )
        checks += 5
    success = {
        "ss_invoked": True,
        "ss_returncode": 0,
        "ss_stdout_bytes": 0,
        "ss_stderr_category": "none",
        "after_absence": True,
        "error_category": "none",
    }
    for changes in (
        {"ss_returncode": False},
        {"after_absence": False},
        {"ss_invoked": False},
        {"error_category": "socket_destroy_unconfirmed"},
        {"raw_stderr": "synthetic-private-error"},
        {"ss_stdout_bytes": -1},
        {"ss_stderr_category": "synthetic-private-error"},
    ):
        require(
            not socket_result_success({**success, **changes}),
            "A malformed or unconfirmed socket result passed",
        )
        checks += 1
    return {"checks": checks, "docker_calls": 0, "native_process_calls": 0}


def current_session_monitor():
    master = request_master()
    diagnostic_step("session_ancestry", "enter")
    chain, seen = [], {os.getpid()}
    parent = os.getppid()
    for _ in range(16):
        require(
            parent not in seen and parent > 1, "The fixed SSH process ancestry could not be proven"
        )
        if parent == master["pid"]:
            break
        seen.add(parent)
        record = process_record(parent)
        chain.append(record)
        parent = record["ppid"]
    else:
        raise LabError("The SSH process ancestry exceeded the fixed bound")
    require(parent == master["pid"], "The control wrapper was not below the request SSH master")
    diagnostic_step(
        "session_ancestry",
        "ok",
        {
            "ancestor_count": len(chain),
            "root_ancestor_count": sum(record["uid"] == 0 for record in chain),
        },
    )
    diagnostic_step("session_candidate", "enter")
    monitor = session_monitor_candidate(chain, master)
    diagnostic_step(
        "session_candidate",
        "ok" if monitor is not None else "refused",
        {"candidate_count": int(monitor is not None)},
    )
    require(monitor is not None, "The exact SSH connection monitor could not be selected")
    diagnostic_step("session_program_verify", "enter", program_observations(monitor))
    verify_program(monitor, "/usr/sbin/sshd")
    diagnostic_step("session_program_verify", "ok")
    diagnostic_step("session_connections", "enter")
    connections = request_connections()
    diagnostic_step(
        "session_connections",
        "ok" if len(connections) == 1 else "refused",
        {"connection_count": len(connections)},
    )
    require(len(connections) == 1, "The request SSH connection was not uniquely scoped")
    inode = connections[0][9]
    diagnostic_step("session_socket_owner", "enter")
    descriptors = list((Path("/proc") / str(monitor["pid"]) / "fd").iterdir())
    socket_owned = any(os.readlink(entry) == f"socket:[{inode}]" for entry in descriptors)
    diagnostic_step(
        "session_socket_owner",
        "ok" if socket_owned else "refused",
        {"socket_owned": socket_owned, "socket_fd_count": len(descriptors)},
    )
    require(
        socket_owned,
        "The request socket did not belong to the exact SSH monitor",
    )
    return monitor, master, inode


def session_monitor_candidate(chain, master):
    if type(chain) is not list or not 1 <= len(chain) <= 16:
        return None
    records: list[dict] = []
    for record in chain:
        if type(record) is not dict or not {"pid", "ppid", "uid"}.issubset(record):
            return None
        if any(type(record[key]) is not int for key in ("pid", "ppid", "uid")):
            return None
        records.append(record)
    pids = [record["pid"] for record in records]
    if len(pids) != len(set(pids)) or master["pid"] in pids:
        return None
    if any(
        record["ppid"] != following["pid"]
        for record, following in zip(records, records[1:], strict=False)
    ):
        return None
    monitor = records[-1]
    return monitor if monitor["ppid"] == master["pid"] and monitor["uid"] == 0 else None


def fault_ledger():
    raw = owned_read(REQUEST_ROOT / "requests.json", 196_608)
    return raw, decode(raw, 196_608)


def fault_action(state, rid):
    record = state["records"].get(rid)
    require(
        record is not None and record["kind"] == "action" and record["payload"] is not None,
        "The fault did not bind an original prepared action",
    )
    payload = record["payload"]
    binding = {
        "action_id": payload["action_id"],
        "manifest_sha256": digest(payload["manifest"]),
        "cursor_id": payload["cursor_id"],
    }
    return record, binding


def terminate_session(request, binding, *, remaining=None, root_completed=False):
    path = FAULT_ROOT / f"session-{request['op']}.json"
    if path.exists():
        previous = decode(owned_read(path, 4096))
        require(
            previous["request_sha256"] == digest(request),
            "The one-shot SSH fault declaration changed",
        )
        return False
    diagnostic_step("session_drop_request", "enter")
    monitor, master, inode = current_session_monitor()
    marker = {
        "request_ref": request["request_id"],
        "request_sha256": digest(request),
        "identity_binding_sha256": digest(binding),
        "remaining_ms": remaining,
        "root_cli_completed": root_completed,
        "monitor": process_identity(monitor),
        "master": process_identity(master),
        "connection_inode": inode,
    }
    diagnostic_step("session_marker_write", "enter")
    owned_create(path, canonical(marker) + b"\n")
    diagnostic_step("session_marker_write", "ok")
    kill_exact(monitor, "/usr/sbin/sshd")
    os._exit(0)


def nft_write_matches(arguments, raw, action):
    if (
        type(arguments) is not list
        or arguments != ["-f", "-"]
        or type(raw) is not bytes
        or type(action) is not str
        or re.fullmatch(r"[0-9a-f]{32}", action) is None
    ):
        return False
    expected = (
        f"create element ip opsark_ssh_lab blocked {{ {ADDRESSES['candidate']} timeout 60s "
        f'comment "opsark-{action}" }}\n'
    ).encode("ascii")
    return raw == expected


def fake_fault_regression():
    action = "1" * 32
    script = (
        f"create element ip opsark_ssh_lab blocked {{ 198.18.241.3 timeout 60s "
        f'comment "opsark-{action}" }}\n'
    ).encode("ascii")
    cases = [
        (["-f", "-"], script, action, True),
        (["-f", "-"], script, "2" * 32, False),
        (["-f", "/fixture-other"], script, action, False),
        (["-f", "-", "extra"], script, action, False),
        (("-f", "-"), script, action, False),
        (["-f", "-"], script.decode("ascii"), action, False),
        (["-f", "-"], script, None, False),
        (["-f", "-"], script, "\u4e00" * 32, False),
    ]
    cases.extend(
        (["-f", "-"], value, action, False)
        for value in (
            script[:-1],
            script + b"\n",
            script + script,
            script.replace(b"create element", b"add element"),
            script.replace(b"create", b"delete"),
            script.replace(b"198.18.241.3", b"198.18.241.4"),
            script.replace(b"198.18.241.3", b"198.18.241.5"),
            script.replace(b"timeout 60s", b"timeout 61s"),
            script.replace(b"blocked", b"other"),
            script.replace(b"opsark_ssh_lab", b"other"),
            script.replace(b"\n", b"\r\n"),
        )
    )
    for arguments, raw, identity, accepted in cases:
        require(
            nft_write_matches(arguments, raw, identity) is accepted,
            "The native write boundary grammar regression failed",
        )
    master = {"pid": 10}
    monitor = {"pid": 20, "ppid": 10, "uid": 0}
    child = {"pid": 30, "ppid": 20, "uid": 1000}
    chains = [
        ([child, monitor], master, monitor),
        ([monitor], master, monitor),
        ([], master, None),
        ([child], master, None),
        ([child, {**monitor, "uid": 1000}], master, None),
        ([{**child, "ppid": 40}, monitor], master, None),
        ([child, monitor], {"pid": 11}, None),
        ([child, monitor, monitor], master, None),
        ([child, monitor], {"pid": 20}, None),
        (tuple([child, monitor]), master, None),
    ]
    for chain, listener, expected in chains:
        require(
            session_monitor_candidate(chain, listener) == expected,
            "The bounded SSH ancestry regression failed",
        )
    return {"checks": len(cases) + len(chains), "docker_calls": 0}


def install_faults(case, image):
    if case not in FAULT_CASES:
        return
    FAULT_ROOT.mkdir(mode=0o700)
    DIAGNOSTIC_ROOT.mkdir(mode=0o700)
    if case in SOCKET_CASES:
        native = owned_read(Path(SS), 8 * 1024**2, private=False)
        require(
            native.startswith(b"\x7fELF"),
            "The cached laboratory image lacks a trusted ss executable",
        )
        _, state = fault_ledger()
        owned_create(
            FAULT_ROOT / "socket-plan.json",
            canonical(
                {
                    "case": case,
                    "scope_sha256": state["deployment"]["scope_sha256"],
                    "boot_ref": state["boot_ref"],
                    "binding_ref": state["binding_ref"],
                    "ss_sha256": hashlib.sha256(native).hexdigest(),
                    "supervisor": process_identity(process_record(os.getpid())),
                }
            )
            + b"\n",
        )
        return
    if case not in INTENT_CASES:
        return
    native = Path("/usr/sbin/nft")
    raw = owned_read(native, 8 * 1024**2, private=False)
    require(raw.startswith(b"\x7fELF"), "The original nft tool was not a native ELF executable")
    owned_create(REAL_NFT, raw, mode=0o700)
    real_sha = hashlib.sha256(raw).hexdigest()
    require(
        hashlib.sha256(owned_read(REAL_NFT, 8 * 1024**2)).hexdigest() == real_sha,
        "The private original nft binary hash changed",
    )
    shim = (
        "#!/bin/sh\nexec /usr/bin/python3 -I -B "
        + SELF
        + " --internal-nft-shim --image "
        + image
        + ' --confirm-isolated -- "$@"\n'
    ).encode("ascii")
    pending = native.with_name("opsark-nft-shim.pending")
    owned_create(pending, shim, mode=0o755)
    pending.replace(native)
    owned_create(
        FAULT_ROOT / "nft-plan.json",
        canonical(
            {"case": case, "real_sha256": real_sha, "shim_sha256": hashlib.sha256(shim).hexdigest()}
        )
        + b"\n",
    )


def unexpected_native_write():
    path = FAULT_ROOT / "unexpected-write.json"
    if not path.exists():
        owned_create(path, b'{"unexpected_write":true}\n')
    raise LabError("An unexpected native write was refused")


def internal_nft_shim(arguments):
    internal_modules()
    require(fixture_case() in INTENT_CASES, "The nft fault shim is restricted to its owned fixture")
    plan = decode(owned_read(FAULT_ROOT / "nft-plan.json", 4096))
    require(
        plan["case"] == fixture_case()
        and hashlib.sha256(owned_read(REAL_NFT, 8 * 1024**2)).hexdigest() == plan["real_sha256"]
        and hashlib.sha256(owned_read(Path("/usr/sbin/nft"), 4096, private=False)).hexdigest()
        == plan["shim_sha256"],
        "The controlled native nft boundary changed",
    )
    if arguments in (
        ["list", "tables", "ip"],
        ["--numeric-priority", "list", "table", "ip", "opsark_ssh_lab"],
    ):
        os.execv(str(REAL_NFT), [str(REAL_NFT), *arguments])  # noqa: S606 -- fixed original ELF and fixed read-only argv.
    if arguments != ["-f", "-"]:
        unexpected_native_write()
    raw = sys.stdin.buffer.read(4097)
    ledger_raw, state = fault_ledger()
    actions = [
        (rid, record)
        for rid, record in state["records"].items()
        if record["kind"] == "action" and record["payload"] is not None
    ]
    require(len(actions) == 1, "The native fault requires one prepared action")
    rid, record = actions[0]
    payload = record["payload"]
    if not nft_write_matches(arguments, raw, payload["action_id"]):
        unexpected_native_write()
    require(
        record["phase"] == "intent"
        and state["usage"] == [rid]
        and payload["expiry_bound"] is None
        and payload["apply_hash"] is not None
        and next(item for item in state["records"].values() if item["kind"] == "cursor")["phase"]
        == "consumed",
        "The native write was not behind one durable Root intent",
    )
    root = process_record(os.getppid())
    verify_program(root, "/usr/bin/python3")
    command = (Path("/proc") / str(root["pid"]) / "cmdline").read_bytes().split(b"\0")[:-1]
    require(
        command == [b"/usr/bin/python3", b"-I", b"-B", INSTALLED.encode("ascii"), b"--control"],
        "The nft shim parent was not the exact fixed Root CLI",
    )
    _, binding = fault_action(state, rid)
    claim = FAULT_ROOT / "write-claim.json"
    if claim.exists():
        unexpected_native_write()
    owned_create(
        claim, canonical({"request_ref": rid, "identity_binding_sha256": digest(binding)}) + b"\n"
    )
    real_adds = 0
    if plan["case"] == "intent-after-add":
        result = run(
            str(REAL_NFT), "-f", "-", input_bytes=raw, timeout=1, limit=4096, parent_death=True
        )
        require(
            result.returncode == 0 and not result.stdout and not result.stderr,
            "The original native nft add did not finish before the barrier",
        )
        real_adds = 1
    barrier = {
        "request_ref": rid,
        "identity_binding_sha256": digest(binding),
        "boundary": plan["case"],
        "ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "real_add_count": real_adds,
        "root_cli": process_identity(root),
        "shim": process_identity(process_record(os.getpid())),
        "real_nft_sha256": plan["real_sha256"],
        "shim_sha256": plan["shim_sha256"],
    }
    owned_create(FAULT_ROOT / "barrier.json", canonical(barrier) + b"\n")
    # The shim stdout remains open: Core cannot return from its fixed nft call or save active.
    kill_exact(root, "/usr/bin/python3")
    owned_create(FAULT_ROOT / "root-killed.json", b'{"root_cli_killed":true}\n')
    os._exit(0)


def internal_control_wrapper():
    global _trace_ref, _trace_request_ref, _trace_operation, _trace_order, _trace_sequence
    internal_modules()
    _trace_ref, _trace_sequence = secrets.token_hex(8), 0
    _trace_order = time.monotonic_ns()
    diagnostic_step("wrapper_enter", "enter")
    diagnostic_step("target_gate", "enter")
    # The initial unrecorded preflight keeps all metadata writes inside the fixed target.
    internal_modules()
    diagnostic_step("target_gate", "ok")
    diagnostic_step("case_gate", "enter")
    case = fixture_case()
    require(case in FAULT_CASES, "The control fault gate is restricted to its fixed fixture")
    diagnostic_step("case_gate", "ok")
    from deploy.defense import request_protocol as wire

    diagnostic_step("request_read", "enter")
    raw = sys.stdin.buffer.read(4097)
    diagnostic_step("request_read", "ok")
    diagnostic_step("request_parse", "enter")
    request = wire.parse(raw)
    _trace_request_ref, _trace_operation = request["request_id"], request["op"]
    diagnostic_step("request_parse", "ok")
    require(
        case not in {PROBE_CASE, SOCKET_PROBE_CASE}
        or request["op"] == "query"
        and request["body"] == {"kind": "mode"},
        "The SSH layout probe accepts only its fixed read-only query",
    )
    diagnostic_step("root_cli_run", "enter")
    result = run(
        "/usr/bin/python3",
        "-I",
        "-B",
        INSTALLED,
        "--control",
        input_bytes=raw,
        timeout=23,
        limit=4096,
    )
    diagnostic_step(
        "root_cli_run",
        "ok",
        {
            "root_returncode": result.returncode,
            "root_stdout_bytes": len(result.stdout),
            "root_stderr_category": stderr_category(result.stderr),
        },
    )
    if case in {PROBE_CASE, SOCKET_PROBE_CASE}:
        require(
            result.returncode == 0 and not result.stderr,
            "The fixed query-only Root CLI did not confirm",
        )
        receipt = validate_reply(decode(result.stdout), request)
        require(
            receipt["state"] == "not_found", "The layout probe unexpectedly found a stored request"
        )
        diagnostic_step("probe_layout", "enter")
        if case == SOCKET_PROBE_CASE:
            state, master, plan, binary_sha = socket_preflight(request)
            namespace_ref = digest([state["boot_ref"], state["binding"][:2]])
            diagnostic_step("probe_layout", "ok")
            print(
                canonical(
                    {
                        "schema": "opsark-ssh-socket-layout/v1",
                        "request_ref": request["request_id"],
                        "tuple_sha256": plan["tuple_sha256"],
                        "inode_sha256": digest([namespace_ref, plan["inode"]]),
                        "ss_sha256": binary_sha,
                        "master_ref": digest(process_identity(master)),
                        "scope_bound": True,
                        "namespace_bound": True,
                        "ss_read_matched": True,
                        "destroy_invoked": False,
                    }
                ).decode("ascii")
            )
            return 0
        monitor, master, _ = current_session_monitor()
        diagnostic_step("probe_layout", "ok")
        print(
            canonical(
                {
                    "schema": "opsark-ssh-session-layout/v1",
                    "request_ref": request["request_id"],
                    "layout_proven": True,
                    "master_ref": digest(process_identity(master)),
                    "monitor_ref": digest(process_identity(monitor)),
                }
            ).decode("ascii")
        )
        return 0
    if (
        case in {"ssh-session-loss", SOCKET_CASE}
        and request["op"] in {"prepare", "apply"}
        and result.returncode == 0
        and not result.stderr
    ):
        diagnostic_step("root_receipt_validate", "enter")
        receipt = validate_reply(decode(result.stdout), request)
        diagnostic_step("root_receipt_validate", "ok", {"receipt_state": receipt["state"]})
        if receipt["state"] == ("ready" if request["op"] == "prepare" else "active"):
            binding = {key: receipt[key] for key in ("action_id", "manifest_sha256", "cursor_id")}
            if case == SOCKET_CASE:
                request_socket_interruption(request, binding, receipt["remaining_ms"])
            else:
                terminate_session(
                    request, binding, remaining=receipt["remaining_ms"], root_completed=True
                )
    elif (
        case in INTENT_CASES
        and request["op"] == "apply"
        and result.returncode == -9
        and not result.stdout
    ):
        for _ in range(100):
            if (FAULT_ROOT / "root-killed.json").exists():
                break
            time.sleep(0.01)
        require(
            (FAULT_ROOT / "root-killed.json").exists(), "The exact Root CLI crash was not confirmed"
        )
        _, state = fault_ledger()
        _, binding = fault_action(state, request["request_id"])
        terminate_session(request, binding)
    diagnostic_step("wrapper_reply", "enter")
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    diagnostic_step("wrapper_reply", "ok")
    return result.returncode if result.returncode >= 0 else 1


def internal_fault_proof():
    internal_modules()
    from deploy.defense import ssh_fixture as fixture

    request = decode(sys.stdin.buffer.read(4097))
    require(request["op"] in {"prepare", "apply"}, "Unknown fixed fault proof operation")
    if fixture_case() == SOCKET_CASE:
        print(canonical(socket_fault_proof(request)).decode("ascii"))
        return 0
    marker = decode(owned_read(FAULT_ROOT / f"session-{request['op']}.json", 4096))
    require(
        marker["request_sha256"] == digest(request),
        "The original fault request declaration changed",
    )
    for _ in range(100):
        if not process_alive(marker["monitor"]):
            break
        time.sleep(0.01)
    master = request_master()
    require(
        process_identity(master) == marker["master"]
        and not process_alive(marker["monitor"])
        and all(row[9] != marker["connection_inode"] for row in request_connections()),
        "The target SSH session did not terminate with its master preserved",
    )
    ledger_raw, state = fault_ledger()
    record, binding = fault_action(state, request["request_id"])
    require(
        digest(binding) == marker["identity_binding_sha256"],
        "The persisted fault action binding changed",
    )
    with fixture._locked() as directory:
        require(
            fixture._bound_listener(directory, "private") == state["binding"],
            "The protected native SSH listener changed",
        )
    proof = {
        "request_ref": request["request_id"],
        "identity_binding_sha256": digest(binding),
        "fault_layer": "target_ssh_session_termination",
        "ssh_session_terminated": True,
        "request_master_preserved": True,
        "native_listener_preserved": True,
        "root_cli_completed": marker["root_cli_completed"],
        "remaining_ms_before_loss": marker["remaining_ms"],
        "ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "phase": record["phase"],
        "usage_count": len(state["usage"]),
        "expiry_bound_present": record["payload"]["expiry_bound"] is not None,
    }
    if fixture_case() in INTENT_CASES:
        barrier = decode(owned_read(FAULT_ROOT / "barrier.json", 4096))
        for _ in range(100):
            if not process_alive(barrier["shim"]):
                break
            time.sleep(0.01)
        require(
            barrier["request_ref"] == request["request_id"]
            and barrier["identity_binding_sha256"] == digest(binding)
            and not process_alive(barrier["root_cli"])
            and not process_alive(barrier["shim"])
            and barrier["ledger_sha256"] == proof["ledger_sha256"]
            and not (FAULT_ROOT / "unexpected-write.json").exists(),
            "The deterministic native boundary proof changed",
        )
        proof.update(
            fault_layer="controlled_target_nft_boundary",
            boundary=barrier["boundary"],
            real_add_count=barrier["real_add_count"],
            root_cli_killed=True,
            shim_terminated=True,
            unexpected_write=False,
            real_nft_sha256=barrier["real_nft_sha256"],
            shim_sha256=barrier["shim_sha256"],
        )
    print(canonical(proof).decode("ascii"))
    return 0


def internal_diagnostics():
    internal_modules()
    request = decode(sys.stdin.buffer.read(4097))
    require(request["op"] in {"prepare", "apply", "query"}, "Unknown fixed diagnostic operation")
    files = list(DIAGNOSTIC_ROOT.iterdir())
    require(len(files) <= 1024, "The owned diagnostic file budget was exhausted")
    rows = []
    for path in files:
        require(
            re.fullmatch(r"[0-9a-f]{16}-[0-9]{3}\.json", path.name),
            "Unexpected diagnostic filename",
        )
        event = decode(owned_read(path, 2048), 2048)
        require(
            set(event)
            == {
                "trace_ref",
                "trace_order",
                "sequence",
                "request_ref",
                "operation",
                "step",
                "status",
                "error_category",
                "observations",
            },
            "Unexpected diagnostic fields",
        )
        require(
            type(event["trace_order"]) is int and 0 < event["trace_order"] < 2**64,
            "Unsafe diagnostic trace order",
        )
        rows.append(event)
    matches = [
        row
        for row in rows
        if row["request_ref"] == request["request_id"] and row["operation"] == request["op"]
    ]
    require(matches, "No owned metadata exists for the original diagnostic request")
    trace = max(matches, key=lambda row: row["trace_order"])["trace_ref"]
    events = sorted(
        (row for row in rows if row["trace_ref"] == trace), key=lambda row: row["sequence"]
    )
    if fixture_case() == SOCKET_CASE and request["op"] in {"prepare", "apply"}:
        paths = socket_paths(request["op"])
        if socket_signal_ready(paths["done"]) and not any(
            event["step"] == "socket_destroy" for event in events
        ):
            result = decode(owned_read(paths["result"], 4096))
            require(socket_result_valid(result), "Unsafe socket completion metadata was refused")
            observations = {
                "ss_stdout_bytes": result["ss_stdout_bytes"],
                "ss_stderr_category": result["ss_stderr_category"],
                "after_absence": result["after_absence"],
            }
            if type(result["ss_returncode"]) is int:
                observations["ss_returncode"] = result["ss_returncode"]
            events.append(
                {
                    "sequence": events[-1]["sequence"] + 1,
                    "step": "socket_destroy",
                    "status": "ok"
                    if result["after_absence"]
                    and result["ss_returncode"] == 0
                    and result["error_category"] == "none"
                    else "refused",
                    "error_category": result["error_category"],
                    "observations": observations,
                }
            )
    raw, state = fault_ledger()
    record = state["records"].get(request["request_id"])
    phase = "not_found" if record is None else record["phase"]
    known = {
        "armed",
        "attached",
        "consumed",
        "ready",
        "intent",
        "active",
        "revoke_intent",
        "revoked",
        "rejected",
        "synced",
        "not_found",
    }
    export = {
        "schema": "opsark-session-diagnostics/v1",
        "trace_ref": trace,
        "event_count": len(events),
        "events": [
            {
                key: event[key]
                for key in ("sequence", "step", "status", "error_category", "observations")
            }
            for event in events[-24:]
        ],
        "ledger": {
            "phase": phase if phase in known else "invalid_state",
            "record_count": len(state["records"]),
            "usage_count": len(state["usage"]),
            "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        },
    }
    require(diagnostic_export_valid(export), "Unsafe diagnostic export was refused")
    encoded = canonical(export) + b"\n"
    require(len(encoded) <= 6144, "The safe diagnostic export exceeded its bound")
    sys.stdout.buffer.write(encoded)
    return 0


def provision_roles(target, image):
    import pwd

    for executable in ("/usr/bin/sudo", "/usr/sbin/visudo", "/usr/bin/timeout"):
        require(Path(executable).is_file(), "The pinned laboratory image lacks required tools")
    installed = Path(INSTALLED).parent
    installed.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name in DEFENSE_FILES:
        original = Path(CODE) / "deploy/defense" / name
        if name in FROZEN:
            require(
                hashlib.sha256(original.read_bytes()).hexdigest() == FROZEN[name],
                "Frozen installed source hash differs",
            )
        shutil.copyfile(original, installed / name)
        (installed / name).chmod(0o644)
    sudoers = []
    matches = []
    for role in ("readonly", "observe", "control"):
        user, home = f"opsark-defense-{role}", Path(f"/home/opsark-defense-{role}")
        try:
            pwd.getpwnam(user)  # ty: ignore[unresolved-attribute] -- Linux-only
        except KeyError:
            pass
        else:
            raise LabError("A synthetic role account already exists")
        require(not home.exists(), "A synthetic role home already exists")
        result = run(
            "/usr/sbin/useradd",
            "--create-home",
            "--user-group",
            "--home-dir",
            str(home),
            "--shell",
            "/bin/sh",
            "--password",
            "*",
            user,
        )
        require(result.returncode == 0, "Synthetic role account creation failed")
        authorized = home / ".ssh" / "authorized_keys"
        authorized.parent.mkdir(mode=0o700)
        key = target.public_key(target.read_fixture_file(Path(AUTHORITY) / f"{role}.pub", 256))
        authorized.write_text(f'from="198.18.241.4",restrict {key}\n', encoding="ascii")
        authorized.chmod(0o600)
        # Keep the complete key path administrator-owned; the account cannot replace it.
        for path in (home, authorized.parent, authorized):
            os.chown(path, 0, 0)  # ty: ignore[unresolved-attribute] -- Linux-only
        home.chmod(0o755)
        authorized.parent.chmod(0o755)
        authorized.chmod(0o644)
        wrapper = Path(f"/usr/local/sbin/opsark-defense-{role}")
        require(not wrapper.exists(), "A fixed role entrypoint already exists")
        flag = "" if role == "readonly" else f" --{role}"
        command = f"/usr/bin/python3 -I -B {INSTALLED}{flag}"
        if role == "control" and fixture_case() in FAULT_CASES:
            command = (
                f"/usr/bin/python3 -I -B {SELF} --internal-control-wrapper "
                f"--image {image} --confirm-isolated"
            )
        wrapper.write_text(
            f"#!/bin/sh\nexec /usr/bin/timeout -k 1s 25s {command}\n",
            encoding="ascii",
        )
        wrapper.chmod(0o755)
        sudoers.append(f'{user} ALL=(root) NOPASSWD: {wrapper} ""\n')
        matches.append(f"Match User {user}\n    ForceCommand /usr/bin/sudo -n -- {wrapper}\n")
    policy = Path("/etc/sudoers.d/opsark-defense-requests-lab")
    require(not policy.exists(), "A synthetic sudo policy already exists")
    policy.write_text(
        "Defaults env_reset\nDefaults !requiretty\n" + "".join(sudoers), encoding="ascii"
    )
    policy.chmod(0o440)
    require(
        run("/usr/sbin/visudo", "-cf", str(policy)).returncode == 0,
        "The exact sudo policy did not validate",
    )
    config = Path("/run/opsark-ssh-defense/requests-sshd.conf")
    config.write_text(
        f"""AddressFamily inet
ListenAddress {TARGET}:{REQUEST_PORT}
PidFile /run/opsark-ssh-defense/requests-sshd.pid
HostKey /run/opsark-ssh-defense/host
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers opsark-defense-readonly opsark-defense-observe opsark-defense-control
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
DisableForwarding yes
PermitTTY no
PermitUserRC no
LogLevel ERROR
{"".join(matches)}""",
        encoding="ascii",
    )
    config.chmod(0o600)
    require(
        run("/usr/sbin/sshd", "-t", "-f", str(config)).returncode == 0,
        "Fixed role SSH listener configuration failed",
    )
    return config


def internal_target(image):
    from http.server import ThreadingHTTPServer

    target, _ = internal_modules()
    config, host_key = target.prepare_ssh(
        target.public_key(target.read_fixture_file(Path(AUTHORITY) / "client.pub", 256))
    )
    request_config = provision_roles(target, image)
    with target.sshd(config), ExitStack() as cleanup:
        result = run(
            "/usr/bin/python3",
            "-I",
            "-B",
            f"{CODE}/deploy/defense/ssh_fixture.py",
            "--profile",
            "private",
            "initialize",
        )
        require(
            result.returncode == 0 and decode(result.stdout) == {"status": "initialized"},
            "Native private nft policy initialization failed",
        )
        deployment = target.read_fixture_file(Path(AUTHORITY) / "deployment.json", 4096)
        result = run(
            "/usr/bin/python3", "-I", "-B", INSTALLED, "--initialize", input_bytes=deployment
        )
        require(
            result.returncode == 0 and decode(result.stdout) == {"v": 1, "state": "initialized"},
            "Explicit fresh Root request initialization failed",
        )
        install_faults(fixture_case(), image)
        log = Path("/run/opsark-ssh-defense/requests-sshd.log")
        log.touch(mode=0o600, exist_ok=False)
        process = cleanup.enter_context(
            subprocess.Popen(  # noqa: S603 -- fixed private SSH listener.
                ["/usr/sbin/sshd", "-D", "-E", str(log), "-f", str(request_config)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=ENV,
            )
        )
        cleanup.callback(process.terminate)
        for _ in range(50):
            if Path("/run/opsark-ssh-defense/requests-sshd.pid").is_file():
                break
            require(process.poll() is None, "The fixed role SSH listener stopped")
            time.sleep(0.1)
        else:
            raise LabError("The fixed role SSH listener did not start")
        server = cleanup.enter_context(ThreadingHTTPServer((TARGET, 22480), target.HealthHandler))
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        cleanup.callback(server.shutdown)
        target.publish_ready(host_key)
        while process.poll() is None:
            if fixture_case() == SOCKET_CASE:
                process_socket_interruption(image)
                time.sleep(0.05)
            else:
                time.sleep(1)
    return 0


def internal_snapshot():
    _, nft = internal_modules()
    from deploy.defense import ssh_fixture_evidence as native_evidence

    raw = (REQUEST_ROOT / "requests.json").read_bytes()
    value = decode(raw, 196_608)
    records = value["records"]
    counts = {}
    for record in records.values():
        counts[record["kind"]] = counts.get(record["kind"], 0) + 1
    failures, successes = 0, 0
    cursors = [
        record
        for record in records.values()
        if record["kind"] == "cursor" and record["payload"] is not None
    ]
    require(len(cursors) <= 1, "The independent fixture had more than one cursor")
    if cursors:
        mark = cursors[0]["payload"]["mark"]
        dev, inode, log = native_evidence._read_log(Path("/run/opsark-ssh-defense/sshd.log"))
        require(
            (dev, inode) == (mark["dev"], mark["ino"])
            and hashlib.sha256(log[: mark["offset"]]).hexdigest() == mark["prefix_sha256"],
            "The native authentication prefix changed",
        )
        for line in log[mark["offset"] :].splitlines():
            event = native_evidence._AUTH.fullmatch(line.removesuffix(b"\r"))
            if event is not None and event["peer"] == b"198.18.241.3":
                failures += event["kind"] == b"Failed"
                successes += event["kind"] == b"Accepted"
    result = {
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "records": counts,
        "usage_count": len(value["usage"]),
        "intents": sum(
            record["phase"] in {"intent", "active", "revoke_intent", "revoked"}
            for record in records.values()
        ),
        "kernel_active": nft.observe(profile="private") is not None,
        "candidate_failure_events": failures,
        "candidate_success_events": successes,
    }
    print(canonical(result).decode("ascii"))
    return 0


def internal_drop():
    import fcntl

    require(
        sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file(),
        "Use the owned management container",
    )
    require(
        {name for _, name in socket.if_nameindex()} == {"lo", "eth0"},
        "Unexpected management interfaces",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        request_address = struct.pack("256s", b"eth0")
        address = socket.inet_ntoa(fcntl.ioctl(peer.fileno(), 0x8915, request_address)[20:24])  # ty: ignore[unresolved-attribute] -- Linux-only
        mask = socket.inet_ntoa(fcntl.ioctl(peer.fileno(), 0x891B, request_address)[20:24])  # ty: ignore[unresolved-attribute] -- Linux-only
    require(
        address == ADDRESSES["management"] and mask == "255.255.255.240", "Wrong management address"
    )
    status = Path("/proc/self/status").read_text().splitlines()
    require(
        next(line.split()[1] for line in status if line.startswith("CapEff:")) == "0000000000000000"
        and next(line.split()[1] for line in status if line.startswith("NoNewPrivs:")) == "1",
        "The management client had unexpected privileges",
    )
    require(
        all(
            line.split()[1] != "00000000"
            for line in Path("/proc/net/route").read_text().splitlines()[1:]
        ),
        "The management client had a default route",
    )
    request = decode(sys.stdin.buffer.read(4097))
    require(
        request["op"] in {"prepare", "apply"}, "Only fixed prepare/apply receipt loss is supported"
    )
    # The TCP reset is on a private loopback hop AFTER native forced-command SSH has
    # completed. It does not claim to cut or decrypt the underlying SSH connection.
    failures, binding = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(30)
        endpoint = listener.getsockname()

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(30)
                    require(peer.recv(1) == b"!", "Unexpected reset-fixture handshake")
                    result = run(
                        *ssh_argv(role="control"),
                        input_bytes=canonical(request) + b"\n",
                        timeout=28,
                        limit=4096,
                    )
                    require(
                        result.returncode == 0 and not result.stderr,
                        "The native SSH operation failed before the reset",
                    )
                    receipt = validate_reply(decode(result.stdout), request)
                    require(
                        receipt["state"] == ("ready" if request["op"] == "prepare" else "active"),
                        "The native SSH operation did not confirm before reset",
                    )
                    binding.append(identity_binding(receipt))
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                failures.append(True)

        worker = Thread(target=serve)
        worker.start()
        reset = False
        with socket.create_connection(endpoint, timeout=30) as peer:
            peer.settimeout(30)
            peer.sendall(b"!")
            try:
                data = peer.recv(1)
                require(not data, "The reset hop leaked a native receipt")
            except ConnectionResetError:
                reset = True
        worker.join(timeout=2)
        require(
            reset and not worker.is_alive() and not failures and len(binding) == 1,
            "No actual TCP reset followed a confirmed native SSH result",
        )
    print(
        canonical(
            {
                "tcp_reset": True,
                "fault_layer": "management_loopback_after_native_ssh",
                "identity_binding_sha256": binding[0],
            }
        ).decode("ascii")
    )
    return 0


def main():
    global _deadline, _overall_deadline, _last_diagnostic
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, help="Existing root-private child of /var/lib/opsark-release-lab"
    )
    parser.add_argument("--image", help="Already cached exact sha256 image ID; never pull or build")
    parser.add_argument(
        "--proof", type=Path, help="New proof JSON directly beneath --root; never overwritten"
    )
    parser.add_argument(
        "--case", choices=("all", *CASES, PROBE_CASE, SOCKET_PROBE_CASE), default="all"
    )
    parser.add_argument("--confirm-isolated", action="store_true")
    internal = parser.add_mutually_exclusive_group()
    internal.add_argument("--internal-target", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-snapshot", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-drop", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-control-wrapper", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-nft-shim", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-fault-proof", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-diagnostics", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--internal-ss-close", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("nft_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        require(args.confirm_isolated, "Explicit --confirm-isolated is required")
        require(
            args.image is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", args.image),
            "Use an exact cached image ID",
        )
        require(
            args.internal_nft_shim or not args.nft_args,
            "No arbitrary fixture command operands are accepted",
        )
        if args.internal_target:
            return internal_target(args.image)
        if args.internal_snapshot:
            return internal_snapshot()
        if args.internal_drop:
            return internal_drop()
        if args.internal_control_wrapper:
            return internal_control_wrapper()
        if args.internal_nft_shim:
            arguments = args.nft_args[1:] if args.nft_args[:1] == ["--"] else args.nft_args
            return internal_nft_shim(arguments)
        if args.internal_fault_proof:
            return internal_fault_proof()
        if args.internal_diagnostics:
            return internal_diagnostics()
        if args.internal_ss_close:
            return internal_ss_close()
        require(not args.nft_args, "No arbitrary fixture command operands are accepted")
        require(
            args.root is not None and args.proof is not None,
            "Explicit --root and new --proof are required",
        )
        require_root(args.root)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        cases = CASES if args.case == "all" else (args.case,)
        total_budget = sum(case_budget(case) for case in cases) + CLEANUP_SECONDS
        _overall_deadline = time.monotonic() + total_budget
        report = {
            "schema": "opsark-native-requests-lab/v1",
            "completed": False,
            "image": args.image,
            "source_sha256": FROZEN,
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "case_budget_seconds": {case: case_budget(case) for case in cases},
            "total_budget_seconds": total_budget,
            "cases": [],
            "console_and_ai_verified": False,
            "fault_scope": "per-case controlled isolated fault boundary",
        }
        with proof_file(args.root, args.proof) as output:
            try:
                for case in cases:
                    _last_diagnostic = None
                    _deadline = min(_overall_deadline, time.monotonic() + case_budget(case))
                    report["running_case"] = case
                    report["cases"].append(exercise_case(args.root, args.image, case))
                report["running_case"] = None
                report["completed"] = True
            finally:
                if not report["completed"] and _last_diagnostic is not None:
                    report["failure_diagnostic"] = _last_diagnostic
                output.write(canonical(report) + b"\n")
                output.flush()
                os.fsync(output.fileno())
        print(
            canonical(
                {
                    "completed": True,
                    "case_count": len(cases),
                    "proof_ref": args.proof.name,
                    "console_and_ai_verified": False,
                }
            ).decode("ascii")
        )
        return 0
    except LabError as error:
        if args.internal_control_wrapper:
            diagnostic_failure(error)
        print(str(error), file=sys.stderr)
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        subprocess.SubprocessError,
    ) as error:
        if args.internal_control_wrapper:
            diagnostic_failure(error)
        print("The isolated native request laboratory could not be verified.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
