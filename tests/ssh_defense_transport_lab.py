#!/usr/bin/env python3
"""One owned protocol-sshd restart over the frozen private auto-ACK fixture.

Only a fresh fixture can select this profile. The supervisor replaces its held
22423 child once; it never reinitializes Root, provisions accounts, renews a grant
or restarts the protected listener. No arbitrary PID, argv or signal is input.
"""

import hashlib
import json
import os
import re
import signal
import socket
import stat
import sys
import time
from contextlib import ExitStack, contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssh_defense_session_lab as session  # noqa: E402 -- fixed owned sibling under -I.

business, base, native = session.business, session.base, session.native
SELF = "/fixture-code/tests/ssh_defense_transport_lab.py"
SESSION_SHA256 = "4e167b3e528b8be2b3e2eadc332574d32b67510d2ac456c7cb3999db7b53e6a1"
PROFILE = "root-protocol-sshd-restart-once/v1"
PROFILE_SPEC = {
    "profile": PROFILE,
    "session_profile": "auto-ack",
    "protected_port": 22422,
    "transport_port": 22423,
    "restart_limit": 1,
    "requires_quiescent_transport": True,
    "root_initialization_during_restart": False,
    "provision_during_restart": False,
    "nft_initialization_during_restart": False,
    "host_key_generation_during_restart": False,
}
PROFILE_SHA256 = native.digest(PROFILE_SPEC)
PROFILE_FILE = "transport-profile.json"
OPERATION = "root-transport-restart"
OPERATIONS = business.OPERATIONS | {OPERATION}
PREFIX = "root-transport-restart"
REQUEST = PREFIX + ".request.json"
REQUEST_READY = PREFIX + ".request.ready"
CLAIM = PREFIX + ".claim.json"
RESULT = PREFIX + ".result.json"
RESULT_READY = PREFIX + ".result.ready"
FIXTURE_ROOT = Path("/run/opsark-ssh-defense")
PIDFILE = FIXTURE_ROOT / "requests-sshd.pid"
CONFIG = FIXTURE_ROOT / "requests-sshd.conf"
LOG = FIXTURE_ROOT / "requests-sshd.log"
READY_ROOT = Path("/fixture-ready")
ARGV = ("/usr/sbin/sshd", "-D", "-E", str(LOG), "-f", str(CONFIG))
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
IMMUTABLE_FIELDS = (
    "protected_process_sha256",
    "protected_listener_sha256",
    "netns_sha256",
    "protected_log_identity_sha256",
    "protected_log_sha256",
    "public_pin_sha256",
    "key_file_identity_sha256",
    "protected_config_sha256",
    "transport_config_sha256",
    "roles_policy_sha256",
    "authority_sha256",
    "root_ledger_sha256",
    "root_grants_sha256",
    "root_usage_sha256",
    "root_intents_sha256",
    "root_binding_sha256",
)
TRANSPORT_FIELDS = ("transport_process_sha256", "transport_listener_sha256")
_SOURCE_CLOSURE = session.verify_source_closure
_STAGE_SESSION = session.stage_session
_BUSINESS_READY = business.ready_value
_PROCESS_COMMAND = business.process_command
_INTERNAL_DISPATCH = session.internal_dispatch
_PROOF_FILE = native.proof_file


def transport_ref_sha256(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def verify_source_closure(root):
    value = _SOURCE_CLOSURE(root)
    native.require(
        len(value) == 15 and value["tests/ssh_defense_session_lab.py"] == SESSION_SHA256,
        "Frozen fifteen-file source closure changed",
    )
    raw = native.owned_read(root / "tests/ssh_defense_transport_lab.py", 262144)
    native.require(b"\r\n" not in raw, "Transport source must be canonical LF")
    return value | {"tests/ssh_defense_transport_lab.py": hashlib.sha256(raw).hexdigest()}


def validate_metadata(value, source_root=None):
    native.require(
        type(value) is dict
        and set(value)
        == {"transport_profile", "transport_profile_sha256", "transport_ref", "source_sha256"}
        and value["transport_profile"] == PROFILE
        and value["transport_profile_sha256"] == PROFILE_SHA256
        and type(value["transport_ref"]) is str
        and re.fullmatch("[0-9a-f]{32}", value["transport_ref"])
        and value["source_sha256"]
        == verify_source_closure(Path(native.CODE) if source_root is None else source_root),
        "Transport profile or source closure changed",
    )
    return value


def authority_metadata():
    value = base.read_json(Path(native.AUTHORITY) / PROFILE_FILE)
    return validate_metadata(value)


def stage_transport(workspace, policy_path, expected):
    native.require(
        expected == session.profile_metadata("auto-ack"), "Transport requires fresh auto-ACK"
    )
    with patch.object(session, "verify_source_closure", _SOURCE_CLOSURE):
        staged = _STAGE_SESSION(workspace, policy_path, expected)
    code, _keys, _management, authority, *_ = staged
    business.copy_source(Path(__file__).resolve(), code / "tests/ssh_defense_transport_lab.py")
    value = {
        "transport_profile": PROFILE,
        "transport_profile_sha256": PROFILE_SHA256,
        "transport_ref": native.secrets.token_hex(16),
        "source_sha256": verify_source_closure(code),
    }
    base.write_new(authority / PROFILE_FILE, value)
    return staged


def checked_request(value, metadata):
    native.require(
        type(value) is dict
        and set(value)
        == {"schema", "operation", "request_id", "fixture_id", "transport_ref", "command_sha256"}
        and value["schema"] == "opsark-root-transport-restart-command/v1"
        and value["operation"] == OPERATION
        and value["transport_ref"] == metadata["transport_ref"]
        and type(value["request_id"]) is str
        and re.fullmatch("[0-9a-f]{32}", value["request_id"])
        and type(value["fixture_id"]) is str
        and re.fullmatch("[0-9a-f]{16}", value["fixture_id"])
        and type(value["command_sha256"]) is str
        and re.fullmatch("[0-9a-f]{64}", value["command_sha256"]),
        "Unapproved fixed transport restart request",
    )
    original = {
        "schema": "opsark-controller-command/v1",
        "request_id": value["request_id"],
        "operation": OPERATION,
        "fixture_id": value["fixture_id"],
    }
    native.require(
        native.digest(original) == value["command_sha256"], "Original restart command changed"
    )
    return value


def process_command(command, root, network, target, clients):
    if command["operation"] != OPERATION:
        return _PROCESS_COMMAND(command, root, network, target, clients)
    business.checked_command(command)
    native.require(command["fixture_id"] == network.fixture, "Restart fixture identity changed")
    authority = network.workspace / "authority"
    metadata = validate_metadata(
        base.read_json(authority / PROFILE_FILE), network.workspace / "code"
    )
    native.require(
        metadata["source_sha256"] == verify_source_closure(network.workspace / "code")
        and metadata["transport_profile_sha256"] == PROFILE_SHA256,
        "Restart original transport authority changed",
    )
    once = root / (PREFIX + ".once.json")
    native.require(
        not once.exists() and not once.is_symlink(), "Transport restart was already claimed"
    )
    request = checked_request(
        {
            "schema": "opsark-root-transport-restart-command/v1",
            "operation": OPERATION,
            "request_id": command["request_id"],
            "fixture_id": network.fixture,
            "transport_ref": metadata["transport_ref"],
            "command_sha256": native.digest(command),
        },
        metadata,
    )
    # Retain the host claim even if publication, SSH or the supervisor fails.
    base.write_new(once, request)
    directory = network.workspace / "ready"
    base.write_new(directory / REQUEST, request)
    native.publish_socket_signal(directory / REQUEST_READY)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if native.socket_signal_ready(directory / RESULT_READY):
            result = base.read_json(directory / RESULT, 32768)
            native.require(
                result.get("schema") == "opsark-root-transport-restart-result/v1"
                and result.get("command_sha256") == request["command_sha256"]
                and result.get("transport_ref_sha256")
                == transport_ref_sha256(metadata["transport_ref"])
                and result.get("completed") is True,
                "The one transport restart did not confirm",
            )
            proof = result.get("proof")
            native.require(
                type(proof) is dict and proof.get("completed") is True,
                "The physical transport restart proof is missing",
            )
            return proof
        time.sleep(0.05)
    raise native.LabError("The one transport restart receipt is unavailable; do not retry")


def _file_identity(path):
    info = path.lstat()
    native.require(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and info.st_nlink == 1
        and not info.st_mode & 0o022
        and 0 < info.st_size <= 32768,
        "An immutable fixture file identity changed",
    )
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ]


def _public_sha(path, limit=32768):
    return hashlib.sha256(native.owned_read(path, limit, private=False)).hexdigest()


def listener_identity(process):
    native.require(
        process.poll() is None and process.args == list(ARGV), "The held transport child changed"
    )
    record = native.process_record(process.pid)
    native.require(
        record["ppid"] == os.getpid(), "The transport is not this supervisor's held child"
    )
    native.verify_program(record, "/usr/sbin/sshd")
    raw = native.owned_read(PIDFILE, 16, private=False)
    native.require(
        raw == str(process.pid).encode("ascii") + b"\n", "Transport PID file is not the held child"
    )
    suffix = f":{int(native.REQUEST_PORT):04X}"
    native.require(native.REQUEST_PORT == "22423", "The fixed transport port changed")
    endpoint = socket.inet_aton(native.TARGET)[::-1].hex().upper() + suffix
    rows = [
        parts
        for line in Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        if (parts := line.split())[3] == "0A" and parts[1].endswith(suffix)
    ]
    native.require(
        len(rows) == 1 and rows[0][1] == endpoint, "The exact transport listener is absent"
    )
    inode = int(rows[0][9])
    native.require(
        any(
            os.readlink(path) == f"socket:[{inode}]"
            for path in (Path("/proc") / str(process.pid) / "fd").iterdir()
            if path.is_symlink()
        ),
        "The transport listener is not owned by its held child",
    )
    return native.process_identity(record), inode


def no_inflight(process):
    record, _inode = listener_identity(process)
    raw = (Path("/proc") / str(process.pid) / "task" / str(process.pid) / "children").read_bytes()
    native.require(
        len(raw) <= 4096 and not raw.strip() and not native.request_connections(),
        "A transport connection or child is still in flight",
    )
    return record


def snapshot(process):
    from deploy.defense import ssh_fixture as fixture
    from deploy.defense import ssh_fixture_evidence as evidence
    from deploy.defense import ssh_requests as root

    transport, socket_inode = listener_identity(process)
    with root._locked() as directory, fixture._locked() as protected:
        state = root._load(directory)
        root._bound(state, protected)
        binding = fixture._bound_listener(protected, "private")
        ledger = root._read_ledger(directory)
        actions = [
            (rid, record) for rid, record in state["records"].items() if record["kind"] == "action"
        ]
        cursors = [record for record in state["records"].values() if record["kind"] == "cursor"]
        native.require(
            len(actions) == len(cursors) == 1 and len(state["usage"]) == 1,
            "Restart requires one original completed action",
        )
        rid, action = actions[0]
        payload = action["payload"]
        native.require(
            action["phase"] == "active"
            and state["usage"] == [rid]
            and payload["intent_bound"] is not None
            and payload["expiry_bound"] is not None
            and payload["apply_hash"] is not None
            and state["mode"] == {"mode": "auto", "mode_revision": 2},
            "Restart cannot establish or adopt action authority",
        )
        authority = Path(native.AUTHORITY)
        native.require(
            base.read_json(authority / "deployment.json") == state["deployment"],
            "Root deployment no longer matches its sealed authority",
        )
        public = {}
        for role in ("readonly", "observe", "control"):
            public["key_" + role] = _public_sha(
                Path(f"/home/opsark-defense-{role}/.ssh/authorized_keys")
            )
            public["wrapper_" + role] = _public_sha(Path(f"/usr/local/sbin/opsark-defense-{role}"))
        public["sudoers"] = _public_sha(Path("/etc/sudoers.d/opsark-defense-requests-lab"))
        authorities = {path.name: _public_sha(path) for path in authority.iterdir()}
        dev, ino, log = evidence._read_log(FIXTURE_ROOT / "sshd.log")
        manifest_sha = native.digest(payload["manifest"])
        identity = {
            "action_id": payload["action_id"],
            "manifest_sha256": manifest_sha,
            "cursor_id": payload["cursor_id"],
        }
        fields = {
            "protected_process_sha256": native.digest(
                {"identity": binding[3:5], "pid_file": _file_identity(FIXTURE_ROOT / "sshd.pid")}
            ),
            "protected_listener_sha256": native.digest(binding),
            "netns_sha256": native.digest(binding[:2]),
            "protected_log_identity_sha256": native.digest([dev, ino]),
            "protected_log_sha256": hashlib.sha256(log).hexdigest(),
            "public_pin_sha256": _public_sha(FIXTURE_ROOT / "host.pub"),
            # Metadata only. Never read or hash the private host-key body.
            "key_file_identity_sha256": native.digest(_file_identity(FIXTURE_ROOT / "host")),
            "protected_config_sha256": _public_sha(FIXTURE_ROOT / "sshd_config"),
            "transport_config_sha256": _public_sha(CONFIG),
            "roles_policy_sha256": native.digest(public),
            "authority_sha256": native.digest(authorities),
            "root_ledger_sha256": hashlib.sha256(ledger).hexdigest(),
            "root_grants_sha256": native.digest(state["deployment"]),
            "root_usage_sha256": native.digest(state["usage"]),
            "root_intents_sha256": native.digest(action),
            "root_binding_sha256": native.digest(
                {
                    "boot": state["boot_ref"],
                    "binding": state["binding"],
                    "binding_ref": state["binding_ref"],
                    "ledger_file": _file_identity(native.REQUEST_ROOT / "requests.json"),
                }
            ),
            "transport_process_sha256": native.digest(transport),
            "transport_listener_sha256": native.digest(socket_inode),
        }
    return {
        "fields": fields,
        "request_id_sha256": hashlib.sha256(rid.encode("ascii")).hexdigest(),
        "manifest_sha256": manifest_sha,
        "identity_binding_sha256": native.digest(identity),
        "usage_count": 1,
        "intent_count": 1,
    }


class FixedTransport:
    """Own exactly the fixed protocol listener; no PID or argv comes from a request."""

    def __init__(self):
        self.current = None
        self.identity = None
        self.starts = 0
        self.restart_count = 0

    def start(self):
        native.require(
            (
                self.starts == 0
                or (
                    self.starts == 1
                    and self.restart_count == 1
                    and self.current is not None
                    and self.current.poll() is not None
                )
            )
            and native.ENV == ENV,
            "Transport start budget changed",
        )
        self.starts += 1
        self.current = native.subprocess.Popen(
            list(ARGV),
            stdin=native.subprocess.DEVNULL,
            stdout=native.subprocess.DEVNULL,
            stderr=native.subprocess.DEVNULL,
            env=dict(ENV),
        )
        # Bind birth before readiness so cleanup can also stop a held child
        # that executes successfully but never publishes a listener/PID file.
        record = native.process_record(self.current.pid)
        native.require(record["ppid"] == os.getpid(), "The spawned transport is not a held child")
        native.verify_program(record, "/usr/sbin/sshd")
        self.identity = native.process_identity(record)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            native.require(self.current.poll() is None, "The held transport failed to start")
            try:
                self.identity, _inode = listener_identity(self.current)
                return self.current
            except (FileNotFoundError, native.LabError):
                time.sleep(0.05)
        raise native.LabError("The held transport did not become ready")

    def stop(self):
        process = self.current
        if process is None:
            return
        if process.poll() is not None:
            process.wait(timeout=3)
            return
        record = native.process_record(process.pid)
        native.require(
            self.identity == native.process_identity(record) and record["ppid"] == os.getpid(),
            "Held transport process identity changed",
        )
        native.verify_program(record, "/usr/sbin/sshd")
        descriptor = os.pidfd_open(process.pid)  # ty: ignore[unresolved-attribute] -- fixed Linux child.
        try:
            native.require(
                self.identity == native.process_identity(native.process_record(process.pid)),
                "Pinned held transport identity changed",
            )
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)  # ty: ignore[unresolved-attribute] -- fixed Linux pidfd.
            try:
                process.wait(timeout=3)
            except native.subprocess.TimeoutExpired:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)  # ty: ignore[unresolved-attribute] -- same held child only.
                process.wait(timeout=3)
        finally:
            os.close(descriptor)

    def restart(self, request, metadata, counters):
        native.require(
            self.restart_count == 0 and self.starts == 1 and self.current is not None,
            "Only one held transport restart is permitted",
        )
        self.restart_count = 1  # Consumed before any stop/start, including a failed attempt.
        no_inflight(self.current)
        before = snapshot(self.current)
        previous_identity = self.identity
        original = dict(counters)
        old = self.current
        if old is None or previous_identity is None:
            raise native.LabError("The original held child identity is unavailable")
        self.stop()
        native.require(old.poll() is not None, "Old transport was not reaped")
        self.start()
        if self.current is None or self.identity is None:
            raise native.LabError("The new held child identity is unavailable")
        native.require(
            self.current is not old
            and self.identity["pid"] != previous_identity["pid"]
            and self.identity["start"] != previous_identity["start"],
            "New transport did not have a distinct process birth",
        )
        no_inflight(self.current)
        after = snapshot(self.current)
        native.require(
            all(
                before[key] == after[key]
                for key in ("request_id_sha256", "manifest_sha256", "identity_binding_sha256")
            ),
            "Original action changed across transport replacement",
        )
        native.require(
            all(before["fields"][key] == after["fields"][key] for key in IMMUTABLE_FIELDS)
            and all(before["fields"][key] != after["fields"][key] for key in TRANSPORT_FIELDS),
            "Restart changed protected state or failed to replace the transport",
        )
        native.require(counters == original, "Restart repeated an initialization operation")
        return {
            "schema": "opsark-root-transport-restart-proof/v1",
            "completed": True,
            "transport_profile": PROFILE,
            "transport_profile_sha256": PROFILE_SHA256,
            "transport_ref_sha256": transport_ref_sha256(metadata["transport_ref"]),
            "command_sha256": request["command_sha256"],
            "restart_count": self.restart_count,
            "request_id_sha256": before["request_id_sha256"],
            "manifest_sha256": before["manifest_sha256"],
            "identity_binding_sha256": before["identity_binding_sha256"],
            "old_transport_terminated": True,
            "new_transport_started": True,
            "transport_identity_changed": True,
            "transport_listening": True,
            "no_inflight_transport_sessions": True,
            "protected_listener_preserved": True,
            "immutable_state_preserved": True,
            "initialize_calls_during_restart": counters["root_initialize"]
            - original["root_initialize"],
            "provision_calls_during_restart": counters["provision"] - original["provision"],
            "nft_initialize_calls_during_restart": counters["nft_initialize"]
            - original["nft_initialize"],
            "host_key_generation_calls_during_restart": counters["prepare"] - original["prepare"],
            "usage_count_before": before["usage_count"],
            "usage_count_after": after["usage_count"],
            "intent_count_before": before["intent_count"],
            "intent_count_after": after["intent_count"],
            "before": before["fields"],
            "after": after["fields"],
        }


def service_request(transport, metadata, counters):
    directory = READY_ROOT
    if not native.socket_signal_ready(directory / REQUEST_READY) or (directory / CLAIM).exists():
        return
    request = checked_request(base.read_json(directory / REQUEST), metadata)
    base.write_new(directory / CLAIM, request)
    try:
        proof = transport.restart(request, metadata, counters)
        result = {
            "schema": "opsark-root-transport-restart-result/v1",
            "completed": True,
            "transport_ref_sha256": transport_ref_sha256(metadata["transport_ref"]),
            "command_sha256": request["command_sha256"],
            "proof": proof,
        }
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        result = {
            "schema": "opsark-root-transport-restart-result/v1",
            "completed": False,
            "reason_code": "restart_unconfirmed_no_retry",
            "restart_count": transport.restart_count,
            "transport_ref_sha256": transport_ref_sha256(metadata["transport_ref"]),
            "command_sha256": request["command_sha256"],
        }
    base.write_new(directory / RESULT, result)
    native.publish_socket_signal(directory / RESULT_READY)


def internal_target(image):
    """The original setup runs once; only the protocol-listener loop is replaced."""
    target, _ = native.internal_modules()
    metadata = authority_metadata()
    session.validate_authority(Path(native.AUTHORITY), session.profile_metadata("auto-ack"))
    counters = {"prepare": 0, "provision": 0, "nft_initialize": 0, "root_initialize": 0}
    business.begin_diagnostic("target", READY_ROOT / business.TARGET_DIAGNOSTIC)
    business.require_fresh_root_storage()
    config, host_key = target.prepare_ssh(
        target.public_key(target.read_fixture_file(Path(native.AUTHORITY) / "client.pub", 256))
    )
    counters["prepare"] += 1
    business.diagnostic_step("prepare", "ok")
    business.install_collector(config)
    business.collector_traversal_preflight(image)
    business.diagnostic_step("root_roles_prepare")
    request_config = native.provision_roles(target, image)
    counters["provision"] += 1
    native.require(request_config == CONFIG, "The protocol SSH configuration path changed")
    business.diagnostic_step("root_roles_prepare", "ok")
    business.diagnostic_step("protected_sshd_start")
    with target.sshd(config), ExitStack() as cleanup:
        business.diagnostic_step("protected_sshd_start", "ok")
        business.diagnostic_step("nft_init")
        result = native.run(
            "/usr/bin/python3",
            "-I",
            "-B",
            f"{native.CODE}/deploy/defense/ssh_fixture.py",
            "--profile",
            "private",
            "initialize",
        )
        counters["nft_initialize"] += 1
        business.diagnostic_step("nft_init", result=result)
        native.require(
            result.returncode == 0 and native.decode(result.stdout) == {"status": "initialized"},
            "Native private nft initialization failed",
        )
        business.diagnostic_step("nft_init", "ok")
        business.diagnostic_step("root_init")
        deployment = target.read_fixture_file(Path(native.AUTHORITY) / "deployment.json", 4096)
        result = native.run(
            "/usr/bin/python3", "-I", "-B", native.INSTALLED, "--initialize", input_bytes=deployment
        )
        counters["root_initialize"] += 1
        business.diagnostic_step("root_init", result=result)
        native.require(
            result.returncode == 0
            and native.decode(result.stdout) == {"v": 1, "state": "initialized"},
            "Fresh Root initialization failed",
        )
        business.diagnostic_step("root_init", "ok")
        business.verify_private_root_storage()
        LOG.touch(mode=0o600, exist_ok=False)
        business.diagnostic_step("root_roles_start")
        transport = FixedTransport()
        cleanup.callback(transport.stop)
        transport.start()
        business.diagnostic_step("root_roles_start", "ok")
        for address, port, handler in (
            (native.TARGET, 22480, target.HealthHandler),
            ("127.0.0.1", business.HTTP_PORT, business.BusinessHandler),
        ):
            step = "http_start_business" if address == "127.0.0.1" else "http_start_protected"
            business.diagnostic_step(step)
            server = cleanup.enter_context(ThreadingHTTPServer((address, port), handler))
            Thread(target=server.serve_forever, daemon=True).start()
            cleanup.callback(server.shutdown)
            business.diagnostic_step(step, "ok")
        business.diagnostic_step("publish_ready")
        target.publish_ready(host_key)
        business.diagnostic_step("publish_ready", "ok")
        business.diagnostic_step("target_runtime")
        while True:
            if transport.current is None:
                raise native.LabError("The held transport child is unavailable")
            if transport.current.poll() is not None:
                break
            service_request(transport, metadata, counters)
            time.sleep(0.05)
    return 0


class TransportProof:
    def __init__(self, output, metadata):
        self.output, self.metadata = output, metadata

    def write(self, raw):
        value = json.loads(raw, object_pairs_hook=native.strict_pairs)
        value.update(
            schema="opsark-transport-controller-fixture-proof/v1",
            transport_profile=PROFILE,
            transport_profile_sha256=PROFILE_SHA256,
        )
        if self.metadata:
            value["transport_ref_sha256"] = transport_ref_sha256(self.metadata["transport_ref"])
        return self.output.write(native.canonical(value) + b"\n")

    def flush(self):
        return self.output.flush()

    def fileno(self):
        return self.output.fileno()


@contextmanager
def bound_transport():
    metadata = {}

    def stage(workspace, policy_path, expected):
        result = stage_transport(workspace, policy_path, expected)
        metadata.update(base.read_json(workspace / "authority" / PROFILE_FILE))
        return result

    def ready(*args):
        value = _BUSINESS_READY(*args)
        native.require(bool(metadata), "Transport authority was not sealed before readiness")
        return value | {
            key: metadata[key]
            for key in ("transport_profile", "transport_profile_sha256", "transport_ref")
        }

    def dispatch(name, image):
        native.internal_modules()
        authority_metadata()
        return internal_target(image) if name == "target" else _INTERNAL_DISPATCH(name, image)

    @contextmanager
    def proof_file(root, path):
        with _PROOF_FILE(root, path) as output:
            yield TransportProof(output, metadata)

    with (
        patch.object(session, "SELF", SELF),
        patch.object(session, "verify_source_closure", verify_source_closure),
        patch.object(session, "stage_session", stage),
        patch.object(session, "internal_dispatch", dispatch),
        patch.object(business, "OPERATIONS", OPERATIONS),
        patch.object(business, "process_command", process_command),
        patch.object(business, "ready_value", ready),
        patch.object(native, "proof_file", proof_file),
    ):
        yield


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["describe"]:
        print(
            native.canonical(
                {
                    "transport_profile": PROFILE,
                    "transport_profile_sha256": PROFILE_SHA256,
                    "profile": PROFILE_SPEC,
                    "session_profile": "auto-ack",
                    "checks": business.business_checks(),
                    "policy": business.expected_policy(),
                }
            ).decode("ascii")
        )
        return 0
    try:
        for index, value in enumerate(argv):
            if value == "--session-profile":
                native.require(
                    index + 1 < len(argv) and argv[index + 1] == "auto-ack",
                    "The transport profile accepts only auto-ACK",
                )
            native.require(
                not value.startswith("--session-profile="), "Use the fixed explicit profile operand"
            )
        with bound_transport():
            return session.main(argv)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        print("The isolated transport fixture could not be confirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
