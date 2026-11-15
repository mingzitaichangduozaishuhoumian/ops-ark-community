#!/usr/bin/env python3
"""Restart one held protected listener to prove frozen Root rejects its old binding.

This fresh negative experiment adds no recovery support. Root's protocol listener,
grant, ledger and binding are retained. Its normal SSH query must report the old
RID as unknown/binding_changed; local comparison snapshots are not Root replies.
"""

import hashlib
import json
import os
import re
import sys
import time
from contextlib import ExitStack, contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, TypedDict
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssh_defense_transport_lab as previous  # noqa: E402 -- immutable owned sibling under -I.

session, business, base, native = (
    previous.session,
    previous.business,
    previous.base,
    previous.native,
)
SELF = "/fixture-code/tests/ssh_defense_binding_loss_lab.py"
TRANSPORT_SHA256 = "9e42aa250d3a8f2e177ad25b22b0e1fd5e4d2ad3ac989547524d492de4277c7d"
PROFILE = "protected-listener-binding-loss-once/v1"
SPEC = {
    "profile": PROFILE,
    "session_profile": "auto-ack",
    "protected_port": 22422,
    "protocol_port": 22423,
    "protected_restart_limit": 1,
    "protocol_restarts_allowed": False,
    "execution_continuation_supported": False,
    "root_rebind_allowed": False,
    "root_initialization_during_restart": False,
    "provision_during_restart": False,
    "nft_initialization_during_restart": False,
    "host_key_generation_during_restart": False,
}
PROFILE_SHA256 = native.digest(SPEC)
PROFILE_FILE = "binding-loss-profile.json"
OPERATION = "protected-listener-restart"
OPERATIONS = business.OPERATIONS | {OPERATION}
PREFIX = "protected-listener-restart"
REQUEST, REQUEST_READY, CLAIM, RESULT, RESULT_READY = (
    PREFIX + suffix
    for suffix in (
        ".request.json",
        ".request.ready",
        ".claim.json",
        ".result.json",
        ".result.ready",
    )
)
ROOT = previous.FIXTURE_ROOT
READY_ROOT = previous.READY_ROOT
PROTECTED_CONFIG = ROOT / "sshd_config"
PROTECTED_LOG = ROOT / "sshd.log"
PROTECTED_PIDFILE = ROOT / "sshd.pid"
ARGV = ("/usr/sbin/sshd", "-D", "-E", str(PROTECTED_LOG), "-f", str(PROTECTED_CONFIG))
SOURCE_CATEGORY = "local_original_ledger_and_current_listener_comparison"
PRESERVED = (
    "protocol_process_sha256",
    "protocol_listener_sha256",
    "netns_sha256",
    "protected_log_identity_sha256",
    "protected_log_prefix_sha256",
    "public_pin_sha256",
    "key_file_identity_sha256",
    "protected_config_sha256",
    "protocol_config_sha256",
    "roles_policy_sha256",
    "authority_sha256",
    "root_ledger_sha256",
    "root_grants_sha256",
    "root_usage_sha256",
    "root_intents_sha256",
    "root_binding_sha256",
)
REPLACED = ("protected_process_sha256", "protected_listener_sha256", "current_binding_sha256")
_SOURCE = previous.verify_source_closure
_STAGE = previous.stage_transport
_READY = previous._BUSINESS_READY
_DISPATCH = previous._INTERNAL_DISPATCH
_PROCESS = previous.process_command
_PROOF = previous._PROOF_FILE
_SNAPSHOT = native.snapshot


def ref_sha(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def verify_source_closure(root):
    value = _SOURCE(root)
    native.require(
        len(value) == 16 and value["tests/ssh_defense_transport_lab.py"] == TRANSPORT_SHA256,
        "Frozen sixteen-file source closure changed",
    )
    raw = native.owned_read(root / "tests/ssh_defense_binding_loss_lab.py", 262144)
    native.require(b"\r\n" not in raw, "Binding-loss source must be canonical LF")
    return value | {"tests/ssh_defense_binding_loss_lab.py": hashlib.sha256(raw).hexdigest()}


def validate_metadata(value, root=None):
    native.require(
        type(value) is dict
        and set(value)
        == {
            "binding_loss_profile",
            "binding_loss_profile_sha256",
            "binding_loss_ref",
            "source_sha256",
        }
        and value["binding_loss_profile"] == PROFILE
        and value["binding_loss_profile_sha256"] == PROFILE_SHA256
        and type(value["binding_loss_ref"]) is str
        and re.fullmatch("[0-9a-f]{32}", value["binding_loss_ref"])
        and value["source_sha256"]
        == verify_source_closure(Path(native.CODE) if root is None else root),
        "Binding-loss authority or source closure changed",
    )
    return value


def authority_metadata():
    return validate_metadata(base.read_json(Path(native.AUTHORITY) / PROFILE_FILE))


def stage(workspace, policy, expected):
    native.require(
        expected == session.profile_metadata("auto-ack"), "Binding loss requires fresh auto-ACK"
    )
    with patch.object(previous, "verify_source_closure", _SOURCE):
        result = _STAGE(workspace, policy, expected)
    code, _keys, _management, authority, *_ = result
    business.copy_source(Path(__file__).resolve(), code / "tests/ssh_defense_binding_loss_lab.py")
    source = verify_source_closure(code)
    # Finalize the unused fresh authority before any container or Root exists.
    transport = base.read_json(authority / previous.PROFILE_FILE)
    native.require(
        transport["source_sha256"] == _SOURCE(code), "Fresh sixteen-file authority changed"
    )
    transport["source_sha256"] = source
    pending = authority / "binding-loss-transport.pending"
    base.write_new(pending, transport)
    os.replace(pending, authority / previous.PROFILE_FILE)
    session.sync_directory(authority)
    value = {
        "binding_loss_profile": PROFILE,
        "binding_loss_profile_sha256": PROFILE_SHA256,
        "binding_loss_ref": native.secrets.token_hex(16),
        "source_sha256": source,
    }
    base.write_new(authority / PROFILE_FILE, value)
    return result


def _local_state():
    from deploy.defense import ssh_fixture as fixture
    from deploy.defense import ssh_requests as root

    with root._locked() as directory, fixture._locked() as protected:
        state = root._load(directory)  # Integrity check only; deliberately no _bound/rebind.
        binding = fixture._bound_listener(protected, "private")
        raw = root._read_ledger(directory)
    matches = root._boot() == state["boot_ref"] and binding == state["binding"]
    return state, binding, raw, matches


def internal_projection(*, stimulus=False):
    from deploy.defense import ssh_fixture_evidence as evidence
    from deploy.defense import ssh_requests as root

    state, binding, _raw, matches = _local_state()
    cursors = [
        (rid, record) for rid, record in state["records"].items() if record["kind"] == "cursor"
    ]
    native.require(len(cursors) <= 1, "Multiple original cursors are not supported")
    if stimulus:
        native.require(
            matches
            and len(cursors) == 1
            and cursors[0][1]["phase"] == "armed"
            and not state["usage"]
            and not any(r["kind"] == "action" for r in state["records"].values()),
            "Stimulus requires the original unchanged fresh binding",
        )
        root._cursor_live(cursors[0][1])
    failures, successes, ports = 0, 0, set()
    if cursors:
        mark = cursors[0][1]["payload"]["mark"]
        dev, ino, raw = evidence._read_log(PROTECTED_LOG)
        native.require(
            (dev, ino) == (mark["dev"], mark["ino"])
            and hashlib.sha256(raw[: mark["offset"]]).hexdigest() == mark["prefix_sha256"],
            "Original authentication log prefix changed",
        )
        for line in raw[mark["offset"] :].splitlines():
            event = evidence._AUTH.fullmatch(line.removesuffix(b"\r"))
            if event is not None and event["peer"] == b"198.18.241.3":
                failures += event["kind"] == b"Failed"
                successes += event["kind"] == b"Accepted"
                if event["kind"] == b"Failed":
                    port = int(event["port"])
                    native.require(1 <= port <= 65535, "Invalid original source port")
                    ports.add(port)
    value = {
        "scope_sha256": state["deployment"]["scope_sha256"],
        "policy_sha256": state["deployment"]["policy_sha256"],
        "boot_ref": state["boot_ref"],
        "binding_ref": state["binding_ref"],
        "mode": state["mode"],
        "binding_verified": False,
        "binding_matches": matches,
        "current_binding_sha256": native.digest(binding),
        "cursor_count": len(cursors),
        "cursor_request_id": cursors[0][0] if cursors else None,
        "failure_count": failures,
        "success_count": successes,
        "distinct_failure_ports": len(ports),
        "usage_count": len(state["usage"]),
        "apply_fault": None,
        "source_category": SOURCE_CATEGORY,
        "trusted_current_root_observation": False,
    }
    print(native.canonical(value).decode("ascii"))
    return 0


def independent_snapshot(network, target):
    # Frozen native snapshot reads raw ledger/counts, not Root._bound. Keep its
    # strict legacy seven-key validation, then label this as local negative data.
    value = _SNAPSHOT(network, target)
    projection = base.projection(network, target)
    return value | {
        "source_category": SOURCE_CATEGORY,
        "trusted_current_root_observation": False,
        "binding_matches": projection["binding_matches"],
        "current_binding_sha256": projection["current_binding_sha256"],
        "original_binding_sha256": projection["binding_ref"],
    }


def protected_identity(process):
    from deploy.defense import ssh_fixture as fixture

    native.require(
        process.poll() is None and process.args == list(ARGV), "The held protected child changed"
    )
    record = native.process_record(process.pid)
    native.require(record["ppid"] == os.getpid(), "Protected listener is not a held child")
    native.verify_program(record, "/usr/sbin/sshd")
    with fixture._locked() as directory:
        binding = fixture._bound_listener(directory, "private")
    native.require(
        binding[3] == process.pid and binding[4] == record["start"],
        "Protected PID file or listener changed",
    )
    return native.process_identity(record), binding


def protected_quiescent(process):
    identity, _binding = protected_identity(process)
    raw = (Path("/proc") / str(process.pid) / "task" / str(process.pid) / "children").read_bytes()
    native.require(len(raw) <= 4096 and not raw.strip(), "A protected SSH child is still in flight")
    return identity


class LogPrefix(TypedDict):
    identity: list[int]
    length: int
    sha256: str


def capture(protected, protocol, prefix: LogPrefix | None = None) -> dict[str, Any]:
    from deploy.defense import ssh_fixture_evidence as evidence

    native.require(
        protocol.starts == 1 and protocol.restart_count == 0 and protocol.current is not None,
        "Protocol transport must not be restarted in this experiment",
    )
    protocol_identity, protocol_inode = previous.listener_identity(protocol.current)
    protected_record, current = protected_identity(protected.current)
    state, binding, raw, matches = _local_state()
    native.require(binding == current, "Current protected binding changed during capture")
    actions = [(rid, r) for rid, r in state["records"].items() if r["kind"] == "action"]
    native.require(
        len(actions) == 1 and len(state["usage"]) == 1, "One original action is required"
    )
    rid, action = actions[0]
    payload = action["payload"]
    native.require(
        action["phase"] == "active"
        and state["usage"] == [rid]
        and payload["intent_bound"] is not None
        and payload["expiry_bound"] is not None
        and payload["apply_hash"] is not None,
        "Original completed intent is missing",
    )
    dev, ino, log = evidence._read_log(PROTECTED_LOG)
    if prefix is None:
        prefix = {
            "identity": [dev, ino],
            "length": len(log),
            "sha256": hashlib.sha256(log).hexdigest(),
        }
    native.require(
        [dev, ino] == prefix["identity"]
        and len(log) >= prefix["length"]
        and hashlib.sha256(log[: prefix["length"]]).hexdigest() == prefix["sha256"],
        "Restart changed or truncated the original authentication log",
    )
    public = {}
    for role in ("readonly", "observe", "control"):
        public["key_" + role] = previous._public_sha(
            Path(f"/home/opsark-defense-{role}/.ssh/authorized_keys")
        )
        public["wrapper_" + role] = previous._public_sha(
            Path(f"/usr/local/sbin/opsark-defense-{role}")
        )
    public["sudoers"] = previous._public_sha(Path("/etc/sudoers.d/opsark-defense-requests-lab"))
    authorities = {
        path.name: previous._public_sha(path) for path in Path(native.AUTHORITY).iterdir()
    }
    native.require(
        base.read_json(Path(native.AUTHORITY) / "deployment.json") == state["deployment"],
        "Root original grants differ from sealed authority",
    )
    fields = {
        "protocol_process_sha256": native.digest(protocol_identity),
        "protocol_listener_sha256": native.digest(protocol_inode),
        "netns_sha256": native.digest(binding[:2]),
        "protected_log_identity_sha256": native.digest([dev, ino]),
        "protected_log_prefix_sha256": prefix["sha256"],
        "public_pin_sha256": previous._public_sha(ROOT / "host.pub"),
        "key_file_identity_sha256": native.digest(previous._file_identity(ROOT / "host")),
        "protected_config_sha256": previous._public_sha(PROTECTED_CONFIG),
        "protocol_config_sha256": previous._public_sha(previous.CONFIG),
        "roles_policy_sha256": native.digest(public),
        "authority_sha256": native.digest(authorities),
        "root_ledger_sha256": hashlib.sha256(raw).hexdigest(),
        "root_grants_sha256": native.digest(state["deployment"]),
        "root_usage_sha256": native.digest(state["usage"]),
        "root_intents_sha256": native.digest(action),
        "root_binding_sha256": state["binding_ref"],
        "protected_process_sha256": native.digest(protected_record),
        "protected_listener_sha256": native.digest(binding[5]),
        "current_binding_sha256": native.digest(binding),
    }
    manifest = native.digest(payload["manifest"])
    return {
        "fields": fields,
        "prefix": prefix,
        "binding_matches": matches,
        "usage_count": 1,
        "intent_count": 1,
        "request_id_sha256": ref_sha(rid),
        "manifest_sha256": manifest,
        "identity_binding_sha256": native.digest(
            {
                "action_id": payload["action_id"],
                "manifest_sha256": manifest,
                "cursor_id": payload["cursor_id"],
            }
        ),
    }


class FixedProtected(previous.FixedTransport):
    """Use the frozen pidfd stop for one fixed 22422 Popen; no arbitrary argv."""

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
            and native.ENV == previous.ENV,
            "Protected start budget changed",
        )
        self.starts += 1
        self.current = native.subprocess.Popen(
            list(ARGV),
            stdin=native.subprocess.DEVNULL,
            stdout=native.subprocess.DEVNULL,
            stderr=native.subprocess.DEVNULL,
            env=dict(previous.ENV),
        )
        record = native.process_record(self.current.pid)
        native.require(
            record["ppid"] == os.getpid(), "Spawned protected child has a foreign parent"
        )
        native.verify_program(record, "/usr/sbin/sshd")
        self.identity = native.process_identity(record)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            native.require(self.current.poll() is None, "Protected listener failed to start")
            try:
                self.identity, _binding = protected_identity(self.current)
                return self.current
            except (FileNotFoundError, ValueError, native.LabError):
                time.sleep(0.05)
        raise native.LabError("The held protected listener did not become ready")

    def restart(self, request, metadata, counters, protocol=None):
        if protocol is None:
            raise native.LabError("An unchanged held protocol listener is required")
        native.require(
            self.restart_count == 0 and self.starts == 1 and self.current is not None,
            "Only one protected restart is permitted",
        )
        self.restart_count = 1
        previous.no_inflight(protocol.current)
        protected_quiescent(self.current)
        before = capture(self, protocol)
        native.require(
            before["binding_matches"] is True, "The original Root binding was already invalid"
        )
        old, identity, original = self.current, self.identity, dict(counters)
        if old is None or identity is None:
            raise native.LabError("Original protected process birth is unavailable")
        self.stop()
        native.require(old.poll() is not None, "Old protected child was not reaped")
        self.start()
        if self.current is None or self.identity is None:
            raise native.LabError("New protected process birth is unavailable")
        native.require(
            self.identity["pid"] != identity["pid"] and self.identity["start"] != identity["start"],
            "Protected listener did not have a new process birth",
        )
        previous.no_inflight(protocol.current)
        protected_quiescent(self.current)
        after = capture(self, protocol, before["prefix"])
        native.require(
            after["binding_matches"] is False
            and before["fields"]["current_binding_sha256"]
            == before["fields"]["root_binding_sha256"]
            and after["fields"]["current_binding_sha256"] != after["fields"]["root_binding_sha256"],
            "Restart did not retain and invalidate the original Root binding",
        )
        native.require(
            all(before["fields"][name] == after["fields"][name] for name in PRESERVED)
            and all(before["fields"][name] != after["fields"][name] for name in REPLACED)
            and all(
                before[name] == after[name]
                for name in ("request_id_sha256", "manifest_sha256", "identity_binding_sha256")
            )
            and counters == original,
            "Protected restart changed immutable Root authority",
        )
        return {
            "schema": "opsark-protected-listener-restart-proof/v1",
            "completed": True,
            "restart_count": 1,
            "binding_loss_profile": PROFILE,
            "binding_loss_profile_sha256": PROFILE_SHA256,
            "binding_loss_ref_sha256": ref_sha(metadata["binding_loss_ref"]),
            "command_sha256": request["command_sha256"],
            "request_id_sha256": before["request_id_sha256"],
            "manifest_sha256": before["manifest_sha256"],
            "identity_binding_sha256": before["identity_binding_sha256"],
            "old_protected_terminated": True,
            "new_protected_started": True,
            "protected_identity_changed": True,
            "protected_listening": True,
            "protocol_listener_preserved": True,
            "immutable_root_preserved": True,
            "protected_log_prefix_preserved": True,
            "binding_changed": True,
            "execution_continuation_supported": False,
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


def checked_request(value, metadata):
    native.require(
        type(value) is dict
        and set(value)
        == {"schema", "operation", "request_id", "fixture_id", "binding_loss_ref", "command_sha256"}
        and value["schema"] == "opsark-protected-listener-restart-command/v1"
        and value["operation"] == OPERATION
        and value["binding_loss_ref"] == metadata["binding_loss_ref"]
        and type(value["request_id"]) is str
        and re.fullmatch("[0-9a-f]{32}", value["request_id"])
        and type(value["fixture_id"]) is str
        and re.fullmatch("[0-9a-f]{16}", value["fixture_id"]),
        "Unapproved fixed protected restart request",
    )
    original = {
        "schema": "opsark-controller-command/v1",
        "request_id": value["request_id"],
        "operation": OPERATION,
        "fixture_id": value["fixture_id"],
    }
    native.require(
        value["command_sha256"] == native.digest(original), "Original protected command changed"
    )
    return value


def process_command(command, root, network, target, clients):
    native.require(
        command["operation"] != previous.OPERATION,
        "Protocol restart is forbidden in the negative profile",
    )
    if command["operation"] != OPERATION:
        return _PROCESS(command, root, network, target, clients)
    business.checked_command(command)
    native.require(command["fixture_id"] == network.fixture, "Protected restart fixture changed")
    metadata = validate_metadata(
        base.read_json(network.workspace / "authority" / PROFILE_FILE), network.workspace / "code"
    )
    once = root / (PREFIX + ".once.json")
    native.require(
        not once.exists() and not once.is_symlink(), "Protected restart was already claimed"
    )
    request = checked_request(
        {
            "schema": "opsark-protected-listener-restart-command/v1",
            "operation": OPERATION,
            "request_id": command["request_id"],
            "fixture_id": network.fixture,
            "binding_loss_ref": metadata["binding_loss_ref"],
            "command_sha256": native.digest(command),
        },
        metadata,
    )
    base.write_new(once, request)
    directory = network.workspace / "ready"
    base.write_new(directory / REQUEST, request)
    native.publish_socket_signal(directory / REQUEST_READY)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if native.socket_signal_ready(directory / RESULT_READY):
            result = base.read_json(directory / RESULT, 32768)
            native.require(
                result.get("schema") == "opsark-protected-listener-restart-result/v1"
                and result.get("completed") is True
                and result.get("command_sha256") == request["command_sha256"]
                and result.get("binding_loss_ref_sha256") == ref_sha(metadata["binding_loss_ref"]),
                "The one protected restart did not confirm",
            )
            native.require(
                type(result.get("proof")) is dict and result["proof"].get("completed") is True,
                "Physical protected restart proof is missing",
            )
            return result["proof"]
        time.sleep(0.05)
    raise native.LabError("Protected restart receipt unavailable; do not retry")


def service_request(protected, protocol, metadata, counters):
    if not native.socket_signal_ready(READY_ROOT / REQUEST_READY) or (READY_ROOT / CLAIM).exists():
        return
    request = checked_request(base.read_json(READY_ROOT / REQUEST), metadata)
    base.write_new(READY_ROOT / CLAIM, request)
    result = {
        "schema": "opsark-protected-listener-restart-result/v1",
        "completed": False,
        "binding_loss_ref_sha256": ref_sha(metadata["binding_loss_ref"]),
        "command_sha256": request["command_sha256"],
    }
    try:
        result.update(
            completed=True, proof=protected.restart(request, metadata, counters, protocol)
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        result.update(completed=False, reason_code="protected_restart_unconfirmed_no_retry")
    base.write_new(READY_ROOT / RESULT, result)
    native.publish_socket_signal(READY_ROOT / RESULT_READY)


def internal_target(image):
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
    native.require(config == PROTECTED_CONFIG, "Protected config path changed")
    business.diagnostic_step("prepare", "ok")
    business.install_collector(config)
    business.collector_traversal_preflight(image)
    business.diagnostic_step("root_roles_prepare")
    native.require(
        native.provision_roles(target, image) == previous.CONFIG, "Protocol config path changed"
    )
    counters["provision"] += 1
    business.diagnostic_step("root_roles_prepare", "ok")
    business.diagnostic_step("protected_sshd_start")
    with ExitStack() as cleanup:
        protected = FixedProtected()
        cleanup.callback(protected.stop)
        protected.start()
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
            "Native nft initialization failed",
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
        previous.LOG.touch(mode=0o600, exist_ok=False)
        business.diagnostic_step("root_roles_start")
        protocol = previous.FixedTransport()
        cleanup.callback(protocol.stop)
        protocol.start()
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
            if protocol.current is None or protected.current is None:
                raise native.LabError("A held listener is unavailable")
            if protocol.current.poll() is not None or protected.current.poll() is not None:
                break
            service_request(protected, protocol, metadata, counters)
            time.sleep(0.05)
    return 0


class BindingLossProof(previous.TransportProof):
    def write(self, raw):
        value = json.loads(raw, object_pairs_hook=native.strict_pairs)
        value.update(
            schema="opsark-binding-loss-controller-fixture-proof/v1",
            binding_loss_profile=PROFILE,
            binding_loss_profile_sha256=PROFILE_SHA256,
            execution_continuation_supported=False,
        )
        if self.metadata:
            value["binding_loss_ref_sha256"] = ref_sha(self.metadata["binding_loss_ref"])
        return self.output.write(native.canonical(value) + b"\n")


@contextmanager
def bound_profile():
    metadata = {}

    def stage_with_metadata(workspace, policy, expected):
        result = stage(workspace, policy, expected)
        metadata.update(base.read_json(workspace / "authority" / PROFILE_FILE))
        return result

    def ready(*args):
        value = _READY(*args)
        native.require(bool(metadata), "Binding-loss authority was not sealed")
        return value | {
            name: metadata[name]
            for name in ("binding_loss_profile", "binding_loss_profile_sha256", "binding_loss_ref")
        }

    def dispatch(name, image):
        authority_metadata()
        if name in {"projection", "stimulus_gate"}:
            return internal_projection(stimulus=name == "stimulus_gate")
        return _DISPATCH(name, image)

    @contextmanager
    def proof_file(root, path):
        with _PROOF(root, path) as output:
            yield BindingLossProof(output, metadata)

    with (
        patch.object(previous, "SELF", SELF),
        patch.object(previous, "OPERATIONS", OPERATIONS),
        patch.object(previous, "verify_source_closure", verify_source_closure),
        patch.object(previous, "stage_transport", stage_with_metadata),
        patch.object(previous, "process_command", process_command),
        patch.object(previous, "internal_target", internal_target),
        patch.object(previous, "_BUSINESS_READY", ready),
        patch.object(previous, "_INTERNAL_DISPATCH", dispatch),
        patch.object(previous, "_PROOF_FILE", proof_file),
        patch.object(native, "snapshot", independent_snapshot),
    ):
        yield


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["describe"]:
        print(
            native.canonical(
                {
                    "binding_loss_profile": PROFILE,
                    "binding_loss_profile_sha256": PROFILE_SHA256,
                    "profile": SPEC,
                    "session_profile": "auto-ack",
                    "execution_continuation_supported": False,
                    "checks": business.business_checks(),
                    "policy": business.expected_policy(),
                }
            ).decode("ascii")
        )
        return 0
    with bound_profile():
        return previous.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
