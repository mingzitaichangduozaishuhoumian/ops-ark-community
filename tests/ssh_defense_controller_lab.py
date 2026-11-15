#!/usr/bin/env python3
"""Hold a fresh private SSH fixture for the real controller, with bounded mailboxes.

Administrator laboratory only. The controller must perform every mode/arm/action
operation itself. Keys are synthetic, private, and referenced by path, never printed.
"""

import argparse
import hashlib
import os
import re
import secrets
import signal
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssh_defense_requests_lab as native  # noqa: E402 -- owned sibling for -I.
from ssh_defense_requests_lab import (  # noqa: E402 -- fixed bounded profile helpers.
    CAPS,
    LABEL,
    capabilities_match,
    require,
    trusted_directory,
)

SELF = "/fixture-code/tests/ssh_defense_controller_lab.py"
LIFETIME_SECONDS = 600
WORK_SECONDS = 480
CLEANUP_SECONDS = 120
FAULT_SCOPE = "controller_apply_only_exact_socket_interruption"
OPERATIONS = frozenset({"stimulate", "snapshot", "health", "stop"})
MAX_COMMANDS = 16
CORE_SHA256 = {
    "request_protocol.py": "ebf2884f2bfdbc2f74de3b11179a6024e56b1c77a60a9eeea1a5f58668422ac9",
    "ssh_requests.py": "51149482ab202bbde8bbef5c5ce5a980430db6a71603095b7f56c02884ffd0ee",
    "ssh_fixture.py": "632467a225d9b4d8ce115829bd0c479b035365ea32d10fa98569050a7403111c",
    "ssh_fixture_evidence.py": "6587b863d36368548271aecacf09a0dffdc07464ff69246d73897d15c0d83364",
    "ssh_fixture_nft.py": "7e78ca5727eac66aeae22f24d6f8a8fef361f9440bdc49b73567be229b9dcb36",
}


@contextmanager
def bound_self():
    """Only this standalone process uses the new fixed internal entrypoint."""
    previous = native.SELF
    native.SELF = SELF  # ty: ignore[invalid-assignment] -- scoped laboratory entrypoint.
    try:
        yield
    finally:
        native.SELF = previous


class ControllerNetwork(native.Network):
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


def write_new(path, value):
    native.owned_create(path, native.canonical(value) + b"\n")


def read_json(path, limit=8192):
    return native.decode(native.owned_read(path, limit), limit)


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
        "Invalid fixed controller laboratory command",
    )
    return value


def controller_control_wrapper():
    """Pass prepare through; lose only a completed active apply acknowledgement."""
    native.internal_modules()
    native._trace_ref, native._trace_sequence = secrets.token_hex(8), 0
    native._trace_order = time.monotonic_ns()
    native.diagnostic_step("wrapper_enter", "enter")
    require(native.fixture_case() == native.SOCKET_CASE, "Wrong controller fault fixture")
    from deploy.defense import request_protocol as wire

    raw = sys.stdin.buffer.read(4097)
    request = wire.parse(raw)
    native._trace_request_ref, native._trace_operation = request["request_id"], request["op"]
    result = native.run(
        "/usr/bin/python3",
        "-I",
        "-B",
        native.INSTALLED,
        "--control",
        input_bytes=raw,
        timeout=23,
        limit=4096,
    )
    if request["op"] == "apply" and result.returncode == 0 and not result.stderr:
        receipt = native.validate_reply(native.decode(result.stdout), request)
        if receipt["state"] == "active":
            stored = native.FAULT_ROOT / "controller-apply-request.json"
            if stored.exists():
                require(
                    native.owned_read(stored, 4096) == raw, "Original apply declaration changed"
                )
            else:
                native.owned_create(stored, raw)
            binding = {key: receipt[key] for key in ("action_id", "manifest_sha256", "cursor_id")}
            native.request_socket_interruption(request, binding, receipt["remaining_ms"])
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode if result.returncode >= 0 else 1


def internal_projection(*, stimulus=False):
    native.internal_modules()
    from deploy.defense import ssh_fixture as fixture
    from deploy.defense import ssh_fixture_evidence as evidence
    from deploy.defense import ssh_requests as root

    with root._locked() as directory, fixture._locked() as target:
        state = root._load(directory)
        root._bound(state, target)
        cursors = [(rid, r) for rid, r in state["records"].items() if r["kind"] == "cursor"]
        require(len(cursors) <= 1, "The controller fixture has multiple cursors")
        if stimulus:
            require(
                len(cursors) == 1
                and cursors[0][1]["phase"] == "armed"
                and all(r["kind"] != "action" for r in state["records"].values())
                and not state["usage"],
                "Only one fresh controller-armed cursor may receive the fixed stimulus",
            )
            root._cursor_live(cursors[0][1])
        failures, successes, ports = 0, 0, set()
        if cursors:
            mark = cursors[0][1]["payload"]["mark"]
            dev, inode, raw = evidence._read_log(Path("/run/opsark-ssh-defense/sshd.log"))
            require(
                (dev, inode) == (mark["dev"], mark["ino"])
                and hashlib.sha256(raw[: mark["offset"]]).hexdigest() == mark["prefix_sha256"],
                "The controller authentication prefix changed",
            )
            for line in raw[mark["offset"] :].splitlines():
                event = evidence._AUTH.fullmatch(line.removesuffix(b"\r"))
                if event is not None and event["peer"] == b"198.18.241.3":
                    failures += event["kind"] == b"Failed"
                    successes += event["kind"] == b"Accepted"
                    if event["kind"] == b"Failed":
                        port = int(event["port"])
                        require(1 <= port <= 65535, "Invalid authentication source port")
                        ports.add(port)
        projected = {
            "scope_sha256": state["deployment"]["scope_sha256"],
            "policy_sha256": state["deployment"]["policy_sha256"],
            "boot_ref": state["boot_ref"],
            "binding_ref": state["binding_ref"],
            "mode": state["mode"],
            "binding_verified": True,
            "cursor_count": len(cursors),
            "cursor_request_id": cursors[0][0] if cursors else None,
            "failure_count": failures,
            "success_count": successes,
            "distinct_failure_ports": len(ports),
            "usage_count": len(state["usage"]),
        }
    request_path = native.FAULT_ROOT / "controller-apply-request.json"
    if request_path.exists():
        from deploy.defense import request_protocol as wire

        request = wire.parse(native.owned_read(request_path, 4096))
        require(request["op"] == "apply", "Unexpected controller fault request")
        proof = native.socket_fault_proof(request)
        proof["fault_scope"] = FAULT_SCOPE
        proof["request_sha256"] = hashlib.sha256(native.canonical(request) + b"\n").hexdigest()
        require(
            not native.socket_paths("prepare")["json"].exists(),
            "Prepare acknowledgement was unexpectedly interrupted",
        )
        projected["apply_fault"] = proof
    else:
        projected["apply_fault"] = None
    print(native.canonical(projected).decode("ascii"))
    return 0


def projection(network, target, *, stimulus=False):
    result = network.execute(
        target,
        "/usr/bin/python3",
        "-I",
        "-B",
        SELF,
        "--internal-stimulus-gate" if stimulus else "--internal-projection",
        "--image",
        network.image,
        "--confirm-isolated",
    )
    require(result.returncode == 0 and not result.stderr, "Controller projection was unavailable")
    return native.decode(result.stdout, 8192)


def process_command(command, root, network, target, clients):
    operation = checked_command(command)["operation"]
    require(command["fixture_id"] == network.fixture, "Controller command scope changed")
    if operation == "stimulate":
        marker = root / "stimulus.once.json"
        require(not marker.exists(), "The fixed stimulus has already been claimed")
        baseline = projection(network, target, stimulus=True)
        write_new(
            marker, {"request_id": command["request_id"], "command_sha256": native.digest(command)}
        )
        for _ in range(5):
            native.login(network, clients["candidate"], valid=False)
        observed = native.snapshot(network, target)
        after = projection(network, target, stimulus=True)
        require(
            observed["candidate_failure_events"] == 5
            and observed["candidate_success_events"] == 0
            and observed["usage_count"] == 0
            and observed["intents"] == 0,
            "Fixed native authentication stimulus did not match",
        )
        require(
            after["cursor_request_id"] == baseline["cursor_request_id"]
            and after["failure_count"] == 5
            and after["success_count"] == 0
            and after["distinct_failure_ports"] == 5,
            "The native stimulus changed cursor or distinct port evidence",
        )
        return {
            "stimulus_count": 1,
            "cursor_request_id": after["cursor_request_id"],
            "failure_count": 5,
            "distinct_failure_ports": 5,
            "ledger": observed,
        }
    if operation == "snapshot":
        return {
            "projection": projection(network, target),
            "ledger": native.snapshot(network, target),
        }
    if operation == "health":
        native.login(network, clients["management"])
        native.login(network, clients["alternate"])
        native.http_health(network, clients["candidate"])
        return {"management_ssh": True, "contrast_ssh": True, "same_source_http": True}
    return {"stop_requested": True}


def ready_value(root, workspace, network, target, clients, pin, deployment, grants, metadata):
    return {
        "schema": "opsark-controller-fixture-ready/v1",
        "stage_root": str(root),
        "workspace": str(workspace),
        "image_id": network.image,
        "fixture_id": network.fixture,
        "network_id": network.identity,
        "container_ids": {"target": target, **clients},
        "fault_scope": FAULT_SCOPE,
        "root_scope_sha256": deployment["scope_sha256"],
        "root_policy_sha256": deployment["policy_sha256"],
        "boot_ref": metadata["boot_ref"],
        "binding_ref": metadata["binding_ref"],
        "host_public_key": pin,
        "observation_grant_ref": grants["observation"],
        "controller_grant_ref": grants["controller"],
        "root_grant_ref": grants["root"],
        "grant_not_before": deployment["defense_grants"][0]["not_before"],
        "grant_deadline_at": deployment["defense_grants"][0]["deadline_at"],
        "observation_not_before": deployment["observation_grant"]["not_before"],
        "observation_deadline_at": deployment["observation_grant"]["deadline_at"],
        "role_key_files": {
            role: str(workspace / "management" / role)
            for role in ("readonly", "observe", "control")
        },
        "work_budget_seconds": WORK_SECONDS,
        "container_timeout_seconds": LIFETIME_SECONDS,
        "root_cursor_seconds": 120,
        "action_ttl_ms": 60000,
    }


def process_identity(pid):
    value = (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()
    return {"pid": pid, "start_ticks": int(value[19]), "state": value[0]}


def supervisor_alive(record):
    try:
        actual = process_identity(record["pid"])
        return actual["start_ticks"] == record["start_ticks"] and actual["state"] not in {"Z", "X"}
    except FileNotFoundError:
        return False


def live_resources(ready):
    """Inspect owned IDs; a ready file alone is not evidence of live resources."""
    require(
        re.fullmatch("[0-9a-f]{16}", ready["fixture_id"])
        and re.fullmatch("sha256:[0-9a-f]{64}", ready["image_id"])
        and re.fullmatch("[0-9a-f]{64}", ready["network_id"])
        and set(ready["container_ids"]) == {"target", *native.ADDRESSES},
        "Invalid original resource identity",
    )
    workspace = Path(ready["workspace"])
    require(workspace.parent == Path(ready["stage_root"]), "The workspace left its private stage")
    trusted_directory(workspace, private=True)
    base = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", str(workspace))

    def inspect(kind, identity):
        require(re.fullmatch("[0-9a-f]{64}", identity), "A full resource identity is required")
        result = native.run(*base, kind, "inspect", identity, timeout=5, limit=65536)
        require(result.returncode == 0 and not result.stderr, "Original resource is unavailable")
        value = native.json.loads(result.stdout)
        require(
            type(value) is list and len(value) == 1 and value[0]["Id"] == identity,
            "Resource identity changed",
        )
        return value[0]

    network = inspect("network", ready["network_id"])
    name = "opsark-requests-" + ready["fixture_id"]
    require(
        network["Name"] == name
        and network["Driver"] == "bridge"
        and network["Internal"]
        and not network["EnableIPv6"]
        and native.ipam_config_matches(network["IPAM"]["Config"])
        and network["Labels"] == {LABEL: ready["fixture_id"]}
        and set(network.get("Containers", {})) == set(ready["container_ids"].values()),
        "Original private network changed",
    )
    for role, identity in ready["container_ids"].items():
        container = inspect("container", identity)
        config, host = container["Config"], container["HostConfig"]
        address = native.TARGET if role == "target" else native.ADDRESSES[role]
        networks = container["NetworkSettings"]["Networks"]
        arguments = (
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                SELF,
                "--internal-target",
                "--image",
                ready["image_id"],
                "--confirm-isolated",
            ]
            if role == "target"
            else ["/bin/sleep", "infinity"]
        )
        require(
            container["State"]["Running"]
            and container["Image"] == ready["image_id"]
            and config["Labels"].get(LABEL) == ready["fixture_id"]
            and config["Entrypoint"] == ["/usr/bin/timeout"]
            and config["Cmd"] == ["-k", "2s", "600s", *arguments]
            and config["User"] == "0:0"
            and host["NetworkMode"] == name
            and set(networks) == {name}
            and networks[name]["NetworkID"] == ready["network_id"]
            and networks[name]["IPAddress"] == address
            and not host["Privileged"]
            and host["CapDrop"] == ["ALL"]
            and capabilities_match(host["CapAdd"], CAPS if role == "target" else ())
            and host["ReadonlyRootfs"] == (role != "target")
            and (host["SecurityOpt"] or [])
            == ([] if role == "target" else ["no-new-privileges:true"])
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
            and host["RestartPolicy"]["Name"] == "no",
            "An original bounded fixture container changed",
        )
    return True


def serve(root, image, proof):
    native.require_root(root)
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
        "schema": "opsark-controller-fixture-proof/v1",
        "completed": False,
        "fault_scope": FAULT_SCOPE,
        "root_source_sha256": CORE_SHA256,
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
                    native.stage(workspace, native.SOCKET_CASE)
                )
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
                network = ControllerNetwork(workspace, image, cleanup)
                target = network.start(
                    "target",
                    native.TARGET,
                    [
                        (code, native.CODE, True),
                        (authority, native.AUTHORITY, True),
                        (readiness, "/fixture-ready", False),
                        (state, "/var/lib", False),
                    ],
                    target=True,
                )
                pin = native.ready(network, target, readiness / "ready.json")
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
                        role, address, [(code, native.CODE, True), (selected, native.CLIENT, True)]
                    )
                    native.login(network, clients[role])
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
                write_new(
                    root / "controller-ready.json",
                    ready_value(
                        root, workspace, network, target, clients, pin, deployment, grants, metadata
                    ),
                )
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
                        claim = {"command_sha256": native.digest(command), "request_id": request_id}
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
        finally:
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


def status(root):
    native.require_root(root)
    live = supervisor_alive(read_json(root / "supervisor.json"))
    path = root / "controller-ready.json"
    ready = read_json(path) if live and path.exists() else None
    if ready is not None:
        live_resources(ready)
    return {
        "supervisor_live": live,
        "ready": live and path.exists(),
        "fixture": ready,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("serve", "status", *sorted(OPERATIONS)))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--proof", type=Path)
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
    ):
        group.add_argument("--internal-" + name, action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        require(
            args.confirm_isolated and re.fullmatch("sha256:[0-9a-f]{64}", args.image),
            "Explicit isolated mode and pinned image are required",
        )
        with bound_self():
            dispatch = {
                "target": lambda: native.internal_target(args.image),
                "control_wrapper": controller_control_wrapper,
                "ss_close": native.internal_ss_close,
                "snapshot": native.internal_snapshot,
                "fault_proof": native.internal_fault_proof,
                "projection": internal_projection,
                "stimulus_gate": lambda: internal_projection(stimulus=True),
            }
            for name, function in dispatch.items():
                if getattr(args, "internal_" + name):
                    require(args.action is None, "Internal entrypoints accept no action")
                    return function()
            require(args.root is not None, "A fixed private stage root is required")
            if args.action == "serve":
                require(args.proof is not None, "An original proof path is required")
                signal.signal(signal.SIGTERM, native.interrupted)
                signal.signal(signal.SIGINT, native.interrupted)
                return serve(args.root, args.image, args.proof)
            value = (
                status(args.root)
                if args.action == "status"
                else command(args.root, args.action, args.request_id)
            )
            print(native.canonical(value).decode("ascii"))
            return 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        print("The isolated controller fixture could not be confirmed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
