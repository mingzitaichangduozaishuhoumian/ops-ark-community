#!/usr/bin/env python3
"""Exercise temporary SSH containment over an owned internal Docker network."""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, closing
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = Path("/var/lib/opsark-release-lab")
SUBNET = "198.18.241.0/28"
TARGET = "198.18.241.2"
SOURCES = {"candidate": "198.18.241.3", "management": "198.18.241.4", "alternate": "198.18.241.5"}
LABEL = "io.opsark.ssh-defense-private"
SSH_PORT = "22422"
READONLY_PORT = "22423"
SCRIPT = "/fixture-code/deploy/defense/ssh_fixture.py"
READONLY_SCRIPT = "/usr/local/libexec/opsark-defense/deploy/defense/ssh_fixture.py"
AUTHORITY = "/fixture-authority"
KEYS = "/fixture-client"
CONTROLLER_HOST = "ssh-defense-private-lab"
CONTROLLER_IP = "198.18.241.6"
CONTROLLER_PYTHON = "/app/.venv/bin/python"
CONTROLLER_PATH = f"/api/hosts/{CONTROLLER_HOST}/ssh-defense/actions"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

_HTTP_PROBE = """import http.client
c = http.client.HTTPConnection('198.18.241.2', 22480, timeout=3)
try:
    c.request('GET', '/health')
    print(c.getresponse().status)
finally:
    c.close()
"""
_RELAY_PROBE = """import json
import socket
import sys
from pathlib import Path

op, identity = sys.argv[1:]
nonce = Path('/fixture-authority/nonce').read_text('ascii').strip()
frame = json.dumps({'op': op, 'id': identity, 'nonce': nonce}).encode('ascii') + b'\\n'
with socket.create_connection(('198.18.241.2', 22424), timeout=5) as peer:
    peer.sendall(frame)
    data = bytearray()
    try:
        while len(data) < 1024 and not data.endswith(b'\\n'):
            chunk = peer.recv(1024 - len(data))
            if not chunk:
                break
            data.extend(chunk)
    except ConnectionResetError:
        if op == 'apply_drop' and not data:
            print('reset-before-response')
            raise SystemExit(0)
        raise SystemExit(1) from None
if op == 'status' and data.endswith(b'\\n') and len(data) < 1024:
    print(data.decode('ascii').strip())
else:
    raise SystemExit(1)
"""
_CONTROLLER_PROBE = """import http.client
import json
import sys
from pathlib import Path

method, path, payload, authenticated = sys.argv[1:]
headers = {'Content-Type': 'application/json'}
if authenticated == 'yes':
    headers['Authorization'] = 'Bearer ' + Path('/fixture-data/access-token').read_text().strip()
c = http.client.HTTPConnection('127.0.0.1', 8010, timeout=8)
try:
    c.request(method, path, payload or None, headers)
    reply = c.getresponse()
    body = reply.read(4097)
    if len(body) > 4096:
        raise SystemExit(1)
    print(json.dumps([reply.status, json.loads(body)]))
finally:
    c.close()
"""
_STOP_READONLY_SSHD = """import os
import re
import select
import signal
import socket
import stat
from pathlib import Path

pid_path = Path('/run/opsark-ssh-defense-status/sshd.pid')
with os.fdopen(os.open(pid_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
    info = os.fstat(f.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022):
        raise SystemExit(1)
    raw = f.read(17)
if re.fullmatch(rb'[1-9][0-9]{0,8}\\n', raw) is None:
    raise SystemExit(1)
pid = int(raw)
process = Path('/proc') / str(pid)
endpoint = socket.inet_aton('198.18.241.2')[::-1].hex().upper() + f':{22423:04X}'
fd = os.pidfd_open(pid)
try:
    rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    listeners = [row[9] for row in rows if row[1] == endpoint and row[3] == '0A']
    if (len(listeners) != 1 or process.stat().st_uid != 0
            or (process / 'exe').resolve(strict=True) != Path('/usr/sbin/sshd').resolve(strict=True)
            or not os.path.samestat((process / 'ns/net').stat(), Path('/proc/self/ns/net').stat())
            or f'socket:[{listeners[0]}]' not in {
                os.readlink(entry) for entry in (process / 'fd').iterdir() if entry.is_symlink()
            }):
        raise SystemExit(1)
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    if not poll.poll(3000):
        raise SystemExit(1)
finally:
    os.close(fd)
"""
_READONLY_SSHD = f"""AddressFamily inet
ListenAddress {TARGET}:{READONLY_PORT}
PidFile /run/opsark-ssh-defense-status/sshd.pid
HostKey /run/opsark-ssh-defense-status/host
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers opsark-readonly
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM yes
DisableForwarding yes
PermitTTY no
PermitUserRC no
LogLevel ERROR
"""
_DEFENSE_FILES = ("ssh_fixture.py", "ssh_fixture_evidence.py", "ssh_fixture_nft.py")
_GUARD_FILES = ("guard.py", "ssh_entry.py", "install.py", "http_readiness.py")


def require(condition: object, error: str) -> None:
    if not condition:
        raise RuntimeError(error)


def require_root(root: Path) -> None:
    require(
        sys.platform == "linux"
        and os.geteuid() == 0
        and root != LAB_ROOT
        and root.is_absolute()
        and root.is_relative_to(LAB_ROOT)
        and root.resolve(strict=True) == root,
        "A private fixture laboratory is required",
    )
    for path in (root, *root.parents):
        info = path.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "The fixture laboratory path is not trusted",
        )
    require(not root.stat().st_mode & 0o077, "The fixture laboratory must be private")


def run(*argv: str, timeout: float = 15) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- fixed local tools and scoped fixture operands.
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        env=ENV,
        check=False,
    )


def mount(path: Path, target: str) -> tuple[str, str]:
    return "--mount", f"type=bind,src={path},dst={target},readonly"


def stage(workspace: Path, *, controller: bool = False) -> tuple[Path, Path, Path]:
    code, keys, authority = (workspace / name for name in ("code", "client", "authority"))
    for directory in (code, keys, authority):
        directory.mkdir(mode=0o700)
    files = (
        *(f"deploy/defense/{name}" for name in _DEFENSE_FILES),
        "tests/ssh_defense_lab.py",
        "tests/ssh_defense_private_target.py",
        *(f"deploy/readonly/{name}" for name in _GUARD_FILES if controller),
    )
    for relative in files:
        target = code / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
        target.chmod(0o600)
    for name in ("valid", "invalid"):
        result = run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keys / name))
        require(result.returncode == 0, "Synthetic SSH key generation failed")
    shutil.copyfile(keys / "valid.pub", authority / "client.pub")
    (authority / "client.pub").chmod(0o600)
    (authority / "nonce").write_text(secrets.token_hex(16) + "\n", encoding="ascii")
    (authority / "nonce").chmod(0o600)
    return code, keys, authority


class Network:
    def __init__(self, workspace: Path, image: str, cleanup: ExitStack) -> None:
        self.image = image
        self.cleanup = cleanup
        self.fixture = secrets.token_hex(8)
        self.name = f"opsark-ssh-private-{self.fixture}"
        self.base = (
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(workspace),
        )
        self.require_image(image)
        self.identity = self.identifier(
            self.command(
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--subnet",
                SUBNET,
                "--label",
                f"{LABEL}={self.fixture}",
                self.name,
            )
        )
        self.cleanup.callback(self.remove, "network", self.identity)
        observed = (
            self.command(
                "network",
                "inspect",
                "--format",
                "{{.Id}} {{.Driver}} {{.Internal}} {{.EnableIPv6}} "
                "{{(index .IPAM.Config 0).Subnet}} "
                f'{{{{index .Labels "{LABEL}"}}}}',
                self.identity,
            )
            .decode("ascii")
            .split()
        )
        require(
            observed == [self.identity, "bridge", "true", "false", SUBNET, self.fixture],
            "The fixture bridge was not internal and exactly scoped",
        )

    @staticmethod
    def identifier(output: bytes) -> str:
        value = output.decode("ascii")
        require(re.fullmatch(r"[0-9a-f]{64}", value), "Docker did not return an exact fixture ID")
        return value

    def command(self, *args: str) -> bytes:
        result = run(*self.base, *args)
        operation = args[0]
        if operation in {"image", "network", "container"} and args[1] in {
            "inspect",
            "create",
            "rm",
        }:
            operation += " " + args[1]
        require(
            result.returncode == 0 and len(result.stdout) <= 4096,
            f"Fixture Docker {operation} failed",
        )
        return result.stdout.strip()

    def require_image(self, image: str) -> None:
        observed = (
            self.command(
                "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', image
            )
            .decode("ascii")
            .split()
        )
        require(observed in ([image, "null"], [image, "{}"]), "Fixture image was not pinned")

    def remove(self, kind: str, identity: str) -> None:
        if kind == "network":
            label = f'{{{{index .Labels "{LABEL}"}}}}'
        else:
            label = f'{{{{index .Config.Labels "{LABEL}"}}}}'
        observed = self.command(kind, "inspect", "--format", "{{.Id}} " + label, identity)
        require(
            observed.decode("ascii").split() == [identity, self.fixture],
            "The cleanup identity could not be verified",
        )
        self.command(kind, "rm", *(("-f",) if kind == "container" else ()), identity)

    def start(
        self,
        role: str,
        address: str,
        options: tuple[str, ...],
        *entry: str,
        image: str | None = None,
        allow_setuid: bool = False,
    ) -> str:
        selected = image or self.image
        privileges = () if allow_setuid else ("--security-opt", "no-new-privileges:true")
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
                *privileges,
                "--no-healthcheck",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                *options,
                "--entrypoint",
                entry[0],
                selected,
                *entry[1:],
            )
        )
        self.cleanup.callback(self.remove, "container", identity)
        self.command("start", identity)
        observed = (
            self.command(
                "container",
                "inspect",
                "--format",
                "{{.Id}} {{.Image}} {{json .HostConfig.PortBindings}} "
                f'{{{{(index .NetworkSettings.Networks "{self.name}").IPAddress}}}} '
                "{{len .NetworkSettings.Networks}}",
                identity,
            )
            .decode("ascii")
            .split()
        )
        require(
            observed in ([identity, selected, ports, address, "1"] for ports in ("{}", "null")),
            "Fixture container had an unexpected network or published port",
        )
        return identity

    def execute(self, identity: str, *args: str) -> subprocess.CompletedProcess[bytes]:
        return run(*self.base, "exec", identity, *args)


def ready(network: Network, target: str, marker: Path) -> str:
    for _ in range(60):
        if marker.exists():
            info = marker.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and 0 < info.st_size <= 256,
                "The fixture readiness marker is not private",
            )
            payload = json.loads(marker.read_bytes())
            key = payload.get("host_public_key", "")
            require(
                set(payload) == {"status", "host_public_key"}
                and payload["status"] == "ready"
                and isinstance(key, str)
                and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", key),
                "The target did not publish a valid synthetic host pin",
            )
            return key
        require(
            network.command("container", "inspect", "--format", "{{.State.Running}}", target)
            == b"true",
            "The private target stopped during startup",
        )
        time.sleep(0.1)
    raise RuntimeError("The target did not become ready")


def ssh(network: Network, client: str, *, valid: bool = True, expected: str = "ok") -> None:
    key = "valid" if valid else "invalid"
    result = network.execute(
        client,
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-oBatchMode=yes",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oGlobalKnownHostsFile=/dev/null",
        f"-oUserKnownHostsFile={KEYS}/known_hosts",
        "-oStrictHostKeyChecking=yes",
        "-oUpdateHostKeys=no",
        "-oPreferredAuthentications=publickey",
        "-oConnectionAttempts=1",
        "-oConnectTimeout=1",
        "-oLogLevel=ERROR",
        "-i",
        f"{KEYS}/{key}",
        "-p",
        SSH_PORT,
        f"opsark-ssh-lab@{TARGET}",
        "/usr/bin/true",
    )
    if expected == "ok":
        require(result.returncode == 0 and not result.stdout, "Pinned fixture SSH did not pass")
    else:
        marker = {"denied": b"Permission denied (publickey)", "blocked": b"Connection timed out"}
        require(
            result.returncode == 255 and marker[expected] in result.stderr and not result.stdout,
            "Fixture SSH did not produce the expected authentication or TCP result",
        )


def executor(network: Network, target: str, *args: str, refused: bool = False) -> dict:
    result = network.execute(
        target, "/usr/bin/python3", "-I", "-B", SCRIPT, "--profile", "private", *args
    )
    if refused:
        require(result.returncode == 1 and not result.stdout, "Fixture executor did not refuse")
        return {}
    require(
        result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 1024,
        "Fixture executor did not return a bounded receipt",
    )
    value = json.loads(result.stdout)
    require(isinstance(value, dict), "Fixture executor did not return a receipt object")
    return value


def grant(network: Network, target: str, source: str) -> str:
    payload = executor(network, target, "grant", "--source", source, "--confirm")
    identity = payload.get("grant_id", "")
    require(
        set(payload) == {"grant_id", "status"}
        and payload["status"] == "ready"
        and isinstance(identity, str)
        and re.fullmatch(r"[0-9a-f]{32}", identity),
        "Invalid private fixture grant",
    )
    return identity


def relay(network: Network, management: str, operation: str, identity: str) -> dict:
    result = network.execute(
        management, "/usr/bin/python3", "-I", "-B", "-c", _RELAY_PROBE, operation, identity
    )
    require(
        result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 1024,
        "The TCP relay did not produce the expected bounded result",
    )
    if operation == "apply_drop":
        require(
            result.stdout == b"reset-before-response\n",
            "No TCP reset before the reply was observed",
        )
        return {}
    return json.loads(result.stdout)


def receipt(payload: dict, identity: str, status: str) -> int:
    require(
        isinstance(payload, dict)
        and set(payload) == {"action_id", "status", "remaining_ms"}
        and payload["action_id"] == identity
        and payload["status"] == status,
        "The original action identity or status did not match",
    )
    remaining = payload["remaining_ms"]
    if status == "active":
        require(type(remaining) is int and 0 < remaining <= 60_000, "Kernel TTL outside the bound")
        return remaining
    require(remaining is None, "Finished receipt unexpectedly retains a TTL")
    return 0


def healthy_http(network: Network, candidate: str) -> None:
    result = network.execute(candidate, "/usr/bin/python3", "-I", "-B", "-c", _HTTP_PROBE)
    require(result.returncode == 0 and result.stdout == b"204\n", "Candidate HTTP was affected")


def configure_readonly(network: Network, target: str, authority: Path, identifier: str) -> str:
    def execute(*args: str) -> bytes:
        result = network.execute(target, *args)
        require(
            result.returncode == 0 and len(result.stdout) <= 4096,
            f"Readonly fixture provisioning failed ({Path(args[0]).name})",
        )
        return result.stdout

    argv = [
        "timeout",
        "-k",
        "1s",
        "5s",
        "/usr/bin/python3",
        "-I",
        "-B",
        READONLY_SCRIPT,
        "--profile",
        "private",
        "status-readonly",
        "--action-id",
        identifier,
    ]
    policy = {"schema_version": 1, "commands": {"LC_ALL=C " + " ".join(argv): argv}}
    (authority / "readonly-policy.json").write_text(json.dumps(policy), encoding="ascii")
    (authority / "readonly-policy.json").chmod(0o600)
    (authority / "sshd-readonly.conf").write_text(_READONLY_SSHD, encoding="ascii")
    (authority / "sshd-readonly.conf").chmod(0o600)
    installed = str(Path(READONLY_SCRIPT).parent)
    execute("/usr/bin/install", "-d", "-m", "0755", installed)
    for name in _DEFENSE_FILES:
        execute(
            "/usr/bin/install",
            "-m",
            "0644",
            f"/fixture-code/deploy/defense/{name}",
            f"{installed}/{name}",
        )
    execute(
        "/usr/bin/python3",
        "-I",
        "-B",
        "/fixture-code/deploy/readonly/install.py",
        "--policy",
        f"{AUTHORITY}/readonly-policy.json",
        "--public-key",
        f"{AUTHORITY}/collector.pub",
    )
    status = "/run/opsark-ssh-defense-status"
    execute("/usr/bin/install", "-d", "-m", "0700", status)
    execute("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{status}/host")
    config = f"{AUTHORITY}/sshd-readonly.conf"
    execute("/usr/sbin/sshd", "-t", "-f", config)
    execute("/usr/sbin/sshd", "-f", config, "-E", f"{status}/sshd.log")
    pin = " ".join(execute("/usr/bin/cat", f"{status}/host.pub").decode("ascii").split()[:2])
    require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", pin), "Invalid readonly host pin")
    return pin


def controller_response(
    network: Network,
    controller: str,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    authenticated: bool = True,
) -> tuple[int, object]:
    result = network.execute(
        controller,
        CONTROLLER_PYTHON,
        "-I",
        "-B",
        "-c",
        _CONTROLLER_PROBE,
        method,
        path,
        "" if payload is None else json.dumps(payload),
        "yes" if authenticated else "no",
    )
    if result.returncode != 0 or not 0 < len(result.stdout) <= 8192:
        raise ConnectionError("The isolated controller API was unavailable")
    code, body = json.loads(result.stdout)
    require(type(code) is int, "Invalid controller API response")
    return code, body


def controller_request(
    network: Network,
    controller: str,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    authenticated: bool = True,
) -> tuple[int, dict]:
    status, result = controller_response(
        network, controller, method, path, payload, authenticated=authenticated
    )
    if not isinstance(result, dict):
        raise RuntimeError("Invalid controller API object")
    return status, result


def await_controller(network: Network, controller: str) -> None:
    for _ in range(40):
        try:
            status, _ = controller_request(
                network, controller, "GET", "/api/status", authenticated=False
            )
        except ConnectionError:
            time.sleep(0.1)
            continue
        require(status == 200, "Controller startup response was invalid")
        return
    raise RuntimeError("The isolated controller did not become ready")


def start_controller(
    network: Network,
    target: str,
    authority: Path,
    workspace: Path,
    image: str,
    identifier: str,
    *,
    baked: bool = False,
) -> tuple[str, Path]:
    network.require_image(image)
    credential = workspace / "controller-credentials"
    data = workspace / "controller-data"
    for directory in (credential, data):
        directory.mkdir(mode=0o700)
    result = run(
        "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(credential / "collector")
    )
    require(result.returncode == 0, "Synthetic readonly key generation failed")
    shutil.copyfile(credential / "collector.pub", authority / "collector.pub")
    (authority / "collector.pub").chmod(0o600)
    pin = configure_readonly(network, target, authority, identifier)
    known = credential / "known_hosts"
    known.write_text(f"[{TARGET}]:{READONLY_PORT} {pin}\n", encoding="ascii")
    known.chmod(0o600)
    inventory = credential / "inventory.toml"
    inventory.write_text(
        '[credentials.fixture]\nkey_file = "collector"\nknown_hosts_file = "known_hosts"\n'
        f'[[hosts]]\nid = "{CONTROLLER_HOST}"\naddress = "{TARGET}"\nport = {READONLY_PORT}\n'
        'username = "opsark-readonly"\ncredential = "fixture"\nsite_domain = "defense.invalid"\n'
        f'ssh_defense_action_ids = ["{identifier}"]\n',
        encoding="ascii",
    )
    inventory.chmod(0o600)
    mounts = ()
    appdir = "/app/src"
    if not baked:
        require(all((ROOT / name).is_dir() for name in ("src", "web")), "Missing controller source")
        mounts = (
            *mount(ROOT / "src", "/fixture-app/src"),
            *mount(ROOT / "web", "/fixture-app/web"),
        )
        appdir = "/fixture-app/src"
    container = network.start(
        "controller",
        CONTROLLER_IP,
        (
            "--read-only",
            "--cap-drop",
            "ALL",
            "--log-driver",
            "none",
            *mounts,
            *mount(credential, "/fixture-credentials"),
            "--mount",
            f"type=bind,src={data},dst=/fixture-data",
            "--env",
            "OPSARK_DATA_DIR=/fixture-data",
            "--env",
            "OPSARK_INVENTORY=/fixture-credentials/inventory.toml",
            "--env",
            "OPSARK_TOKEN=",
            "--env",
            "OPSARK_OBSERVE_ENABLED=false",
            "--env",
            "OPSARK_VULNERABILITY_SCAN_ENABLED=false",
        ),
        CONTROLLER_PYTHON,
        "-I",
        "-B",
        "-m",
        "uvicorn",
        "opsark.main:app",
        "--app-dir",
        appdir,
        "--host",
        "127.0.0.1",
        "--port",
        "8010",
        "--no-access-log",
        "--log-level",
        "critical",
        image=image,
    )
    await_controller(network, container)
    return container, known


def controller_history(network: Network, controller: str, identifier: str) -> dict | None:
    code, result = controller_request(network, controller, "GET", CONTROLLER_PATH)
    require(
        code == 200
        and set(result) == {"host_id", "actions"}
        and result["host_id"] == CONTROLLER_HOST
        and len(result["actions"]) == 1,
        "The controller did not return the one registered action",
    )
    row = result["actions"][0]
    require(
        set(row) == {"action_id", "last_observed"} and row["action_id"] == identifier,
        "The controller returned a different defense action",
    )
    return row["last_observed"]


def controller_status(
    network: Network,
    controller: str,
    identifier: str,
    expected: str,
) -> tuple[int, dict]:
    path = f"{CONTROLLER_PATH}/{identifier}/status"
    code, result = controller_request(network, controller, "POST", path, {})
    require(
        code == 200
        and set(result)
        == {"host_id", "action_id", "status", "remaining_ms", "checked_at", "last_observed"}
        and result["host_id"] == CONTROLLER_HOST
        and isinstance(result["checked_at"], str),
        "The controller did not return a bounded status projection",
    )
    value = {field: result[field] for field in ("action_id", "status", "remaining_ms")}
    return receipt(value, identifier, expected), result


def cold_sidecar(root: Path, destination: Path) -> Path:
    sidecar = destination.with_name(destination.name + ".expected.json")
    require(
        destination.parent == root
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", destination.name)
        and not any(path.exists() or path.is_symlink() for path in (destination, sidecar)),
        "Cold capture requires a new direct child of the private laboratory",
    )
    return sidecar


def capture_cold_snapshot(
    network: Network,
    controller: str,
    image: str,
    known_hosts: Path,
    identifier: str,
    last_observed: dict,
    destination: Path,
) -> None:
    workspace = known_hosts.parent.parent
    sidecar = cold_sidecar(workspace.parent, destination)
    data = workspace / "controller-data"
    status, hosts = controller_response(network, controller, "GET", "/api/hosts")
    if status != 200 or not isinstance(hosts, list):
        raise RuntimeError("The public fixture registration could not be read")
    registered = [
        host for host in hosts if isinstance(host, dict) and host.get("id") == CONTROLLER_HOST
    ]
    require(len(registered) == 1, "The public fixture registration was ambiguous")
    host = registered[0]
    require(
        (host["source"], host["username"], host["address"], host["port"])
        == ("ssh", "opsark-readonly", TARGET, int(READONLY_PORT))
        and last_observed["status"] == "active"
        and last_observed == controller_history(network, controller, identifier),
        "The cold capture did not retain the confirmed original action",
    )
    inspect = (
        "container",
        "inspect",
        "--format",
        "{{.Id}} {{.Image}} {{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}",
        controller,
    )
    require(
        network.command(*inspect).decode("ascii").split()
        == [controller, image, "running", "false", "0"],
        "The source controller identity changed",
    )
    network.command("stop", "--time", "4", controller)
    stopped = network.command(*inspect).decode("ascii").split()
    require(
        stopped in ([controller, image, "exited", "false", str(code)] for code in (0, 143)),
        "The source controller did not stop cleanly",
    )
    with closing(
        sqlite3.connect((data / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        rows = db.execute(
            "SELECT host_id,host_scope,action_id,status,remaining_ms,observed_at "
            "FROM ssh_defense_observations WHERE host_id=? AND action_id=?",
            (CONTROLLER_HOST, identifier),
        ).fetchall()
    require(len(rows) == 1, "The original defense observation was not unique")
    row = list(rows[0])
    require(
        (row[0], row[2], row[3], row[4])
        == (CONTROLLER_HOST, identifier, "active", last_observed["remaining_ms"])
        and datetime.fromisoformat(row[5]) == datetime.fromisoformat(last_observed["observed_at"]),
        "The cold observation differed from the confirmed API history",
    )
    known = known_hosts.read_text(encoding="ascii")
    known_bytes = known.encode("ascii")
    require(
        hashlib.sha256(known_bytes).hexdigest() == host["trusted_hosts_digest"],
        "The public host pin no longer matches its registration",
    )
    expected = {
        "host_id": CONTROLLER_HOST,
        "action_id": identifier,
        "host_public": host,
        "known_hosts": known,
        "known_hosts_sha256": hashlib.sha256(known_bytes).hexdigest(),
        "last_observed": last_observed,
        "cache_row": row,
        "cache_row_sha256": hashlib.sha256(
            json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest(),
        "source_token_sha256": hashlib.sha256(
            (data / "access-token").read_bytes().strip()
        ).hexdigest(),
    }
    tool = str(ROOT / "deploy/observer/store_transfer.py")
    captured = run("/usr/bin/python3", "-I", tool, "snapshot", str(data), str(destination))
    require(captured.returncode == 0, "The private cold snapshot could not be created")
    verified = run("/usr/bin/python3", "-I", tool, "verify", str(destination))
    require(verified.returncode == 0, "The private cold snapshot could not be verified")
    proof = json.loads(verified.stdout)
    stores = json.loads(captured.stdout)
    require(
        proof["status"] == stores["status"] == "complete"
        and proof["database_count"] == len(stores["databases"]) == 10
        and stores["databases"]["security.sqlite3"]["table_rows"]["ssh_defense_observations"] == 1,
        "The cold snapshot did not preserve all ten stores and the scoped observation",
    )
    descriptor = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(json.dumps(expected, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def verify_controller_restart(
    network: Network,
    target: str,
    management: str,
    controller: str,
    known_hosts: Path,
    identifier: str,
    *,
    cold_snapshot: Path | None = None,
    controller_image: str | None = None,
) -> None:
    remaining, active = controller_status(network, controller, identifier, "active")
    last = active["last_observed"]
    require(last == controller_history(network, controller, identifier), "Status was not cached")
    require(isinstance(last, dict) and last.get("status") == "active", "No confirmed active state")
    original_pin = known_hosts.read_bytes()
    try:
        known_hosts.write_bytes(b"fixture trust pin intentionally unavailable\n")
        _, unavailable = controller_status(network, controller, identifier, "unavailable")
        require(unavailable["last_observed"] == last, "Unavailable query erased known state")
    finally:
        known_hosts.write_bytes(original_pin)
    stopped = network.execute(target, "/usr/bin/python3", "-I", "-B", "-c", _STOP_READONLY_SSHD)
    require(
        stopped.returncode == 0 and not stopped.stdout and not stopped.stderr,
        "The exact readonly listener could not be stopped",
    )
    try:
        _, disconnected = controller_status(network, controller, identifier, "unavailable")
        require(disconnected["last_observed"] == last, "SSH listener loss erased known state")
        ssh(network, management)
        if cold_snapshot is not None:
            if controller_image is None:
                raise RuntimeError("A cold capture needs a pinned controller image")
            capture_cold_snapshot(
                network, controller, controller_image, known_hosts, identifier, last, cold_snapshot
            )
    finally:
        restarted = network.execute(
            target,
            "/usr/sbin/sshd",
            "-f",
            f"{AUTHORITY}/sshd-readonly.conf",
            "-E",
            "/run/opsark-ssh-defense-status/sshd.log",
        )
        require(restarted.returncode == 0, "The readonly listener could not restart")
    started = ("container", "inspect", "--format", "{{.State.StartedAt}}", controller)
    before = network.command(*started)
    if cold_snapshot is not None:
        network.command("start", controller)
    else:
        network.command("restart", "--time", "4", controller)
    require(network.command(*started) != before, "The controller process did not restart")
    await_controller(network, controller)
    require(
        controller_history(network, controller, identifier) == last,
        "The last confirmed action was lost on restart",
    )
    later, _ = controller_status(network, controller, identifier, "active")
    require(later < remaining, "Controller restart or query refreshed the kernel TTL")


def target_ledger_digest(network: Network, target: str) -> bytes:
    result = network.execute(
        target, "/usr/bin/sha256sum", "--", "/run/opsark-ssh-defense/ledger.json"
    )
    digest = re.fullmatch(rb"([0-9a-f]{64})  /run/opsark-ssh-defense/ledger\.json\n", result.stdout)
    if result.returncode != 0 or result.stderr or digest is None:
        raise RuntimeError("The target ledger fingerprint could not be verified")
    return digest[1]


def verify_expiry(network: Network, management: str, identity: str) -> None:
    deadline = time.monotonic() + 66
    while time.monotonic() < deadline:
        value = relay(network, management, "status", identity)
        state = value.get("status")
        if not isinstance(state, str) or state not in {"active", "unknown", "expired"}:
            raise RuntimeError("Unexpected state while waiting for TTL")
        receipt(value, identity, state)
        if state == "expired":
            return
        time.sleep(1)
    raise RuntimeError("The original kernel action did not expire")


def exercise(
    root: Path,
    image: str,
    controller_image: str | None = None,
    *,
    cold_snapshot: Path | None = None,
) -> dict[str, bool]:
    if cold_snapshot is not None:
        require(controller_image is not None, "Cold capture needs a pinned controller image")
        cold_sidecar(root, cold_snapshot)
    with TemporaryDirectory(prefix="ssh-private-", dir=root) as directory, ExitStack() as cleanup:
        workspace = Path(directory)
        code, keys, authority = stage(workspace, controller=controller_image is not None)
        readiness = workspace / "ready"
        readiness.mkdir(mode=0o700)
        network = Network(workspace, image, cleanup)
        target = network.start(
            "target",
            TARGET,
            (
                "--cap-add",
                "NET_ADMIN",
                "--log-driver",
                "none",
                *mount(code, "/fixture-code"),
                *mount(authority, AUTHORITY),
                "--mount",
                f"type=bind,src={readiness},dst=/fixture-ready",
            ),
            "/usr/bin/python3",
            "-I",
            "-B",
            "/fixture-code/tests/ssh_defense_private_target.py",
            "--fixture-script",
            SCRIPT,
            "--client-public-key",
            f"{AUTHORITY}/client.pub",
            "--relay-nonce-file",
            f"{AUTHORITY}/nonce",
            "--confirm-isolated",
            allow_setuid=controller_image is not None,
        )
        pin = ready(network, target, readiness / "ready.json")
        (keys / "known_hosts").write_text(f"[{TARGET}]:{SSH_PORT} {pin}\n", encoding="ascii")
        (keys / "known_hosts").chmod(0o600)
        clients = {
            role: network.start(
                role,
                address,
                (
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--log-driver",
                    "none",
                    *mount(keys, KEYS),
                    *(mount(authority, AUTHORITY) if role == "management" else ()),
                ),
                "/bin/sleep",
                "infinity",
            )
            for role, address in SOURCES.items()
        }
        candidate, management, alternate = (clients[role] for role in SOURCES)
        for client in clients.values():
            ssh(network, client)
        healthy_http(network, candidate)
        require(
            executor(network, target, "initialize") == {"status": "initialized"},
            "Fixture policy initialization missing",
        )
        executor(
            network, target, "grant", "--source", SOURCES["management"], "--confirm", refused=True
        )

        excluded = grant(network, target, SOURCES["alternate"])
        for _ in range(5):
            ssh(network, alternate, valid=False, expected="denied")
        ssh(network, alternate)
        executor(network, target, "apply", "--grant-id", excluded, refused=True)

        identity = grant(network, target, SOURCES["candidate"])
        controller = None
        if controller_image is not None:
            controller = start_controller(
                network,
                target,
                authority,
                workspace,
                controller_image,
                identity,
                baked=cold_snapshot is not None,
            )
            instance, _ = controller
            require(
                controller_history(network, instance, identity) is None,
                "An unqueried action unexpectedly had a cached status",
            )
            path = f"{CONTROLLER_PATH}/{identity}/status"
            unauthorized, _ = controller_request(
                network, instance, "POST", path, {}, authenticated=False
            )
            require(unauthorized == 401, "Controller allowed unauthenticated defense status")
            foreign = "0" * 32 if identity != "0" * 32 else "1" * 32
            unregistered, _ = controller_request(
                network, instance, "POST", f"{CONTROLLER_PATH}/{foreign}/status", {}
            )
            require(unregistered == 404, "Controller accepted an unregistered defense action")
            unexpected, _ = controller_request(network, instance, "POST", path, {"op": "apply"})
            require(unexpected == 422, "Controller accepted a defense mutation field")
        for _ in range(5):
            ssh(network, candidate, valid=False, expected="denied")
        relay(network, management, "apply_drop", identity)
        remaining = receipt(relay(network, management, "status", identity), identity, "active")
        if controller is not None:
            ledger_before = target_ledger_digest(network, target)
            verify_controller_restart(
                network,
                target,
                management,
                *controller,
                identity,
                cold_snapshot=cold_snapshot,
                controller_image=controller_image,
            )
            require(
                target_ledger_digest(network, target) == ledger_before,
                "Controller status or restart changed the target ledger",
            )
        ssh(network, candidate, expected="blocked")
        ssh(network, management)
        ssh(network, alternate)
        healthy_http(network, candidate)
        duplicate = executor(network, target, "apply", "--grant-id", identity)
        require(receipt(duplicate, identity, "active") < remaining, "Duplicate apply refreshed TTL")

        verify_expiry(network, management, identity)
        if controller is not None:
            controller_status(network, controller[0], identity, "expired")
        receipt(executor(network, target, "apply", "--grant-id", identity), identity, "expired")
        ssh(network, candidate)

        revocable = grant(network, target, SOURCES["candidate"])
        require(revocable != identity, "Independent grant reused an original action ID")
        for _ in range(5):
            ssh(network, candidate, valid=False, expected="denied")
        receipt(executor(network, target, "apply", "--grant-id", revocable), revocable, "active")
        ssh(network, candidate, expected="blocked")
        receipt(
            executor(network, target, "revoke", "--action-id", revocable, "--confirm"),
            revocable,
            "revoked",
        )
        receipt(
            executor(network, target, "revoke", "--action-id", revocable, "--confirm"),
            revocable,
            "revoked",
        )
        ssh(network, candidate)
    return {
        "internal_bridge_no_published_ports": True,
        "real_failed_auth_and_successful_login_exclusion": True,
        "candidate_ssh_only_blocked": True,
        "management_and_alternate_ssh_preserved": True,
        "candidate_http_preserved": True,
        "actual_tcp_reset_before_apply_reply": True,
        "original_action_reconciled_without_refresh": True,
        "kernel_ttl_expired_without_rearm": True,
        "independent_exact_revoke_verified": True,
        "owned_fixture_resources_removed": True,
        **({"defense_cold_snapshot_captured": True} if cold_snapshot is not None else {}),
        **(
            {
                "controller_pinned_readonly_ssh_after_tcp_reset": True,
                "controller_scope_and_unavailable_status_verified": True,
                "readonly_ssh_listener_loss_retained_last_status": True,
                "controller_restart_preserved_confirmed_status": True,
                "controller_queries_left_target_ledger_unchanged": True,
                "controller_confirmed_original_action_expired": True,
            }
            if controller_image is not None
            else {}
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--controller-image", help="Pinned dependency image for real app readback")
    parser.add_argument(
        "--cold-snapshot", type=Path, help="Capture baked controller history while active"
    )
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        require_root(args.root)
        require(
            all(
                re.fullmatch(r"sha256:[0-9a-f]{64}", image)
                for image in (args.image, args.controller_image)
                if image is not None
            ),
            "Pinned fixture images are required",
        )
        print(
            json.dumps(
                exercise(
                    args.root, args.image, args.controller_image, cold_snapshot=args.cold_snapshot
                ),
                sort_keys=True,
            )
        )
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError):
        print("The isolated SSH defense experiment could not be verified.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
