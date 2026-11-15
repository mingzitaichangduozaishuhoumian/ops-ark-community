"""Run the synthetic SSH defense target and receipt relay on its private bridge."""

import argparse
import base64
import hmac
import json
import os
import pwd
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import suppress
from fcntl import ioctl
from http.server import ThreadingHTTPServer
from pathlib import Path
from socketserver import BaseRequestHandler, TCPServer
from threading import Thread

# The sibling harness is trusted fixture code. Isolated Python drops the script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ssh_defense_lab import (  # noqa: E402 -- restore only the fixture sibling path for Python -I.
    HOME,
    HTTP_PORT,
    ROOT,
    SSH_PORT,
    TTL_MS,
    USER,
    HealthHandler,
    LabError,
    require,
    run,
    sshd,
)

ADDRESS = "198.18.241.2"
MANAGEMENT = "198.18.241.4"
RELAY_PORT = 22424
READY = Path("/fixture-ready/ready.json")
MAX_REQUEST = 192
IDENTIFIER = re.compile(r"[0-9a-f]{32}")
ED25519 = re.compile(rb"ssh-ed25519 ([A-Za-z0-9+/]{68})(?: [\x20-\x7e]{1,160})?\n")
REFUSED = b'{"status":"refused"}\n'


def validate_network() -> None:
    require(
        sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file(),
        "Run inside the disposable private target container",
    )
    require({name for _, name in socket.if_nameindex()} == {"lo", "eth0"}, "Wrong interfaces")
    require(
        os.path.samestat(os.stat("/proc/self/ns/net"), os.stat("/proc/1/ns/net")),
        "Wrong private namespace",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
        eth0 = struct.pack("256s", b"eth0")
        address = socket.inet_ntoa(ioctl(descriptor.fileno(), 0x8915, eth0)[20:24])
        mask = socket.inet_ntoa(ioctl(descriptor.fileno(), 0x891B, eth0)[20:24])
    require(address == ADDRESS and mask == "255.255.255.240", "Wrong private target address")
    routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    require(all(row.split()[1] != "00000000" for row in routes), "IPv4 default route exists")


def read_fixture_file(path: Path, limit: int, *, secret: bool = False) -> bytes:
    require(path.is_absolute() and path.resolve(strict=True) == path, "Unsafe fixture input path")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & (0o077 if secret else 0o022)
            and 0 < info.st_size <= limit,
            "Unsafe fixture input file",
        )
        content = source.read(limit + 1)
        require(len(content) == info.st_size, "Fixture input changed during read")
        return content


def public_key(content: bytes) -> str:
    match = ED25519.fullmatch(content)
    if match is None:
        raise LabError("Expected one synthetic Ed25519 public key")
    encoded = match[1]
    blob = base64.b64decode(encoded, validate=True)
    require(
        len(blob) == 51 and blob.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"),
        "Invalid synthetic Ed25519 public key format",
    )
    return "ssh-ed25519 " + encoded.decode("ascii")


def prepare_ssh(key: str) -> tuple[Path, str]:
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise LabError("The disposable SSH account already exists")
    require(not HOME.exists() and not HOME.is_symlink(), "The fixture home must be new")
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    (ROOT / "lab.marker").write_bytes(b"opsark-ssh-defense-private-v1\n")
    (ROOT / "sshd.log").touch(mode=0o600, exist_ok=False)
    host = ROOT / "host"
    require(
        run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host)).returncode
        == 0,
        "Could not generate the synthetic host key",
    )
    require(
        run(
            "/usr/sbin/useradd",
            "--create-home",
            "--user-group",
            "--home-dir",
            str(HOME),
            "--shell",
            "/bin/sh",
            "--password",
            "*",
            USER,
        ).returncode
        == 0,
        "Could not create the fixture SSH user",
    )
    account = pwd.getpwnam(USER)
    authorized = HOME / ".ssh" / "authorized_keys"
    authorized.parent.mkdir(mode=0o700)
    authorized.write_text(key + "\n", encoding="ascii")
    for path in (authorized.parent, authorized):
        os.chown(path, account.pw_uid, account.pw_gid)
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    config = ROOT / "sshd_config"
    config.write_text(
        f"""AddressFamily inet
ListenAddress {ADDRESS}:{SSH_PORT}
PidFile {ROOT}/sshd.pid
HostKey {host}
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers {USER}
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
DisableForwarding yes
PermitTTY no
PermitUserRC no
ForceCommand /usr/bin/true
LogLevel VERBOSE
""",
        encoding="ascii",
    )
    require(
        run("/usr/sbin/sshd", "-t", "-f", str(config)).returncode == 0, "Invalid lab sshd config"
    )
    return config, public_key((ROOT / "host.pub").read_bytes())


def strict_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Repeated JSON field")
    return result


def request(stream: socket.socket, nonce: str) -> tuple[str, str]:
    deadline = time.monotonic() + 2
    frame = bytearray()
    while b"\n" not in frame and len(frame) <= MAX_REQUEST:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Relay request timed out")
        stream.settimeout(remaining)
        chunk = stream.recv(MAX_REQUEST + 1 - len(frame))
        if not chunk:
            break
        frame.extend(chunk)
    if len(frame) > MAX_REQUEST or not frame.endswith(b"\n") or frame.count(b"\n") != 1:
        raise ValueError("Invalid relay frame")
    payload = json.loads(frame.decode("ascii"), object_pairs_hook=strict_keys)
    if not isinstance(payload, dict) or set(payload) != {"op", "id", "nonce"}:
        raise ValueError("Invalid relay request")
    operation, identity, supplied = payload["op"], payload["id"], payload["nonce"]
    if (
        operation not in ("apply_drop", "status")
        or not isinstance(identity, str)
        or IDENTIFIER.fullmatch(identity) is None
        or not isinstance(supplied, str)
        or IDENTIFIER.fullmatch(supplied) is None
        or not hmac.compare_digest(nonce, supplied)
    ):
        raise ValueError("Unapproved relay request")
    return operation, identity


def cli_result(script: Path, operation: str, identity: str) -> bytes:
    arguments = ("apply", "--grant-id") if operation == "apply_drop" else ("status", "--action-id")
    result = run(
        "/usr/bin/python3", "-I", "-B", str(script), "--profile", "private", *arguments, identity
    )
    if result.returncode or result.stderr or len(result.stdout) > 256:
        raise ValueError("Private fixture action did not confirm a result")
    payload = json.loads(result.stdout.decode("ascii"), object_pairs_hook=strict_keys)
    if not isinstance(payload, dict) or set(payload) != {"action_id", "status", "remaining_ms"}:
        raise ValueError("Unexpected fixture receipt")
    state, remaining = payload["status"], payload["remaining_ms"]
    if (
        payload["action_id"] != identity
        or state not in ("active", "expired", "revoked", "unknown")
        or (operation == "apply_drop" and state != "active")
        or (state == "active" and (type(remaining) is not int or not 0 < remaining <= TTL_MS))
        or (state != "active" and remaining is not None)
    ):
        raise ValueError("Unexpected fixture action state")
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def relay_handler(script: Path, nonce: str) -> type[BaseRequestHandler]:
    class RelayHandler(BaseRequestHandler):
        def handle(self) -> None:
            try:
                operation, identity = request(self.request, nonce)
                receipt = cli_result(script, operation, identity)
                if operation == "apply_drop":
                    self.request.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                    )
                    # Close here so socketserver cannot send an orderly shutdown first.
                    self.request.close()
                else:
                    self.request.sendall(receipt)
            except (OSError, ValueError, subprocess.SubprocessError):
                with suppress(OSError):
                    self.request.sendall(REFUSED)

    return RelayHandler


class PrivateRelay(TCPServer):
    def verify_request(self, request: object, client_address: object) -> bool:
        return (
            isinstance(client_address, tuple)
            and len(client_address) == 2
            and client_address[0] == MANAGEMENT
        )


def publish_ready(host_key: str) -> None:
    info = READY.parent.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
        "The fixture readiness directory must be private",
    )
    require(not READY.exists() and not READY.is_symlink(), "The fixture is already ready")
    pending = READY.with_suffix(".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            json.dump({"status": "ready", "host_public_key": host_key}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        pending.rename(READY)
    finally:
        pending.unlink(missing_ok=True)


def serve(script: Path, key: str, nonce: str) -> None:
    config, host_key = prepare_ssh(key)
    with (
        sshd(config),
        ThreadingHTTPServer((ADDRESS, HTTP_PORT), HealthHandler) as health,
        PrivateRelay((ADDRESS, RELAY_PORT), relay_handler(script, nonce)) as relay,
    ):
        worker = Thread(target=health.serve_forever, daemon=True)
        worker.start()
        try:
            publish_ready(host_key)
            relay.serve_forever()
        finally:
            health.shutdown()
            worker.join(timeout=3)


def stop(_signal: int, _frame: object) -> None:
    raise SystemExit(0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-script", type=Path, required=True)
    parser.add_argument("--client-public-key", type=Path, required=True)
    parser.add_argument("--relay-nonce-file", type=Path, required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        validate_network()
        script = args.fixture_script
        require(
            script.is_absolute()
            and script.resolve(strict=True) == script
            and script.is_file()
            and script.name == "ssh_fixture.py",
            "Use the absolute fixture executor path",
        )
        key_path, nonce_path = args.client_public_key, args.relay_nonce_file
        require(
            key_path.suffix == ".pub" and key_path.parent == nonce_path.parent,
            "Use a public key in the private synthetic key workspace",
        )
        parent = key_path.parent.lstat()
        require(
            stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o077,
            "The synthetic key workspace must be root-private",
        )
        key = public_key(read_fixture_file(key_path, 256))
        secret = read_fixture_file(nonce_path, 33, secret=True)
        require(re.fullmatch(rb"[0-9a-f]{32}\n", secret), "Invalid synthetic relay nonce")
        signal.signal(signal.SIGTERM, stop)
        serve(script, key, secret[:-1].decode("ascii"))
    except LabError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("The private SSH defense target could not run", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
