"""Verify bounded SSH defense inside a disposable Docker network-none fixture."""

import argparse
import http.client
import json
import os
import pwd
import re
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path("/run/opsark-ssh-defense")
HOME = Path("/home/opsark-ssh-lab")
USER = "opsark-ssh-lab"
ADDRESS = "127.0.0.1"
CANDIDATE = "127.0.0.2"
MANAGEMENT = "127.0.0.3"
ACCEPTED_CONTRAST = "127.0.0.4"
SSH_PORT = 22422
HTTP_PORT = 22480
TTL_MS = 60_000
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class LabError(RuntimeError):
    """Report a failed acceptance stage without private fixture output."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise LabError(message)


def run(*argv: str, timeout: float = 5) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- fixed programs and constrained fixture arguments.
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=timeout,
        check=False,
    )


def prepare_fixture() -> Path:
    require(
        sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file(),
        "Run in a disposable root Docker fixture",
    )
    require({name for _, name in socket.if_nameindex()} == {"lo"}, "Use a network-none fixture")
    caps = next(
        (
            line.split()[1]
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith("CapEff:")
        ),
        "0",
    )
    require(int(caps, 16) & (1 << 12), "NET_ADMIN is required in the fixture namespace")
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise LabError("The disposable SSH account already exists")
    require(not HOME.exists() and not HOME.is_symlink(), "The fixture home must be new")
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    (ROOT / "lab.marker").write_text("opsark-ssh-defense-fixture-v1\n", encoding="ascii")
    (ROOT / "sshd.log").touch(mode=0o600, exist_ok=False)
    for key in ("host", "client", "invalid-client"):
        result = run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ROOT / key))
        require(result.returncode == 0, "Could not generate fixture keys")
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
    authorized.write_bytes((ROOT / "client.pub").read_bytes())
    for path in (authorized.parent, authorized):
        os.chown(path, account.pw_uid, account.pw_gid)
    host_public = (ROOT / "host.pub").read_text(encoding="ascii").split()[:2]
    (ROOT / "known_hosts").write_text(
        f"[{ADDRESS}]:{SSH_PORT} {' '.join(host_public)}\n", encoding="ascii"
    )
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    config = ROOT / "sshd_config"
    config.write_text(
        f"""AddressFamily inet
ListenAddress {ADDRESS}:{SSH_PORT}
PidFile {ROOT}/sshd.pid
HostKey {ROOT}/host
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
    return config


@contextmanager
def sshd(config: Path) -> Generator[None]:
    with subprocess.Popen(  # noqa: S603 -- isolated, fixed listener and synthetic credentials.
        ["/usr/sbin/sshd", "-D", "-E", str(ROOT / "sshd.log"), "-f", str(config)],
        env=ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:
            deadline = time.monotonic() + 5
            while not (ROOT / "sshd.pid").is_file():
                require(
                    process.poll() is None and time.monotonic() < deadline, "sshd did not start"
                )
                time.sleep(0.05)
            require((ROOT / "sshd.pid").read_text().strip() == str(process.pid), "Wrong sshd PID")
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204 if self.path == "/health" else 404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def http_server() -> Generator[None]:
    with ThreadingHTTPServer((ADDRESS, HTTP_PORT), HealthHandler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join(timeout=3)


def http_reaches_candidate() -> bool:
    client = http.client.HTTPConnection(
        ADDRESS, HTTP_PORT, timeout=2, source_address=(CANDIDATE, 0)
    )
    try:
        client.request("GET", "/health")
        return client.getresponse().status == 204
    finally:
        client.close()


def ssh_client(source: str, *, valid: bool = True) -> subprocess.CompletedProcess[bytes]:
    identity = "client" if valid else "invalid-client"
    return run(
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-oBatchMode=yes",
        "-oIdentitiesOnly=yes",
        "-oIdentityAgent=none",
        "-oGlobalKnownHostsFile=/dev/null",
        f"-oUserKnownHostsFile={ROOT / 'known_hosts'}",
        "-oStrictHostKeyChecking=yes",
        "-oPreferredAuthentications=publickey",
        "-oConnectionAttempts=1",
        "-oConnectTimeout=1",
        "-oLogLevel=ERROR",
        "-i",
        str(ROOT / identity),
        "-b",
        source,
        "-p",
        str(SSH_PORT),
        f"{USER}@{ADDRESS}",
        "/usr/bin/true",
    )


def rejected_logins(source: str, count: int) -> None:
    for _ in range(count):
        result = ssh_client(source, valid=False)
        require(
            result.returncode == 255 and b"Permission denied (publickey)" in result.stderr,
            "Expected a real rejected SSH authentication",
        )


def fixture(script: Path, *args: str, exit_code: int = 0) -> dict:
    result = run("/usr/bin/python3", "-I", "-B", str(script), *args)
    if result.returncode != exit_code:
        reason = ""
        if args[0] == "apply":
            ledger = json.loads((ROOT / "ledger.json").read_bytes())
            record = ledger.get("grants", {}).get(args[-1], {})
            phase = record.get("phase")
            if phase in {"ready", "intent", "active", "revoke_intent", "revoked"}:
                reason = f" in {phase} phase"
        raise LabError(
            f"Unexpected exit status for fixture {args[0]}{reason} "
            f"(expected {exit_code}, received {result.returncode})"
        )
    if exit_code:
        require(not result.stdout, "A refused action returned unexpected output")
        if exit_code == 1:
            require(
                result.stderr == b"The isolated SSH defense action could not be confirmed.\n",
                "A refused action returned an unbounded error",
            )
        return {}
    require(not result.stderr and len(result.stdout) <= 4096, "Unexpected fixture diagnostics")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeError, ValueError):
        raise LabError("Fixture command did not return JSON") from None
    require(isinstance(payload, dict), "Invalid fixture result")
    return payload


def grant(script: Path, source: str) -> str:
    payload = fixture(script, "grant", "--source", source, "--confirm")
    grant_id = payload.get("grant_id")
    if (
        set(payload) != {"grant_id", "status"}
        or payload["status"] != "ready"
        or not isinstance(grant_id, str)
    ):
        raise LabError("Unexpected grant response")
    require(re.fullmatch(r"[0-9a-f]{32}", grant_id), "Unexpected grant ID shape")
    return grant_id


def action(script: Path, command: str, identity: str, expected: str) -> int:
    flag = "--grant-id" if command == "apply" else "--action-id"
    confirmation = ("--confirm",) if command == "revoke" else ()
    payload = fixture(script, command, flag, identity, *confirmation)
    require(
        set(payload) == {"action_id", "status", "remaining_ms"}
        and payload["action_id"] == identity
        and payload["status"] == expected,
        "Unexpected action identity or status",
    )
    remaining = payload.get("remaining_ms")
    if expected == "active":
        if type(remaining) is not int or not 0 < remaining <= TTL_MS:
            raise LabError("Active rule has no bounded lifetime")
        return remaining
    require(
        remaining is None or (type(remaining) is int and remaining == 0),
        "A finished rule must have no remaining lifetime",
    )
    return 0


def verify_block() -> None:
    blocked = ssh_client(CANDIDATE)
    require(
        blocked.returncode == 255 and b"Connection timed out" in blocked.stderr,
        "Candidate SSH did not hit the network timeout",
    )
    require(ssh_client(MANAGEMENT).returncode == 0, "Management SSH was affected")
    require(ssh_client(ACCEPTED_CONTRAST).returncode == 0, "Independent SSH source was affected")
    require(http_reaches_candidate(), "Candidate HTTP on a different port was affected")


def exercise(script: Path) -> dict[str, bool]:
    config = prepare_fixture()
    with sshd(config), http_server():
        for source in (CANDIDATE, MANAGEMENT, ACCEPTED_CONTRAST):
            require(ssh_client(source).returncode == 0, "Pinned SSH baseline did not pass")
        require(http_reaches_candidate(), "Fixture HTTP baseline did not pass")
        require(fixture(script, "initialize") == {"status": "initialized"}, "Missing setup proof")
        fixture(script, "grant", "--source", MANAGEMENT, "--confirm", exit_code=1)
        fixture(script, "grant", "--source", CANDIDATE, exit_code=2)

        contrast = grant(script, ACCEPTED_CONTRAST)
        rejected_logins(ACCEPTED_CONTRAST, 5)
        require(ssh_client(ACCEPTED_CONTRAST).returncode == 0, "Contrast login did not pass")
        fixture(script, "apply", "--grant-id", contrast, exit_code=1)
        require(ssh_client(ACCEPTED_CONTRAST).returncode == 0, "Contrast source was blocked")

        first = grant(script, CANDIDATE)
        rejected_logins(CANDIDATE, 4)
        fixture(script, "apply", "--grant-id", first, exit_code=1)
        rejected_logins(CANDIDATE, 1)
        remaining = action(script, "apply", first, "active")
        deadline = time.monotonic() + remaining / 1000 + 1
        verify_block()
        time.sleep(2)
        duplicate = action(script, "apply", first, "active")
        require(duplicate < remaining - 1000, "Duplicate apply refreshed the rule")
        action(script, "status", first, "active")
        # Do not run the fixture executor again until a real SSH connection proves expiry.
        time.sleep(max(0, deadline - time.monotonic()))
        while ssh_client(CANDIDATE).returncode != 0:
            require(time.monotonic() < deadline + 4, "Kernel rule did not expire independently")
            time.sleep(0.25)
        action(script, "status", first, "expired")
        action(script, "apply", first, "expired")
        require(ssh_client(CANDIDATE).returncode == 0, "An expired grant blocked SSH again")

        second = grant(script, CANDIDATE)
        require(second != first, "Revocation test did not use an independent grant")
        rejected_logins(CANDIDATE, 5)
        action(script, "apply", second, "active")
        verify_block()
        fixture(script, "revoke", "--action-id", second, exit_code=2)
        action(script, "revoke", second, "revoked")
        require(ssh_client(CANDIDATE).returncode == 0, "SSH did not recover after confirmed revoke")
        action(script, "status", second, "revoked")
    return {
        "real_sshd_and_pinned_clients": True,
        "management_and_unconfirmed_grants_refused": True,
        "accepted_login_excludes_source": True,
        "fresh_distinct_failures_required": True,
        "command_output_limited_to_fixed_metadata": True,
        "only_candidate_ssh_blocked": True,
        "management_ssh_and_candidate_http_unaffected": True,
        "duplicate_apply_did_not_refresh": True,
        "kernel_expired_without_executor": True,
        "expired_grant_cannot_reapply": True,
        "independent_confirmed_revoke_restored_ssh": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-script", type=Path, required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        script = args.fixture_script
        require(
            script.is_absolute()
            and script.resolve(strict=True) == script
            and script.is_file()
            and script.name == "ssh_fixture.py",
            "Use the absolute isolated SSH fixture script path",
        )
        print(json.dumps(exercise(script), sort_keys=True))
    except LabError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("SSH defense fixture could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
