"""Loopback SSH harness that executes only exact, fixture-owned read commands."""

import contextlib
import os
import shlex
import socket
import subprocess
import threading
from pathlib import Path

import paramiko


class _ReadOnlyServer(paramiko.ServerInterface):
    def __init__(self, harness: "DockerLabSSH") -> None:
        self.harness = harness

    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username == "opsark-lab" and key == self.harness.user_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        try:
            decoded = command.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
        argv = self.harness.allowed.get(decoded)
        if argv is None:
            self.harness.rejected.append(decoded)
            return False
        self.harness.executed.append(decoded)
        thread = threading.Thread(target=self._respond, args=(channel, argv), daemon=True)
        self.harness.workers.append(thread)
        thread.start()
        return True

    @staticmethod
    def _respond(channel: paramiko.Channel, argv: list[str]) -> None:
        try:
            if len(argv) > 4 and Path(argv[4]).name == "journalctl":
                channel.sendall_stderr(
                    b"Kernel journal is outside the disposable Docker lab scope.\n"
                )
                channel.send_exit_status(125)
                channel.shutdown_write()
                return
            # This is the fixture runner, never the application. argv comes only
            # from an exact allowlist generated before opening the SSH listener.
            result = subprocess.run(  # noqa: S603
                argv,
                capture_output=True,
                check=False,
                timeout=6,
                env={**os.environ, "LC_ALL": "C"},
            )
            with contextlib.suppress(OSError, EOFError):
                if result.stdout:
                    channel.sendall(result.stdout)
                if result.stderr:
                    channel.sendall_stderr(result.stderr)
                channel.send_exit_status(result.returncode)
                channel.shutdown_write()
        except (OSError, subprocess.TimeoutExpired):
            with contextlib.suppress(OSError, EOFError):
                channel.sendall_stderr(b"Docker lab command did not finish.\n")
                channel.send_exit_status(124)
                channel.shutdown_write()


class DockerLabSSH:
    """Temporary keys, strict exec allowlist, and no PTY, shell, SFTP or forwarding.

    This harness runs on a disposable CI runner that already has Docker access.
    It is not an OpenSSH or production account-isolation acceptance test.
    """

    def __init__(self, directory: Path, commands: set[str]) -> None:
        self.server_key = paramiko.RSAKey.generate(2048)
        self.user_key = paramiko.RSAKey.generate(2048)
        self.key_file = directory / "docker-lab-client-key"
        self.user_key.write_private_key_file(str(self.key_file))
        self.key_file.chmod(0o600)
        self.allowed: dict[str, list[str]] = {}
        for command in commands:
            argv = shlex.split(command)
            if not argv or argv[0] != "timeout":
                raise ValueError("Only the collector's timeout-bounded commands may be registered")
            self.allowed["LC_ALL=C " + command] = argv
        self.executed: list[str] = []
        self.rejected: list[str] = []
        self.workers: list[threading.Thread] = []
        self.transports: list[paramiko.Transport] = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.known_hosts_file = directory / "docker-lab-known-hosts"
        self.known_hosts_file.write_text(
            f"[127.0.0.1]:{self.port} {self.server_key.get_name()} "
            f"{self.server_key.get_base64()}\n",
            encoding="utf-8",
        )
        self.known_hosts_file.chmod(0o600)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            transport = paramiko.Transport(connection)
            self.transports.append(transport)
            transport.add_server_key(self.server_key)
            # No subsystem handlers are registered; SFTP is unavailable.
            with contextlib.suppress(OSError, EOFError, paramiko.SSHException):
                transport.start_server(server=_ReadOnlyServer(self))

    def __enter__(self) -> "DockerLabSSH":
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=2)
        for thread in self.workers:
            thread.join(timeout=7)
