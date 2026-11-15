#!/usr/bin/python3 -I
"""Root-owned, exact-command SSH collection guard for Ubuntu/Debian.

Installed as /usr/local/libexec/opsark-readonly-guard. No options or alternate
policy paths are accepted at the command line. Root administrators own policy.
"""

import hashlib
import json
import os
import queue
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

POLICY_PATH = Path("/etc/opsark/readonly-policy.json")
LOCK_PATH = Path("/run/opsark-readonly.lock")
MAX_POLICY_BYTES = 262_144
MAX_COMMAND_BYTES = 4096
MAX_OUTPUT_BYTES = 16_384
DATA_OUTPUT_BYTES = MAX_OUTPUT_BYTES - 256
WALL_SECONDS = 6.0
SAFE_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
    "PAGER": "cat",
}


class PolicyError(ValueError):
    """The caller or root-managed policy failed closed."""


class BusyError(RuntimeError):
    """Another approved collection command already holds this host's slot."""


def _metadata_ok(metadata, *, directory=False):
    kind = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    return kind and metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0


def _trusted_parents(path):
    for parent in reversed(path.parents):
        if not _metadata_ok(parent.lstat(), directory=True):
            raise PolicyError("Untrusted policy parent")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("Duplicate policy field")
        result[key] = value
    return result


def parse_policy(data):
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError("Policy too large")
    try:
        policy = json.loads(data, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise PolicyError("Invalid policy JSON") from error
    if (
        not isinstance(policy, dict)
        or set(policy) != {"schema_version", "commands"}
        or type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or not isinstance(policy["commands"], dict)
        or not 1 <= len(policy["commands"]) <= 256
    ):
        raise PolicyError("Invalid policy schema")
    for original, argv in policy["commands"].items():
        if (
            not isinstance(original, str)
            or not original.startswith("LC_ALL=C timeout -k 1s 5s ")
            or len(original.encode("utf-8")) > MAX_COMMAND_BYTES
            or "\x00" in original
            or not isinstance(argv, list)
            or not 5 <= len(argv) <= 80
            or any(not isinstance(item, str) or "\x00" in item or len(item) > 8192 for item in argv)
            or argv[:4] != ["timeout", "-k", "1s", "5s"]
        ):
            raise PolicyError("Invalid fixed command")
        try:
            matches = shlex.split(original[len("LC_ALL=C ") :]) == argv
        except ValueError as error:
            raise PolicyError("Invalid fixed argv") from error
        if not matches:
            raise PolicyError("Original command and fixed argv differ")
    return policy["commands"]


def load_policy(path=POLICY_PATH):
    if not path.is_absolute():
        raise PolicyError("Policy path must be absolute")
    _trusted_parents(path)
    if not hasattr(os, "O_NOFOLLOW"):
        raise PolicyError("This guard requires Linux no-follow file opens")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not _metadata_ok(metadata)
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_POLICY_BYTES
        ):
            raise PolicyError("Untrusted policy file")
        return parse_policy(handle.read(MAX_POLICY_BYTES + 1))


def _kill(process):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, OSError):
        pass


@contextmanager
def execution_lock(path=LOCK_PATH):
    import fcntl

    _trusted_parents(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not _metadata_ok(metadata)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PolicyError("Untrusted execution lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BusyError("Collection slot busy") from error
        yield descriptor
    finally:
        os.close(descriptor)


def run_bounded(argv, *, wall_seconds=WALL_SECONDS, lock_fd=None):
    """Read both streams concurrently without unbounded communicate() buffers."""
    executable = ["/usr/bin/timeout", *argv[1:]] if argv[0] == "timeout" else list(argv)
    process = subprocess.Popen(  # noqa: S603 -- argv is from the verified root policy.
        executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SAFE_ENVIRONMENT.copy(),
        cwd="/",
        shell=False,
        start_new_session=True,
        pass_fds=(lock_fd,) if lock_fd is not None else (),
    )
    stdout_stream, stderr_stream = process.stdout, process.stderr
    if stdout_stream is None or stderr_stream is None:
        _kill(process)
        raise PolicyError("Missing bounded output streams")
    messages = queue.Queue(maxsize=8)
    stop = threading.Event()

    def read_stream(stream, label):
        try:
            while not stop.is_set():
                chunk = stream.read1(4096)
                while not stop.is_set():
                    try:
                        messages.put((label, chunk), timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    return
        except (OSError, ValueError):
            return

    threads = [
        threading.Thread(target=read_stream, args=(stdout_stream, "stdout"), daemon=True),
        threading.Thread(target=read_stream, args=(stderr_stream, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + wall_seconds
    closed = 0
    failure = None
    try:
        while closed < 2:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            try:
                label, chunk = messages.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if not chunk:
                closed += 1
                continue
            capacity = DATA_OUTPUT_BYTES - len(output["stdout"]) - len(output["stderr"])
            output[label].extend(chunk[:capacity])
            if len(chunk) > capacity:
                failure = "output_limit"
                break
        if failure:
            _kill(process)
        try:
            code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            failure = "timeout"
            _kill(process)
            code = process.wait(timeout=1)
    finally:
        stop.set()
        if process.poll() is None:
            _kill(process)
        for thread in threads:
            thread.join(timeout=0.3)
        stdout_stream.close()
        stderr_stream.close()
    if failure:
        output["stderr"].extend(("\nOpsArk collection guard: " + failure + ".\n").encode("ascii"))
        code = 124 if failure == "timeout" else 125
    if code < 0:
        code = 128 - code
    return code, bytes(output["stdout"]), bytes(output["stderr"])


def audit(event, command=""):
    identifier = hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()[:16]
    try:
        import syslog

        syslog.openlog("opsark-readonly", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE, f"event={event} command_id={identifier}")
    except (ImportError, OSError):
        pass


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    command = ""
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise PolicyError("Root helper required")
        if len(arguments) != 1 or not isinstance(arguments[0], str):
            raise PolicyError("One exact command required")
        command = arguments[0]
        if not command or len(command.encode("utf-8")) > MAX_COMMAND_BYTES or "\x00" in command:
            raise PolicyError("Invalid original command")
        commands = load_policy()
        if command not in commands:
            raise PolicyError("Command not allowed")
        os.umask(0o077)
        with execution_lock() as lock_fd:
            code, output, errors = run_bounded(commands[command], lock_fd=lock_fd)
        sys.stdout.buffer.write(output)
        sys.stderr.buffer.write(errors)
        audit("completed_" + str(code), command)
        return code
    except BusyError:
        audit("busy", command)
        sys.stderr.write("OpsArk restricted collector is busy; no command executed.\n")
        return 75
    except (PolicyError, OSError, ValueError):
        audit("refused", command)
        sys.stderr.write("OpsArk restricted collector refused this request.\n")
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
