#!/usr/bin/python3 -I
"""Read one enrolled Compose generation from local Docker and emit keyed evidence."""

import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

SCOPE = Path("/etc/opsark/compose-generation-scope.json")
KEY = Path("/etc/opsark/compose-generation-key")
SOCKET = Path("/run/docker.sock")
CONTAINER_LIST = "/v1.44/containers/json"
PROC = Path("/proc")
DOCKERD = Path("/usr/bin/dockerd")
BOOT = re.compile(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n\Z")
SCHEMA = "opsark-compose-generation/v1"
MAX_BYTES = 65536
SECONDS = 4
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERSION = re.compile(r"[A-Za-z0-9.+-]{1,40}\Z")
COMPOSE_V2 = re.compile(r"v?2\.[0-9]{1,4}\.[0-9]{1,4}\Z")
LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
LABEL_CONFIG = "com.docker.compose.config-hash"
LABEL_VERSION = "com.docker.compose.version"
REASONS = frozenset(
    {
        "scope_invalid",
        "scope_unavailable",
        "collection_unavailable",
        "collection_timeout",
        "metadata_invalid",
        "evidence_changed",
    }
)


class Refused(ValueError):
    """Only a fixed reason may leave the helper."""


def need(ok, reason="metadata_invalid"):
    if not ok:
        raise Refused(reason)


def canonical(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (text + "\n").encode("ascii")


def decode(raw, reason):
    def unique(items):
        result = dict(items)
        need(len(items) == len(result), reason)
        return result

    def invalid(_):
        raise Refused(reason)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused(reason) from None


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def checked_scope(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "scope_invalid")
    value = decode(raw, "scope_invalid")
    need(
        type(value) is dict
        and value.keys() == {"schema_version", "compose_project", "container_name", "service"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and matches(PROJECT, value["compose_project"])
        and matches(NAME, value["container_name"])
        and matches(NAME, value["service"])
        and raw == canonical(value),
        "scope_invalid",
    )
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def trusted_parents(path, reason):
    for parent in reversed(path.parents):
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022, reason)


def read_private(path, limit):
    reason = "scope_unavailable"
    trusted_parents(path, reason)
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == 0o600
        and before.st_nlink == 1
        and 0 < before.st_size <= limit,
        reason,
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as reader:
        original = identity(before)
        need(identity(os.fstat(reader.fileno())) == original, "evidence_changed")
        raw = reader.read(limit + 1)
        need(
            len(raw) == before.st_size and identity(os.fstat(reader.fileno())) == original,
            "evidence_changed",
        )
    need(identity(path.lstat()) == original, "evidence_changed")
    return raw, original


def endpoint_identity():
    trusted_parents(SOCKET, "collection_unavailable")
    row = SOCKET.lstat()
    need(
        stat.S_ISSOCK(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o002,
        "collection_unavailable",
    )
    return row.st_dev, row.st_ino


def remaining(deadline):
    seconds = deadline - time.monotonic()
    need(seconds > 0, "collection_timeout")
    return seconds


def activated_pid(deadline):
    reason = "collection_unavailable"
    need((PROC / "1/exe").resolve(strict=True) == Path("/usr/lib/systemd/systemd"), reason)
    try:
        result = subprocess.run(  # noqa: S603 -- fixed local systemd unit and properties.
            (
                "/usr/bin/systemctl",
                "show",
                "--no-pager",
                "-p",
                "MainPID",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "ControlGroup",
                "docker.service",
            ),
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=remaining(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise Refused("collection_timeout") from None
    need(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 4096, reason)
    pairs = [line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()]
    values = dict(pairs)
    pid = values.get("MainPID", "")
    need(
        len(pairs) == 4
        and values
        == {
            "MainPID": pid,
            "ActiveState": "active",
            "SubState": "running",
            "ControlGroup": "/system.slice/docker.service",
        }
        and re.fullmatch(r"[1-9][0-9]{0,7}", pid) is not None
        and int(pid) > 1,
        reason,
    )
    need(
        (PROC / pid / "cgroup").read_bytes() == b"0::/system.slice/docker.service\n",
        reason,
    )
    return int(pid)


def daemon_witness(connection, deadline):
    reason = "collection_unavailable"
    pid, uid, _ = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    need(pid >= 1 and uid == 0, reason)
    if pid == 1:
        pid = activated_pid(deadline)
    proc = PROC / str(pid)
    need(proc.stat().st_uid == 0 and (proc / "exe").resolve(strict=True) == DOCKERD, reason)
    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[-1].split()
    need(len(fields) >= 20 and fields[0] not in {b"Z", b"X"} and fields[19].isdigit(), reason)
    birth = int(fields[19])
    boot = (PROC / "sys/kernel/random/boot_id").read_bytes()
    need(birth > 0 and BOOT.fullmatch(boot), reason)
    return boot.decode("ascii").strip(), pid, birth


class DockerConnection(http.client.HTTPConnection):
    """Never allow HTTPConnection to connect over TCP or reconnect through a proxy."""

    def __init__(self, endpoint, deadline):
        super().__init__("localhost", timeout=remaining(deadline))
        self.endpoint, self.deadline = endpoint, deadline

    def connect(self):
        need(endpoint_identity() == self.endpoint, "evidence_changed")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(remaining(self.deadline))
            connection.connect(str(SOCKET))
            need(endpoint_identity() == self.endpoint, "evidence_changed")
            self.witness = daemon_witness(connection, self.deadline)
            self.sock = connection
        except BaseException:
            connection.close()
            raise


def docker_get(path, endpoint, deadline):
    # Paths are made only from fixed routes and canonical enrolled values below.
    connection = DockerConnection(endpoint, deadline)
    try:
        # Keep a duplicate of the connected socket for the second peer witness.
        # http.client may otherwise close its socket while returning the response.
        connection.connect()
        with connection.sock.dup() as peer:
            value = read_response(connection, path, deadline)
            need(daemon_witness(peer, deadline) == connection.witness, "evidence_changed")
            need(endpoint_identity() == endpoint, "evidence_changed")
        remaining(deadline)
        return value, (*endpoint, *connection.witness)
    except TimeoutError:
        raise Refused("collection_timeout") from None
    except (OSError, http.client.HTTPException):
        raise Refused("collection_unavailable") from None
    finally:
        connection.close()


def read_response(connection, path, deadline):
    connection.request("GET", path, headers={"Connection": "close"})
    connection.sock.settimeout(remaining(deadline))
    with connection.getresponse() as response:
        lengths = response.headers.get_all("Content-Length") or []
        transfers = response.headers.get_all("Transfer-Encoding") or []
        need(
            response.status == 200
            and response.headers.get_content_type() == "application/json"
            and response.getheader("Content-Encoding", "identity") == "identity"
            and (
                transfers == ["chunked"]
                and not lengths
                or not transfers
                and len(lengths) == 1
                and lengths[0].isascii()
                and lengths[0].isdigit()
            ),
            "collection_unavailable",
        )
        expected = response.length
        need(expected is None or 0 < expected <= MAX_BYTES, "metadata_invalid")
        raw = response.read(MAX_BYTES + 1)
        need(
            0 < len(raw) <= MAX_BYTES and (expected is None or len(raw) == expected),
            "metadata_invalid",
        )
    return decode(raw, "metadata_invalid")


def list_path(scope):
    name = scope["container_name"].replace(".", r"\.")
    filters = {
        "name": [f"^/{name}$"],
        "label": [
            LABEL_PROJECT + "=" + scope["compose_project"],
            LABEL_SERVICE + "=" + scope["service"],
        ],
    }
    query = urlencode({"all": "1", "filters": canonical(filters).decode("ascii").rstrip("\n")})
    return CONTAINER_LIST + "?" + query


def container_metadata(value, scope):
    # The filtered Engine list API supplies immutable ImageID without fetching
    # inspect/Config.Env. Extra list fields and labels never enter the witness.
    need(type(value) is list and len(value) == 1 and type(value[0]) is dict)
    row = value[0]
    labels = row.get("Labels")
    need(
        row.get("Names") == ["/" + scope["container_name"]]
        and matches(HEX, row.get("Id"))
        and matches(IMAGE, row.get("ImageID"))
        and type(labels) is dict
        and labels.get(LABEL_PROJECT) == scope["compose_project"]
        and labels.get(LABEL_SERVICE) == scope["service"]
    )
    config = labels.get(LABEL_CONFIG, "")
    version = labels.get(LABEL_VERSION, "")
    need((config == "" or matches(HEX, config)) and (version == "" or matches(VERSION, version)))
    return row["Id"], row["ImageID"], config, version


def unavailable(reason):
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "reason": reason,
        "scope_digest": None,
        "binding": None,
        "container": None,
        "image": None,
        "configuration": None,
        "compose_version": None,
    }


def collect(scope_raw, key, get):
    scope = checked_scope(scope_raw)
    need(type(key) is bytes and len(key) == 32, "scope_unavailable")
    path = list_path(scope)

    def sample():
        raw, daemon = get(path)
        return container_metadata(raw, scope), daemon

    first, daemon = sample()
    need((first, daemon) == sample(), "evidence_changed")
    container, image, config, version = first
    scope_digest = digest(scope_raw)

    def mark(*values):
        data = b"opsark-compose-generation-target/v1\0" + canonical(values)
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    binding = mark("binding", scope_digest, daemon)
    has_compose = bool(config and COMPOSE_V2.fullmatch(version))
    return unavailable(None) | {
        "status": "observed",
        "scope_digest": scope_digest,
        "binding": binding,
        "container": mark(binding, "container", container),
        "image": mark(binding, "image", image),
        "configuration": mark(binding, "configuration", config) if has_compose else None,
        "compose_version": mark(binding, "compose_version", version.removeprefix("v"))
        if has_compose
        else None,
    }


def local_projection(argv):
    try:
        need(sys.platform == "linux" and os.geteuid() == 0, "collection_unavailable")
        need(not argv, "scope_invalid")
        try:
            scope = read_private(SCOPE, 4096)
            key = read_private(KEY, 32)
        except OSError:
            raise Refused("scope_unavailable") from None
        deadline = time.monotonic() + SECONDS
        endpoint = endpoint_identity()
        result = collect(scope[0], key[0], lambda path: docker_get(path, endpoint, deadline))
        try:
            need(
                read_private(SCOPE, 4096) == scope and read_private(KEY, 32) == key,
                "evidence_changed",
            )
        except OSError:
            raise Refused("evidence_changed") from None
        need(endpoint_identity() == endpoint, "evidence_changed")
        remaining(deadline)
        return result
    except Refused as error:
        reason = error.args[0] if len(error.args) == 1 and error.args[0] in REASONS else None
        return unavailable(reason or "collection_unavailable")
    except (OSError, ValueError, TypeError, KeyError, RecursionError, struct.error):
        return unavailable("collection_unavailable")


if __name__ == "__main__":
    sys.stdout.buffer.write(canonical(local_projection(sys.argv[1:])))
