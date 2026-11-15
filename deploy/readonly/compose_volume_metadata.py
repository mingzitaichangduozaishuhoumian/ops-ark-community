#!/usr/bin/python3 -I
"""Project local-driver named-volume attachments for one Compose project.

Volume filters carry the name briefly in local Docker CLI argv. Local accounts
with permission to inspect that process may see it. Only aliases leave this helper.
Docker may discover other drivers before applying its list filter. The built-in
local driver can use nonlocal backing storage through its mount options.
"""

import hashlib
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

SCOPE = Path("/etc/opsark/compose-volume-metadata-scope.json")
SCHEMA = "opsark-compose-volume-metadata/v1"
MAX_CONTAINERS = 32
MAX_VOLUMES = 16
MAX_BYTES = 14_000
SECONDS = 4.0
DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
    "LC_ALL": "C",
}
PROJECT_LABEL = "com.docker.compose.project"
VOLUME_LABEL = "com.docker.compose.volume"
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
STATES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
REASONS = {
    "scope_invalid",
    "scope_unavailable",
    "collection_unavailable",
    "collection_timeout",
    "metadata_invalid",
    "metadata_limit",
    "evidence_changed",
}
CONTAINERS = (
    '{"id":{{json .ID}},"state":{{json .State}},'
    f'"project":{{{{json (.Label "{PROJECT_LABEL}")}}}},'
    '"service":{{json (.Label "com.docker.compose.service")}}}'
)
VOLUMES = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    f'"project":{{{{json (.Label "{PROJECT_LABEL}")}}}},'
    f'"volume":{{{{json (.Label "{VOLUME_LABEL}")}}}}' + "}"
)
ENGINE = '{"id":{{json .ID}},"os":{{json .OSType}},"security":{{json .SecurityOptions}}}'


class Refused(ValueError):
    """Only a fixed reason may escape the helper."""


def need(condition, reason="metadata_invalid"):
    if not condition:
        raise Refused(reason)


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw, reason="metadata_invalid"):
    def pairs(items):
        parsed = dict(items)
        need(len(parsed) == len(items), reason)
        return parsed

    def constant(_):
        raise Refused(reason)

    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused(reason) from None


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def scope_project(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "scope_invalid")
    scope = strict(raw, "scope_invalid")
    need(
        type(scope) is dict
        and scope.keys() == {"schema_version", "compose_project"}
        and type(scope["schema_version"]) is int
        and scope["schema_version"] == 1
        and matches(PROJECT, scope["compose_project"])
        and raw == canonical(scope),
        "scope_invalid",
    )
    return scope["compose_project"]


def arguments(project, *, volume=None):
    need(matches(PROJECT, project), "scope_invalid")
    args = (
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        f"label={PROJECT_LABEL}={project}",
    )
    if volume is not None:
        # Moby compares volume names, bind sources, and destinations by exact value.
        # Its Linux mount parser requires absolute bind sources and destinations.
        need(matches(NAME, volume))
        args += ("--filter", f"volume={volume}")
    return DOCKER + args + ("--format", CONTAINERS)


def volume_arguments(project):
    need(matches(PROJECT, project), "scope_invalid")
    return DOCKER + (
        "volume",
        "ls",
        "--filter",
        "driver=local",
        "--filter",
        f"label={PROJECT_LABEL}={project}",
        "--filter",
        f"label={VOLUME_LABEL}",
        "--format",
        VOLUMES,
    )


def rows(raw, fields, limit):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, "metadata_limit")
    if not raw:
        return []
    need(raw.endswith(b"\n") and b"\r" not in raw)
    lines = raw[:-1].split(b"\n")
    need(len(lines) <= limit, "metadata_limit")
    result = []
    for line in lines:
        value = strict(line)
        need(
            type(value) is dict
            and value.keys() == fields
            and all(type(x) is str for x in value.values())
        )
        result.append(value)
    return result


def containers(raw, project):
    result = {}
    for row in rows(raw, {"id", "state", "project", "service"}, MAX_CONTAINERS):
        need(
            row["project"] == project
            and matches(HEX, row["id"])
            and matches(NAME, row["service"])
            and row["state"] in STATES
            and row["id"] not in result
        )
        result[row["id"]] = (row["service"], row["state"])
    return result


def volumes(raw, project):
    result = {}
    for row in rows(raw, {"name", "driver", "scope", "project", "volume"}, MAX_VOLUMES):
        need(
            row["project"] == project
            and matches(NAME, row["name"])
            and matches(NAME, row["volume"])
            and row["driver"] == "local"
            and row["scope"] == "local"
            and row["name"] not in result
        )
        result[row["name"]] = (row["driver"], row["scope"], row["volume"])
    return result


def engine(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "collection_unavailable")
    value = strict(raw)
    need(
        type(value) is dict
        and value.keys() == {"id", "os", "security"}
        and type(value["id"]) is str
        and 1 <= len(value["id"]) <= 128
        and re.fullmatch(r"[A-Za-z0-9:-]+", value["id"])
        and value["os"] == "linux"
        and type(value["security"]) is list
        and len(value["security"]) <= 16
        and all(type(item) is str and 0 < len(item) <= 256 for item in value["security"])
        and not any("rootless" in item.lower() for item in value["security"]),
        "collection_unavailable",
    )
    return value


def sample(project, run):
    inventory = containers(run(arguments(project)), project)
    named = volumes(run(volume_arguments(project)), project)
    attached = {}
    for name in sorted(named):
        found = containers(run(arguments(project, volume=name)), project)
        need(
            all(inventory.get(identifier) == facts for identifier, facts in found.items()),
            "evidence_changed",
        )
        attached[name] = found
    return inventory, named, attached


def result(*, reason=None):
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "reason": reason,
        "scope_digest": None,
        "snapshot_digest": None,
        "observed_containers": 0,
        "coverage": "unavailable",
        "mount_mode": "unknown",
        "volumes": [],
        "actions_enabled": False,
        "model_calls": 0,
    }


def collect(scope_raw, run):
    project = scope_project(scope_raw)
    before = engine(run(DOCKER + ("info", "--format", ENGINE)))
    first = sample(project, run)
    second = sample(project, run)
    after = engine(run(DOCKER + ("info", "--format", ENGINE)))
    need(first == second and before == after, "evidence_changed")
    inventory, _, attached = second

    aliases = set()

    def alias():
        token = secrets.token_hex(16)
        need(token not in aliases)
        aliases.add(token)
        return token

    service_refs = {}
    shared = []
    for found in attached.values():
        if not found:
            continue
        counts = Counter(service for service, _ in found.values())
        services = []
        for service, count in counts.items():
            if service not in service_refs:
                service_refs[service] = alias()
            services.append({"service_ref": service_refs[service], "container_count": count})
        shared.append(
            {
                "volume_ref": alias(),
                "sharing": "shared_across_services" if len(counts) > 1 else "one_service",
                "services": sorted(services, key=lambda item: item["service_ref"]),
            }
        )
    observation = result() | {
        "status": "observed",
        "scope_digest": digest(scope_raw),
        "observed_containers": len(inventory),
        "coverage": "compose_labeled_local_named_volumes",
        "volumes": sorted(shared, key=lambda item: item["volume_ref"]),
    }
    observation.pop("snapshot_digest")
    observation["snapshot_digest"] = digest(canonical(observation))
    need(len(canonical(observation)) <= MAX_BYTES, "metadata_limit")
    return observation


def run_docker(argv, deadline):
    need(time.monotonic() < deadline, "collection_timeout")
    # Every argument comes from the fixed templates and strictly validated names above.
    with (
        subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=ENV,
            shell=False,
        ) as process,
        selectors.DefaultSelector() as selector,
    ):
        try:
            stdout, stderr = process.stdout, process.stderr
            if stdout is None or stderr is None:
                raise Refused("collection_unavailable")
            selector.register(stdout, selectors.EVENT_READ, "stdout")
            selector.register(stderr, selectors.EVENT_READ, "stderr")
            raw = bytearray()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, "collection_timeout")
                events = selector.select(remaining)
                need(bool(events), "collection_timeout")
                for stream, _ in events:
                    part = os.read(stream.fd, min(4096, MAX_BYTES - len(raw) + 1))
                    if not part:
                        selector.unregister(stream.fileobj)
                        continue
                    need(stream.data == "stdout", "collection_unavailable")
                    raw.extend(part)
                    need(len(raw) <= MAX_BYTES, "metadata_limit")
            remaining = deadline - time.monotonic()
            need(remaining > 0, "collection_timeout")
            need(process.wait(timeout=remaining) == 0, "collection_unavailable")
            return bytes(raw)
        except subprocess.TimeoutExpired:
            raise Refused("collection_timeout") from None
        finally:
            if process.poll() is None:
                process.kill()


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_scope(path):
    for parent in reversed(path.parents):
        info = parent.lstat()
        need(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "scope_unavailable",
        )
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and not before.st_mode & 0o022
        and before.st_nlink == 1
        and 0 < before.st_size <= 4096,
        "scope_unavailable",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as file:
        need(identity(os.fstat(file.fileno())) == identity(before), "evidence_changed")
        raw = file.read(4097)
        need(
            len(raw) == before.st_size and identity(os.fstat(file.fileno())) == identity(before),
            "evidence_changed",
        )
    need(identity(path.lstat()) == identity(before), "evidence_changed")
    return raw, identity(before)


def local_projection(argv):
    try:
        need(sys.platform == "linux", "collection_unavailable")
        need(not argv, "scope_invalid")
        try:
            raw, before = read_scope(SCOPE)
        except OSError:
            raise Refused("scope_unavailable") from None
        deadline = time.monotonic() + SECONDS
        observation = collect(raw, lambda args: run_docker(args, deadline))
        try:
            need(read_scope(SCOPE) == (raw, before), "evidence_changed")
        except OSError:
            raise Refused("evidence_changed") from None
        return observation
    except Refused as error:
        reason = (
            error.args[0]
            if len(error.args) == 1 and error.args[0] in REASONS
            else "collection_unavailable"
        )
        return result(reason=reason)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return result(reason="collection_unavailable")


if __name__ == "__main__":
    print(canonical(local_projection(sys.argv[1:])).decode("ascii"), end="")
