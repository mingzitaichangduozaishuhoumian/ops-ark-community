"""Fixed local Docker access for one registered, running container."""

import hashlib
import json
import re
import socket
import stat
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SOCKET = Path("/run/docker.sock")
DOCKER = ("/usr/bin/docker", "--host", "unix:///run/docker.sock")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DOCKER_CONFIG": "/nonexistent"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
BOOT = re.compile(rb"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n\Z")
DOCKER_TIME = re.compile(
    r"(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z\Z"
)
INFO = (
    '{"id":{{json .ID}},"os":{{json .OSType}},"security":{{json .SecurityOptions}},'
    '"storage":{{json .Driver}}}'
)
CONTAINER = (
    '{"id":{{json .Id}},"image":{{json .Image}},"created":{{json .Created}},'
    '"start":{{json .State.StartedAt}},"pid":{{json .State.Pid}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},'
    '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
    '"dead":{{json .State.Dead}},"auto_remove":{{json .HostConfig.AutoRemove}},'
    '"restart_policy":{{json .HostConfig.RestartPolicy.Name}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"mounts":{{json .Mounts}}}'
)


class Refused(ValueError):
    """Use a closed failure code without Docker diagnostics."""


def need(condition, code="scope_changed"):
    if not condition:
        raise Refused(code)


def match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = dict(pairs)
        need(len(value) == len(pairs), "policy_refused")
        return value

    def invalid(_value):
        raise Refused("policy_refused")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, RecursionError):
        raise Refused("policy_refused") from None


def integer(value, low=0, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def invoke(argv, maximum, timeout):
    result = subprocess.run(  # noqa: S603 - fixed local Docker argv with an exact full hex CID.
        argv,
        env=ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    need(
        result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= maximum,
        "operation_unconfirmed",
    )
    return result.stdout


def command(args, maximum, timeout):
    return invoke((*DOCKER, *args), maximum, timeout)


def birth(pid):
    need(integer(pid, 2, 2**22))
    raw = (Path("/proc") / str(pid) / "stat").read_bytes()
    fields = raw.rsplit(b") ", 1)[-1].split()
    need(len(fields) >= 20 and fields[0] not in {b"Z", b"X"} and fields[19].isdigit())
    started = int(fields[19])
    need(integer(started, 1))
    return started


def boot_digest():
    raw = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    need(BOOT.fullmatch(raw) is not None)
    return hashlib.sha256(raw).hexdigest()


def activated_daemon():
    # On systemd socket activation, SO_PEERCRED can identify the listener creator (PID 1).
    need(Path("/proc/1/exe").resolve(strict=True) == Path("/usr/lib/systemd/systemd"))
    raw = invoke(
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
        4096,
        3,
    ).decode("ascii")
    pairs = [line.split("=", 1) for line in raw.splitlines()]
    values = dict(pairs)
    need(
        len(pairs) == len(values) == 4
        and values.get("ActiveState") == "active"
        and values.get("SubState") == "running"
        and values.get("ControlGroup") == "/system.slice/docker.service"
        and re.fullmatch(r"[1-9][0-9]{0,7}", values.get("MainPID", "")) is not None
    )
    pid = int(values["MainPID"])
    proc = Path("/proc") / str(pid)
    need(
        proc.stat().st_uid == 0
        and proc.joinpath("cgroup").read_bytes() == b"0::/system.slice/docker.service\n"
    )
    return pid


def socket_witness():
    parent = SOCKET.parent.lstat()
    info = SOCKET.lstat()
    need(
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == 0
        and not parent.st_mode & 0o022
        and stat.S_ISSOCK(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & 0o002
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(str(SOCKET))
        pid, uid, _gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
    current = SOCKET.lstat()
    need(uid == 0 and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino))
    if pid == 1:
        pid = activated_daemon()
    executable = (Path("/proc") / str(pid) / "exe").resolve(strict=True)
    need(executable == Path("/usr/bin/dockerd"))
    return [info.st_dev, info.st_ino, pid, birth(pid)]


def docker_time(value):
    found = DOCKER_TIME.fullmatch(value) if type(value) is str else None
    if found is None:
        raise Refused("scope_changed")
    whole = datetime.fromisoformat(found[1]).replace(tzinfo=UTC)
    return int(whole.timestamp()) * 10**9 + int((found[2] or "").ljust(9, "0"))


def mount_projection(rows):
    need(type(rows) is list and len(rows) <= 32)
    # Only root-local metadata participates in the binding; never open any mount or return a path.
    for row in rows:
        need(
            type(row) is dict
            and row.get("Type") in {"bind", "volume", "tmpfs"}
            and type(row.get("Destination")) is str
            and row["Destination"].startswith("/")
            and type(row.get("RW")) is bool
            and len(canonical(row)) <= 4096
        )
    need(len({row["Destination"] for row in rows}) == len(rows))
    return digest(sorted(rows, key=lambda row: row["Destination"]))


def capture(policy):
    local = socket_witness()
    boot = boot_digest()
    info = decode(command(("info", "--format", INFO), 8192, 5))
    need(
        type(info) is dict
        and set(info) == {"id", "os", "security", "storage"}
        and type(info["id"]) is str
        and re.fullmatch(r"[A-Za-z0-9:-]{8,96}", info["id"])
        and info["os"] == "linux"
        and info["storage"] in {"overlay2", "overlayfs"}
        and type(info["security"]) is list
        and len(info["security"]) <= 16
        and all(type(item) is str and "rootless" not in item for item in info["security"])
    )
    cid = policy["container_id"]
    need(match(HEX, cid), "policy_refused")
    row = decode(command(("container", "inspect", "--format", CONTAINER, cid), 65536, 5))
    need(
        type(row) is dict
        and set(row)
        == {
            "id",
            "image",
            "created",
            "start",
            "pid",
            "status",
            "running",
            "paused",
            "restarting",
            "dead",
            "auto_remove",
            "restart_policy",
            "project",
            "service",
            "mounts",
        }
    )
    need(
        row["id"] == cid
        and row["image"] == policy["image_id"]
        and row["status"] == "running"
        and row["running"] is True
        and all(row[name] is False for name in ("paused", "restarting", "dead", "auto_remove"))
        and row["restart_policy"] in {"no", ""}
        and all(row[name] == (policy["compose_" + name] or "") for name in ("project", "service"))
    )
    pid = row["pid"]
    proc = birth(pid)
    created, started = docker_time(row["created"]), docker_time(row["start"])
    need(created <= started and started > 0 and socket_witness() == local and boot_digest() == boot)
    return {
        "daemon": digest([local, info["id"], info["storage"], boot]),
        "boot": boot,
        "created_ns": created,
        "started_ns": started,
        "pid": pid,
        "birth": proc,
        "mounts": mount_projection(row["mounts"]),
    }


def changed(before, after):
    return (
        all(before[key] == after[key] for key in ("daemon", "boot", "created_ns", "mounts"))
        and after["started_ns"] > before["started_ns"]
        and after["birth"] > before["birth"]
        and after["pid"] != before["pid"]
    )


def restart(container_id):
    need(match(HEX, container_id), "policy_refused")
    raw = command(("container", "restart", "--timeout", "10", container_id), 128, 30)
    need(raw == container_id.encode("ascii") + b"\n", "operation_unconfirmed")
