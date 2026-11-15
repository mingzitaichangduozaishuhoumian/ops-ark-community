#!/usr/bin/env python3
"""Collect live disk faults from bounded private tmpfs roots through exact SSH commands."""

import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from docker_lab.ssh_server import DockerLabSSH  # noqa: E402 -- standalone fixture source paths.
from fastapi.testclient import TestClient  # noqa: E402

from opsark.collector import commands_for  # noqa: E402
from opsark.config import HostConfig, Settings  # noqa: E402
from opsark.diagnostics import _df  # noqa: E402
from opsark.models import HostPublic  # noqa: E402

LABEL = "opsark.test.filesystem-lab"
TARGET_SCRIPT = "/fixture-state/target.py"
MEMORY_BYTES = 192 * 1024 * 1024
BYTE_ROOT_BYTES = 32 * 1024 * 1024
INODE_ROOT_BYTES = 2 * 1024 * 1024 * 1024
CHECKS = ("os_release", "platform_tools", "disk_bytes", "disk_inodes", "disk_directories")
DIRECTORIES = ("/var/log/nginx", "/var/log/journal", "/srv", "/var/lib/docker/containers")
INIT_SCRIPT = """import os
import signal
import time

def reap(_signal=None, _frame=None):
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return

def stop(_signal, _frame):
    os._exit(0)

signal.signal(signal.SIGCHLD, reap)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
deadline = time.monotonic() + 300
while time.monotonic() < deadline:
    reap()
    time.sleep(0.05)
os._exit(0)
"""


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def app_factory(directory: Path):
    previous = {name: value for name, value in os.environ.items() if name.startswith("OPSARK_")}
    for name in previous:
        os.environ.pop(name)
    os.environ["OPSARK_DATA_DIR"] = str(directory / "bootstrap")
    try:
        from opsark.main import create_app
    finally:
        os.environ.pop("OPSARK_DATA_DIR", None)
        os.environ.update(previous)
    return create_app


class Fixture:
    def __init__(self, directory: Path, image: str, *, inode: bool, web: bool = False) -> None:
        executable = shutil.which("docker")
        if executable is None:
            raise RuntimeError("The local Docker CLI is required")
        config = directory / "docker-config"
        config.mkdir(mode=0o700)
        self.base = (executable, "--host", "unix:///var/run/docker.sock", "--config", str(config))
        self.label = secrets.token_hex(8)
        self.name = f"opsark-filesystem-lab-{self.label}"
        self.image = image
        self.inode = inode
        self.web = web
        self.identity: str | None = None

    def call(self, *args: str, payload: bytes | None = None) -> bytes:
        environment = os.environ.copy()
        for name in (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            environment.pop(name, None)
        result = subprocess.run(  # noqa: S603 -- fixed local Docker and fixture-owned operands.
            [*self.base, *args],
            input=payload,
            stdin=subprocess.DEVNULL if payload is None else None,
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        operation = args[0]
        if operation == "exec":
            for name in ("target.py", "mixed.py"):
                if any(Path(value).name == name for value in args):
                    operation += " " + name
                    break
            if args[-1] in {
                "initialize",
                "state",
                "logs",
                "business",
                "deleted-open",
                "inodes",
                "reset",
                "start",
                "stop-upstream",
                "start-upstream",
                "stop",
            }:
                operation += " " + args[-1]
        require(
            result.returncode == 0 and len(result.stdout) <= 16_384,
            f"Filesystem fixture Docker {operation} failed",
        )
        return result.stdout.strip()

    def __enter__(self):
        image = self.call(
            "image", "inspect", "--format", '{{.Id}} {{json (index .Config "Volumes")}}', self.image
        )
        require(
            image.decode("ascii").split() in ([self.image, "null"], [self.image, "{}"]),
            "The filesystem image must be pinned and have no volumes",
        )
        size = "2g" if self.inode else "32m"
        created = self.call(
            "create",
            "--pull",
            "never",
            "--name",
            self.name,
            "--label",
            f"{LABEL}={self.label}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_CHROOT",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "0:0",
            "--no-healthcheck",
            "--memory",
            "192m",
            "--memory-swap",
            "192m",
            "--pids-limit",
            "32",
            "--cpus",
            "0.25",
            "--log-driver",
            "none",
            "--tmpfs",
            f"/fixture-root:rw,exec,nosuid,nodev,size={size},nr_inodes=256,mode=0755",
            "--tmpfs",
            "/fixture-state:rw,nosuid,nodev,noexec,size=4m,mode=0700",
            "--entrypoint",
            "/usr/bin/python3",
            self.image,
            "-I",
            "-B",
            "-c",
            INIT_SCRIPT,
        ).decode("ascii")
        require(re.fullmatch(r"[0-9a-f]{64}", created), "No immutable filesystem container ID")
        self.identity = created
        try:
            self.call("start", created)
            output = self.call("inspect", "--format", "{{json .HostConfig}}", created)
            config = json.loads(output)
            require(
                config["NetworkMode"] == "none"
                and config["ReadonlyRootfs"] is True
                and config["Memory"] == config["MemorySwap"] == MEMORY_BYTES
                and config["PidsLimit"] == 32
                and config["NanoCpus"] == 250_000_000
                and config["CapDrop"] == ["ALL"]
                and config["CapAdd"] in (["SYS_CHROOT"], ["CAP_SYS_CHROOT"])
                and not config.get("Binds")
                and not config.get("PortBindings")
                and set(config["Tmpfs"]) == {"/fixture-root", "/fixture-state"},
                "The filesystem fixture escaped its fixed resource or mount scope",
            )
            mounts = json.loads(self.call("inspect", "--format", "{{json .Mounts}}", created))
            require(
                all(
                    item["Type"] == "tmpfs"
                    and item["Destination"] in {"/fixture-root", "/fixture-state"}
                    for item in mounts
                ),
                "Unexpected host mount in filesystem fixture",
            )
            program = """import os
import sys

data = sys.stdin.buffer.read(65537)
assert 0 < len(data) <= 65536
fd = os.open('/fixture-state/target.py',
             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as handle:
    handle.write(data)
    handle.flush()
    os.fsync(handle.fileno())
"""
            self.call(
                "exec",
                "-i",
                created,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                program,
                payload=(ROOT / "tests/filesystem_lab/target.py").read_bytes(),
            )
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args: object) -> None:
        if self.identity is None:
            return
        binding = (
            self.call(
                "inspect",
                "--format",
                f'{{{{.Id}}}} {{{{.Image}}}} {{{{index .Config.Labels "{LABEL}"}}}}',
                self.identity,
            )
            .decode("ascii")
            .split()
        )
        require(
            binding == [self.identity, self.image, self.label],
            "Filesystem cleanup identity changed",
        )
        self.call("rm", "--force", self.identity)

    def state(self, mode: str) -> dict:
        profile = (
            *(("--inode-profile",) if self.inode else ()),
            *(("--web-profile",) if self.web else ()),
        )
        output = self.call(
            "exec",
            str(self.identity),
            "/usr/bin/python3",
            "-I",
            "-B",
            TARGET_SCRIPT,
            *profile,
            mode,
        )
        value = json.loads(output)
        require(
            set(value)
            == {
                "mode",
                "bytes_total",
                "bytes_used",
                "bytes_available",
                "inodes_total",
                "inodes_free",
                "enospc",
                "held_bytes",
            },
            "Unexpected native filesystem proof",
        )
        require(
            all(
                type(value[name]) is int and value[name] >= 0
                for name in value
                if name not in {"mode", "enospc"}
            )
            and type(value["enospc"]) is bool
            and value["bytes_total"] == (INODE_ROOT_BYTES if self.inode else BYTE_ROOT_BYTES)
            and value["inodes_total"] == 256,
            "The native filesystem did not retain its fixed bounds",
        )
        return value


def evidence(report: dict, name: str) -> dict:
    values = [item for item in report["evidence"] if item["check_id"] == name]
    require(len(values) == 1, "The disk report did not contain unique fixed evidence")
    item = values[0]
    require(
        item["source"] == "ssh"
        and item["status"] == "ok"
        and item["exit_code"] == 0
        and not item["truncated"],
        f"Native filesystem evidence was incomplete ({name}, {item['status']}, "
        f"exit={item['exit_code']}, truncated={item['truncated']})",
    )
    return item


def measurements(
    report: dict,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int], dict[str, int]]:
    capacity = _df(evidence(report, "disk_bytes")["output"])
    inodes = _df(evidence(report, "disk_inodes")["output"], inode=True)
    if capacity is None or inodes is None:
        raise RuntimeError("Native df formatting is outside the current production parser")
    directories = {}
    for line in evidence(report, "disk_directories")["output"].splitlines():
        match = re.fullmatch(r"\s*([0-9]+)\s+(/[^\r\n]+)\s*", line)
        if match:
            directories[match[2].strip()] = int(match[1])
    require(
        set(directories) == set(DIRECTORIES), "Native du did not cover the four fixed directories"
    )
    require(
        report["source"] == "ssh"
        and report["action"]["executable"] is False
        and report["comparison"]["restore_capable"] is False
        and not any(item["status"] == "passed" for item in report["verification"]),
        "A read-only disk observation was presented as a completed recovery",
    )
    require(
        any("开放文件引用" in gap and "实际可回收空间未核实" in gap for gap in report["missing"]),
        "The report omitted its unresolved file-reference and reclaim-space gap",
    )
    return capacity, inodes, directories


def run_profile(directory: Path, image: str, *, inode: bool) -> dict[str, bool | int]:
    create_app = app_factory(directory)
    with Fixture(directory, image, inode=inode) as target:
        target.state("initialize")
        public = HostPublic(
            id="filesystem-inodes" if inode else "filesystem-bytes",
            name="Private tmpfs fixture",
            address="127.0.0.1",
            username="opsark-lab",
            site_domain="fixture.invalid",
            source="ssh",
        )
        host = HostConfig(public, directory / "pending", directory / "pending")
        commands = commands_for(host, "disk")
        require(tuple(commands) == CHECKS, "Disk collection extended beyond the five exact checks")
        with DockerLabSSH(directory, set(commands.values())) as bridge:
            bridge.allowed = {
                "LC_ALL=C " + command: [
                    *target.base,
                    "exec",
                    "--env",
                    "LC_ALL=C",
                    str(target.identity),
                    "/usr/sbin/chroot",
                    "/fixture-root",
                    *shlex.split(command),
                ]
                for command in commands.values()
            }
            inventory = directory / "inventory.toml"
            inventory.write_text(
                "[credentials.fixture]\nkey_file = "
                + json.dumps(str(bridge.key_file))
                + "\nknown_hosts_file = "
                + json.dumps(str(bridge.known_hosts_file))
                + f'\n[[hosts]]\nid = "{public.id}"\nname = "Private tmpfs fixture"\n'
                + f'address = "127.0.0.1"\nport = {bridge.port}\nusername = "opsark-lab"\n'
                + 'site_domain = "fixture.invalid"\ncredential = "fixture"\n',
                encoding="utf-8",
            )
            settings = Settings(
                data_dir=directory / "reports",
                token=secrets.token_urlsafe(32),
                inventory_path=inventory,
            )
            auth = {"Authorization": "Bearer " + settings.token}
            expected = ["LC_ALL=C " + command for command in commands.values()]
            with TestClient(create_app(settings)) as client:

                def investigate() -> tuple[dict, tuple, tuple, dict]:
                    before = len(bridge.executed)
                    response = client.post(
                        "/api/investigations",
                        headers=auth,
                        json={"source": "ssh", "scenario": "disk", "host_id": public.id},
                    )
                    require(response.status_code == 200, "The normal disk investigation API failed")
                    require(
                        bridge.executed[before:] == expected,
                        "SSH executed a different filesystem command",
                    )
                    report = response.json()
                    capacity, inodes, directories = measurements(report)
                    return report, capacity, inodes, directories

                baseline, normal_bytes, normal_inodes, _ = investigate()
                native = target.state("state")
                require(
                    normal_bytes[0] * 1024 == native["bytes_total"]
                    and normal_bytes[1] * 1024 == native["bytes_used"]
                    and normal_inodes[2] == native["inodes_free"],
                    "The baseline differed from native statfs",
                )
                saved = client.post(
                    f"/api/reports/{baseline['id']}/baseline",
                    headers=auth,
                    json={"confirm_observation_only": True},
                )
                require(
                    saved.status_code in (200, 201) and saved.json()["restore_capable"] is False,
                    "The disk baseline was not saved as an observation",
                )
                if inode:
                    require(
                        normal_bytes[2] * 1024 > 1024**3,
                        "The inode control lacks healthy byte capacity",
                    )
                    result = target.state("inodes")
                    report, capacity, inode_counts, _ = investigate()
                    require(
                        result["enospc"] is True
                        and inode_counts[2] <= 1
                        and capacity[2] * 1024 > 1024**3
                        and capacity[3] < 25,
                        "Native inode ENOSPC was not isolated from byte pressure",
                    )
                    candidates = report["candidates"]
                    require(
                        any(
                            "inode 使用率偏高" in item["text"]
                            and item["evidence_ids"] == ["E-DISK-INODES"]
                            for item in candidates
                        )
                        and not any("根分区空间已达到" in item["text"] for item in candidates),
                        "The inode candidate lost direct evidence or acquired byte pressure",
                    )
                else:
                    for mode, path, category in (
                        ("logs", "/var/log/nginx", "日志目录"),
                        ("business", "/srv", "业务或持久化数据"),
                    ):
                        target.state(mode)
                        report, capacity, _, directories = investigate()
                        require(
                            capacity[1] - normal_bytes[1] >= 16 * 1024
                            and directories[path] >= 16 * 1024,
                            "The bounded allocation did not appear in native df and du",
                        )
                        require(
                            any(
                                path in item["text"]
                                and category in item["text"]
                                and item["evidence_ids"] == ["E-DISK-DIRECTORIES"]
                                for item in report["facts"]
                            ),
                            "The native directory allocation was not classified from its evidence",
                        )
                        require(
                            report["comparison"]["status"] == "compared",
                            "The disk baseline was not compared",
                        )
                    held = target.state("deleted-open")
                    _, capacity, _, directories = investigate()
                    require(
                        held["held_bytes"] >= 16 * 1024**2
                        and capacity[1] - normal_bytes[1] >= 16 * 1024
                        and capacity[1] - sum(directories.values()) >= 16 * 1024,
                        "The live unlinked file did not retain the native df/du discrepancy",
                    )
                target.state("reset")
                _, restored_bytes, restored_inodes, _ = investigate()
                require(
                    abs(restored_bytes[1] - normal_bytes[1]) <= 64
                    and restored_inodes[2] == normal_inodes[2],
                    "The isolated filesystem did not return to its measured baseline",
                )
    return {
        "live_native_df_du_collected": True,
        "observation_baseline_compared": True,
        "business_recovery_left_unverified": True,
        "restored_measurements_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        require(
            sys.platform == "linux" and Path("/var/run/docker.sock").is_socket(),
            "A disposable Linux runner's local Docker Engine is required",
        )
        require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "Use a pinned local filesystem image"
        )
        with tempfile.TemporaryDirectory(prefix="opsark-filesystem-") as temporary:
            directory = Path(temporary)
            for name, inode in (("bytes", False), ("inodes", True)):
                profile = directory / name
                profile.mkdir(mode=0o700)
                run_profile(profile, args.image, inode=inode)
        print(
            json.dumps(
                {
                    "lab_only": True,
                    "exact_disk_commands_over_ssh": True,
                    "normal_and_restore_native_measurements": True,
                    "logs_and_business_classified": True,
                    "deleted_open_df_du_discrepancy": True,
                    "inode_enospc_with_healthy_byte_capacity": True,
                    "no_automatic_action_or_reclaim_estimate": True,
                },
                sort_keys=True,
            )
        )
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("The isolated filesystem experiment could not be verified.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
