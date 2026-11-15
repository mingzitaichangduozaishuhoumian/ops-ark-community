"""Connect the managed Nginx startup witness to its fixed Linux service."""

import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_INSTALL_ROOT = Path("/usr/local/lib/opsark-nginx-action")
_ENTRY = _INSTALL_ROOT / "deploy/nginx/managed_runtime.py"

if __name__ == "__main__":
    try:
        if (
            sys.platform != "linux"
            or os.geteuid() != 0
            or Path(__file__) != _ENTRY
            or not sys.flags.isolated
            or not sys.dont_write_bytecode
        ):
            raise ValueError
        for path in (*_ENTRY.parents, _INSTALL_ROOT / "deploy/readonly"):
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
                raise ValueError
        for name in (
            "deploy/__init__.py",
            "deploy/nginx/__init__.py",
            "deploy/readonly/__init__.py",
            "deploy/nginx/managed_runtime.py",
            "deploy/nginx/managed_startup.py",
            "deploy/nginx/managed_context.py",
            "deploy/nginx/action_journal.py",
            "deploy/nginx/config_snapshot.py",
            "deploy/readonly/nginx_dependencies.py",
        ):
            path = _INSTALL_ROOT / name
            info = path.lstat()
            if (
                info.st_uid != 0
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_mode & 0o022
                or (path.name == "__init__.py" and info.st_size != 0)
            ):
                raise ValueError
        sys.path.insert(0, str(_INSTALL_ROOT))
    except (OSError, ValueError):
        raise SystemExit(126) from None

from deploy.nginx import managed_context as context  # noqa: E402 - verify installed source first.
from deploy.nginx import managed_startup as startup  # noqa: E402

_BOOT = Path("/proc/sys/kernel/random/boot_id")
_CGROUP = Path("/proc/self/cgroup")


@dataclass(frozen=True)
class NativeEvidence:
    policy: context.Policy
    expected_master_sha256: str | None = None

    def unit(self) -> startup.UnitState:
        properties = ",".join(sorted(startup._PROPERTIES))
        output = context._command(
            [context.SYSTEMCTL, "show", f"--property={properties}", startup.UNIT]
        )
        context.require(output.returncode == 0, "scope_changed")
        return startup.parse_unit_properties(output.stdout)

    def clock(self) -> startup.BootClock:
        boot = context._bounded_proc(_BOOT, 64).strip().decode("ascii")
        frequency = os.sysconf("SC_CLK_TCK")
        ticks = time.clock_gettime_ns(time.CLOCK_BOOTTIME) * frequency // 1_000_000_000
        return startup.BootClock(boot, ticks, frequency)

    def _capture(self) -> context.Graph:
        return context.capture_graph(context.active_policy(self.policy.policy_digest))

    def graph(self) -> startup.DiskGraph:
        return _disk_graph(self.policy, self._capture())

    def master(self, pid: int, graph: startup.DiskGraph) -> startup.MasterIdentity:
        captured = self._capture()
        context.require(_disk_graph(self.policy, captured) == graph, "scope_changed")
        if pid == 0:
            # A forking daemon can write its root-owned PID file during start-post,
            # before the manager adopts MainPID. Current proof still requires that adoption.
            raw, _ = context.trusted_read(context.PID_PATH, 32)
            value = raw.strip()
            context.require(re.fullmatch(rb"[1-9][0-9]{0,9}", value) is not None, "scope_changed")
            pid = int(value)
        first = context.inspect_master(self.policy, captured, pid)
        descriptor = os.pidfd_open(pid)
        try:
            signal.pidfd_send_signal(descriptor, 0)
            context.require(
                context.inspect_master(self.policy, captured, pid) == first
                and (self.expected_master_sha256 in {None, first.sha256}),
                "scope_changed",
            )
        finally:
            os.close(descriptor)
        return startup.MasterIdentity(pid, first.birth_tick, first.sha256, str(context.MAIN_CONFIG))


def _disk_graph(policy: context.Policy, graph: context.Graph) -> startup.DiskGraph:
    return startup.DiskGraph(
        policy.policy_digest, graph.sha256, graph.context_sha256(exclude=policy.target)
    )


def _witness() -> startup.StartupWitness:
    return startup.StartupWitness(context.PRIVATE_ROOT / "startup")


def require_started(
    policy: context.Policy,
    graph: context.Graph,
    master: context.Master,
    *,
    origin: str | None = None,
) -> str:
    source = NativeEvidence(policy, master.sha256)
    expected = _disk_graph(policy, graph)
    context.require(source.graph() == expected, "scope_changed")
    try:
        witness = _witness().require_current(source, expected_origin_sha256=origin)
    except (FileNotFoundError, startup.StartupRefused):
        raise context.Refused("scope_changed") from None
    context.require(source.graph() == expected, "scope_changed")
    master.verify(policy, graph)
    return witness


def _hook() -> startup.HookIdentity:
    raw = context._bounded_proc(_CGROUP, 512).strip().decode("ascii")
    context.require(raw.startswith("0::"), "scope_changed")
    return startup.HookIdentity(
        os.environ.get("INVOCATION_ID", ""), os.geteuid(), os.getpid(), raw[3:]
    )


def _wait_next_tick(source: NativeEvidence) -> None:
    initial = source.clock().ticks
    deadline = time.monotonic() + 0.25
    while source.clock().ticks <= initial:
        context.require(time.monotonic() < deadline, "scope_changed")
        time.sleep(0.002)


def _record_post(
    witness: startup.StartupWitness, source: NativeEvidence, hook: startup.HookIdentity
) -> None:
    deadline = time.monotonic() + 3
    while True:
        try:
            witness.record_post(source, hook)
            return
        except (FileNotFoundError, startup.StartupRefused):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.025)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"pre", "post"}:
        return 126

    def timed_out(_signal, _frame):
        raise TimeoutError("Nginx startup witness budget exhausted")

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(8)
    try:
        raw, _ = context.trusted_read(context.POLICY_PATH, context.MAX_POLICY, private=True)
        policy = context.active_policy(context.digest(raw))
        source, witness, hook = NativeEvidence(policy), _witness(), _hook()
        if sys.argv[1] == "pre":
            witness.record_pre(source, hook)
            _wait_next_tick(source)
        else:
            _record_post(witness, source, hook)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return 126
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
