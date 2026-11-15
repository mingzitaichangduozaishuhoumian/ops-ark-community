"""Private startup witness for one closed systemd Nginx launch scope.

The host integration must provide native evidence. This module exposes no CLI.
"""

import os
import re
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Protocol

from deploy.nginx import action_journal as journal

if sys.platform == "linux":
    import fcntl

UNIT = "nginx.service"
CGROUP = "/system.slice/nginx.service"
CONFIG_PATH = "/etc/nginx/nginx.conf"
_HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_PROPERTIES = {
    "Id",
    "Type",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
}
_RECORD_NAME = re.compile(r"[0-9a-f]{32}\.(?:pre|post)\.json\Z")
_PENDING_NAME = re.compile(r"\.pending-[0-9a-f]{32}\Z")
_MAX_RECORDS = 128
_MAX_START_SECONDS = 120
_SEAL = "witness_sha256"
type Phase = Literal["pre", "post", "current"]


class StartupRefused(ValueError):
    """Native startup evidence is absent or outside the supported scope."""


def _require(condition: bool) -> None:
    if not condition:
        raise StartupRefused("Nginx startup witness unavailable")


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _integer(value: object, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


def _invocation(value: object) -> bool:
    return _matches(_HEX_ID, value) and value != "0" * 32


def _boot(value: object) -> bool:
    return _matches(_BOOT_ID, value) and value != "00000000-0000-0000-0000-000000000000"


def _pid(value: str) -> int:
    _require(re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None)
    result = int(value)
    _require(result < 2**31)
    return result


@dataclass(frozen=True)
class UnitState:
    invocation_id: str
    active: str
    substate: str
    main_pid: int
    control_pid: int


def parse_unit_properties(raw: bytes) -> UnitState:
    """Validate a fixed-property systemctl show response without retaining raw output."""
    _require(type(raw) is bytes and 0 < len(raw) <= 2048)
    try:
        rows = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        _require(len(rows) == len(_PROPERTIES) and all(len(row) == 2 for row in rows))
        values = dict(rows)
        _require(
            set(values) == _PROPERTIES
            and values["Id"] == UNIT
            and values["Type"] == "forking"
            and values["LoadState"] == "loaded"
            and values["ControlGroup"] == CGROUP
            and _invocation(values["InvocationID"])
            and (values["ActiveState"], values["SubState"])
            in {("activating", "start-pre"), ("activating", "start-post"), ("active", "running")}
        )
        return UnitState(
            values["InvocationID"],
            values["ActiveState"],
            values["SubState"],
            _pid(values["MainPID"]),
            _pid(values["ControlPID"]),
        )
    except UnicodeError:
        raise StartupRefused("Nginx startup witness unavailable") from None


@dataclass(frozen=True)
class HookIdentity:
    invocation_id: str
    effective_uid: int
    pid: int
    cgroup: str


@dataclass(frozen=True)
class BootClock:
    boot_id: str
    ticks: int
    ticks_per_second: int


@dataclass(frozen=True)
class DiskGraph:
    policy_sha256: str
    full_sha256: str
    non_target_sha256: str


@dataclass(frozen=True)
class MasterIdentity:
    pid: int
    born_at_ticks: int
    identity_sha256: str
    explicit_config_path: str


class Evidence(Protocol):
    """Local native provider, with no caller-controlled arguments or raw output."""

    def unit(self) -> UnitState: ...

    def clock(self) -> BootClock: ...

    def graph(self) -> DiskGraph: ...

    def master(self, pid: int, graph: DiskGraph) -> MasterIdentity:
        """Pin the exact root master and verify its executable, effective paths and pidfd.

        During post, PID zero requests the unique pinned PID-file candidate.
        """
        ...


@dataclass(frozen=True)
class _Sample:
    unit: UnitState
    clock: BootClock
    graph: DiskGraph
    master: MasterIdentity | None


def _clock(value: BootClock) -> None:
    _require(
        _boot(value.boot_id)
        and _integer(value.ticks, 1, 2**63 - 1)
        and _integer(value.ticks_per_second, 1, 100_000)
    )


def _graph(value: DiskGraph) -> None:
    _require(all(_matches(_SHA, field) for field in asdict(value).values()))


def _unit(value: UnitState, phase: Phase, hook: HookIdentity | None) -> None:
    _require(
        _invocation(value.invocation_id)
        and _integer(value.main_pid, 0, 2**31 - 1)
        and _integer(value.control_pid, 0, 2**31 - 1)
    )
    if phase == "current":
        _require(
            hook is None
            and value.active == "active"
            and value.substate == "running"
            and value.main_pid > 1
            and value.control_pid == 0
        )
        return
    _require(hook is not None)
    assert hook is not None  # noqa: S101 - guarded above for static narrowing.
    _require(
        type(hook.effective_uid) is int
        and hook.effective_uid == 0
        and _integer(hook.pid, 2, 2**31 - 1)
        and hook.invocation_id == value.invocation_id
        and hook.cgroup == CGROUP
        and value.active == "activating"
        and value.control_pid == hook.pid
        and (
            (phase == "pre" and value.substate == "start-pre" and value.main_pid == 0)
            or (
                phase == "post"
                and value.substate == "start-post"
                and (value.main_pid == 0 or (value.main_pid > 1 and value.main_pid != hook.pid))
            )
        )
    )


def _master(value: MasterIdentity, unit: UnitState, ticks: int, *, phase: Phase) -> None:
    _require(
        _integer(value.pid, 2, 2**31 - 1)
        and value.pid != unit.control_pid
        and (value.pid == unit.main_pid or (phase == "post" and unit.main_pid == 0))
        and _integer(value.born_at_ticks, 1, ticks)
        and _matches(_SHA, value.identity_sha256)
        and value.explicit_config_path == CONFIG_PATH
    )


def _sample(source: Evidence, phase: Phase, hook: HookIdentity | None = None) -> _Sample:
    unit = source.unit()
    _unit(unit, phase, hook)
    start, graph = source.clock(), source.graph()
    _clock(start)
    _graph(graph)
    master = None if phase == "pre" else source.master(unit.main_pid, graph)
    if master is not None:
        _master(master, unit, start.ticks, phase=phase)
    _require(source.graph() == graph and source.unit() == unit)
    if master is not None:
        _require(source.master(unit.main_pid, graph) == master)
    end = source.clock()
    _clock(end)
    _require(
        (end.boot_id, end.ticks_per_second) == (start.boot_id, start.ticks_per_second)
        and end.ticks >= start.ticks
        and (phase == "pre" or master is not None)
    )
    return _Sample(unit, end, graph, master)


def _pre_fields(sample: _Sample) -> dict:
    return {
        "schema_version": 1,
        "kind": "pre",
        "invocation_id": sample.unit.invocation_id,
        "clock": asdict(sample.clock),
        "graph": asdict(sample.graph),
    }


def _read_pre(
    fd: int, sample: _Sample, *, allow_target_change: bool = False
) -> tuple[dict, BootClock]:
    invocation = sample.unit.invocation_id
    record = journal._record(fd, f"{invocation}.pre.json", _SEAL)
    if record is None:
        raise StartupRefused("Nginx startup witness unavailable")
    fields = _pre_fields(sample)
    _require(
        set(record) == {*fields, _SEAL}
        and type(record["schema_version"]) is int
        and all(record[key] == fields[key] for key in fields if key not in {"clock", "graph"})
        and type(record["clock"]) is dict
        and set(record["clock"]) == set(fields["clock"])
        and type(record["graph"]) is dict
        and set(record["graph"]) == set(fields["graph"])
    )
    clock = BootClock(**record["clock"])
    original_graph = DiskGraph(**record["graph"])
    _clock(clock)
    _graph(original_graph)
    _require(
        (clock.boot_id, clock.ticks_per_second)
        == (sample.clock.boot_id, sample.clock.ticks_per_second)
        and original_graph.policy_sha256 == sample.graph.policy_sha256
        and original_graph.non_target_sha256 == sample.graph.non_target_sha256
        and (allow_target_change or original_graph.full_sha256 == sample.graph.full_sha256)
    )
    return record, clock


def _post_fields(sample: _Sample, pre: dict, clock: BootClock) -> dict:
    master = sample.master
    if master is None:
        raise StartupRefused("Nginx startup witness unavailable")
    _require(clock.ticks < master.born_at_ticks <= sample.clock.ticks)
    return {
        "schema_version": 1,
        "kind": "post",
        "invocation_id": sample.unit.invocation_id,
        "pre_sha256": pre[_SEAL],
        "clock": asdict(sample.clock),
        "master": asdict(master),
    }


def _capacity(fd: int, required: int) -> None:
    with os.scandir(fd) as entries:
        for count, entry in enumerate(entries, start=1):
            _require(
                count <= _MAX_RECORDS - required
                and (
                    _RECORD_NAME.fullmatch(entry.name) is not None
                    or _PENDING_NAME.fullmatch(entry.name) is not None
                )
            )


class StartupWitness:
    """Bounded root-private before/after evidence, one pair per systemd invocation."""

    def __init__(self, directory: Path):
        self._directory = directory

    @contextmanager
    def _locked(self) -> Generator[int]:
        with journal._directory(self._directory, durable=True) as fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StartupRefused("Nginx startup witness unavailable") from None
            yield fd

    def record_pre(self, source: Evidence, hook: HookIdentity) -> None:
        with self._locked() as fd:
            _capacity(fd, 2)
            sample = _sample(source, "pre", hook)
            name = f"{sample.unit.invocation_id}.pre.json"
            journal._publish(fd, name, _pre_fields(sample), _SEAL)

    def record_post(self, source: Evidence, hook: HookIdentity) -> None:
        with self._locked() as fd:
            _capacity(fd, 1)
            sample = _sample(source, "post", hook)
            pre, clock = _read_pre(fd, sample)
            elapsed = sample.clock.ticks - clock.ticks
            _require(elapsed <= _MAX_START_SECONDS * clock.ticks_per_second)
            fields = _post_fields(sample, pre, clock)
            journal._publish(fd, f"{sample.unit.invocation_id}.post.json", fields, _SEAL)

    def require_current(
        self, source: Evidence, *, expected_origin_sha256: str | None = None
    ) -> str:
        """Return the exact startup seal, optionally bound to a prior approved action.

        The locked action caller still proves the exact intended target state.
        """
        _require(expected_origin_sha256 is None or _matches(_SHA, expected_origin_sha256))
        with self._locked() as fd:
            sample = _sample(source, "current")
            pre, clock = _read_pre(
                fd, sample, allow_target_change=expected_origin_sha256 is not None
            )
            expected = _post_fields(sample, pre, clock)
            record = journal._record(fd, f"{sample.unit.invocation_id}.post.json", _SEAL)
            if record is None:
                raise StartupRefused("Nginx startup witness unavailable")
            _require(
                set(record) == {*expected, _SEAL}
                and type(record["schema_version"]) is int
                and all(record[key] == expected[key] for key in expected if key != "clock")
                and type(record["clock"]) is dict
                and set(record["clock"]) == set(expected["clock"])
                and (expected_origin_sha256 is None or record[_SEAL] == expected_origin_sha256)
            )
            post = BootClock(**record["clock"])
            _clock(post)
            master = sample.master
            assert master is not None  # noqa: S101 - checked by _post_fields.
            _require(
                post.boot_id == clock.boot_id
                and post.ticks_per_second == clock.ticks_per_second
                and master.born_at_ticks <= post.ticks <= sample.clock.ticks
                and post.ticks - clock.ticks <= _MAX_START_SECONDS * clock.ticks_per_second
            )
            os.fsync(fd)
            return record[_SEAL]
