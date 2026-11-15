"""Startup witnesses can authorize only a matched, continuously bound launch."""

import os
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from deploy.nginx import action_journal as journal
from deploy.nginx import managed_startup as startup

INVOCATION = "1" * 32
BOOT_ID = "11111111-1111-1111-1111-111111111111"
GRAPH = startup.DiskGraph("2" * 64, "3" * 64, "4" * 64)
MASTER = startup.MasterIdentity(400, 105, "5" * 64, startup.CONFIG_PATH)
PRE_UNIT = startup.UnitState(INVOCATION, "activating", "start-pre", 0, 300)
POST_UNIT = startup.UnitState(INVOCATION, "activating", "start-post", 400, 301)
POST_WAITING = replace(POST_UNIT, main_pid=0)
RUNNING = startup.UnitState(INVOCATION, "active", "running", 400, 0)
PRE_HOOK = startup.HookIdentity(INVOCATION, 0, 300, startup.CGROUP)
POST_HOOK = startup.HookIdentity(INVOCATION, 0, 301, startup.CGROUP)
_PROPERTIES = (
    b"MainPID=0\nControlPID=300\nType=forking\nId=nginx.service\nLoadState=loaded\n"
    b"ActiveState=activating\nSubState=start-pre\nControlGroup=/system.slice/nginx.service\n"
    b"InvocationID=" + INVOCATION.encode("ascii") + b"\n"
)


class Samples:
    def __init__(self, unit=PRE_UNIT, ticks=100):
        self.state = unit
        self.timing = startup.BootClock(BOOT_ID, ticks, 100)
        self.disk = GRAPH
        self.identity = MASTER

    def unit(self):
        return self.state

    def clock(self):
        return self.timing

    def graph(self):
        return self.disk

    def master(self, pid, graph):
        assert pid == self.state.main_pid and graph == self.disk
        return self.identity


@pytest.fixture
def memory_witness(monkeypatch):
    # Only replace private filesystem persistence. All witness validation is real.
    records = {}
    witness = startup.StartupWitness(Path("/unused/private"))

    @contextmanager
    def locked():
        yield 10

    def publish(_, name, record, seal):
        if name in records:
            raise journal.JournalError("Already exists")
        records[name] = {**record, seal: journal._digest(record)}

    monkeypatch.setattr(witness, "_locked", locked)
    monkeypatch.setattr(startup, "_capacity", lambda *_: None)
    monkeypatch.setattr(startup.os, "fsync", lambda _: None)
    monkeypatch.setattr(journal, "_publish", publish)
    monkeypatch.setattr(journal, "_record", lambda _, name, _seal: records.get(name))
    return witness, records


def test_systemd_parser_only_retains_the_closed_required_properties():
    assert startup.parse_unit_properties(_PROPERTIES) == PRE_UNIT
    for broken in (
        _PROPERTIES.replace(b"MainPID=0", b"MainPID=00"),
        _PROPERTIES.replace(b"Id=nginx.service", b"Id=other.service"),
        _PROPERTIES.replace(b"Type=forking", b"Type=simple"),
        _PROPERTIES.replace(b"SubState=start-pre", b"SubState=unexpected"),
        _PROPERTIES.replace(b"InvocationID=", b"Description="),
        _PROPERTIES.replace(INVOCATION.encode(), b"0" * 32),
        _PROPERTIES + b"ControlPID=300\n",
        _PROPERTIES + b"Extra=blocked\n",
        _PROPERTIES + b"\xff",
    ):
        with pytest.raises(startup.StartupRefused):
            startup.parse_unit_properties(broken)


@pytest.mark.parametrize(
    "hook",
    [
        replace(PRE_HOOK, invocation_id="0" * 32),
        replace(PRE_HOOK, effective_uid=1000),
        replace(PRE_HOOK, pid=301),
        replace(PRE_HOOK, cgroup="/system.slice/other.service"),
    ],
)
def test_mismatched_hook_is_rejected_before_reading_graph(memory_witness, monkeypatch, hook):
    witness, records = memory_witness
    source = Samples()
    monkeypatch.setattr(source, "graph", lambda: pytest.fail("unbound hook accessed disk graph"))
    with pytest.raises(startup.StartupRefused):
        witness.record_pre(source, hook)
    assert not records


def test_missing_pre_or_post_cannot_approve_running_service(memory_witness):
    witness, records = memory_witness
    with pytest.raises(startup.StartupRefused):
        witness.record_post(Samples(POST_UNIT, 110), POST_HOOK)
    assert not records
    witness.record_pre(Samples(), PRE_HOOK)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(Samples(RUNNING, 115))
    assert list(records) == [f"{INVOCATION}.pre.json"]


def test_provisional_post_must_match_mainpid_once_running(memory_witness):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    witness.record_post(Samples(POST_WAITING, 110), POST_HOOK)
    assert records[f"{INVOCATION}.post.json"]["master"]["pid"] == MASTER.pid
    no_adoption = Samples(replace(RUNNING, main_pid=0), 115)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(no_adoption)
    adopted_another = Samples(replace(RUNNING, main_pid=401), 115)
    adopted_another.identity = replace(MASTER, pid=401)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(adopted_another)
    current = witness.require_current(Samples(RUNNING, 115))
    assert current == records[f"{INVOCATION}.post.json"]["witness_sha256"]


@pytest.mark.parametrize(
    "identity",
    [
        replace(MASTER, pid=0),
        replace(MASTER, pid=1),
        replace(MASTER, pid=POST_HOOK.pid),
        replace(MASTER, born_at_ticks=100),
    ],
)
def test_provisional_post_refuses_invalid_candidate(memory_witness, identity):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    source = Samples(POST_WAITING, 110)
    source.identity = identity
    with pytest.raises(startup.StartupRefused):
        witness.record_post(source, POST_HOOK)
    assert list(records) == [f"{INVOCATION}.pre.json"]


def test_provisional_candidate_must_be_unique_and_stable(memory_witness, monkeypatch):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    source = Samples(POST_WAITING, 110)
    candidates = iter([MASTER, replace(MASTER, pid=401)])
    monkeypatch.setattr(source, "master", lambda *_: next(candidates))
    with pytest.raises(startup.StartupRefused):
        witness.record_post(source, POST_HOOK)
    assert list(records) == [f"{INVOCATION}.pre.json"]


def test_unit_graph_and_pid_must_stay_bound_during_each_sample(memory_witness, monkeypatch):
    witness, records = memory_witness
    with monkeypatch.context() as changed:
        source = Samples()
        graphs = iter([GRAPH, replace(GRAPH, full_sha256="b" * 64)])
        changed.setattr(source, "graph", lambda: next(graphs))
        with pytest.raises(startup.StartupRefused):
            witness.record_pre(source, PRE_HOOK)
    assert not records

    witness.record_pre(Samples(), PRE_HOOK)
    with monkeypatch.context() as changed:
        source = Samples(POST_UNIT, 110)
        states = iter([POST_UNIT, RUNNING])
        changed.setattr(source, "unit", lambda: next(states))
        with pytest.raises(startup.StartupRefused):
            witness.record_post(source, POST_HOOK)
    with monkeypatch.context() as changed:
        source = Samples(POST_UNIT, 110)
        masters = iter([MASTER, replace(MASTER, born_at_ticks=107)])
        changed.setattr(source, "master", lambda *_: next(masters))
        with pytest.raises(startup.StartupRefused):
            witness.record_post(source, POST_HOOK)
    assert list(records) == [f"{INVOCATION}.pre.json"]


@pytest.mark.parametrize("scenario", ["full", "non_target", "boot", "birth", "path", "deadline"])
def test_post_rejects_drift_or_unbound_master(memory_witness, scenario):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    source = Samples(POST_UNIT, 110)
    if scenario == "full":
        source.disk = replace(GRAPH, full_sha256="e" * 64)
    elif scenario == "non_target":
        source.disk = replace(GRAPH, non_target_sha256="e" * 64)
    elif scenario == "boot":
        source.timing = replace(source.timing, boot_id="b" + BOOT_ID[1:])
    elif scenario == "birth":
        source.identity = replace(MASTER, born_at_ticks=100)
    elif scenario == "path":
        source.identity = replace(MASTER, explicit_config_path="/etc/nginx/alternate.conf")
    else:
        source.timing = replace(source.timing, ticks=13000)
    with pytest.raises(startup.StartupRefused):
        witness.record_post(source, POST_HOOK)
    assert list(records) == [f"{INVOCATION}.pre.json"]


def test_current_requires_the_same_boot_invocation_graph_and_process_birth(memory_witness):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    witness.record_post(Samples(POST_UNIT, 110), POST_HOOK)
    current = Samples(RUNNING, 115)
    witness.require_current(current)
    original = dict(records)
    for source in (
        Samples(replace(RUNNING, invocation_id="f" * 32), 115),
        Samples(replace(RUNNING, main_pid=401), 115),
        Samples(replace(RUNNING, substate="reload"), 115),
        Samples(replace(RUNNING, control_pid=303), 115),
        Samples(RUNNING, 108),
    ):
        with pytest.raises(startup.StartupRefused):
            witness.require_current(source)
    current.identity = replace(MASTER, born_at_ticks=106)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(current)
    current.identity = MASTER
    current.disk = replace(GRAPH, full_sha256="c" * 64)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(current)
    with pytest.raises(journal.JournalError):
        witness.record_pre(Samples(), PRE_HOOK)
    with pytest.raises(journal.JournalError):
        witness.record_post(Samples(POST_UNIT, 111), POST_HOOK)
    assert records == original


def test_related_action_can_only_reuse_exact_startup_seal_with_target_change(memory_witness):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    witness.record_post(Samples(POST_UNIT, 110), POST_HOOK)
    current = Samples(RUNNING, 115)
    origin = witness.require_current(current)
    assert origin == records[f"{INVOCATION}.post.json"]["witness_sha256"]
    assert witness.require_current(current, expected_origin_sha256=origin) == origin

    current.disk = replace(GRAPH, full_sha256="a" * 64)
    with pytest.raises(startup.StartupRefused):
        witness.require_current(current)
    assert witness.require_current(current, expected_origin_sha256=origin) == origin

    for wrong_seal in ("f" * 64, "F" * 64, "f" * 63):
        with pytest.raises(startup.StartupRefused):
            witness.require_current(current, expected_origin_sha256=wrong_seal)
    for graph in (
        replace(current.disk, non_target_sha256="b" * 64),
        replace(current.disk, policy_sha256="b" * 64),
    ):
        changed = Samples(RUNNING, 115)
        changed.disk = graph
        with pytest.raises(startup.StartupRefused):
            witness.require_current(changed, expected_origin_sha256=origin)

    for unit, clock, identity in (
        (replace(RUNNING, invocation_id="f" * 32), current.timing, MASTER),
        (RUNNING, replace(current.timing, boot_id="b" + BOOT_ID[1:]), MASTER),
        (RUNNING, current.timing, replace(MASTER, identity_sha256="b" * 64)),
        (RUNNING, current.timing, replace(MASTER, born_at_ticks=107)),
    ):
        changed = Samples(unit, 115)
        changed.disk, changed.timing, changed.identity = current.disk, clock, identity
        with pytest.raises(startup.StartupRefused):
            witness.require_current(changed, expected_origin_sha256=origin)


@pytest.mark.parametrize("invalid_full", [None, "b" * 63, "B" * 64, 42])
def test_related_action_still_validates_original_full_graph_field(memory_witness, invalid_full):
    witness, records = memory_witness
    witness.record_pre(Samples(), PRE_HOOK)
    witness.record_post(Samples(POST_UNIT, 110), POST_HOOK)
    pre = records[f"{INVOCATION}.pre.json"]
    post = records[f"{INVOCATION}.post.json"]
    pre["graph"]["full_sha256"] = invalid_full
    pre["witness_sha256"] = journal._digest(
        {key: value for key, value in pre.items() if key != "witness_sha256"}
    )
    post["pre_sha256"] = pre["witness_sha256"]
    post["witness_sha256"] = journal._digest(
        {key: value for key, value in post.items() if key != "witness_sha256"}
    )
    with pytest.raises(startup.StartupRefused):
        witness.require_current(
            Samples(RUNNING, 115), expected_origin_sha256=post["witness_sha256"]
        )


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Requires actual Linux root filesystem locks and ownership",
)
def test_root_private_receipts_survive_reopening_and_refuse_tampering(monkeypatch):
    monkeypatch.setattr(startup, "_MAX_RECORDS", 2)
    with TemporaryDirectory(prefix=".opsark-start-witness-", dir="/root") as root:
        directory = Path(root)
        witness = startup.StartupWitness(directory)
        witness.record_pre(Samples(), PRE_HOOK)
        witness.record_post(Samples(POST_UNIT, 110), POST_HOOK)
        fresh = startup.StartupWitness(directory)
        fresh.require_current(Samples(RUNNING, 115))
        with pytest.raises(startup.StartupRefused):
            fresh.record_pre(Samples(), PRE_HOOK)
        pre = directory / f"{INVOCATION}.pre.json"
        assert pre.stat().st_mode & 0o777 == 0o600
        pre.chmod(0o644)
        with pytest.raises(journal.JournalError):
            fresh.require_current(Samples(RUNNING, 115))
