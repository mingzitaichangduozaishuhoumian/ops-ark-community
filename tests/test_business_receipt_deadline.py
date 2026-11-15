"""A silent exec acknowledgement must not retain an unbounded collector connection."""

import threading
import time
from pathlib import Path

import paramiko

from opsark import collector
from opsark.config import HostConfig
from opsark.models import HostPublic


def test_silent_exec_ack_closes_transport_and_does_not_start_the_next_probe(monkeypatch):
    class SilentPeer:
        def __init__(self):
            self.closed = threading.Event()
            self.commands = []

        def exec_command(self, command, **_kwargs):
            self.commands.append(command)
            assert self.closed.wait(1), "An acknowledgement wait outlived its transport deadline"
            raise paramiko.SSHException("synthetic peer closed")

        def close(self):
            self.closed.set()

    peer = SilentPeer()
    monkeypatch.setattr(collector.paramiko, "SSHClient", lambda: peer)
    monkeypatch.setattr(collector, "_connect_registered", lambda *_: None)
    monkeypatch.setattr(collector, "RECEIPT_COLLECTION_TIMEOUT", 0.04)
    host = HostConfig(
        HostPublic(
            id="deadline-fixture",
            name="synthetic",
            address="192.0.2.10",
            source="ssh",
            trusted_hosts_digest="1" * 64,
        ),
        Path("unused-synthetic-key"),
        Path("unused-synthetic-pin"),
    )
    started = time.monotonic()
    receipts = collector.collect_registered_receipts(
        host,
        {"business_first": "first-fixed-probe", "business_second": "second-fixed-probe"},
        output_limit=96,
    )
    assert peer.closed.is_set() and time.monotonic() - started < 0.8
    assert peer.commands == ["LC_ALL=C first-fixed-probe"]
    assert set(receipts) == {"business_first"}
    assert receipts["business_first"].status == "timeout"
    assert not receipts["business_first"].stdout
    assert "synthetic peer" not in receipts["business_first"].stderr
