"""Exercise the actual dispatcher loop with elapsed model time and bounded progress."""

import json
from datetime import timedelta
from threading import Event
from types import SimpleNamespace
from typing import cast

import httpx
from test_defense_ai import OUTPUT, wire
from test_defense_client import keyset as keyset
from test_defense_client import target as target
from test_defense_session_coordinator import REF, cost_counts, start
from test_defense_session_coordinator import harness as harness
from test_defense_session_coordinator import no_real_transport as no_real_transport
from test_defense_session_coordinator import scene as scene

from opsark.defense_session_worker import DefenseSessionWorker, SessionCoordinator


class OneCycle(Event):
    def __init__(self, worker, on_wait):
        super().__init__()
        self.worker, self.on_wait = worker, on_wait
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.on_wait()
        self.worker.stopped.set()
        return False


def test_slow_model_completes_one_original_session_before_poll_wait(scene, monkeypatch):
    s = scene(requires_ai=True)

    def respond(_request):
        s.clock[0] += timedelta(seconds=19.99)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(OUTPUT)},
                    }
                ]
            },
        )

    calls = wire(monkeypatch, s.provider_state, handler=respond)
    initial = start(s)
    worker = DefenseSessionWorker(s.coordinator, enabled=True)

    def finished():
        record = s.coordinator.get(REF)
        assert record.phase == record.effective_phase == "completed"
        assert record.business_verdict == "pending"
        assert record.declaration == initial.declaration
        assert len(calls) == 1 and cost_counts(s) == (("ai", 1), ("execution", 1))
        assert sum(op == "apply" for op, _ in s.root.sent) == 1

    signal = OneCycle(worker, finished)
    worker._wake = signal
    worker._run()
    assert signal.waits == [5]


def test_unchanged_phase_waits_without_spinning_or_discovering_history():
    class Busy:
        calls = 0

        def owned_session_refs(self):
            return (REF,)

        def tick(self, ref):
            assert ref == REF
            self.calls += 1
            return SimpleNamespace(phase="analyzing", effective_phase="analyzing", revision=2)

    coordinator = Busy()
    worker = DefenseSessionWorker(cast(SessionCoordinator, coordinator), enabled=True)
    signal = OneCycle(worker, lambda: None)
    worker._wake = signal
    worker._run()
    assert coordinator.calls == 2 and signal.waits == [5]


def test_progress_burst_is_bounded_even_for_unexpected_nonterminal_coordinator():
    class Changing:
        calls = 0

        def owned_session_refs(self):
            return (REF,)

        def tick(self, ref):
            assert ref == REF
            self.calls += 1
            return SimpleNamespace(
                phase="analyzing", effective_phase="analyzing", revision=self.calls
            )

    coordinator = Changing()
    worker = DefenseSessionWorker(cast(SessionCoordinator, coordinator), enabled=True)
    signal = OneCycle(worker, lambda: None)
    worker._wake = signal
    worker._run()
    assert coordinator.calls == 8 and signal.waits == [5]
