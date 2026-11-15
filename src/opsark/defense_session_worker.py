"""Default-off dispatch of explicitly started, current-boot single sessions only."""

import sqlite3
from threading import Event, Lock, Thread
from typing import Protocol

from opsark.defense_session_models import SessionRecord

TERMINAL = frozenset({"completed", "stopped", "expired", "reconciliation_only"})
ADVANCING = frozenset(
    {"analyzing", "analysis_ready", "preparing", "prepared", "applying", "confirmed"}
)
MAX_TICKS_PER_CYCLE = 8


class SessionCoordinator(Protocol):
    def owned_session_refs(self) -> tuple[str, ...]: ...
    def tick(self, session_ref: str) -> SessionRecord: ...
    def stop(self, session_ref: str | None = None): ...


class DefenseSessionWorker:
    """Never discovers old sessions or creates arm/mode/grant authority."""

    def __init__(self, coordinator: SessionCoordinator, *, enabled=False, interval_seconds=5):
        if type(enabled) is not bool or type(interval_seconds) is not int or interval_seconds != 5:
            raise ValueError("Session dispatcher requires its explicit switch and fixed interval")
        self.coordinator, self.enabled = coordinator, enabled
        self.interval_seconds = interval_seconds
        self.stopped, self._wake = Event(), Event()
        self._tick_lock = Lock()
        self._thread = None
        self._retired = set()
        self._after = None
        self._reason = "idle" if enabled else "disabled"
        self._progress = {}
        self._continue = False

    def wake(self):
        if self.enabled and not self.stopped.is_set():
            self._wake.set()

    def tick(self):
        self._continue = False
        if not self.enabled or self.stopped.is_set() or not self._tick_lock.acquire(blocking=False):
            return False
        try:
            refs = tuple(
                ref for ref in self.coordinator.owned_session_refs() if ref not in self._retired
            )
            if not refs:
                self._reason = "idle"
                return False
            index = (refs.index(self._after) + 1) % len(refs) if self._after in refs else 0
            reference = refs[index]
            self._after = reference
            result = self.coordinator.tick(reference)
            if result.effective_phase in TERMINAL:
                self._retired.add(reference)
                self._progress.pop(reference, None)
            else:
                marker = (result.phase, result.revision)
                self._continue = (
                    result.phase in ADVANCING and self._progress.get(reference) != marker
                )
                self._progress[reference] = marker
            self._reason = "running"
            return True
        except (ValueError, OSError, RuntimeError, KeyError, sqlite3.Error):
            self._reason = "unavailable"
            return False
        finally:
            self._tick_lock.release()

    def _run(self):
        while not self.stopped.is_set():
            self._wake.clear()
            # Advance only this process's explicitly started sessions. A bounded
            # burst avoids spending source freshness on artificial phase waits;
            # unchanged observations or a busy coordinator still wait normally.
            for _ in range(MAX_TICKS_PER_CYCLE):
                if self.stopped.is_set() or not self.tick() or not self._continue:
                    break
            self._wake.wait(self.interval_seconds)

    def start(self):
        if not self.enabled or self.stopped.is_set():
            return False
        if self._thread is None:
            self._thread = Thread(
                target=self._run, name="opsark-single-defense-session", daemon=True
            )
            self._thread.start()
        return True

    def stop(self, timeout=35):
        # Persist the fence before joining; do not wait for a model or tick lock.
        self.stopped.set()
        self._wake.set()
        fenced = True
        try:
            self.coordinator.stop()
        except (ValueError, OSError, RuntimeError, KeyError, sqlite3.Error):
            self._reason = "unavailable"
            fenced = False
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        return fenced and (self._thread is None or not self._thread.is_alive())

    def status(self):
        return {
            "enabled": self.enabled,
            "running": self._thread is not None and self._thread.is_alive(),
            "stopping": self.stopped.is_set(),
            "session_only": True,
            "continuous_execution": False,
            "max_actions_per_session": 1,
            "interval_seconds": self.interval_seconds,
            "reason_code": "stopped" if self.stopped.is_set() else self._reason,
        }
