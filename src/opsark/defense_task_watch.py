"""Optional, bounded query-only following of previously submitted defense tasks."""

import secrets
import sqlite3
from datetime import UTC, datetime
from threading import Event, Lock, Thread

from opsark import defense_task_watch_store as watch_limits
from opsark.defense_client import MAX_KNOWN_HOSTS_BYTES, DefenseTarget, _read_file
from opsark.defense_models import digest
from opsark.defense_store import DefenseConflict
from opsark.defense_task_watch_store import DefenseTaskWatchStore, _hosts

ROOT_STATES = frozenset(
    {
        "active",
        "expired",
        "revoked",
        "ready",
        "ready_expired",
        "unknown",
        "not_found",
        "rejected",
    }
)


def now_utc():
    return datetime.now(UTC)


class DefenseTaskWatcher:
    """No model and no mutating method is reachable from a watch tick.

    A stop prevents new sends and commits. An already in-flight read-only RPC can
    finish within its transport deadline, but cannot publish a late result.
    """

    def __init__(
        self,
        controller,
        store: DefenseTaskWatchStore,
        host_ids,
        interval_seconds=60,
        *,
        clock=now_utc,
        enabled=True,
    ):
        if (
            type(enabled) is not bool
            or type(interval_seconds) is not int
            or not 30 <= interval_seconds <= 3600
        ):
            raise ValueError("Task watch needs an explicit switch and bounded interval")
        if type(store) is not DefenseTaskWatchStore or store.base is not controller.store:
            raise ValueError("Task watch must share the original defense ledger")
        hosts = _hosts(host_ids) if enabled or host_ids else ()
        if any(host not in controller.targets for host in hosts):
            raise ValueError("Task watch targets must be explicitly registered")
        self.controller, self.store = controller, store
        self.host_ids, self.interval_seconds, self.enabled = hosts, interval_seconds, enabled
        self.clock = clock
        self.owner = "defense-watch-" + secrets.token_hex(16)
        self.stopped, self.in_flight = Event(), Event()
        self._tick_lock = Lock()
        self._thread = None
        self._reason = "idle" if enabled else "disabled"

    def _registration(self, claim):
        target = self.controller.targets.get(claim.host_id)
        if type(target) is not DefenseTarget:
            raise DefenseConflict("Task watch target registration changed")
        context = self.controller._context(claim.host_id)
        original = self.controller.store.transaction(claim.request_id)
        if context.defense_scope != claim.defense_scope or (
            original.context.host_id != claim.host_id
            or original.context.defense_scope != claim.defense_scope
            or original.kind != "action"
        ):
            raise DefenseConflict("Task watch original scope changed")
        manifest = self.controller.store.manifest(claim.request_id)
        if (
            digest(
                {
                    "v": 1,
                    "host_id": claim.host_id,
                    "request_id": claim.request_id,
                    "manifest_sha256": manifest.sha256,
                }
            )
            != claim.task_reference_sha256
        ):
            raise DefenseConflict("Task watch original manifest changed")
        # Read public trust files only. The ordinary readonly invoker separately
        # validates its own private credential when it actually connects.
        for role in ("readonly", "observe", "control"):
            credential = getattr(target, role)
            _, seal = _read_file(credential.known_hosts_file, MAX_KNOWN_HOSTS_BYTES, private=False)
            if seal != credential._hosts_seal or seal.sha256 != credential.trusted_hosts_digest:
                raise DefenseConflict("Task watch public trust changed")

    def _admit(self, lease, claim):
        if self.stopped.is_set() or self.controller.stopped.is_set() or not self.enabled:
            raise DefenseConflict("Task watch is stopping")
        self.store.assert_claim(lease, claim, now=self.clock())
        self._registration(claim)

    def tick(self):
        if (
            not self.enabled
            or self.stopped.is_set()
            or self.controller.stopped.is_set()
            or not self._tick_lock.acquire(blocking=False)
        ):
            return {"queried": False, "state": None}
        lease = claim = None
        try:
            lease = self.store.acquire(self.owner, now=self.clock())
            if lease is None:
                self._reason = "idle"
                return {"queried": False, "state": None}
            self.store.discover(lease, self.host_ids, now=self.clock())
            claim = self.store.claim_due(lease, self.host_ids, now=self.clock())
            if claim is None:
                self._reason = "idle"
                return {"queried": False, "state": None}
            try:
                self._registration(claim)
            except (ValueError, OSError, KeyError):
                self.store.finish(
                    lease,
                    claim,
                    "registration_changed",
                    interval_seconds=self.interval_seconds,
                    now=self.clock(),
                )
                return {"queried": False, "state": "registration_changed"}

            def admit():
                self._admit(lease, claim)

            def commit_guard(connection):
                # Called while the base ledger already owns BEGIN IMMEDIATE.
                # Never acquire mode_lock or open another write transaction here.
                if self.stopped.is_set() or self.controller.stopped.is_set() or not self.enabled:
                    raise DefenseConflict("Task watch is stopping")
                self.store.assert_claim(lease, claim, now=self.clock(), connection=connection)

            self._admit(lease, claim)
            self.in_flight.set()
            observation, reply = self.controller.query_with_observation(
                claim.host_id, claim.request_id, admit=admit, commit_guard=commit_guard
            )
            self._admit(lease, claim)
            state = (
                reply.state
                if observation.accepted and reply is not None and reply.state in ROOT_STATES
                else "unavailable"
            )
            self.store.finish(
                lease, claim, state, interval_seconds=self.interval_seconds, now=self.clock()
            )
            self._reason = "running"
            return {
                "queried": True,
                "state": state,
                "task_reference_sha256": claim.task_reference_sha256,
            }
        except (ValueError, OSError, RuntimeError, KeyError, sqlite3.Error):
            # A public pin can change at the invoker's final checkpoint. The
            # client hides guard exceptions; classify locally only while this
            # original claim is still ours. No late owner may publish a result.
            if (
                lease is not None
                and claim is not None
                and not (self.stopped.is_set() or self.controller.stopped.is_set())
            ):
                try:
                    self.store.assert_claim(lease, claim, now=self.clock())
                    try:
                        self._registration(claim)
                    except (ValueError, OSError, KeyError):
                        self.store.finish(
                            lease,
                            claim,
                            "registration_changed",
                            interval_seconds=self.interval_seconds,
                            now=self.clock(),
                        )
                        return {"queried": False, "state": "registration_changed"}
                except (ValueError, OSError, sqlite3.Error):
                    pass
            # Fixed code only; never turn an exception message or remote log into
            # an alert or return it to a model-facing entry point.
            self._reason = "stopped" if self.stopped.is_set() else "store_unavailable"
            return {"queried": False, "state": None}
        finally:
            self.in_flight.clear()
            if lease is not None:
                try:
                    self.store.release(lease, now=self.clock())
                except (ValueError, OSError, sqlite3.Error):
                    self._reason = "store_unavailable"
            self._tick_lock.release()

    def _run(self):
        while not self.stopped.is_set():
            self.tick()
            self.stopped.wait(self.interval_seconds)

    def start(self):
        if not self.enabled or self.stopped.is_set() or self.controller.stopped.is_set():
            return False
        if self._thread is None:
            self._thread = Thread(target=self._run, name="opsark-original-task-watch", daemon=True)
            self._thread.start()
        return True

    def stop(self, timeout=35):
        self.stopped.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        return self._thread is None or not self._thread.is_alive()

    def status(self):
        counts = self.store.counts()
        capacity = (
            counts["tasks"] >= watch_limits.MAX_TASKS
            or counts["alerts"] >= watch_limits.MAX_EVENTS - 1
        )
        return {
            "enabled": self.enabled,
            "running": self._thread is not None and self._thread.is_alive(),
            "stopping": self.stopped.is_set(),
            "query_in_flight": self.in_flight.is_set(),
            "host_ids": list(self.host_ids),
            "interval_seconds": self.interval_seconds,
            "continuous_execution": False,
            "reason_code": "disabled"
            if not self.enabled
            else "stopped"
            if self.stopped.is_set()
            else "capacity_limit"
            if capacity
            else self._reason,
            "capacity_limited": capacity,
            "discovery_incomplete": self.enabled and self.store.discovery_incomplete(self.host_ids),
            "counts": counts,
        }
