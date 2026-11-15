"""Serial polling of original activation IDs; never prepares or resubmits an action."""

import logging
import secrets
import sqlite3
from threading import Event, Lock, Thread

from fastapi import HTTPException

from opsark.activation_store import MAX_RECORDS
from opsark.patch_client import PatchClientError

logger = logging.getLogger(__name__)


class ActivationMonitor:
    def __init__(self, service, *, interval_seconds=15, on_verified=None):
        self.service = service
        self.interval_seconds = interval_seconds
        self.on_verified = on_verified
        self.stop_event = Event()
        self.poll_lock = Lock()
        self.thread = None
        self.owner = secrets.token_hex(16)
        self.last_error = None

    def start(self):
        if not self.service.service.targets or self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = Thread(target=self._run, name="opsark-service-activation", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.thread is None or not self.thread.is_alive():
            self.service.store.release_monitor(self.owner)

    def _observe(self, record):
        if record is None or record["status"] != "verified" or self.on_verified is None:
            return
        self.service.validate_cached(record)
        # Scope is checked before the callback so a reused host label cannot scan
        # a replacement machine on behalf of an old activation.
        target = self.service.service.targets.get(record["host_id"])
        if target is None:
            return
        from opsark.patch_api import PatchService

        if (
            target.policy_digest != record["policy_digest"]
            or PatchService._automatic_scope(target) != record["scope_hash"]
        ):
            return
        if record["rescan_reference"] is None:
            reference = self.on_verified(record)
            if reference is not None:
                self.service.store.attach_rescan(
                    record["host_id"], record["activation_id"], reference
                )

    def poll_once(self):
        if self.stop_event.is_set() or not self.poll_lock.acquire(blocking=False):
            return
        try:
            if not self.service.store.claim_monitor(self.owner, now=self.service.service.now()):
                return
            for record in self.service.store.pollable():
                if self.stop_event.is_set():
                    return
                if not self.service.store.claim_monitor(self.owner, now=self.service.service.now()):
                    return
                try:
                    current = self.service.poll(record["host_id"], record["activation_id"])
                    self._observe(current)
                    self.last_error = None
                except (PatchClientError, HTTPException, ValueError, OSError, sqlite3.Error):
                    self.last_error = "原服务激活状态或复扫关联暂时未能核实；未重发执行。"
            # A crash after accepting the receipt but before writing the rescan
            # reference resumes this idempotent callback without a second restart.
            for record in self.service.store.list(limit=MAX_RECORDS):
                if self.stop_event.is_set():
                    return
                try:
                    self._observe(record)
                except (PatchClientError, HTTPException, ValueError, OSError, sqlite3.Error):
                    self.last_error = "原激活已保存，后续只读复扫关联尚未完成。"
        finally:
            self.poll_lock.release()

    def _run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    self.poll_once()
                except (ValueError, OSError, sqlite3.Error):
                    self.last_error = "服务激活轮询未能核实，原记录保留且不会重新执行。"
                    logger.warning("Service activation polling unavailable; no action resubmitted.")
                self.stop_event.wait(self.interval_seconds)
        finally:
            self.service.store.release_monitor(self.owner)
