"""Poll registered patch jobs; this monitor never scans, prepares or submits patches."""

import logging
import secrets
import sqlite3
from threading import Event, Thread

from fastapi import HTTPException

from opsark.automation_store import StaleModeError
from opsark.patch_api import ModeSynchronizationError, PatchService
from opsark.patch_client import PatchClientError

logger = logging.getLogger(__name__)


class PatchMonitor:
    def __init__(self, service: PatchService, *, interval_seconds: int = 15):
        self.service = service
        self.interval_seconds = interval_seconds
        self.stop_event = Event()
        self.thread: Thread | None = None
        self.owner = secrets.token_hex(16)
        self.last_error: str | None = None

    def start(self) -> None:
        if not self.service.targets or self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = Thread(target=self._run, name="opsark-patch-status", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.thread is None or not self.thread.is_alive():
            self.service.store.release_monitor(self.owner)

    def poll_once(self) -> None:
        if self.stop_event.is_set() or not self.service.targets:
            return
        if not self.service.store.claim_monitor(self.owner):
            return
        mode = self.service.automation.status()
        if not mode["mode_sync_complete"]:
            try:
                self.service.sync_mode()
            except ModeSynchronizationError:
                self.last_error = "模式同步未完成，新修复提交保持停止。"
        for job in self.service.store.pollable_jobs():
            if self.stop_event.is_set():
                break
            if job["host_id"] not in self.service.targets:
                continue
            if not self.service.store.claim_monitor(self.owner):
                return
            try:
                self.service.job_status(job["host_id"], job["job_id"])
                self.last_error = None
            except (PatchClientError, HTTPException, ValueError, OSError, sqlite3.Error):
                self.last_error = "补丁状态暂时未能读取，原任务继续保留，不会重新提交。"

    def _run(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    self.poll_once()
                except StaleModeError:
                    self.last_error = "部署范围已改变，此旧轮询实例停止。"
                    self.stop_event.set()
                    break
                except (ValueError, OSError, sqlite3.Error):
                    self.last_error = "补丁轮询暂时失败，未提交任何新任务。"
                    logger.warning("Patch status polling unavailable; no installation submitted.")
                self.stop_event.wait(self.interval_seconds)
        finally:
            self.service.store.release_monitor(self.owner)
