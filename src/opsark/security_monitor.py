"""Explicit-scope background polling; observations never invoke remediation."""

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from uuid import uuid4

from opsark.baselines import scope_for
from opsark.config import HostConfig, Settings
from opsark.security_events import collect_security
from opsark.security_models import SecurityObservation
from opsark.security_store import SecurityStore
from opsark.web_security_events import collect_web_security, profile_digest, scope_for_web
from opsark.web_security_models import WebSecurityObservation
from opsark.web_security_store import WebSecurityStore

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


class SecurityMonitor:
    def __init__(
        self,
        settings: Settings,
        hosts: dict[str, HostConfig],
        store: SecurityStore,
        investigation_lock: Lock,
        *,
        collector: Callable[[HostConfig], SecurityObservation] | None = None,
        now: Callable[[], datetime] | None = None,
        web_store: WebSecurityStore | None = None,
        web_collector: Callable[[HostConfig], WebSecurityObservation] | None = None,
    ) -> None:
        if any(host_id not in hosts for host_id in settings.observation_host_ids):
            raise ValueError("持续观察目标必须已经登记，不能自动扩大到其他主机。")
        self.settings = settings
        self.hosts = {host_id: hosts[host_id] for host_id in settings.observation_host_ids}
        if any(host.public.source != "ssh" for host in self.hosts.values()):
            raise ValueError("持续观察只支持明确登记的 SSH 主机。")
        self.store = store
        self.lock = investigation_lock
        self.collector = collector or collect_security
        self.web_store = web_store
        self.web_collector = web_collector or collect_web_security
        self.web_error: str | None = None
        if settings.web_observation_enabled and (
            web_store is None
            or any(
                not host.public.web_profile_digest or profile_digest(host.public) == "0" * 64
                for host in self.hosts.values()
            )
        ):
            raise ValueError("启用 Web 观察前必须为每台目标登记已核验的 Web profile 摘要。")
        self.now = now or _now
        self.owner = secrets.token_hex(16)
        self.stop_event = Event()
        self.thread: Thread | None = None
        self.owns_lease = False
        self.last_error: str | None = None
        self.due = {host_id: datetime.min.replace(tzinfo=UTC) for host_id in self.hosts}
        self.web_due = dict(self.due)
        existing = {(state["host_id"], state["scope_hash"]) for state in self.store.host_states()}
        for host_id, host in self.hosts.items():
            if (host_id, scope_for(host.public)) in existing:
                continue
            self.store.set_host_state(
                host_id,
                scope_for(host.public),
                status="starting" if settings.observation_enabled else "stopped",
                detail="等待首次采集。"
                if settings.observation_enabled
                else "部署配置未启用持续观察。",
            )
        if self.settings.web_observation_enabled and self.web_store is not None:
            existing_web = {(s["host_id"], s["scope_hash"]) for s in self.web_store.host_states()}
            for host_id, host in self.hosts.items():
                scope = scope_for_web(host.public)
                if (host_id, scope) not in existing_web:
                    self.web_store.set_host_state(
                        host_id, scope, status="starting", detail="等待首次 Web 读取。"
                    )

    def start(self) -> None:
        if not self.settings.observation_enabled or (self.thread and self.thread.is_alive()):
            return
        self.stop_event.clear()
        self.thread = Thread(target=self._run, name="opsark-security-observer", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=25)
            if self.thread.is_alive():
                logger.error("Security observer has not completed its bounded shutdown.")
                return
        self.owns_lease = False
        self.store.release_monitor(self.owner)

    def _unavailable(self, host: HostConfig, now: datetime) -> SecurityObservation:
        return SecurityObservation(
            id=str(uuid4()),
            host_id=host.public.id,
            scope_hash=scope_for(host.public),
            collected_at=now,
            window_started_at=now - timedelta(minutes=15),
            window_ended_at=now,
            status="unavailable",
            gaps=["持续观察采集未完成；请核验连接、服务端策略和采集组件。"],
        )

    def poll_once(self) -> None:
        if not self.settings.observation_enabled or self.stop_event.is_set():
            return
        now = self.now()
        if not self.store.claim_monitor(self.owner, now, ttl_seconds=90):
            self.owns_lease = False
            return
        self.owns_lease = True
        for host_id, host in self.hosts.items():
            if self.stop_event.is_set() or self.now() < self.due[host_id]:
                continue
            now = self.now()
            if not self.store.claim_monitor(self.owner, now, ttl_seconds=90):
                self.owns_lease = False
                return
            scope = scope_for(host.public)
            if not self.lock.acquire(blocking=False):
                self.due[host_id] = now + timedelta(seconds=5)
                self.store.set_host_state(
                    host_id,
                    scope,
                    status="busy",
                    next_poll=self.due[host_id].isoformat(),
                    detail="其他只读调查正在使用采集通道，等待下一轮；当前没有新的观察结果。",
                )
                continue
            try:
                self.due[host_id] = now + timedelta(
                    seconds=self.settings.observation_interval_seconds
                )
                self.store.set_host_state(host_id, scope, last_attempt=now.isoformat())
                try:
                    batch = self.collector(host)
                    batch = SecurityObservation.model_validate(batch.model_dump())
                    if batch.host_id != host_id or batch.scope_hash != scope:
                        raise ValueError("Collector scope mismatch")
                except Exception:
                    batch = self._unavailable(host, self.now())
                if not self.store.claim_monitor(self.owner, self.now(), ttl_seconds=90):
                    self.owns_lease = False
                    return
                try:
                    result = self.store.ingest(batch)
                except ValueError:
                    batch = self._unavailable(host, self.now())
                    result = self.store.ingest(batch)
                effective_status = result.get("observation_status", batch.status)
                effective_gaps = result.get("gaps", batch.gaps)
                state = {
                    "status": "ok" if effective_status == "complete" else effective_status,
                    "next_poll": self.due[host_id].isoformat(),
                    "last_observation_id": batch.id,
                    "detail": (
                        "本次有限时间窗采集完成，不代表整机安全或不存在入侵。"
                        if effective_status == "complete"
                        else "；".join(effective_gaps)[:500] or "本次观察不完整，不能作为安全依据。"
                    ),
                }
                if effective_status != "unavailable":
                    state["last_success"] = batch.collected_at.isoformat()
                self.store.set_host_state(host_id, scope, **state)
                self.last_error = None
            finally:
                self.lock.release()
        self._poll_web()

    def _poll_web(self) -> None:
        if not self.settings.web_observation_enabled or self.web_store is None:
            return
        for host_id, host in self.hosts.items():
            if self.stop_event.is_set() or self.now() < self.web_due[host_id]:
                continue
            now = self.now()
            if not self.store.claim_monitor(self.owner, now, ttl_seconds=90):
                self.owns_lease = False
                return
            scope = scope_for_web(host.public)
            if not self.lock.acquire(blocking=False):
                self.web_due[host_id] = now + timedelta(seconds=5)
                self.web_store.set_host_state(
                    host_id,
                    scope,
                    status="busy",
                    next_poll=self.web_due[host_id].isoformat(),
                    detail="采集通道繁忙，尚未取得新的 Web 结果。",
                )
                continue
            try:
                self.web_due[host_id] = now + timedelta(
                    seconds=self.settings.observation_interval_seconds
                )
                self.web_store.set_host_state(host_id, scope, last_attempt=now.isoformat())

                def unavailable(host_id=host_id, scope=scope, host=host):
                    instant = self.now()
                    return WebSecurityObservation(
                        id=str(uuid4()),
                        host_id=host_id,
                        scope_hash=scope,
                        profile_digest=profile_digest(host.public),
                        collected_at=instant,
                        window_started_at=instant - timedelta(minutes=15),
                        window_ended_at=instant,
                        status="unavailable",
                        gaps=["Web 采集未完成，请核验固定 reader、配置摘要和连接。"],
                    )

                try:
                    batch = self.web_collector(host)
                    batch = WebSecurityObservation.model_validate(batch.model_dump())
                    if (
                        batch.host_id != host_id
                        or batch.scope_hash != scope
                        or batch.profile_digest != profile_digest(host.public)
                    ):
                        raise ValueError("Web collector scope mismatch")
                except Exception:
                    batch = unavailable()
                if not self.store.claim_monitor(self.owner, self.now(), ttl_seconds=90):
                    self.owns_lease = False
                    return
                try:
                    result = self.web_store.ingest(batch)
                except ValueError:
                    batch = unavailable()
                    result = self.web_store.ingest(batch)
                status = result.get("observation_status", batch.status)
                gaps = result.get("gaps", batch.gaps)
                state = {
                    "status": "ok" if status == "complete" else status,
                    "next_poll": self.web_due[host_id].isoformat(),
                    "last_observation_id": batch.id,
                    "detail": "本次有限 Web 窗口读取完成，不代表不存在攻击。"
                    if status == "complete"
                    else "；".join(gaps)[:500],
                }
                if status != "unavailable":
                    state["last_success"] = batch.collected_at.isoformat()
                self.web_store.set_host_state(host_id, scope, **state)
                self.web_error = None
            except Exception:
                self.web_error = "Web 观察暂时无法完成，请检查本机存储和组件。"
                logger.error("Web observer could not complete its bounded polling cycle.")
            finally:
                self.lock.release()

    def _run(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    self.poll_once()
                except Exception:
                    self.last_error = "持续观察暂时无法完成，请检查本机存储和组件状态。"
                    logger.error("Security observer could not complete its bounded polling cycle.")
                self.stop_event.wait(1)
        finally:
            try:
                self.store.release_monitor(self.owner)
            except Exception:
                logger.error("Security observer lease release did not complete.")
            self.owns_lease = False

    def status(self) -> dict[str, object]:
        states = {
            (state["host_id"], state["scope_hash"]): state for state in self.store.host_states()
        }
        now = self.now()
        hosts = []
        running = bool(self.thread and self.thread.is_alive() and self.owns_lease)
        for host_id, host in self.hosts.items():
            scope = scope_for(host.public)
            state = dict(states.get((host_id, scope), {}))
            state.update({"host_id": host_id, "scope_hash": scope, "name": host.public.name})
            state.setdefault(
                "status", "starting" if self.settings.observation_enabled else "stopped"
            )
            if not self.settings.observation_enabled:
                state.update(status="stopped", detail="部署配置未启用持续观察。")
            elif self.last_error:
                state.update(status="unavailable", detail=self.last_error)
            else:
                success = state.get("last_success")
                if success and now - datetime.fromisoformat(str(success)) > timedelta(
                    seconds=max(120, self.settings.observation_interval_seconds * 3)
                ):
                    state.update(
                        status="stale", detail="最近有效观察已过期；缺少新结果不能解释为安全。"
                    )
                elif not running and self.thread is not None:
                    state.update(
                        status="starting", detail="观察进程尚未取得租约或已停止，结果可能不是最新。"
                    )
            hosts.append(state)
        if self.settings.web_observation_enabled and self.web_store is not None:
            web_states = {(s["host_id"], s["scope_hash"]): s for s in self.web_store.host_states()}
            ranks = {
                "ok": 0,
                "stopped": 1,
                "starting": 2,
                "busy": 3,
                "degraded": 4,
                "stale": 5,
                "unavailable": 6,
            }
            for state in hosts:
                host_id = state["host_id"]
                web = dict(web_states.get((host_id, scope_for_web(self.hosts[host_id].public)), {}))
                web.update(
                    host_id=host_id,
                    scope_hash=scope_for_web(self.hosts[host_id].public),
                    enabled=True,
                )
                web.setdefault("status", "starting")
                if self.web_error or self.last_error:
                    web.update(status="unavailable", detail=self.web_error or self.last_error)
                elif web.get("last_success") and now - datetime.fromisoformat(
                    web["last_success"]
                ) > timedelta(seconds=max(120, self.settings.observation_interval_seconds * 3)):
                    web.update(status="stale", detail="Web 观察已过期，缺少结果不代表安全。")
                elif not running and self.thread is not None:
                    web.update(status="starting", detail="Web 观察进程尚未取得租约或已停止。")
                ssh = dict(state)
                ssh["enabled"] = self.settings.observation_enabled
                state["channels"] = {"ssh": ssh, "web": web}
                if ranks.get(web["status"], 6) > ranks.get(state["status"], 6):
                    state["status"] = web["status"]
                    state["detail"] = "Web：" + str(web.get("detail", "结果尚未取得。"))
                successes = [c.get("last_success") for c in (ssh, web)]
                state["last_success"] = (
                    min(str(value) for value in successes) if all(successes) else None
                )
        return {
            "enabled": self.settings.observation_enabled,
            "running": running,
            "interval_seconds": self.settings.observation_interval_seconds,
            "read_only": True,
            "notification_channel": "console",
            "hosts": hosts,
            "supported_sources": ["system_ssh", "controlled_probe"]
            + (
                ["system_web", "controlled_web_probe"]
                if self.settings.web_observation_enabled
                else []
            ),
            "web_enabled": self.settings.web_observation_enabled,
            "window_seconds": 900,
            "threshold": 5,
        }
