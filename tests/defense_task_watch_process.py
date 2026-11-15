"""A dedicated owned child for real query-only watcher lifecycle acceptance.

The ordinary offline/live fixtures still reject an enabled watcher. Only this
fixed entry permits it, for one explicit registered host, with models and all
execution/collection workers disabled. No configuration or credential is logged.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import defense_live_process as live  # noqa: E402
from defense_recheck_process_restart import _decode_settings, _json, require  # noqa: E402

_INERT_CONFIGURATION = live._configuration


def _configuration(settings):
    require(
        settings.defense_task_watch_enabled is True
        and len(settings.defense_task_watch_host_ids) == 1
        and settings.defense_task_watch_interval_seconds == 30,
        "explicit_single_host_watcher_required",
    )
    document = _INERT_CONFIGURATION(replace(settings, defense_task_watch_enabled=False))
    document["defense_task_watch_enabled"] = True
    return document


def _decode(document):
    require(document.get("defense_task_watch_enabled") is True, "watcher_not_enabled")
    inert = {**document, "defense_task_watch_enabled": False}
    settings = replace(_decode_settings(inert), defense_task_watch_enabled=True)
    _configuration(settings)
    return settings


def _application(settings):
    from opsark.main import create_app

    return create_app(settings)


class WatchProcess(live.LiveProcess):
    """Use the existing creation-verified handle, with a distinct fixed child."""

    def _command(self):
        return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--watch-child"]

    def __enter__(self):
        with patch.object(live, "_configuration", _configuration):
            return super().__enter__()

    def _finish(self, success):
        super()._finish(success)
        if success:
            require(self.audit.get("watcher_stopped") is True, "watcher_not_stopped")
            require(self.audit.get("forbidden_write_attempts") == 0, "watcher_write_attempted")


def _child():
    payload = json.loads(sys.stdin.buffer.read(32769))
    ready, stop, audit = (Path(payload[name]) for name in ("ready", "stop", "audit"))
    identity = {"pid": os.getpid(), "parent_pid": os.getppid(), "creation_filetime": None}
    if os.name == "nt":
        kernel = live._windows_kernel()
        identity["creation_filetime"] = live._creation_filetime(kernel, kernel.GetCurrentProcess())
    _json(Path(payload["runtime"]), identity)
    counts: dict[str, Any] = {
        "pid": os.getpid(),
        "model_attempts": 0,
        "read_requests": 0,
        "write_requests": {},
        "forbidden_write_attempts": 0,
    }
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    settings = _decode(payload["settings"])
    os.environ["OPSARK_DATA_DIR"] = str(ready.parent / ("bootstrap-" + str(os.getpid())))
    os.environ["OPSARK_TOKEN"] = settings.token
    import httpx
    import uvicorn

    async def no_model(*_args, **_kwargs):
        counts["model_attempts"] += 1
        raise RuntimeError("model_forbidden")

    httpx.AsyncClient.send = no_model
    try:
        from opsark.business_readiness import run_business_readiness
        from opsark.defense_client import invoke
        from opsark.defense_task_watch import DefenseTaskWatcher

        app = _application(settings)
        controller, rechecks = app.state.defense_service, app.state.defense_recheck_service
        watcher = app.state.defense_task_watcher
        counts["production_root_invoker"] = controller.invoker is invoke
        counts["production_business_collector"] = rechecks.collector is run_business_readiness
        counts["production_watcher"] = type(watcher) is DefenseTaskWatcher
        counts["worker_disabled"] = not settings.defense_worker_enabled
        require(
            len(controller.targets) == 1
            and not app.state.patch_service.targets
            and type(watcher) is DefenseTaskWatcher
            and watcher.enabled
            and watcher.store.base is controller.store
            and watcher.interval_seconds == 30,
            "unexpected_watch_configuration",
        )
        require(
            not controller.policy.ai.enabled and not controller.policy.ai.requires_ai,
            "ai_policy_present",
        )
        target = next(iter(controller.targets.values()))
        require(watcher.host_ids == (target.host.public.id,), "watcher_target_changed")

        @app.middleware("http")
        async def count_requests(request, call_next):
            if request.method in {"GET", "HEAD"}:
                counts["read_requests"] += 1
            else:
                path = request.url.path
                operation = (
                    "mode"
                    if path == "/api/automation"
                    else "ack"
                    if (
                        path.startswith("/api/ssh-defense/task-watch/events/")
                        and path.endswith("/ack")
                    )
                    else "forbidden"
                )
                if operation == "forbidden":
                    counts["forbidden_write_attempts"] += 1
                require(operation in {"mode", "ack"}, "watch_child_mutation_forbidden")
                counts["write_requests"][operation] = counts["write_requests"].get(operation, 0) + 1
            return await call_next(request)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                loop="asyncio",
                http="h11",
                ws="none",
                access_log=False,
                log_level="critical",
                timeout_graceful_shutdown=2,
            )
        )

        def supervise():
            deadline = time.monotonic() + 420
            while not server.started:
                if stop.exists() or time.monotonic() >= deadline:
                    server.should_exit = True
                    return
                time.sleep(0.02)
            _json(
                ready,
                {
                    "pid": os.getpid(),
                    "parent_pid": os.getppid(),
                    "base": f"http://127.0.0.1:{port}",
                    "host_id": target.host.public.id,
                    "production_root_invoker": counts["production_root_invoker"],
                    "production_business_collector": counts["production_business_collector"],
                    "production_watcher": counts["production_watcher"],
                },
            )
            while not stop.exists() and time.monotonic() < deadline:
                time.sleep(0.03)
            server.should_exit = True

        supervisor = threading.Thread(target=supervise, daemon=True)
        supervisor.start()
        try:
            server.run(sockets=[listener])
        finally:
            listener.close()
        supervisor.join(timeout=1)
        require(not supervisor.is_alive(), "supervisor_not_stopped")
        counts["stopped"] = True
        counts["watcher_stopped"] = watcher.stopped.is_set() and not watcher.status()["running"]
        counts["watch_counts"] = watcher.store.counts()
        _json(audit, counts)
        return 0
    except Exception as error:
        counts["failure_type"] = type(error).__name__
        _json(audit, counts)
        return 1


if __name__ == "__main__":
    require(sys.argv[1:] == ["--watch-child"], "invalid_watch_child_entry")
    raise SystemExit(_child())
