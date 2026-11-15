"""Explicit single-session real process; no fake adapter exists in this entry.

Settings arrive on private stdin. Credentials remain opaque file references.
The old inert/live process boundary is deliberately unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import sys
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import defense_live_process as live  # noqa: E402
from defense_recheck_process_restart import PATH_FIELDS, _json, require  # noqa: E402

from opsark.config import Settings  # noqa: E402

_INERT_CONFIGURATION = live._configuration


def _configuration(settings, expected_ai_calls=0):
    require(type(expected_ai_calls) is int and expected_ai_calls in (0, 1), "invalid_ai_budget")
    require(
        settings.defense_session_enabled is True
        and settings.inventory_path is not None
        and settings.defense_inventory_path is not None
        and settings.defense_policy_path is not None
        and settings.patch_inventory_path is None
        and not settings.defense_task_watch_enabled
        and not settings.defense_worker_enabled
        and not settings.observation_enabled
        and not settings.web_observation_enabled
        and not settings.vulnerability_scan_enabled,
        "explicit_session_only_required",
    )
    if expected_ai_calls:
        require(
            settings.ai_provider == "openai"
            and settings.ai_key is None
            and isinstance(settings.ai_key_file, Path)
            and settings.ai_key_file.is_absolute()
            and isinstance(settings.ai_base_url, str)
            and bool(settings.ai_base_url)
            and isinstance(settings.ai_model, str)
            and bool(settings.ai_model)
            and settings.ai_max_output_tokens == 512
            and settings.ai_thinking_mode == "disabled",
            "bounded_file_provider_required",
        )
    else:
        require(
            all(
                value is None
                for value in (
                    settings.ai_base_url,
                    settings.ai_model,
                    settings.ai_key,
                    settings.ai_key_file,
                )
            ),
            "rule_profile_model_forbidden",
        )
    _INERT_CONFIGURATION(
        replace(
            settings,
            defense_session_enabled=False,
            ai_base_url=None,
            ai_key=None,
            ai_key_file=None,
            ai_model=None,
        )
    )
    document = asdict(settings)
    for name in PATH_FIELDS | {"ai_key_file"}:
        if document[name] is not None:
            document[name] = str(document[name])
    return {**document, "_session_expected_ai_calls": expected_ai_calls}


def _decode(document):
    document = dict(document)
    expected = document.pop("_session_expected_ai_calls")
    for name in PATH_FIELDS | {"ai_key_file"}:
        if document.get(name) is not None:
            document[name] = Path(document[name])
    for name in (
        "observation_host_ids",
        "vulnerability_scan_host_ids",
        "defense_task_watch_host_ids",
    ):
        if name in document:
            require(type(document[name]) in (tuple, list), "invalid_tuple_settings")
            document[name] = tuple(document[name])
    settings = Settings(**document)
    _configuration(settings, expected)
    return settings, expected


def _application(settings):
    from opsark.main import create_app

    return create_app(settings)


class SessionProcess(live.LiveProcess):
    """Creation-bound runtime handle and atomic handshakes from LiveProcess."""

    def __init__(self, settings, directory, index, *, expected_ai_calls=0):
        super().__init__(settings, directory, index)
        self.expected_ai_calls = expected_ai_calls

    def _command(self):
        return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--session-child"]

    def __enter__(self):
        with patch.object(
            live,
            "_configuration",
            lambda settings: _configuration(settings, self.expected_ai_calls),
        ):
            return super().__enter__()

    def _finish(self, success):
        # Keep the base success guard forbidding all models; this entry has its
        # own explicit 0/1 budget. Base still waits for its bound runtime handle.
        super()._finish(False)
        if success:
            require(
                self.process is not None
                and self.process.returncode == 0
                and self.audit.get("pid") == self.pid
                and self.audit.get("stopped") is True
                and self.audit.get("session_worker_stopped") is True
                and self.audit.get("worker_disabled") is True
                and self.audit.get("forbidden_write_attempts") == 0,
                "session_child_failed",
            )
            attempts = self.audit.get("model_attempts")
            require(
                type(attempts) is int and attempts <= self.expected_ai_calls,
                "session_model_budget_exceeded",
            )


def _write_operation(method, path):
    if method == "PUT" and path == "/api/automation":
        return "mode"
    if method == "POST" and path.startswith("/api/hosts/"):
        if path.endswith("/ssh-defense/arm"):
            return "arm"
        if path.endswith("/ssh-defense/sessions"):
            return "session_start"
        if "/ssh-defense/transactions/" in path and path.endswith("/query"):
            return "query"
    return "forbidden"


def _model_request_metadata(settings, request):
    endpoint = urlsplit(settings.ai_base_url.rstrip("/") + "/chat/completions")
    default_port = 443 if endpoint.scheme == "https" else 80
    require(
        request.method == "POST"
        and request.url.scheme == endpoint.scheme
        and request.url.host == endpoint.hostname
        and (request.url.port or default_port) == (endpoint.port or default_port)
        and request.url.path == endpoint.path
        and not request.url.query
        and not request.url.fragment,
        "unexpected_model_route",
    )
    timeouts = request.extensions.get("timeout")
    require(
        type(timeouts) is dict
        and set(timeouts) == {"connect", "read", "write", "pool"}
        and all(
            type(value) in (int, float) and math.isfinite(value) and 0 < value <= 20
            for value in timeouts.values()
        )
        and len(set(timeouts.values())) == 1,
        "model_timeout_budget_changed",
    )
    seconds = next(iter(timeouts.values()))
    body = request.content
    value = json.loads(body)
    require(
        value.get("thinking") == {"type": "disabled"}
        and value.get(settings.ai_token_limit_parameter) == 512,
        "model_request_budget_changed",
    )
    from opsark.defense_ai import ModelInput
    from opsark.defense_models import digest

    messages = value.get("messages")
    require(
        type(messages) is list and len(messages) == 2 and messages[1].get("role") == "user",
        "model_input_shape_changed",
    )
    bounded = ModelInput.model_validate_json(messages[1]["content"])
    return {
        "method": "POST",
        "route": "chat_completions",
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_bytes": len(body),
        "timeout_seconds": seconds,
        "max_output_tokens": 512,
        "thinking": "disabled",
        "bounded_input_sha256": digest(bounded),
    }


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
        "model_requests": [],
        "read_requests": 0,
        "write_requests": {},
        "forbidden_write_attempts": 0,
    }
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    settings, expected = _decode(payload["settings"])
    os.environ["OPSARK_DATA_DIR"] = str(ready.parent / ("bootstrap-" + str(os.getpid())))
    os.environ["OPSARK_TOKEN"] = settings.token
    import httpx
    import uvicorn

    original_transport = httpx.AsyncHTTPTransport.handle_async_request
    counts["production_http_transport"] = (
        original_transport.__module__ == "httpx._transports.default"
        and original_transport.__qualname__ == "AsyncHTTPTransport.handle_async_request"
    )

    async def observe_transport(
        self: httpx.AsyncHTTPTransport, request: httpx.Request
    ) -> httpx.Response:
        counts["model_attempts"] += 1
        require(expected == 1 and counts["model_attempts"] <= 1, "model_dispatch_forbidden")
        counts["model_requests"].append(_model_request_metadata(settings, request))
        return await original_transport(self, request)

    httpx.AsyncHTTPTransport.handle_async_request = observe_transport
    try:
        from opsark import ai_provider
        from opsark.business_readiness import run_business_readiness
        from opsark.defense_ai import DefenseAIService
        from opsark.defense_client import invoke
        from opsark.defense_session import DefenseSessionCoordinator
        from opsark.defense_session_worker import DefenseSessionWorker

        app = _application(settings)
        controller = app.state.defense_service
        worker, coordinator = (
            app.state.defense_session_worker,
            app.state.defense_session_coordinator,
        )
        rechecks = app.state.defense_recheck_service
        counts.update(
            production_root_invoker=controller.invoker is invoke,
            production_business_collector=rechecks.collector is run_business_readiness,
            production_session_worker=type(worker) is DefenseSessionWorker,
            production_session_coordinator=type(coordinator) is DefenseSessionCoordinator,
            production_defense_ai=type(controller.ai_service) is DefenseAIService,
            worker_disabled=not settings.defense_worker_enabled,
        )
        require(
            len(controller.targets) == 1
            and not app.state.patch_service.targets
            and type(worker) is DefenseSessionWorker
            and type(coordinator) is DefenseSessionCoordinator
            and worker.enabled
            and worker.coordinator is coordinator
            and worker.interval_seconds == 5,
            "unexpected_session_configuration",
        )
        consent = controller.policy.ai
        require(
            consent.enabled is bool(expected)
            and consent.requires_ai is bool(expected)
            and (
                not expected
                or (
                    consent.provider_fingerprint == ai_provider.provider_fingerprint(settings)
                    and consent.max_analyses_per_day == consent.max_total_analyses == 1
                )
            ),
            "session_provider_consent_changed",
        )
        target = next(iter(controller.targets.values()))

        @app.middleware("http")
        async def count_requests(request, call_next):
            if request.method in {"GET", "HEAD"}:
                counts["read_requests"] += 1
            else:
                operation = _write_operation(request.method, request.url.path)
                counts["write_requests"][operation] = counts["write_requests"].get(operation, 0) + 1
                if operation == "forbidden":
                    counts["forbidden_write_attempts"] += 1
                require(operation != "forbidden", "session_http_mutation_forbidden")
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
            deadline = time.monotonic() + 175
            while not server.started:
                if stop.exists() or time.monotonic() >= deadline:
                    server.should_exit = True
                    return
                time.sleep(0.02)
            _json(
                ready,
                {
                    "pid": os.getpid(),
                    "base": f"http://127.0.0.1:{port}",
                    "host_id": target.host.public.id,
                    "production_root_invoker": counts["production_root_invoker"],
                    "production_business_collector": counts["production_business_collector"],
                    "production_session_worker": counts["production_session_worker"],
                    "production_http_transport": counts["production_http_transport"],
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
        require(not supervisor.is_alive(), "session_supervisor_not_stopped")
        counts["stopped"] = True
        counts["session_worker_stopped"] = (
            worker.stopped.is_set() and not worker.status()["running"]
        )
        _json(audit, counts)
        return 0
    except Exception as error:
        counts["failure_type"] = type(error).__name__
        _json(audit, counts)
        return 1


if __name__ == "__main__":
    require(sys.argv[1:] == ["--session-child"], "invalid_session_child_entry")
    raise SystemExit(_child())
