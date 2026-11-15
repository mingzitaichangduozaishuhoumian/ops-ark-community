"""Owned live-SSH Controller process fixture; no credentials or logs are exported.

The fixed child assembles the formal application. Unlike the offline fixture,
SSH remains available for its registered bounded tools. Models and workers stay
disabled. This fixture never restarts Root, sshd, a container or the host.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from defense_recheck_process_restart import (  # noqa: E402
    _decode_settings,
    _json,
    _settings_document,
    require,
)

from opsark.config import Settings  # noqa: E402


def apply_record(directory: Path, rid: str) -> dict:
    """Read only the immutable original apply identity, never export its bytes."""
    with closing(
        sqlite3.connect((directory / "security.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("PRAGMA query_only=ON")
        row = db.execute(
            "SELECT request_sha256,request_bytes FROM defense_requests WHERE rid=? AND op='apply'",
            (rid,),
        ).fetchone()
        require(row is not None and hashlib.sha256(row[1]).hexdigest() == row[0], "apply_missing")
        count = db.execute("SELECT count(*) FROM defense_requests WHERE op='apply'").fetchone()[0]
        return {"request_sha256": row[0], "total_apply_intents": count}


def _application(settings):
    from opsark.main import create_app

    return create_app(settings)


def _configuration(settings):
    document = _settings_document(settings)
    require(not settings.web_observation_enabled, "web_worker_enabled")
    return document


def _windows_kernel():
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    return kernel


def _creation_filetime(kernel, handle):
    import ctypes
    from ctypes import wintypes

    created, ended, system, user = (wintypes.FILETIME() for _ in range(4))
    require(
        kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(ended),
            ctypes.byref(system),
            ctypes.byref(user),
        ),
        "runtime_creation_unavailable",
    )
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


class LiveProcess:
    """A new real Python/Uvicorn process, including Windows redirector handling."""

    def __init__(self, settings: Settings, directory: Path, index: int):
        self.settings, self.directory, self.index = settings, directory, index
        self.ready_path = directory / f"process-{index}-ready.json"
        self.identity_path = directory / f"process-{index}-runtime.json"
        self.stop_path = directory / f"process-{index}-stop.json"
        self.audit_path = directory / f"process-{index}-audit.json"
        self.audit: dict[str, Any] = {}
        self.ready: dict[str, Any] = {}
        self.process = None
        self.base = ""
        self.pid = None
        self._runtime_handle = None

    def _command(self):
        return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"]

    def __enter__(self):
        document = _configuration(self.settings)
        require(
            self.directory.is_absolute() and self.directory.is_dir(), "process_directory_missing"
        )
        require(
            not any(
                p.exists()
                for p in (self.ready_path, self.identity_path, self.stop_path, self.audit_path)
            ),
            "process_artifact_exists",
        )
        payload = {
            "settings": document,
            "ready": str(self.ready_path),
            "stop": str(self.stop_path),
            "audit": str(self.audit_path),
            "runtime": str(self.identity_path),
        }
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("OPSARK_")
        }
        self.process = subprocess.Popen(  # noqa: S603 -- fixed owned Python child, no shell.
            self._command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        try:
            stream = self.process.stdin
            require(stream is not None, "child_input_missing")
            if stream is None:
                raise RuntimeError("child_input_missing")
            stream.write(json.dumps(payload).encode("utf-8"))
            stream.close()
            deadline = time.monotonic() + 20
            while not self.ready_path.exists():
                if self.pid is None and self.identity_path.exists():
                    self._bind_runtime(json.loads(self.identity_path.read_text(encoding="ascii")))
                require(self.process.poll() is None, "child_start_failed")
                require(time.monotonic() < deadline, "child_start_timeout")
                time.sleep(0.03)
            self.ready = json.loads(self.ready_path.read_text(encoding="ascii"))
            if self.pid is None:
                self._bind_runtime(json.loads(self.identity_path.read_text(encoding="ascii")))
            require(self.ready["pid"] == self.pid, "ready_runtime_changed")
            self.base = self.ready["base"]
            return self
        except BaseException:
            self._finish(False)
            raise

    def _bind_runtime(self, identity):
        require(self.process is not None, "launcher_missing")
        if self.process is None:
            raise RuntimeError("launcher_missing")
        self.pid = identity["pid"]
        require(
            self.pid == self.process.pid
            or (os.name == "nt" and identity["parent_pid"] == self.process.pid),
            "child_identity_changed",
        )
        if os.name == "nt":
            self._bind_windows_runtime(identity)

    def _bind_windows_runtime(self, identity):
        kernel = _windows_kernel()
        handle = kernel.OpenProcess(0x101001, False, self.pid)
        require(bool(handle), "runtime_handle_missing")
        try:
            creation = identity.get("creation_filetime")
            require(
                type(creation) is int
                and creation > 0
                and _creation_filetime(kernel, handle) == creation,
                "runtime_creation_changed",
            )
        except BaseException:
            kernel.CloseHandle(handle)
            raise
        self._runtime_handle = (kernel, handle)

    def _abort_owned(self):
        """Terminate only a verified owned runtime handle and its Popen launcher."""
        try:
            if self._runtime_handle is not None:
                kernel, handle = self._runtime_handle
                if kernel.WaitForSingleObject(handle, 0) != 0:
                    terminated = kernel.TerminateProcess(handle, 1)
                    require(
                        terminated or kernel.WaitForSingleObject(handle, 0) == 0,
                        "runtime_terminate_failed",
                    )
                    require(
                        kernel.WaitForSingleObject(handle, 5000) == 0, "runtime_terminate_timeout"
                    )
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)

    def _finish(self, success):
        if self.process is None:
            return
        if not self.stop_path.exists():
            _json(self.stop_path, {"stop": True})
        try:
            self.process.wait(timeout=8)
            if self._runtime_handle is not None:
                kernel, handle = self._runtime_handle
                require(kernel.WaitForSingleObject(handle, 8000) == 0, "runtime_not_exited")
            if self.audit_path.exists():
                self.audit = json.loads(self.audit_path.read_text(encoding="ascii"))
            if success:
                require(
                    self.process.returncode == 0 and self.audit.get("stopped") is True,
                    "child_failed",
                )
                require(self.audit.get("pid") == self.pid, "audit_identity_changed")
                require(self.audit.get("model_attempts") == 0, "model_attempted")
                require(self.audit.get("worker_disabled") is True, "worker_enabled")
        except subprocess.TimeoutExpired:
            self._abort_owned()
            raise RuntimeError("child_stop_timeout") from None
        except BaseException:
            self._abort_owned()
            raise
        finally:
            if self._runtime_handle is not None:
                kernel, handle = self._runtime_handle
                kernel.CloseHandle(handle)
                self._runtime_handle = None

    def __exit__(self, kind, _value, _traceback):
        self._finish(kind is None)
        return False


def _child():
    payload = json.loads(sys.stdin.buffer.read(32769))
    ready, stop, audit = (Path(payload[name]) for name in ("ready", "stop", "audit"))
    identity = {"pid": os.getpid(), "parent_pid": os.getppid(), "creation_filetime": None}
    if os.name == "nt":
        kernel = _windows_kernel()
        identity["creation_filetime"] = _creation_filetime(kernel, kernel.GetCurrentProcess())
    _json(Path(payload["runtime"]), identity)
    counts: dict[str, Any] = {
        "pid": os.getpid(),
        "model_attempts": 0,
        "read_requests": 0,
        "write_requests": {},
    }
    for name in tuple(os.environ):
        if name.startswith("OPSARK_"):
            del os.environ[name]
    settings = _decode_settings(payload["settings"])
    _configuration(settings)
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

        app = _application(settings)
        controller, rechecks = app.state.defense_service, app.state.defense_recheck_service
        counts["production_root_invoker"] = controller.invoker is invoke
        counts["production_business_collector"] = rechecks.collector is run_business_readiness
        counts["worker_disabled"] = not settings.defense_worker_enabled
        require(
            len(controller.targets) == 1 and not app.state.patch_service.targets,
            "unexpected_targets",
        )
        require(
            not controller.policy.ai.enabled and not controller.policy.ai.requires_ai,
            "ai_policy_present",
        )
        target = next(iter(controller.targets.values()))
        require(len(target.host.business_checks) == 3, "business_profile_missing")

        @app.middleware("http")
        async def count_requests(request, call_next):
            if request.method in {"GET", "HEAD"}:
                counts["read_requests"] += 1
            else:
                path = request.url.path
                operation = "mode" if path == "/api/automation" else path.rsplit("/", 1)[-1]
                require(
                    operation in {"mode", "arm", "prepare", "apply", "query", "revoke", "rechecks"},
                    "unexpected_write_route",
                )
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
        _json(audit, counts)
        return 0
    except Exception as error:
        counts["failure_type"] = type(error).__name__
        _json(audit, counts)
        return 1


if __name__ == "__main__":
    require(sys.argv[1:] == ["--child"], "invalid_child_entry")
    raise SystemExit(_child())
